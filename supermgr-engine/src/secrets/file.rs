//! File-based secrets store with optional `AES-256-GCM` at-rest wrapping.
//!
//! Credentials are stored as a map of `label -> base64(bytes)` in an
//! owner-only (`0600`) file. When configured with a 256-bit master key
//! (supplied on macOS from the Data Protection Keychain), the map is sealed in
//! an authenticated `AES-256-GCM` envelope (`version: 2`) on disk, while
//! transparently upgrading legacy plain JSON (`version: 1`) files in place.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use supermgr_core::error::SecretError;
use supermgr_core::keyring::{SecretStore, ZeroizingSecret};

const ENVELOPE_VERSION: u32 = 2;
const ENVELOPE_CIPHER: &str = "aes-256-gcm";
const ENVELOPE_AAD: &[u8] = b"supermanager-secrets-v2";

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedSecretsEnvelope {
    version: u32,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

/// File-based [`SecretStore`] implementation.
pub struct FileSecretStore {
    path: PathBuf,
    master_key: Option<Arc<Zeroizing<[u8; 32]>>>,
}

impl FileSecretStore {
    /// Create a new file-based store at the given path (unwrapped JSON mode).
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            master_key: None,
        }
    }

    /// Create an `AES-256-GCM` encrypted store wrapped by `master_key`.
    #[must_use]
    pub fn with_master_key(path: PathBuf, master_key: [u8; 32]) -> Self {
        Self {
            path,
            master_key: Some(Arc::new(Zeroizing::new(master_key))),
        }
    }

    /// Parse a 64-character hex master key (e.g. delivered over stdin pipe from
    /// the signed GUI bundle) into a zeroizing 32-byte key and construct an
    /// encrypted [`FileSecretStore`].
    pub fn from_hex_key(path: PathBuf, hex_key: &str) -> Result<Self> {
        let trimmed = hex_key.trim();
        if trimmed.len() != 64 || !trimmed.is_ascii() {
            bail!("expected 64-character hex master key");
        }
        let mut key = Zeroizing::new([0u8; 32]);
        for (i, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk).context("invalid UTF-8 in hex key")?;
            key[i] = u8::from_str_radix(pair, 16).context("invalid hex digit in master key")?;
        }
        Ok(Self::with_master_key(path, *key))
    }

    /// Create with the default path for the current platform.
    #[must_use]
    pub fn default_path() -> Self {
        let dir = super::default_data_dir();
        Self::new(dir.join("secrets.json"))
    }

    /// Transparently upgrade an existing plain JSON `secrets.json` into an
    /// `AES-256-GCM` envelope on disk while holding the store's OS lock.
    /// No-op when no `master_key` is configured, when the file does not yet
    /// exist, or when it is already an encrypted v2 envelope.
    pub async fn migrate_to_encrypted_if_needed(&self) -> Result<()> {
        let Some(key) = self.master_key.clone() else {
            return Ok(());
        };
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            if !path.exists() {
                return Ok(());
            }
            let dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::create_dir_all(dir).context("create secrets directory")?;
            let lock = open_transaction_lock(&path)?;

            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read secrets file {}", path.display()))?;
            if is_encrypted_envelope(&text) {
                // Verify the key actually decrypts the existing store at startup.
                let _ = parse_secrets_text(&text, &path, Some(&key))?;
                drop(lock);
                return Ok(());
            }
            let map: HashMap<String, String> = serde_json::from_str(&text)
                .with_context(|| format!("parse legacy secrets file {}", path.display()))?;
            persist_map_atomic(dir, &path, &map, Some(&key))?;
            tracing::info!(
                "migrated {} secret(s) in {} to AES-256-GCM at-rest format",
                map.len(),
                path.display()
            );
            drop(lock);
            Ok(())
        })
        .await
        .context("secret store migration task failed")?
    }

    async fn read_map(&self) -> Result<HashMap<String, String>> {
        let path = self.path.clone();
        let key = self.master_key.clone();
        tokio::task::spawn_blocking(move || read_map_at(&path, key.as_deref().map(|z| &**z)))
            .await
            .context("secret store reader task failed")?
    }

    /// The OS lock spans read/modify/durable replace, including independent
    /// store instances and processes. Keep the lock on a separate stable inode:
    /// the data file itself is replaced atomically. Blocking lock and disk I/O
    /// run off the async executor. Cancellation cannot interrupt a replacement.
    async fn update_map(
        &self,
        update: impl FnOnce(&mut HashMap<String, String>) + Send + 'static,
    ) -> Result<()> {
        let path = self.path.clone();
        let key = self.master_key.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::create_dir_all(dir).context("create secrets directory")?;
            let lock = open_transaction_lock(&path)?;

            let key_ref = key.as_deref().map(|z| &**z);
            let mut map = read_map_at(&path, key_ref)?;
            update(&mut map);
            persist_map_atomic(dir, &path, &map, key_ref)?;
            // Closing the handle releases the OS lock, including error paths.
            drop(lock);
            Ok(())
        })
        .await
        .context("secret store writer task failed")?
    }
}

fn open_transaction_lock(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(path.with_extension("lock"))
        .context("open secret store transaction lock")?;
    lock.lock().context("lock secret store transaction")?;
    Ok(lock)
}

fn persist_map_atomic(
    dir: &Path,
    path: &Path,
    map: &HashMap<String, String>,
    master_key: Option<&[u8; 32]>,
) -> Result<()> {
    // NamedTempFile is create-new, randomly named, and 0600 on Unix
    // from the first write. Dropping it on failure removes the file.
    let mut tmp =
        tempfile::NamedTempFile::new_in(dir).context("create private secrets temporary file")?;
    if let Some(key) = master_key {
        let plaintext =
            Zeroizing::new(serde_json::to_vec(map).context("serialize secrets map")?);
        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: ENVELOPE_AAD,
                },
            )
            .map_err(|_| anyhow!("AES-256-GCM encryption failed"))?;
        let env = EncryptedSecretsEnvelope {
            version: ENVELOPE_VERSION,
            cipher: ENVELOPE_CIPHER.into(),
            nonce: STANDARD.encode(nonce_bytes),
            ciphertext: STANDARD.encode(ciphertext),
        };
        serde_json::to_writer_pretty(&mut tmp, &env)
            .context("serialize encrypted secrets envelope")?;
    } else {
        serde_json::to_writer_pretty(&mut tmp, map).context("serialize secrets map")?;
    }
    tmp.flush().context("flush secrets temporary file")?;
    tmp.as_file()
        .sync_all()
        .context("sync secrets temporary file")?;
    tmp.persist(path).context("replace secrets file")?;
    #[cfg(unix)]
    std::fs::File::open(dir)?
        .sync_all()
        .context("sync secrets directory")?;
    Ok(())
}

fn is_encrypted_envelope(text: &str) -> bool {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    val.as_object().is_some_and(|obj| {
        obj.contains_key("version") && obj.contains_key("cipher") && obj.contains_key("ciphertext")
    })
}

fn parse_secrets_text(
    text: &str,
    path: &Path,
    master_key: Option<&[u8; 32]>,
) -> Result<HashMap<String, String>> {
    if is_encrypted_envelope(text) {
        let env: EncryptedSecretsEnvelope = serde_json::from_str(text)
            .with_context(|| format!("parse encrypted secrets envelope {}", path.display()))?;
        if env.version != ENVELOPE_VERSION || env.cipher != ENVELOPE_CIPHER {
            bail!(
                "unsupported encrypted secrets format version={} cipher={} in {}",
                env.version,
                env.cipher,
                path.display()
            );
        }
        let key = master_key.ok_or_else(|| {
            anyhow!(
                "secrets file {} is encrypted at rest; Keychain master key required",
                path.display()
            )
        })?;
        let nonce_bytes = STANDARD
            .decode(&env.nonce)
            .context("decode secrets envelope nonce")?;
        let nonce_arr: [u8; 12] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid secrets envelope nonce length {}", nonce_bytes.len()))?;
        let ciphertext = STANDARD
            .decode(&env.ciphertext)
            .context("decode secrets envelope ciphertext")?;
        let cipher = Aes256Gcm::new(key.into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::from(nonce_arr),
                    Payload {
                        msg: &ciphertext,
                        aad: ENVELOPE_AAD,
                    },
                )
                .map_err(|_| {
                    anyhow!(
                        "failed to authenticate/decrypt secrets file {}",
                        path.display()
                    )
                })?,
        );
        return serde_json::from_slice(&plaintext)
            .with_context(|| format!("parse decrypted secrets map {}", path.display()));
    }
    serde_json::from_str(text).with_context(|| format!("parse secrets file {}", path.display()))
}

fn read_map_at(path: &Path, master_key: Option<&[u8; 32]>) -> Result<HashMap<String, String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e).with_context(|| format!("read secrets file {}", path.display())),
    };
    parse_secrets_text(&text, path, master_key)
}

#[async_trait]
impl SecretStore for FileSecretStore {
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError> {
        let label_owned = label.to_owned();
        let encoded = STANDARD.encode(secret);
        self.update_map(move |map| {
            map.insert(label_owned, encoded);
        })
        .await
        .map_err(|e| SecretError::StoreFailed {
            label: label.to_owned(),
            reason: e.to_string(),
        })
    }

    async fn retrieve(&self, label: &str) -> Result<ZeroizingSecret, SecretError> {
        let map = self
            .read_map()
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;
        let encoded = map.get(label).ok_or_else(|| SecretError::NotFound {
            label: label.to_owned(),
        })?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|e| SecretError::ServiceUnavailable(format!("base64 decode: {e}")))?;
        Ok(ZeroizingSecret::from_vec(bytes))
    }

    async fn delete(&self, label: &str) -> Result<(), SecretError> {
        let label_owned = label.to_owned();
        self.update_map(move |map| {
            map.remove(&label_owned);
        })
        .await
        .map_err(|e| SecretError::StoreFailed {
            label: label.to_owned(),
            reason: e.to_string(),
        })
    }

    async fn read_all(&self) -> Result<std::collections::HashMap<String, String>, SecretError> {
        self.read_map()
            .await
            .map_err(|e| SecretError::ServiceUnavailable(format!("read_all: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supermgr_core::keyring::SecretStore;

    #[tokio::test]
    async fn read_all_returns_every_stored_secret_as_base64() {
        let dir = std::env::temp_dir().join(format!("smfs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = FileSecretStore::new(dir.join("secrets.json"));

        store
            .store("vpn/a/wg-private-key", b"keybytes")
            .await
            .unwrap();
        store.store("ssh/b/password", b"hunter2").await.unwrap();

        let all = store.read_all().await.unwrap();
        assert_eq!(all.len(), 2);
        // Values are base64 of the stored bytes — the exact form the
        // portable backup carries.
        assert_eq!(
            all.get("vpn/a/wg-private-key").map(String::as_str),
            Some("a2V5Ynl0ZXM=")
        );
        assert_eq!(
            all.get("ssh/b/password").map(String::as_str),
            Some("aHVudGVyMg==")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn read_all_is_empty_when_nothing_stored() {
        let dir = std::env::temp_dir().join(format!("smfs-{}", uuid::Uuid::new_v4()));
        let store = FileSecretStore::new(dir.join("secrets.json"));
        assert!(store.read_all().await.unwrap().is_empty());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_independent_stores_keep_all_acknowledged_writes() {
        let dir = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(32));
        let mut tasks = Vec::new();
        for i in 0..32 {
            let store = FileSecretStore::new(dir.path().join("secrets.json"));
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .store(&format!("key-{i}"), b"fake-secret")
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let store = FileSecretStore::new(dir.path().join("secrets.json"));
        assert_eq!(store.read_all().await.unwrap().len(), 32);
        for i in 0..32 {
            assert!(store.retrieve(&format!("key-{i}")).await.is_ok());
        }
    }

    #[tokio::test]
    async fn corrupt_store_is_never_replaced_by_store_or_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        std::fs::write(&path, b"broken JSON").unwrap();
        let store = FileSecretStore::new(path.clone());
        assert!(store.store("new", b"fake-secret").await.is_err());
        assert!(store.delete("old").await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"broken JSON");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_deletes_and_stores_do_not_restore_deleted_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let store = FileSecretStore::new(path.clone());
        for i in 0..16 {
            store.store(&format!("old-{i}"), b"old").await.unwrap();
        }
        let mut tasks = Vec::new();
        for i in 0..16 {
            let store = FileSecretStore::new(path.clone());
            tasks.push(tokio::spawn(async move {
                store.delete(&format!("old-{i}")).await.unwrap();
                store.store(&format!("new-{i}"), b"new").await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let all = store.read_all().await.unwrap();
        assert_eq!(all.len(), 16);
        assert!(all.keys().all(|k| k.starts_with("new-")));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn writes_are_private_and_ignore_legacy_predictable_temp_symlink() {
        use std::os::unix::{fs::symlink, fs::PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let victim = dir.path().join("untouched");
        std::fs::write(&victim, b"keep").unwrap();
        symlink(&victim, path.with_extension("tmp")).unwrap();
        let store = FileSecretStore::new(path.clone());
        store.store("new", b"fake-secret").await.unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.with_extension("lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn separate_processes_share_the_secret_transaction_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        let mut children = Vec::new();
        for worker in 0..4 {
            children.push(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "secrets::file::tests::process_writer",
                    ])
                    .env("SUPERMGR_TEST_WRITER_PATH", &path)
                    .env("SUPERMGR_TEST_WRITER_ID", worker.to_string())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
        for child in children {
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "child failed: {} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert_eq!(read_map_at(&path, None).unwrap().len(), 40);
    }

    #[tokio::test]
    async fn encrypted_store_migrates_legacy_json_in_place_and_rejects_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");

        // Start with a legacy plain JSON secrets.json containing two entries.
        let legacy = FileSecretStore::new(path.clone());
        legacy
            .store("ssh/host1/password", b"existing-ssh-password")
            .await
            .unwrap();
        legacy
            .store("vpn/p1/wg-private-key", b"existing-wg-key")
            .await
            .unwrap();
        let raw_before = std::fs::read_to_string(&path).unwrap();
        assert!(raw_before.contains("ssh/host1/password"));

        // Upgrade in place with a 32-byte master key: zero secrets lost,
        // and neither labels nor base64 values remain in plaintext on disk.
        let key_a = [0x42u8; 32];
        let enc = FileSecretStore::with_master_key(path.clone(), key_a);
        enc.migrate_to_encrypted_if_needed().await.unwrap();

        let raw_after = std::fs::read_to_string(&path).unwrap();
        assert!(raw_after.contains("\"version\": 2"));
        assert!(!raw_after.contains("ssh/host1/password"));
        assert!(!raw_after.contains("ZXhpc3Rpbmctc3NoLXBhc3N3b3Jk"));

        assert_eq!(
            &*enc.retrieve("ssh/host1/password").await.unwrap(),
            b"existing-ssh-password"
        );
        assert_eq!(
            &*enc.retrieve("vpn/p1/wg-private-key").await.unwrap(),
            b"existing-wg-key"
        );

        // Unkeyed or wrong-key stores refuse to read or clobber the file.
        let unkeyed = FileSecretStore::new(path.clone());
        assert!(unkeyed.retrieve("ssh/host1/password").await.is_err());
        assert!(unkeyed.store("new", b"nope").await.is_err());

        let wrong = FileSecretStore::with_master_key(path.clone(), [0x99u8; 32]);
        assert!(wrong.retrieve("ssh/host1/password").await.is_err());
        assert!(wrong.store("new", b"nope").await.is_err());

        // Original encrypted contents remain intact.
        assert_eq!(
            &*enc.retrieve("ssh/host1/password").await.unwrap(),
            b"existing-ssh-password"
        );
    }

    // Only launched by the parent test, with an isolated path in its own
    // environment. Never falls back to a real user store.
    #[test]
    #[ignore = "subprocess helper for separate_processes_share_the_secret_transaction_lock"]
    fn process_writer() {
        let path = std::env::var_os("SUPERMGR_TEST_WRITER_PATH").expect("test path required");
        let worker = std::env::var("SUPERMGR_TEST_WRITER_ID").expect("test worker required");
        let store = FileSecretStore::new(PathBuf::from(path));
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for i in 0..10 {
                store
                    .store(&format!("{worker}-{i}"), b"fake-secret")
                    .await
                    .unwrap();
            }
        });
    }
}
