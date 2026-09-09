//! File-based secrets store.
//!
//! Credentials are stored as a JSON map of `label -> base64(bytes)` in a
//! permission-restricted file. Used on both Linux and macOS as a simple
//! alternative to system keyrings.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};

use supermgr_core::error::SecretError;
use supermgr_core::keyring::{SecretStore, ZeroizingSecret};

/// File-based [`SecretStore`] implementation.
pub struct FileSecretStore {
    path: PathBuf,
}

impl FileSecretStore {
    /// Create a new file-based store at the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Create with the default path for the current platform.
    pub fn default_path() -> Self {
        let dir = super::default_data_dir();
        Self::new(dir.join("secrets.json"))
    }

    async fn read_map(&self) -> Result<HashMap<String, String>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || read_map_at(&path))
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
        tokio::task::spawn_blocking(move || -> Result<()> {
            let dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::create_dir_all(dir).context("create secrets directory")?;
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

            let mut map = read_map_at(&path)?;
            update(&mut map);
            // NamedTempFile is create-new, randomly named, and 0600 on Unix
            // from the first write. Dropping it on failure removes the file.
            let mut tmp = tempfile::NamedTempFile::new_in(dir)
                .context("create private secrets temporary file")?;
            serde_json::to_writer_pretty(&mut tmp, &map).context("serialize secrets map")?;
            tmp.flush().context("flush secrets temporary file")?;
            tmp.as_file()
                .sync_all()
                .context("sync secrets temporary file")?;
            tmp.persist(&path).context("replace secrets file")?;
            #[cfg(unix)]
            std::fs::File::open(dir)?
                .sync_all()
                .context("sync secrets directory")?;
            // Closing the handle releases the OS lock, including error paths.
            drop(lock);
            Ok(())
        })
        .await
        .context("secret store writer task failed")?
    }
}

fn read_map_at(path: &Path) -> Result<HashMap<String, String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e).with_context(|| format!("read secrets file {}", path.display())),
    };
    serde_json::from_str(&text).with_context(|| format!("parse secrets file {}", path.display()))
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
        assert_eq!(read_map_at(&path).unwrap().len(), 40);
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
