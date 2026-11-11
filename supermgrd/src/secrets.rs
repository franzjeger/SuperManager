//! File-based secrets store for `supermgrd`.
//!
//! Credentials are stored as a JSON map of `label -> base64(bytes)` in a
//! root-owned, `0600`-permission file.  The file-permission boundary provides
//! the same security model as `/etc/shadow`: only root can read it, which is
//! acceptable because `supermgrd` itself runs as root.
//!
//! # File location
//!
//! | Effective UID | Path |
//! |---------------|------|
//! | root (production) | `/etc/supermgrd/secrets.json` |
//! | non-root (dev/test) | `$XDG_DATA_HOME/supermgrd/secrets.json` |
//!
//! # Wire format
//!
//! ```json
//! {
//!   "supermgr/wg/abc123.../privkey": "<base64>",
//!   "supermgr/fg/def456.../password": "<base64>",
//!   "supermgr/fg/def456.../psk":      "<base64>"
//! }
//! ```
//!
//! # Atomicity & Concurrency
//!
//! Read-modify-write cycles are serialised in-process via [`SECRETS_LOCK`], and
//! writes go through an unguessable `0600` `O_CREAT | O_EXCL` temporary file in
//! the target directory (`sync_all` + atomic `rename`) so the main file is never
//! partially written, never world-readable, and immune to predictable `.tmp`
//! sibling races.

use std::{collections::HashMap, path::PathBuf};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};

/// In-process serialisation lock protecting read-modify-write updates on the
/// secrets JSON file.
static SECRETS_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn secrets_lock() -> &'static tokio::sync::Mutex<()> {
    SECRETS_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// Return the canonical path to the secrets JSON file.
fn secrets_path() -> Result<PathBuf> {
    // Test-only override. Look at the branch below: when uid is 0 — sudo test,
    // a root container, any privileged CI runner — setting `XDG_DATA_HOME` to
    // somewhere safe does not help, because that branch is not taken. The
    // result was a test run that read, rewrote, and deleted entries in a
    // production credential file. Compiled out entirely for the daemon
    // itself: `cfg(test)` covers only this crate's own unit tests.
    #[cfg(test)]
    if let Ok(path) = std::env::var("SUPERMGRD_TEST_SECRETS_PATH") {
        return Ok(PathBuf::from(path));
    }

    let dir = supermgr_core::paths::try_default_data_dir().map_err(anyhow::Error::msg)?;
    Ok(dir.join("secrets.json"))
}

// ---------------------------------------------------------------------------
// Internal read / write helpers
// ---------------------------------------------------------------------------

/// Read the label->base64 map from disk.  Returns an empty map if the file
/// does not exist yet.
async fn read_map() -> Result<HashMap<String, String>> {
    let path = secrets_path()?;
    if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return Ok(HashMap::new());
    }
    let text = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("read secrets file {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse secrets file {}", path.display()))
}

/// RAII temporary file created exclusively (`O_CREAT | O_EXCL`) at mode `0600`
/// with 128 bits of randomness in `dir`, removed on drop unless persisted.
struct PrivateTempFile {
    file: Option<std::fs::File>,
    path: PathBuf,
}

impl PrivateTempFile {
    fn new_in(dir: &std::path::Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;

        let name = format!(".secrets.{}.tmp", uuid::Uuid::new_v4().simple());
        let path = dir.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let file = opts.open(&path)?;
        Ok(Self {
            file: Some(file),
            path,
        })
    }

    fn write_and_sync(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;
        let Some(ref mut file) = self.file else {
            return Err(std::io::Error::other("temporary file already closed"));
        };
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn persist(mut self, target: &std::path::Path) -> std::io::Result<()> {
        // Drop the open descriptor before renaming.
        self.file.take();
        std::fs::rename(&self.path, target)?;
        // Prevent Drop from unlinking the newly renamed file if target == self.path.
        self.path.clear();
        Ok(())
    }
}

impl Drop for PrivateTempFile {
    fn drop(&mut self) {
        self.file.take();
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Write the map to disk atomically with mode `0600`.
///
/// Sequence:
/// 1. Ensure parent directory exists.
/// 2. Create a unique `0600` temporary file via [`PrivateTempFile::new_in`].
/// 3. Write serialised JSON and `sync_all`.
/// 4. Atomically `persist` over the target path.
async fn write_map(map: &HashMap<String, String>) -> Result<()> {
    let path = secrets_path()?;
    let dir = path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let text = serde_json::to_string_pretty(map).context("serialise secrets map")?;

    tokio::task::spawn_blocking(move || -> Result<()> {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create secrets directory {}", dir.display()))?;

        let mut tmp = PrivateTempFile::new_in(&dir)
            .with_context(|| format!("create temporary secrets file in {}", dir.display()))?;

        tmp.write_and_sync(text.as_bytes())
            .with_context(|| format!("write/sync temporary secrets file in {}", dir.display()))?;

        tmp.persist(&path)
            .with_context(|| format!("persist secrets file {}", path.display()))?;

        Ok(())
    })
    .await
    .context("join secrets write task")?
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Persist `value` bytes under `label`, replacing any existing entry.
pub async fn store_secret(label: &str, value: &[u8]) -> Result<()> {
    let _guard = secrets_lock().lock().await;
    let mut map = read_map().await?;
    map.insert(label.to_owned(), STANDARD.encode(value));
    write_map(&map).await
}

/// Retrieve the bytes stored under `label`.
///
/// Returns an error if the label is absent — callers should surface this as
/// "credential not found in keyring — please re-import the profile".
pub async fn retrieve_secret(label: &str) -> Result<Vec<u8>> {
    let map = read_map().await?;
    let encoded = map.get(label).with_context(|| {
        format!("secret not found for label '{label}' — please re-import the profile")
    })?;
    STANDARD
        .decode(encoded)
        .with_context(|| format!("base64 decode failed for label '{label}'"))
}

/// Return the entire label→base64 map (for backup/export).
pub async fn read_all_secrets() -> Result<HashMap<String, String>> {
    read_map().await
}

/// Atomically add a batch of pre-encoded secrets during backup restore.
///
/// Every value is validated before the store is touched, and existing labels
/// are rejected rather than overwritten. A failed import therefore cannot
/// replace a credential that belongs to an existing profile, host, or key.
pub async fn import_secrets_raw(entries: &HashMap<String, String>) -> Result<()> {
    for (label, encoded) in entries {
        STANDARD
            .decode(encoded)
            .with_context(|| format!("invalid base64 for imported secret '{label}'"))?;
    }

    if entries.is_empty() {
        return Ok(());
    }

    let _guard = secrets_lock().lock().await;
    let mut map = read_map().await?;
    if let Some(label) = entries.keys().find(|label| map.contains_key(*label)) {
        anyhow::bail!("refusing to overwrite existing secret '{label}'");
    }
    map.extend(entries.clone());
    write_map(&map).await
}

/// Remove the entry for `label`.  No-op if the label does not exist.
pub async fn delete_secret(label: &str) -> Result<()> {
    let _guard = secrets_lock().lock().await;
    let mut map = read_map().await?;
    if map.remove(label).is_some() {
        write_map(&map).await?;
    }
    Ok(())
}

/// Point the secrets store at a private file for the duration of a test.
///
/// The returned guard both serialises access and restores the previous value
/// on drop, including on panic. `secrets_path()` reads the environment on
/// every call and cargo runs tests as threads of one process, so without the
/// lock two tests would each be reading the other's file.
///
/// Poisoning is ignored deliberately: a panic in one test leaves the variable
/// pointing at a temp file, and turning that into a cascade of failures in
/// every other test hides the one that actually broke.
#[cfg(test)]
pub(crate) fn test_store(path: &std::path::Path) -> TestStoreGuard {
    let lock = env_lock();
    let previous = std::env::var("SUPERMGRD_TEST_SECRETS_PATH").ok();
    std::env::set_var("SUPERMGRD_TEST_SECRETS_PATH", path);
    TestStoreGuard {
        _lock: lock,
        previous,
    }
}

/// The process-wide lock any test must hold while it mutates the environment.
///
/// Cargo runs tests as threads of one process, so a test that sets a variable
/// another test reads is a race whatever the variables are — hence one lock
/// rather than one per variable. Held by [`test_store`], and by any test that
/// repoints `XDG_RUNTIME_DIR` or similar.
///
/// Poisoning is ignored deliberately: a panic in one test leaves a variable
/// pointing somewhere harmless, and turning that into a cascade of failures in
/// every other test hides the one that actually broke.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Guard returned by [`test_store`]. See its docs.
#[cfg(test)]
pub(crate) struct TestStoreGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    previous: Option<String>,
}

#[cfg(test)]
impl Drop for TestStoreGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(v) => std::env::set_var("SUPERMGRD_TEST_SECRETS_PATH", v),
            None => std::env::remove_var("SUPERMGRD_TEST_SECRETS_PATH"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Combined test for store, retrieve, overwrite, and delete.
    ///
    /// Runs as a single test to avoid parallel env-var mutation (the
    /// `secrets_path()` function reads the environment on every call).
    #[tokio::test]
    async fn store_retrieve_overwrite_delete() {
        // Use a tmp file so we don't touch real secrets.
        let tmp = tempfile::tempdir().expect("create temp dir");
        let _store = test_store(&tmp.path().join("secrets.json"));

        // --- Round-trip: store then retrieve ---
        let label = "supermgr/test/roundtrip_key";
        let value = b"super-secret-bytes-1234";

        store_secret(label, value).await.expect("store_secret");

        let retrieved = retrieve_secret(label).await.expect("retrieve_secret");
        assert_eq!(retrieved, value);

        // --- Overwrite: storing again replaces the value ---
        store_secret(label, b"new-value").await.expect("overwrite");
        let retrieved = retrieve_secret(label)
            .await
            .expect("retrieve after overwrite");
        assert_eq!(retrieved, b"new-value");

        // --- Delete: label is removed ---
        delete_secret(label).await.expect("delete_secret");
        let err = retrieve_secret(label).await;
        assert!(err.is_err(), "expected error after deletion");

        // --- Delete non-existent: no-op, no error ---
        delete_secret("supermgr/test/does-not-exist")
            .await
            .expect("delete non-existent should be no-op");
    }

    /// The override exists so the suite cannot reach the production store.
    /// If it stops being honoured, every secrets test silently starts
    /// operating on `/etc/supermgrd/secrets.json` again.
    #[tokio::test]
    async fn tests_never_touch_the_real_store() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let path = tmp.path().join("secrets.json");
        let _store = test_store(&path);

        assert_eq!(secrets_path().unwrap(), path);
        store_secret("supermgr/test/isolation", b"x").await.unwrap();
        assert!(path.exists(), "secret went somewhere else entirely");
    }

    #[tokio::test]
    async fn backup_import_is_atomic_and_never_overwrites() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let _store = test_store(&tmp.path().join("secrets.json"));

        store_secret("existing", b"keep-me").await.unwrap();
        let entries = HashMap::from([
            ("existing".to_owned(), STANDARD.encode(b"replacement")),
            ("new".to_owned(), STANDARD.encode(b"new-value")),
        ]);

        assert!(import_secrets_raw(&entries).await.is_err());
        assert_eq!(retrieve_secret("existing").await.unwrap(), b"keep-me");
        assert!(retrieve_secret("new").await.is_err());

        let invalid = HashMap::from([("bad".to_owned(), "not base64!".to_owned())]);
        assert!(import_secrets_raw(&invalid).await.is_err());
        assert!(retrieve_secret("bad").await.is_err());
    }

    #[tokio::test]
    async fn concurrent_writes_preserve_all_entries_and_keep_0600_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let path = tmp.path().join("secrets.json");
        let _store = test_store(&path);

        let futs = (0..16u32).map(|i| async move {
            let label = format!("supermgr/test/concurrent/{i}");
            let val = format!("secret-value-{i}");
            store_secret(&label, val.as_bytes()).await.unwrap();
        });
        futures_util::future::join_all(futs).await;

        let all = read_all_secrets().await.unwrap();
        assert_eq!(all.len(), 16);
        for i in 0..16u32 {
            let label = format!("supermgr/test/concurrent/{i}");
            let expected = format!("secret-value-{i}");
            assert_eq!(retrieve_secret(&label).await.unwrap(), expected.as_bytes());
        }

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secrets.json must stay 0600, got {mode:o}");
        assert!(
            !tmp.path().join("secrets.tmp").exists(),
            "predictable secrets.tmp sibling must not be created"
        );
    }
}
