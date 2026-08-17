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
//! # Atomicity
//!
//! Writes go to a `.tmp` sibling file that is `chmod 600`d before being
//! renamed over the target, so the main file is never partially written and
//! is never world-readable.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::secure_file;
use base64::{engine::general_purpose::STANDARD, Engine as _};

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// Return the canonical path to the secrets JSON file.
fn secrets_path() -> PathBuf {
    // Tests must never reach the real store. The uid check below resolves to
    // `/etc/supermgrd/secrets.json` whenever the suite runs as root — in a
    // container, or under `sudo cargo test` — and pointing `XDG_DATA_HOME`
    // somewhere safe does not help, because that branch is not taken. The
    // result was a test run that read, rewrote, and deleted entries in a
    // production credential file. Compiled out entirely for the daemon
    // itself: `cfg(test)` covers only this crate's own unit tests.
    #[cfg(test)]
    if let Ok(path) = std::env::var("SUPERMGRD_TEST_SECRETS_PATH") {
        return PathBuf::from(path);
    }

    if nix::unistd::getuid().is_root() {
        PathBuf::from("/etc/supermgrd/secrets.json")
    } else {
        // Non-root: development / CI path under XDG_DATA_HOME.
        let base = std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
                PathBuf::from(home).join(".local/share")
            });
        base.join("supermgrd/secrets.json")
    }
}

// ---------------------------------------------------------------------------
// Internal read / write helpers
// ---------------------------------------------------------------------------

/// Read the label->base64 map from disk.  Returns an empty map if the file
/// does not exist yet.
async fn read_map() -> Result<HashMap<String, String>> {
    let path = secrets_path();
    match tokio::fs::try_exists(&path).await {
        Ok(true) => {}
        Ok(false) => return Ok(HashMap::new()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e).with_context(|| format!("stat secrets file {}", path.display())),
    }
    let text = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("read secrets file {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("parse secrets file {}", path.display()))
}

/// Write the map to disk atomically with mode `0600`.
///
/// Sequence:
/// 1. Ensure parent directory exists.
/// 2. Serialise to a `.tmp` sibling.
/// 3. `chmod 600` the tmp file (before rename so there is no readable window).
/// 4. `rename` tmp -> target (atomic on Linux if on the same filesystem).
async fn write_map(map: &HashMap<String, String>) -> Result<()> {
    let path = secrets_path();

    // Ensure directory exists.
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .with_context(|| format!("create secrets directory {}", dir.display()))?;
    }

    // Write to a unique tmp sibling so concurrent writers can't clobber
    // each other's in-flight bytes, then rename over the target.
    let base = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("secrets.json");
    let tmp = path.with_file_name(format!("{base}.{}.{}.tmp", std::process::id(), rand::random::<u32>()));
    let text = serde_json::to_string_pretty(map).context("serialise secrets map")?;

    // `write_private` creates the file at 0600 in one step (O_CREAT|O_EXCL
    // with mode 0600), so the secret never exists at a wider mode. This is
    // the same guarantee the VPN backends rely on — see secure_file. It is
    // a blocking syscall, so run it off the async worker.
    let tmp_for_io = tmp.clone();
    let bytes = text.into_bytes();
    tokio::task::spawn_blocking(move || secure_file::write_private(&tmp_for_io, &bytes, None))
        .await
        .with_context(|| format!("spawn write of {}", tmp.display()))?
        .with_context(|| format!("write secrets tmp file {}", tmp.display()))?;

    tokio::fs::rename(&tmp, &path)
        .await
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Process-wide lock serialising read-modify-write cycles.
///
/// Each mutating call does `read_map` → mutate → `write_map`. Without a lock
/// two concurrent calls read the same snapshot, and one `rename` silently
/// wins — the other caller's secret is lost. Holding this across the whole
/// cycle makes the store behave like a single-writer file.
static MUTEX: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Persist `value` bytes under `label`, replacing any existing entry.
pub async fn store_secret(label: &str, value: &[u8]) -> Result<()> {
    let _guard = MUTEX.lock().await;
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

/// Store a pre-encoded (base64) secret directly — used by backup import
/// to avoid double-encoding.
pub async fn store_secret_raw(label: &str, base64_value: &str) -> Result<()> {
    let _guard = MUTEX.lock().await;
    let mut map = read_map().await?;
    map.insert(label.to_owned(), base64_value.to_owned());
    write_map(&map).await
}

/// Remove the entry for `label`.  No-op if the label does not exist.
pub async fn delete_secret(label: &str) -> Result<()> {
    let _guard = MUTEX.lock().await;
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

        let retrieved = retrieve_secret(label)
            .await
            .expect("retrieve_secret");
        assert_eq!(retrieved, value);

        // --- Overwrite: storing again replaces the value ---
        store_secret(label, b"new-value").await.expect("overwrite");
        let retrieved = retrieve_secret(label).await.expect("retrieve after overwrite");
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

        assert_eq!(secrets_path(), path);
        store_secret("supermgr/test/isolation", b"x").await.unwrap();
        assert!(path.exists(), "secret went somewhere else entirely");
    }
}
