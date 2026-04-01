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

use std::{collections::HashMap, os::unix::fs::PermissionsExt, path::PathBuf};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// Return the canonical path to the secrets JSON file.
fn secrets_path() -> PathBuf {
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
    if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return Ok(HashMap::new());
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

    let tmp = path.with_extension("tmp");
    let text = serde_json::to_string_pretty(map).context("serialise secrets map")?;

    tokio::fs::write(&tmp, text.as_bytes())
        .await
        .with_context(|| format!("write secrets tmp file {}", tmp.display()))?;

    // chmod 600 — must happen before rename.
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", tmp.display()))?;

    tokio::fs::rename(&tmp, &path)
        .await
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Persist `value` bytes under `label`, replacing any existing entry.
pub async fn store_secret(label: &str, value: &[u8]) -> Result<()> {
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
    let mut map = read_map().await?;
    map.insert(label.to_owned(), base64_value.to_owned());
    write_map(&map).await
}

/// Remove the entry for `label`.  No-op if the label does not exist.
pub async fn delete_secret(label: &str) -> Result<()> {
    let mut map = read_map().await?;
    if map.remove(label).is_some() {
        write_map(&map).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Combined test for store, retrieve, overwrite, and delete.
    ///
    /// Runs as a single test to avoid parallel env-var mutation (the
    /// `secrets_path()` function reads `XDG_DATA_HOME`).
    #[tokio::test]
    async fn store_retrieve_overwrite_delete() {
        // Use a tmp dir so we don't touch real secrets.
        let tmp = tempfile::tempdir().expect("create temp dir");
        // Keep the path alive independently of the TempDir guard so
        // the directory survives even if TempDir drops early.
        let dir = tmp.path().to_path_buf();
        std::env::set_var("XDG_DATA_HOME", &dir);

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

        // Restore env
        std::env::remove_var("XDG_DATA_HOME");
    }
}
