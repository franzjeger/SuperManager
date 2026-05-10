//! Persistent known-hosts store for SSH host-key verification.
//!
//! Backs `SshClientHandler::check_server_key` so we don't accept whatever
//! host key the wire hands us without thought.
//!
//! ## Design
//!
//! - JSON file at `<data_dir>/known_hosts.json`, mode 0600 on Unix.
//! - One entry per `<host>:<port>` keyed by host:port string, value is the
//!   SHA-256 fingerprint of the server's public key (lowercase hex, 64 chars).
//! - First connection to a new host: record (TOFU). Subsequent connections
//!   to the same host:port REQUIRE the same fingerprint, otherwise the
//!   handler returns `Ok(false)` and russh rejects the connection.
//!
//! This is intentionally simpler than OpenSSH's `known_hosts` file format
//! (which we don't need to interop with) and intentionally stricter than
//! the previous "accept-everything" handler. A real MITM after first
//! connection now fails loudly instead of silently succeeding.
//!
//! ## Future
//!
//! When the GUI grows a "trust this host" prompt, the constructor can take
//! a callback for the unknown-host case so the user gets to see and verify
//! the fingerprint before we record it. Until then, TOFU on first sight
//! is the documented behaviour.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// In-memory cache + disk-backed map of host:port -> fingerprint.
pub struct KnownHostsStore {
    path: PathBuf,
    /// Cache so we don't re-read the file on every `check`. Synchronous
    /// `Mutex` because the SSH handler is sync at the trait level — we
    /// only ever hold this lock for a microsecond per call.
    cache: Mutex<HashMap<String, String>>,
}

#[derive(Debug)]
pub enum HostKeyCheck {
    /// First time we see this host. Caller should store the new fingerprint.
    NewHost,
    /// Host known and fingerprint matches what we have on file.
    Match,
    /// Host known but fingerprint differs. Caller MUST refuse the connection.
    Mismatch { stored: String, current: String },
}

impl KnownHostsStore {
    /// Open (or create) the store at `<data_dir>/known_hosts.json`.
    pub fn open(data_dir: &std::path::Path) -> Result<Self> {
        let path = data_dir.join("known_hosts.json");
        let cache = if path.exists() {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("parse {}", path.display()))?
        } else {
            HashMap::new()
        };
        Ok(Self {
            path,
            cache: Mutex::new(cache),
        })
    }

    /// Compute a SHA-256 fingerprint of an SSH public key's wire encoding.
    /// We use raw hex rather than OpenSSH's base64-truncated format because
    /// it's simpler and we don't need cross-tool compatibility.
    pub fn fingerprint(public_key_bytes: &[u8]) -> String {
        let digest = Sha256::digest(public_key_bytes);
        format!("{digest:x}")
    }

    /// Check the current fingerprint of `host:port` against the recorded
    /// one. Does NOT mutate the store — call `record` separately for the
    /// `NewHost` case, after any user confirmation.
    pub fn check(&self, host: &str, port: u16, current_fingerprint: &str) -> HostKeyCheck {
        let key = format!("{host}:{port}");
        let cache = self.cache.lock().unwrap();
        match cache.get(&key) {
            None => HostKeyCheck::NewHost,
            Some(stored) if stored == current_fingerprint => HostKeyCheck::Match,
            Some(stored) => HostKeyCheck::Mismatch {
                stored: stored.clone(),
                current: current_fingerprint.to_owned(),
            },
        }
    }

    /// Persist a (host, port, fingerprint) entry. Replaces any existing
    /// entry for that host:port.
    pub fn record(&self, host: &str, port: u16, fingerprint: &str) -> Result<()> {
        let key = format!("{host}:{port}");
        let mut cache = self.cache.lock().unwrap();
        cache.insert(key, fingerprint.to_owned());
        let snapshot: HashMap<String, String> = cache.clone();
        drop(cache);
        self.persist(&snapshot)
    }

    /// Forget a host. Called when the user explicitly removes a host or
    /// after a fingerprint mismatch the user has investigated.
    pub fn forget(&self, host: &str, port: u16) -> Result<()> {
        let key = format!("{host}:{port}");
        let mut cache = self.cache.lock().unwrap();
        let removed = cache.remove(&key).is_some();
        let snapshot: HashMap<String, String> = cache.clone();
        drop(cache);
        if removed {
            self.persist(&snapshot)?;
        }
        Ok(())
    }

    fn persist(&self, snapshot: &HashMap<String, String>) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(snapshot)?;
        std::fs::write(&tmp, &text)?;
        // 0600 — owner read/write only; same posture as secrets.json.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn first_check_returns_new_host() {
        let dir = TempDir::new().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();
        assert!(matches!(store.check("h", 22, "fp"), HostKeyCheck::NewHost));
    }

    #[test]
    fn record_then_match() {
        let dir = TempDir::new().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();
        store.record("h", 22, "abc123").unwrap();
        assert!(matches!(store.check("h", 22, "abc123"), HostKeyCheck::Match));
    }

    #[test]
    fn mismatch_is_loud_and_carries_both_fingerprints() {
        // The MITM scenario. We've seen the host before; today's
        // fingerprint differs; we MUST refuse and surface enough detail
        // for the user to investigate.
        let dir = TempDir::new().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();
        store.record("h", 22, "trusted-fingerprint").unwrap();
        match store.check("h", 22, "different-fingerprint") {
            HostKeyCheck::Mismatch { stored, current } => {
                assert_eq!(stored, "trusted-fingerprint");
                assert_eq!(current, "different-fingerprint");
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn record_persists_across_reopen() {
        // Reopening the store loads the disk file. A regression here
        // would defeat the whole purpose: every restart would forget
        // every host and silently re-TOFU.
        let dir = TempDir::new().unwrap();
        {
            let store = KnownHostsStore::open(dir.path()).unwrap();
            store.record("server.example.com", 2222, "fp-X").unwrap();
        }
        let store = KnownHostsStore::open(dir.path()).unwrap();
        assert!(matches!(
            store.check("server.example.com", 2222, "fp-X"),
            HostKeyCheck::Match
        ));
    }

    #[test]
    fn forget_drops_the_entry() {
        let dir = TempDir::new().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();
        store.record("h", 22, "fp").unwrap();
        store.forget("h", 22).unwrap();
        assert!(matches!(store.check("h", 22, "fp"), HostKeyCheck::NewHost));
    }

    #[test]
    fn fingerprint_is_lowercase_64_hex() {
        // Hard-pin the format so we don't accidentally start storing
        // colon-separated MD5 or anything else.
        let fp = KnownHostsStore::fingerprint(b"hello world");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Known SHA-256 of "hello world" so the algorithm doesn't drift.
        assert_eq!(
            fp,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
