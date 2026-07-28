//! Persistent known-hosts store for SSH host-key verification.
//!
//! Backs the `check_server_key` callback of every russh client handler in
//! the workspace so we don't accept whatever host key the wire hands us
//! without thought.
//!
//! ## Design
//!
//! - JSON file at `<data_dir>/known_hosts.json`, mode 0600 on Unix.
//! - One entry per `<host>:<port>` keyed by the `host:port` string, value is
//!   the SHA-256 fingerprint of the server's public key (lowercase hex, 64
//!   chars).
//! - First connection to a new host: record (TOFU). Subsequent connections
//!   to the same `host:port` REQUIRE the same fingerprint, otherwise the
//!   handler rejects the connection.
//!
//! This is intentionally simpler than OpenSSH's `known_hosts` file format
//! (which we don't need to interop with) and intentionally stricter than an
//! "accept-everything" handler. A real MITM after first connection now
//! fails loudly instead of silently succeeding.
//!
//! ## Why this lives in `supermgr-core`
//!
//! Both the Linux daemon (`supermgrd`) and the macOS engine
//! (`supermgr-engine`) open SSH sessions and both must apply the same
//! policy. It used to live in the engine only, which is how the Linux
//! daemon ended up trusting every host key it was offered. One
//! implementation, shared, so the platforms can't drift apart again.
//!
//! ## Future
//!
//! When the GUI grows a "trust this host" prompt, the constructor can take
//! a callback for the unknown-host case so the user gets to see and verify
//! the fingerprint before we record it. Until then, TOFU on first sight
//! is the documented behaviour.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors raised while reading or writing the known-hosts file.
#[derive(Debug, Error)]
pub enum KnownHostsError {
    /// The store file could not be read or written.
    #[error("known_hosts I/O error at {path}: {source}")]
    Io {
        /// The file or directory the operation was against.
        path: String,
        /// The underlying I/O failure.
        source: std::io::Error,
    },

    /// The store file exists but is not valid JSON.
    #[error("known_hosts file at {path} is corrupt: {source}")]
    Corrupt {
        /// The file that failed to parse.
        path: String,
        /// The underlying deserialisation failure.
        source: serde_json::Error,
    },
}

/// Result alias for known-hosts operations.
pub type Result<T> = std::result::Result<T, KnownHostsError>;

/// Outcome of comparing a server's presented host key against the store.
#[derive(Debug)]
pub enum HostKeyCheck {
    /// First time we see this host. Caller should store the new fingerprint.
    NewHost,
    /// Host known and fingerprint matches what we have on file.
    Match,
    /// Host known but fingerprint differs. Caller MUST refuse the connection.
    Mismatch {
        /// The fingerprint recorded on the first (trusted) connection.
        stored: String,
        /// The fingerprint the server presented just now.
        current: String,
    },
}

/// In-memory cache + disk-backed map of `host:port` -> fingerprint.
#[derive(Debug)]
pub struct KnownHostsStore {
    path: PathBuf,
    /// Cache so we don't re-read the file on every `check`. Synchronous
    /// `Mutex` because the SSH handler is sync at the trait level — we
    /// only ever hold this lock for a microsecond per call.
    cache: Mutex<HashMap<String, String>>,
}

impl KnownHostsStore {
    /// Open (or create) the store at `<data_dir>/known_hosts.json`.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("known_hosts.json");
        let cache = if path.exists() {
            let text = std::fs::read_to_string(&path).map_err(|source| KnownHostsError::Io {
                path: path.display().to_string(),
                source,
            })?;
            serde_json::from_str(&text).map_err(|source| KnownHostsError::Corrupt {
                path: path.display().to_string(),
                source,
            })?
        } else {
            HashMap::new()
        };
        Ok(Self {
            path,
            cache: Mutex::new(cache),
        })
    }

    /// Path of the backing JSON file. Useful in log lines that tell an
    /// operator where to look after a mismatch.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Compute a SHA-256 fingerprint of an SSH public key's wire encoding.
    /// We use raw hex rather than OpenSSH's base64-truncated format because
    /// it's simpler and we don't need cross-tool compatibility.
    #[must_use]
    pub fn fingerprint(public_key_bytes: &[u8]) -> String {
        // Hex-encode byte by byte. sha2 0.11's digest output is `Array`
        // (hybrid-array), which no longer implements `LowerHex` the way 0.10's
        // `GenericArray` did, so `format!("{digest:x}")` stopped compiling.
        // This produces the identical lowercase-hex string — the format is a
        // stored, compared fingerprint, so it must not shift or every recorded
        // host key would read as changed.
        Sha256::digest(public_key_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Check the current fingerprint of `host:port` against the recorded
    /// one. Does NOT mutate the store — call [`Self::record`] separately for
    /// the [`HostKeyCheck::NewHost`] case, after any user confirmation.
    #[must_use]
    pub fn check(&self, host: &str, port: u16, current_fingerprint: &str) -> HostKeyCheck {
        let key = format!("{host}:{port}");
        let cache = self.lock();
        match cache.get(&key) {
            None => HostKeyCheck::NewHost,
            Some(stored) if stored == current_fingerprint => HostKeyCheck::Match,
            Some(stored) => HostKeyCheck::Mismatch {
                stored: stored.clone(),
                current: current_fingerprint.to_owned(),
            },
        }
    }

    /// Persist a `(host, port, fingerprint)` entry. Replaces any existing
    /// entry for that `host:port`.
    pub fn record(&self, host: &str, port: u16, fingerprint: &str) -> Result<()> {
        let key = format!("{host}:{port}");
        let mut cache = self.lock();
        cache.insert(key, fingerprint.to_owned());
        let snapshot: HashMap<String, String> = cache.clone();
        drop(cache);
        self.persist(&snapshot)
    }

    /// Forget a host, so the next connection to it is treated as first
    /// sight and re-recorded.
    ///
    /// This is the documented remedy for a fingerprint mismatch that the
    /// operator has investigated and found benign — a reinstalled server, a
    /// deliberate host-key rotation, a device swapped out under the same
    /// address. Without it a legitimate rotation would lock the host out
    /// permanently.
    ///
    /// Returns `true` if an entry was actually removed, `false` if the host
    /// wasn't in the store to begin with.
    pub fn forget(&self, host: &str, port: u16) -> Result<bool> {
        let key = format!("{host}:{port}");
        let mut cache = self.lock();
        let removed = cache.remove(&key).is_some();
        let snapshot: HashMap<String, String> = cache.clone();
        drop(cache);
        if removed {
            self.persist(&snapshot)?;
        }
        Ok(removed)
    }

    /// Every recorded `("host:port", fingerprint)` pair, sorted by host.
    ///
    /// Lets the GUI show what has been trusted and offer a per-entry
    /// "forget" action instead of making the user find the JSON file.
    #[must_use]
    pub fn entries(&self) -> Vec<(String, String)> {
        let mut all: Vec<(String, String)> = self
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all
    }

    /// Take the cache lock, recovering from a poisoned mutex.
    ///
    /// A panic while the lock was held would otherwise take host-key
    /// verification down with it — and a store that can't be read is a
    /// store that accepts nothing. The data behind the lock is a plain
    /// map with no invariants to violate, so recovering is safe.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.cache.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("known_hosts cache mutex was poisoned; recovering");
            poisoned.into_inner()
        })
    }

    fn persist(&self, snapshot: &HashMap<String, String>) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| io_error(dir, e))?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let text =
            serde_json::to_string_pretty(snapshot).map_err(|source| KnownHostsError::Corrupt {
                path: self.path.display().to_string(),
                source,
            })?;
        // Write-then-rename so a crash mid-write can't leave a truncated
        // file that fails to parse on the next open.
        std::fs::write(&tmp, &text).map_err(|e| io_error(&tmp, e))?;
        // 0600 — owner read/write only; same posture as secrets.json.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| io_error(&tmp, e))?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| io_error(&self.path, e))?;
        Ok(())
    }
}

fn io_error(path: &Path, source: std::io::Error) -> KnownHostsError {
    KnownHostsError::Io {
        path: path.display().to_string(),
        source,
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
        assert!(store.forget("h", 22).unwrap());
        assert!(matches!(store.check("h", 22, "fp"), HostKeyCheck::NewHost));
    }

    #[test]
    fn forget_reports_whether_anything_was_removed() {
        // The D-Bus caller turns this bool into "forgotten" vs "no entry
        // for that host", so a wrong answer here is a wrong answer in the
        // GUI.
        let dir = TempDir::new().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();
        assert!(!store.forget("never-seen", 22).unwrap());
        store.record("seen", 22, "fp").unwrap();
        assert!(store.forget("seen", 22).unwrap());
    }

    #[test]
    fn forget_survives_reopen() {
        // Forgetting has to hit the disk, not just the cache — otherwise
        // the mismatch comes straight back on the next daemon restart and
        // the documented remedy silently doesn't work.
        let dir = TempDir::new().unwrap();
        {
            let store = KnownHostsStore::open(dir.path()).unwrap();
            store.record("h", 22, "old-fp").unwrap();
            store.forget("h", 22).unwrap();
        }
        let store = KnownHostsStore::open(dir.path()).unwrap();
        assert!(matches!(store.check("h", 22, "new-fp"), HostKeyCheck::NewHost));
    }

    #[test]
    fn ports_are_part_of_the_identity() {
        // Two SSH daemons on one address are two different hosts as far
        // as host-key verification is concerned.
        let dir = TempDir::new().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();
        store.record("h", 22, "fp-22").unwrap();
        assert!(matches!(store.check("h", 2222, "fp-22"), HostKeyCheck::NewHost));
    }

    #[test]
    fn entries_lists_everything_sorted() {
        let dir = TempDir::new().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();
        store.record("zeta", 22, "fp-z").unwrap();
        store.record("alpha", 22, "fp-a").unwrap();
        let entries = store.entries();
        assert_eq!(
            entries,
            vec![
                ("alpha:22".to_owned(), "fp-a".to_owned()),
                ("zeta:22".to_owned(), "fp-z".to_owned()),
            ]
        );
    }

    #[test]
    fn corrupt_file_is_an_error_not_an_empty_store() {
        // Silently starting empty would re-TOFU every host in the fleet,
        // which is precisely the posture this module exists to prevent.
        // The caller has to see the failure and decide.
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("known_hosts.json"), "{not json").unwrap();
        let err = KnownHostsStore::open(dir.path()).unwrap_err();
        assert!(matches!(err, KnownHostsError::Corrupt { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let store = KnownHostsStore::open(dir.path()).unwrap();
        store.record("h", 22, "fp").unwrap();
        let mode = std::fs::metadata(store.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "known_hosts.json must be 0600");
    }

    #[test]
    fn fingerprint_is_lowercase_64_hex() {
        // Hard-pin the format so we don't accidentally start storing
        // colon-separated MD5 or anything else.
        let fp = KnownHostsStore::fingerprint(b"hello world");
        assert_eq!(fp.len(), 64);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Known SHA-256 of "hello world" so the algorithm doesn't drift.
        assert_eq!(
            fp,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
