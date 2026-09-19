//! Persistent SSH host-key store.
//!
//! Backs Windows SSH trust-on-first-use with
//! a `known_hosts.json` file under `%PROGRAMDATA%\SuperManager\`. Each
//! entry is keyed on `<host>:<port>` and stores the SHA-256 fingerprint
//! of the server's public key alongside its algorithm name and the
//! timestamp at which it was first seen.
//!
//! # Behaviour
//!
//! - First connection to a host → fingerprint is recorded silently
//!   (still TOFU, but now durable).
//! - Subsequent connection with the **same** fingerprint → accepted.
//! - Subsequent connection with a **different** fingerprint →
//!   refused with a typed error so the GUI can surface a clear warning.
//!
//! Compare to OpenSSH's `~/.ssh/known_hosts`: same idea, JSON format
//! rather than the OpenSSH-specific text format so other tooling can
//! read/write it without parsing a quirky line grammar.
//!
//! # Concurrency
//!
//! A single file is shared across all SSH operations. The store wraps
//! the in-memory map in `RwLock`; writes flush to disk under the write
//! lock. Concurrent reads (the common path — every connection looks up
//! its host) are lock-free against each other.

use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

/// On-disk shape of one entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Known {
    /// Server public-key algorithm name (e.g. `ssh-ed25519`).
    pub algorithm: String,
    /// SHA-256 fingerprint in the OpenSSH `SHA256:<base64>` format.
    pub fingerprint: String,
    /// First-seen timestamp, RFC 3339.
    pub first_seen: String,
}

/// File-backed known-hosts store. Cheap to clone (it's an `Arc` internally).
#[derive(Clone)]
pub struct KnownHostsStore {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    map: RwLock<HashMap<String, Known>>,
}

/// Verification verdicts.
///
/// `FirstSeen` and `Match` carry the [`Known`] record so callers can
/// inspect it (e.g. show "trusted since YYYY-MM-DD" in the GUI). Today
/// only the discriminant is consumed; the field is `#[allow(dead_code)]`d
/// rather than removed because the typed payload keeps the API stable
/// for future callers.
#[derive(Debug)]
#[allow(dead_code)]
pub enum HostKeyVerdict {
    /// Host wasn't in the store; we just added it.
    FirstSeen(Known),
    /// Host was in the store with this exact fingerprint.
    Match(Known),
    /// Host was in the store with a *different* fingerprint. Refuse the
    /// connection and surface this to the user.
    Changed {
        /// What we have on file.
        stored: Known,
        /// What the server actually presented.
        presented: Known,
    },
}

impl KnownHostsStore {
    /// Load `<root>/known_hosts.json` from disk, or create an empty
    /// store on first run.
    pub fn load_from(root: &Path) -> std::io::Result<Self> {
        let path = root.join("known_hosts.json");
        let map = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<HashMap<String, Known>>(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };
        info!(entries = map.len(), "known_hosts loaded");
        Ok(Self {
            inner: Arc::new(Inner {
                path,
                map: RwLock::new(map),
            }),
        })
    }

    /// Inspect a server key. Records the fingerprint on first sight,
    /// matches on subsequent sights, and rejects on mismatch.
    pub async fn check(
        &self,
        host: &str,
        port: u16,
        algorithm: &str,
        fingerprint: &str,
    ) -> std::io::Result<HostKeyVerdict> {
        let key = format!("{host}:{port}");
        let presented = Known {
            algorithm: algorithm.to_owned(),
            fingerprint: fingerprint.to_owned(),
            first_seen: chrono::Utc::now().to_rfc3339(),
        };
        // Fast path: read-only check for the common "exact match" case.
        {
            let map = self.inner.map.read().await;
            if let Some(known) = map.get(&key) {
                if known.fingerprint == fingerprint {
                    return Ok(HostKeyVerdict::Match(known.clone()));
                } else {
                    return Ok(HostKeyVerdict::Changed {
                        stored: known.clone(),
                        presented,
                    });
                }
            }
        }
        // Keep verification, durable replacement and cache publication in one
        // blocking transaction. Cancelling the async caller cannot release
        // the lock while a background writer still has an older snapshot.
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<HostKeyVerdict> {
            let mut map = inner.map.blocking_write();
            if let Some(known) = map.get(&key) {
                return Ok(if known.fingerprint == presented.fingerprint {
                    HostKeyVerdict::Match(known.clone())
                } else {
                    HostKeyVerdict::Changed {
                        stored: known.clone(),
                        presented,
                    }
                });
            }
            let mut snapshot = map.clone();
            snapshot.insert(key, presented.clone());
            let bytes = serde_json::to_vec_pretty(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let directory = inner.path.parent().expect("known-hosts path has a parent");
            let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
            temporary.write_all(&bytes)?;
            temporary.as_file().sync_all()?;
            temporary.persist(&inner.path).map_err(|e| e.error)?;
            *map = snapshot;
            Ok(HostKeyVerdict::FirstSeen(presented))
        })
        .await
        .map_err(|e| std::io::Error::other(format!("spawn_blocking: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupted_trust_store_is_not_silently_reset() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("known_hosts.json"), "{broken").unwrap();
        assert_eq!(
            KnownHostsStore::load_from(directory.path())
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn failed_persistence_never_trusts_an_unrecorded_key() {
        let directory = tempfile::tempdir().unwrap();
        let store = KnownHostsStore::load_from(directory.path()).unwrap();
        let path = directory.path().join("known_hosts.json");
        std::fs::create_dir(&path).unwrap();
        assert!(store
            .check("host", 22, "ssh-ed25519", "failed-key")
            .await
            .is_err());
        std::fs::remove_dir(&path).unwrap();
        assert!(matches!(
            store
                .check("host", 22, "ssh-ed25519", "real-key")
                .await
                .unwrap(),
            HostKeyVerdict::FirstSeen(_)
        ));
        let reloaded = KnownHostsStore::load_from(directory.path()).unwrap();
        assert!(matches!(
            reloaded
                .check("host", 22, "ssh-ed25519", "real-key")
                .await
                .unwrap(),
            HostKeyVerdict::Match(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_enrollments_preserve_all_acknowledged_keys() {
        let directory = tempfile::tempdir().unwrap();
        let store = KnownHostsStore::load_from(directory.path()).unwrap();
        let mut tasks = Vec::new();
        for i in 0..32 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store
                    .check(&format!("host-{i}"), 22, "ssh-ed25519", "key")
                    .await
                    .unwrap()
            }));
        }
        for task in tasks {
            assert!(matches!(task.await.unwrap(), HostKeyVerdict::FirstSeen(_)));
        }
        let reloaded = KnownHostsStore::load_from(directory.path()).unwrap();
        assert_eq!(reloaded.inner.map.read().await.len(), 32);
    }

    #[tokio::test]
    async fn conflicting_first_keys_cannot_replace_the_winner() {
        let directory = tempfile::tempdir().unwrap();
        let store = KnownHostsStore::load_from(directory.path()).unwrap();
        let (first, second) = tokio::join!(
            store.check("host", 22, "ssh-ed25519", "first"),
            store.check("host", 22, "ssh-ed25519", "second")
        );
        assert!(matches!(
            (first.unwrap(), second.unwrap()),
            (HostKeyVerdict::FirstSeen(_), HostKeyVerdict::Changed { .. })
                | (HostKeyVerdict::Changed { .. }, HostKeyVerdict::FirstSeen(_))
        ));
    }
}
