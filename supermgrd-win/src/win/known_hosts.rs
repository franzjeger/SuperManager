//! Persistent SSH host-key store.
//!
//! Replaces the trust-on-first-use behaviour of [`super::ssh_exec`] with
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
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

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
        let map = if path.exists() {
            let bytes = std::fs::read(&path)?;
            serde_json::from_slice::<HashMap<String, Known>>(&bytes)
                .unwrap_or_else(|e| {
                    warn!(
                        "known_hosts.json is corrupt ({e}); starting with an empty store"
                    );
                    HashMap::new()
                })
        } else {
            HashMap::new()
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
        // Slow path: insert + persist under the write lock.
        let mut map = self.inner.map.write().await;
        // Re-check in case another writer raced us to the insert.
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
        map.insert(key, presented.clone());
        // Flush. The store is small (typically <100 hosts) so a full
        // rewrite per insert is acceptable; if it grows we can switch
        // to an append-only log.
        let snapshot: HashMap<String, Known> = map.clone();
        drop(map);
        let path = self.inner.path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec_pretty(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            std::fs::write(&path, bytes)
        })
        .await
        .map_err(|e| std::io::Error::other(format!("spawn_blocking: {e}")))??;
        Ok(HostKeyVerdict::FirstSeen(presented))
    }
}
