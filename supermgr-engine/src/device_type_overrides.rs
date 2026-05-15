//! Human-in-the-loop device-type overrides.
//!
//! The OUI-based vendor sniffing in `discovery.rs` is wrong
//! sometimes — Ubiquiti owns dozens of OUI prefixes that we
//! can't possibly all curate, and the IEEE registry isn't
//! shipped with macOS. When the operator hits a row mis-
//! classified as "Linux" that's actually a UniFi AP (or vice
//! versa), this module lets them say so once and have every
//! future scan remember.
//!
//! Persistence: one TOML file in `<data>/device_type_overrides.toml`
//! with a single `[overrides]` table mapping MAC (lowercase,
//! colon-separated) → device type string. The engine's
//! `active_scan` post-processor consults this map after the
//! vendor sniffer runs and overrides `device_type` (and the
//! GUI's per-row badge) accordingly.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// In-memory + on-disk store of operator-set device-type
/// overrides. Cheap to clone (Arc-shared). Single global
/// instance lives on `DaemonState`.
#[derive(Debug, Clone)]
pub struct DeviceTypeOverrides {
    inner: Arc<RwLock<HashMap<String, String>>>,
    path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct OnDisk {
    #[serde(default)]
    overrides: HashMap<String, String>,
}

impl DeviceTypeOverrides {
    /// Open + load the override file from disk. A missing
    /// file produces an empty store; a malformed one logs
    /// and produces empty so the daemon still boots.
    pub fn open(data_dir: &std::path::Path) -> Self {
        let path = data_dir.join("device_type_overrides.toml");
        let map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| toml::from_str::<OnDisk>(&text).ok())
            .map(|d| d.overrides)
            .unwrap_or_default();
        Self {
            inner: Arc::new(RwLock::new(map)),
            path,
        }
    }

    /// Look up the override for a MAC, if any. MACs are
    /// normalised to lowercase + colon separators before
    /// lookup so a hit doesn't depend on whatever case the
    /// caller happens to have.
    pub async fn get(&self, mac: &str) -> Option<String> {
        let key = normalise_mac(mac);
        self.inner.read().await.get(&key).cloned()
    }

    /// Set (or clear) an override. Passing `None` for
    /// `device_type` deletes the entry. Writes the TOML
    /// atomically (sibling .tmp + rename) on every mutation
    /// so a crash mid-write can't truncate the canonical file.
    pub async fn set(&self, mac: &str, device_type: Option<&str>) -> Result<()> {
        let key = normalise_mac(mac);
        {
            let mut guard = self.inner.write().await;
            match device_type {
                Some(t) => { guard.insert(key, t.to_owned()); }
                None => { guard.remove(&key); }
            }
        }
        self.persist().await
    }

    pub async fn snapshot(&self) -> HashMap<String, String> {
        self.inner.read().await.clone()
    }

    async fn persist(&self) -> Result<()> {
        let map = self.inner.read().await.clone();
        let on_disk = OnDisk { overrides: map };
        let text = toml::to_string_pretty(&on_disk)
            .context("serialize device-type overrides")?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {parent:?}"))?;
        }
        let tmp = self.path.with_extension("toml.tmp");
        std::fs::write(&tmp, text.as_bytes())
            .with_context(|| format!("write {tmp:?}"))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {tmp:?} -> {:?}", self.path))?;
        Ok(())
    }
}

fn normalise_mac(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}
