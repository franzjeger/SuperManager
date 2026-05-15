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
/// overrides. Two scopes:
///
///   - `mac` — exact MAC address match. Wins over prefix.
///   - `oui` — three-octet OUI prefix match. Lets the
///             operator classify every UniFi device on a
///             newly-encountered Ubiquiti OUI in one stroke
///             instead of repeating per host.
///
/// Cheap to clone (Arc-shared). One global instance lives
/// on `DaemonState`.
#[derive(Debug, Clone)]
pub struct DeviceTypeOverrides {
    inner: Arc<RwLock<Inner>>,
    path: PathBuf,
}

#[derive(Debug, Default)]
struct Inner {
    /// Exact-MAC overrides. Higher priority than OUI rules.
    by_mac: HashMap<String, String>,
    /// OUI-prefix overrides (three lowercase octets,
    /// colon-separated — "58:d6:1f").
    by_oui: HashMap<String, String>,
}

/// Result of an override lookup — the type plus which scope
/// matched, so the GUI can show "via OUI rule 58:d6:1f" hover
/// help on a host whose override comes from a broader rule.
#[derive(Debug, Clone)]
pub struct OverrideHit {
    pub device_type: String,
    pub scope: OverrideScope,
    pub matched_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideScope {
    Mac,
    Oui,
}

impl OverrideScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::Oui => "oui",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct OnDisk {
    /// Legacy flat shape — older builds wrote `[overrides]`
    /// as a flat map. Honoured on load for back-compat; new
    /// writes always go to the structured shape below.
    #[serde(default)]
    overrides: HashMap<String, String>,
    /// New shape — separate tables per scope.
    #[serde(default)]
    by_mac: HashMap<String, String>,
    #[serde(default)]
    by_oui: HashMap<String, String>,
}

impl DeviceTypeOverrides {
    /// Open + load the override file from disk. A missing
    /// file produces an empty store; a malformed one logs
    /// and produces empty so the daemon still boots.
    /// Tolerates the legacy flat `[overrides]` table shape
    /// from earlier builds — those entries migrate into
    /// `by_mac` on the next save.
    pub fn open(data_dir: &std::path::Path) -> Self {
        let path = data_dir.join("device_type_overrides.toml");
        let mut inner = Inner::default();
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(d) = toml::from_str::<OnDisk>(&text) {
                inner.by_mac = d.by_mac;
                inner.by_oui = d.by_oui;
                // Migrate legacy flat shape: those keys are
                // raw MACs.
                for (k, v) in d.overrides {
                    inner.by_mac.entry(k).or_insert(v);
                }
            }
        }
        Self {
            inner: Arc::new(RwLock::new(inner)),
            path,
        }
    }

    /// Look up the override for a MAC. Returns the matching
    /// rule with provenance so the GUI can show "(via OUI
    /// rule)" vs "(exact)". Exact-MAC entries win over
    /// OUI-prefix entries.
    pub async fn get_detailed(&self, mac: &str) -> Option<OverrideHit> {
        let key = normalise_mac(mac);
        let guard = self.inner.read().await;
        if let Some(t) = guard.by_mac.get(&key) {
            return Some(OverrideHit {
                device_type: t.clone(),
                scope: OverrideScope::Mac,
                matched_key: key,
            });
        }
        if let Some(prefix) = oui_prefix(&key) {
            if let Some(t) = guard.by_oui.get(&prefix) {
                return Some(OverrideHit {
                    device_type: t.clone(),
                    scope: OverrideScope::Oui,
                    matched_key: prefix,
                });
            }
        }
        None
    }

    /// Bare-string view of `get_detailed` for callers that
    /// don't care which scope matched. Existing callers stay
    /// source-compatible.
    pub async fn get(&self, mac: &str) -> Option<String> {
        self.get_detailed(mac).await.map(|h| h.device_type)
    }

    /// Set (or clear) an override.
    ///
    /// `scope == Mac`  → uses the full MAC as key.
    /// `scope == Oui`  → uses the first three octets. Passing
    ///                    a full MAC here is fine — it's
    ///                    truncated to the prefix before the
    ///                    lookup.
    /// Passing `None` for `device_type` deletes the entry.
    /// Atomic writes (sibling .tmp + rename) on every
    /// mutation.
    pub async fn set(
        &self,
        key: &str,
        scope: OverrideScope,
        device_type: Option<&str>,
    ) -> Result<()> {
        let normalised = match scope {
            OverrideScope::Mac => normalise_mac(key),
            OverrideScope::Oui => oui_prefix(&normalise_mac(key)).unwrap_or_else(|| key.to_owned()),
        };
        {
            let mut guard = self.inner.write().await;
            let target = match scope {
                OverrideScope::Mac => &mut guard.by_mac,
                OverrideScope::Oui => &mut guard.by_oui,
            };
            match device_type {
                Some(t) => { target.insert(normalised, t.to_owned()); }
                None => { target.remove(&normalised); }
            }
        }
        self.persist().await
    }

    /// Map of both scopes for the GUI's override-list view.
    pub async fn snapshot(&self) -> SnapshotView {
        let guard = self.inner.read().await;
        SnapshotView {
            by_mac: guard.by_mac.clone(),
            by_oui: guard.by_oui.clone(),
        }
    }

    async fn persist(&self) -> Result<()> {
        let snap = self.snapshot().await;
        let on_disk = OnDisk {
            overrides: HashMap::new(),
            by_mac: snap.by_mac,
            by_oui: snap.by_oui,
        };
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

#[derive(Debug, Serialize)]
pub struct SnapshotView {
    pub by_mac: HashMap<String, String>,
    pub by_oui: HashMap<String, String>,
}

fn normalise_mac(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// Extract the first three octets of a MAC as
/// `aa:bb:cc`. Returns None for inputs that don't have at
/// least three octets.
fn oui_prefix(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split(':').take(3).collect();
    if parts.len() < 3 {
        return None;
    }
    Some(parts.join(":"))
}
