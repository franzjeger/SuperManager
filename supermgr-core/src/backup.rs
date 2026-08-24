//! Portable, cross-platform configuration backup.
//!
//! One JSON shape that every platform's daemon exports to and imports
//! from, so a backup taken on macOS restores on Linux and vice versa.
//! The Linux daemon (`supermgrd`) has produced this shape — "version 3"
//! — for a while; defining it here as a typed struct lets the macOS
//! engine produce and consume the *identical* JSON, and stops the two
//! sides drifting the way an ad-hoc `serde_json::json!` on each would.
//!
//! ## What travels
//!
//! Everything the daemons hold that a restore needs: VPN profiles, SSH
//! keys and hosts, the whole secret store (`label -> base64(bytes)`:
//! WireGuard keys and PSKs, SSH private keys and passwords, API tokens,
//! and — where the caller supplies them — IKEv2/OpenVPN credentials),
//! plus GUI settings and any FortiGate config snapshots.
//!
//! ## Secret storage is the platform-specific part
//!
//! Linux keeps every secret in one file store, so its export is
//! self-contained by construction. macOS splits them: the engine's file
//! store holds WireGuard keys, SSH material, API tokens and UniFi
//! passwords, while IKEv2 and OpenVPN login credentials live in the app
//! Keychain. The `secrets` map here is just `label -> base64` and does
//! not care which store a value came from — the exporter merges both
//! sources in, and the importer routes each label back to the right
//! store for its platform. See the app's backup code for the Keychain
//! half.
//!
//! ## Sensitivity
//!
//! A populated backup contains private keys and passwords in the clear
//! (base64 is encoding, not encryption). It is exactly as sensitive as
//! the data directory it came from; callers write it 0600 and warn.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::host::Host;
use crate::ssh::key::SshKey;
use crate::vpn::profile::Profile;

/// The current backup format version. Bump only on a breaking change to
/// the field shape; `#[serde(default)]` on every collection keeps older
/// and newer readers interoperable for additive changes.
pub const BACKUP_VERSION: u32 = 3;

/// A complete, portable configuration backup.
///
/// Field names match the JSON the Linux daemon has emitted since
/// version 3, so the two are wire-compatible. Every collection is
/// `#[serde(default)]` so a backup missing a section (an older export,
/// or a platform that has nothing for it) imports cleanly rather than
/// failing to parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableBackup {
    /// Format version. See [`BACKUP_VERSION`].
    pub version: u32,

    /// RFC 3339 timestamp of when the backup was taken. Informational.
    #[serde(default)]
    pub exported_at: String,

    /// VPN profiles (WireGuard, IKEv2/FortiGate, OpenVPN, Azure).
    #[serde(default)]
    pub profiles: Vec<Profile>,

    /// SSH key metadata and material.
    #[serde(default)]
    pub ssh_keys: Vec<SshKey>,

    /// SSH hosts.
    #[serde(default)]
    pub hosts: Vec<Host>,

    /// The secret store as `label -> base64(bytes)`. The single most
    /// important section — without it, restored profiles reference key
    /// material that isn't there.
    #[serde(default)]
    pub secrets: HashMap<String, String>,

    /// GUI settings (theme, preferences). Opaque JSON — each platform's
    /// GUI owns its own shape, so this passes through untyped.
    #[serde(default)]
    pub gui_settings: serde_json::Value,

    /// FortiGate config snapshots as `filename -> contents`.
    #[serde(default)]
    pub config_backups: HashMap<String, String>,
}

impl PortableBackup {
    /// A new, empty backup stamped with the current version. Callers
    /// fill the sections they have and set `exported_at`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: BACKUP_VERSION,
            exported_at: String::new(),
            profiles: Vec::new(),
            ssh_keys: Vec::new(),
            hosts: Vec::new(),
            secrets: HashMap::new(),
            gui_settings: serde_json::Value::Null,
            config_backups: HashMap::new(),
        }
    }

    /// Total number of items across all sections — for a one-line
    /// "restored N profiles, M keys, K secrets" summary.
    #[must_use]
    pub fn counts(&self) -> BackupCounts {
        BackupCounts {
            profiles: self.profiles.len(),
            ssh_keys: self.ssh_keys.len(),
            hosts: self.hosts.len(),
            secrets: self.secrets.len(),
        }
    }
}

impl Default for PortableBackup {
    fn default() -> Self {
        Self::new()
    }
}

/// Item counts for a restore/export summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupCounts {
    /// Number of VPN profiles.
    pub profiles: usize,
    /// Number of SSH keys.
    pub ssh_keys: usize,
    /// Number of SSH hosts.
    pub hosts: usize,
    /// Number of stored secrets.
    pub secrets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_backup_round_trips_and_keeps_version() {
        let b = PortableBackup::new();
        let json = serde_json::to_string(&b).unwrap();
        let back: PortableBackup = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, BACKUP_VERSION);
        assert_eq!(back.counts(), BackupCounts { profiles: 0, ssh_keys: 0, hosts: 0, secrets: 0 });
    }

    /// Wire-compatibility with the JSON the Linux daemon emits: a
    /// `version 3` document with a secrets map and the other sections
    /// present must parse, with secrets preserved verbatim (base64).
    #[test]
    fn parses_a_linux_version3_document() {
        let json = r#"{
            "version": 3,
            "exported_at": "2026-01-02T03:04:05+00:00",
            "profiles": [],
            "ssh_keys": [],
            "hosts": [],
            "secrets": {
                "vpn/abc/wg-private-key": "a2V5Ym9keXRleHQ=",
                "vpn/abc/password": "cGFzcw=="
            },
            "gui_settings": {"theme": "dark"},
            "config_backups": {"fw1.conf": "config system"}
        }"#;
        let b: PortableBackup = serde_json::from_str(json).unwrap();
        assert_eq!(b.version, 3);
        assert_eq!(b.secrets.get("vpn/abc/password").map(String::as_str), Some("cGFzcw=="));
        assert_eq!(b.config_backups.len(), 1);
        assert_eq!(b.gui_settings["theme"], "dark");
    }

    /// A document missing whole sections (an older or minimal export)
    /// must still import — every collection defaults to empty rather
    /// than failing the parse.
    #[test]
    fn missing_sections_default_to_empty() {
        let json = r#"{ "version": 3 }"#;
        let b: PortableBackup = serde_json::from_str(json).unwrap();
        assert!(b.profiles.is_empty() && b.secrets.is_empty() && b.hosts.is_empty());
    }

    /// Unknown future fields are ignored, so a newer export still
    /// imports on an older build (forward compatibility).
    #[test]
    fn unknown_fields_are_ignored() {
        let json = r#"{ "version": 4, "brand_new_section": [1,2,3], "secrets": {"k":"dg=="} }"#;
        let b: PortableBackup = serde_json::from_str(json).unwrap();
        assert_eq!(b.version, 4);
        assert_eq!(b.secrets.get("k").map(String::as_str), Some("dg=="));
    }
}
