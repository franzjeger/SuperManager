//! Persistent per-user appearance settings for supermgr.
//!
//! Settings are stored as JSON at `$XDG_CONFIG_HOME/supermgr/settings.json`
//! (falling back to `~/.config/supermgr/settings.json`).  All fields are
//! optional in the file; missing fields use their defaults so that older
//! settings files remain valid after an upgrade.
//!
//! # Master password is intentionally NOT in this struct
//!
//! The Argon2id master-password hash lives in its own file
//! (`master-password.hash`) handled by [`crate::master_password`]. It used
//! to be the `password_hash` field on this struct, but every call to
//! [`Self::save`] wrote the whole struct back — so changing any unrelated
//! setting silently re-persisted the password hash that had been loaded
//! into memory at startup. That meant deleting the password from disk
//! never stuck while the GUI was running. Splitting it out makes the
//! single writer of the password hash an explicit user action, never a
//! side-effect of saving theme/opacity/RDP-client preference.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The colour scheme to request from libadwaita.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColorScheme {
    /// Follow the system / desktop preference.
    #[default]
    Default,
    /// Force a light appearance regardless of the system setting.
    Light,
    /// Force a dark appearance regardless of the system setting.
    Dark,
}

/// Serialisable application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Which colour scheme to use.
    #[serde(default)]
    pub color_scheme: ColorScheme,
    /// Window opacity in the range `[0.1, 1.0]`.
    #[serde(default = "default_opacity")]
    pub opacity: f64,
    /// Anthropic API key for the built-in Claude console.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub anthropic_api_key: String,
    /// Whether to use Claude Code CLI (subscription) instead of API key.
    #[serde(default)]
    pub use_claude_subscription: bool,
    /// Migration-only: legacy settings.json files written by builds before
    /// the master-password split contained a `password_hash` field here.
    /// We deserialise it so [`Self::load`] can hand it to
    /// [`crate::master_password::migrate_from_legacy_field`], but never
    /// serialise it again — the hash now lives in its own file. The
    /// `skip_serializing` attribute ensures every subsequent
    /// [`Self::save`] writes a settings.json without this field.
    #[serde(default, skip_serializing, rename = "password_hash")]
    legacy_password_hash: String,
    /// Minutes of inactivity before the session auto-locks.
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u64,

    // ---- Webhook / notification settings ----

    /// Webhook URL for outgoing notifications (Slack, Teams, Discord).
    /// Empty string means disabled.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub webhook_url: String,
    /// Send a webhook notification when an SSH host goes down.
    #[serde(default = "default_true")]
    pub webhook_on_host_down: bool,
    /// Send a webhook notification when a VPN tunnel disconnects unexpectedly.
    #[serde(default)]
    pub webhook_on_vpn_disconnect: bool,

    // ---- UniFi Cloud (ui.com Site Manager) ----

    /// API key for the UI.com Site Manager API (https://unifi.ui.com).
    /// Create at Settings > API Keys in Site Manager.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub unifi_cloud_api_key: String,

    // ---- Remote Desktop ----

    /// Preferred RDP client: "auto", "remmina", "xfreerdp3", "xfreerdp".
    #[serde(default = "default_rdp_client")]
    pub rdp_client: String,
}

fn default_rdp_client() -> String {
    "auto".into()
}

fn default_opacity() -> f64 {
    1.0
}

fn default_auto_lock_minutes() -> u64 {
    15
}

fn default_true() -> bool {
    true
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            color_scheme: ColorScheme::default(),
            opacity: 1.0,
            anthropic_api_key: String::new(),
            use_claude_subscription: false,
            legacy_password_hash: String::new(),
            auto_lock_minutes: 15,
            webhook_url: String::new(),
            webhook_on_host_down: true,
            webhook_on_vpn_disconnect: false,
            unifi_cloud_api_key: String::new(),
            rdp_client: "auto".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

fn settings_path() -> PathBuf {
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| {
                let mut p = PathBuf::from(h);
                p.push(".config");
                p
            })
        })
        .unwrap_or_else(|| PathBuf::from("."));
    config_dir.join("supermgr").join("settings.json")
}

impl AppSettings {
    /// Load settings from disk, falling back to defaults on any error.
    ///
    /// If the JSON contains a legacy `password_hash` field it is migrated
    /// to the dedicated `master-password.hash` file (best-effort) and a
    /// fresh save is issued so the legacy field is gone from disk on the
    /// next read.
    pub fn load() -> Self {
        let path = settings_path();
        let mut s: Self = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => return Self::default(),
        };

        if !s.legacy_password_hash.is_empty() {
            crate::master_password::migrate_from_legacy_field(&s.legacy_password_hash);
            // Drop the legacy value so the next save() doesn't include
            // it (skip_serializing already does that, but clearing the
            // in-memory copy makes the migration intent explicit).
            s.legacy_password_hash.clear();
            s.save();
        }
        s
    }

    /// Persist settings to disk.  Errors are silently ignored (best-effort).
    ///
    /// Note: this NEVER writes the master-password hash, even if a legacy
    /// file used to. The hash is owned by [`crate::master_password`] and
    /// has its own writer.
    pub fn save(&self) {
        let path = settings_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, text);
        }
    }

    /// Convert the stored colour-scheme variant into a libadwaita value.
    pub fn adw_color_scheme(&self) -> libadwaita::ColorScheme {
        match self.color_scheme {
            ColorScheme::Default => libadwaita::ColorScheme::Default,
            ColorScheme::Light => libadwaita::ColorScheme::ForceLight,
            ColorScheme::Dark => libadwaita::ColorScheme::ForceDark,
        }
    }
}
