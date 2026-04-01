//! Persistent per-user appearance settings for supermgr.
//!
//! Settings are stored as JSON at `$XDG_CONFIG_HOME/supermgr/settings.json`
//! (falling back to `~/.config/supermgr/settings.json`).  All fields are
//! optional in the file; missing fields use their defaults so that older
//! settings files remain valid after an upgrade.

use std::path::PathBuf;

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// Master password hash stored as `"salt_hex:hash_hex"`.
    /// Empty string means no master password has been set yet.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_hash: String,
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
            password_hash: String::new(),
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
// Password hashing helpers
// ---------------------------------------------------------------------------

/// Hash a password with the given hex-encoded salt using SHA-256.
fn hash_password(password: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Generate a random 16-byte salt and return it as a hex string.
fn generate_salt() -> String {
    let salt_bytes: [u8; 16] = rand::thread_rng().gen();
    salt_bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl AppSettings {
    /// Returns `true` if a master password has been configured.
    pub fn has_password(&self) -> bool {
        !self.password_hash.is_empty()
    }

    /// Verify `password` against the stored `salt:hash`.
    pub fn verify_password(&self, password: &str) -> bool {
        if self.password_hash.is_empty() {
            return false;
        }
        if let Some((salt, expected_hash)) = self.password_hash.split_once(':') {
            hash_password(password, salt) == expected_hash
        } else {
            false
        }
    }

    /// Hash and store a new master password.  Saves to disk immediately.
    pub fn set_password(&mut self, password: &str) {
        let salt = generate_salt();
        let hash = hash_password(password, &salt);
        self.password_hash = format!("{salt}:{hash}");
        self.save();
    }

    /// Remove the master password (disables the lock screen).
    pub fn clear_password(&mut self) {
        self.password_hash.clear();
        self.save();
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
    pub fn load() -> Self {
        let path = settings_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => return Self::default(),
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    /// Persist settings to disk.  Errors are silently ignored (best-effort).
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
