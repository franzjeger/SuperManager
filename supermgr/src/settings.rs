//! Persistent per-user appearance settings for supermgr.
//!
//! Settings are stored as JSON at `$XDG_CONFIG_HOME/supermgr/settings.json`
//! (falling back to `~/.config/supermgr/settings.json`).  All fields are
//! optional in the file; missing fields use their defaults so that older
//! settings files remain valid after an upgrade.

use std::path::PathBuf;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
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
//
// New hashes use Argon2id and are stored in the PHC string format
// (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`). Older installs
// stored a `<hex_salt>:<sha256_hex>` pair; those are still verifiable for
// backwards compatibility and are auto-upgraded to Argon2id on the next
// successful unlock so an offline attacker can't crack a leaked SHA-256
// hash with a wordlist in seconds.

/// Hash a password with Argon2id and the OWASP-recommended defaults.
fn hash_argon2id(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
}

/// Verify a PHC-format Argon2 hash.
fn verify_argon2(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Constant-time-ish verification of the legacy `<hex_salt>:<sha256_hex>`
/// format. Kept only so existing installs can unlock once and have their
/// hash transparently upgraded to Argon2id.
fn verify_legacy_sha256(password: &str, salt_hex: &str, expected_hex: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(salt_hex.as_bytes());
    hasher.update(password.as_bytes());
    let computed = format!("{:x}", hasher.finalize());
    // Length check first — `eq` on differing-length strings short-circuits,
    // but the lengths are public anyway.
    computed.len() == expected_hex.len()
        && computed
            .bytes()
            .zip(expected_hex.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

impl AppSettings {
    /// Returns `true` if a master password has been configured.
    pub fn has_password(&self) -> bool {
        !self.password_hash.is_empty()
    }

    /// Verify `password` against the stored hash.
    ///
    /// Accepts both the modern Argon2id PHC string and the legacy
    /// `salt:sha256` pair from pre-Argon2 builds. Verification alone does
    /// not rewrite the stored hash; call [`Self::upgrade_legacy_hash`] from
    /// the unlock flow after a successful verify to migrate.
    pub fn verify_password(&self, password: &str) -> bool {
        if self.password_hash.is_empty() {
            return false;
        }
        if self.password_hash.starts_with("$argon2") {
            verify_argon2(password, &self.password_hash)
        } else if let Some((salt, expected_hash)) = self.password_hash.split_once(':') {
            verify_legacy_sha256(password, salt, expected_hash)
        } else {
            false
        }
    }

    /// Returns `true` when the stored hash is the legacy SHA-256 format and
    /// should be re-hashed with Argon2id at the next opportunity.
    pub fn needs_hash_upgrade(&self) -> bool {
        !self.password_hash.is_empty() && !self.password_hash.starts_with("$argon2")
    }

    /// Re-hash `password` with Argon2id and persist. Caller must verify the
    /// password against the legacy hash *first*; this routine trusts its
    /// argument and overwrites the stored hash unconditionally.
    pub fn upgrade_legacy_hash(&mut self, password: &str) {
        if let Ok(phc) = hash_argon2id(password) {
            self.password_hash = phc;
            self.save();
        }
    }

    /// Hash and store a new master password.  Saves to disk immediately.
    pub fn set_password(&mut self, password: &str) {
        match hash_argon2id(password) {
            Ok(phc) => {
                self.password_hash = phc;
                self.save();
            }
            // Argon2id failure is exceedingly rare (OOM at allocation of the
            // memory cost); leaving the previous hash in place is safer than
            // silently downgrading to an unsalted/cleartext store.
            Err(_) => {}
        }
    }

    /// Remove the master password (disables the lock screen).
    pub fn clear_password(&mut self) {
        self.password_hash.clear();
        self.save();
    }
}

#[cfg(test)]
mod password_tests {
    use super::*;

    #[test]
    fn argon2_round_trip() {
        let mut s = AppSettings::default();
        s.set_password("correct horse battery staple");
        assert!(s.password_hash.starts_with("$argon2id$"));
        assert!(s.verify_password("correct horse battery staple"));
        assert!(!s.verify_password("wrong"));
        assert!(!s.needs_hash_upgrade());
    }

    #[test]
    fn legacy_hash_verifies_and_upgrades() {
        let pw = "old-pass";
        let salt = "0123456789abcdef0123456789abcdef";
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        hasher.update(pw.as_bytes());
        let legacy = format!("{salt}:{:x}", hasher.finalize());

        let mut s = AppSettings::default();
        s.password_hash = legacy.clone();
        assert!(s.verify_password(pw));
        assert!(s.needs_hash_upgrade());

        s.upgrade_legacy_hash(pw);
        assert!(s.password_hash.starts_with("$argon2id$"));
        assert!(s.verify_password(pw));
        assert!(!s.needs_hash_upgrade());
    }

    #[test]
    fn empty_hash_rejects_everything() {
        let s = AppSettings::default();
        assert!(!s.has_password());
        assert!(!s.verify_password(""));
        assert!(!s.verify_password("anything"));
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
