//! Platform-agnostic secrets storage.
//!
//! Two backends:
//!  - `file::FileSecretStore` — JSON map of label -> base64(bytes) on
//!    disk. Used as a Linux fallback and a development scaffold.
//!  - `keychain::KeychainSecretStore` (macOS only) — the macOS Data
//!    Protection Keychain via the Security framework. Production
//!    default on macOS. Requires a `keychain-access-groups` entitlement,
//!    which in turn requires the binary to be signed with an explicit
//!    App ID (Personal Team via Xcode + Maps capability trick is
//!    enough; full Developer ID is the long-term path).
//!
//! See `keychain::migrate_from_file` for the one-shot migration that
//! moves an existing `secrets.json` into the keychain on first run.

pub mod file;

#[cfg(target_os = "macos")]
pub mod keychain;

use std::path::PathBuf;

/// Return the default data directory for the current platform.
pub fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
        PathBuf::from(home).join("Library/Application Support/SuperManager")
    }

    #[cfg(target_os = "linux")]
    {
        if nix::unistd::getuid().is_root() {
            PathBuf::from("/etc/supermgrd")
        } else {
            let base = std::env::var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
                    PathBuf::from(home).join(".local/share")
                });
            base.join("supermgrd")
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
        PathBuf::from(home).join(".supermanager")
    }
}
