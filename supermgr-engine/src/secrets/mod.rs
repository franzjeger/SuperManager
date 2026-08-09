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


// Lives in `supermgr-core::paths` now: the Linux daemon needs the same answer
// and does not depend on this crate. Re-exported so `secrets::default_data_dir`
// keeps resolving at every existing call site.
pub use supermgr_core::paths::default_data_dir;
