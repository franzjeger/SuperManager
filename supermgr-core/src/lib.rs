//! `supermgr-core` — shared types, traits, and D-Bus interface definitions.
//!
//! This crate is the shared vocabulary for the SuperManager workspace:
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`vpn`]      | VPN profile types, state machine, backend trait |
//! | [`ssh`]      | SSH key, host, device type, and audit types |
//! | [`dbus`]     | D-Bus interface constants, client proxy, error mapping |
//! | [`error`]    | Unified error hierarchy (VPN + SSH) |
//! | [`keyring`]  | Secret store trait and libsecret implementation |

#![warn(missing_docs)]

pub mod dbus;
pub mod error;
pub mod keyring;
pub mod ssh;
pub mod vpn;

// Re-export commonly used items at crate root.
pub use error::{BackendError, CoreError, ProfileError, SecretError, SshError};
pub use vpn::profile::{Profile, ProfileConfig, ProfileSummary, SecretRef};
pub use vpn::state::{ErrorCode, TunnelStats, VpnState};
pub use ssh::key::{SshKey, SshKeySummary, SshKeyType};
pub use ssh::host::{AuthMethod, SshHost, SshHostSummary};
pub use ssh::device_type::DeviceType;

