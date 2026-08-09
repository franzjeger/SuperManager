//! `supermgr-core` — shared types, traits, and interface definitions.
//!
//! This crate is the shared vocabulary for the SuperManager workspace:
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`vpn`]      | VPN profile types, state machine, backend trait |
//! | [`host`]     | Managed-device model (`Host`, `HostSummary`) — used for SSH boxes, firewalls, controllers, anything we manage |
//! | [`ssh`]      | SSH-specific types: keys, audit log, authentication method, known-hosts store |
//! | [`dbus`]     | D-Bus interface constants, client proxy, error mapping (Linux only) |
//! | [`pipe`]     | Windows named-pipe client (Windows only) |
//! | [`protocol`] | Wire-format types shared by all transports |
//! | [`client`]   | Platform-selected re-export of the daemon client type |
//! | [`error`]    | Unified error hierarchy (VPN + SSH) |
//! | [`keyring`]  | Secret store trait and platform implementations |
//! | [`secret_lifecycle`] | Which secret labels an entity owns, and which are orphaned |

#![warn(missing_docs)]

#[cfg(target_os = "linux")]
pub mod dbus;
#[cfg(target_os = "windows")]
pub mod pipe;
pub mod protocol;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod client;
pub mod compliance;
pub mod error;
pub mod host;
pub mod keyring;
pub mod paths;
pub mod secret_lifecycle;
pub mod severity;
pub mod ssh;
pub mod ssh_compliance;
pub mod tailscale;
pub mod vpn;

// Re-export commonly used items at crate root.
pub use error::{BackendError, CoreError, ProfileError, SecretError, SshError};
pub use host::{AuthMethod, Host, HostSummary};
pub use secret_lifecycle::{LiveSecrets, SecretOwner};
pub use ssh::device_type::DeviceType;
pub use ssh::key::{SshKey, SshKeySummary, SshKeyType};
pub use ssh::known_hosts::{HostKeyCheck, KnownHostsStore};
pub use vpn::profile::{Profile, ProfileConfig, ProfileSummary, SecretRef};
pub use vpn::state::{ErrorCode, TunnelStats, VpnState};

