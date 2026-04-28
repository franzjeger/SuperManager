//! SSH key + audit types.
//!
//! Note: the managed-host model used to live here as `SshHost` because the
//! manager started life as an SSH-only tool. As the daemon grew to drive
//! REST APIs (FortiGate, OPNsense, UniFi), RDP/VNC, and tag-based grouping,
//! the SSH-centric naming became misleading — a FortiGate is not, in any
//! useful sense, "an SSH host". The type now lives at
//! [`crate::host::Host`] and is re-exported at the crate root.

pub mod audit;
pub mod device_type;
pub mod key;

pub use device_type::DeviceType;
pub use key::{SshKey, SshKeySummary, SshKeyType};

// `AuthMethod` describes how the SSH connection authenticates and is
// genuinely SSH-specific, so it stays here. `Host` users that need it can
// either reach for `supermgr_core::AuthMethod` (re-exported at the crate
// root) or `supermgr_core::ssh::AuthMethod`.
pub use crate::host::AuthMethod;
