//! VPN profile, state machine, and backend abstraction types.
//!
//! This module is a direct port of the `vpnr-core` VPN types into the
//! `supermgr-core` namespace.  Sub-modules:
//!
//! - [`profile`] — VPN profile definitions and WireGuard config import.
//! - [`state`]   — Connection state machine and tunnel statistics.
//! - [`backend`] — The [`VpnBackend`] trait and reconciliation logic.

pub mod backend;
pub mod profile;
pub mod state;

// ── Convenience re-exports ──────────────────────────────────────────────────

pub use backend::{BackendStatus, Capabilities, VpnBackend};
pub use profile::{
    AzureVpnConfig, FortiGateConfig, GenericConfig, OpenVpnConfig, Profile, ProfileConfig,
    ProfileSummary, SecretRef, WireGuardConfig, WireGuardPeer, ZeroingKey,
};
pub use state::{ErrorCode, TunnelStats, VpnState};
