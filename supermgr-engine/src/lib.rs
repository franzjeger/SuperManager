//! `supermgr-engine` — cross-platform daemon engine for `SuperManager`.
//!
//! This crate contains the platform-independent business logic:
//! SSH operations, state management, secrets, and the JSON-RPC server.
//! It is used by `supermgrd-mac` (macOS).

pub mod asset_enrich;
pub mod azure_oauth;
pub mod azure_vpn;
pub mod compliance;
pub mod customer;
pub mod cve_feed;
pub mod device_type_overrides;
pub mod discovery;
pub mod dns_health;
pub mod error;
pub mod findings_store;
pub mod fortigate;
pub mod handlers;
pub mod netdetect;
pub mod notify;
pub mod probes;
pub mod protocol;
pub mod provisioning;
pub mod secrets;
pub mod server;
pub mod ssh;
/// The Linux CIS baseline, which lives in core now — nothing about running
/// `sshd -T` over a closure is macOS-specific, and the Linux daemon needs the
/// same check definitions rather than a second set. Re-exported so existing
/// `crate::ssh_compliance::` paths keep resolving.
pub mod ssh_compliance {
    pub use supermgr_core::ssh_compliance::*;
}
pub mod state;
pub mod subdomain_enum;
pub mod tls_pin;
pub mod tools;
pub mod unifi;
pub mod unifi_controllers;
