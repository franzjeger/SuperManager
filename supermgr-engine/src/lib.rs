//! `supermgr-engine` — cross-platform daemon engine for SuperManager.
//!
//! This crate contains the platform-independent business logic:
//! SSH operations, state management, secrets, and the JSON-RPC server.
//! It is used by both `supermgrd` (Linux) and `supermgrd-mac` (macOS).

pub mod activity_log;
pub mod anomaly;
pub mod asset_enrich;
pub mod azure_oauth;
pub mod azure_vpn;
pub mod compliance;
pub mod creds;
pub mod customer;
pub mod cve_feed;
pub mod discovery;
pub mod dns_axfr;
pub mod dns_health;
pub mod engagement;
pub mod error;
pub mod findings_store;
pub mod fortigate;
pub mod handlers;
pub mod ldap_enum;
pub mod netdetect;
pub mod notify;
pub mod operations;
pub mod tools;
pub mod probes;
pub mod protocol;
pub mod provisioning;
pub mod remediation;
pub mod report;
pub mod risk;
pub mod scheduler;
pub mod subdomain_enum;
pub mod secrets;
pub mod server;
pub mod smb_enum;
pub mod snmp_walk;
pub mod ssh;
pub mod ssh_compliance;
pub mod state;
pub mod unifi;
pub mod vuln;
pub mod waf_detect;
pub mod web_paths;
