//! Per-area JSON-RPC handler modules.
//!
//! Each submodule contains an `impl crate::server::EngineServer { ... }`
//! block that holds the `async fn handle_*` methods routed from the big
//! `dispatch()` match in `server.rs`. Splitting them by area keeps each
//! file under a few hundred lines and makes the responsibility obvious
//! from the path. The dispatch table itself stays in `server.rs`.

pub mod ssh;
pub mod fortigate;
pub mod unifi;
pub mod compliance;
pub mod provisioning;
pub mod customer;
pub mod engagement;
pub mod discovery;
pub mod findings;
pub mod tools;
pub mod notifications;
pub mod timeline;
pub mod security_ops;
pub mod vpn;
pub mod tailscale;
