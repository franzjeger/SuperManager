//! Per-area JSON-RPC handler modules.
//!
//! Each submodule contains an `impl crate::server::EngineServer { ... }`
//! block that holds the `handle_*` methods routed from the big
//! `dispatch()` match in `server.rs`. Splitting them by area keeps each
//! file under a few hundred lines and makes the responsibility obvious
//! from the path. The dispatch table itself stays in `server.rs`.
//!
//! Every handler is a method of the server, including those that read
//! nothing from it: where a handler lives says what it is, not what it
//! happens to touch today.
#![expect(
    clippy::unused_self,
    reason = "every RPC handler is a method of the server; see above"
)]

pub mod backup;
pub mod compliance;
pub mod customer;
pub mod discovery;
pub mod engagement;
pub mod findings;
pub mod fortigate;
pub mod notifications;
pub mod operations;
pub mod provisioning;
pub mod security_ops;
pub mod ssh;
pub mod tailscale;
pub mod timeline;
pub mod tools;
pub mod unifi;
pub mod vpn;
