//! JSON-RPC 2.0 protocol types for daemon communication.
//!
//! This replaces D-Bus as the IPC mechanism on macOS (and potentially Linux
//! in the future). Messages are length-prefixed JSON-RPC 2.0 frames over
//! a Unix domain socket.

use serde::{Deserialize, Serialize};

/// Wire-protocol API version. Bumped on:
///   - Major: breaking changes (renamed/removed RPC, changed required fields).
///   - Minor: additive changes (new RPC, new optional field).
/// Mac app reads this on connect via `api_version` RPC and warns
/// the user if the major version doesn't match the bundled
/// expectation (`HelperClient.expectedMajor`).
pub const API_VERSION_MAJOR: u32 = 1;
pub const API_VERSION_MINOR: u32 = 0;

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: u64,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: u64,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 notification (server → client push, no `id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

impl Response {
    /// Create a success response.
    pub fn ok(id: u64, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response.
    pub fn err(id: u64, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }
}

impl Notification {
    /// Create a notification (server push).
    pub fn new(method: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        }
    }
}

// Standard JSON-RPC error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// Typed RPC parameter structs.
///
/// These replace the previous "get the params as a `serde_json::Value`,
/// fish each field out by name with `.get(...).and_then(...)`" pattern
/// that every handler used to do at the top. The old way was repetitive,
/// untyped, and error-prone — see the `merge_host_update` regression
/// where a missing `auth_password_ref` field silently wiped the stored
/// password on every host edit. Typed structs catch that class of bug
/// at parse time, with serde-driven validation.
///
/// Convention: one struct per RPC, named `<MethodCamelCase>Params`.
/// Required fields are non-`Option`; optional fields use `Option<T>`
/// with `#[serde(default)]`. The handler dispatcher deserialises once
/// and passes the typed struct to the handler — every handler stops
/// caring about JSON shape.
///
/// We add these incrementally rather than converting the whole API at
/// once. Each new RPC, and every old RPC that gets a bug fix, adopts
/// the typed pattern. Old handlers continue to read raw `Value` until
/// they're touched.
pub mod rpc {
    use serde::Deserialize;
    use uuid::Uuid;

    /// `ssh_update_host` — the regression-prone case. The whole point of
    /// the typed struct here is to make it impossible for the handler to
    /// "see" fields that weren't sent (the old replace-the-whole-host bug)
    /// while still validating the wire shape up front.
    #[derive(Debug, Deserialize)]
    pub struct SshUpdateHostParams {
        pub host_id: Uuid,
        /// Whitelisted-fields JSON, exactly as the GUI sends it. The
        /// handler runs `merge_host_update` over it; we leave the merge
        /// logic in `serde_json::Value` form because individual field
        /// presence is the meaningful signal there.
        pub host_json: String,
    }

    /// `ssh_delete_host` — trivial param, but typed for consistency.
    #[derive(Debug, Deserialize)]
    pub struct SshDeleteHostParams {
        pub host_id: Uuid,
    }

    /// `ssh_set_password` — store an SSH password under the host's
    /// `auth_password_ref` label.
    #[derive(Debug, Deserialize)]
    pub struct SshSetPasswordParams {
        pub host_id: Uuid,
        pub password: String,
    }

    /// `ssh_test_connection` — fire-and-report SSH connect against an
    /// existing host.
    #[derive(Debug, Deserialize)]
    pub struct SshTestConnectionParams {
        pub host_id: Uuid,
    }

    /// `ssh_execute_command` — run a single command on a host and return
    /// stdout/stderr/exit.
    #[derive(Debug, Deserialize)]
    pub struct SshExecuteCommandParams {
        pub host_id: Uuid,
        pub command: String,
    }

    /// `ssh_push_key` / `ssh_revoke_key` — fan-out key operations.
    #[derive(Debug, Deserialize)]
    pub struct SshFanoutKeyParams {
        pub key_id: Uuid,
        /// JSON-encoded `Vec<Uuid>` (the GUI sends this as a string for
        /// historical reasons; a follow-up could change it to a typed
        /// array, but that's a wire-format change).
        pub host_ids_json: String,
        #[serde(default)]
        pub use_sudo: bool,
    }

    /// `vpn_get_profile` / `vpn_delete_profile` — id-only.
    #[derive(Debug, Deserialize)]
    pub struct VpnProfileIdParams {
        pub id: Uuid,
    }

    /// `vpn_add_ikev2_profile` — every editable field of a fresh profile.
    /// `dns_servers` and `routes` parse leniently (any string array, we
    /// accept FQDNs alongside IPs and let the daemon validate).
    #[derive(Debug, Deserialize)]
    pub struct VpnAddIkev2Params {
        pub name: String,
        pub host: String,
        pub username: String,
        #[serde(default = "default_full_tunnel")]
        pub full_tunnel: bool,
        #[serde(default)]
        pub kill_switch: bool,
        #[serde(default)]
        pub dns_servers: Vec<String>,
        #[serde(default)]
        pub routes: Vec<String>,
    }

    fn default_full_tunnel() -> bool {
        true
    }
}
