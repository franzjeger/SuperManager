//! Wire-level protocol shared between transports.
//!
//! Both the Linux D-Bus transport ([`crate::dbus`]) and the Windows named-pipe
//! transport ([`crate::pipe`]) carry the same logical contract: a method name,
//! a JSON-encoded argument bag, and a response that is either a JSON value or
//! a typed error.
//!
//! This module defines the framed JSON-RPC envelope used by the named-pipe
//! transport. The D-Bus transport does **not** use these envelopes — zbus
//! provides its own framing — but it does use [`RpcError`] when reporting
//! daemon-side failures back to the GUI/MCP server in a transport-agnostic
//! way.
//!
//! # Framing
//!
//! Each message is a single line of UTF-8 JSON terminated by `\n`. There is
//! no length prefix: callers and the daemon both use [`tokio::io::AsyncBufReadExt::read_line`]
//! to consume one message at a time. Maximum message size is bounded by the
//! daemon to `MAX_FRAME_BYTES` to avoid an unbounded read from a misbehaving
//! client.
//!
//! # Versioning
//!
//! The envelope carries an explicit `v` field. Bumping it allows the daemon
//! to reject clients that speak an incompatible protocol without ambiguity.
//! When introducing breaking changes, increment [`PROTOCOL_VERSION`] and add
//! a compatibility note here.

use serde::{Deserialize, Serialize};

/// Current protocol version. Bump on breaking changes to envelope shape or
/// method semantics. A daemon will refuse `PipeRequest`s carrying a version
/// it does not understand.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum single-frame size accepted by the daemon, in bytes. Anything
/// larger is treated as a protocol violation. 16 MiB is enough to round-trip
/// large config blobs (FortiGate exports, OpenVPN configs with embedded
/// certificates, full SSH key inventories) without artificial chunking.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Well-known Windows named-pipe path the daemon listens on. The
/// `\\.\pipe\` prefix is required by the Win32 named-pipe namespace.
///
/// Access is restricted to `Authenticated Users` by the daemon at creation
/// time — the pipe lives in the global namespace because the daemon runs as
/// `LocalSystem` and the GUI runs as the interactive user.
pub const PIPE_NAME: &str = r"\\.\pipe\supermgrd";

/// A method invocation sent from the client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeRequest {
    /// Protocol version. Must match [`PROTOCOL_VERSION`] on the daemon side.
    pub v: u32,
    /// Request id chosen by the client; echoed back on the response so the
    /// client can correlate concurrent in-flight calls.
    pub id: u64,
    /// Method name. Mirrors the D-Bus method names exposed by `supermgrd`
    /// on Linux (`list_hosts`, `ssh_generate_key`, `connect`, etc.) so that
    /// MCP tool handlers and the GUI can share dispatch code.
    pub method: String,
    /// Method arguments encoded as a JSON object. Positional vs named
    /// argument layout is per-method; see the dispatcher in `supermgrd-win`.
    #[serde(default)]
    pub args: serde_json::Value,
}

/// A response from the daemon. Exactly one of `result` and `error` is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeResponse {
    /// Protocol version of the daemon.
    pub v: u32,
    /// Echoed request id.
    pub id: u64,
    /// Success payload — `null` for void methods, a JSON string for methods
    /// that return JSON-encoded domain types on the existing D-Bus contract,
    /// or an array for methods like `get_logs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Failure payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// An unsolicited server-pushed event (state change, stats update,
/// auth-challenge prompt, progress message). Frames distinguish themselves
/// from `PipeResponse` by the presence of the `event` discriminator.
///
/// Events are delivered on a separate subscription pipe to keep the
/// request/response stream simple; see `pipe::EventStream`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PipeEvent {
    /// VPN state machine transitioned.
    StateChanged {
        /// Full state JSON, same shape the D-Bus signal carries.
        state_json: String,
    },
    /// Periodic tunnel stats update.
    StatsUpdated {
        /// Stats JSON.
        stats_json: String,
    },
    /// Interactive auth challenge (Azure OAuth device-flow, etc.).
    AuthChallenge {
        /// Device-flow user code.
        user_code: String,
        /// URL the user must visit to authorise.
        verification_url: String,
    },
    /// SSH long-running operation progress message.
    SshOperationProgress {
        /// Operation correlation id.
        operation_id: String,
        /// Human-readable host label.
        host_label: String,
        /// Free-form progress message.
        message: String,
    },
    /// SSH host health probe result changed.
    HostHealthChanged {
        /// Host UUID.
        host_id: String,
        /// New health JSON.
        health_json: String,
    },
}

/// Transport-agnostic error category mirroring the D-Bus FDO error groups so
/// that callers can branch on failure type regardless of OS.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", content = "msg", rename_all = "snake_case")]
pub enum RpcError {
    /// Protocol-level failure — bad version, malformed frame, unknown method.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The requested object (profile, host, key) does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The caller is not permitted to perform this action.
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// A backend operation failed (VPN connect, SSH key push, firewall rule).
    #[error("backend failure: {0}")]
    Backend(String),
    /// The secret store is unavailable or rejected the operation.
    #[error("secret store: {0}")]
    Secret(String),
    /// Any other error not covered by the above categories.
    #[error("{0}")]
    Other(String),
}

impl RpcError {
    /// Convenience constructor for [`RpcError::Other`] from any displayable
    /// value. Useful in match arms that want to forward an unexpected error
    /// with minimal ceremony.
    pub fn other<E: std::fmt::Display>(e: E) -> Self {
        Self::Other(e.to_string())
    }
}
