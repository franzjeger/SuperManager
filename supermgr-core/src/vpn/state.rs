//! VPN connection state machine types.
//!
//! The daemon maintains a single [`VpnState`] that it broadcasts over D-Bus
//! whenever it transitions.  The GUI and tray icon subscribe to the
//! `StateChanged` signal and render accordingly.
//!
//! ## State diagram
//!
//! ```text
//!                  Connect(id)
//!  Disconnected ──────────────► Connecting
//!       ▲                           │
//!       │    error                  │ tunnel up
//!       │◄──────────────────────    │
//!       │                           ▼
//!  Disconnecting ◄────────── Connected
//!       │          Disconnect()
//!       │
//!       └──► Disconnected
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Core state enum
// ---------------------------------------------------------------------------

/// The connection state as tracked by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VpnState {
    /// No tunnel is active and no connection attempt is in progress.
    Disconnected,

    /// A connection attempt is in progress for the identified profile.
    Connecting {
        /// The profile being connected.
        profile_id: Uuid,
        /// When the attempt started.
        since: DateTime<Utc>,
        /// Current human-readable phase description (e.g. `"IKE_SA_INIT"`).
        phase: String,
    },

    /// A tunnel is active.
    Connected {
        /// The connected profile.
        profile_id: Uuid,
        /// When the tunnel came up.
        since: DateTime<Utc>,
        /// The name of the active kernel interface (e.g. `wg0`).
        interface: String,
    },

    /// A graceful disconnect is in progress.
    Disconnecting {
        /// The profile being disconnected.
        profile_id: Uuid,
    },

    /// The connection attempt or active tunnel encountered a fatal error.
    Error {
        /// The affected profile, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile_id: Option<Uuid>,
        /// Machine-readable error code.
        code: ErrorCode,
        /// Human-readable description.
        message: String,
    },
}

impl VpnState {
    /// Returns `true` if a tunnel is currently established.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    /// Returns `true` if no tunnel is active and no operation is running.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        matches!(self, Self::Disconnected | Self::Error { .. })
    }

    /// Returns the active profile ID, if any operation is associated with one.
    #[must_use]
    pub fn profile_id(&self) -> Option<Uuid> {
        match self {
            Self::Connecting { profile_id, .. }
            | Self::Connected { profile_id, .. }
            | Self::Disconnecting { profile_id, .. } => Some(*profile_id),
            Self::Error { profile_id, .. } => *profile_id,
            Self::Disconnected => None,
        }
    }

    /// Short label suitable for use in the system tray tooltip.
    #[must_use]
    pub fn display_label(&self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting { .. } => "Connecting…",
            Self::Connected { .. } => "Connected",
            Self::Disconnecting { .. } => "Disconnecting…",
            Self::Error { .. } => "Error",
        }
    }
}

impl Default for VpnState {
    fn default() -> Self {
        Self::Disconnected
    }
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Machine-readable error codes for [`VpnState::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Authentication failure (wrong password, bad certificate, expired PSK).
    AuthFailed,
    /// The remote host was unreachable (network error, firewall).
    Unreachable,
    /// The connection attempt timed out.
    Timeout,
    /// The kernel refused to create or configure the interface.
    KernelError,
    /// The strongSwan helper returned an unexpected error.
    SubprocessError,
    /// The profile configuration is invalid.
    ConfigError,
    /// A required secret was not found in the keyring.
    SecretMissing,
    /// An unclassified internal error.
    Internal,
}

// ---------------------------------------------------------------------------
// Tunnel statistics
// ---------------------------------------------------------------------------

/// Live traffic statistics for an active tunnel, polled periodically by the daemon
/// and broadcast via the `StatsUpdated` D-Bus signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TunnelStats {
    /// Total bytes sent through the tunnel since it came up.
    pub bytes_sent: u64,
    /// Total bytes received through the tunnel since it came up.
    pub bytes_received: u64,
    /// Timestamp of the most recent WireGuard handshake (absent for IPsec).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_handshake: Option<DateTime<Utc>>,
    /// Round-trip time to the peer endpoint in milliseconds, if measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    /// VPN-assigned virtual IP (e.g. `10.134.2.3/24`).  Empty if not reported.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub virtual_ip: String,
    /// Routes active through this tunnel (CIDR strings).  Empty if not reported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_routes: Vec<String>,
    /// Seconds elapsed since the tunnel was established.  `0` if not tracked.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub uptime_secs: u64,
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

impl TunnelStats {
    /// Format `bytes` as a human-readable string (e.g. `"1.23 GiB"`).
    #[must_use]
    pub fn format_bytes(bytes: u64) -> String {
        const KIB: u64 = 1024;
        const MIB: u64 = KIB * 1024;
        const GIB: u64 = MIB * 1024;
        if bytes >= GIB {
            format!("{:.2} GiB", bytes as f64 / GIB as f64)
        } else if bytes >= MIB {
            format!("{:.2} MiB", bytes as f64 / MIB as f64)
        } else if bytes >= KIB {
            format!("{:.1} KiB", bytes as f64 / KIB as f64)
        } else {
            format!("{bytes} B")
        }
    }
}

// ---------------------------------------------------------------------------
// D-Bus transfer objects (JSON-serialised strings over the wire)
// ---------------------------------------------------------------------------

/// Serialise a [`VpnState`] to a JSON string for D-Bus transport.
///
/// # Errors
///
/// Returns an error if serialisation fails (should be infallible for well-formed
/// state values).
pub fn state_to_json(state: &VpnState) -> Result<String, serde_json::Error> {
    serde_json::to_string(state)
}

/// Deserialise a [`VpnState`] from a JSON string received over D-Bus.
///
/// # Errors
///
/// Returns an error if the JSON is malformed or the discriminant is unknown.
pub fn state_from_json(json: &str) -> Result<VpnState, serde_json::Error> {
    serde_json::from_str(json)
}

/// Serialise [`TunnelStats`] to a JSON string for D-Bus transport.
///
/// # Errors
///
/// Returns an error if serialisation fails.
pub fn stats_to_json(stats: &TunnelStats) -> Result<String, serde_json::Error> {
    serde_json::to_string(stats)
}

/// Deserialise [`TunnelStats`] from a JSON string received over D-Bus.
///
/// # Errors
///
/// Returns an error if the JSON is malformed.
pub fn stats_from_json(json: &str) -> Result<TunnelStats, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_disconnected() {
        let state = VpnState::Disconnected;
        let json = state_to_json(&state).unwrap();
        let back = state_from_json(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn round_trip_connected() {
        let id = Uuid::new_v4();
        let state = VpnState::Connected {
            profile_id: id,
            since: Utc::now(),
            interface: "wg0".into(),
        };
        let json = state_to_json(&state).unwrap();
        let back = state_from_json(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn format_bytes() {
        assert_eq!(TunnelStats::format_bytes(512), "512 B");
        assert_eq!(TunnelStats::format_bytes(1536), "1.5 KiB");
        assert_eq!(TunnelStats::format_bytes(2 * 1024 * 1024), "2.00 MiB");
    }
}
