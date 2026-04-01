//! The [`VpnBackend`] trait that every VPN implementation must satisfy.
//!
//! The trait is object-safe (via `async_trait`) so the daemon can store a
//! `Box<dyn VpnBackend>` and swap backends at runtime without monomorphisation.
//!
//! ## Implementing a new backend
//!
//! 1. Add a new variant to [`crate::vpn::profile::ProfileConfig`].
//! 2. Create a struct in `supermgrd/src/backends/` and implement `VpnBackend` on it.
//! 3. Register the backend in `supermgrd/src/daemon.rs` `backend_for_profile()`.
//!
//! The daemon calls methods in this order:
//!
//! ```text
//! connect() → [poll status() until Connected] → disconnect()
//! ```

use async_trait::async_trait;

use crate::{
    error::BackendError,
    vpn::profile::Profile,
    vpn::state::{TunnelStats, VpnState},
};

// ---------------------------------------------------------------------------
// Backend status
// ---------------------------------------------------------------------------

/// Lightweight status snapshot returned by [`VpnBackend::status`].
///
/// This is a read from the kernel / subprocess without triggering any state
/// transition.  The daemon reconciles the returned status against its internal
/// [`VpnState`] to detect unexpected disconnects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendStatus {
    /// The backend has no active tunnel.
    Inactive,

    /// The backend is actively negotiating a tunnel.
    Negotiating {
        /// Optional progress description.
        phase: String,
    },

    /// A tunnel is established and traffic is flowing.
    Active {
        /// The kernel interface name (e.g. `wg0`).
        interface: String,
        /// Latest traffic statistics.
        stats: TunnelStats,
        /// IP address assigned to this client by the VPN (virtual IP / inner IP).
        /// Empty string if not applicable or not yet known.
        virtual_ip: String,
        /// Routes that are currently active through this tunnel (CIDR strings).
        /// Empty means the backend did not report route information.
        active_routes: Vec<String>,
    },

    /// The backend is in an error state that requires operator intervention.
    Failed {
        /// Diagnostic description.
        reason: String,
    },
}

impl BackendStatus {
    /// Returns `true` if the backend reports an active tunnel.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

// ---------------------------------------------------------------------------
// Backend capability flags
// ---------------------------------------------------------------------------

/// Declares optional capabilities of a backend implementation.
///
/// Backends should return an accurate [`Capabilities`] set so the daemon can
/// offer the right UI options (e.g. hide the "split-tunnel" toggle for backends
/// that manage routing themselves).
#[derive(Debug, Clone, Default)]
pub struct Capabilities {
    /// The backend can be configured for split-tunnel mode.
    pub split_tunnel: bool,
    /// The backend supports full-tunnel (default-route override) mode.
    pub full_tunnel: bool,
    /// The backend can push DNS servers and configure `systemd-resolved`.
    pub dns_push: bool,
    /// The backend supports persistent keepalive (to keep NAT mappings alive).
    pub persistent_keepalive: bool,
    /// The backend supports importing a vendor config file.
    pub config_import: bool,
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// Abstraction over a single VPN backend.
///
/// All methods are async and cancellation-safe (tokio semantics).  The daemon
/// serialises calls via its own state machine so concurrent calls to the same
/// backend will not occur in normal operation, but implementations should be
/// robust against unexpected cancellation (e.g. use transactions or clean up
/// in [`VpnBackend::disconnect`]).
#[async_trait]
pub trait VpnBackend: Send + Sync {
    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Establish a VPN tunnel for the given profile.
    ///
    /// The implementation **must not** return until the tunnel is fully up and
    /// traffic can flow (or until the attempt definitively fails).  The daemon
    /// calls this inside a `tokio::spawn` with a configurable timeout.
    ///
    /// Secrets referenced by [`profile`] are already resolved and available in
    /// the system keyring — backends should retrieve them via the provided
    /// keyring handle rather than doing their own keyring I/O.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::AlreadyConnected`] if a tunnel is already active.
    /// Returns [`BackendError::ConnectionFailed`] for all protocol-level failures.
    async fn connect(&self, profile: &Profile) -> Result<(), BackendError>;

    /// Tear down the active tunnel.
    ///
    /// Called both on user-initiated disconnect and on error recovery.  Must be
    /// idempotent: calling `disconnect` when no tunnel is active should return
    /// `Ok(())`, not an error.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::KernelError`] or [`BackendError::SubprocessError`]
    /// if teardown fails at the OS level (rare).
    async fn disconnect(&self) -> Result<(), BackendError>;

    // -----------------------------------------------------------------------
    // Observation
    // -----------------------------------------------------------------------

    /// Poll the current backend status without triggering state transitions.
    ///
    /// Called periodically by the daemon's monitoring loop (default: every 5 s).
    /// Implementations should be cheap: read from the kernel or parse cached
    /// subprocess output rather than issuing new IPC calls.
    ///
    /// # Errors
    ///
    /// Returns an error only if the status query itself fails (e.g. the kernel
    /// interface vanished unexpectedly).
    async fn status(&self) -> Result<BackendStatus, BackendError>;

    // -----------------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------------

    /// Returns the capabilities supported by this backend.
    ///
    /// Called once at backend construction time; the result is cached.
    fn capabilities(&self) -> Capabilities;

    /// Human-readable name for this backend (e.g. `"WireGuard"`, `"FortiGate"`).
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Reconcile a [`BackendStatus`] snapshot with the daemon's current [`VpnState`]
/// and return a new [`VpnState`] if a transition is warranted.
///
/// This is called by the daemon's status-polling loop.  `None` means "no change
/// is needed".
#[must_use]
pub fn reconcile_status(current: &VpnState, backend: &BackendStatus) -> Option<VpnState> {
    use crate::vpn::state::ErrorCode;

    match (current, backend) {
        // Tunnel was connected but the backend reports it as gone.
        (VpnState::Connected { profile_id, .. }, BackendStatus::Inactive) => {
            Some(VpnState::Error {
                profile_id: Some(*profile_id),
                code: ErrorCode::Internal,
                message: "tunnel disappeared unexpectedly".into(),
            })
        }

        // Tunnel was connected but the backend reports failure.
        (
            VpnState::Connected { profile_id, .. },
            BackendStatus::Failed { reason },
        ) => Some(VpnState::Error {
            profile_id: Some(*profile_id),
            code: ErrorCode::Internal,
            message: reason.clone(),
        }),

        // All other combinations require no daemon-side state change.
        _ => None,
    }
}
