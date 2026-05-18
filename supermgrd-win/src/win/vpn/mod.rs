//! VPN backend layer (Windows).
//!
//! Each protocol gets its own backend implementing the same internal trait,
//! and the daemon picks one per profile based on the profile type.
//!
//! | Module          | Backend struct       | Routed for             | Windows mechanism |
//! |-----------------|----------------------|------------------------|-------------------|
//! | [`wireguard`]   | `WireGuardBackend`   | `ProfileConfig::WireGuard` | WireGuardNT driver via `wireguard-nt` |
//! | [`openvpn`]     | `OpenVpnBackend`     | `ProfileConfig::OpenVpn`   | `openvpn.exe` subprocess + management protocol |
//! | [`azure`]       | `Ikev2Backend`       | `ProfileConfig::AzureVpn`  | PKCE auth → generated `.ovpn` → `openvpn.exe` |
//! | [`fortigate`]   | `FortiGateBackend`   | `ProfileConfig::FortiGate` | Windows RAS via `Add-VpnConnection` + `rasdial` |
//! | [`forticlient`] | `ForticlientBackend` | `ProfileConfig::ForticlientSslvpn` | `openfortivpn.exe` subprocess + PPP-line monitor |
//!
//! All five backends are wired through `handle_connect`/`handle_disconnect`;
//! the dispatcher routes by `ProfileConfig` discriminator.

use async_trait::async_trait;

pub mod azure;
pub mod fortigate;
pub mod forticlient;
/// Backwards-compatibility alias — the daemon's slot is named `ikev2`
/// from when this backend was a stub doing IKEv2 via PowerShell. The
/// real implementation under `azure` is the Azure P2S OpenVPN flow.
pub use azure as ikev2;
pub mod openvpn;
pub mod wireguard;

/// Outcome of a VPN operation on Windows. Carries enough detail for the
/// daemon to map it back to a [`supermgr_core::protocol::RpcError`].
#[derive(Debug, thiserror::Error)]
pub enum VpnError {
    /// The backend exists but the requested operation hasn't been
    /// implemented yet. Used by skeleton stubs.
    #[error("not implemented on Windows: {0}")]
    NotImplemented(&'static str),
    /// A subprocess (openvpn.exe, openfortivpn) exited non-zero.
    #[error("subprocess exited {code}: {stderr}")]
    Subprocess {
        /// Process exit code.
        code: i32,
        /// Captured stderr.
        stderr: String,
    },
    /// A required external tool isn't installed (driver, binary).
    #[error("missing dependency: {0}")]
    MissingDependency(String),
    /// A Win32 API call failed.
    #[error("win32: {0}")]
    Win32(String),
    /// Authentication was rejected upstream (Azure auth failure,
    /// FortiGate EAP rejected, etc.). Maps to
    /// [`supermgr_core::protocol::RpcError::PermissionDenied`].
    #[error("authentication rejected: {0}")]
    PermissionDenied(&'static str),
    /// Catch-all for unexpected I/O or system errors.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Per-backend trait. Every protocol implements this; the daemon picks
/// the concrete type based on the profile.
#[async_trait]
pub trait VpnBackend: Send + Sync {
    /// Bring the tunnel up. The `profile_json` argument is the profile's
    /// on-disk JSON, identical to the format the Linux daemon stores.
    async fn connect(&self, profile_json: &str) -> Result<(), VpnError>;

    /// Tear the tunnel down. Idempotent — calling twice is not an error.
    async fn disconnect(&self) -> Result<(), VpnError>;

    /// Return a JSON status blob in the shape the GUI expects (`state`,
    /// `profile_id`, `stats`). Stubs return `{ "state": "Disconnected" }`.
    async fn status(&self) -> Result<String, VpnError>;
}
