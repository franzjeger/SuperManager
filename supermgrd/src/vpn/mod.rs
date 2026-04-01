//! VPN backend implementations.
//!
//! Each module in this directory implements [`supermgr_core::vpn::backend::VpnBackend`]
//! for one protocol.  The daemon selects a backend at connect time based on the
//! [`supermgr_core::vpn::profile::ProfileConfig`] discriminant.

pub mod azure;
pub mod fortigate;
pub mod openvpn;
pub mod wireguard;

use std::sync::Arc;

use supermgr_core::{vpn::backend::VpnBackend, vpn::profile::Profile, vpn::state::TunnelStats, CoreError};

/// Read TX/RX byte counters for a network interface from sysfs.
///
/// Returns zeroed stats if the interface name is empty or the sysfs files are
/// unreadable (e.g. the interface has already been torn down).
pub(super) fn read_iface_stats(iface: &str) -> TunnelStats {
    if iface.is_empty() {
        return TunnelStats::default();
    }
    let read_u64 = |stat: &str| -> u64 {
        let path = format!("/sys/class/net/{iface}/statistics/{stat}");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    TunnelStats {
        bytes_sent: read_u64("tx_bytes"),
        bytes_received: read_u64("rx_bytes"),
        ..TunnelStats::default()
    }
}

/// Return the appropriate backend for a profile.
///
/// `auth_tx` is used only for [`supermgr_core::vpn::profile::ProfileConfig::AzureVpn`]
/// profiles: it receives `(user_code, verification_url)` when the Entra ID
/// device-code flow needs the user to authenticate.  Pass `None` (or a
/// no-op sender) for all other profile types.
///
/// # Errors
///
/// Returns [`CoreError::Internal`] if no backend is registered for the
/// profile's [`supermgr_core::vpn::profile::ProfileConfig`] variant.
pub fn backend_for_profile(
    profile: &Profile,
    auth_tx: Option<tokio::sync::mpsc::UnboundedSender<(String, String)>>,
) -> Result<Arc<dyn VpnBackend>, CoreError> {
    use supermgr_core::vpn::profile::ProfileConfig;

    match &profile.config {
        ProfileConfig::WireGuard(_) => {
            Ok(Arc::new(wireguard::WireGuardBackend::new()))
        }
        ProfileConfig::FortiGate(_) => {
            Ok(Arc::new(fortigate::FortiGateBackend::new()))
        }
        ProfileConfig::OpenVpn(_) => {
            Ok(Arc::new(openvpn::OpenVpnBackend::new()) as Arc<dyn VpnBackend>)
        }
        ProfileConfig::AzureVpn(_) => {
            // Provide a no-op sender if none was supplied (e.g. auto-reconnect
            // path where there is no GUI listening).
            let tx = auth_tx.unwrap_or_else(|| {
                let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
                tx
            });
            Ok(Arc::new(azure::AzureBackend::new(tx)) as Arc<dyn VpnBackend>)
        }
        ProfileConfig::Generic(g) => Err(CoreError::internal(format!(
            "no backend registered for generic plugin '{}'",
            g.backend_id
        ))),
    }
}
