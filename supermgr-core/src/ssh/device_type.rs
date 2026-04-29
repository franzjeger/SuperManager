//! Device type classification for SSH hosts.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The kind of device behind an SSH host.
///
/// Some device types require special handling when deploying keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// Standard Linux/Unix server (default).
    #[default]
    Linux,
    /// Ubiquiti UniFi device.
    UniFi,
    /// pfSense firewall.
    PfSense,
    /// OPNsense firewall (FreeBSD-based fork of pfSense, distinct REST API).
    OpnSense,
    /// Sophos XG / SFOS firewall.
    Sophos,
    /// OpenWrt router.
    OpenWrt,
    /// Fortinet FortiGate appliance.
    Fortigate,
    /// Microsoft Windows (OpenSSH server).
    Windows,
    /// User-defined device type.
    Custom,
}

impl DeviceType {
    /// Returns a warning message for device types that require manual key
    /// deployment steps, or `None` if automated deployment is supported.
    pub fn warning_message(&self) -> Option<&'static str> {
        match self {
            Self::UniFi => Some("Keys must be added via UniFi Controller GUI"),
            Self::Fortigate => Some("Keys must be added via FortiGate GUI or CLI"),
            Self::OpnSense => Some(
                "Keys must be added via OPNsense → System → Access → Users",
            ),
            Self::Sophos => Some(
                "Keys must be added via Sophos Webadmin → Authentication → Users",
            ),
            _ => None,
        }
    }
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
            Self::UniFi => write!(f, "UniFi"),
            Self::PfSense => write!(f, "pfSense"),
            Self::OpnSense => write!(f, "OPNsense"),
            Self::Sophos => write!(f, "Sophos"),
            Self::OpenWrt => write!(f, "OpenWrt"),
            Self::Fortigate => write!(f, "FortiGate"),
            Self::Windows => write!(f, "Windows"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}
