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

/// Which compliance baseline applies to a device, if any.
///
/// Two destinations and an explicit "neither", rather than an `Option`: the
/// difference between "run the FortiGate controls" and "run the Linux
/// controls" is not a presence check, and collapsing the third case into
/// `None` loses the ability to say *why* a host has no scan button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceDispatch {
    /// FortiGate controls, read over the REST API and CLI.
    FortigateBaseline,
    /// The CIS Linux host baseline, run as shell commands over SSH.
    LinuxBaseline,
    /// No baseline exists for this device type. Not a gap to fill by
    /// guessing — a UniFi AP is not a Linux server for CIS purposes even
    /// though it runs Linux.
    NotApplicable,
}

impl DeviceType {
    /// Which baseline to run against this device type.
    ///
    /// An allowlist with an exhaustive match, deliberately: adding a variant
    /// to [`DeviceType`] without classifying it here fails to compile, which
    /// is the point. The alternative — a `_ => NotApplicable` catch-all —
    /// would silently give every new device type no compliance coverage and no
    /// error to notice it by.
    ///
    /// Shared with the macOS app, which had this mapping in Swift and now
    /// reads it from here. Two copies would be two chances to disagree about
    /// which controls a device gets audited against.
    #[must_use]
    pub fn compliance_dispatch(&self) -> ComplianceDispatch {
        match self {
            Self::Fortigate => ComplianceDispatch::FortigateBaseline,
            Self::Linux => ComplianceDispatch::LinuxBaseline,
            Self::UniFi
            | Self::PfSense
            | Self::OpenWrt
            | Self::OpnSense
            | Self::Sophos
            | Self::Windows
            | Self::Custom => ComplianceDispatch::NotApplicable,
        }
    }

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
