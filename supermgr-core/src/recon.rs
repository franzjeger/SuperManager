//! Safe local-network reconnaissance result types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One explicit, operator-started scan of a private IPv4 range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconScanResult {
    /// Normalized CIDR that was scanned.
    pub target: String,
    /// Ports tested on every address.
    pub ports: Vec<u16>,
    /// Start time.
    pub started_at: DateTime<Utc>,
    /// Completion time.
    pub finished_at: DateTime<Utc>,
    /// Addresses that answered or already exist in managed inventory.
    pub hosts: Vec<ReconHost>,
}

/// One host seen by a local-network scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconHost {
    /// IPv4 address.
    pub ip: String,
    /// TCP ports that accepted a connection.
    pub open_ports: Vec<u16>,
    /// Existing managed host UUID, when this address is already known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_host_id: Option<String>,
    /// Existing managed label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_label: Option<String>,
    /// Existing customer ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,
}
