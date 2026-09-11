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
    /// Inventory DNS lookups that could not be completed; these are not scan findings.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// One host seen by a local-network scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconHost {
    /// IPv4 address.
    pub ip: String,
    /// TCP ports that accepted a connection.
    pub open_ports: Vec<u16>,
    /// Service hints; port-based names are explicitly distinguished from observed banners.
    #[serde(default)]
    pub services: Vec<ReconService>,
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

/// One discovered service, with the basis for identifying it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconService {
    /// Open TCP port.
    pub port: u16,
    /// Conventional service name, or SSH when its greeting was observed.
    pub name: String,
    /// `port` means an inference; `ssh_banner` means the server sent an SSH greeting.
    pub source: String,
    /// Observed SSH greeting; limited and stripped of control characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

/// Common port names are hints, never proof of what is listening.
pub fn service_hint(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        80 | 8080 => "HTTP",
        443 | 8443 => "HTTPS",
        445 => "SMB",
        3389 => "RDP",
        5900 => "VNC",
        53 => "DNS",
        25 | 587 => "SMTP",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        _ => "TCP",
    }
}

/// Changes are comparable only when the target and selected ports are identical.
pub fn service_changes(
    previous: &ReconScanResult,
    current: &ReconScanResult,
) -> Option<(usize, usize)> {
    use std::collections::BTreeSet;
    if previous.target != current.target || previous.ports != current.ports {
        return None;
    }
    let endpoints = |r: &ReconScanResult| -> BTreeSet<(String, u16)> {
        r.hosts
            .iter()
            .flat_map(|h| h.open_ports.iter().map(|p| (h.ip.clone(), *p)))
            .collect()
    };
    let old = endpoints(previous);
    let new = endpoints(current);
    Some((new.difference(&old).count(), old.difference(&new).count()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changes_use_endpoints_and_require_the_same_scan_scope() {
        let previous: ReconScanResult = serde_json::from_value(serde_json::json!({
            "target":"192.168.1.0/24","ports":[22,443],"started_at":"2026-09-09T00:00:00Z",
            "finished_at":"2026-09-09T00:00:01Z","hosts":[{"ip":"192.168.1.1","open_ports":[22]}]
        }))
        .unwrap();
        let mut current = previous.clone();
        current.hosts[0].open_ports = vec![443];
        assert_eq!(service_changes(&previous, &current), Some((1, 1)));
        current.ports = vec![443];
        assert_eq!(service_changes(&previous, &current), None);
    }
}
