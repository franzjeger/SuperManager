//! Per-host port-baseline + anomaly detection.
//!
//! Stores a baseline of "normally open ports" per host and flags
//! ports that suddenly appear in a scan as anomalous. The
//! baseline is built incrementally from successive active scans:
//! a port is considered "normal" once it's been seen in N>=2
//! consecutive scans for the same host. New ports show up as
//! findings until they've stabilised, giving the operator a
//! chance to investigate "this server suddenly has port 4444
//! open" before it becomes background noise.
//!
//! # Storage
//!
//! `findings_store/<scope>/baselines/<host>.json` —
//! `{ ports: [22, 443, ...], stable_since: ISO8601, last_seen_ports: [...] }`.
//!
//! The baseline lives alongside the findings store so the same
//! per-customer scope plumbing applies (slug validation, lock,
//! atomic writes).

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::vuln::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostBaseline {
    /// Ports that have been seen in at least 2 consecutive scans
    /// — considered "normal" for this host.
    pub stable_ports: Vec<u16>,
    /// Ports seen in the latest scan only. Promoted to
    /// `stable_ports` when the next scan also reports them.
    pub pending_ports: Vec<u16>,
    pub stable_since: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

fn baselines_dir(customer_slug: &str) -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("findings_store");
    p.push(customer_slug);
    p.push("baselines");
    p
}

fn baseline_path(customer_slug: &str, host_ip: &str) -> PathBuf {
    let mut p = baselines_dir(customer_slug);
    // Use the IP itself as the file name — IPs are filesystem-safe
    // (just digits + dots / colons). Validation upstream prevents
    // arbitrary paths from leaking into this name.
    p.push(format!("{}.json", host_ip.replace('/', "_")));
    p
}

pub fn load(customer_slug: &str, host_ip: &str) -> HostBaseline {
    let path = baseline_path(customer_slug, host_ip);
    if !path.exists() { return HostBaseline::default(); }
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => HostBaseline::default(),
    }
}

pub fn save(customer_slug: &str, host_ip: &str, baseline: &HostBaseline) -> Result<()> {
    let dir = baselines_dir(customer_slug);
    std::fs::create_dir_all(&dir).context("create baselines dir")?;
    let path = baseline_path(customer_slug, host_ip);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(baseline).context("serialize baseline")?;
    std::fs::write(&tmp, bytes).with_context(|| format!("write {tmp:?}"))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("rename {path:?}"))?;
    Ok(())
}

/// Compare `observed_ports` from the latest scan against the
/// baseline for `host_ip`. Returns:
///   - findings for ports newly observed (not in stable, not in pending);
///   - findings for ports that existed before but are now missing
///     (stable port disappeared — could be a host going down OR
///     a service being stopped intentionally).
/// Side effect: persists the updated baseline.
pub fn reconcile_host(
    customer_slug: &str,
    host_ip: &str,
    observed_ports: &[u16],
) -> Result<Vec<Finding>> {
    let mut baseline = load(customer_slug, host_ip);
    let observed: HashSet<u16> = observed_ports.iter().copied().collect();
    let stable: HashSet<u16> = baseline.stable_ports.iter().copied().collect();
    let pending: HashSet<u16> = baseline.pending_ports.iter().copied().collect();

    // First-ever scan = no prior data. Promote everything to
    // pending and skip findings — we have nothing to compare to.
    let first_scan = stable.is_empty() && pending.is_empty();

    let mut findings: Vec<Finding> = Vec::new();
    let mut new_pending: Vec<u16> = Vec::new();
    let mut new_stable: Vec<u16> = baseline.stable_ports.clone();

    for &port in &observed {
        if stable.contains(&port) {
            // Already in the baseline — keep it stable.
            continue;
        }
        if pending.contains(&port) {
            // Was pending → seen again → promote to stable.
            if !new_stable.contains(&port) {
                new_stable.push(port);
            }
            continue;
        }
        // Brand new port. If first_scan, just put in pending.
        new_pending.push(port);
        if !first_scan {
            findings.push(Finding {
                id: "anomaly.new-port".into(),
                host_ip: host_ip.to_owned(),
                port: Some(port),
                service: Some("anomaly".into()),
                severity: Severity::Medium,
                title: format!("Anomalous port {port} appeared on {host_ip}"),
                detail: format!(
                    "Port {port} was not present in any prior scan baseline for this host. \
                     Common reasons: legitimate new service, attacker-deployed implant, or \
                     mis-routed scan. Investigate before adding to baseline."
                ),
                recommendation: "Confirm the service is intentional. If it is, the port will \
                                 stabilise into the baseline after the next scan.".into(),
                cve: None,
                cvss: Some(5.0),
            });
        }
    }

    // Stable ports that vanished from the latest scan. Lower
    // severity than new-port — services going down is more often
    // benign (reboot, controlled shutdown, network blip) but
    // still surfaces drift.
    for &port in &stable {
        if !observed.contains(&port) {
            findings.push(Finding {
                id: "anomaly.missing-port".into(),
                host_ip: host_ip.to_owned(),
                port: Some(port),
                service: Some("anomaly".into()),
                severity: Severity::Low,
                title: format!("Stable port {port} missing from {host_ip}"),
                detail: format!(
                    "Port {port} has been part of this host's baseline but was not detected \
                     in the latest scan. Service may be stopped or the host may be down."
                ),
                recommendation: "Verify the service is intentionally stopped. If permanent, \
                                 the next clean scan will remove it from the baseline.".into(),
                cve: None,
                cvss: Some(2.0),
            });
            // Drop the missing port from the stable list — if
            // it's intentional, future scans will reset cleanly.
            new_stable.retain(|p| *p != port);
        }
    }

    let now = Utc::now();
    let new_baseline = HostBaseline {
        stable_ports: {
            new_stable.sort_unstable();
            new_stable.dedup();
            new_stable
        },
        pending_ports: {
            new_pending.sort_unstable();
            new_pending.dedup();
            new_pending
        },
        stable_since: baseline.stable_since.or(Some(now)),
        updated_at: now,
    };
    save(customer_slug, host_ip, &new_baseline).ok();

    let _ = baseline.stable_since.is_some();  // touch to avoid dead-code lint
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_scope() -> String {
        // UUID v4 instead of timestamp — guarantees uniqueness even
        // when parallel tests start within the same nanosecond.
        format!("test-anomaly-{}", uuid::Uuid::new_v4().simple())
    }

    fn cleanup(scope: &str) {
        let dir = baselines_dir(scope);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_scan_produces_no_findings() {
        let scope = unique_scope();
        let findings = reconcile_host(&scope, "10.0.0.1", &[22, 80, 443]).unwrap();
        assert!(findings.is_empty(), "first scan establishes baseline silently");
        cleanup(&scope);
    }

    #[test]
    fn second_scan_promotes_pending_to_stable() {
        let scope = unique_scope();
        // First scan: 22 + 80 → pending.
        reconcile_host(&scope, "10.0.0.1", &[22, 80]).unwrap();
        // Second scan: same ports → promoted to stable. Still no
        // findings because nothing changed.
        let findings = reconcile_host(&scope, "10.0.0.1", &[22, 80]).unwrap();
        assert!(findings.is_empty(), "stable baseline should not produce findings");
        let baseline = load(&scope, "10.0.0.1");
        assert!(baseline.stable_ports.contains(&22));
        assert!(baseline.stable_ports.contains(&80));
        cleanup(&scope);
    }

    #[test]
    fn new_port_after_stable_baseline_flagged() {
        let scope = unique_scope();
        reconcile_host(&scope, "10.0.0.1", &[22, 80]).unwrap();
        reconcile_host(&scope, "10.0.0.1", &[22, 80]).unwrap(); // promote to stable
        // Third scan: port 4444 appears.
        let findings = reconcile_host(&scope, "10.0.0.1", &[22, 80, 4444]).unwrap();
        assert_eq!(findings.len(), 1, "exactly one new-port finding");
        assert_eq!(findings[0].id, "anomaly.new-port");
        assert_eq!(findings[0].port, Some(4444));
        cleanup(&scope);
    }

    #[test]
    fn missing_stable_port_flagged() {
        let scope = unique_scope();
        reconcile_host(&scope, "10.0.0.1", &[22, 80, 443]).unwrap();
        reconcile_host(&scope, "10.0.0.1", &[22, 80, 443]).unwrap(); // stable
        // 443 disappears.
        let findings = reconcile_host(&scope, "10.0.0.1", &[22, 80]).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "anomaly.missing-port");
        assert_eq!(findings[0].port, Some(443));
        // The dropped port should NOT be in the new stable list.
        let baseline = load(&scope, "10.0.0.1");
        assert!(!baseline.stable_ports.contains(&443));
        cleanup(&scope);
    }

    #[test]
    fn pending_port_does_not_fire_finding_yet() {
        let scope = unique_scope();
        // Create stable baseline first.
        reconcile_host(&scope, "10.0.0.1", &[22, 80]).unwrap();
        reconcile_host(&scope, "10.0.0.1", &[22, 80]).unwrap();
        // Brand new port 4444 → flagged + put in pending.
        let f1 = reconcile_host(&scope, "10.0.0.1", &[22, 80, 4444]).unwrap();
        assert_eq!(f1.len(), 1);
        // Same port appears again → promoted to stable, no new
        // finding (the port is now baseline-normal).
        let f2 = reconcile_host(&scope, "10.0.0.1", &[22, 80, 4444]).unwrap();
        assert!(f2.is_empty(), "port that's been seen twice shouldn't re-fire");
        cleanup(&scope);
    }

    #[test]
    fn baseline_persists_across_loads() {
        let scope = unique_scope();
        reconcile_host(&scope, "10.0.0.1", &[22]).unwrap();
        reconcile_host(&scope, "10.0.0.1", &[22]).unwrap();
        let loaded = load(&scope, "10.0.0.1");
        assert_eq!(loaded.stable_ports, vec![22]);
        cleanup(&scope);
    }
}
