//! SNMP read enumeration via shell-out to `snmpget` / `snmpwalk`.
//!
//! When SNMP is reachable and a community works (we try `public`
//! then `private`), we pull a curated set of high-value OIDs:
//!   - `1.3.6.1.2.1.1.1.0` — sysDescr (already in probes.rs)
//!   - `1.3.6.1.2.1.1.5.0` — sysName
//!   - `1.3.6.1.2.1.1.4.0` — sysContact
//!   - `1.3.6.1.2.1.1.6.0` — sysLocation
//!   - `1.3.6.1.2.1.1.3.0` — sysUptime
//!   - `1.3.6.1.2.1.25.1.6.0` — hrSystemProcesses (Windows hosts)
//!   - `1.3.6.1.2.1.2.2.1.2` — ifDescr table (interfaces)
//!
//! All of these are read-only. The whole batch finishes in
//! ~5 seconds for a responsive host. We use snmpget for scalar
//! OIDs and a single short snmpwalk for the interface table.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SnmpDetail {
    pub community: Option<String>,         // which community worked
    pub sys_descr: Option<String>,
    pub sys_name: Option<String>,
    pub sys_contact: Option<String>,
    pub sys_location: Option<String>,
    pub sys_uptime: Option<String>,
    pub interfaces: Vec<String>,           // ifDescr entries
    pub raw_count: u32,                    // total OIDs successfully read
}

/// Try `public`, then `private`. First community that responds
/// to sysDescr wins; we proceed with that community for the rest.
pub async fn walk(host: &str) -> Option<SnmpDetail> {
    for community in &["public", "private"] {
        if let Some(descr) = snmpget(host, community, "1.3.6.1.2.1.1.1.0").await {
            let mut detail = SnmpDetail {
                community: Some((*community).to_owned()),
                sys_descr: Some(descr),
                raw_count: 1,
                ..Default::default()
            };
            detail.sys_name = snmpget(host, community, "1.3.6.1.2.1.1.5.0").await;
            if detail.sys_name.is_some() { detail.raw_count += 1; }
            detail.sys_contact = snmpget(host, community, "1.3.6.1.2.1.1.4.0").await;
            if detail.sys_contact.is_some() { detail.raw_count += 1; }
            detail.sys_location = snmpget(host, community, "1.3.6.1.2.1.1.6.0").await;
            if detail.sys_location.is_some() { detail.raw_count += 1; }
            detail.sys_uptime = snmpget(host, community, "1.3.6.1.2.1.1.3.0").await;
            if detail.sys_uptime.is_some() { detail.raw_count += 1; }
            detail.interfaces = snmpwalk_iface(host, community).await;
            if !detail.interfaces.is_empty() {
                detail.raw_count += detail.interfaces.len() as u32;
            }
            return Some(detail);
        }
    }
    None
}

async fn snmpget(host: &str, community: &str, oid: &str) -> Option<String> {
    let res = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new("snmpget")
            .args(["-v", "2c", "-c", community, "-Ovq", "-t", "2", "-r", "0", host, oid])
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !res.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&res.stdout).trim().to_owned();
    if s.is_empty() {
        return None;
    }
    // -Ovq prints just the value, often quoted: "value" → strip.
    let trimmed = s.trim_matches('"').to_owned();
    Some(trimmed)
}

/// Walk ifDescr table (1.3.6.1.2.1.2.2.1.2). Returns interface
/// names. Empty if walk fails.
async fn snmpwalk_iface(host: &str, community: &str) -> Vec<String> {
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("snmpwalk")
            .args(["-v", "2c", "-c", community, "-Ovq", "-t", "2", host, "1.3.6.1.2.1.2.2.1.2"])
            .output(),
    )
    .await;
    let Ok(Ok(out)) = res else { return Vec::new(); };
    if !out.status.success() {
        return Vec::new();
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .map(|l| l.trim().trim_matches('"').to_owned())
        .filter(|l| !l.is_empty())
        .take(64) // safety cap
        .collect()
}
