//! Network discovery — passive and active.
//!
//! # Phase A (this module): passive
//!
//! - **ARP cache** — `arp -an` reads the kernel's ARP table for
//!   hosts the OS already knows about. Zero packets sent.
//! - **mDNS browse** — `dns-sd -B _services._dns-sd._udp` lists
//!   all advertised service types on the local link, then per
//!   type we resolve to (host, port). Multicast — no per-host
//!   probes.
//! - **Local interfaces** — `getifaddrs` (via `nix` or shell-out
//!   to `ifconfig`) tells us the Mac's own subnets.
//! - **OUI lookup** — IEEE OUI-database (bundled CSV) maps the
//!   MAC vendor for every discovered host. Helps the GUI label
//!   things like "Apple, Inc." / "Ubiquiti Networks Inc.".
//!
//! # Why shell-out to `arp` / `dns-sd`?
//!
//! macOS doesn't expose stable Rust APIs for these. `dns-sd` is
//! the system command for mDNS Service Discovery and gives us
//! exactly the data we want with zero dependencies. `arp -an`
//! has been stable since the BSD era — easy to parse, no risk
//! of API drift.
//!
//! # Active scanning (Phase B+) lives in a future module.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::state::DaemonState;

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscoveredHost {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    /// MAC vendor from OUI lookup ("Apple, Inc.", "Ubiquiti Networks", …).
    pub vendor: Option<String>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Services advertised via mDNS or detected via banner-grab.
    /// In Phase A only mDNS-advertised services populate this.
    #[serde(default)]
    pub services: Vec<DiscoveredService>,
    /// Aggregated source list ("arp", "mdns", "tailscale", "interface").
    /// Helps the GUI explain *how* we know about this host.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Reverse-DNS hostname from PTR lookup (best-effort, may be
    /// `None` if the resolver doesn't know the host or we hit the
    /// timeout). Distinct from `hostname` which is the mDNS-advertised
    /// instance name.
    #[serde(default)]
    pub reverse_dns: Option<String>,
    /// RFC zone classification — "internal" / "public" / "loopback" / etc.
    /// Tells the operator at a glance whether a finding is
    /// publicly exposed.
    #[serde(default)]
    pub zone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredService {
    pub port: u16,
    pub protocol: String,    // "tcp" / "udp"
    pub service_type: String, // "ssh" / "http" / "_unifi._tcp" / etc.
    pub instance_name: Option<String>, // mDNS instance name if any
    pub txt_records: Vec<String>,      // mDNS TXT record entries
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalInterface {
    pub name: String,
    pub mac: Option<String>,
    pub ipv4: Option<String>,
    pub cidr: Option<String>,
    pub ipv6: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveScanResult {
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: chrono::DateTime<chrono::Utc>,
    pub local_interfaces: Vec<LocalInterface>,
    pub hosts: Vec<DiscoveredHost>,
    /// Engagement id this scan was run under, if any. Surfaces
    /// in audit log + report headers.
    pub engagement_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Passive scan entry point
// ---------------------------------------------------------------------------

/// Run a complete passive discovery sweep. Three concurrent
/// data-collection tasks: ARP-cache parse, mDNS browse,
/// interface enumeration. Results are merged by IP into a
/// single host list; persistent inventory is updated and the
/// merged result is returned.
pub async fn passive_scan(
    state: &Arc<Mutex<DaemonState>>,
    customer_slug: Option<&str>,
    engagement_id: Option<&str>,
) -> Result<PassiveScanResult> {
    let started_at = chrono::Utc::now();

    let (arp_r, mdns_r, ifaces_r) = tokio::join!(
        scan_arp_cache(),
        scan_mdns(),
        list_local_interfaces(),
    );
    let arp_hosts = arp_r.unwrap_or_else(|e| {
        warn!("arp scan failed: {e:#}");
        Vec::new()
    });
    let mdns_hosts = mdns_r.unwrap_or_else(|e| {
        warn!("mdns scan failed: {e:#}");
        Vec::new()
    });
    let local_interfaces = ifaces_r.unwrap_or_else(|e| {
        warn!("interface enumeration failed: {e:#}");
        Vec::new()
    });

    // Merge by IP. mDNS-only hosts (no ARP entry yet) get added;
    // ARP-only hosts (no mDNS advertisement) keep their entry.
    let mut by_ip: HashMap<String, DiscoveredHost> = HashMap::new();
    for h in arp_hosts {
        by_ip.insert(h.ip.clone(), h);
    }
    for m in mdns_hosts {
        if let Some(existing) = by_ip.get_mut(&m.ip) {
            // Merge: keep ARP MAC + vendor, append mDNS services + hostname.
            if existing.hostname.is_none() {
                existing.hostname = m.hostname.clone();
            }
            for service in m.services {
                existing.services.push(service);
            }
            if !existing.sources.contains(&"mdns".to_owned()) {
                existing.sources.push("mdns".into());
            }
        } else {
            by_ip.insert(m.ip.clone(), m);
        }
    }

    // Apply OUI lookup to fill `vendor` for every host with a MAC.
    let vendors = oui_database();
    for host in by_ip.values_mut() {
        if let Some(ref mac) = host.mac {
            if host.vendor.is_none() {
                host.vendor = lookup_oui(&vendors, mac);
            }
        }
    }

    let mut hosts: Vec<DiscoveredHost> = by_ip.into_values().collect();
    hosts.sort_by(|a, b| a.ip.cmp(&b.ip));

    // Asset enrichment pass — reverse-DNS + zone classification
    // for every IP. Bounded to ~8s total via internal semaphores
    // (16 in-flight × 2s timeout each), so a slow resolver can't
    // wedge the scan.
    {
        let ips: Vec<String> = hosts.iter().map(|h| h.ip.clone()).collect();
        let enrichment = crate::asset_enrich::enrich_many(&ips).await;
        let by_ip: HashMap<String, &crate::asset_enrich::AssetEnrichment> =
            enrichment.iter().map(|e| (e.ip.clone(), e)).collect();
        for host in hosts.iter_mut() {
            if let Some(en) = by_ip.get(&host.ip) {
                host.reverse_dns = en.reverse_dns.clone();
                host.zone = Some(en.zone.label().to_owned());
            }
        }
    }

    let result = PassiveScanResult {
        started_at,
        finished_at: chrono::Utc::now(),
        local_interfaces,
        hosts: hosts.clone(),
        engagement_id: engagement_id.map(str::to_owned),
    };

    // Persist into customer inventory if a customer was provided.
    if let Some(slug) = customer_slug {
        if let Err(e) = persist_inventory(slug, &hosts) {
            warn!("inventory persist failed: {e:#}");
        }
    }

    // Append to engagement audit log if applicable.
    if let Some(eid) = engagement_id {
        let _ = crate::engagement::log_event(
            eid,
            crate::engagement::EngagementEvent {
                at: chrono::Utc::now(),
                technique: crate::engagement::Technique::Recon,
                target: customer_slug.unwrap_or("local").to_owned(),
                action: "passive_scan".to_owned(),
                findings: result.hosts.len() as u32,
                notes: format!("{} hosts discovered", result.hosts.len()),
            },
        );
    }

    info!(
        "passive_scan: {} hosts ({} interfaces) in {}ms",
        result.hosts.len(),
        result.local_interfaces.len(),
        (result.finished_at - result.started_at).num_milliseconds()
    );
    let _ = state; // future-proof signature; state will drive scope filtering later
    Ok(result)
}

// ---------------------------------------------------------------------------
// ARP cache parser
// ---------------------------------------------------------------------------

async fn scan_arp_cache() -> Result<Vec<DiscoveredHost>> {
    let output = tokio::process::Command::new("arp")
        .args(["-an"])
        .output()
        .await
        .context("run arp -an")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "arp -an exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(parse_arp(&stdout))
}

/// Parse the macOS `arp -an` format:
///   `? (10.0.10.1) at 0:11:32:aa:bb:cc on en0 ifscope [ethernet]`
/// Each line → one host. Skips "incomplete" entries and broadcast.
fn parse_arp(text: &str) -> Vec<DiscoveredHost> {
    let now = chrono::Utc::now();
    let mut out = Vec::new();
    for line in text.lines() {
        // Quick filter — must contain "at" and not "incomplete".
        if !line.contains(" at ") || line.contains("(incomplete)") {
            continue;
        }
        // Parse "? (IP) at MAC on IFACE …"
        let ip = match extract_between(line, '(', ')') {
            Some(s) => s,
            None => continue,
        };
        let mac = match line.split(" at ").nth(1) {
            Some(rest) => match rest.split_whitespace().next() {
                Some(s) => normalize_mac(s),
                None => continue,
            },
            None => continue,
        };
        // Skip multicast / broadcast.
        if mac == "ff:ff:ff:ff:ff:ff" || mac.starts_with("01:00:5e") {
            continue;
        }
        out.push(DiscoveredHost {
            ip: ip.to_owned(),
            mac: Some(mac),
            hostname: None,
            vendor: None,
            first_seen: now,
            last_seen: now,
            services: Vec::new(),
            sources: vec!["arp".into()],
            reverse_dns: None,
            zone: None,
        });
    }
    out
}

fn extract_between(s: &str, start: char, end: char) -> Option<&str> {
    let i = s.find(start)?;
    let j = s[i..].find(end)?;
    Some(&s[i + 1..i + j])
}

/// Normalise a MAC to lowercase colon-separated form. Inputs
/// like `0:11:32:aa:bb:cc` get zero-padded to `00:11:32:aa:bb:cc`.
fn normalize_mac(raw: &str) -> String {
    raw.split(':')
        .map(|seg| {
            let s = seg.trim().to_lowercase();
            if s.len() == 1 {
                format!("0{s}")
            } else {
                s
            }
        })
        .collect::<Vec<_>>()
        .join(":")
}

// ---------------------------------------------------------------------------
// mDNS browser
// ---------------------------------------------------------------------------

/// Enumerate mDNS services in two passes:
///   1. `dns-sd -B _services._dns-sd._udp local.` lists service
///      types being advertised on the local network.
///   2. For each service type, `dns-sd -B <type>` enumerates
///      instances; we then `dns-sd -L` to resolve each to a
///      (host, port).
///
/// Ten-second time budget total — mDNS responses arrive fast
/// in <1 second, longer waits don't help.
async fn scan_mdns() -> Result<Vec<DiscoveredHost>> {
    let timeout = Duration::from_secs(8);
    let interesting_types = [
        "_http._tcp",
        "_https._tcp",
        "_ssh._tcp",
        "_smb._tcp",
        "_ipp._tcp",
        "_ipps._tcp",
        "_printer._tcp",
        "_unifi._tcp",
        "_ubnt._tcp",
        "_workstation._tcp",
        "_airplay._tcp",
        "_raop._tcp",
        "_homekit._tcp",
        "_hap._tcp",
        "_companion-link._tcp",
        "_apple-mobdev2._tcp",
        "_googlecast._tcp",
        "_device-info._tcp",
        "_nfs._tcp",
        "_afpovertcp._tcp",
        "_rdp._tcp",
        "_telnet._tcp",
    ];

    // For each type, run `dns-sd -B <type>` for ~1 second, parse
    // discovered instance names. We can't do `dns-sd -L` inline
    // safely (it never exits) — for v1 we just record presence.
    let mut hosts: HashMap<String, DiscoveredHost> = HashMap::new();
    let now = chrono::Utc::now();

    for service_type in &interesting_types {
        let result = tokio::time::timeout(
            Duration::from_millis(800),
            run_dns_sd_browse(service_type),
        )
        .await;
        let entries = match result {
            Ok(Ok(v)) => v,
            _ => continue,
        };
        for entry in entries {
            // entry: (instance_name, hostname-ish, ip, port)
            let key = entry.ip.clone().unwrap_or_else(|| entry.instance.clone());
            let host = hosts.entry(key.clone()).or_insert(DiscoveredHost {
                ip: entry.ip.clone().unwrap_or_default(),
                mac: None,
                hostname: entry.host.clone(),
                vendor: None,
                first_seen: now,
                last_seen: now,
                services: Vec::new(),
                sources: vec!["mdns".into()],
                reverse_dns: None,
                zone: None,
            });
            host.services.push(DiscoveredService {
                port: entry.port.unwrap_or(0),
                protocol: "tcp".into(),
                service_type: (*service_type).to_owned(),
                instance_name: Some(entry.instance.clone()),
                txt_records: entry.txt_records,
            });
            if host.hostname.is_none() {
                host.hostname = entry.host.clone();
            }
        }
        // Tiny cooperative yield so we don't monopolise the
        // executor when many service types are queried in a row.
        tokio::task::yield_now().await;
        let _ = timeout;
    }

    Ok(hosts.into_values().collect())
}

#[derive(Debug, Default, Clone)]
struct MdnsEntry {
    instance: String,
    host: Option<String>,
    ip: Option<String>,
    port: Option<u16>,
    txt_records: Vec<String>,
}

/// Run `dns-sd -B <type>` briefly to capture instances of a
/// service type. Output format:
///   `Browsing for _ssh._tcp.local`
///   `DATE   IF Domain   Service Type   Instance Name`
///   `... 12 en0 local.  _ssh._tcp.   MyMac`
///
/// We collect instance names + their resolved (host, ip, port)
/// in a follow-up `dns-sd -L`.
async fn run_dns_sd_browse(service_type: &str) -> Result<Vec<MdnsEntry>> {
    let domain = format!("{service_type}.local");
    let mut child = tokio::process::Command::new("dns-sd")
        .args(["-B", service_type, "local."])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawn dns-sd")?;

    // Let it run briefly; mDNS responses arrive within ~200ms.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let _ = child.start_kill();
    let output = child.wait_with_output().await.context("dns-sd output")?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let mut instances: Vec<MdnsEntry> = Vec::new();
    for line in stdout.lines() {
        // Skip header lines.
        if line.starts_with("Browsing for") || line.contains("DATE") || line.trim().is_empty() {
            continue;
        }
        // Format: "<timestamp> <flags> <iface> <domain> <type> <instance>"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let instance_name = parts[5..].join(" ");
        instances.push(MdnsEntry {
            instance: instance_name,
            host: None,
            ip: None,
            port: None,
            txt_records: Vec::new(),
        });
    }

    // For each instance, resolve hostname + IP via dns-sd -L.
    let mut resolved = Vec::with_capacity(instances.len());
    for inst in instances {
        match resolve_mdns_instance(&inst.instance, service_type).await {
            Ok(r) => resolved.push(r),
            Err(_) => resolved.push(inst),
        }
    }
    let _ = domain;
    Ok(resolved)
}

async fn resolve_mdns_instance(instance: &str, service_type: &str) -> Result<MdnsEntry> {
    let mut child = tokio::process::Command::new("dns-sd")
        .args(["-L", instance, service_type, "local."])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawn dns-sd -L")?;

    tokio::time::sleep(Duration::from_millis(400)).await;
    let _ = child.start_kill();
    let output = child.wait_with_output().await.context("dns-sd -L output")?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let mut entry = MdnsEntry {
        instance: instance.to_owned(),
        host: None,
        ip: None,
        port: None,
        txt_records: Vec::new(),
    };

    // Output format includes "can be reached at <hostname>.local.:<port>"
    for line in stdout.lines() {
        if let Some(idx) = line.find("can be reached at ") {
            let rest = &line[idx + 18..];
            // Format: "Mac.local.:22 (interface 12)"
            let token = rest.split_whitespace().next().unwrap_or("");
            // Split on ':' to get host:port. Last colon-separated.
            if let Some(colon) = token.rfind(':') {
                entry.host = Some(token[..colon].trim_end_matches('.').to_owned());
                if let Ok(p) = token[colon + 1..].parse::<u16>() {
                    entry.port = Some(p);
                }
            }
        }
        // TXT records appear as " key=value" lines in some
        // dns-sd outputs; capture them.
        if line.starts_with(' ') && line.contains('=') {
            entry.txt_records.push(line.trim().to_owned());
        }
    }

    // dns-sd doesn't give us IP directly. We use a sync DNS
    // resolve of the .local hostname to get the IP — macOS's
    // mDNSResponder serves these.
    if let Some(ref host) = entry.host {
        if let Ok(addrs) = tokio::net::lookup_host(format!("{host}:1")).await {
            for addr in addrs {
                let ip = addr.ip().to_string();
                if !ip.starts_with("fe80") && !ip.starts_with("::") {
                    entry.ip = Some(ip);
                    break;
                }
            }
        }
    }
    Ok(entry)
}

// ---------------------------------------------------------------------------
// Local interface enumeration
// ---------------------------------------------------------------------------

async fn list_local_interfaces() -> Result<Vec<LocalInterface>> {
    let output = tokio::process::Command::new("ifconfig")
        .output()
        .await
        .context("run ifconfig")?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(parse_ifconfig(&stdout))
}

fn parse_ifconfig(text: &str) -> Vec<LocalInterface> {
    let mut out: Vec<LocalInterface> = Vec::new();
    let mut current: Option<LocalInterface> = None;

    for line in text.lines() {
        if !line.starts_with('\t') && !line.is_empty() {
            // New interface header: "en0: flags=8863<...>".
            if let Some(c) = current.take() {
                out.push(c);
            }
            let name = line.split(':').next().unwrap_or("").to_owned();
            current = Some(LocalInterface {
                name,
                mac: None,
                ipv4: None,
                cidr: None,
                ipv6: None,
            });
            continue;
        }
        let trimmed = line.trim_start();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        if let Some(ref mut c) = current {
            match parts[0] {
                "ether" if parts.len() > 1 => c.mac = Some(parts[1].to_owned()),
                "inet" if parts.len() > 1 => {
                    c.ipv4 = Some(parts[1].to_owned());
                    // Try to convert netmask to CIDR.
                    if parts.len() > 3 && parts[2] == "netmask" {
                        if let Ok(mask) = u32::from_str_radix(
                            parts[3].trim_start_matches("0x"),
                            16,
                        ) {
                            let prefix = mask.count_ones();
                            // Compute network address by masking the IP.
                            if let Ok(ip_n) = ipv4_to_u32(parts[1]) {
                                let net = ip_n & mask;
                                c.cidr = Some(format!("{}/{}", u32_to_ipv4(net), prefix));
                            }
                        }
                    }
                }
                "inet6" if parts.len() > 1 => {
                    if c.ipv6.is_none() && !parts[1].starts_with("fe80") {
                        c.ipv6 = Some(parts[1].split('%').next().unwrap_or("").to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(c) = current {
        out.push(c);
    }
    // Drop loopback + interfaces without IP.
    out.retain(|i| i.name != "lo0" && i.ipv4.is_some());
    out
}

fn ipv4_to_u32(s: &str) -> Result<u32, std::num::ParseIntError> {
    let octets: Vec<u8> = s
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()?;
    if octets.len() != 4 {
        return "x".parse::<u8>().map(|_| 0);
    }
    Ok((u32::from(octets[0]) << 24)
        | (u32::from(octets[1]) << 16)
        | (u32::from(octets[2]) << 8)
        | u32::from(octets[3]))
}

fn u32_to_ipv4(n: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (n >> 24) & 0xff,
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff
    )
}

// ---------------------------------------------------------------------------
// OUI lookup (MAC vendor database)
// ---------------------------------------------------------------------------

/// Bundled IEEE OUI prefix → vendor table. The curated list
/// below covers every Ubiquiti / Fortinet / Cisco / MikroTik
/// / Aruba / HPE / Meraki / TP-Link / Netgear prefix the
/// author has personally seen in MSP fleets, plus the major
/// consumer-PC + virtualisation vendors so misc IPs get a
/// useful label too. The list is intentionally fat for the
/// network-gear side because those are the rows the operator
/// most needs to act on.
///
/// If `oui_database_load_external()` finds a Wireshark `manuf`
/// file at one of the well-known paths, its 35k+ entries are
/// layered on top of the curated set — so a missing prefix
/// here doesn't doom the device to "no vendor" on systems
/// where the operator has Wireshark installed.
fn oui_database() -> HashMap<String, String> {
    let mut m = HashMap::new();
    // ---- Ubiquiti — comprehensive list of registered OUIs
    //     (UniFi APs / switches / routers / Cloud Keys). The
    //     user's U7-Pro is on 8c:ed:e1; missing this entry was
    //     the entire reason adopted UniFi gear rendered as
    //     "generic Linux" in scan results.
    let ubiquiti: &[&str] = &[
        "00:15:6d", "00:27:22", "04:18:d6", "18:e8:29", "24:5a:4c",
        "24:a4:3c", "28:70:4e", "44:d9:e7", "60:22:32", "68:72:51",
        "68:d7:9a", "70:a7:41", "74:83:c2", "74:ac:b9", "78:45:58",
        "78:8a:20", "80:2a:a8", "80:2d:7a", "8c:ed:e1", "94:2a:6f",
        "a0:36:bc", "ac:8b:a9", "b4:fb:e4", "d0:21:f9", "d2:21:f9",
        "dc:9f:db", "e0:63:da", "e4:38:83", "e4:6f:13", "f0:9f:c2",
        "f4:e2:c6", "f8:1b:73", "f8:8e:38", "fc:ec:da",
    ];
    for p in ubiquiti { m.insert((*p).to_owned(), "Ubiquiti Networks Inc.".to_owned()); }

    // ---- Fortinet (FortiGate / FortiSwitch / FortiAP)
    let fortinet: &[&str] = &[
        "00:09:0f", "00:13:5f", "04:d5:90", "08:5b:0e", "08:5b:0f",
        "08:62:66", "0c:74:c2", "10:0a:f8", "1c:a4:dc", "70:4c:a5",
        "78:f0:9c", "90:6c:ac", "b4:cb:57", "e8:1c:ba", "f0:b2:b9",
    ];
    for p in fortinet { m.insert((*p).to_owned(), "Fortinet, Inc.".to_owned()); }

    // ---- MikroTik (RouterBOARD / CCR / CRS / hAP)
    let mikrotik: &[&str] = &[
        "00:0c:42", "08:55:31", "18:fd:74", "2c:c8:1b", "48:8f:5a",
        "4c:5e:0c", "64:d1:54", "6c:3b:6b", "74:4d:28", "78:9a:18",
        "b8:69:f4", "c4:ad:34", "cc:2d:e0", "d4:ca:6d", "dc:2c:6e",
        "e4:8d:8c",
    ];
    for p in mikrotik { m.insert((*p).to_owned(), "MikroTik".to_owned()); }

    // ---- Cisco (incl. Linksys legacy + Meraki) — small subset
    let cisco: &[&str] = &[
        "00:0a:b8", "00:0b:46", "00:0d:bd", "00:0e:08", "00:0e:39",
        "00:14:bf", "00:14:f1", "00:16:9c", "00:18:73", "00:1b:53",
        "00:1b:8b", "00:1d:7e", "00:21:d8", "00:21:d7", "00:23:33",
        "00:25:84", "00:26:0b", "00:2a:10", "00:30:96", "08:96:ad",
        "0c:33:5e", "10:f3:11", "18:8b:9d", "1c:6a:7a", "2c:36:f8",
        "44:e4:d9", "5c:50:15", "70:cd:60", "8c:60:4f", "a0:f8:49",
        "c8:9c:1d", "cc:48:3a", "f8:7b:20",
    ];
    for p in cisco { m.insert((*p).to_owned(), "Cisco Systems".to_owned()); }

    // ---- Meraki (Cisco's small-business / MSP line) —
    //     separated so the operator gets a clearer signal.
    for p in ["00:18:0a", "88:15:44", "ac:17:c8", "e0:55:3d", "e0:cb:bc"] {
        m.insert(p.to_owned(), "Cisco Meraki".to_owned());
    }

    // ---- HPE / Aruba / ProCurve
    let hpe: &[&str] = &[
        "00:01:e7", "00:0b:cd", "00:11:0a", "00:14:c2", "00:1f:fe",
        "00:23:7d", "00:25:b3", "00:80:77", "18:64:72", "3c:d9:2b",
        "94:18:82", "a4:5d:36", "b0:e9:7e", "d0:7e:35", "f0:7f:06",
        "00:24:6c", "20:4c:03", "70:3a:0e", "94:b4:0f", "ac:a3:1e",
    ];
    for p in hpe { m.insert((*p).to_owned(), "HPE / Aruba Networks".to_owned()); }

    // ---- TP-Link / Netgear / D-Link — common consumer/SMB gear
    let tplink: &[&str] = &[
        "00:14:78", "00:23:cd", "00:27:19", "14:cc:20", "30:b5:c2",
        "44:23:7c", "50:c7:bf", "54:e6:fc", "64:6e:97", "70:4f:57",
        "84:16:f9", "98:da:c4", "a0:f3:c1", "c0:25:e9", "f4:f2:6d",
    ];
    for p in tplink { m.insert((*p).to_owned(), "TP-Link Technologies".to_owned()); }
    let netgear: &[&str] = &[
        "00:09:5b", "00:0f:b5", "00:14:6c", "00:18:4d", "00:1b:2f",
        "00:1f:33", "10:0d:7f", "20:0c:c8", "30:46:9a", "44:94:fc",
        "9c:3d:cf", "a0:21:b7", "a4:2b:8c", "c0:3f:0e", "e0:46:9a",
    ];
    for p in netgear { m.insert((*p).to_owned(), "Netgear".to_owned()); }
    let dlink: &[&str] = &[
        "00:05:5d", "00:0d:88", "00:0f:3d", "00:11:95", "00:13:46",
        "00:15:e9", "00:17:9a", "00:1c:f0", "00:1e:58", "00:21:91",
        "00:24:01", "1c:7e:e5", "78:54:2e", "84:c9:b2", "c4:e9:0a",
    ];
    for p in dlink { m.insert((*p).to_owned(), "D-Link".to_owned()); }

    // ---- pfSense / Netgate appliances + generic FreeBSD
    for p in ["00:08:a2", "ac:1f:6b"] {
        m.insert(p.to_owned(), "Netgate / pfSense".to_owned());
    }

    // ---- Apple — big mix because most operator workstations
    //     are Macs and personal devices show up in scans.
    let apple: &[&str] = &[
        "00:03:93", "00:05:02", "00:0a:27", "00:0a:95", "00:0d:93",
        "00:10:fa", "00:11:24", "00:14:51", "00:16:cb", "00:17:f2",
        "00:19:e3", "00:1b:63", "00:1c:b3", "00:1e:c2", "00:1f:5b",
        "00:1f:f3", "00:21:e9", "00:22:41", "00:23:12", "00:23:32",
        "00:24:36", "00:25:00", "00:25:4b", "00:25:bc", "00:26:08",
        "00:26:4a", "00:26:b0", "00:26:bb", "00:30:65", "00:50:e4",
        "00:88:65", "00:a0:40", "00:c6:10", "04:0c:ce", "04:15:52",
        "04:1e:64", "04:48:9a", "04:54:53", "04:69:f8", "04:db:56",
        "04:e5:36", "04:f1:3e", "08:00:07", "08:74:02", "08:e6:89",
        "0c:30:21", "0c:74:c2", "10:1c:0c", "10:9a:dd", "14:10:9f",
        "18:81:0e", "18:af:61", "18:e7:f4", "1c:91:48", "1c:ab:a7",
        "28:5a:eb", "28:cf:da", "28:e0:2c", "2c:f0:a2", "30:90:ab",
        "34:36:3b", "34:c0:59", "3c:07:54", "3c:15:c2", "3c:ab:8e",
        "40:30:04", "40:6c:8f", "40:a6:d9", "44:00:10", "44:2a:60",
        "44:fb:42", "48:60:bc", "48:74:6e", "4c:74:bf", "4c:7c:5f",
        "4c:8d:79", "4c:b1:99", "50:7a:55", "50:ea:d6", "54:26:96",
        "54:72:4f", "54:e4:3a", "58:1f:aa", "58:55:ca", "58:b0:35",
        "5c:8d:4e", "5c:95:ae", "5c:96:9d", "5c:97:f3", "60:03:08",
        "60:33:4b", "60:69:44", "60:c5:47", "60:f8:1d", "60:fa:cd",
        "60:fb:42", "64:9a:be", "64:a3:cb", "64:a5:c3", "64:b9:e8",
        "68:09:27", "68:5b:35", "68:96:7b", "68:9c:70", "68:a8:6d",
        "68:ab:1e", "68:db:ca", "6c:40:08", "6c:70:9f", "6c:72:e7",
        "6c:94:f8", "6c:96:cf", "6c:ab:31", "70:11:24", "70:48:0f",
        "70:73:cb", "70:cd:60", "70:de:e2", "74:e1:b6", "74:e2:f5",
        "78:31:c1", "78:6c:1c", "78:7e:61", "78:88:6d", "78:a3:e4",
        "78:ca:39", "78:fd:94", "7c:11:be", "7c:6d:62", "7c:6d:f8",
        "7c:c3:a1", "7c:c5:37", "7c:d1:c3", "80:49:71", "80:92:9f",
        "80:be:05", "80:ea:96", "84:38:35", "84:78:8b", "84:85:06",
        "84:fc:fe", "88:1f:a1", "88:53:95", "88:c6:63", "88:e9:fe",
        "8c:00:6d", "8c:29:37", "8c:2d:aa", "8c:7b:9d", "8c:85:90",
        "8c:fa:ba", "90:27:e4", "90:72:40", "90:84:0d", "90:b0:ed",
        "90:b2:1f", "90:b9:31", "90:fd:61", "94:94:26", "98:01:a7",
        "98:03:d8", "98:b8:e3", "98:d6:bb", "98:e0:d9", "98:f0:ab",
        "9c:04:eb", "9c:35:eb", "9c:84:bf", "9c:e6:5e", "9c:f3:87",
        "9c:f4:8e", "a0:99:9b", "a4:5e:60", "a4:67:06", "a4:b1:97",
        "a4:b8:05", "a4:c3:61", "a4:d1:8c", "a4:d1:d2", "a4:f1:e8",
        "a4:fc:14", "a8:20:66", "a8:51:ab", "a8:5c:2c", "a8:60:b6",
        "a8:8e:24", "a8:96:8a", "a8:bb:cf", "a8:fa:d8", "ac:1f:74",
        "ac:29:3a", "ac:3c:0b", "ac:61:ea", "ac:7f:3e", "ac:87:a3",
        "ac:bc:32", "ac:cf:5c", "ac:fd:ec", "b0:34:95", "b0:48:1a",
        "b0:65:bd", "b4:18:d1", "b4:f0:ab", "b8:09:8a", "b8:17:c2",
        "b8:44:d9", "b8:53:ac", "b8:78:2e", "b8:8d:12", "b8:c7:5d",
        "b8:e8:56", "b8:f6:b1", "bc:3b:af", "bc:52:b7", "bc:67:1c",
        "bc:92:6b", "bc:a9:20", "bc:b8:63", "c0:63:94", "c0:84:7a",
        "c0:b6:58", "c0:cc:f8", "c0:e8:62", "c0:f2:fb", "c4:2c:03",
        "c4:84:66", "c4:b3:01", "c8:1e:e7", "c8:2a:14", "c8:33:4b",
        "c8:69:cd", "c8:6f:1d", "c8:85:50", "c8:bc:c8", "c8:d0:83",
        "c8:e0:eb", "c8:f6:50", "cc:08:e0", "cc:25:ef", "cc:29:f5",
        "cc:78:5f", "cc:c7:60", "d0:23:db", "d0:25:98", "d0:33:11",
        "d0:81:7a", "d4:61:9d", "d4:f4:6f", "d4:f4:65", "d8:a2:5e",
        "d8:cf:9c", "d8:d1:cb", "dc:0c:5c", "dc:2b:2a", "dc:2b:61",
        "dc:9b:9c", "dc:a4:ca", "dc:a9:04", "dc:e2:ac", "e0:5f:45",
        "e0:b9:ba", "e0:c9:7a", "e0:f5:c6", "e0:f8:47", "e4:25:e7",
        "e4:8b:7f", "e4:9a:dc", "e4:c6:3d", "e8:80:2e", "e8:8d:28",
        "e8:b2:ac", "ec:35:86", "ec:85:2f", "ec:ad:b8", "f0:18:98",
        "f0:24:75", "f0:99:bf", "f0:b4:79", "f0:b0:e7", "f0:c1:f1",
        "f0:cb:a1", "f0:d1:a9", "f0:db:e2", "f0:db:f8", "f0:dc:e2",
        "f0:f6:1c", "f4:0f:24", "f4:31:c3", "f4:5c:89", "f4:f1:5a",
        "f8:1e:df", "f8:27:93", "f8:4e:73", "fc:25:3f", "fc:b6:d8",
        "fc:e9:98", "fc:fc:48",
    ];
    for p in apple { m.insert((*p).to_owned(), "Apple, Inc.".to_owned()); }

    // ---- Microsoft (incl. Surface devices) + virtualization
    for p in ["00:03:ff", "00:0d:3a", "00:15:5d", "00:17:fa", "00:1d:d8",
              "00:50:f2", "28:18:78", "30:59:b7", "60:45:bd", "7c:1e:52",
              "98:5f:d3", "a0:8c:fd", "b0:7d:64", "e4:e7:49"]
    {
        m.insert(p.to_owned(), "Microsoft Corporation".to_owned());
    }
    for p in ["00:0c:29", "00:1c:14", "00:50:56", "00:05:69"] {
        m.insert(p.to_owned(), "VMware, Inc.".to_owned());
    }
    for p in ["00:1c:42"] {
        m.insert(p.to_owned(), "Parallels".to_owned());
    }
    for p in ["52:54:00"] {
        m.insert(p.to_owned(), "QEMU / KVM (libvirt)".to_owned());
    }
    for p in ["02:42:ac"] {
        m.insert(p.to_owned(), "Docker container".to_owned());
    }

    // ---- Raspberry Pi (B+/Zero/3/4/5)
    for p in ["b8:27:eb", "dc:a6:32", "e4:5f:01", "2c:cf:67", "d8:3a:dd"] {
        m.insert(p.to_owned(), "Raspberry Pi Foundation".to_owned());
    }

    // ---- Intel / Dell / HP / Lenovo / Samsung / Xiaomi / etc.
    for p in ["00:1b:21", "8c:16:45", "a4:34:d9", "f8:34:41", "fc:f8:ae"] {
        m.insert(p.to_owned(), "Intel Corporate".to_owned());
    }
    for p in ["00:11:43", "00:23:ae", "00:26:b9", "18:03:73", "d4:81:d7",
              "d4:ae:52", "f0:1f:af"]
    {
        m.insert(p.to_owned(), "Dell Inc.".to_owned());
    }
    for p in ["00:21:cc", "00:24:7e", "08:b2:58", "20:1a:06", "94:18:82"] {
        m.insert(p.to_owned(), "Lenovo".to_owned());
    }
    for p in ["00:23:99", "08:08:c2", "20:64:32", "28:ba:b5", "70:14:a6",
              "ac:5f:3e", "c0:bd:d1"]
    {
        m.insert(p.to_owned(), "Samsung Electronics".to_owned());
    }
    for p in ["28:6c:07", "3c:8c:f8", "ac:f7:f3", "f0:b4:29", "f4:8c:50"] {
        m.insert(p.to_owned(), "Xiaomi Communications".to_owned());
    }

    // ---- NAS / printer / IoT staples
    for p in ["00:11:32", "28:cd:c1"] {
        m.insert(p.to_owned(), "Synology".to_owned());
    }
    for p in ["00:08:9b", "00:24:0b"] {
        m.insert(p.to_owned(), "QNAP Systems".to_owned());
    }
    for p in ["00:25:90", "0c:c4:7a", "30:5a:3a"] {
        m.insert(p.to_owned(), "Super Micro Computer".to_owned());
    }
    for p in ["00:e0:b8"] {
        m.insert(p.to_owned(), "Foxconn".to_owned());
    }
    for p in ["00:e0:4c"] {
        m.insert(p.to_owned(), "Realtek Semiconductor".to_owned());
    }
    for p in ["ac:de:48"] {
        m.insert(p.to_owned(), "Private (locally administered)".to_owned());
    }

    // Apply an external Wireshark manuf overlay if present —
    // that file has ~35k entries and covers everything the
    // curated list misses (assuming the operator has
    // Wireshark installed, which most network engineers do).
    apply_wireshark_manuf_overlay(&mut m);

    m
}

/// Layer the Wireshark `manuf` database on top of the curated
/// set if any of the well-known install paths exist. macOS
/// users typically have one of these via:
///   - Homebrew Wireshark (Intel):  /usr/local/etc/wireshark/manuf
///   - Homebrew Wireshark (Silicon): /opt/homebrew/etc/wireshark/manuf
///   - System Wireshark.app: bundled inside the .app
///
/// File format is one line per OUI:
///     08:00:20	Sun	Oracle Corporation
///     8C:ED:E1	UbiquitiI	Ubiquiti Inc
/// We just take the first two whitespace-separated fields per
/// line, lowercase the prefix, and overwrite our curated entry
/// only when the curated table has no entry (so a curated
/// "Ubiquiti Networks Inc." beats Wireshark's "UbiquitiI"
/// truncated alias).
fn apply_wireshark_manuf_overlay(out: &mut HashMap<String, String>) {
    let candidates = [
        "/opt/homebrew/etc/wireshark/manuf",
        "/usr/local/etc/wireshark/manuf",
        "/Applications/Wireshark.app/Contents/Resources/share/wireshark/manuf",
        "/usr/share/wireshark/manuf",
    ];
    for path in candidates {
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        let mut added = 0usize;
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || trimmed.is_empty() { continue }
            // Three-octet OUI lines look like
            //   "8C:ED:E1\tUbiquiti\tUbiquiti Networks Inc"
            // Lines with /36 (28-bit MA-M) or /28 (24+4 bit
            // MA-S) prefixes look like "8C:1F:64:1A:0/28 ..."
            // — skip those, our key is a /24 (first 3 octets).
            let mut parts = trimmed.splitn(3, |c: char| c == '\t' || c == ' ');
            let raw_prefix = parts.next().unwrap_or("");
            if raw_prefix.contains('/') { continue }
            let prefix_clean: String = raw_prefix
                .chars()
                .filter(|c| c.is_ascii_hexdigit() || *c == ':')
                .collect();
            // Want exactly 8 chars: "XX:XX:XX". Two hex digits
            // per octet, two colons.
            if prefix_clean.len() != 8 { continue }
            let prefix = prefix_clean.to_ascii_lowercase();
            // Prefer the curated entry. Use Wireshark's "long"
            // (third column) name when present, else the short
            // alias (second column).
            let short = parts.next().unwrap_or("").trim();
            let long = parts.next().unwrap_or("").trim();
            let vendor = if !long.is_empty() {
                long.to_owned()
            } else if !short.is_empty() {
                short.to_owned()
            } else {
                continue
            };
            out.entry(prefix).or_insert(vendor);
            added += 1;
        }
        tracing::debug!(
            "OUI overlay: loaded {} entries from {}",
            added, path
        );
        return; // first one that exists wins
    }
}

fn lookup_oui(db: &HashMap<String, String>, mac: &str) -> Option<String> {
    let prefix = mac.split(':').take(3).collect::<Vec<_>>().join(":");
    db.get(&prefix).cloned()
}

/// Sort key that gives sane numerical ordering for IPv4
/// addresses (so `192.168.1.10` sorts after `192.168.1.9`, not
/// after `192.168.1.1`). Non-parseable strings fall back to
/// lexical order via the unused octets being all-zero.
fn ip_sort_key(s: &str) -> (u32, String) {
    if let Ok(addr) = s.parse::<std::net::Ipv4Addr>() {
        (u32::from(addr), String::new())
    } else {
        (0, s.to_owned())
    }
}

// ---------------------------------------------------------------------------
// Inventory persistence
// ---------------------------------------------------------------------------

fn inventory_dir(customer_slug: &str) -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("discovery");
    p.push(customer_slug);
    p
}

fn persist_inventory(customer_slug: &str, hosts: &[DiscoveredHost]) -> Result<()> {
    let dir = inventory_dir(customer_slug);
    std::fs::create_dir_all(&dir).context("create discovery dir")?;
    let mut path = dir;
    path.push("inventory.json");
    let bytes = serde_json::to_vec_pretty(hosts).context("serialize inventory")?;
    std::fs::write(&path, bytes).with_context(|| format!("write {path:?}"))?;
    Ok(())
}

pub fn load_inventory(customer_slug: &str) -> Result<Vec<DiscoveredHost>> {
    let mut path = inventory_dir(customer_slug);
    path.push("inventory.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {path:?}"))?;
    let hosts: Vec<DiscoveredHost> =
        serde_json::from_slice(&bytes).context("deserialize inventory")?;
    Ok(hosts)
}

// ---------------------------------------------------------------------------
// Active scan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveScanResult {
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: chrono::DateTime<chrono::Utc>,
    pub hosts: Vec<ActiveHost>,
    pub findings: Vec<crate::vuln::Finding>,
    pub engagement_id: Option<String>,
    /// Diff produced by `findings_store::reconcile`. None when the
    /// scan ran without a persistence scope (no customer_slug
    /// AND no engagement_id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<crate::findings_store::ScanDiff>,
    /// The persistence scope used for reconciliation — either the
    /// customer slug or the engagement ID. Frontend uses this to
    /// build subsequent `findings_list` / `findings_set_disposition`
    /// calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings_scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveHost {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub probes: Vec<crate::probes::PortProbe>,
    pub finding_count: u32,
    /// Controller cross-reference. Populated post-scan by
    /// matching `mac` against every configured UniFi
    /// controller's device inventory. Non-None means a
    /// controller-API path is available for this host;
    /// the GUI uses it to replace SSH-based actions with
    /// controller-driven ones (locate / restart / forget /
    /// re-adopt) and to render the controller-state badge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_state: Option<crate::unifi_controllers::ControllerStateRef>,
    /// RFC zone classification — drives the exposure pill in the
    /// UI ("internal" vs. "public"). Computed pure-compute from
    /// the IP at scan time, no I/O.
    #[serde(default)]
    pub zone: Option<String>,
}

/// Active scan against every host in `targets`. For each host:
///   1. TCP connect-test against `ports`
///   2. For each open port, run service-specific banner-grab
///   3. Pass probes into `vuln::analyse_host` for findings
///
/// Concurrency capped at 32 hosts × 16 ports per host. Avoids
/// blasting through scope at the cost of slightly slower scans.
pub async fn active_scan(
    targets: &[String],
    ports: &[u16],
    customer_slug: Option<&str>,
    engagement_id: Option<&str>,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<ActiveScanResult> {
    use std::sync::atomic::Ordering;

    let started_at = chrono::Utc::now();

    // ARP lookup runs in parallel with the host fan-out so it
    // doesn't add to wall-clock. ARP gives us MAC + OUI vendor
    // for every host on the local L2 segment — without this
    // pre-pass the active-scan results would be MAC-blank, and
    // the GUI's vendor-pill / device-type sniffing would have
    // nothing to work with for devices like UniFi APs that
    // disclose nothing about themselves over an open port.
    let arp_lookup = tokio::spawn(async {
        let cache = scan_arp_cache().await.unwrap_or_default();
        let vendors = oui_database();
        let mut by_ip: HashMap<String, (Option<String>, Option<String>)> =
            HashMap::new();
        for h in cache {
            let v = h
                .mac
                .as_deref()
                .and_then(|m| lookup_oui(&vendors, m));
            by_ip.insert(h.ip, (h.mac, v));
        }
        by_ip
    });

    let host_sema = Arc::new(tokio::sync::Semaphore::new(32));
    let mut futs = Vec::new();
    for ip in targets {
        // Skip remaining targets if cancellation was requested
        // before we even queued them. The fan-out loop is fast
        // so this only matters when the user clicks Stop within
        // the first few hundred ms.
        if let Some(c) = &cancel {
            if c.load(Ordering::Acquire) {
                break;
            }
        }
        let ip = ip.clone();
        let ports: Vec<u16> = ports.to_vec();
        let host_sema = Arc::clone(&host_sema);
        let cancel_clone = cancel.clone();
        futs.push(tokio::spawn(async move {
            // Honour cancel at the front of the host scan so a
            // mid-scan Stop short-circuits before opening any
            // new TCP connections for this host.
            if let Some(c) = &cancel_clone {
                if c.load(Ordering::Acquire) {
                    return None;
                }
            }
            let _permit = host_sema.acquire_owned().await.ok()?;
            // Pass cancel through so port-probe fan-out inside
            // a host scan also honours the flag — without this,
            // a host that's already started its 105-port sweep
            // would run to completion even after cancellation.
            scan_host_active(&ip, &ports, cancel_clone).await
        }));
    }
    let mut hosts: Vec<ActiveHost> = Vec::new();
    let mut findings: Vec<crate::vuln::Finding> = Vec::new();
    let mut was_cancelled = false;
    for f in futs {
        // Don't `await` a join handle whose work we no longer
        // want — abort it so the connection workers drop out
        // immediately. New code below: track that we cancelled
        // so the caller can distinguish "complete" from "cut
        // short" in the audit log.
        if let Some(c) = &cancel {
            if c.load(Ordering::Acquire) {
                was_cancelled = true;
                f.abort();
                continue;
            }
        }
        if let Ok(Some(active)) = f.await {
            findings.extend(crate::vuln::analyse_host(&active.ip, &active.probes));
            hosts.push(active);
        }
    }
    if was_cancelled {
        tracing::info!(
            "active_scan cancelled mid-flight after {} hosts",
            hosts.len()
        );
    }

    // Merge ARP data — every host we already collected via TCP
    // probe gets its MAC + OUI vendor filled in. This is the
    // single most important pass for the GUI: without it the
    // "vendor pill" / "device-type" badges have nothing to
    // chew on and every host renders as a grey Linux generic.
    let arp_map: HashMap<String, (Option<String>, Option<String>)> = arp_lookup
        .await
        .unwrap_or_else(|e| {
            warn!("arp lookup task failed: {e:#}");
            HashMap::new()
        });
    let scanned_ips: HashSet<String> = hosts.iter().map(|h| h.ip.clone()).collect();
    for h in hosts.iter_mut() {
        if let Some((mac, vendor)) = arp_map.get(&h.ip) {
            if h.mac.is_none() { h.mac = mac.clone(); }
            if h.vendor.is_none() { h.vendor = vendor.clone(); }
        }
    }

    // Include ARP-only hosts. UniFi APs that are already
    // adopted to a controller lock down EVERY listener except
    // the inform channel (often only outbound), so the active
    // TCP sweep returns zero probes — but the device is still
    // very much on the network. Dropping them silently meant
    // operators couldn't find their own adopted gear. We add
    // these hosts with an empty `probes` vec and a synthetic
    // `arp-only` zone hint so the GUI knows to render them
    // with the "no open ports — discovered via ARP" treatment.
    for ip in targets {
        if scanned_ips.contains(ip) {
            continue;
        }
        if let Some((mac, vendor)) = arp_map.get(ip) {
            if mac.is_some() {
                hosts.push(ActiveHost {
                    ip: ip.clone(),
                    mac: mac.clone(),
                    hostname: None,
                    vendor: vendor.clone(),
                    probes: Vec::new(),
                    finding_count: 0,
                    zone: Some(crate::asset_enrich::classify(ip).label().to_owned()),
                    controller_state: None,
                });
            }
        }
    }

    // Reverse-DNS for every host that didn't already get a
    // hostname from a probe. Same `enrich_many` the passive
    // scan uses — bounded by internal concurrency + timeout
    // so a slow resolver can't wedge results.
    {
        let ips: Vec<String> = hosts.iter().map(|h| h.ip.clone()).collect();
        let enrichment = crate::asset_enrich::enrich_many(&ips).await;
        let by_ip: HashMap<String, &crate::asset_enrich::AssetEnrichment> =
            enrichment.iter().map(|e| (e.ip.clone(), e)).collect();
        for h in hosts.iter_mut() {
            if h.hostname.is_none() {
                if let Some(en) = by_ip.get(&h.ip) {
                    h.hostname = en.reverse_dns.clone();
                }
            }
        }
    }

    // Sort by IP so the GUI's row order is stable across re-
    // runs. Hosts with TCP probes are interleaved with ARP-only
    // hosts in IP order — keeping the visual "this is what's
    // on my network" view coherent.
    hosts.sort_by(|a, b| {
        ip_sort_key(&a.ip).cmp(&ip_sort_key(&b.ip))
    });
    // Update finding-count on each host post-aggregation.
    let mut by_ip: HashMap<String, u32> = HashMap::new();
    for f in &findings {
        *by_ip.entry(f.host_ip.clone()).or_insert(0) += 1;
    }
    for h in hosts.iter_mut() {
        h.finding_count = by_ip.get(&h.ip).copied().unwrap_or(0);
    }
    let finished_at = chrono::Utc::now();

    // Pick a persistence scope: customer slug if present, else
    // fall back to engagement_id so ad-hoc engagements still get
    // findings history. None only when neither is given.
    let findings_scope: Option<String> = customer_slug
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| engagement_id.map(str::to_owned));

    // Anomaly detection — per-host port-baseline reconciliation
    // produces extra findings for "new port appeared" / "stable
    // port missing". Run before findings_store reconcile so the
    // anomaly findings flow through the same persistence + diff
    // + notification pipeline as everything else.
    let mut anomaly_findings: Vec<crate::vuln::Finding> = Vec::new();
    if let Some(scope) = findings_scope.as_deref() {
        for host in &hosts {
            let observed_ports: Vec<u16> = host.probes.iter().map(|p| p.port).collect();
            match crate::anomaly::reconcile_host(scope, &host.ip, &observed_ports) {
                Ok(mut found) => anomaly_findings.append(&mut found),
                Err(e) => warn!("anomaly reconcile failed for {}: {e:#}", host.ip),
            }
        }
    }
    let mut findings = findings;
    findings.append(&mut anomaly_findings);

    let mut result = ActiveScanResult {
        started_at,
        finished_at,
        hosts,
        findings,
        engagement_id: engagement_id.map(str::to_owned),
        diff: None,
        findings_scope: findings_scope.clone(),
    };

    // Reconcile against persistent findings store + capture the
    // diff. We do this even if customer_slug is None as long as
    // we have an engagement_id, so each engagement maintains its
    // own finding history.
    if let Some(scope) = findings_scope.as_deref() {
        match crate::findings_store::reconcile(scope, &result.findings) {
            Ok(diff) => {
                // Fire-and-forget Slack notification (no error if
                // webhook isn't configured).
                let scope_for_notify = scope.to_owned();
                let diff_for_notify = diff.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::notify::notify_scan_diff(&scope_for_notify, &diff_for_notify).await
                    {
                        warn!("notify_scan_diff failed: {e:#}");
                    }
                });
                result.diff = Some(diff);
            }
            Err(e) => warn!("reconcile findings failed: {e:#}"),
        }
    }

    // Persist findings + active hosts under customer (legacy
    // path — frontend still reads this; redundant with the
    // findings_store but kept for backward compatibility).
    if let Some(slug) = customer_slug.filter(|s| !s.is_empty()) {
        if let Err(e) = persist_active_scan(slug, &result) {
            warn!("persist active_scan failed: {e:#}");
        }
    }
    if let Some(eid) = engagement_id {
        let diff_summary = result
            .diff
            .as_ref()
            .map(|d| {
                format!(
                    "{}new, {}regressed, {}still-open, {}auto-resolved",
                    d.new_findings.len(),
                    d.regressed.len(),
                    d.still_open.len(),
                    d.auto_resolved.len()
                )
            })
            .unwrap_or_else(|| "no diff".into());
        let _ = crate::engagement::log_event(
            eid,
            crate::engagement::EngagementEvent {
                at: chrono::Utc::now(),
                technique: crate::engagement::Technique::Discovery,
                target: format!("{} hosts", targets.len()),
                action: "active_scan".into(),
                findings: result.findings.len() as u32,
                notes: format!(
                    "{} hosts × {} ports → {} findings ({})",
                    result.hosts.len(),
                    ports.len(),
                    result.findings.len(),
                    diff_summary
                ),
            },
        );
    }
    info!(
        "active_scan: {} hosts, {} findings, {}s",
        result.hosts.len(),
        result.findings.len(),
        (result.finished_at - result.started_at).num_seconds()
    );
    Ok(result)
}

async fn scan_host_active(
    ip: &str,
    ports: &[u16],
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Option<ActiveHost> {
    use crate::probes::probe_port;
    use std::sync::atomic::Ordering;

    let port_sema = Arc::new(tokio::sync::Semaphore::new(16));
    let mut futs = Vec::with_capacity(ports.len());
    for port in ports {
        // Cheap front-of-queue check so we don't even queue port
        // futures for cancelled hosts.
        if let Some(c) = &cancel {
            if c.load(Ordering::Acquire) {
                break;
            }
        }
        let ip = ip.to_owned();
        let port = *port;
        let sema = Arc::clone(&port_sema);
        let c = cancel.clone();
        futs.push(tokio::spawn(async move {
            if let Some(c) = &c {
                if c.load(Ordering::Acquire) {
                    return None;
                }
            }
            let _permit = sema.acquire_owned().await.ok()?;
            probe_port(&ip, port).await
        }));
    }
    let mut probes: Vec<crate::probes::PortProbe> = Vec::new();
    for f in futs {
        // Bail out of joins once cancel fires — already-running
        // probe_port calls finish, but pending ones get aborted.
        if let Some(c) = &cancel {
            if c.load(Ordering::Acquire) {
                f.abort();
                continue;
            }
        }
        if let Ok(Some(p)) = f.await {
            probes.push(p);
        }
    }
    if probes.is_empty() {
        // No open TCP port. Return None so this slot is filled
        // — if at all — by the ARP-only pass in active_scan
        // (which keeps the host visible when MAC was learned)
        // and discarded otherwise. Most addresses in a /24 are
        // unused so this keeps the response set tight.
        return None;
    }
    let zone = Some(crate::asset_enrich::classify(ip).label().to_owned());
    // mac / hostname / vendor are left None here on purpose —
    // active_scan's post-pass fills them from the parallel ARP
    // lookup + reverse-DNS enrichment so every probe-found
    // host gets full identity without doing two DNS lookups
    // per host or refetching the ARP cache for every host.
    Some(ActiveHost {
        ip: ip.to_owned(),
        mac: None,
        hostname: None,
        vendor: None,
        probes,
        finding_count: 0,
        zone,
        controller_state: None,
    })
}

fn persist_active_scan(customer_slug: &str, result: &ActiveScanResult) -> Result<()> {
    let dir = inventory_dir(customer_slug);
    std::fs::create_dir_all(&dir).context("create discovery dir")?;
    let mut path = dir.clone();
    path.push("active_scan.json");
    let bytes = serde_json::to_vec_pretty(result).context("serialize")?;
    std::fs::write(&path, bytes).with_context(|| format!("write {path:?}"))?;
    let mut findings_path = dir;
    findings_path.push("findings.json");
    let bytes = serde_json::to_vec_pretty(&result.findings).context("serialize findings")?;
    std::fs::write(&findings_path, bytes).with_context(|| format!("write {findings_path:?}"))?;
    Ok(())
}

pub fn load_findings(customer_slug: &str) -> Result<Vec<crate::vuln::Finding>> {
    let mut path = inventory_dir(customer_slug);
    path.push("findings.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {path:?}"))?;
    let findings: Vec<crate::vuln::Finding> =
        serde_json::from_slice(&bytes).context("deserialize findings")?;
    Ok(findings)
}

/// Expand a list of targets (hosts and CIDRs) into a flat list
/// of IPs. Caps total at 4096 to avoid runaways. Anything
/// invalid is silently skipped.
pub fn expand_targets(targets: &[String], cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    for t in targets {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        if t.contains('/') {
            // CIDR — expand.
            if let Some(expanded) = expand_cidr(t, cap.saturating_sub(out.len())) {
                out.extend(expanded);
                if out.len() >= cap {
                    break;
                }
            }
        } else {
            out.push(t.to_owned());
        }
    }
    out.truncate(cap);
    out
}

fn expand_cidr(cidr: &str, cap: usize) -> Option<Vec<String>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let prefix: u32 = parts[1].parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let octets: Vec<u32> = parts[0]
        .split('.')
        .map(|s| s.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 4 {
        return None;
    }
    let base = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    let net = base & mask;
    let host_count = if prefix >= 31 { 1u64 << (32 - prefix) } else { (1u64 << (32 - prefix)) - 2 };
    if host_count > cap as u64 {
        // Don't allow pathologically large CIDRs.
        return Some(Vec::new());
    }
    let start = if prefix >= 31 { net } else { net + 1 };
    let mut out = Vec::with_capacity(host_count as usize);
    for i in 0..host_count {
        let ip = start + i as u32;
        out.push(format!(
            "{}.{}.{}.{}",
            (ip >> 24) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 8) & 0xff,
            ip & 0xff
        ));
    }
    Some(out)
}
