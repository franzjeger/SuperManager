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

/// Bundled IEEE OUI prefix → vendor table. We include a small
/// curated set covering the most common gear an MSP encounters;
/// production builds would ship the full IEEE registry.
fn oui_database() -> HashMap<String, String> {
    let mut m = HashMap::new();
    let curated = [
        ("00:11:32", "Apple, Inc."),
        ("00:1c:42", "Parallels"),
        ("00:0c:29", "VMware, Inc."),
        ("00:50:56", "VMware, Inc."),
        ("00:25:90", "Super Micro Computer"),
        ("00:e0:4c", "Realtek Semiconductor"),
        ("00:1d:d8", "Microsoft Corporation"),
        ("d8:c4:97", "Apple, Inc."),
        ("dc:a6:32", "Raspberry Pi Foundation"),
        ("b8:27:eb", "Raspberry Pi Foundation"),
        ("e4:5f:01", "Raspberry Pi Foundation"),
        ("18:e8:29", "Ubiquiti Networks Inc."),
        ("24:5a:4c", "Ubiquiti Networks Inc."),
        ("44:d9:e7", "Ubiquiti Networks Inc."),
        ("78:8a:20", "Ubiquiti Networks Inc."),
        ("80:2a:a8", "Ubiquiti Networks Inc."),
        ("dc:9f:db", "Ubiquiti Networks Inc."),
        ("e0:63:da", "Ubiquiti Networks Inc."),
        ("f0:9f:c2", "Ubiquiti Networks Inc."),
        ("00:09:0f", "Fortinet, Inc."),
        ("90:6c:ac", "Fortinet, Inc."),
        ("70:4c:a5", "Fortinet, Inc."),
        ("00:1b:21", "Intel Corporate"),
        ("00:e0:b8", "Foxconn"),
        ("3c:8c:f8", "Xiaomi Communications"),
        ("ac:bc:32", "Apple, Inc."),
        ("60:f8:1d", "Apple, Inc."),
        ("a4:5e:60", "Apple, Inc."),
        ("00:11:43", "Dell Inc."),
        ("d4:81:d7", "Dell Inc."),
        ("0c:c4:7a", "Super Micro Computer"),
        ("00:14:bf", "Cisco-Linksys"),
        ("00:21:d8", "Cisco Systems"),
        ("00:1b:8b", "Cisco Systems"),
        ("00:80:77", "HP, Inc."),
        ("3c:d9:2b", "HP, Inc."),
        ("a4:5d:36", "HP, Inc."),
        ("00:14:c2", "HP, Inc."),
        ("28:cd:c1", "Synology"),
        ("00:11:32", "Synology"),
        ("ac:de:48", "Private (locally administered)"),
    ];
    for (prefix, vendor) in curated.iter() {
        m.insert((*prefix).to_owned(), (*vendor).to_owned());
    }
    m
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
