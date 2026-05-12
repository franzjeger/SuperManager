//! Local network introspection — what's our WAN/LAN/gateway/DNS?
//!
//! Used by the customer/site editor's "Detect from current network"
//! button to pre-fill fields the operator would otherwise have to
//! type by hand.
//!
//! All probes are read-only:
//!   - `route -n get default`     → default gateway
//!   - `ifconfig <iface>`         → primary IPv4 + mask + MAC
//!   - `scutil --dns | grep nameserver` → DNS resolvers
//!   - `curl https://ifconfig.me` → public WAN IP (only if user
//!     opts in — implicit when they click the detect button)
//!
//! The combination is what populates `Site::lanBase`,
//! `Site::wanStaticIp`, plus suggested VLAN entries derived from
//! the passive-scan subnets seen on the link.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkDetect {
    /// Default gateway IP, e.g. "192.0.2.1".
    pub default_gateway: Option<String>,
    /// Primary interface name, e.g. "en0".
    pub primary_interface: Option<String>,
    /// IPv4 + CIDR of primary interface, e.g. "192.0.2.42/24".
    pub primary_cidr: Option<String>,
    /// LAN base derived from the primary interface, e.g. "192.0.2.0/24".
    pub lan_base: Option<String>,
    /// MAC of the primary interface.
    pub primary_mac: Option<String>,
    /// Public WAN IP as seen from outside (via ifconfig.me).
    pub public_ip: Option<String>,
    /// DNS resolvers configured on the system.
    pub dns_servers: Vec<String>,
}

pub async fn detect() -> NetworkDetect {
    let mut out = NetworkDetect::default();

    // -- default gateway via `route -n get default` --
    if let Ok(s) = run("route", &["-n", "get", "default"]).await {
        for line in s.lines() {
            let trim = line.trim();
            if let Some(rest) = trim.strip_prefix("gateway:") {
                out.default_gateway = Some(rest.trim().to_owned());
            } else if let Some(rest) = trim.strip_prefix("interface:") {
                out.primary_interface = Some(rest.trim().to_owned());
            }
        }
    }

    // -- primary interface details via `ifconfig <iface>` --
    if let Some(iface) = out.primary_interface.as_deref() {
        if let Ok(s) = run("ifconfig", &[iface]).await {
            for line in s.lines() {
                let trim = line.trim();
                if let Some(rest) = trim.strip_prefix("inet ") {
                    // "inet 192.0.2.42 netmask 0xffffff00 broadcast 192.0.2.255"
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    if let Some(ip) = parts.first() {
                        let mask_idx = parts
                            .iter()
                            .position(|p| *p == "netmask")
                            .map(|i| i + 1);
                        let mask = mask_idx.and_then(|i| parts.get(i)).copied();
                        let prefix = mask.and_then(|m| parse_hex_mask(m)).unwrap_or(24);
                        out.primary_cidr = Some(format!("{ip}/{prefix}"));
                        out.lan_base = network_address(ip, prefix).map(|n| format!("{n}/{prefix}"));
                    }
                } else if let Some(rest) = trim.strip_prefix("ether ") {
                    out.primary_mac = Some(rest.trim().to_owned());
                }
            }
        }
    }

    // -- DNS servers via `scutil --dns` --
    if let Ok(s) = run("scutil", &["--dns"]).await {
        let mut dns: Vec<String> = Vec::new();
        for line in s.lines() {
            let trim = line.trim();
            if let Some(rest) = trim.strip_prefix("nameserver[") {
                if let Some(idx) = rest.find("] : ") {
                    let v = &rest[idx + 4..];
                    let v = v.trim().to_owned();
                    if !v.is_empty() && !dns.contains(&v) {
                        dns.push(v);
                    }
                }
            }
        }
        out.dns_servers = dns;
    }

    // -- Public WAN IP via ifconfig.me --
    out.public_ip = fetch_public_ip().await.ok();

    out
}

async fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let res = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new(cmd).args(args).output(),
    )
    .await
    .with_context(|| format!("{cmd} timeout"))??;
    Ok(String::from_utf8_lossy(&res.stdout).into_owned())
}

async fn fetch_public_ip() -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    let resp = client.get("https://ifconfig.me").send().await?;
    // Cap response at 1 KB — ifconfig.me returns 16 bytes for an
    // IPv4. Anything bigger is a malicious or misrouted reply.
    let bytes = resp.bytes().await?;
    if bytes.len() > 1024 {
        anyhow::bail!("ifconfig.me response too large: {} bytes", bytes.len());
    }
    let text = String::from_utf8_lossy(&bytes).trim().to_owned();
    if text.is_empty() || text.len() > 64 {
        anyhow::bail!("unexpected ifconfig.me response");
    }
    Ok(text)
}

/// Convert a hex-encoded subnet mask ("0xffffff00") to a prefix
/// length (24). Returns None for malformed input.
fn parse_hex_mask(hex: &str) -> Option<u8> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let n = u32::from_str_radix(stripped, 16).ok()?;
    Some(n.count_ones() as u8)
}

/// Compute the network address by AND-ing the IP with the mask.
/// Returns None for malformed input.
fn network_address(ip: &str, prefix: u8) -> Option<String> {
    let octets: Vec<u32> = ip
        .split('.')
        .map(|o| o.parse::<u32>().ok().unwrap_or(256))
        .collect();
    if octets.len() != 4 || octets.iter().any(|o| *o > 255) {
        return None;
    }
    let ip_u32: u32 = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    let net = ip_u32 & mask;
    Some(format!(
        "{}.{}.{}.{}",
        (net >> 24) & 0xff,
        (net >> 16) & 0xff,
        (net >> 8) & 0xff,
        net & 0xff
    ))
}
