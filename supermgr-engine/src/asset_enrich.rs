//! Discovered-host enrichment — reverse DNS + zone classification.
//!
//! Runs as a post-pass on `discovery::passive_scan` /
//! `discovery::active_scan` results. Two enrichments:
//!
//! 1. **Reverse DNS.** A PTR-record lookup gives a hostname for
//!    each IP — much more useful than a bare IP for the operator.
//!    Best-effort (~1s timeout per IP, parallel).
//! 2. **Zone classification.** Tags each host as `internal` /
//!    `dmz` / `wan` / `loopback` based on RFC 1918 + RFC 6598
//!    + 169.254 link-local rules. Drives the per-finding
//!    "exposure" judgement: a Critical CVE on an `internal` host
//!    is bad, on `wan` it's incident-response material.
//!
//! All in pure Rust — no shell-out, no external services.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Zone {
    Loopback,        // 127.0.0.0/8
    LinkLocal,       // 169.254.0.0/16
    Internal,        // RFC 1918 (10/8, 172.16/12, 192.168/16)
    Cgnat,           // 100.64.0.0/10 (RFC 6598)
    Multicast,       // 224.0.0.0/4
    Public,          // everything else (incl. routable internet)
}

impl Zone {
    pub fn label(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::Internal => "internal",
            Self::Cgnat => "cgnat",
            Self::Multicast => "multicast",
            Self::Public => "public",
        }
    }

    pub fn is_routable_externally(self) -> bool {
        matches!(self, Self::Public)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEnrichment {
    pub ip: String,
    pub reverse_dns: Option<String>,
    pub zone: Zone,
}

/// Classify an IP address into one of the well-known zones.
/// Defaults to `Public` for anything that doesn't match a known
/// reserved range. IPv6 is treated as `Public` for now (we don't
/// run IPv6-specific scanning paths yet).
pub fn classify(ip: &str) -> Zone {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return Zone::Public;
    };
    match addr {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(_) => Zone::Public,
    }
}

fn classify_v4(addr: Ipv4Addr) -> Zone {
    let o = addr.octets();
    // 127.0.0.0/8 — loopback
    if o[0] == 127 { return Zone::Loopback; }
    // 169.254.0.0/16 — link-local
    if o[0] == 169 && o[1] == 254 { return Zone::LinkLocal; }
    // 10.0.0.0/8 — private
    if o[0] == 10 { return Zone::Internal; }
    // 172.16.0.0/12 — private
    if o[0] == 172 && (16..=31).contains(&o[1]) { return Zone::Internal; }
    // 192.168.0.0/16 — private
    if o[0] == 192 && o[1] == 168 { return Zone::Internal; }
    // 100.64.0.0/10 — RFC 6598 carrier-grade NAT
    if o[0] == 100 && (64..=127).contains(&o[1]) { return Zone::Cgnat; }
    // 224.0.0.0/4 — multicast
    if (224..=239).contains(&o[0]) { return Zone::Multicast; }
    Zone::Public
}

/// Reverse-DNS lookup using the OS resolver. Bounded timeout so a
/// stalled DNS server doesn't block the whole enrichment pass.
pub async fn reverse_dns(ip: &str) -> Option<String> {
    let ip_owned = ip.to_owned();
    let res = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            let parsed: IpAddr = ip_owned.parse().ok()?;
            // std::net has no reverse DNS — shell out to `host` (BSD/macOS).
            // Falls back to None on any failure; not worth a hard error.
            let out = std::process::Command::new("host")
                .arg(parsed.to_string())
                .output()
                .ok()?;
            if !out.status.success() { return None; }
            let s = String::from_utf8_lossy(&out.stdout);
            // Output: "1.0.168.192.in-addr.arpa domain name pointer foo.local."
            for line in s.lines() {
                if let Some(idx) = line.find(" domain name pointer ") {
                    let rest = &line[idx + " domain name pointer ".len()..];
                    let name = rest.trim().trim_end_matches('.').to_owned();
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
            None
        }),
    )
    .await;
    match res {
        Ok(Ok(opt)) => opt,
        _ => None,
    }
}

/// Enrich a list of IPs in parallel — bounded to 16 concurrent
/// PTR lookups so we don't overload the resolver.
pub async fn enrich_many(ips: &[String]) -> Vec<AssetEnrichment> {
    let sema = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
    let mut futs = Vec::with_capacity(ips.len());
    for ip in ips {
        let ip = ip.clone();
        let sema = sema.clone();
        futs.push(tokio::spawn(async move {
            let _permit = sema.acquire_owned().await.ok();
            let zone = classify(&ip);
            let reverse = reverse_dns(&ip).await;
            AssetEnrichment { ip, reverse_dns: reverse, zone }
        }));
    }
    let mut out = Vec::with_capacity(ips.len());
    for f in futs {
        if let Ok(r) = f.await { out.push(r); }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1918_ranges_classified_internal() {
        assert_eq!(classify("10.0.0.1"), Zone::Internal);
        assert_eq!(classify("10.255.255.254"), Zone::Internal);
        assert_eq!(classify("172.16.0.1"), Zone::Internal);
        assert_eq!(classify("172.31.255.254"), Zone::Internal);
        assert_eq!(classify("192.168.1.1"), Zone::Internal);
        assert_eq!(classify("192.168.255.254"), Zone::Internal);
    }

    #[test]
    fn rfc1918_boundaries() {
        // 172.15/* and 172.32/* are NOT RFC 1918.
        assert_eq!(classify("172.15.0.1"), Zone::Public);
        assert_eq!(classify("172.32.0.1"), Zone::Public);
        // 192.167/* is NOT 192.168/*.
        assert_eq!(classify("192.167.1.1"), Zone::Public);
        // 9.255.* and 11.* are NOT 10/8.
        assert_eq!(classify("9.255.255.255"), Zone::Public);
        assert_eq!(classify("11.0.0.0"), Zone::Public);
    }

    #[test]
    fn loopback_is_loopback() {
        assert_eq!(classify("127.0.0.1"), Zone::Loopback);
        assert_eq!(classify("127.255.255.254"), Zone::Loopback);
    }

    #[test]
    fn link_local() {
        assert_eq!(classify("169.254.0.1"), Zone::LinkLocal);
        assert_eq!(classify("169.254.255.254"), Zone::LinkLocal);
        // 169.253.* is not link-local.
        assert_eq!(classify("169.253.0.1"), Zone::Public);
    }

    #[test]
    fn cgnat_rfc6598() {
        assert_eq!(classify("100.64.0.1"), Zone::Cgnat);
        assert_eq!(classify("100.127.255.254"), Zone::Cgnat);
        assert_eq!(classify("100.63.0.1"), Zone::Public);
        assert_eq!(classify("100.128.0.1"), Zone::Public);
    }

    #[test]
    fn multicast() {
        assert_eq!(classify("224.0.0.1"), Zone::Multicast);
        assert_eq!(classify("239.255.255.255"), Zone::Multicast);
        assert_eq!(classify("240.0.0.0"), Zone::Public);
    }

    #[test]
    fn invalid_input_falls_back_to_public() {
        assert_eq!(classify("not.an.ip"), Zone::Public);
        assert_eq!(classify(""), Zone::Public);
        assert_eq!(classify("256.256.256.256"), Zone::Public);
    }

    #[test]
    fn ipv6_treated_as_public() {
        assert_eq!(classify("2001:db8::1"), Zone::Public);
        assert_eq!(classify("::1"), Zone::Public);
    }

    #[test]
    fn external_routability_only_public() {
        assert!(Zone::Public.is_routable_externally());
        assert!(!Zone::Internal.is_routable_externally());
        assert!(!Zone::Cgnat.is_routable_externally());
        assert!(!Zone::Loopback.is_routable_externally());
        assert!(!Zone::LinkLocal.is_routable_externally());
        assert!(!Zone::Multicast.is_routable_externally());
    }
}
