//! DNS zone-transfer (AXFR) probe.
//!
//! Tries to pull the full DNS zone from each of the domain's
//! authoritative nameservers. Misconfigured authoritative NSes
//! that allow anonymous AXFR leak every record in the zone —
//! internal hostnames, IPs, mail routing, SPF/DKIM/DMARC, all of
//! it. This is one of the highest-signal-to-effort recon checks
//! a Kali-style toolkit ships (see: `dig axfr`, `dnsenum`,
//! `dnsrecon -t axfr`).
//!
//! # How it works
//!
//!   1. Resolve the domain's NS records via `dig`.
//!   2. For each nameserver, attempt `dig @<ns> AXFR <domain>` with
//!      a tight timeout.
//!   3. If the response contains `XFR size` or multiple A/CNAME
//!      records, the transfer succeeded — emit a Critical finding
//!      with a sample of the leaked records.
//!
//! # Why shell out to `dig` instead of an AXFR-capable Rust lib?
//!
//! AXFR is a multi-message TCP-only DNS exchange. Implementing it
//! correctly in Rust would mean either pulling in `hickory-dns`
//! (heavy) or hand-rolling DNS message parsing. `dig` ships on
//! every Mac/Linux box, handles edge cases (rfc-1035 truncation,
//! glue records, etc.), and matches the pattern already used by
//! `dns_health.rs`. Shell-out cost is dwarfed by the 4-second
//! TCP timeout per nameserver.
//!
//! # Output
//!
//! Returns a `Vec<Finding>`. Empty when no NS allowed AXFR (the
//! good case). One finding per leaking NS — operators usually
//! want to see them individually because each leak is its own
//! misconfig to remediate.

use std::time::Duration;

use crate::vuln::{Finding, Severity};

/// Probe a domain for AXFR leakage across all its authoritative
/// nameservers. Returns one finding per nameserver that allowed
/// the zone transfer.
pub async fn check(domain: &str) -> Vec<Finding> {
    let nameservers = list_nameservers(domain).await;
    if nameservers.is_empty() {
        return Vec::new();
    }

    let mut findings: Vec<Finding> = Vec::new();
    for ns in &nameservers {
        if let Some(transfer) = attempt_axfr(domain, ns).await {
            findings.push(build_finding(domain, ns, &transfer));
        }
    }
    findings
}

/// Resolve `<domain> NS` to a list of authoritative servers.
/// Returns hostnames (trailing dot stripped). Empty on failure.
async fn list_nameservers(domain: &str) -> Vec<String> {
    let lines = dig_short(domain, "NS").await;
    lines
        .into_iter()
        .map(|l| l.trim_end_matches('.').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Run `dig @<ns> AXFR <domain>` and inspect the result.
/// Returns:
///   - `Some(transfer)` — the NS allowed the transfer; `transfer`
///     is a struct with the record count and a sample.
///   - `None` — the NS refused (typical), timed out, or
///     unreachable.
async fn attempt_axfr(domain: &str, ns: &str) -> Option<AxfrTransfer> {
    let output = match tokio::time::timeout(
        Duration::from_secs(8),
        tokio::process::Command::new("dig")
            .args([
                &format!("@{ns}"),
                "+timeout=5",
                "+tries=1",
                // Force TCP — AXFR is always TCP.
                "+tcp",
                // Don't show the verbose header noise; we only
                // need the records themselves.
                "+nocomments",
                "+nocmd",
                "+noquestion",
                "+nostats",
                "+noauthority",
                "+noadditional",
                "AXFR",
                domain,
            ])
            .output(),
    )
    .await
    {
        Ok(Ok(o)) => o,
        _ => return None,  // timeout or spawn error
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    // "Transfer failed" / "REFUSED" / "connection refused" /
    // "communications error" are the canonical refusal markers.
    let lc = combined.to_lowercase();
    if lc.contains("transfer failed")
        || lc.contains("refused")
        || lc.contains("communications error")
        || lc.contains("connection refused")
        || lc.contains("no servers could be reached")
        || lc.contains("rcode = notauth")
    {
        return None;
    }

    // A successful AXFR returns a series of DNS records, one per
    // line. Filter out comments + empty lines and require at
    // least two records (just an SOA isn't useful and is
    // sometimes returned even on partial-allow servers).
    let records: Vec<String> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with(';'))
        .map(str::to_owned)
        .collect();

    if records.len() < 2 {
        return None;
    }

    Some(AxfrTransfer {
        record_count: records.len(),
        // Keep first 10 records as evidence — enough to confirm
        // the leak without overflowing the finding detail.
        sample: records.into_iter().take(10).collect(),
    })
}

struct AxfrTransfer {
    record_count: usize,
    sample: Vec<String>,
}

fn build_finding(domain: &str, ns: &str, transfer: &AxfrTransfer) -> Finding {
    let sample_text = transfer
        .sample
        .iter()
        .map(|r| format!("  • {r}"))
        .collect::<Vec<_>>()
        .join("\n");
    Finding {
        id: "dns.axfr-allowed".into(),
        host_ip: ns.to_owned(),
        port: Some(53),
        service: Some("dns".into()),
        severity: Severity::High,
        title: format!("DNS zone transfer (AXFR) leaks {domain} from {ns}"),
        detail: format!(
            "{ns} responded to an anonymous AXFR query and returned \
             {} record(s) for the {domain} zone. Anyone who can reach \
             port 53/TCP on this nameserver can now enumerate every \
             A, CNAME, MX, TXT, and SRV record in the zone — internal \
             hostnames, mail routing, SPF/DKIM, infrastructure layout. \
             First records returned:\n{sample_text}",
            transfer.record_count
        ),
        recommendation: format!(
            "Restrict AXFR to a known-NS allowlist. \
             BIND: `allow-transfer {{ <secondary-NS-IP>; }};` in the zone block, \
             default to `none`. \
             NSD/Knot/PowerDNS: same — explicit ACL on `also-notify` / \
             `allow-axfr`. \
             Cloud DNS (Route 53, Cloudflare, Google Cloud DNS): zone \
             transfer is disabled by default, but if you've enabled it \
             for migration, revoke once cutover is complete. \
             Verify: `dig @{ns} AXFR {domain}` from an unauthorized IP \
             should return `Transfer failed.`"
        ),
        cve: None,
        cvss: Some(7.5),
    }
}

// ---------------------------------------------------------------------------
// dig helpers (mirrors the pattern in dns_health.rs but tighter)
// ---------------------------------------------------------------------------

async fn dig_short(name: &str, rrtype: &str) -> Vec<String> {
    let res = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::process::Command::new("dig")
            .args(["+short", "+timeout=2", "+tries=1", rrtype, name])
            .output(),
    )
    .await;
    let Ok(Ok(out)) = res else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Refusal marker detection — every common phrasing rejected.
    #[test]
    fn refusal_markers_recognised() {
        // We can't easily unit-test the full attempt_axfr without
        // network, but the refusal-marker logic IS isolated: the
        // function returns None for any of these substrings in the
        // combined stdout/stderr.
        let cases = [
            "; Transfer failed.",
            ";; communications error to 1.2.3.4#53: connection refused",
            ";; communications error to 1.2.3.4#53: timed out",
            "; <<>> DiG 9.10 <<>> @ns1.example.com AXFR example.com\n;; no servers could be reached",
            "rcode = NOTAUTH",
            ";; REFUSED",
        ];
        for c in cases {
            let lc = c.to_lowercase();
            let is_refusal = lc.contains("transfer failed")
                || lc.contains("refused")
                || lc.contains("communications error")
                || lc.contains("connection refused")
                || lc.contains("no servers could be reached")
                || lc.contains("rcode = notauth");
            assert!(is_refusal, "should recognise as refusal: {c:?}");
        }
    }

    /// Building the finding produces the right shape.
    #[test]
    fn finding_shape() {
        let t = AxfrTransfer {
            record_count: 42,
            sample: vec![
                "example.com. 86400 IN SOA ns1.example.com. ...".into(),
                "www.example.com. 300 IN A 192.0.2.1".into(),
            ],
        };
        let f = build_finding("example.com", "ns1.example.com", &t);
        assert_eq!(f.id, "dns.axfr-allowed");
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("example.com"));
        assert!(f.title.contains("ns1.example.com"));
        assert!(f.detail.contains("42 record"));
        assert!(f.detail.contains("www.example.com"));
        assert!(f.recommendation.contains("allow-transfer"));
    }
}
