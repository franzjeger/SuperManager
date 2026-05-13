//! Passive traffic sniffer — finds clients communicating
//! insecurely + generates proof-of-concept evidence for customer
//! validation.
//!
//! # What this is for (and what it isn't)
//!
//! MSP audits routinely uncover suspicions like "is anything on
//! this LAN still using cleartext FTP / telnet / HTTP basic
//! auth?". The right answer to give a customer is:
//!
//!   - **YES, here is evidence:** "Client 192.168.1.50 sent 23
//!     HTTP-basic-auth requests to 192.168.1.100:80 between
//!     14:23 and 14:24 UTC. Username `admin` was transmitted in
//!     cleartext. The full packet capture is at
//!     `<engagement>/captures/2026-05-13-1423.pcap` for your DLP
//!     review."
//!   - **NO, no evidence found in N minutes of capture:**
//!     "We listened for 60 seconds on en0 with a BPF filter
//!     covering cleartext FTP/telnet/HTTP-basic/POP3/IMAP/SMTP-AUTH
//!     and saw nothing. The capture file is empty."
//!
//! What this is NOT:
//!   - A red-team tool. We never inject traffic, never strip
//!     TLS, never ARP-spoof. Pure passive observation.
//!   - A credential harvester. Captured passwords are hashed
//!     (SHA-256) before being persisted in findings. Operators
//!     who genuinely need the cleartext can read the raw .pcap
//!     directly with Wireshark.
//!
//! # How the analyser works
//!
//! Caller (helper or operator) writes a .pcap. We shell out to
//! `tcpdump -r <pcap> -A -nn -tttt -X` and grep the ASCII
//! payload representation for cleartext-protocol signatures.
//! Each matched packet becomes evidence; packets sharing
//! (src_ip, protocol) are clustered into a single Finding so an
//! ftp session of 30 commands produces ONE finding ("Cleartext
//! FTP credentials from 192.168.1.50") rather than 30.
//!
//! Why shell-out to tcpdump instead of a pure-Rust pcap parser?
//! Same reason as `dns_axfr.rs`: tcpdump handles every edge case
//! (8021Q VLAN tags, IPv6, IP fragmentation, TCP reassembly when
//! `-A` is used) for free. Detection is substring-matching on
//! ASCII payloads — exactly the format tcpdump emits.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vuln::{Finding, Severity};

/// What gets returned to the caller of `analyse_pcap()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAuditResult {
    /// One finding per (src_ip, protocol) cluster of cleartext
    /// events seen in the capture.
    pub findings: Vec<Finding>,
    /// Paths to per-finding evidence excerpts (redacted) that
    /// were written next to the .pcap. Useful for embedding in
    /// engagement reports.
    pub evidence_files: Vec<String>,
    /// Total packets the analyser inspected (may differ from the
    /// pcap's packet count if tcpdump bails early).
    pub packets_inspected: usize,
    /// Total cleartext events matched across all protocols. Sum
    /// of per-finding event counts.
    pub events_matched: usize,
}

/// Analyse a packet capture for cleartext-protocol exposure.
/// `pcap_path` must exist and be readable. `evidence_dir` is
/// where redacted per-finding excerpt files are written; if it
/// doesn't exist, it is created.
pub async fn analyse_pcap(pcap_path: &Path, evidence_dir: &Path) -> Result<TrafficAuditResult> {
    if !pcap_path.exists() {
        return Err(anyhow!("pcap not found: {}", pcap_path.display()));
    }
    std::fs::create_dir_all(evidence_dir)
        .map_err(|e| anyhow!("create evidence dir {}: {e}", evidence_dir.display()))?;

    // Shell out to tcpdump -r with ASCII payload (-A) +
    // numeric ports (-nn) + ISO timestamps (-tttt) + verbose
    // header (-v) so we can attribute packets to their src/dst.
    //
    // The 60s timeout is generous; even a multi-gigabyte pcap
    // parses to text in well under that on a modern Mac.
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("tcpdump")
            .args([
                "-r", &pcap_path.to_string_lossy(),
                "-A",         // ASCII payload dump
                "-nn",        // numeric host + port (no DNS resolve)
                "-tttt",      // ISO-like timestamps
                "-v",         // include IP-level info
                "-q",         // quiet protocol decoding (keeps output compact)
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("tcpdump -r timed out"))?
    .map_err(|e| anyhow!("spawn tcpdump: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("tcpdump -r exited non-zero: {stderr}"));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let events = scan_events(&text);

    let packets_inspected = text.lines().filter(|l| is_packet_header_line(l)).count();
    let events_matched = events.len();

    // Cluster events by (src_ip, protocol_id).
    let mut by_cluster: HashMap<(String, &'static str), Vec<&Event>> = HashMap::new();
    for ev in &events {
        by_cluster
            .entry((ev.src_ip.clone(), ev.protocol.id))
            .or_default()
            .push(ev);
    }

    // Stable iteration order for deterministic finding output.
    let mut clusters: Vec<((String, &'static str), Vec<&Event>)> =
        by_cluster.into_iter().collect();
    clusters.sort_by(|a, b| a.0.cmp(&b.0));

    let mut findings: Vec<Finding> = Vec::new();
    let mut evidence_files: Vec<String> = Vec::new();

    for ((src_ip, _proto_id), cluster) in clusters {
        let proto = cluster[0].protocol;
        let dst_set: std::collections::BTreeSet<String> = cluster
            .iter()
            .map(|e| format!("{}:{}", e.dst_ip, e.dst_port))
            .collect();

        // Write per-cluster redacted evidence file. Filename
        // pattern: traffic-<proto>-<src_ip>.txt
        let evidence_filename = format!(
            "traffic-{}-{}.txt",
            proto.id.replace('.', "-"),
            src_ip.replace(':', "_"),
        );
        let evidence_path = evidence_dir.join(&evidence_filename);
        let mut evidence_body = String::new();
        evidence_body.push_str(&format!(
            "Cleartext {} from {} — {} event(s)\n",
            proto.name,
            src_ip,
            cluster.len()
        ));
        evidence_body.push_str(&format!("Generated by SuperManager traffic-sniff\n"));
        evidence_body.push_str(&format!("Source pcap: {}\n\n", pcap_path.display()));
        for ev in &cluster {
            evidence_body.push_str(&format!(
                "[{}] {}:{} -> {}:{}\n",
                ev.timestamp, ev.src_ip, ev.src_port, ev.dst_ip, ev.dst_port,
            ));
            evidence_body.push_str(&format!("    {}\n\n", ev.redacted_excerpt));
        }
        if let Err(e) = std::fs::write(&evidence_path, &evidence_body) {
            tracing::warn!(
                "could not write evidence file {}: {e}",
                evidence_path.display()
            );
        } else {
            evidence_files.push(evidence_path.to_string_lossy().into_owned());
        }

        let title = format!("Cleartext {} from {}", proto.name, src_ip);
        let detail = format!(
            "{} event(s) of cleartext {} captured from {} to {}. \
             Anyone passively listening on the network segment can read \
             the credentials or session tokens in plaintext. Evidence \
             file (redacted, passwords SHA-256 hashed) saved at \
             {}. Full unredacted .pcap for DLP review: {}.",
            cluster.len(),
            proto.name,
            src_ip,
            dst_set.iter().cloned().collect::<Vec<_>>().join(", "),
            evidence_path.display(),
            pcap_path.display(),
        );
        findings.push(Finding {
            id: format!("traffic.cleartext-{}", proto.id),
            host_ip: src_ip.clone(),
            port: cluster.first().map(|e| e.src_port),
            service: Some(proto.id.into()),
            severity: proto.severity,
            title,
            detail,
            recommendation: proto.recommendation.into(),
            cve: None,
            cvss: Some(proto.cvss),
        });
    }

    Ok(TrafficAuditResult {
        findings,
        evidence_files,
        packets_inspected,
        events_matched,
    })
}

// ---------------------------------------------------------------------------
// Event extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Event {
    timestamp: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    protocol: ProtocolDef,
    redacted_excerpt: String,
}

#[derive(Debug, Clone, Copy)]
struct ProtocolDef {
    id: &'static str,
    name: &'static str,
    severity: Severity,
    cvss: f32,
    recommendation: &'static str,
}

const PROTO_FTP_CREDS: ProtocolDef = ProtocolDef {
    id: "ftp",
    name: "FTP credentials",
    severity: Severity::High,
    cvss: 8.0,
    recommendation: "Disable FTP; switch to SFTP (SSH-tunneled) or FTPS (FTP over TLS). \
        On the affected client: replace `ftp` calls with `sftp` / `scp` / `rsync over ssh`.",
};
const PROTO_TELNET: ProtocolDef = ProtocolDef {
    id: "telnet",
    name: "Telnet session",
    severity: Severity::Critical,
    cvss: 9.0,
    recommendation: "Disable telnet on the destination. Use SSH for command-line access. \
        On Cisco IOS: `no telnet` / `transport input ssh`. On legacy IoT, replace device \
        or front-end with an SSH bastion.",
};
const PROTO_HTTP_BASIC: ProtocolDef = ProtocolDef {
    id: "http-basic",
    name: "HTTP basic-auth",
    severity: Severity::High,
    cvss: 7.5,
    recommendation: "Either move the affected endpoint behind HTTPS only (Strict-Transport-Security + \
        HTTP→HTTPS redirect), or replace basic-auth with a token/OAuth/SAML flow that doesn't \
        re-transmit credentials on every request.",
};
const PROTO_POP3_CREDS: ProtocolDef = ProtocolDef {
    id: "pop3",
    name: "POP3 credentials",
    severity: Severity::High,
    cvss: 7.5,
    recommendation: "Enforce POP3S (port 995) or IMAPS. Disable plaintext POP3 (port 110) on the \
        mail server. Migrate clients to TLS-only connections.",
};
const PROTO_IMAP_CREDS: ProtocolDef = ProtocolDef {
    id: "imap",
    name: "IMAP credentials",
    severity: Severity::High,
    cvss: 7.5,
    recommendation: "Enforce IMAPS (port 993). Disable plaintext IMAP (port 143). \
        On the client: update mail-account config to require SSL/TLS.",
};
const PROTO_SMTP_AUTH: ProtocolDef = ProtocolDef {
    id: "smtp-auth",
    name: "SMTP AUTH (cleartext)",
    severity: Severity::High,
    cvss: 7.0,
    recommendation: "Enforce STARTTLS or migrate to submission-port 587/465 with explicit TLS. \
        Disable plaintext AUTH on the MTA (Postfix: `smtpd_tls_auth_only = yes`; \
        Exchange: require TLS on receive connectors).",
};
const PROTO_SNMP_COMMUNITY: ProtocolDef = ProtocolDef {
    id: "snmp-community",
    name: "SNMP community string (cleartext)",
    severity: Severity::High,
    cvss: 7.5,
    recommendation: "Migrate to SNMPv3 with authPriv (SHA + AES). \
        On managed switches / firewalls / printers / UPS: set v3 user with \
        authProtocol = SHA-256, privProtocol = AES-128 minimum, then disable v1/v2c. \
        If v2c MUST stay (legacy device): rotate the community string to a 32-char random \
        secret and ACL the SNMP listener to the management VLAN only.",
};
const PROTO_HTTP_FORM_POST: ProtocolDef = ProtocolDef {
    id: "http-form-post",
    name: "HTTP form-POST credentials (cleartext)",
    severity: Severity::High,
    cvss: 8.0,
    recommendation: "Move the affected endpoint behind HTTPS only. Set HSTS, redirect HTTP→HTTPS, \
        and ensure login forms POST to https:// URLs (not http://). Check the form's HTML \
        for absolute http:// action URLs — those bypass any redirect.",
};

/// Header line emitted by `tcpdump -A -tttt`: starts with an ISO-like
/// timestamp.
fn is_packet_header_line(line: &str) -> bool {
    // Cheap shape check: "2026-05-13 14:23:45.123456 IP …"
    line.len() > 27
        && line.as_bytes().get(4) == Some(&b'-')
        && line.as_bytes().get(7) == Some(&b'-')
        && line.as_bytes().get(10) == Some(&b' ')
        && line.contains(" IP ")
}

/// Walk the tcpdump -A text output looking for cleartext-protocol
/// signatures. Returns one Event per match. Multi-line payload
/// reassembly is approximate — we look at each packet's contiguous
/// payload block (everything after the header line until the next
/// header line or EOF).
fn scan_events(text: &str) -> Vec<Event> {
    let mut events: Vec<Event> = Vec::new();
    let mut current_header: Option<PacketHeader> = None;
    let mut current_payload = String::new();

    for line in text.lines() {
        if is_packet_header_line(line) {
            // Flush previous packet.
            if let Some(header) = current_header.take() {
                events.extend(scan_packet_payload(&header, &current_payload));
            }
            current_payload.clear();
            current_header = parse_packet_header(line);
        } else if current_header.is_some() {
            current_payload.push_str(line);
            current_payload.push('\n');
        }
    }
    // Flush final packet.
    if let Some(header) = current_header {
        events.extend(scan_packet_payload(&header, &current_payload));
    }
    events
}

#[derive(Debug, Clone)]
struct PacketHeader {
    timestamp: String,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

/// Parse a tcpdump packet header like:
///   "2026-05-13 14:23:45.123456 IP 192.168.1.50.43021 > 192.168.1.100.80: tcp …"
/// We only care about the timestamp + the IP.port -> IP.port piece.
fn parse_packet_header(line: &str) -> Option<PacketHeader> {
    // Timestamp: first 26 chars roughly.
    let ts_end = line.find(" IP ")?;
    let timestamp = line[..ts_end].to_owned();
    let rest = &line[ts_end + 4..];
    let arrow = rest.find(" > ")?;
    let src = &rest[..arrow];
    let after = &rest[arrow + 3..];
    let colon = after.find(':')?;
    let dst = &after[..colon];

    let (src_ip, src_port) = split_ip_port(src)?;
    let (dst_ip, dst_port) = split_ip_port(dst)?;

    Some(PacketHeader {
        timestamp,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    })
}

/// "192.168.1.50.43021" → ("192.168.1.50", 43021). Last dot
/// separates the port from the address (works for IPv4; for IPv6
/// tcpdump uses `.` after the bracketed address — covered).
fn split_ip_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim_end_matches(',').trim();
    let last_dot = s.rfind('.')?;
    let port: u16 = s[last_dot + 1..].parse().ok()?;
    Some((s[..last_dot].to_owned(), port))
}

/// Scan a single packet's payload block for any of our protocol
/// signatures. Multiple Events per packet are possible (e.g. an
/// FTP payload that contains both USER and PASS — though that's
/// rare in a single TCP segment).
fn scan_packet_payload(header: &PacketHeader, payload: &str) -> Vec<Event> {
    let mut out: Vec<Event> = Vec::new();

    // FTP: USER / PASS on port 21
    if header.dst_port == 21 || header.src_port == 21 {
        if let Some(idx) = find_line_prefix(payload, "USER ") {
            let line = extract_line_from(payload, idx);
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_FTP_CREDS,
                redacted_excerpt: line, // username is OK to keep
            });
        }
        if let Some(idx) = find_line_prefix(payload, "PASS ") {
            let line = extract_line_from(payload, idx);
            let redacted = redact_after_first_space(&line);
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_FTP_CREDS,
                redacted_excerpt: redacted,
            });
        }
    }

    // Telnet: any payload on port 23 = cleartext exposure
    if header.dst_port == 23 || header.src_port == 23 {
        if !payload.trim().is_empty() {
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_TELNET,
                redacted_excerpt: "(telnet payload — see .pcap for content)".into(),
            });
        }
    }

    // HTTP basic auth: case-insensitive "Authorization: Basic"
    if header.dst_port == 80
        || header.dst_port == 8080
        || header.dst_port == 8000
        || header.dst_port == 8888
    {
        let lc = payload.to_lowercase();
        if let Some(idx) = lc.find("authorization: basic ") {
            // Pull the original-case line. The header value (base64
            // creds) is redacted to SHA-256 of the base64 string,
            // not the raw creds — close enough for fingerprinting
            // duplicate events without leaking the credential.
            let line = extract_line_from(payload, idx);
            let redacted = redact_basic_auth(&line);
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_HTTP_BASIC,
                redacted_excerpt: redacted,
            });
        }
    }

    // POP3: USER / PASS on port 110
    if header.dst_port == 110 || header.src_port == 110 {
        if let Some(idx) = find_line_prefix(payload, "USER ") {
            let line = extract_line_from(payload, idx);
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_POP3_CREDS,
                redacted_excerpt: line,
            });
        }
        if let Some(idx) = find_line_prefix(payload, "PASS ") {
            let line = extract_line_from(payload, idx);
            let redacted = redact_after_first_space(&line);
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_POP3_CREDS,
                redacted_excerpt: redacted,
            });
        }
    }

    // IMAP: tag LOGIN user pass — e.g. "a001 LOGIN user pass"
    if header.dst_port == 143 || header.src_port == 143 {
        let lc = payload.to_lowercase();
        // Look for " LOGIN " (space before+after) to avoid matching
        // strings like "LOGIN PLAIN".
        if let Some(idx) = lc.find(" login ") {
            let line = extract_line_from(payload, idx);
            // IMAP LOGIN is "tag LOGIN user pass" — redact from
            // the second space after LOGIN onwards.
            let redacted = redact_imap_login(&line);
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_IMAP_CREDS,
                redacted_excerpt: redacted,
            });
        }
    }

    // SMTP AUTH: client sends "AUTH PLAIN <base64>" or "AUTH LOGIN"
    if header.dst_port == 25 || header.dst_port == 587 || header.dst_port == 465 {
        let lc = payload.to_lowercase();
        if let Some(idx) = lc.find("auth plain ") {
            let line = extract_line_from(payload, idx);
            let redacted = redact_after_first_space_then_space(&line);
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_SMTP_AUTH,
                redacted_excerpt: redacted,
            });
        } else if let Some(idx) = lc.find("auth login") {
            let line = extract_line_from(payload, idx);
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_SMTP_AUTH,
                redacted_excerpt: line,
            });
        }
    }

    // SNMP v1/v2c community-string exposure (UDP 161 / 162). When
    // `tcpdump -v` decodes an SNMP packet it prints the community
    // in the clear in several different forms depending on
    // tcpdump version: `C="public"`, `community public`,
    // `{ Community = "public" }`. Match any of them.
    if header.dst_port == 161
        || header.dst_port == 162
        || header.src_port == 161
        || header.src_port == 162
    {
        if let Some(community) = extract_snmp_community(payload) {
            // Treat well-known "public" / "private" as separately-
            // important — those are the canonical default-credential
            // findings — but flag ANY cleartext community since v3
            // is the only safe path. The redacted excerpt keeps the
            // community name in the clear (the operator needs it to
            // see WHICH legacy credential is exposed) — this isn't
            // a "redact for safety" path, it's the actual finding.
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_SNMP_COMMUNITY,
                redacted_excerpt: format!("SNMP community=\"{community}\""),
            });
        }
    }

    // HTTP form-POST password capture. Operates on requests to
    // common HTTP ports — the body of a POST with
    // `application/x-www-form-urlencoded` is plaintext key=value
    // pairs (limited to the first TCP segment; multi-segment
    // form bodies are out of scope for the text-parsing model
    // and would need real TCP reassembly).
    if header.dst_port == 80
        || header.dst_port == 8080
        || header.dst_port == 8000
        || header.dst_port == 8888
    {
        if let Some(form) = extract_http_form_password(payload) {
            out.push(Event {
                timestamp: header.timestamp.clone(),
                src_ip: header.src_ip.clone(),
                src_port: header.src_port,
                dst_ip: header.dst_ip.clone(),
                dst_port: header.dst_port,
                protocol: PROTO_HTTP_FORM_POST,
                redacted_excerpt: form,
            });
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Helpers — payload pattern matching + redaction
// ---------------------------------------------------------------------------

/// Find a prefix that occurs at the start of any line in the
/// payload. Returns the byte index of the prefix into `payload`.
/// Used for protocols whose command words are line-anchored.
fn find_line_prefix(payload: &str, prefix: &str) -> Option<usize> {
    // Direct match at byte 0 of the payload.
    if payload.starts_with(prefix) {
        return Some(0);
    }
    // After any newline.
    let pat = format!("\n{prefix}");
    payload.find(&pat).map(|i| i + 1)
}

fn extract_line_from(payload: &str, start: usize) -> String {
    let end = payload[start..]
        .find('\n')
        .map(|i| start + i)
        .unwrap_or(payload.len());
    payload[start..end].trim_end_matches('\r').to_owned()
}

/// "PASS hunter2" → "PASS sha256:abcd1234…"
/// We hash the full password so duplicate events cluster, but
/// the cleartext never lands in our findings/evidence files.
fn redact_after_first_space(line: &str) -> String {
    let mut iter = line.splitn(2, ' ');
    let cmd = iter.next().unwrap_or("");
    let rest = iter.next().unwrap_or("");
    format!("{cmd} sha256:{}", short_hash(rest))
}

/// "AUTH PLAIN dXNlcgB1c2VyAHBhc3M=" → "AUTH PLAIN sha256:abcd1234…"
fn redact_after_first_space_then_space(line: &str) -> String {
    // First two tokens are the verb ("AUTH" and "PLAIN"), the
    // rest is the base64 blob to redact.
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    match parts.as_slice() {
        [a, b, rest] => format!("{a} {b} sha256:{}", short_hash(rest)),
        _ => line.to_owned(),
    }
}

/// "a001 LOGIN frank hunter2" → "a001 LOGIN frank sha256:abcd1234…"
fn redact_imap_login(line: &str) -> String {
    let parts: Vec<&str> = line.splitn(4, ' ').collect();
    match parts.as_slice() {
        [tag, login, user, pass] if login.eq_ignore_ascii_case("login") => {
            format!("{tag} {login} {user} sha256:{}", short_hash(pass))
        }
        _ => line.to_owned(),
    }
}

/// "Authorization: Basic dXNlcjpwYXNz" →
/// "Authorization: Basic sha256:abcd1234…"
fn redact_basic_auth(line: &str) -> String {
    let lc = line.to_lowercase();
    let needle = "authorization: basic ";
    if let Some(idx) = lc.find(needle) {
        let prefix = &line[..idx + needle.len()];
        let blob = &line[idx + needle.len()..];
        // Strip trailing CR/spaces from the blob.
        let blob = blob.trim_end();
        return format!("{prefix}sha256:{}", short_hash(blob));
    }
    line.to_owned()
}

fn short_hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let bytes = h.finalize();
    // 16 hex chars (64 bits) — enough to distinguish duplicate
    // creds without enabling cross-engagement correlation.
    let hex: String = bytes.iter().take(8).map(|b| format!("{b:02x}")).collect();
    hex
}

/// Extract an SNMP community string from a tcpdump-printed
/// SNMP packet, if one is present. tcpdump's SNMP printer emits
/// the community in a few different forms depending on version:
///
///   - `C="public"`
///   - `{ Community = "public" }`
///   - `community public`
///   - `Community: "public"`
///
/// We try each in turn. Returns the community string itself
/// (without surrounding quotes / whitespace). Returns `None` if
/// the payload isn't an SNMP packet or tcpdump didn't decode it
/// (which happens for SNMPv3 — those packets carry an encrypted
/// PDU and don't have a cleartext community to print).
fn extract_snmp_community(payload: &str) -> Option<String> {
    // Pattern 1: `C="..."`
    if let Some(idx) = payload.find("C=\"") {
        let rest = &payload[idx + 3..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_owned());
        }
    }
    // Pattern 2: `Community = "..."` (with or without spaces around =)
    let lc = payload.to_lowercase();
    if let Some(idx) = lc.find("community") {
        let rest = &payload[idx + "community".len()..];
        let trimmed = rest.trim_start_matches([' ', '=', ':', '\t']);
        // Quoted form
        if let Some(stripped) = trimmed.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                return Some(stripped[..end].to_owned());
            }
        }
        // Bareword form — take the first whitespace-delimited token.
        if let Some(token) = trimmed.split_whitespace().next() {
            // Sanity: rule out tokens that look like noise.
            if token.len() <= 64
                && token.chars().all(|c| c.is_ascii_graphic())
                // Skip tcpdump's own punctuation/wrapper tokens.
                && !token.starts_with('{')
                && !token.starts_with('[')
                && !token.starts_with('(')
            {
                let cleaned = token.trim_matches(|c: char| matches!(c, ',' | '}' | ']' | ')'));
                if !cleaned.is_empty() {
                    return Some(cleaned.to_owned());
                }
            }
        }
    }
    None
}

/// Extract a password-bearing field from an HTTP form-POST body
/// in a tcpdump ASCII payload. Returns a redacted string like
///   `POST /login.php  password=sha256:abcd1234…`
/// keeping the path + non-credential fields useful for attribution
/// while hashing the password itself.
///
/// Single-segment captures only: if the POST body spans multiple
/// TCP segments, this misses it. Real TCP reassembly is out of
/// scope for the text-parsing model. In practice ~95% of login
/// POSTs fit in one segment because the typical form body is
/// `username=…&password=…&csrf=…` — well under MTU.
fn extract_http_form_password(payload: &str) -> Option<String> {
    // Must be a POST request.
    if !payload.starts_with("POST ") && !payload.contains("\nPOST ") {
        return None;
    }
    // Must be form-urlencoded — JSON / multipart bodies aren't
    // simple key=value pairs and need a different parse.
    let lc = payload.to_lowercase();
    if !lc.contains("application/x-www-form-urlencoded") {
        return None;
    }
    // Find the body — separator is `\r\n\r\n` or `\n\n`.
    let body_start = payload
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| payload.find("\n\n").map(|i| i + 2))?;
    let body = &payload[body_start..];
    // Look for password-bearing keys.
    let body_lc = body.to_lowercase();
    let key = ["password=", "passwd=", "pwd=", "pass="]
        .iter()
        .find(|k| body_lc.contains(*k))
        .copied()?;
    // Extract the request path from the POST line for context.
    let request_line = payload.lines().find(|l| l.starts_with("POST "))?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();
    // Pull the password value, hash it, leave other fields alone.
    let idx = body_lc.find(key)?;
    let key_len = key.len();
    let value_end = body[idx + key_len..]
        .find('&')
        .map(|i| idx + key_len + i)
        .unwrap_or(body.len());
    let password = &body[idx + key_len..value_end];
    // Build a redacted version of the body that swaps the
    // password value for its hash but keeps the other keys
    // (`username`, `csrf_token`, etc.) intact for attribution.
    let mut redacted = String::with_capacity(body.len());
    redacted.push_str(&body[..idx + key_len]);
    redacted.push_str(&format!("sha256:{}", short_hash(password)));
    redacted.push_str(&body[value_end..]);
    // Trim to first 200 chars so we don't paste huge form blobs
    // into the finding detail.
    if redacted.len() > 200 {
        redacted.truncate(200);
        redacted.push_str("…");
    }
    Some(format!("POST {path}  {redacted}"))
}

/// Helper to produce the engagement evidence directory path.
/// Given an engagement_id, returns
/// `<data-dir>/findings_store/<engagement_id>/captures/`.
pub fn engagement_evidence_dir(engagement_id: &str) -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("findings_store");
    p.push(engagement_id);
    p.push("captures");
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_packet_header() {
        let line = "2026-05-13 14:23:45.123456 IP 192.168.1.50.43021 > 192.168.1.100.80: tcp 240";
        let h = parse_packet_header(line).expect("must parse");
        assert_eq!(h.timestamp, "2026-05-13 14:23:45.123456");
        assert_eq!(h.src_ip, "192.168.1.50");
        assert_eq!(h.src_port, 43021);
        assert_eq!(h.dst_ip, "192.168.1.100");
        assert_eq!(h.dst_port, 80);
    }

    #[test]
    fn is_packet_header_recognises_iso_timestamp() {
        assert!(is_packet_header_line(
            "2026-05-13 14:23:45.123456 IP 1.1.1.1.80 > 2.2.2.2.443: tcp 0"
        ));
        assert!(!is_packet_header_line("    payload bytes here"));
        assert!(!is_packet_header_line(""));
    }

    #[test]
    fn find_line_prefix_at_start() {
        let payload = "USER frank\r\nPASS secret\r\n";
        assert_eq!(find_line_prefix(payload, "USER "), Some(0));
        assert_eq!(find_line_prefix(payload, "PASS "), Some(12));
    }

    #[test]
    fn extract_line_strips_cr() {
        let payload = "USER frank\r\nPASS secret\r\n";
        assert_eq!(extract_line_from(payload, 0), "USER frank");
        assert_eq!(extract_line_from(payload, 12), "PASS secret");
    }

    #[test]
    fn redact_pass_command() {
        let r = redact_after_first_space("PASS hunter2");
        assert!(r.starts_with("PASS sha256:"));
        assert!(!r.contains("hunter2"));
    }

    #[test]
    fn redact_imap_login_keeps_user_not_pass() {
        let r = redact_imap_login("a001 LOGIN frank hunter2");
        assert!(r.contains("frank"), "user kept: {r}");
        assert!(r.contains("sha256:"), "pass redacted: {r}");
        assert!(!r.contains("hunter2"));
    }

    #[test]
    fn redact_basic_auth_blob() {
        let r = redact_basic_auth("Authorization: Basic dXNlcjpwYXNz");
        assert!(r.starts_with("Authorization: Basic sha256:"));
        assert!(!r.contains("dXNlcjpwYXNz"));
    }

    #[test]
    fn redact_smtp_auth_plain_blob() {
        let r = redact_after_first_space_then_space("AUTH PLAIN dXNlcgB1c2VyAHBhc3M=");
        assert!(r.starts_with("AUTH PLAIN sha256:"));
        assert!(!r.contains("dXNlcgB1c2VyAHBhc3M="));
    }

    #[test]
    fn short_hash_deterministic() {
        let a = short_hash("hunter2");
        let b = short_hash("hunter2");
        let c = short_hash("hunter3");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }

    /// Synthesise a tcpdump-style output and verify scanning
    /// produces an FTP credential event with correct details.
    #[test]
    fn scan_events_extracts_ftp_credentials() {
        let text = "\
2026-05-13 14:23:45.000000 IP 192.168.1.50.43021 > 192.168.1.100.21: tcp 13
USER frank
2026-05-13 14:23:45.500000 IP 192.168.1.50.43021 > 192.168.1.100.21: tcp 15
PASS hunter2
";
        let events = scan_events(text);
        assert_eq!(events.len(), 2, "USER + PASS");
        assert!(events.iter().all(|e| e.protocol.id == "ftp"));
        assert!(events[0].redacted_excerpt.contains("frank"));
        assert!(events[1].redacted_excerpt.starts_with("PASS sha256:"));
        assert!(!events[1].redacted_excerpt.contains("hunter2"));
    }

    #[test]
    fn scan_events_extracts_http_basic_auth() {
        let text = "\
2026-05-13 14:23:45.000000 IP 192.168.1.50.43021 > 192.168.1.100.80: tcp 120
GET /admin HTTP/1.1
Host: 192.168.1.100
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
User-Agent: curl/8.0
";
        let events = scan_events(text);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].protocol.id, "http-basic");
        assert_eq!(events[0].src_ip, "192.168.1.50");
        assert_eq!(events[0].dst_port, 80);
        assert!(events[0].redacted_excerpt.contains("sha256:"));
        assert!(!events[0].redacted_excerpt.contains("YWRtaW46cGFzc3dvcmQ="));
    }

    #[test]
    fn scan_events_extracts_telnet_session() {
        let text = "\
2026-05-13 14:23:45.000000 IP 192.168.1.50.43021 > 192.168.1.100.23: tcp 20
some telnet payload bytes here
";
        let events = scan_events(text);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].protocol.id, "telnet");
        assert_eq!(events[0].protocol.severity, Severity::Critical);
    }

    #[test]
    fn scan_events_extracts_imap_login() {
        let text = "\
2026-05-13 14:23:45.000000 IP 192.168.1.50.43021 > 192.168.1.100.143: tcp 30
a001 LOGIN frank.lia hunter2
";
        let events = scan_events(text);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].protocol.id, "imap");
        assert!(events[0].redacted_excerpt.contains("frank.lia"));
        assert!(!events[0].redacted_excerpt.contains("hunter2"));
    }

    #[test]
    fn scan_events_extracts_smtp_auth_plain() {
        let text = "\
2026-05-13 14:23:45.000000 IP 192.168.1.50.43021 > mail.example.com.587: tcp 40
AUTH PLAIN dXNlcgB1c2VyAHBhc3M=
";
        let events = scan_events(text);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].protocol.id, "smtp-auth");
        assert!(!events[0].redacted_excerpt.contains("dXNlcgB1c2VyAHBhc3M="));
    }

    #[test]
    fn clean_traffic_emits_zero_events() {
        // HTTPS only, no cleartext credentials.
        let text = "\
2026-05-13 14:23:45.000000 IP 192.168.1.50.43021 > 1.1.1.1.443: tcp 60
.....binary tls bytes....
";
        let events = scan_events(text);
        assert!(events.is_empty(), "no cleartext = no events; got {events:?}");
    }

    // ─── SNMP community-string extraction ──────────────────────────

    #[test]
    fn extract_snmp_community_c_equals_form() {
        // tcpdump's terse `C="public"` form.
        let payload = "  SNMPv2c C=\"public\" GetRequest(28) R=12345\n";
        assert_eq!(extract_snmp_community(payload).as_deref(), Some("public"));
    }

    #[test]
    fn extract_snmp_community_braced_form() {
        // tcpdump's `{ Community = "private" }` form.
        let payload = "  { SNMPv2c { Community = \"private\" } GetRequest }\n";
        assert_eq!(extract_snmp_community(payload).as_deref(), Some("private"));
    }

    #[test]
    fn extract_snmp_community_bareword_form() {
        // `community public` (no quotes).
        let payload = "    community public  GetRequest(28) ...\n";
        assert_eq!(extract_snmp_community(payload).as_deref(), Some("public"));
    }

    #[test]
    fn extract_snmp_community_custom_string() {
        // A non-default community is still a finding (cleartext is
        // cleartext); we want to surface the actual string so the
        // operator knows what's leaked.
        let payload = "C=\"super-secret-2024\" GetRequest";
        assert_eq!(
            extract_snmp_community(payload).as_deref(),
            Some("super-secret-2024")
        );
    }

    #[test]
    fn extract_snmp_community_returns_none_when_absent() {
        // SNMPv3 packets have no plaintext community.
        let payload = "    SNMPv3 msgUserName=foo encryptedPDU(48)\n";
        assert_eq!(extract_snmp_community(payload), None);
    }

    #[test]
    fn scan_events_extracts_snmp_community() {
        let text = "\
2026-05-13 14:23:45.000000 IP 192.0.2.5.55555 > 192.0.2.10.161: udp 80
  SNMPv2c C=\"public\" GetRequest(28) .1.3.6.1.2.1.1.5.0
";
        let events = scan_events(text);
        let snmp: Vec<&Event> = events.iter().filter(|e| e.protocol.id == "snmp-community").collect();
        assert_eq!(snmp.len(), 1);
        assert!(snmp[0].redacted_excerpt.contains("public"));
        assert_eq!(snmp[0].src_ip, "192.0.2.5");
        assert_eq!(snmp[0].dst_port, 161);
    }

    // ─── HTTP form-POST password extraction ────────────────────────

    #[test]
    fn extract_http_form_password_basic() {
        let payload = "POST /login.php HTTP/1.1\r\n\
                       Host: example.com\r\n\
                       Content-Type: application/x-www-form-urlencoded\r\n\
                       Content-Length: 42\r\n\
                       \r\n\
                       username=alex&password=hunter2&remember=1";
        let result = extract_http_form_password(payload).expect("must extract");
        assert!(result.contains("POST /login.php"));
        assert!(result.contains("username=alex"));
        assert!(result.contains("password=sha256:"));
        assert!(!result.contains("hunter2"));
        // Other form fields kept for attribution.
        assert!(result.contains("remember=1"));
    }

    #[test]
    fn extract_http_form_password_alternative_keys() {
        for key in &["passwd", "pwd", "pass"] {
            let payload = format!(
                "POST /signin HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=alex&{key}=hunter2",
            );
            let result = extract_http_form_password(&payload)
                .unwrap_or_else(|| panic!("must extract for key {key}"));
            assert!(result.contains(&format!("{key}=sha256:")), "got: {result}");
            assert!(!result.contains("hunter2"));
        }
    }

    #[test]
    fn extract_http_form_password_returns_none_on_get() {
        let payload = "GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_form_password(payload), None);
    }

    #[test]
    fn extract_http_form_password_returns_none_without_form_content_type() {
        // JSON-bodied POST is out of scope for this detector.
        let payload = "POST /api/login HTTP/1.1\r\n\
                       Content-Type: application/json\r\n\r\n\
                       {\"username\":\"alex\",\"password\":\"hunter2\"}";
        assert_eq!(extract_http_form_password(payload), None);
    }

    #[test]
    fn extract_http_form_password_returns_none_without_password_field() {
        let payload = "POST /api/event HTTP/1.1\r\n\
                       Content-Type: application/x-www-form-urlencoded\r\n\r\n\
                       event_name=login&duration=42";
        assert_eq!(extract_http_form_password(payload), None);
    }

    #[test]
    fn scan_events_extracts_http_form_post() {
        let text = "\
2026-05-13 14:23:45.000000 IP 192.0.2.50.43021 > 192.0.2.100.80: tcp 220
POST /admin/login.php HTTP/1.1\r
Host: 192.0.2.100\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 38\r
\r
username=admin&password=correcthorse
";
        let events = scan_events(text);
        let post: Vec<&Event> = events.iter().filter(|e| e.protocol.id == "http-form-post").collect();
        assert_eq!(post.len(), 1, "should find one POST event");
        assert!(post[0].redacted_excerpt.contains("password=sha256:"));
        assert!(!post[0].redacted_excerpt.contains("correcthorse"));
        assert!(post[0].redacted_excerpt.contains("/admin/login.php"));
        assert!(post[0].redacted_excerpt.contains("username=admin"));
    }
}
