//! Minimal binary pcap parser — used by `traffic_sniff` for the
//! protocols where the text-output approach (`tcpdump -A`) is
//! lossy or impossible.
//!
//! # What it parses
//!
//! - libpcap "classic" format: 24-byte global header + per-packet
//!   records (16-byte header + payload).
//! - Ethernet II frames (no support for 802.1Q VLAN tags, no PPP).
//! - IPv4 only (skipped for IPv6).
//! - TCP only (UDP / ICMP / SCTP skipped).
//!
//! # What it detects
//!
//! **TLS ClientHello downgrade attempts.** A ClientHello whose
//! `legacy_version` field is less than 0x0303 (TLS 1.2) is a
//! client that's either ancient or actively attempting to
//! downgrade the handshake. The `tls_audit` server-side probe
//! tells you which TLS versions a server ACCEPTS; this fills in
//! the other side — which CLIENTS on the network are still
//! trying to use deprecated TLS.
//!
//! # Why not pcap-file / pcap crates?
//!
//! libpcap classic format is ~60 lines of byte arithmetic for a
//! reader. Pulling in a 5kloc dep for that — plus the dep audit
//! surface, the build-time hit, the IPv6+VLAN+PPP code paths
//! we'll never exercise — wasn't worth it. If we ever need
//! exotic capture formats (pcapng) or want IPv6 dual-stack
//! traffic analysis, revisit then.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::vuln::{Finding, Severity};

/// A single TLS ClientHello observed in the capture, with the
/// connection 5-tuple and the legacy_version field extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHello {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    /// Wire-format version bytes: 0x0301 = TLS 1.0, 0x0302 = 1.1,
    /// 0x0303 = 1.2 / 1.3 (real version in supported_versions ext).
    pub legacy_version: u16,
}

impl TlsClientHello {
    /// Pretty version name for the wire-format field. TLS 1.3
    /// ClientHellos use 0x0303 as legacy_version for compat —
    /// we surface "TLS 1.2+" because we can't distinguish 1.2
    /// from 1.3 without parsing the supported_versions extension
    /// (out of MVP scope).
    pub fn version_label(&self) -> &'static str {
        match self.legacy_version {
            0x0300 => "SSLv3",
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2+",
            _ => "unknown",
        }
    }

    /// True if this is a deprecated-protocol attempt.
    pub fn is_downgrade(&self) -> bool {
        self.legacy_version < 0x0303
    }
}

/// Parse a pcap file (running tcpdump capture or completed) for
/// TLS ClientHellos that attempt a deprecated protocol version.
/// Returns one finding per (client_ip, version) cluster.
pub async fn detect_tls_downgrade_clients(pcap_path: &Path) -> Result<Vec<Finding>> {
    let bytes = tokio::fs::read(pcap_path)
        .await
        .map_err(|e| anyhow!("read pcap {}: {e}", pcap_path.display()))?;

    let hellos = parse_pcap_for_clienthellos(&bytes);

    // Cluster: one finding per (src_ip, version) so a client
    // that opens 50 TLS-1.0 connections produces ONE finding,
    // not 50.
    use std::collections::BTreeMap;
    let mut by_cluster: BTreeMap<(String, u16), Vec<TlsClientHello>> = BTreeMap::new();
    for h in hellos {
        if !h.is_downgrade() {
            continue;
        }
        by_cluster
            .entry((h.src_ip.clone(), h.legacy_version))
            .or_default()
            .push(h);
    }

    let mut findings: Vec<Finding> = Vec::new();
    for ((src_ip, version), cluster) in by_cluster {
        let label = cluster[0].version_label();
        let dsts: std::collections::BTreeSet<String> = cluster
            .iter()
            .map(|h| format!("{}:{}", h.dst_ip, h.dst_port))
            .collect();
        let dsts_text: Vec<String> = dsts.into_iter().collect();
        let (severity, cvss) = match version {
            0x0300 => (Severity::Critical, 9.0), // SSLv3 — POODLE
            0x0301 => (Severity::High, 6.5),     // TLS 1.0 — BEAST + RFC 8996 deprecated
            0x0302 => (Severity::High, 5.5),     // TLS 1.1 — RFC 8996 deprecated
            _ => (Severity::Medium, 4.0),
        };
        findings.push(Finding {
            id: format!("tls.client-downgrade-{}", label.to_lowercase().replace(' ', "")),
            host_ip: src_ip.clone(),
            port: cluster.first().map(|h| h.src_port),
            service: Some("tls-client".into()),
            severity,
            title: format!("Client attempts {label} TLS handshake ({src_ip})"),
            detail: format!(
                "{} ClientHello(s) from {} requested {label} (legacy_version=0x{:04x}). \
                 RFC 8996 deprecated TLS <1.2; SSLv3 is broken (POODLE). The client is \
                 either ancient or has a misconfigured TLS library that proposes weak \
                 versions. Destination(s) observed: {}.",
                cluster.len(),
                src_ip,
                version,
                dsts_text.join(", ")
            ),
            recommendation: tls_downgrade_recommendation(version),
            cve: None,
            cvss: Some(cvss),
        });
    }
    Ok(findings)
}

fn tls_downgrade_recommendation(version: u16) -> String {
    match version {
        0x0300 => "Identify the SSLv3-attempting client and upgrade or replace it. \
            SSLv3 is broken (POODLE downgrade attack); modern servers refuse the handshake. \
            On macOS: `system_profiler SPSoftwareDataType` to identify the host. On Windows: \
            `Get-Hotfix` + check the registry SCHANNEL keys.".into(),
        0x0301 => "Identify the TLS-1.0-attempting client and update its TLS library. \
            Common culprits: legacy Java apps (pre-JDK-8u261), Python 2.7 with old OpenSSL, \
            embedded devices (printers, IP cameras, IoT). Server-side: enforce \
            `minimum_protocol_version = TLS_1_2` to break the downgrade cleanly.".into(),
        0x0302 => "Identify the TLS-1.1-attempting client and update its TLS library. \
            Same playbook as TLS 1.0 — both are RFC 8996 deprecated. Enforce TLS 1.2+ on \
            the server side to surface the broken clients via connection failure logs.".into(),
        _ => "Investigate the client's TLS configuration.".into(),
    }
}

// ---------------------------------------------------------------------------
// Pcap parser — minimal, hand-rolled, doc'd against the libpcap classic spec
// ---------------------------------------------------------------------------

fn parse_pcap_for_clienthellos(bytes: &[u8]) -> Vec<TlsClientHello> {
    let mut out = Vec::new();

    // Global header: 24 bytes. Magic + 2x version + 4 fields.
    if bytes.len() < 24 {
        return out;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let big_endian = match magic {
        0xa1b2c3d4 => false, // microsec, little-endian
        0xd4c3b2a1 => true,  // microsec, big-endian
        0xa1b23c4d => false, // nanosec, little-endian (we treat the same)
        0x4d3cb2a1 => true,  // nanosec, big-endian
        _ => return out,     // not a libpcap file
    };
    let link_type = read_u32(&bytes[20..24], big_endian);
    if link_type != 1 {
        // 1 = Ethernet. We don't support Null/Loopback (0), Raw IP (101), etc.
        return out;
    }

    let mut cursor = 24usize;
    while cursor + 16 <= bytes.len() {
        // Per-packet header: 16 bytes (ts_sec, ts_usec, incl_len, orig_len)
        let incl_len = read_u32(&bytes[cursor + 8..cursor + 12], big_endian) as usize;
        cursor += 16;
        if cursor + incl_len > bytes.len() {
            // Truncated tail packet — common during live polling.
            break;
        }
        let packet = &bytes[cursor..cursor + incl_len];
        cursor += incl_len;

        if let Some(hello) = parse_packet_for_clienthello(packet) {
            out.push(hello);
        }
    }
    out
}

/// Parse one Ethernet+IPv4+TCP packet for a TLS ClientHello in
/// the TCP payload. Returns `None` for any layer mismatch (IPv6,
/// fragments, non-TCP, etc.).
fn parse_packet_for_clienthello(eth: &[u8]) -> Option<TlsClientHello> {
    // Ethernet II header: 14 bytes (dst_mac, src_mac, ethertype).
    if eth.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
    if ethertype != 0x0800 {
        // 0x0800 = IPv4. We skip 0x86DD (IPv6) and 0x8100 (VLAN-tagged).
        return None;
    }
    let ip = &eth[14..];
    if ip.len() < 20 {
        return None;
    }
    // IPv4 header: first nibble = version, second = IHL (32-bit words).
    let version_ihl = ip[0];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (version_ihl & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    // Protocol byte at offset 9. 6 = TCP.
    if ip[9] != 6 {
        return None;
    }
    // Skip fragmented packets — TLS records won't be reconstructable.
    let frag_offset_word = u16::from_be_bytes([ip[6], ip[7]]);
    let mf_flag = (frag_offset_word >> 13) & 1;
    let frag_offset = frag_offset_word & 0x1fff;
    if mf_flag != 0 || frag_offset != 0 {
        return None;
    }
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);

    let tcp = &ip[ihl..];
    if tcp.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    // TCP header length: byte 12, upper 4 bits, in 32-bit words.
    let data_offset = ((tcp[12] >> 4) & 0x0f) as usize * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return None;
    }
    let payload = &tcp[data_offset..];
    if payload.is_empty() {
        return None;
    }

    // TLS record header: 5 bytes. Type (1), Version (2), Length (2).
    if payload.len() < 5 {
        return None;
    }
    // Type 22 = Handshake.
    if payload[0] != 22 {
        return None;
    }
    let record_version = u16::from_be_bytes([payload[1], payload[2]]);
    // Sanity: record version should be 0x03XX (SSLv3 family).
    if record_version & 0xff00 != 0x0300 {
        return None;
    }

    // Handshake message header: 4 bytes inside the record body.
    // Type (1) + Length (3, big-endian).
    if payload.len() < 9 {
        return None;
    }
    // Handshake type 1 = ClientHello.
    if payload[5] != 1 {
        return None;
    }

    // ClientHello body: starts at payload[9].
    // First field: legacy_version (2 bytes, big-endian).
    let legacy_version = u16::from_be_bytes([payload[9], payload[10]]);
    if legacy_version & 0xff00 != 0x0300 {
        // Not a TLS-family version; bogus.
        return None;
    }

    Some(TlsClientHello {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        legacy_version,
    })
}

fn read_u32(bytes: &[u8], big_endian: bool) -> u32 {
    let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if big_endian {
        u32::from_be_bytes(arr)
    } else {
        u32::from_le_bytes(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal libpcap file (LE host order) wrapping a
    /// single packet. The packet is whatever bytes the caller
    /// provides (typically a hand-crafted Eth+IP+TCP+payload).
    fn pcap_with_one_packet(packet: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24 + 16 + packet.len());
        // Magic 0xa1b2c3d4 (LE)
        buf.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        // Version major 2, minor 4
        buf.extend_from_slice(&[0x02, 0x00, 0x04, 0x00]);
        // thiszone (4) + sigfigs (4)
        buf.extend_from_slice(&[0; 8]);
        // snaplen 262144
        buf.extend_from_slice(&[0x00, 0x00, 0x04, 0x00]);
        // link type 1 (Ethernet)
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // Per-packet header
        buf.extend_from_slice(&[0; 8]); // ts_sec, ts_usec
        let len = packet.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(packet);
        buf
    }

    /// Build a minimal Ethernet+IPv4+TCP frame carrying the given
    /// TCP payload, from `src_ip`:`src_port` to `dst_ip`:`dst_port`.
    fn build_eth_ipv4_tcp(
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        // Eth: dst MAC (6) + src MAC (6) + ethertype (2)
        frame.extend_from_slice(&[0; 12]);
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        // IPv4 header (20 bytes, no options).
        let ip_total_len = 20 + 20 + payload.len();
        frame.push(0x45); // version 4, IHL 5
        frame.push(0x00); // DSCP/ECN
        frame.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0; 4]); // id + flags + frag_offset
        frame.push(64); // TTL
        frame.push(6); // protocol TCP
        frame.extend_from_slice(&[0, 0]); // checksum (unchecked)
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);
        // TCP header (20 bytes, no options)
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0; 8]); // seq + ack
        frame.push(0x50); // data offset 5 (20 bytes), reserved 0
        frame.push(0x18); // flags PSH+ACK
        frame.extend_from_slice(&[0xff, 0xff]); // window
        frame.extend_from_slice(&[0, 0]); // checksum (unchecked)
        frame.extend_from_slice(&[0, 0]); // urgent pointer
        frame.extend_from_slice(payload);
        frame
    }

    /// Build a minimal TLS ClientHello payload with the given
    /// legacy_version. We only need bytes through legacy_version
    /// — everything after is ignored by our parser.
    fn build_clienthello(legacy_version: u16) -> Vec<u8> {
        let mut p = Vec::new();
        // Record header: type=22, version=0x0301 (TLS 1.0 — what
        // a real ClientHello uses regardless of the version it's
        // requesting in the handshake body).
        p.push(22);
        p.extend_from_slice(&[0x03, 0x01]); // record version
        p.extend_from_slice(&[0x00, 0x40]); // record length (placeholder)
        // Handshake header: type=1 (ClientHello), length 3 bytes
        p.push(1);
        p.extend_from_slice(&[0x00, 0x00, 0x3c]); // body length
        // ClientHello body: legacy_version (2)
        p.extend_from_slice(&legacy_version.to_be_bytes());
        // …followed by ignored bytes (random, session_id, ciphers, ext)
        p.extend_from_slice(&[0; 64]);
        p
    }

    #[test]
    fn parses_tls10_clienthello() {
        let payload = build_clienthello(0x0301);
        let frame = build_eth_ipv4_tcp([192, 0, 2, 5], 43021, [203, 0, 113, 10], 443, &payload);
        let pcap = pcap_with_one_packet(&frame);

        let hellos = parse_pcap_for_clienthellos(&pcap);
        assert_eq!(hellos.len(), 1);
        assert_eq!(hellos[0].src_ip, "192.0.2.5");
        assert_eq!(hellos[0].src_port, 43021);
        assert_eq!(hellos[0].dst_ip, "203.0.113.10");
        assert_eq!(hellos[0].dst_port, 443);
        assert_eq!(hellos[0].legacy_version, 0x0301);
        assert!(hellos[0].is_downgrade());
        assert_eq!(hellos[0].version_label(), "TLS 1.0");
    }

    #[test]
    fn parses_tls13_clienthello_legacy_version_is_tls12() {
        // TLS 1.3 ClientHellos always carry legacy_version = 0x0303
        // (TLS 1.2). We can't distinguish 1.2 from 1.3 without
        // parsing supported_versions — that's fine, both are
        // safe; we just don't flag them.
        let payload = build_clienthello(0x0303);
        let frame = build_eth_ipv4_tcp([192, 0, 2, 5], 43021, [203, 0, 113, 10], 443, &payload);
        let pcap = pcap_with_one_packet(&frame);

        let hellos = parse_pcap_for_clienthellos(&pcap);
        assert_eq!(hellos.len(), 1);
        assert_eq!(hellos[0].legacy_version, 0x0303);
        assert!(!hellos[0].is_downgrade(), "TLS 1.2/1.3 not flagged");
        assert_eq!(hellos[0].version_label(), "TLS 1.2+");
    }

    #[test]
    fn parses_sslv3_clienthello_as_critical() {
        let payload = build_clienthello(0x0300);
        let frame = build_eth_ipv4_tcp([192, 0, 2, 5], 43021, [203, 0, 113, 10], 443, &payload);
        let pcap = pcap_with_one_packet(&frame);

        let hellos = parse_pcap_for_clienthellos(&pcap);
        assert_eq!(hellos.len(), 1);
        assert!(hellos[0].is_downgrade());
        assert_eq!(hellos[0].version_label(), "SSLv3");
    }

    #[test]
    fn ignores_non_tls_tcp_payload() {
        // HTTP request as TCP payload — type byte is 'G' = 0x47,
        // not 22 (TLS handshake).
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let frame = build_eth_ipv4_tcp([192, 0, 2, 5], 43021, [203, 0, 113, 10], 80, payload);
        let pcap = pcap_with_one_packet(&frame);

        let hellos = parse_pcap_for_clienthellos(&pcap);
        assert!(hellos.is_empty());
    }

    #[test]
    fn ignores_short_packets() {
        // Truncated payload — only 3 bytes after TCP header.
        let payload = &[22, 0x03, 0x01][..];
        let frame = build_eth_ipv4_tcp([192, 0, 2, 5], 43021, [203, 0, 113, 10], 443, payload);
        let pcap = pcap_with_one_packet(&frame);

        let hellos = parse_pcap_for_clienthellos(&pcap);
        assert!(hellos.is_empty());
    }

    #[test]
    fn ignores_handshake_type_not_clienthello() {
        // TLS record with handshake type 2 (ServerHello), not 1.
        let mut payload = Vec::new();
        payload.push(22);
        payload.extend_from_slice(&[0x03, 0x03]);
        payload.extend_from_slice(&[0x00, 0x40]);
        payload.push(2); // ServerHello
        payload.extend_from_slice(&[0x00, 0x00, 0x3c]);
        payload.extend_from_slice(&[0x03, 0x03]);
        payload.extend_from_slice(&[0; 64]);
        let frame = build_eth_ipv4_tcp([192, 0, 2, 5], 443, [203, 0, 113, 10], 43021, &payload);
        let pcap = pcap_with_one_packet(&frame);

        let hellos = parse_pcap_for_clienthellos(&pcap);
        assert!(hellos.is_empty(), "only ClientHellos flagged, not ServerHellos");
    }

    #[test]
    fn empty_pcap_returns_empty() {
        let pcap = pcap_with_one_packet(&[]);
        let hellos = parse_pcap_for_clienthellos(&pcap);
        assert!(hellos.is_empty());
    }

    #[test]
    fn malformed_magic_returns_empty() {
        let mut pcap = pcap_with_one_packet(&[]);
        pcap[0] = 0xff; // corrupt magic
        let hellos = parse_pcap_for_clienthellos(&pcap);
        assert!(hellos.is_empty());
    }

    /// End-to-end: detect_tls_downgrade_clients on a synthetic
    /// pcap with TWO downgrade attempts from the same client
    /// (one TLS 1.0, one TLS 1.1) should produce 2 findings —
    /// the cluster key is (src_ip, version), so different
    /// versions don't merge.
    #[tokio::test]
    async fn detect_two_versions_from_same_client_yields_two_findings() {
        let p1 = build_clienthello(0x0301);
        let p2 = build_clienthello(0x0302);
        let f1 = build_eth_ipv4_tcp([192, 0, 2, 5], 43021, [203, 0, 113, 10], 443, &p1);
        let f2 = build_eth_ipv4_tcp([192, 0, 2, 5], 43022, [203, 0, 113, 10], 443, &p2);
        // Combine the two packets into one pcap manually
        let mut pcap = pcap_with_one_packet(&f1);
        // Append the second packet record manually
        pcap.extend_from_slice(&[0; 8]); // ts
        let len = f2.len() as u32;
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&len.to_le_bytes());
        pcap.extend_from_slice(&f2);

        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), pcap).expect("write");

        let _ = Duration::from_secs(1); // touch import
        let findings = detect_tls_downgrade_clients(tmp.path()).await.expect("ok");
        assert_eq!(findings.len(), 2, "TLS 1.0 + TLS 1.1 = two findings");
        assert!(findings.iter().any(|f| f.id == "tls.client-downgrade-tls1.0"));
        assert!(findings.iter().any(|f| f.id == "tls.client-downgrade-tls1.1"));
    }

    #[tokio::test]
    async fn modern_traffic_emits_no_findings() {
        let payload = build_clienthello(0x0303); // TLS 1.2 / 1.3 — not a downgrade
        let frame = build_eth_ipv4_tcp([192, 0, 2, 5], 43021, [203, 0, 113, 10], 443, &payload);
        let pcap = pcap_with_one_packet(&frame);
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), pcap).expect("write");

        let findings = detect_tls_downgrade_clients(tmp.path()).await.expect("ok");
        assert!(findings.is_empty(), "TLS 1.2+ = no downgrade events");
    }
}
