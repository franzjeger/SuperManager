//! LDAP / Active Directory enumeration via raw protocol probe.
//!
//! When TCP/389 (LDAP) or TCP/636 (LDAPS) is open, attackers
//! often try anonymous-bind to enumerate naming contexts, domain
//! info, and operational attributes. The information leak from a
//! single anonymous query identifies:
//!   - Forest + domain DNS name (`rootDomainNamingContext`)
//!   - Domain Functional Level
//!   - Schema version
//!   - Naming contexts (every OU/container the directory exposes)
//!
//! We send a raw `LDAPv3` `BindRequest` (anonymous) followed by a
//! `SearchRequest` against the rootDSE. Hand-rolled BER encoding —
//! no need to pull in a full LDAP crate for this surface.
//!
//! # Findings produced
//!
//! - `ldap.anonymous-bind` — Critical. Anonymous bind succeeded.
//! - `ldap.rootdse-readable` — High. `RootDSE` is readable
//!   without auth. (Anonymous-bind implies this; we only emit
//!   the second finding when bind required no creds AND the
//!   search returned attributes.)
//!
//! Both findings include the leaked attributes in `detail` so
//! the operator sees what's exposed without needing to re-run
//! the probe manually.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::vuln::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LdapInfo {
    pub anonymous_bind: bool,
    /// Naming contexts (DN strings) returned by rootDSE. Typical
    /// AD entries: "DC=example,DC=com", "CN=Configuration,...",
    /// "CN=Schema,...".
    pub naming_contexts: Vec<String>,
    /// Default naming context (the AD domain DN).
    pub default_naming_context: Option<String>,
    /// Domain DNS name parsed from `default_naming_context`.
    /// "DC=corp,DC=example,DC=com" → "corp.example.com".
    pub domain_dns: Option<String>,
    /// Domain functional level (AD-specific).
    pub domain_functionality: Option<String>,
    /// Forest functional level.
    pub forest_functionality: Option<String>,
    /// Server name + DNS host name.
    pub server_name: Option<String>,
}

/// Probe LDAP on (host, port). Returns None if the bind failed
/// (auth required) or the server didn't speak `LDAPv3`.
pub async fn enumerate(host: &str, port: u16) -> Option<(LdapInfo, Vec<Finding>)> {
    let target = format!("{host}:{port}");
    let mut stream = match timeout(Duration::from_secs(4), TcpStream::connect(&target)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // -- Anonymous BindRequest (LDAPv3) --
    // BER:  30 0c                ; Sequence, len 12
    //         02 01 01            ; messageID = 1
    //         60 07               ; BindRequest, len 7
    //           02 01 03          ; version = 3
    //           04 00             ; bindDN = ""
    //           80 00             ; AuthenticationChoice simple = ""
    let bind = [
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
    ];
    if timeout(Duration::from_secs(3), stream.write_all(&bind))
        .await
        .is_err()
    {
        return None;
    }

    let mut resp = vec![0u8; 256];
    let n = match timeout(Duration::from_secs(3), stream.read(&mut resp)).await {
        Ok(Ok(n)) if n > 7 => n,
        _ => return None,
    };
    resp.truncate(n);

    // Parse BindResponse — the resultCode is at a known offset
    // when the message is well-formed LDAPv3. resultCode = 0
    // means success (anonymous bind accepted).
    let bound = parse_bind_success(&resp);
    if !bound {
        // Not anonymously bound. Stop — we don't probe further.
        return Some((LdapInfo::default(), Vec::new()));
    }

    // -- SearchRequest against rootDSE --
    // Asks for: namingContexts, defaultNamingContext, dnsHostName,
    // serverName, domainFunctionality, forestFunctionality.
    let search = build_rootdse_search();
    if timeout(Duration::from_secs(3), stream.write_all(&search))
        .await
        .is_err()
    {
        return None;
    }

    let mut search_resp = vec![0u8; 8192];
    let n = match timeout(Duration::from_secs(4), stream.read(&mut search_resp)).await {
        Ok(Ok(n)) if n > 8 => n,
        _ => return None,
    };
    search_resp.truncate(n);

    // We don't fully decode the BER — just scrape the printable
    // strings the server returned. AD's rootDSE attributes are
    // ASCII (LDAP DN strings, version numbers, hostnames) so this
    // is enough to surface the info-disclosure.
    let strings = extract_printable_strings(&search_resp);
    let info = build_info_from_strings(&strings);

    let mut findings: Vec<Finding> = Vec::new();
    findings.push(Finding {
        id: "ldap.anonymous-bind".into(),
        host_ip: host.to_owned(),
        port: Some(port),
        service: Some("ldap".into()),
        severity: Severity::High,
        title: "LDAP allows anonymous bind".into(),
        detail: format!(
            "Anonymous LDAP bind succeeded. Even read-only access leaks domain structure, user OUs, and AD functional levels. Attackers chain this with Kerberoasting / AS-REP roasting against discovered SPNs.{}",
            info.domain_dns
                .as_deref()
                .map(|d| format!(" Domain: {d}."))
                .unwrap_or_default()
        ),
        recommendation: "Disable anonymous bind: set `dsHeuristics` 7th character to '2' on AD, or set `olcRequires: authc` on OpenLDAP. Restrict the LDAP service to authenticated callers only.".into(),
        cve: None,
        cvss: Some(7.0),
    });
    if !info.naming_contexts.is_empty() {
        findings.push(Finding {
            id: "ldap.rootdse-leak".into(),
            host_ip: host.to_owned(),
            port: Some(port),
            service: Some("ldap".into()),
            severity: Severity::Medium,
            title: "LDAP rootDSE exposes naming contexts to anonymous callers".into(),
            detail: format!(
                "Naming contexts returned: {}. Default: {}.{}",
                info.naming_contexts.join(", "),
                info.default_naming_context.as_deref().unwrap_or("—"),
                info.domain_functionality
                    .as_deref()
                    .map(|d| format!(" Domain functional level: {d}."))
                    .unwrap_or_default(),
            ),
            recommendation: "If anonymous bind is required for application compatibility, restrict which attributes anonymous callers can read (LDAP ACLs / Domain object dsHeuristics).".into(),
            cve: None,
            cvss: Some(5.5),
        });
    }
    Some((info, findings))
}

/// Parse an ASN.1 BER definite length field starting at `input[0]`.
/// Returns `(content_len, length_header_bytes)`. Rejects indefinite
/// length (`0x80`) and length-of-length > 4 octets (`> 0x84`).
fn parse_ber_length(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    if !(0x81..=0x84).contains(&first) {
        return None;
    }
    let num_octets = (first & 0x7f) as usize;
    let octets = input.get(1..=num_octets)?;
    let mut len = 0usize;
    for &b in octets {
        len = (len << 8) | (b as usize);
    }
    Some((len, 1 + num_octets))
}

/// Look at the `BindResponse`'s resultCode byte. Handles both
/// short-form BER lengths (OpenLDAP: `30 0c 02 01 01 61 07 ...`)
/// and 4-byte `0x84` definite long-form BER lengths (Windows Active
/// Directory: `30 84 00 00 00 10 02 01 01 61 84 00 00 00 07 ...`).
/// resultCode 0 = success.
fn parse_bind_success(bytes: &[u8]) -> bool {
    fn inner(bytes: &[u8]) -> Option<bool> {
        if *bytes.first()? != 0x30 {
            return None;
        }
        let (seq_len, seq_hdr) = parse_ber_length(&bytes[1..])?;
        let seq_start = 1 + seq_hdr;
        let seq_end = seq_start.checked_add(seq_len)?.min(bytes.len());
        let seq = bytes.get(seq_start..seq_end)?;

        // messageID: INTEGER (0x02)
        if *seq.first()? != 0x02 {
            return None;
        }
        let (id_len, id_hdr) = parse_ber_length(&seq[1..])?;
        if id_len == 0 {
            return None;
        }
        let after_id = (1 + id_hdr).checked_add(id_len)?;
        let rest = seq.get(after_id..)?;

        // BindResponse: [APPLICATION 1] (0x61)
        if *rest.first()? != 0x61 {
            return None;
        }
        let (bind_len, bind_hdr) = parse_ber_length(&rest[1..])?;
        let bind_start = 1 + bind_hdr;
        let bind_end = bind_start.checked_add(bind_len)?.min(rest.len());
        let bind_body = rest.get(bind_start..bind_end)?;

        // resultCode: ENUMERATED (0x0a)
        if *bind_body.first()? != 0x0a {
            return None;
        }
        let (rc_len, rc_hdr) = parse_ber_length(&bind_body[1..])?;
        if rc_len == 0 {
            return None;
        }
        let rc_start = 1 + rc_hdr;
        let rc_end = rc_start.checked_add(rc_len)?;
        let rc_bytes = bind_body.get(rc_start..rc_end)?;
        Some(rc_bytes.iter().all(|&b| b == 0))
    }

    inner(bytes).unwrap_or(false)
}

/// Build a `SearchRequest` for rootDSE attributes.
/// BER-encoded `LDAPv3` search filter targeting baseObject "" with
/// scope=baseObject, filter=(objectClass=*), and an explicit
/// attribute list.
fn build_rootdse_search() -> Vec<u8> {
    // Hand-built BER encoding. Pre-computed offsets for clarity.
    // messageID = 2.
    // SearchRequest [APPLICATION 3]:
    //   baseObject ""           : 04 00
    //   scope baseObject (0)    : 0a 01 00
    //   derefAliases never (0)  : 0a 01 00
    //   sizeLimit 0             : 02 01 00
    //   timeLimit 5             : 02 01 05
    //   typesOnly false         : 01 01 00
    //   filter (objectClass=*)  : 87 0b 6f 62 6a 65 63 74 43 6c 61 73 73   (present "objectClass")
    //   attributes [
    //     "namingContexts",
    //     "defaultNamingContext",
    //     "domainFunctionality",
    //     "forestFunctionality",
    //     "dnsHostName",
    //     "serverName",
    //   ]
    let attrs = [
        "namingContexts",
        "defaultNamingContext",
        "domainFunctionality",
        "forestFunctionality",
        "dnsHostName",
        "serverName",
    ];
    let mut attr_seq: Vec<u8> = Vec::new();
    for a in &attrs {
        attr_seq.push(0x04);
        attr_seq.push(a.len() as u8);
        attr_seq.extend_from_slice(a.as_bytes());
    }
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[0x04, 0x00]); // baseObject ""
    body.extend_from_slice(&[0x0a, 0x01, 0x00]); // scope = base
    body.extend_from_slice(&[0x0a, 0x01, 0x00]); // derefAliases = never
    body.extend_from_slice(&[0x02, 0x01, 0x00]); // sizeLimit = 0
    body.extend_from_slice(&[0x02, 0x01, 0x05]); // timeLimit = 5
    body.extend_from_slice(&[0x01, 0x01, 0x00]); // typesOnly = false
                                                 // filter [7] PRESENT "objectClass"
    body.push(0x87);
    body.push(11);
    body.extend_from_slice(b"objectClass");
    // attributes Sequence
    body.push(0x30);
    body.push(attr_seq.len() as u8);
    body.extend_from_slice(&attr_seq);

    let mut search_req: Vec<u8> = Vec::new();
    search_req.push(0x63); // [APPLICATION 3] SearchRequest
    search_req.push(body.len() as u8);
    search_req.extend_from_slice(&body);

    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice(&[0x02, 0x01, 0x02]); // messageID = 2
    msg.extend_from_slice(&search_req);

    let mut envelope: Vec<u8> = Vec::new();
    envelope.push(0x30);
    envelope.push(msg.len() as u8);
    envelope.extend_from_slice(&msg);
    envelope
}

/// Pull printable ASCII runs out of a byte buffer. Skips runs <
/// 4 bytes (too noisy) and runs > 256 bytes (likely binary blob
/// that happens to be ASCII).
fn extract_printable_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for &b in bytes {
        if (32..127).contains(&b) {
            current.push(b);
        } else {
            if (4..=256).contains(&current.len()) {
                if let Ok(s) = std::str::from_utf8(&current) {
                    out.push(s.to_owned());
                }
            }
            current.clear();
        }
    }
    if (4..=256).contains(&current.len()) {
        if let Ok(s) = std::str::from_utf8(&current) {
            out.push(s.to_owned());
        }
    }
    out
}

fn build_info_from_strings(strings: &[String]) -> LdapInfo {
    let mut info = LdapInfo {
        anonymous_bind: true,
        ..Default::default()
    };
    for s in strings {
        if s.starts_with("DC=") || s.starts_with("dc=") {
            info.naming_contexts.push(s.clone());
            if info.default_naming_context.is_none() {
                info.default_naming_context = Some(s.clone());
                info.domain_dns = Some(dn_to_dns(s));
            }
        } else if s.contains("CN=") {
            // Configuration / Schema / DomainDnsZones — naming
            // context but not the default domain.
            info.naming_contexts.push(s.clone());
        }
    }
    // Functional levels are integer-strings ("0".."7") emitted
    // alone in the response; we can't reliably tell them apart
    // from other small strings without full BER, so leave them
    // None unless we explicitly see the tag context.
    let _ = info.domain_functionality.is_none();
    info
}

/// Convert "DC=corp,DC=example,DC=com" → "corp.example.com".
fn dn_to_dns(dn: &str) -> String {
    dn.split(',')
        .filter_map(|component| {
            let trimmed = component.trim();
            let lower = trimmed.to_lowercase();
            lower
                .strip_prefix("dc=")
                .map(std::borrow::ToOwned::to_owned)
        })
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openldap_short_form_bind_response() {
        // Canonical OpenLDAP anonymous BindResponse (resultCode = 0 success).
        let ok_pkt = [
            0x30, 0x0c, // SEQUENCE len 12
            0x02, 0x01, 0x01, // messageID = 1
            0x61, 0x07, // BindResponse len 7
            0x0a, 0x01, 0x00, // resultCode = 0 (success)
            0x04, 0x00, // matchedDN = ""
            0x04, 0x00, // diagnosticMessage = ""
        ];
        assert!(parse_bind_success(&ok_pkt));

        // OpenLDAP invalidCredentials (resultCode = 49 = 0x31).
        let fail_pkt = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00,
        ];
        assert!(!parse_bind_success(&fail_pkt));
    }

    #[test]
    fn parses_windows_ad_long_form_0x84_bind_response() {
        // Windows Active Directory encodes SEQUENCE and BindResponse lengths
        // using 4-byte definite long-form `0x84 0x00 0x00 0x00 LL`.
        let ad_ok_pkt = [
            0x30, 0x84, 0x00, 0x00, 0x00, 0x10, // SEQUENCE (0x84 -> 4-byte len = 16)
            0x02, 0x01, 0x01, // messageID = 1
            0x61, 0x84, 0x00, 0x00, 0x00, 0x07, // BindResponse (0x84 -> 4-byte len = 7)
            0x0a, 0x01, 0x00, // resultCode = 0 (success)
            0x04, 0x00, // matchedDN = ""
            0x04, 0x00, // diagnosticMessage = ""
        ];
        assert!(parse_bind_success(&ad_ok_pkt));

        // Also test long-form encoding on messageID INTEGER itself + failure resultCode.
        let ad_fail_pkt = [
            0x30, 0x84, 0x00, 0x00, 0x00, 0x14, // SEQUENCE
            0x02, 0x84, 0x00, 0x00, 0x00, 0x01, 0x01, // messageID = 1 (long-form len)
            0x61, 0x84, 0x00, 0x00, 0x00, 0x07, // BindResponse
            0x0a, 0x01, 0x30, // resultCode = 48 (inappropriateAuthentication)
            0x04, 0x00, 0x04, 0x00,
        ];
        assert!(!parse_bind_success(&ad_fail_pkt));
    }

    #[test]
    fn rejects_malformed_or_indefinite_ber_without_panic() {
        for bad in [
            &[][..],
            &[0x30, 0x80, 0x02, 0x01, 0x01, 0x61, 0x03, 0x0a, 0x01, 0x00][..], // indefinite 0x80
            &[0x30, 0x85, 0, 0, 0, 0, 1][..],                                  // >4 octets 0x85
            &[0x30, 0x84, 0x00, 0x00][..],                                     // truncated len
        ] {
            assert!(!parse_bind_success(bad));
        }
    }
}
