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
//! - `ldap.anonymous-bind` — High. Anonymous bind succeeded.
//! - `ldap.rootdse-leak` — Medium. `RootDSE` is readable
//!   without auth. (Anonymous-bind implies this; we only emit
//!   the second finding when bind required no creds AND the
//!   search returned naming contexts.)
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
    let Ok(Ok(mut stream)) = timeout(Duration::from_secs(4), TcpStream::connect(&target)).await
    else {
        return None;
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

/// Whether `bytes` is a `BindResponse` whose resultCode is 0, success:
///
/// ```text
///   30 LL           ; LDAPMessage SEQUENCE
///     02 LL ID      ; messageID
///     61 LL         ; BindResponse [APPLICATION 1]
///       0a 01 RC    ; resultCode ENUMERATED
/// ```
///
/// Read element by element, not at fixed offsets: Active Directory writes
/// every length in the long form (`30 84 00 00 00 10 …`), so the offsets of
/// a short-form reply are wrong for exactly the servers this probe is for.
fn parse_bind_success(bytes: &[u8]) -> bool {
    let result_code = || {
        let (message, _) = ber_element(bytes, 0x30)?;
        let (_, rest) = ber_element(message, 0x02)?;
        let (bind_response, _) = ber_element(rest, 0x61)?;
        let (result_code, _) = ber_element(bind_response, 0x0a)?;
        Some(result_code)
    };
    result_code() == Some(&[0])
}

/// Build a `SearchRequest` for rootDSE attributes: baseObject "",
/// scope baseObject, filter (objectClass=*), and an explicit attribute
/// list, as message 2.
fn build_rootdse_search() -> Vec<u8> {
    const ATTRS: [&str; 6] = [
        "namingContexts",
        "defaultNamingContext",
        "domainFunctionality",
        "forestFunctionality",
        "dnsHostName",
        "serverName",
    ];
    let attributes: Vec<u8> = ATTRS.iter().flat_map(|a| ber(0x04, a.as_bytes())).collect();
    let search = [
        ber(0x04, b""),            // baseObject ""
        ber(0x0a, &[0]),           // scope = baseObject
        ber(0x0a, &[0]),           // derefAliases = never
        ber(0x02, &[0]),           // sizeLimit = 0
        ber(0x02, &[5]),           // timeLimit = 5
        ber(0x01, &[0]),           // typesOnly = false
        ber(0x87, b"objectClass"), // filter [7] present "objectClass"
        ber(0x30, &attributes),    // attributes
    ]
    .concat();
    let message = [
        ber(0x02, &[2]),    // messageID = 2
        ber(0x63, &search), // [APPLICATION 3] SearchRequest
    ]
    .concat();
    ber(0x30, &message)
}

/// One BER element: `tag`, the length of `content`, then `content`.
///
/// A length below 128 is one byte; from 128 it is the long form, 0x80 plus
/// the number of bytes that follow, then the length big-endian. (This
/// request's `SearchRequest` is 137 bytes, which a single length byte
/// would claim is "9 length bytes follow".)
fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(content.len()) {
        Ok(len) if len < 0x80 => out.push(len),
        _ => {
            let len = content.len().to_be_bytes();
            let first = len.iter().position(|&b| b != 0).unwrap_or(len.len() - 1);
            let len = &len[first..];
            // A usize has at most 8 bytes, far below the 127 the form allows.
            out.push(0x80 | u8::try_from(len.len()).expect("a usize has at most 8 bytes"));
            out.extend_from_slice(len);
        }
    }
    out.extend_from_slice(content);
    out
}

/// The element at the start of `bytes`, if it has this `tag` and all of it
/// is there: its content, and the bytes after it. Definite lengths only,
/// which is all LDAP allows.
fn ber_element(bytes: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, rest) = bytes.split_first()?;
    if found != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > std::mem::size_of::<usize>() {
            return None; // indefinite, or longer than anything we read
        }
        let (len, rest) = rest.split_at_checked(n)?;
        let len = len.iter().fold(0, |acc, &b| (acc << 8) | usize::from(b));
        (len, rest)
    };
    rest.split_at_checked(len)
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
    // from other small strings without full BER, so they stay None.
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
    fn a_length_from_128_takes_the_long_form() {
        assert_eq!(ber(0x04, &[0; 127])[..2], [0x04, 0x7f]);
        assert_eq!(ber(0x04, &[0; 128])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(ber(0x04, &[0; 256])[..4], [0x04, 0x82, 0x01, 0x00]);
        assert_eq!(ber(0x04, b""), [0x04, 0x00]);
    }

    #[test]
    fn the_rootdse_search_reads_back_as_one_message() {
        let request = build_rootdse_search();
        let (message, after) = ber_element(&request, 0x30).expect("an LDAPMessage");
        assert!(after.is_empty(), "the message covers the whole request");
        let (id, rest) = ber_element(message, 0x02).expect("a messageID");
        assert_eq!(id, [2]);
        let (search, after) = ber_element(rest, 0x63).expect("a SearchRequest");
        assert!(after.is_empty());
        // Past 127 bytes: the length the old encoder wrapped into 0x89.
        assert_eq!(search.len(), 137);
        let (base, _) = ber_element(search, 0x04).expect("a baseObject");
        assert!(base.is_empty());
    }

    #[test]
    fn a_bind_response_is_read_in_either_length_form() {
        // OpenLDAP: short-form lengths.
        let short = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        assert!(parse_bind_success(&short));
        // Active Directory: every length in the long form.
        let long = [
            0x30, 0x84, 0x00, 0x00, 0x00, 0x10, 0x02, 0x01, 0x01, 0x61, 0x84, 0x00, 0x00, 0x00,
            0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        assert!(parse_bind_success(&long));
        // invalidCredentials (49) is not success.
        let refused = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00,
        ];
        assert!(!parse_bind_success(&refused));
        // Cut short, or not LDAP at all.
        assert!(!parse_bind_success(&long[..12]));
        assert!(!parse_bind_success(b"SSH-2.0-OpenSSH_9.6\r\n"));
        assert!(!parse_bind_success(&[]));
    }
}
