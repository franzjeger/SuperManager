//! Service probes — active-discovery building blocks.
//!
//! Each probe is small, async, and time-bounded. Higher-level
//! orchestration in `discovery::active_scan` runs them in
//! parallel across hosts + ports.
//!
//! # What we probe (Phase B+ active scope)
//!
//! - **TCP connect** — reachability of common ports (top-100)
//! - **HTTP** — Server/X-Powered-By/title banner-grab
//! - **HTTPS** — TLS handshake (cipher, version, cert details)
//!   via shell-out to `openssl s_client`
//! - **SSH** — banner read on TCP connect
//! - **SNMP** — read sysDescr.0 with default community strings
//!   via shell-out to `snmpget` (when installed)
//! - **SMB** — NetBIOS query over UDP
//! - **Telnet** — flag if open at all
//!
//! Banner data is the foundation of vulnerability detection in
//! `vuln.rs` — version strings get matched against bundled CVE
//! database.

use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Top-100 most common TCP ports to probe in active-discovery
/// pass. Curated from real MSP fleet experience — covers the
/// services that actually matter (mgmt, infrastructure, web,
/// remote access). Avoids the long tail of esoteric services
/// that rarely yield value.
pub const COMMON_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    67,    // DHCP
    69,    // TFTP
    80,    // HTTP
    81,    // HTTP-alt (mikrotik, etc.)
    88,    // Kerberos
    110,   // POP3
    111,   // RPC
    123,   // NTP
    135,   // MS-RPC
    137,   // NetBIOS-NS
    138,   // NetBIOS-DGM
    139,   // NetBIOS-SSN
    143,   // IMAP
    161,   // SNMP
    389,   // LDAP
    443,   // HTTPS
    445,   // SMB
    465,   // SMTPS
    500,   // IPsec/IKE
    514,   // syslog
    515,   // LPD/printer
    548,   // AFP
    554,   // RTSP
    587,   // SMTP-submission
    631,   // IPP
    636,   // LDAPS
    873,   // rsync
    902,   // VMware
    989,   // FTPS-data
    990,   // FTPS-control
    993,   // IMAPS
    995,   // POP3S
    1080,  // SOCKS
    1194,  // OpenVPN
    1433,  // MSSQL
    1434,  // MSSQL-monitor
    1521,  // Oracle
    1701,  // L2TP
    1723,  // PPTP
    1812,  // RADIUS-auth
    1813,  // RADIUS-acct
    2049,  // NFS
    2082,  // cPanel
    2083,  // cPanel-ssl
    2222,  // SSH-alt
    2375,  // Docker
    2376,  // Docker-tls
    3000,  // Grafana / various web
    3128,  // Squid proxy
    3268,  // LDAP-Global-Catalog
    3306,  // MySQL
    3389,  // RDP
    3478,  // STUN
    4444,  // Metasploit (red flag)
    4500,  // IPsec-NAT-T
    4789,  // VXLAN
    5000,  // UPnP / Synology DSM
    5001,  // Synology DSM-https
    5060,  // SIP
    5061,  // SIPS
    5222,  // XMPP-client
    5269,  // XMPP-server
    5353,  // mDNS
    5432,  // PostgreSQL
    5500,  // VNC server-listen
    5601,  // Kibana
    5672,  // AMQP/RabbitMQ
    5800,  // VNC over HTTP
    5900,  // VNC
    5985,  // WinRM
    5986,  // WinRM-ssl
    6379,  // Redis
    6443,  // Kubernetes API
    7000,  // various
    7001,  // weblogic
    8000,  // Web-alt
    8008,  // Web-alt
    8080,  // HTTP-proxy / UniFi-inform
    8081,  // Web-alt
    8088,  // Hadoop
    8089,  // Splunk
    8090,  // Confluence
    8118,  // Privoxy
    8200,  // Vault
    8333,  // Bitcoin
    8443,  // HTTPS-alt / FortiGate
    8530,  // WSUS
    8888,  // Web-alt
    9000,  // PHP-FPM, SonarQube
    9090,  // Cockpit, Prometheus
    9100,  // Printer (PJL)
    9200,  // Elasticsearch
    9418,  // git
    10000, // Webmin
    11211, // Memcached
    27017, // MongoDB
    32400, // Plex
    49152, // UPnP-dynamic-start
    49153, // UPnP-dynamic
    50000, // SAP
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortProbe {
    pub port: u16,
    pub service: String,         // "ssh" / "http" / "https" / etc.
    pub banner: Option<String>,  // raw banner if grabbed
    pub server_header: Option<String>,
    pub title: Option<String>,
    pub powered_by: Option<String>,
    pub tls: Option<TlsInfo>,
    /// Framework / CMS detected via Wappalyzer-style heuristics.
    /// Populated for HTTP/HTTPS only. Each entry: "WordPress 6.4",
    /// "Drupal 10", "Confluence 8.5.3" — exact strings designed
    /// to pass through `vuln::match_cves` for version matching.
    #[serde(default)]
    pub fingerprints: Vec<String>,
    /// Web path enumeration probe results — all paths checked,
    /// with their status / size / content-type / matched flag.
    #[serde(default)]
    pub web_paths: Vec<crate::web_paths::PathProbe>,
    /// SMB enumeration result (only present on port 445).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smb: Option<crate::smb_enum::SmbInfo>,
    /// SNMP MIB walk result (only present when SNMP responds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snmp: Option<crate::snmp_walk::SnmpDetail>,
    /// LDAP / Active Directory enumeration result. Only present
    /// when the anonymous-bind probe succeeds on port 389/636.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap: Option<crate::ldap_enum::LdapInfo>,
    /// Findings produced by deeper sub-probes (web path enum,
    /// SMB enum). These are aggregated by `vuln::analyse_host`
    /// alongside the host-level findings — keeping them on the
    /// probe means we don't have to re-execute the rule logic.
    #[serde(default)]
    pub extra_findings: Vec<crate::vuln::Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_san: Vec<String>,
    pub cert_expires_iso: Option<String>,
    pub self_signed: bool,
    /// Weak cipher families the server accepted (RC4, 3DES, NULL,
    /// EXPORT, anonymous-DH). Each entry is the openssl-cipher
    /// alias group probed (`"RC4"`, `"3DES"`, etc.). Empty when the
    /// matrix probe didn't run or all families were rejected.
    #[serde(default)]
    pub weak_ciphers_accepted: Vec<String>,
    /// TLS protocol versions the server is willing to speak.
    /// Currently populated only by the cipher matrix probe.
    #[serde(default)]
    pub protocols_accepted: Vec<String>,
}

/// Test connectivity to (host, port) within a timeout. Returns
/// true if TCP three-way handshake completes — i.e. service is
/// listening. Doesn't grab banner; that's a separate function.
pub async fn tcp_check(host: &str, port: u16, timeout_ms: u64) -> bool {
    let target = format!("{host}:{port}");
    matches!(
        timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&target)).await,
        Ok(Ok(_))
    )
}

/// Probe a single (host, port). Picks the right service-specific
/// follow-up based on port, returns rich metadata. ~3-5 second
/// per-port budget — most services respond in <500ms but slow
/// HTTPS handshakes need headroom.
pub async fn probe_port(host: &str, port: u16) -> Option<PortProbe> {
    if !tcp_check(host, port, 1500).await {
        return None;
    }

    let service = guess_service(port);
    let mut probe = PortProbe {
        port,
        service: service.clone(),
        banner: None,
        server_header: None,
        title: None,
        powered_by: None,
        tls: None,
        fingerprints: Vec::new(),
        web_paths: Vec::new(),
        smb: None,
        snmp: None,
        ldap: None,
        extra_findings: Vec::new(),
    };

    match service.as_str() {
        "ssh" => {
            probe.banner = ssh_banner(host, port).await.ok();
        }
        "http" => {
            if let Ok(http) = http_probe(host, port, false).await {
                probe.server_header = http.server;
                probe.title = http.title;
                probe.powered_by = http.powered_by;
                probe.banner = http.first_line;
                probe.fingerprints = http.fingerprints;
            }
            // Web path enumeration — runs in parallel internally,
            // ~3s budget per host:port.
            let (paths, findings) = crate::web_paths::enumerate(host, port, false).await;
            probe.web_paths = paths;
            probe.extra_findings.extend(findings);
        }
        "https" => {
            probe.tls = tls_audit(host, port).await.ok();
            if let Ok(http) = http_probe(host, port, true).await {
                probe.server_header = http.server;
                probe.title = http.title;
                probe.powered_by = http.powered_by;
                probe.fingerprints = http.fingerprints;
            }
            let (paths, findings) = crate::web_paths::enumerate(host, port, true).await;
            probe.web_paths = paths;
            probe.extra_findings.extend(findings);
        }
        "telnet" | "ftp" | "smtp" => {
            probe.banner = generic_banner(host, port).await.ok();
        }
        "snmp" => {
            probe.banner = snmp_sysdescr(host).await.ok();
            // Deeper SNMP walk if we got anything back. The walk
            // doubles as confirmation that a default community
            // works — null result if not.
            probe.snmp = crate::snmp_walk::walk(host).await;
        }
        "smb" => {
            probe.banner = generic_banner(host, port).await.ok();
            // Null-session enumeration + NetBIOS query.
            if let Some((info, findings)) = crate::smb_enum::enumerate(host).await {
                probe.smb = Some(info);
                probe.extra_findings.extend(findings);
            }
        }
        "ldap" | "ldaps" => {
            // Anonymous-bind probe + rootDSE leak detection.
            // Both findings (anonymous-bind + rootdse-leak) are
            // attached to extra_findings so the host-level
            // analyser sees them in the same pass as CVE matches.
            if let Some((info, findings)) = crate::ldap_enum::enumerate(host, port).await {
                probe.ldap = Some(info);
                probe.extra_findings.extend(findings);
            }
        }
        _ => {
            probe.banner = generic_banner(host, port).await.ok();
        }
    }

    Some(probe)
}

fn guess_service(port: u16) -> String {
    match port {
        21 => "ftp".into(),
        22 | 2222 => "ssh".into(),
        23 => "telnet".into(),
        25 | 465 | 587 => "smtp".into(),
        53 => "dns".into(),
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8088 | 8090 | 8888 => "http".into(),
        110 => "pop3".into(),
        111 => "rpc".into(),
        135 => "msrpc".into(),
        139 | 445 => "smb".into(),
        143 => "imap".into(),
        161 => "snmp".into(),
        389 => "ldap".into(),
        443 | 8443 | 5001 | 9090 | 5601 | 8443 | 6443 => "https".into(),
        465 => "smtps".into(),
        514 => "syslog".into(),
        548 => "afp".into(),
        631 => "ipp".into(),
        636 => "ldaps".into(),
        993 => "imaps".into(),
        995 => "pop3s".into(),
        1433 | 1434 => "mssql".into(),
        1521 => "oracle".into(),
        2049 => "nfs".into(),
        2375 | 2376 => "docker".into(),
        3306 => "mysql".into(),
        3389 => "rdp".into(),
        5432 => "postgres".into(),
        5900 | 5800 | 5500 => "vnc".into(),
        5985 => "winrm".into(),
        5986 => "winrm-ssl".into(),
        6379 => "redis".into(),
        9100 => "printer".into(),
        9200 => "elasticsearch".into(),
        10000 => "webmin".into(),
        11211 => "memcached".into(),
        27017 => "mongodb".into(),
        _ => format!("tcp/{port}"),
    }
}

/// Generic banner-grab: connect, send a CRLF, read what comes back.
/// Works for SSH, FTP, SMTP, telnet — services that announce
/// themselves on connect.
pub async fn generic_banner(host: &str, port: u16) -> Result<String> {
    let target = format!("{host}:{port}");
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(&target))
        .await
        .map_err(|_| anyhow!("connect timeout"))?
        .map_err(|e| anyhow!("connect: {e}"))?;
    // Some services need a stimulus.
    let _ = stream.write_all(b"\r\n").await;
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .map_err(|_| anyhow!("read timeout"))??;
    let s = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    Ok(s)
}

/// SSH banner: connect, read first line. SSH server announces
/// "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" before any client send.
pub async fn ssh_banner(host: &str, port: u16) -> Result<String> {
    let target = format!("{host}:{port}");
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(&target))
        .await
        .map_err(|_| anyhow!("connect timeout"))?
        .map_err(|e| anyhow!("connect: {e}"))?;
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .map_err(|_| anyhow!("read timeout"))??;
    let s = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    Ok(s)
}

#[derive(Debug, Default)]
pub struct HttpResult {
    pub status: u16,
    pub server: Option<String>,
    pub title: Option<String>,
    pub powered_by: Option<String>,
    pub first_line: Option<String>,
    /// Detected frameworks/CMSes from headers + body. Each entry
    /// is a banner-shaped string like "WordPress 6.4" so it can
    /// flow through `vuln::match_cves` for version-based CVE
    /// matching.
    pub fingerprints: Vec<String>,
}

/// HTTP / HTTPS GET / and parse common fingerprinting fields.
/// `tls = true` for HTTPS. Uses reqwest with rustls-style perm
/// settings: skip cert validation (we're scanning, not browsing).
pub async fn http_probe(host: &str, port: u16, tls: bool) -> Result<HttpResult> {
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://{host}:{port}/");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(2))
        .build()?;
    let resp = client.get(&url).send().await?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let server = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let powered_by = headers
        .get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = resp.text().await.unwrap_or_default();
    let title = extract_title(&body);
    let fingerprints = fingerprint_web(&headers, &body, &title);
    Ok(HttpResult {
        status,
        server,
        title,
        powered_by,
        first_line: Some(format!("HTTP/{status}")),
        fingerprints,
    })
}

/// Wappalyzer-style web framework / CMS detection.
///
/// Looks at:
///   - Response headers (`X-Powered-By`, `X-Generator`, etc.)
///   - HTML meta tags (`<meta name="generator" content="...">`)
///   - Distinctive HTML patterns (WordPress link tags, Drupal markers)
///   - Cookie names (`PHPSESSID`, `JSESSIONID`, `wordpress_logged_in_*`)
///
/// Returns banner-shaped strings like `"WordPress 6.4.2"`,
/// `"Drupal 10"`, `"Confluence 8.5.3"`. Multiple fingerprints
/// possible (e.g. a WP site is also "PHP/8.2" + WP).
fn fingerprint_web(
    headers: &reqwest::header::HeaderMap,
    body: &str,
    title: &Option<String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let body_lc = body.to_lowercase();

    // Helper: pull header value as string.
    let h = |name: &str| -> Option<String> {
        headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
    };
    let cookies: Vec<String> = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let cookie_blob = cookies.join("; ").to_lowercase();

    // -- WordPress -------------------------------------------------------
    let wp_meta_re = regex_lite_extract(body, r#"<meta name="generator" content="WordPress "#);
    if body_lc.contains("/wp-content/") || body_lc.contains("/wp-includes/")
        || cookie_blob.contains("wordpress_logged_in") || wp_meta_re.is_some() {
        let ver = extract_meta_generator_version(body, "WordPress")
            .unwrap_or_else(|| "unknown".into());
        out.push(format!("WordPress {ver}"));
    }

    // -- Drupal ----------------------------------------------------------
    if let Some(drupal_hdr) = h("x-generator") {
        if drupal_hdr.to_lowercase().contains("drupal") {
            // Header looks like "Drupal 10 (https://www.drupal.org)"
            let ver = drupal_hdr
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown")
                .to_owned();
            out.push(format!("Drupal {ver}"));
        }
    } else if body_lc.contains("drupal.settings") || body_lc.contains("/sites/default/files/") {
        let ver = extract_meta_generator_version(body, "Drupal").unwrap_or_else(|| "unknown".into());
        out.push(format!("Drupal {ver}"));
    }

    // -- Joomla ----------------------------------------------------------
    if body_lc.contains("/components/com_") || body_lc.contains("media/system/js/mootools") {
        let ver = extract_meta_generator_version(body, "Joomla").unwrap_or_else(|| "unknown".into());
        out.push(format!("Joomla {ver}"));
    }

    // -- Confluence / Atlassian -----------------------------------------
    if let Some(s) = h("x-confluence-request-time") { let _ = s; out.push("Confluence unknown".into()); }
    if body_lc.contains("/confluence/") && body_lc.contains("atlassian") {
        // Try to find a build number in HTML comments.
        let ver = body
            .lines()
            .find(|l| l.contains("ajs-version-number"))
            .and_then(|l| l.split('"').nth(3))
            .unwrap_or("unknown")
            .to_owned();
        if !out.iter().any(|s| s.starts_with("Confluence")) {
            out.push(format!("Confluence {ver}"));
        }
    }
    if body_lc.contains("\"jira\"") && (body_lc.contains("atlassian") || body_lc.contains("ajs-version-number")) {
        out.push("Jira unknown".into());
    }

    // -- nginx / Apache / IIS already in `server` header — but echo
    //    them into fingerprints so the CVE matcher sees them too.
    if let Some(s) = h("server") {
        out.push(s);
    }
    if let Some(s) = h("x-powered-by") {
        out.push(s);
    }

    // -- WordPress / Joomla / Drupal further hint via title --
    if let Some(t) = title {
        let tl = t.to_lowercase();
        if tl.contains("powered by") {
            out.push(t.clone());
        }
    }

    // De-duplicate.
    out.sort();
    out.dedup();
    out
}

/// Extract `<meta name="generator" content="<product> <version>">`
/// for the given product. Returns the version string only.
fn extract_meta_generator_version(body: &str, product: &str) -> Option<String> {
    let needle_lc = format!(r#"<meta name="generator" content="{}"#, product).to_lowercase();
    let body_lc = body.to_lowercase();
    let start = body_lc.find(&needle_lc)?;
    let after = &body[start + needle_lc.len()..];
    // Take chars up to closing quote.
    let end = after.find('"')?;
    let token = &after[..end];
    // token like " 6.4.2" or " 6.4.2 (https://...)"
    let trimmed = token.trim();
    let ver = trimmed.split_whitespace().next()?;
    if ver.is_empty() { None } else { Some(ver.to_owned()) }
}

/// Tiny regex-lite — substring presence check used to avoid
/// pulling the regex crate into hot paths. Returns Some when the
/// haystack contains the literal needle (case-sensitive).
fn regex_lite_extract<'a>(haystack: &'a str, needle: &str) -> Option<&'a str> {
    haystack.find(needle).map(|i| &haystack[i..])
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title>")?;
    let end = lower[start + 7..].find("</title>")?;
    let raw = &body[start + 7..start + 7 + end];
    Some(raw.trim().to_owned())
}

/// TLS audit via shell-out to `openssl s_client`. Parses:
///   - Protocol: TLSv1.2 / TLSv1.3 / etc.
///   - Cipher: ECDHE-RSA-AES256-GCM-SHA384 / etc.
///   - Subject + issuer + SAN + expiry from cert chain
///
/// We don't bring in a Rust TLS dep just for this — `openssl`
/// (LibreSSL on macOS) is shipped with the OS and gives us
/// everything in one shot.
pub async fn tls_audit(host: &str, port: u16) -> Result<TlsInfo> {
    let target = format!("{host}:{port}");
    let mut child = tokio::process::Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &target,
            "-servername",
            host,
            "-showcerts",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("spawn openssl: {e}"))?;

    // Send a single newline + EOF so s_client closes cleanly.
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(b"\n").await;
        let _ = stdin.shutdown().await;
    }

    let output = timeout(Duration::from_secs(8), child.wait_with_output())
        .await
        .map_err(|_| anyhow!("openssl timeout"))??;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}\n{stderr}");
    let mut info = parse_tls_output(&combined, host)?;

    // Cipher matrix — probe each weak family. Each shell-out is
    // ~1-2s; we run them in parallel via tokio::join! to keep
    // the total under ~2s wall-clock. A failure to spawn any one
    // probe doesn't break the audit; we just leave the corresponding
    // entry out of `weak_ciphers_accepted`.
    let (rc4, des3, anull, exp, anon) = tokio::join!(
        cipher_supported(host, port, "RC4"),
        cipher_supported(host, port, "3DES"),
        cipher_supported(host, port, "NULL"),
        cipher_supported(host, port, "EXP"),
        cipher_supported(host, port, "aNULL"),
    );
    if rc4.unwrap_or(false)   { info.weak_ciphers_accepted.push("RC4".into()); }
    if des3.unwrap_or(false)  { info.weak_ciphers_accepted.push("3DES".into()); }
    if anull.unwrap_or(false) { info.weak_ciphers_accepted.push("NULL".into()); }
    if exp.unwrap_or(false)   { info.weak_ciphers_accepted.push("EXPORT".into()); }
    if anon.unwrap_or(false)  { info.weak_ciphers_accepted.push("ANONYMOUS".into()); }

    // Protocol matrix — flag if the server speaks protocols
    // older than TLS 1.2.
    let (ssl3, tls10, tls11) = tokio::join!(
        protocol_supported(host, port, "-ssl3"),
        protocol_supported(host, port, "-tls1"),
        protocol_supported(host, port, "-tls1_1"),
    );
    if ssl3.unwrap_or(false)  { info.protocols_accepted.push("SSLv3".into()); }
    if tls10.unwrap_or(false) { info.protocols_accepted.push("TLSv1.0".into()); }
    if tls11.unwrap_or(false) { info.protocols_accepted.push("TLSv1.1".into()); }

    Ok(info)
}

/// Probe whether the server accepts a particular cipher family.
/// Uses `openssl s_client -cipher <family>` and looks at the
/// resulting handshake status.
///
/// Two-stage check:
///   1. Reject obvious failures (`(NONE)`, `no cipher available`,
///      explicit handshake failure).
///   2. Extract the negotiated cipher name and verify it matches
///      the requested family.
///
/// Step 2 is critical — without it we false-positive in two
/// situations:
///   a. The local openssl was compiled without the requested
///      cipher family (e.g. modern LibreSSL has no NULL ciphers).
///      In that case `-cipher NULL` silently degrades to "no
///      constraint" and the server picks a strong cipher.
///   b. The handshake falls through to TLS 1.3, where `-cipher`
///      doesn't apply (TLS 1.3 uses a separate `-ciphersuites`
///      list). A TLS 1.3 handshake against `-cipher NULL` returns
///      a strong AEAD cipher.
///
/// Without verifying the cipher name, a healthy modern server
/// gets flagged as accepting NULL/RC4/etc. — completely wrong.
async fn cipher_supported(host: &str, port: u16, family: &str) -> Result<bool> {
    let target = format!("{host}:{port}");
    let mut child = tokio::process::Command::new("openssl")
        .args([
            "s_client",
            "-connect", &target,
            "-servername", host,
            "-cipher", family,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("spawn openssl cipher {family}: {e}"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(b"\n").await;
        let _ = stdin.shutdown().await;
    }
    let output = match timeout(Duration::from_secs(4), child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        _ => return Ok(false),  // timeout / spawn error = treat as not supported
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    let lc = combined.to_lowercase();

    // Stage 1: explicit failure markers.
    if lc.contains("(none)")
        || lc.contains("no cipher")
        || lc.contains("handshake failure")
        || lc.contains("no ciphers available")
    {
        return Ok(false);
    }

    // Stage 2: must extract a real negotiated cipher AND it must
    // belong to the requested family. If we can't pin a family
    // (e.g. unrecognised name in `family`), be conservative and
    // return false — we'd rather miss a weak-cipher finding than
    // emit a false one.
    match extract_negotiated_cipher(&combined) {
        Some(name) => Ok(cipher_matches_family(&name, family)),
        None => Ok(false),
    }
}

/// Extract the negotiated cipher name from `openssl s_client` output.
///
/// Two output formats coexist across openssl versions:
///   - `New, TLSv1.2, Cipher is AES256-SHA` (top line)
///   - `    Cipher    : AES256-SHA`         (SSL-Session block)
///
/// Returns `None` if no cipher was actually negotiated (handshake
/// failed → `(NONE)`).
fn extract_negotiated_cipher(output: &str) -> Option<String> {
    for line in output.lines() {
        let trim = line.trim();

        // Format A: "Cipher    : <NAME>" / "Cipher: <NAME>"
        if let Some(rest) = trim.strip_prefix("Cipher") {
            let cleaned = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ':');
            if let Some(name) = cleaned.split_whitespace().next() {
                if !name.eq_ignore_ascii_case("(NONE)") && !name.is_empty() {
                    // Guard against matching the "Cipher is X" line here —
                    // that path is handled in format B below to avoid
                    // returning "is" as the name.
                    if name != "is" {
                        return Some(name.to_owned());
                    }
                }
            }
        }

        // Format B: "New, TLSv1.2, Cipher is <NAME>"
        if let Some(idx) = trim.find(", Cipher is ") {
            let rest = &trim[idx + ", Cipher is ".len()..];
            if let Some(name) = rest.split_whitespace().next() {
                if !name.eq_ignore_ascii_case("(NONE)") && !name.is_empty() {
                    return Some(name.to_owned());
                }
            }
        }
    }
    None
}

/// Check whether an openssl cipher name belongs to the requested
/// weak-cipher family. The family arg is the same string passed
/// to `-cipher` (e.g. "RC4", "NULL", "3DES", "EXP", "aNULL").
///
/// Naming conventions used by openssl:
///   - NULL family   → cipher names contain "NULL"
///   - RC4 family    → contain "RC4"
///   - 3DES family   → contain "3DES" or "DES-CBC3"
///   - EXPORT family → contain "EXP"
///   - aNULL family  → contain "ADH", "AECDH", or "ANON"
fn cipher_matches_family(cipher_name: &str, family: &str) -> bool {
    let name = cipher_name.to_uppercase();
    match family {
        "RC4"   => name.contains("RC4"),
        "3DES"  => name.contains("3DES") || name.contains("DES-CBC3"),
        "NULL"  => name.contains("NULL"),
        "EXP" | "EXPORT" => name.contains("EXP"),
        "aNULL" | "ANULL" => {
            name.contains("ADH") || name.contains("AECDH") || name.contains("ANON")
        }
        _ => false,
    }
}

/// Probe whether the server accepts a particular protocol version.
/// Same shape as `cipher_supported` but uses protocol-flag args
/// (`-ssl3`, `-tls1`, `-tls1_1`).
async fn protocol_supported(host: &str, port: u16, proto_flag: &str) -> Result<bool> {
    let target = format!("{host}:{port}");
    let mut child = tokio::process::Command::new("openssl")
        .args([
            "s_client",
            "-connect", &target,
            "-servername", host,
            proto_flag,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("spawn openssl proto {proto_flag}: {e}"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(b"\n").await;
        let _ = stdin.shutdown().await;
    }
    let output = match timeout(Duration::from_secs(4), child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        _ => return Ok(false),
    };
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_lowercase();
    if combined.contains("alert") || combined.contains("handshake failure")
        || combined.contains("unsupported protocol")
        || combined.contains("(none)")
    {
        return Ok(false);
    }
    Ok(combined.contains("verify return code") || combined.contains("cipher    : "))
}

fn parse_tls_output(text: &str, host: &str) -> Result<TlsInfo> {
    let mut version = "unknown".to_owned();
    let mut cipher = "unknown".to_owned();
    let mut subject: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut san: Vec<String> = Vec::new();
    let mut expires_iso: Option<String> = None;

    for line in text.lines() {
        let trim = line.trim();
        if let Some(rest) = trim.strip_prefix("Protocol  : ") {
            version = rest.to_owned();
        } else if let Some(rest) = trim.strip_prefix("Cipher    : ") {
            cipher = rest.to_owned();
        } else if let Some(rest) = trim.strip_prefix("subject=") {
            subject = Some(rest.trim_start_matches('/').replace(", ", "/").trim().to_owned());
        } else if let Some(rest) = trim.strip_prefix("issuer=") {
            issuer = Some(rest.trim_start_matches('/').replace(", ", "/").trim().to_owned());
        } else if let Some(rest) = trim.strip_prefix("notAfter=") {
            expires_iso = Some(rest.trim().to_owned());
        }
    }

    // Extract SAN from text (DNS:foo, DNS:bar, ...).
    if let Some(idx) = text.find("X509v3 Subject Alternative Name:") {
        let tail = &text[idx..];
        if let Some(line) = tail.lines().nth(1) {
            for entry in line.split(',') {
                let entry = entry.trim();
                if let Some(d) = entry.strip_prefix("DNS:") {
                    san.push(d.to_owned());
                }
            }
        }
    }

    let self_signed = subject.as_deref().is_some()
        && issuer.as_deref().is_some()
        && subject == issuer;

    Ok(TlsInfo {
        version,
        cipher,
        cert_subject: subject,
        cert_issuer: issuer,
        cert_san: san,
        cert_expires_iso: expires_iso,
        self_signed,
        weak_ciphers_accepted: Vec::new(),  // populated by tls_audit
        protocols_accepted: Vec::new(),     // populated by tls_audit
    })
    .map(|info| {
        let _ = host; // marker — keep signature flexible
        info
    })
}

/// SNMP read of sysDescr.0 (1.3.6.1.2.1.1.1.0) using common
/// communities. Tries `public` first, then `private`. Returns
/// the system description string if any community works —
/// that's both useful inventory data AND a finding ("public
/// community readable" is a high-severity issue).
pub async fn snmp_sysdescr(host: &str) -> Result<String> {
    for community in &["public", "private"] {
        let res = tokio::process::Command::new("snmpget")
            .args([
                "-v", "2c",
                "-c", community,
                "-t", "2",
                "-r", "0",
                host,
                "1.3.6.1.2.1.1.1.0",
            ])
            .output()
            .await;
        if let Ok(out) = res {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                // Output: "iso.3.6.1.2.1.1.1.0 = STRING: ..."
                if let Some(idx) = s.find("STRING: ") {
                    return Ok(format!(
                        "[community={community}] {}",
                        s[idx + 8..].trim().trim_matches('"')
                    ));
                }
            }
        }
    }
    Err(anyhow!("snmpget did not respond on public/private"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── extract_negotiated_cipher ─────────────────────────────────────

    #[test]
    fn extract_cipher_from_session_block() {
        // Real `openssl s_client` SSL-Session block output.
        let out = "
---
New, TLSv1.2, Cipher is AES256-SHA
Server public key is 2048 bit
Secure Renegotiation IS supported
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : AES256-SHA
    Session-ID: ABCD
";
        let name = extract_negotiated_cipher(out);
        assert_eq!(name.as_deref(), Some("AES256-SHA"));
    }

    #[test]
    fn extract_cipher_from_new_line_only() {
        // Truncated output where the SSL-Session block didn't print
        // (early disconnect). Falls back to the "Cipher is X" line.
        let out = "New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\n";
        let name = extract_negotiated_cipher(out);
        assert_eq!(name.as_deref(), Some("ECDHE-RSA-AES128-GCM-SHA256"));
    }

    #[test]
    fn extract_cipher_tls13_aead() {
        // TLS 1.3 handshake — openssl substitutes a strong cipher
        // because `-cipher` doesn't apply to TLS 1.3.
        let out = "New, TLSv1/SSLv3, Cipher is AEAD-AES256-GCM-SHA384\n    Protocol  : TLSv1.3\n    Cipher    : AEAD-AES256-GCM-SHA384\n";
        let name = extract_negotiated_cipher(out);
        assert_eq!(name.as_deref(), Some("AEAD-AES256-GCM-SHA384"));
    }

    #[test]
    fn extract_cipher_none_returns_none() {
        // Failed handshake — both formats show (NONE).
        let out = "
---
New, (NONE), Cipher is (NONE)
    Cipher    : (NONE)
";
        let name = extract_negotiated_cipher(out);
        assert_eq!(name, None);
    }

    #[test]
    fn extract_cipher_empty_input() {
        assert_eq!(extract_negotiated_cipher(""), None);
    }

    // ─── cipher_matches_family ─────────────────────────────────────────

    #[test]
    fn match_null_family() {
        assert!(cipher_matches_family("NULL-SHA", "NULL"));
        assert!(cipher_matches_family("NULL-MD5", "NULL"));
        assert!(cipher_matches_family("ECDHE-RSA-NULL-SHA", "NULL"));
        // Strong cipher must NOT match.
        assert!(!cipher_matches_family("AEAD-AES256-GCM-SHA384", "NULL"));
        assert!(!cipher_matches_family("ECDHE-RSA-AES256-GCM-SHA384", "NULL"));
    }

    #[test]
    fn match_rc4_family() {
        assert!(cipher_matches_family("RC4-MD5", "RC4"));
        assert!(cipher_matches_family("RC4-SHA", "RC4"));
        assert!(cipher_matches_family("ECDHE-RSA-RC4-SHA", "RC4"));
        assert!(!cipher_matches_family("AES256-SHA", "RC4"));
    }

    #[test]
    fn match_3des_family() {
        assert!(cipher_matches_family("DES-CBC3-SHA", "3DES"));
        assert!(cipher_matches_family("ECDHE-RSA-DES-CBC3-SHA", "3DES"));
        assert!(!cipher_matches_family("AES256-SHA", "3DES"));
        // DES (single) is not 3DES.
        assert!(!cipher_matches_family("DES-CBC-SHA", "3DES"));
    }

    #[test]
    fn match_export_family() {
        assert!(cipher_matches_family("EXP-RC4-MD5", "EXP"));
        assert!(cipher_matches_family("EXP-DES-CBC-SHA", "EXP"));
        assert!(cipher_matches_family("EXP-RC4-MD5", "EXPORT"));
        assert!(!cipher_matches_family("AES256-SHA", "EXP"));
    }

    #[test]
    fn match_anonymous_family() {
        assert!(cipher_matches_family("ADH-AES256-SHA", "aNULL"));
        assert!(cipher_matches_family("AECDH-AES256-SHA", "aNULL"));
        assert!(cipher_matches_family("ADH-AES256-SHA", "ANULL"));
        assert!(!cipher_matches_family("AES256-SHA", "aNULL"));
        // ECDHE is NOT anonymous (it has authentication).
        assert!(!cipher_matches_family("ECDHE-RSA-AES256-GCM-SHA384", "aNULL"));
    }

    #[test]
    fn match_unknown_family_rejects() {
        // Defence in depth: unknown family → always false.
        assert!(!cipher_matches_family("NULL-SHA", "BOGUS"));
        assert!(!cipher_matches_family("RC4-MD5", ""));
    }

    // ─── Regression for the .111:5001 bug ──────────────────────────────

    #[test]
    fn regression_tls13_substitution_does_not_match_null() {
        // openssl shell-out scenario: we asked for `-cipher NULL`
        // but the handshake fell through to TLS 1.3 which ignores
        // -cipher. openssl reports a strong AEAD cipher. The probe
        // must NOT flag this as "server accepts NULL".
        let out = "
---
Verification error: self signed certificate
---
New, TLSv1/SSLv3, Cipher is AEAD-AES256-GCM-SHA384
    Protocol  : TLSv1.3
    Cipher    : AEAD-AES256-GCM-SHA384
";
        let name = extract_negotiated_cipher(out).expect("should extract name");
        assert_eq!(name, "AEAD-AES256-GCM-SHA384");
        // The bug: this would have returned true under the old logic.
        assert!(!cipher_matches_family(&name, "NULL"));
        assert!(!cipher_matches_family(&name, "RC4"));
        assert!(!cipher_matches_family(&name, "3DES"));
        assert!(!cipher_matches_family(&name, "EXP"));
        assert!(!cipher_matches_family(&name, "aNULL"));
    }
}
