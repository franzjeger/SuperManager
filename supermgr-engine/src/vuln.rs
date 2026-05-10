//! Vulnerability detection — banner → CVE matching + common
//! security misconfigurations.
//!
//! # Strategy
//!
//! Two complementary detection paths:
//!
//! 1. **Banner-version → CVE** — when a service banner contains
//!    a known-vulnerable version string ("OpenSSH 7.4p1",
//!    "Apache 2.4.49", "FortiGate v6.2.3"), we surface the
//!    matching CVE(s) from the bundled database.
//!
//! 2. **Configuration findings** — situations that don't need
//!    version-matching: telnet open at all, SMBv1 detected,
//!    self-signed cert on a public service, expired cert,
//!    SNMP "public" community readable, weak TLS protocol.
//!
//! The bundled CVE database is intentionally small (~30
//! high-impact CVEs covering common gear: FortiGate, Cisco,
//! Apache, OpenSSH, Microsoft Exchange). For comprehensive
//! coverage Phase C+ would integrate Nuclei (~10k templates)
//! or pull from NVD weekly. This v1 catches the most
//! consequential CVEs the MSP fleet routinely shows up with.

use chrono::Datelike;
use serde::{Deserialize, Serialize};

use crate::probes::{PortProbe, TlsInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub host_ip: String,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
    pub cve: Option<String>,
    pub cvss: Option<f32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Run all detection rules against a single host's probe results.
/// Returns a flat list of findings — host-level + sub-probe extras.
pub fn analyse_host(host_ip: &str, probes: &[PortProbe]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    for p in probes {
        configuration_checks(host_ip, p, &mut findings);

        // CVE matching against banner / server header / x-powered-by.
        if let Some(banner) = banner_string(p) {
            if let Some(cve_findings) = match_cves(host_ip, p, &banner) {
                findings.extend(cve_findings);
            }
        }

        // CVE matching against Wappalyzer-style fingerprints.
        // Each fingerprint is a banner-shaped string ("WordPress 6.4")
        // so the existing match_cves works as-is.
        for fp in &p.fingerprints {
            if let Some(cve_findings) = match_cves(host_ip, p, fp) {
                findings.extend(cve_findings);
            }
        }

        // Sub-probe findings (web paths, SMB null-session, etc.)
        // are collected on the probe itself — re-emit them as
        // part of the host-level finding set.
        findings.extend(p.extra_findings.iter().cloned());
    }
    findings
}

fn banner_string(p: &PortProbe) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref s) = p.banner { parts.push(s.clone()); }
    if let Some(ref s) = p.server_header { parts.push(s.clone()); }
    if let Some(ref s) = p.powered_by { parts.push(s.clone()); }
    if parts.is_empty() { None } else { Some(parts.join(" ")) }
}

fn configuration_checks(host_ip: &str, p: &PortProbe, out: &mut Vec<Finding>) {
    // Telnet open at all → critical
    if p.service == "telnet" {
        out.push(Finding {
            id: "config.telnet-open".into(),
            host_ip: host_ip.to_owned(),
            port: Some(p.port),
            service: Some(p.service.clone()),
            severity: Severity::Critical,
            title: "Telnet service open".into(),
            detail: "Telnet transmits credentials in cleartext. Any network observer can capture admin passwords.".into(),
            recommendation: "Disable telnet entirely. Replace with SSH (port 22) for command-line management.".into(),
            cve: None,
            cvss: Some(9.0),
        });
    }

    // FTP open without indication of TLS
    if p.service == "ftp" {
        out.push(Finding {
            id: "config.ftp-cleartext".into(),
            host_ip: host_ip.to_owned(),
            port: Some(p.port),
            service: Some("ftp".into()),
            severity: Severity::High,
            title: "FTP service open (cleartext)".into(),
            detail: "FTP transfers credentials and data in plaintext. Use SFTP or FTPS.".into(),
            recommendation: "Disable FTP. Use SFTP (port 22 over SSH) or FTPS (port 990) instead.".into(),
            cve: None,
            cvss: Some(7.5),
        });
    }

    // SNMP read with public community → high
    if p.service == "snmp" {
        if let Some(banner) = &p.banner {
            if banner.contains("[community=public]") {
                out.push(Finding {
                    id: "config.snmp-public".into(),
                    host_ip: host_ip.to_owned(),
                    port: Some(p.port),
                    service: Some("snmp".into()),
                    severity: Severity::High,
                    title: "SNMP readable with default 'public' community".into(),
                    detail: "Default community strings expose device inventory + configuration to any network observer.".into(),
                    recommendation: "Disable SNMPv1/v2c. Switch to SNMPv3 with auth+priv (SHA + AES). If v2c required, change community to a 32-char random string.".into(),
                    cve: None,
                    cvss: Some(7.5),
                });
            }
        }
    }

    // RDP exposed
    if p.service == "rdp" {
        out.push(Finding {
            id: "config.rdp-exposed".into(),
            host_ip: host_ip.to_owned(),
            port: Some(p.port),
            service: Some("rdp".into()),
            severity: Severity::High,
            title: "RDP open".into(),
            detail: "RDP is a primary lateral-movement vector. Direct exposure invites credential-stuffing + BlueKeep-style exploits.".into(),
            recommendation: "Restrict RDP to MGMT VLAN or behind VPN. Enable Network Level Authentication (NLA) + lockout policies.".into(),
            cve: None,
            cvss: Some(7.0),
        });
    }

    // SMB exposed (445) → flag for SMBv1 / weak config
    if p.service == "smb" {
        out.push(Finding {
            id: "config.smb-open".into(),
            host_ip: host_ip.to_owned(),
            port: Some(p.port),
            service: Some("smb".into()),
            severity: Severity::Medium,
            title: "SMB share-server open".into(),
            detail: "SMB is high-value to attackers (EternalBlue / SMBGhost / share enumeration). Verify SMBv1 is disabled and only authenticated access allowed.".into(),
            recommendation: "Disable SMBv1 protocol. Restrict SMB access to internal-only via firewall. Enforce signing.".into(),
            cve: None,
            cvss: Some(5.0),
        });
    }

    // Database servers exposed
    if matches!(p.service.as_str(), "mssql" | "mysql" | "postgres" | "mongodb" | "redis") {
        out.push(Finding {
            id: format!("config.{}-exposed", p.service),
            host_ip: host_ip.to_owned(),
            port: Some(p.port),
            service: Some(p.service.clone()),
            severity: Severity::High,
            title: format!("{} database open to network", p.service.to_uppercase()),
            detail: "Database services should never be reachable from arbitrary network segments. Configuration default exposure leads to data exfiltration + ransomware.".into(),
            recommendation: "Bind to localhost only or restrict via firewall to specific application servers. Enforce strong authentication.".into(),
            cve: None,
            cvss: Some(8.0),
        });
    }

    // Docker / Kubernetes API exposed
    if matches!(p.service.as_str(), "docker" | "kubernetes" | "tcp/2375" | "tcp/6443") {
        out.push(Finding {
            id: format!("config.{}-exposed", p.service),
            host_ip: host_ip.to_owned(),
            port: Some(p.port),
            service: Some(p.service.clone()),
            severity: Severity::Critical,
            title: "Container orchestration API exposed".into(),
            detail: "Unauthenticated container API = full host control. Attackers spawn containers with /host bind-mount + escalate to root in minutes.".into(),
            recommendation: "Bind to localhost. Require client cert authentication. Never expose unauthenticated.".into(),
            cve: None,
            cvss: Some(10.0),
        });
    }

    // TLS findings
    if let Some(tls) = &p.tls {
        tls_findings(host_ip, p.port, tls, out);
    }
}

fn tls_findings(host_ip: &str, port: u16, tls: &TlsInfo, out: &mut Vec<Finding>) {
    // Old TLS protocols
    let v = tls.version.to_lowercase();
    if v.contains("sslv2") || v.contains("sslv3") {
        out.push(Finding {
            id: "tls.ssl-deprecated".into(),
            host_ip: host_ip.to_owned(),
            port: Some(port),
            service: Some("https".into()),
            severity: Severity::Critical,
            title: format!("Deprecated SSL protocol: {}", tls.version),
            detail: "SSLv2/SSLv3 are broken. POODLE, DROWN, and other attacks completely undermine confidentiality.".into(),
            recommendation: "Disable SSLv2 and SSLv3. Allow only TLS 1.2 and TLS 1.3.".into(),
            cve: Some("CVE-2014-3566".into()),
            cvss: Some(9.0),
        });
    } else if v.contains("tlsv1.0") || v.contains("tlsv1") && !v.contains("tlsv1.1") && !v.contains("tlsv1.2") && !v.contains("tlsv1.3") {
        out.push(Finding {
            id: "tls.tls10".into(),
            host_ip: host_ip.to_owned(),
            port: Some(port),
            service: Some("https".into()),
            severity: Severity::High,
            title: "Deprecated TLS 1.0".into(),
            detail: "TLS 1.0 is deprecated by RFC 8996. Vulnerable to BEAST and weak cipher suites.".into(),
            recommendation: "Disable TLS 1.0. Allow only TLS 1.2+.".into(),
            cve: None,
            cvss: Some(6.5),
        });
    } else if v.contains("tlsv1.1") {
        out.push(Finding {
            id: "tls.tls11".into(),
            host_ip: host_ip.to_owned(),
            port: Some(port),
            service: Some("https".into()),
            severity: Severity::High,
            title: "Deprecated TLS 1.1".into(),
            detail: "TLS 1.1 is deprecated by RFC 8996.".into(),
            recommendation: "Disable TLS 1.1. Allow only TLS 1.2+.".into(),
            cve: None,
            cvss: Some(5.5),
        });
    }

    // Self-signed cert on what looks like a real service
    if tls.self_signed {
        out.push(Finding {
            id: "tls.self-signed".into(),
            host_ip: host_ip.to_owned(),
            port: Some(port),
            service: Some("https".into()),
            severity: Severity::Medium,
            title: "Self-signed TLS certificate".into(),
            detail: "Self-signed certs prevent meaningful client-side verification, train users to click-through warnings.".into(),
            recommendation: "Replace with a Let's Encrypt or commercial CA-signed certificate. Use cert-manager for auto-renewal.".into(),
            cve: None,
            cvss: Some(4.0),
        });
    }

    // Expired or expiring soon
    if let Some(ref expires) = tls.cert_expires_iso {
        if let Some(days) = days_until_expiry(expires) {
            if days < 0 {
                out.push(Finding {
                    id: "tls.cert-expired".into(),
                    host_ip: host_ip.to_owned(),
                    port: Some(port),
                    service: Some("https".into()),
                    severity: Severity::High,
                    title: format!("TLS cert EXPIRED ({} days ago)", -days),
                    detail: format!("Certificate expired on {expires}. Browsers and modern clients refuse the connection."),
                    recommendation: "Renew immediately. Set up auto-renewal via cert-manager / Let's Encrypt / ACME.".into(),
                    cve: None,
                    cvss: Some(7.0),
                });
            } else if days < 14 {
                out.push(Finding {
                    id: "tls.cert-expiring".into(),
                    host_ip: host_ip.to_owned(),
                    port: Some(port),
                    service: Some("https".into()),
                    severity: Severity::Medium,
                    title: format!("TLS cert expires in {days} days"),
                    detail: format!("Certificate expires on {expires}."),
                    recommendation: "Renew before expiry. Implement auto-renewal.".into(),
                    cve: None,
                    cvss: Some(4.0),
                });
            }
        }
    }

    // Weak cipher suites
    let cipher_low = tls.cipher.to_lowercase();
    if cipher_low.contains("rc4")
        || cipher_low.contains("3des")
        || cipher_low.contains("des-")
        || cipher_low.contains("null")
        || cipher_low.contains("export")
        || cipher_low.contains("md5")
    {
        out.push(Finding {
            id: "tls.weak-cipher".into(),
            host_ip: host_ip.to_owned(),
            port: Some(port),
            service: Some("https".into()),
            severity: Severity::High,
            title: format!("Weak TLS cipher: {}", tls.cipher),
            detail: "RC4, 3DES, DES, NULL, EXPORT and MD5-based ciphers are broken or deprecated.".into(),
            recommendation: "Configure server to prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305). Disable RC4/3DES/MD5.".into(),
            cve: None,
            cvss: Some(6.0),
        });
    }

    // Cipher matrix — every weak family the server *agreed to use*
    // when probed individually. Each one is a distinct finding so
    // operators can track + remediate them separately.
    for family in &tls.weak_ciphers_accepted {
        let (sev, cvss): (Severity, f32) = match family.as_str() {
            "NULL" | "ANONYMOUS" => (Severity::Critical, 9.0),
            "EXPORT"             => (Severity::Critical, 8.5),
            "RC4"                => (Severity::High, 7.0),
            "3DES"               => (Severity::High, 6.5),
            _                    => (Severity::Medium, 5.0),
        };
        out.push(Finding {
            id: format!("tls.cipher-{}", family.to_lowercase()),
            host_ip: host_ip.to_owned(),
            port: Some(port),
            service: Some("https".into()),
            severity: sev,
            title: format!("Server accepts {family} cipher family"),
            detail: format!(
                "Probed `openssl s_client -cipher {family}` — handshake succeeded, meaning the server is willing to negotiate this family. {}",
                cipher_family_detail(family)
            ),
            recommendation: cipher_family_recommendation(family).into(),
            cve: None,
            cvss: Some(cvss),
        });
    }

    // Protocol matrix — flag any pre-TLS-1.2 versions the server
    // is willing to speak.
    for proto in &tls.protocols_accepted {
        let sev = match proto.as_str() {
            "SSLv3"    => Severity::Critical,
            "TLSv1.0"  => Severity::High,
            "TLSv1.1"  => Severity::High,
            _          => Severity::Medium,
        };
        let cvss = match proto.as_str() {
            "SSLv3"   => 9.0,
            "TLSv1.0" => 6.5,
            "TLSv1.1" => 5.5,
            _         => 4.0,
        };
        out.push(Finding {
            id: format!("tls.proto-{}", proto.to_lowercase().replace('.', "")),
            host_ip: host_ip.to_owned(),
            port: Some(port),
            service: Some("https".into()),
            severity: sev,
            title: format!("Server accepts {proto}"),
            detail: format!(
                "Probed `openssl s_client {}` — handshake succeeded. RFC 8996 deprecates TLS <1.2; SSLv3 is broken (POODLE).",
                proto.to_lowercase()
            ),
            recommendation: format!(
                "Disable {proto} on the server. Allow only TLS 1.2 and 1.3."
            ),
            cve: None,
            cvss: Some(cvss),
        });
    }
}

fn cipher_family_detail(family: &str) -> &'static str {
    match family {
        "NULL"      => "NULL ciphers transmit data in plaintext after the TLS handshake.",
        "ANONYMOUS" => "Anonymous DH skips server authentication — vulnerable to active MITM.",
        "EXPORT"    => "EXPORT ciphers use ≤56-bit keys; cracked in minutes by FREAK.",
        "RC4"       => "RC4 has known biases that recover plaintext after enough captures.",
        "3DES"      => "3DES is vulnerable to SWEET32 birthday attacks at long-lived sessions.",
        _           => "Family is broken or weakened by published cryptanalysis.",
    }
}

fn cipher_family_recommendation(family: &str) -> &'static str {
    match family {
        "NULL"      => "Remove NULL from the cipher list. Force authenticated, encrypted handshakes only.",
        "ANONYMOUS" => "Remove anonymous DH (aNULL) from cipher list.",
        "EXPORT"    => "Remove EXPORT-grade ciphers immediately.",
        "RC4"       => "Disable RC4. Prefer AES-GCM or ChaCha20-Poly1305.",
        "3DES"      => "Disable 3DES (DES-CBC3-SHA). Limit session lifetime if temporarily needed.",
        _           => "Remove this cipher family from the server's allowed list.",
    }
}

fn days_until_expiry(expires_iso: &str) -> Option<i64> {
    // Format: "May 10 12:00:00 2026 GMT" (openssl notAfter format)
    let parsed = chrono::NaiveDateTime::parse_from_str(expires_iso, "%b %e %H:%M:%S %Y %Z")
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(expires_iso, "%b %e %H:%M:%S %Y GMT").ok()
        })?;
    let parsed = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(parsed, chrono::Utc);
    Some((parsed.date_naive() - chrono::Utc::now().date_naive()).num_days())
}

// ---------------------------------------------------------------------------
// CVE matching
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CveEntry {
    pub id: &'static str,
    pub product_match: &'static str,    // case-insensitive substring
    pub version_constraint: VersionPredicate,
    pub severity: Severity,
    pub cvss: f32,
    pub title: &'static str,
    pub detail: &'static str,
    pub recommendation: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum VersionPredicate {
    /// Match if banner contains any of these version-strings.
    /// Cheap substring check — covers most real-world fingerprints.
    Contains(&'static [&'static str]),
    /// Always match if product matches (for CVEs that affect
    /// every shipped version of a product, e.g. "service is
    /// exposed at all").
    Always,
}

fn cve_database() -> &'static [CveEntry] {
    &[
        // OpenSSH
        CveEntry {
            id: "CVE-2023-38408",
            product_match: "OpenSSH",
            version_constraint: VersionPredicate::Contains(&[
                "OpenSSH_5.5p1", "OpenSSH_5.6", "OpenSSH_5.7", "OpenSSH_5.8", "OpenSSH_5.9",
                "OpenSSH_6.0", "OpenSSH_6.1", "OpenSSH_6.2", "OpenSSH_6.3", "OpenSSH_6.4",
                "OpenSSH_6.5", "OpenSSH_6.6", "OpenSSH_6.7", "OpenSSH_6.8", "OpenSSH_6.9",
                "OpenSSH_7.0", "OpenSSH_7.1", "OpenSSH_7.2", "OpenSSH_7.3", "OpenSSH_7.4",
                "OpenSSH_7.5", "OpenSSH_7.6", "OpenSSH_7.7", "OpenSSH_7.8", "OpenSSH_7.9",
                "OpenSSH_8.0", "OpenSSH_8.1", "OpenSSH_8.2", "OpenSSH_8.3", "OpenSSH_8.4",
                "OpenSSH_8.5", "OpenSSH_8.6", "OpenSSH_8.7", "OpenSSH_8.8", "OpenSSH_8.9",
                "OpenSSH_9.0", "OpenSSH_9.1", "OpenSSH_9.2",
            ]),
            severity: Severity::High,
            cvss: 7.4,
            title: "OpenSSH agent forwarding RCE (CVE-2023-38408)",
            detail: "PKCS#11 provider remote code execution via forwarded ssh-agent. Affects OpenSSH < 9.3p2.",
            recommendation: "Upgrade to OpenSSH 9.3p2 or later. Disable agent forwarding (-A flag) where not strictly needed.",
        },
        CveEntry {
            id: "CVE-2024-6387",
            product_match: "OpenSSH",
            version_constraint: VersionPredicate::Contains(&[
                "OpenSSH_8.5p1", "OpenSSH_8.6p1", "OpenSSH_8.7p1", "OpenSSH_8.8p1",
                "OpenSSH_8.9p1", "OpenSSH_9.0p1", "OpenSSH_9.1p1", "OpenSSH_9.2p1",
                "OpenSSH_9.3p1", "OpenSSH_9.4p1", "OpenSSH_9.5p1", "OpenSSH_9.6p1",
                "OpenSSH_9.7p1",
            ]),
            severity: Severity::Critical,
            cvss: 8.1,
            title: "regreSSHion: OpenSSH RCE (CVE-2024-6387)",
            detail: "Race condition in sshd's signal handler allows unauthenticated remote code execution as root. Affects OpenSSH 8.5p1 — 9.7p1.",
            recommendation: "Upgrade to OpenSSH 9.8 or apply distro patches immediately.",
        },
        // Apache
        CveEntry {
            id: "CVE-2021-41773",
            product_match: "Apache",
            version_constraint: VersionPredicate::Contains(&["Apache/2.4.49", "Apache/2.4.50"]),
            severity: Severity::Critical,
            cvss: 9.8,
            title: "Apache 2.4.49/2.4.50 path traversal + RCE",
            detail: "Path traversal via mod_alias mishandling enables file disclosure + RCE if mod_cgi is loaded.",
            recommendation: "Upgrade Apache to 2.4.51 or later.",
        },
        // FortiGate
        CveEntry {
            id: "CVE-2024-21762",
            product_match: "FortiGate",
            version_constraint: VersionPredicate::Contains(&[
                "v6.0", "v6.2", "v6.4", "v7.0.0", "v7.0.1", "v7.0.2", "v7.0.3", "v7.0.4",
                "v7.0.5", "v7.0.6", "v7.0.7", "v7.0.8", "v7.0.9", "v7.0.10", "v7.0.11",
                "v7.0.12", "v7.0.13",
                "v7.2.0", "v7.2.1", "v7.2.2", "v7.2.3", "v7.2.4", "v7.2.5", "v7.2.6",
                "v7.4.0", "v7.4.1", "v7.4.2",
            ]),
            severity: Severity::Critical,
            cvss: 9.8,
            title: "FortiGate SSL VPN out-of-bounds write (CVE-2024-21762)",
            detail: "Out-of-bounds write in sslvpnd allows unauth RCE. Actively exploited in the wild.",
            recommendation: "Upgrade FortiOS to 7.4.3+ / 7.2.7+ / 7.0.14+ / 6.4.15+ / 6.2.16+ immediately.",
        },
        CveEntry {
            id: "CVE-2023-27997",
            product_match: "FortiGate",
            version_constraint: VersionPredicate::Contains(&[
                "v6.0", "v6.2", "v6.4", "v7.0.0", "v7.0.1", "v7.0.2", "v7.0.3", "v7.0.4",
                "v7.0.5", "v7.0.6", "v7.0.7", "v7.0.8", "v7.0.9", "v7.0.10", "v7.0.11",
                "v7.2.0", "v7.2.1", "v7.2.2", "v7.2.3", "v7.2.4",
                "v7.4.0", "v7.4.1",
            ]),
            severity: Severity::Critical,
            cvss: 9.2,
            title: "FortiOS SSL VPN heap overflow (CVE-2023-27997)",
            detail: "Heap-based buffer overflow in SSL-VPN pre-auth allows RCE.",
            recommendation: "Upgrade FortiOS to a patched version. Disable SSL-VPN if not in use.",
        },
        // nginx
        CveEntry {
            id: "CVE-2021-23017",
            product_match: "nginx",
            version_constraint: VersionPredicate::Contains(&[
                "nginx/1.0", "nginx/1.2", "nginx/1.4", "nginx/1.6", "nginx/1.8", "nginx/1.10",
                "nginx/1.12", "nginx/1.14", "nginx/1.16", "nginx/1.18", "nginx/1.19",
                "nginx/1.20.0",
            ]),
            severity: Severity::High,
            cvss: 7.7,
            title: "nginx resolver off-by-one (CVE-2021-23017)",
            detail: "DNS resolver bug allows 1-byte memory overwrite, potentially RCE.",
            recommendation: "Upgrade nginx to 1.20.1 / 1.21.0 or later.",
        },
        // PHP
        CveEntry {
            id: "CVE-2024-4577",
            product_match: "PHP",
            version_constraint: VersionPredicate::Contains(&[
                "PHP/8.1.0", "PHP/8.1.1", "PHP/8.1.2", "PHP/8.1.3", "PHP/8.1.4",
                "PHP/8.1.5", "PHP/8.1.6", "PHP/8.1.7", "PHP/8.1.8", "PHP/8.1.9",
                "PHP/8.1.10", "PHP/8.1.11", "PHP/8.1.12", "PHP/8.1.13", "PHP/8.1.14",
                "PHP/8.1.15", "PHP/8.1.16", "PHP/8.1.17", "PHP/8.1.18", "PHP/8.1.19",
                "PHP/8.1.20", "PHP/8.1.21", "PHP/8.1.22", "PHP/8.1.23", "PHP/8.1.24",
                "PHP/8.1.25", "PHP/8.1.26", "PHP/8.1.27", "PHP/8.1.28",
                "PHP/8.2.0", "PHP/8.2.1", "PHP/8.2.2", "PHP/8.2.3", "PHP/8.2.4",
                "PHP/8.2.5", "PHP/8.2.6", "PHP/8.2.7", "PHP/8.2.8", "PHP/8.2.9",
                "PHP/8.2.10", "PHP/8.2.11", "PHP/8.2.12", "PHP/8.2.13", "PHP/8.2.14",
                "PHP/8.2.15", "PHP/8.2.16", "PHP/8.2.17", "PHP/8.2.18", "PHP/8.2.19",
                "PHP/8.2.20",
                "PHP/8.3.0", "PHP/8.3.1", "PHP/8.3.2", "PHP/8.3.3", "PHP/8.3.4",
                "PHP/8.3.5", "PHP/8.3.6", "PHP/8.3.7", "PHP/8.3.8",
            ]),
            severity: Severity::Critical,
            cvss: 9.8,
            title: "PHP CGI argument injection (CVE-2024-4577)",
            detail: "PHP-CGI argument injection on Windows allows RCE. Actively exploited.",
            recommendation: "Upgrade PHP to 8.1.29 / 8.2.20 / 8.3.8+ or move to PHP-FPM.",
        },
        // Microsoft Exchange
        CveEntry {
            id: "CVE-2022-41040",
            product_match: "Exchange",
            version_constraint: VersionPredicate::Always,
            severity: Severity::High,
            cvss: 8.8,
            title: "Microsoft Exchange ProxyNotShell SSRF (CVE-2022-41040)",
            detail: "Server-side request forgery in autodiscover lets authenticated user pivot. Chained with CVE-2022-41082 for RCE.",
            recommendation: "Apply Microsoft Exchange November 2022 security update or later.",
        },
        // VMware ESXi
        CveEntry {
            id: "CVE-2021-21974",
            product_match: "VMware",
            version_constraint: VersionPredicate::Contains(&["ESXi 6.5", "ESXi 6.7", "ESXi 7.0"]),
            severity: Severity::High,
            cvss: 8.8,
            title: "VMware ESXi OpenSLP heap-overflow (CVE-2021-21974)",
            detail: "Used by ESXiArgs ransomware in 2023. Pre-auth RCE on port 427.",
            recommendation: "Disable OpenSLP on ESXi (port 427) or apply VMSA-2021-0002.",
        },
        // Microsoft IIS
        CveEntry {
            id: "CVE-2021-31166",
            product_match: "Microsoft-IIS",
            version_constraint: VersionPredicate::Contains(&["IIS/10.0"]),
            severity: Severity::High,
            cvss: 9.8,
            title: "HTTP.sys remote code execution (CVE-2021-31166)",
            detail: "Use-after-free in HTTP.sys allows pre-auth RCE on Windows.",
            recommendation: "Apply Windows May 2021 security update.",
        },
        // Confluence
        CveEntry {
            id: "CVE-2023-22515",
            product_match: "Confluence",
            version_constraint: VersionPredicate::Always,
            severity: Severity::Critical,
            cvss: 10.0,
            title: "Confluence privilege escalation (CVE-2023-22515)",
            detail: "Atlassian Confluence Data Center / Server: unauthenticated admin account creation.",
            recommendation: "Upgrade Confluence to 8.3.3+ / 8.4.3+ / 8.5.2+. Cloud is not affected.",
        },
        // F5 BIG-IP
        CveEntry {
            id: "CVE-2022-1388",
            product_match: "BIG-IP",
            version_constraint: VersionPredicate::Always,
            severity: Severity::Critical,
            cvss: 9.8,
            title: "F5 BIG-IP iControl REST auth bypass (CVE-2022-1388)",
            detail: "Pre-auth RCE on iControl REST API. Mass-exploited.",
            recommendation: "Upgrade to fixed version per F5 K23605346.",
        },
        // Generic OpenSSL Heartbleed (for old gear)
        CveEntry {
            id: "CVE-2014-0160",
            product_match: "OpenSSL",
            version_constraint: VersionPredicate::Contains(&[
                "OpenSSL/1.0.1 ", "OpenSSL/1.0.1a", "OpenSSL/1.0.1b", "OpenSSL/1.0.1c",
                "OpenSSL/1.0.1d", "OpenSSL/1.0.1e", "OpenSSL/1.0.1f",
            ]),
            severity: Severity::Critical,
            cvss: 7.5,
            title: "OpenSSL Heartbleed (CVE-2014-0160)",
            detail: "Information disclosure via TLS heartbeat extension. Steals memory contents incl. private keys.",
            recommendation: "Upgrade OpenSSL to 1.0.1g or later. Rotate any keys served by affected versions.",
        },
        // WordPress — frequent target of mass exploits
        CveEntry {
            id: "CVE-2023-2745",
            product_match: "WordPress",
            version_constraint: VersionPredicate::Contains(&[
                "WordPress 6.0", "WordPress 6.1", "WordPress 6.2.0", "WordPress 6.2.1",
                "WordPress 5.0", "WordPress 5.1", "WordPress 5.2", "WordPress 5.3",
                "WordPress 5.4", "WordPress 5.5", "WordPress 5.6", "WordPress 5.7",
                "WordPress 5.8", "WordPress 5.9",
            ]),
            severity: Severity::Medium,
            cvss: 5.4,
            title: "WordPress directory traversal (CVE-2023-2745)",
            detail: "Directory traversal vulnerability in WP_HTML_Tag_Processor allows an authenticated user to access the contents of arbitrary files on the server.",
            recommendation: "Upgrade WordPress to 6.2.2 or later. Auto-update should handle this — verify it's enabled.",
        },
        CveEntry {
            id: "WP-OUTDATED",
            product_match: "WordPress",
            version_constraint: VersionPredicate::Contains(&[
                "WordPress 4.", "WordPress 5.0", "WordPress 5.1", "WordPress 5.2",
                "WordPress 5.3", "WordPress 5.4", "WordPress 5.5",
            ]),
            severity: Severity::High,
            cvss: 7.5,
            title: "Outdated WordPress version",
            detail: "WordPress major version is past end-of-life and accumulates known unpatched vulnerabilities. Wp-vuln databases list dozens of public exploits per major release.",
            recommendation: "Upgrade to the latest stable WordPress release. Audit installed plugins/themes — outdated WP usually means outdated extensions too.",
        },
        // Drupal
        CveEntry {
            id: "CVE-2018-7600",
            product_match: "Drupal",
            version_constraint: VersionPredicate::Contains(&[
                "Drupal 6", "Drupal 7.0", "Drupal 7.1", "Drupal 7.2", "Drupal 7.3",
                "Drupal 7.4", "Drupal 7.5",
                "Drupal 8.0", "Drupal 8.1", "Drupal 8.2", "Drupal 8.3", "Drupal 8.4",
            ]),
            severity: Severity::Critical,
            cvss: 9.8,
            title: "Drupalgeddon2 (CVE-2018-7600)",
            detail: "Pre-auth RCE via form-render input handling. One of the most-exploited public vulnerabilities of all time.",
            recommendation: "Upgrade to Drupal 7.58+, 8.3.9+, 8.4.6+, or 8.5.1+ immediately.",
        },
        CveEntry {
            id: "DRUPAL-OUTDATED",
            product_match: "Drupal",
            version_constraint: VersionPredicate::Contains(&[
                "Drupal 6", "Drupal 7", "Drupal 8", "Drupal 9.0", "Drupal 9.1",
                "Drupal 9.2", "Drupal 9.3",
            ]),
            severity: Severity::High,
            cvss: 7.0,
            title: "Outdated Drupal version",
            detail: "Drupal major version has reached end-of-life. Receives no security patches.",
            recommendation: "Upgrade to Drupal 10 (current stable).",
        },
        // Joomla
        CveEntry {
            id: "CVE-2023-23752",
            product_match: "Joomla",
            version_constraint: VersionPredicate::Contains(&[
                "Joomla 4.0", "Joomla 4.1", "Joomla 4.2.0", "Joomla 4.2.1",
                "Joomla 4.2.2", "Joomla 4.2.3", "Joomla 4.2.4", "Joomla 4.2.5",
                "Joomla 4.2.6", "Joomla 4.2.7",
            ]),
            severity: Severity::High,
            cvss: 5.3,
            title: "Joomla improper access check (CVE-2023-23752)",
            detail: "Improper access check in webservice endpoints allows unauthenticated config disclosure including DB credentials.",
            recommendation: "Upgrade Joomla to 4.2.8 or later.",
        },
        // Confluence
        CveEntry {
            id: "CVE-2022-26134",
            product_match: "Confluence",
            version_constraint: VersionPredicate::Contains(&[
                "Confluence 7.4", "Confluence 7.13", "Confluence 7.14", "Confluence 7.15",
                "Confluence 7.16", "Confluence 7.17", "Confluence 7.18",
            ]),
            severity: Severity::Critical,
            cvss: 9.8,
            title: "Confluence OGNL injection (CVE-2022-26134)",
            detail: "Pre-auth OGNL injection RCE. Mass-exploited in 2022.",
            recommendation: "Upgrade Confluence to a patched version (7.4.17+, 7.13.7+, 7.14.3+, 7.15.2+, 7.16.4+, 7.17.4+, 7.18.1+).",
        },
        // Jira
        CveEntry {
            id: "CVE-2021-26086",
            product_match: "Jira",
            version_constraint: VersionPredicate::Always,
            severity: Severity::Medium,
            cvss: 5.3,
            title: "Jira path traversal information disclosure (CVE-2021-26086)",
            detail: "Atlassian Jira: pre-auth path traversal allows reading WEB-INF files.",
            recommendation: "Upgrade Jira to 8.13.10+, 8.17.0+, 8.18.0+, or 8.5.16+.",
        },
    ]
}

fn match_cves(host_ip: &str, p: &PortProbe, banner: &str) -> Option<Vec<Finding>> {
    let mut hits: Vec<Finding> = Vec::new();
    let lower = banner.to_lowercase();

    // 1) Bundled high-impact list (always present, hand-curated).
    for entry in cve_database() {
        if !lower.contains(&entry.product_match.to_lowercase()) {
            continue;
        }
        let version_match = match entry.version_constraint {
            VersionPredicate::Always => true,
            VersionPredicate::Contains(versions) => versions.iter().any(|v| banner.contains(v)),
        };
        if !version_match {
            continue;
        }
        hits.push(Finding {
            id: format!("cve.{}", entry.id.to_lowercase()),
            host_ip: host_ip.to_owned(),
            port: Some(p.port),
            service: Some(p.service.clone()),
            severity: entry.severity,
            title: entry.title.to_owned(),
            detail: format!("Detected via banner: \"{banner}\". {}", entry.detail),
            recommendation: entry.recommendation.to_owned(),
            cve: Some(entry.id.to_owned()),
            cvss: Some(entry.cvss),
        });
    }

    // 2) Live NVD feed (cached on disk, refreshed weekly).
    // We load the cache once per scan-host call — small enough that
    // the cost is negligible vs running probes.
    let feed = crate::cve_feed::load();
    for fe in crate::cve_feed::match_with_cache(banner, &feed) {
        // Avoid double-reporting if a CVE id is in BOTH the bundled
        // list and the feed (the bundled wording is typically more
        // actionable, so let it win).
        if hits.iter().any(|h| h.cve.as_deref() == Some(&fe.id)) {
            continue;
        }
        hits.push(Finding {
            id: format!("cve.{}", fe.id.to_lowercase()),
            host_ip: host_ip.to_owned(),
            port: Some(p.port),
            service: Some(p.service.clone()),
            severity: fe.severity,
            title: fe.title.clone(),
            detail: format!("Detected via banner: \"{banner}\". {}", fe.detail),
            recommendation: fe.recommendation.clone(),
            cve: Some(fe.id.clone()),
            cvss: Some(fe.cvss),
        });
    }

    if hits.is_empty() {
        let _ = chrono::Utc::now().year();
        None
    } else {
        Some(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::PortProbe;

    fn probe(port: u16, service: &str) -> PortProbe {
        PortProbe {
            port,
            service: service.to_owned(),
            banner: None,
            server_header: None,
            title: None,
            powered_by: None,
            tls: None,
            fingerprints: vec![],
            web_paths: vec![],
            smb: None,
            snmp: None,
            ldap: None,
            extra_findings: vec![],
        }
    }

    #[test]
    fn match_never_panics_on_arbitrary_banner() {
        let p = probe(22, "ssh");
        // Sample of weird-but-valid inputs that could trip naive parsers.
        for banner in &[
            "",
            "OpenSSH",
            "OpenSSH_5.1p1 \x00\x01",
            "% % % % SSH-2.0-",
            "SSH-2.0-OpenSSH_8.2 ⚡ unicode banner",
            "very long banner ".repeat(500).as_str(),
            "{ \"injected\": \"json\" }",
        ] {
            // Should never panic.
            let _ = match_cves("1.1.1.1", &p, banner);
        }
    }

    #[test]
    fn matches_openssh_known_vulnerable_version() {
        let p = probe(22, "ssh");
        // 5.5p1 is the oldest entry in the CVE-2023-38408 list;
        // any match here proves the substring matcher works on
        // a known-vulnerable banner.
        let hits = match_cves("1.1.1.1", &p, "SSH-2.0-OpenSSH_5.5p1");
        let hits = hits.unwrap_or_default();
        assert!(
            hits.iter().any(|f| f.cve.as_deref() == Some("CVE-2023-38408")),
            "OpenSSH 5.5p1 should match CVE-2023-38408 (any pre-9.3p2)"
        );
    }

    #[test]
    fn current_openssh_version_does_not_match_old_cve() {
        let p = probe(22, "ssh");
        let hits = match_cves("1.1.1.1", &p, "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2");
        let hits = hits.unwrap_or_default();
        // OpenSSH 10.0 should not match CVE-2023-38408 (which is
        // for OpenSSH < 9.3p2). Catches a regression where the
        // version-substring list might accidentally include "10".
        assert!(
            !hits.iter().any(|f| f.cve.as_deref() == Some("CVE-2023-38408")),
            "OpenSSH 10.0 should not match CVE-2023-38408 (pre-9.3p2 only)"
        );
    }

    #[test]
    fn config_check_telnet_open() {
        let p = probe(23, "telnet");
        let mut findings = vec![];
        configuration_checks("1.1.1.1", &p, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "config.telnet-open");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn config_check_database_exposed() {
        for service in ["mysql", "postgres", "mongodb", "redis", "mssql"] {
            let p = probe(0, service);
            let mut findings = vec![];
            configuration_checks("1.1.1.1", &p, &mut findings);
            assert!(
                findings.iter().any(|f| f.id.starts_with("config.") && f.id.ends_with("-exposed")),
                "{service} should produce a *-exposed config finding"
            );
        }
    }

    #[test]
    fn tls_findings_flag_self_signed() {
        let tls = crate::probes::TlsInfo {
            version: "TLSv1.3".into(),
            cipher: "TLS_AES_256_GCM_SHA384".into(),
            cert_subject: Some("CN=example".into()),
            cert_issuer: Some("CN=example".into()),
            cert_san: vec![],
            cert_expires_iso: None,
            self_signed: true,
            weak_ciphers_accepted: vec![],
            protocols_accepted: vec![],
        };
        let mut out = vec![];
        tls_findings("1.1.1.1", 443, &tls, &mut out);
        assert!(out.iter().any(|f| f.id == "tls.self-signed"));
    }

    proptest::proptest! {
        /// Property: `match_cves` must never panic regardless of
        /// the banner string. A malformed `Server:` header from a
        /// hostile target shouldn't be able to crash a scan.
        #[test]
        fn prop_match_cves_never_panics(banner in ".{0,2048}") {
            let p = probe(80, "http");
            let _ = match_cves("1.1.1.1", &p, &banner);
        }

        /// Property: configuration_checks doesn't panic on any
        /// service string. Surprising service names from
        /// `guess_service` (or future additions) shouldn't crash.
        #[test]
        fn prop_config_checks_never_panic(
            service in "[a-zA-Z0-9_-]{0,64}",
            port in 0u16..65535
        ) {
            let p = probe(port, &service);
            let mut findings = vec![];
            configuration_checks("1.1.1.1", &p, &mut findings);
        }
    }

    #[test]
    fn tls_findings_flag_weak_cipher_matrix() {
        let tls = crate::probes::TlsInfo {
            version: "TLSv1.2".into(),
            cipher: "ECDHE-RSA-AES128-GCM-SHA256".into(),
            cert_subject: None,
            cert_issuer: None,
            cert_san: vec![],
            cert_expires_iso: None,
            self_signed: false,
            weak_ciphers_accepted: vec!["RC4".into(), "3DES".into()],
            protocols_accepted: vec!["TLSv1.0".into()],
        };
        let mut out = vec![];
        tls_findings("1.1.1.1", 443, &tls, &mut out);
        // One per weak cipher + one for the protocol = 3.
        assert!(out.iter().any(|f| f.id == "tls.cipher-rc4"));
        assert!(out.iter().any(|f| f.id == "tls.cipher-3des"));
        assert!(out.iter().any(|f| f.id == "tls.proto-tlsv10"));
    }
}
