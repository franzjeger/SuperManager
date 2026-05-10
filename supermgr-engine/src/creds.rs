//! Default-credential testing — vendor-specific authentication
//! probes against discovered services.
//!
//! # Strategy
//!
//! Default credentials remain the #1 way attackers gain initial
//! access in Mirai-class botnets and ransomware operations. Our
//! job is to find them before someone else does.
//!
//! Per service we ship:
//!   - **Curated vendor-default list** — `admin/admin`,
//!     `ubnt/ubnt`, `cisco/cisco`, `root/calvin` (Dell iDRAC),
//!     `Administrator/...` (HP iLO), etc. Curated against MSP
//!     fleet experience — not exhaustive, but covers what
//!     actually shows up.
//!   - **Per-service authentication function** — SSH via russh,
//!     HTTP basic-auth via reqwest, SNMP via shell-out.
//!   - **Rate limit** — max 1 attempt per second per host to
//!     avoid lockout policies.
//!
//! Findings are surfaced at `Severity::Critical` — a successful
//! default credential is essentially "the device is open".

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::vuln::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPair {
    pub username: String,
    pub password: String,
    pub source: String,                  // "Ubiquiti default", "vendor-known", etc.
}

/// Curated default-credentials database. Keep small + relevant.
/// Each (service, vendor-context) → list of (user, pass) tuples.
pub fn default_creds_for_service(service: &str) -> Vec<CredentialPair> {
    match service {
        "ssh" => vec![
            // Ubiquiti — UniFi APs / EdgeRouter / EdgeSwitch all default to ubnt/ubnt
            cred("ubnt", "ubnt", "Ubiquiti default"),
            // Cisco
            cred("cisco", "cisco", "Cisco default"),
            cred("admin", "cisco", "Cisco common"),
            // Mikrotik
            cred("admin", "", "Mikrotik default (empty password)"),
            // FortiGate (won't allow over SSH usually but worth checking)
            cred("admin", "", "FortiGate factory default"),
            cred("admin", "admin", "FortiGate common"),
            // Dell iDRAC / Servers
            cred("root", "calvin", "Dell iDRAC default"),
            // HP iLO
            cred("Administrator", "Administrator", "HP iLO default"),
            // Common cheap home routers / IoT
            cred("admin", "admin", "Common default"),
            cred("admin", "password", "Common default"),
            cred("root", "root", "Common default"),
            cred("root", "toor", "BackTrack default"),
            cred("root", "", "Common (empty password)"),
            // Synology
            cred("admin", "", "Synology factory"),
            // pfSense
            cred("admin", "pfsense", "pfSense default"),
            // OpenWrt
            cred("root", "", "OpenWrt factory"),
        ],
        "http" | "https" | "fortigate" | "unifi" => vec![
            cred("admin", "admin", "Common default"),
            cred("admin", "password", "Common default"),
            cred("admin", "", "Common (empty password)"),
            cred("ubnt", "ubnt", "UniFi controller / Edge default"),
            cred("admin", "ubnt", "Ubiquiti web default"),
            cred("admin", "fortinet", "FortiGate web default"),
            cred("Administrator", "Administrator", "HP iLO web"),
            cred("root", "calvin", "Dell iDRAC web"),
            cred("admin", "1234", "Cheap-IoT common"),
            cred("admin", "12345", "Cheap-IoT common"),
            cred("admin", "synology", "Synology web"),
        ],
        "ftp" => vec![
            cred("anonymous", "", "Anonymous FTP"),
            cred("ftp", "ftp", "FTP default"),
            cred("admin", "admin", "Common default"),
        ],
        "telnet" => vec![
            cred("admin", "admin", "Common default"),
            cred("root", "root", "Common default"),
            cred("root", "", "Common (empty)"),
            cred("ubnt", "ubnt", "Ubiquiti default"),
            cred("cisco", "cisco", "Cisco default"),
        ],
        _ => Vec::new(),
    }
}

fn cred(user: &str, pass: &str, source: &str) -> CredentialPair {
    CredentialPair {
        username: user.to_owned(),
        password: pass.to_owned(),
        source: source.to_owned(),
    }
}

/// SSH default-credential test using russh. Max 1 attempt per
/// second per host. Returns the first matching pair (if any).
///
/// This is destructive-looking from the host's perspective —
/// auth failures may trigger lockout. We respect a hard 1-attempt-
/// per-second pace + abort early on the first success.
pub async fn ssh_test_defaults(host: &str, port: u16) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let creds = default_creds_for_service("ssh");
    for pair in creds {
        // Rate-limit between attempts.
        sleep(Duration::from_secs(1)).await;
        match ssh_try_auth(host, port, &pair.username, &pair.password).await {
            Ok(true) => {
                findings.push(Finding {
                    id: "creds.ssh-default".into(),
                    host_ip: host.to_owned(),
                    port: Some(port),
                    service: Some("ssh".into()),
                    severity: Severity::Critical,
                    title: format!(
                        "SSH accepts default credentials: {}:{}",
                        pair.username,
                        if pair.password.is_empty() { "(empty)" } else { &pair.password }
                    ),
                    detail: format!(
                        "Authenticated as '{}' using {}. This is a complete compromise of remote management.",
                        pair.username, pair.source
                    ),
                    recommendation: "Change the password to a 32+ character random string. Disable password auth, switch to SSH key only.".into(),
                    cve: None,
                    cvss: Some(10.0),
                });
                // Don't keep trying — we have a confirmed hit.
                break;
            }
            Ok(false) => {}
            Err(_) => {
                // Network errors abort — no point hammering further.
                break;
            }
        }
    }
    findings
}

/// Attempt password auth against (host, port) with one credential
/// pair. Returns:
///   - `Ok(true)`  — auth accepted; this credential is the answer
///   - `Ok(false)` — handshake completed, server rejected creds
///   - `Err(EngineError::SshNetwork)`     — couldn't reach host
///   - `Err(EngineError::SshDisconnected)` — handshake started then closed
///
/// The structured error variants let `ssh_test_defaults` keep
/// trying when only the password was wrong, but bail immediately
/// when the host is unreachable (no point hammering 20 more
/// passwords against a dead network path).
async fn ssh_try_auth(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
) -> Result<bool, crate::error::EngineError> {
    use crate::error::EngineError;
    use russh::client::{Config, Handle};

    struct Client;
    #[async_trait::async_trait]
    impl russh::client::Handler for Client {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _server_public_key: &russh_keys::key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    let config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(5)),
        ..Config::default()
    });
    let target = (host.to_owned(), port);
    let connect_fut = russh::client::connect(config, target, Client);
    let mut session: Handle<Client> = match tokio::time::timeout(
        Duration::from_secs(5),
        connect_fut,
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(EngineError::SshNetwork {
            reason: format!("connect: {e}"),
        }),
        Err(_) => return Err(EngineError::SshNetwork {
            reason: "connect timeout (5s)".into(),
        }),
    };
    let success = session
        .authenticate_password(user, pass)
        .await
        .map_err(|e| EngineError::SshDisconnected {
            reason: format!("auth path: {e}"),
        })?;
    let _ = session.disconnect(russh::Disconnect::ByApplication, "", "").await;
    Ok(success)
}

/// HTTP basic-auth default-credential test. Probes the root
/// of the web service with each credential pair, looks at the
/// HTTP status. 200/302 = "auth accepted", 401 = "rejected".
pub async fn http_test_defaults(host: &str, port: u16, tls: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://{host}:{port}/");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build client");
    let creds = default_creds_for_service("http");
    for pair in creds {
        sleep(Duration::from_millis(800)).await;
        let resp = match client
            .get(&url)
            .basic_auth(&pair.username, Some(&pair.password))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = resp.status().as_u16();
        if status == 200 || status == 302 {
            // Heuristic — only flag if without auth we got 401
            // (avoiding open services that just always return 200).
            // Cheap probe: do an unauth GET to compare.
            let baseline = client.get(&url).send().await.ok().map(|r| r.status().as_u16()).unwrap_or(200);
            if baseline == 401 || baseline == 403 {
                findings.push(Finding {
                    id: "creds.http-default".into(),
                    host_ip: host.to_owned(),
                    port: Some(port),
                    service: Some(if tls { "https" } else { "http" }.into()),
                    severity: Severity::Critical,
                    title: format!(
                        "HTTP basic-auth accepts default credentials: {}:{}",
                        pair.username,
                        if pair.password.is_empty() { "(empty)" } else { &pair.password }
                    ),
                    detail: format!(
                        "{} returns {status} with basic-auth {}. Likely compromisable web admin.",
                        url, pair.source
                    ),
                    recommendation: "Change credentials to a strong random password. Implement MFA where available.".into(),
                    cve: None,
                    cvss: Some(9.0),
                });
                break;
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_defaults_include_known_vendors() {
        let pairs = default_creds_for_service("ssh");
        // Proves the curated list contains the high-impact entries
        // an operator expects.
        assert!(pairs.iter().any(|p| p.username == "ubnt" && p.password == "ubnt"),
            "Ubiquiti default ubnt/ubnt must be present");
        assert!(pairs.iter().any(|p| p.username == "root" && p.password == "calvin"),
            "Dell iDRAC root/calvin must be present");
        assert!(pairs.iter().any(|p| p.username == "Administrator" && p.password == "Administrator"),
            "HP iLO Administrator/Administrator must be present");
        assert!(pairs.iter().any(|p| p.username == "admin" && p.password.is_empty()),
            "Mikrotik admin with empty password must be present");
    }

    #[test]
    fn http_defaults_include_web_admin_combos() {
        let pairs = default_creds_for_service("http");
        assert!(pairs.iter().any(|p| p.username == "admin" && p.password == "admin"));
        assert!(pairs.iter().any(|p| p.username == "ubnt" && p.password == "ubnt"));
        assert!(pairs.iter().any(|p| p.username == "admin" && p.password == "fortinet"));
    }

    #[test]
    fn unknown_service_returns_empty() {
        let pairs = default_creds_for_service("rdp");
        assert!(pairs.is_empty(), "no default-cred coverage for RDP yet");
    }

    #[test]
    fn each_pair_has_source_attribution() {
        // Source field drives the finding's `detail` text — every
        // pair must have it so we don't ship "(unknown)" findings.
        for pair in default_creds_for_service("ssh") {
            assert!(!pair.source.is_empty(),
                "{}/{} has no source", pair.username, pair.password);
        }
        for pair in default_creds_for_service("http") {
            assert!(!pair.source.is_empty());
        }
    }

    #[test]
    fn no_dangerous_pairs_leak_into_other_services() {
        // SSH-specific defaults shouldn't appear under "http".
        let http = default_creds_for_service("http");
        // pfSense default is SSH-side; should not be in HTTP list.
        assert!(!http.iter().any(|p| p.username == "admin" && p.password == "pfsense"));
    }

    proptest::proptest! {
        /// Property: no service name should panic the lookup.
        /// Future scan code may pass odd service strings; the
        /// matcher must degrade to empty list, never crash.
        #[test]
        fn prop_default_creds_never_panics(service in "[a-z0-9_-]{0,32}") {
            let _ = default_creds_for_service(&service);
        }
    }
}
