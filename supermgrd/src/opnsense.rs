//! OPNsense REST API client.
//!
//! OPNsense exposes a per-user REST API at `https://<host>/api/...` authenticated
//! with HTTP Basic over a key/secret pair created in the Webadmin under
//! *System → Access → Users → API keys*. Each key/secret pair is tied to one
//! user account and inherits that user's privileges.
//!
//! # Storage
//!
//! Credentials are stored as a single JSON blob in the system secret service
//! under the label `supermgr/opnsense/<uuid>/credentials`, mirroring how UniFi
//! controller credentials are stored:
//!
//! ```json
//! { "key": "<api key>", "secret": "<api secret>" }
//! ```
//!
//! The secret blob is referenced from `SshHost.api_token_ref`. The host's
//! `api_port` field stores the HTTPS port (default 443).
//!
//! # API surface
//!
//! - [`request`] — generic Basic-Auth-aware HTTP call. Used by the daemon's
//!   `opnsense_api` D-Bus method as a thin proxy for the GUI.
//! - [`get_status`] — composite call that returns a [`OpnSenseStatus`] struct
//!   suitable for direct consumption by the dashboard. Internally it issues a
//!   handful of GET requests in parallel and tolerates individual endpoint
//!   failures (returns `None` for the missing fields rather than failing the
//!   whole call).
//!
//! Endpoints used here were verified against OPNsense 26.1.6_2 (FreeBSD 14.3)
//! on 2026-04-28. The official docs are at <https://docs.opnsense.org/development/api.html>.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Stored credential blob for one OPNsense host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// API key — used as the Basic Auth username.
    pub key: String,
    /// API secret — used as the Basic Auth password.
    pub secret: String,
}

/// Result of a [`request`] call. The body is returned as a UTF-8 string; XML
/// endpoints (the config-backup download) return their raw payload here too.
#[derive(Debug)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response body as text.
    pub body: String,
}

/// Composite "is this OPNsense alive and what version" snapshot for the dashboard.
///
/// Every field is `Option` because each underlying endpoint is allowed to fail
/// independently — a transient permission error on one shouldn't black-hole the
/// entire status card.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpnSenseStatus {
    /// Hostname (`name` field of `/api/diagnostics/system/system_information`).
    pub hostname: Option<String>,
    /// OPNsense version string (e.g. `OPNsense 26.1.6_2-amd64`).
    pub opnsense_version: Option<String>,
    /// FreeBSD version string.
    pub freebsd_version: Option<String>,
    /// Whether `/api/core/firmware/status` reports any pending updates.
    pub updates_available: Option<bool>,
    /// Whether the box currently needs a reboot to finish a previous update.
    pub needs_reboot: Option<bool>,
    /// Total system memory in bytes.
    pub memory_total_bytes: Option<u64>,
    /// Used system memory in bytes.
    pub memory_used_bytes: Option<u64>,
    /// Map of interface device → label as configured in OPNsense.
    pub interfaces: Vec<InterfaceSummary>,
    /// Whether WireGuard is enabled (does not imply any peer is up).
    pub wireguard_enabled: Option<bool>,
}

/// One interface as listed by `/api/diagnostics/interface/getInterfaceNames`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSummary {
    /// Kernel device name (e.g. `igc0`, `vlan02`).
    pub device: String,
    /// Friendly name configured in OPNsense (e.g. `LAN`, `IoT`).
    pub label: String,
}

/// Build a reqwest client suitable for talking to OPNsense.
///
/// Self-signed certs are common on home appliances, so verification is
/// disabled by default. A 30 s connect+read timeout keeps the daemon from
/// blocking forever if the box is unreachable.
fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .build()
}

/// Issue a Basic-Auth request to an OPNsense API endpoint and return the raw
/// body. Errors map to a human-readable string suitable for surfacing to the
/// GUI.
pub async fn request(
    hostname: &str,
    port: u16,
    creds: &Credentials,
    method: &str,
    path: &str,
    body: &str,
) -> Result<Response, String> {
    let url = format!("https://{hostname}:{port}{path}");
    debug!("opnsense::request {method} {url}");

    let client = http_client().map_err(|e| format!("HTTP client build failed: {e}"))?;

    let mut req = match method.to_ascii_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        m => return Err(format!("unsupported HTTP method: {m}")),
    };

    req = req.basic_auth(&creds.key, Some(&creds.secret));
    if !body.is_empty() && method.eq_ignore_ascii_case("GET") == false {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }

    let resp = req.send().await.map_err(|e| {
        // Don't leak the secret in error strings.
        let msg = e.to_string().replace(&creds.secret, "***");
        if e.is_timeout() {
            format!("OPNsense API request timed out at {hostname}:{port}: {msg}")
        } else if e.is_connect() {
            format!("cannot connect to OPNsense at {hostname}:{port}: {msg}")
        } else {
            format!("OPNsense API request failed: {msg}")
        }
    })?;

    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("read response body: {e}"))?;
    Ok(Response { status, body: text })
}

/// Compose a dashboard-friendly status snapshot. Each underlying endpoint
/// failure is logged as a warning but does not fail the whole call.
pub async fn get_status(
    hostname: &str,
    port: u16,
    creds: &Credentials,
) -> OpnSenseStatus {
    let mut s = OpnSenseStatus::default();

    if let Ok(resp) = request(hostname, port, creds, "GET", "/api/diagnostics/system/system_information", "").await {
        if resp.status == 200 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                s.hostname = v.get("name").and_then(|n| n.as_str()).map(str::to_owned);
                if let Some(versions) = v.get("versions").and_then(|x| x.as_array()) {
                    s.opnsense_version = versions
                        .first()
                        .and_then(|x| x.as_str())
                        .map(str::to_owned);
                    s.freebsd_version = versions
                        .get(1)
                        .and_then(|x| x.as_str())
                        .map(str::to_owned);
                }
            }
        } else {
            warn!("opnsense system_information returned HTTP {}", resp.status);
        }
    }

    if let Ok(resp) = request(hostname, port, creds, "GET", "/api/core/firmware/status", "").await {
        if resp.status == 200 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                // OPNsense reports new packages and upgrade packages separately;
                // any non-empty list means an update is available.
                let new_pkgs = v.get("new_packages").and_then(|x| x.as_array()).map(|a| !a.is_empty());
                let upg_pkgs = v.get("upgrade_packages").and_then(|x| x.as_array()).map(|a| !a.is_empty());
                s.updates_available = match (new_pkgs, upg_pkgs) {
                    (Some(a), Some(b)) => Some(a || b),
                    (Some(a), None) | (None, Some(a)) => Some(a),
                    (None, None) => None,
                };
                s.needs_reboot = v
                    .get("needs_reboot")
                    .and_then(|x| x.as_str())
                    .map(|x| x == "1");
            }
        }
    }

    if let Ok(resp) = request(hostname, port, creds, "GET", "/api/diagnostics/system/system_resources", "").await {
        if resp.status == 200 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                s.memory_total_bytes = v
                    .pointer("/memory/total")
                    .and_then(|x| x.as_str())
                    .and_then(|s| s.parse().ok());
                s.memory_used_bytes = v
                    .pointer("/memory/used")
                    .and_then(|x| x.as_u64());
            }
        }
    }

    if let Ok(resp) = request(hostname, port, creds, "GET", "/api/diagnostics/interface/getInterfaceNames", "").await {
        if resp.status == 200 {
            if let Ok(map) = serde_json::from_str::<std::collections::BTreeMap<String, String>>(&resp.body) {
                s.interfaces = map
                    .into_iter()
                    .map(|(device, label)| InterfaceSummary { device, label })
                    .collect();
            }
        }
    }

    if let Ok(resp) = request(hostname, port, creds, "GET", "/api/wireguard/general/get", "").await {
        if resp.status == 200 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                s.wireguard_enabled = v
                    .pointer("/general/enabled")
                    .and_then(|x| x.as_str())
                    .map(|x| x == "1");
            }
        }
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opnsense_status_defaults_are_all_none_or_empty() {
        let s = OpnSenseStatus::default();
        assert!(s.hostname.is_none());
        assert!(s.opnsense_version.is_none());
        assert!(s.freebsd_version.is_none());
        assert!(s.updates_available.is_none());
        assert!(s.needs_reboot.is_none());
        assert!(s.memory_total_bytes.is_none());
        assert!(s.memory_used_bytes.is_none());
        assert!(s.interfaces.is_empty());
        assert!(s.wireguard_enabled.is_none());
    }

    #[test]
    fn credentials_round_trip_json() {
        let c = Credentials {
            key: "k".into(),
            secret: "s".into(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let parsed: Credentials = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.key, "k");
        assert_eq!(parsed.secret, "s");
    }

    /// Live smoke test against a real OPNsense box. Ignored by default —
    /// run with `cargo test -p supermgrd opnsense::tests::live_status -- \
    ///   --ignored --nocapture` and the env vars below to exercise the full
    /// `get_status` path end-to-end. Useful when adapting to a new
    /// OPNsense major release whose endpoint shapes might have shifted.
    ///
    /// Env vars:
    /// - `OPNSENSE_HOST`   e.g. `opnsense.tailb0b06a.ts.net`
    /// - `OPNSENSE_PORT`   defaults to 443
    /// - `OPNSENSE_KEY`    API key from System → Access → Users
    /// - `OPNSENSE_SECRET` API secret matching the key
    #[tokio::test]
    #[ignore = "live: requires OPNSENSE_HOST/KEY/SECRET env vars"]
    async fn live_status() {
        let host = std::env::var("OPNSENSE_HOST")
            .expect("set OPNSENSE_HOST to a reachable OPNsense box");
        let port: u16 = std::env::var("OPNSENSE_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);
        let key = std::env::var("OPNSENSE_KEY").expect("set OPNSENSE_KEY");
        let secret = std::env::var("OPNSENSE_SECRET").expect("set OPNSENSE_SECRET");
        let creds = Credentials { key, secret };

        let status = get_status(&host, port, &creds).await;
        eprintln!("OPNsense live status: {status:#?}");
        assert!(
            status.opnsense_version.is_some() || status.hostname.is_some(),
            "no fields populated — check credentials/connectivity"
        );
        if let Some(ref v) = status.opnsense_version {
            assert!(v.contains("OPNsense"), "version field has unexpected shape: {v:?}");
        }
    }
}
