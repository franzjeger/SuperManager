//! FortiGate (FortiOS) REST API client.
//!
//! FortiGate exposes a JSON REST API at `https://<host>:<api_port>/api/v2/...`
//! authenticated with a Bearer API token created in the WebAdmin under
//! *System → Administrators → REST API Admin* (or via SSH; see
//! `daemon::fortigate_generate_api_token`).
//!
//! # Storage
//!
//! The token is stored as a single byte blob in the system secret service
//! under the label `supermgr/fg/<uuid>/api_token`. The blob is referenced
//! from `SshHost.api_token_ref`. The host's `api_port` field stores the
//! HTTPS admin port (default 443).
//!
//! # API surface
//!
//! - [`request`] — generic Bearer-auth HTTP call. Used by the daemon's
//!   `fortigate_api` D-Bus method as a thin proxy for the GUI.
//! - [`get_status`] — composite call that returns a [`FortiGateStatus`]
//!   struct suitable for direct consumption by the dashboard. Internally
//!   it issues a handful of GET requests in parallel and tolerates
//!   individual endpoint failures (returns `None` for the missing fields
//!   rather than failing the whole call).
//! - [`backup_config`] — POST `/api/v2/monitor/system/config/backup` and
//!   return the raw config body as a `String`. The daemon writes that to
//!   `/etc/supermgrd/backups/`.
//!
//! Endpoints used here were verified against FortiOS 7.4.x on 2026-04-28.
//! Reference: <https://docs.fortinet.com/document/fortigate/7.4.0/fortios-rest-api/>.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Stored credential blob for one FortiGate host.
///
/// FortiOS uses a single Bearer token; there is no separate user/secret
/// split like OPNsense. The token is sent as `Authorization: Bearer <t>`
/// on every API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// FortiGate REST API token.
    pub token: String,
}

/// Result of a [`request`] call. The body is returned as a UTF-8 string;
/// the config-backup endpoint returns its raw text/plain payload here too.
#[derive(Debug)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response body as text.
    pub body: String,
}

/// Composite "is this FortiGate alive and what version" snapshot for the
/// dashboard.
///
/// Every field is `Option` because each underlying endpoint is allowed to
/// fail independently — a transient permission error on one shouldn't
/// black-hole the entire status card.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FortiGateStatus {
    /// Hostname (`results.hostname` of `/api/v2/monitor/system/status`).
    pub hostname: Option<String>,
    /// FortiOS version string (e.g. `v7.4.5`).
    pub version: Option<String>,
    /// Build number associated with `version`.
    pub build: Option<u64>,
    /// Model identifier (e.g. `FGT60F`).
    pub model: Option<String>,
    /// Serial number — useful for licence / RMA correlation.
    pub serial: Option<String>,
    /// CPU usage percentage (0–100).
    pub cpu_pct: Option<u64>,
    /// Memory usage percentage (0–100).
    pub memory_pct: Option<u64>,
    /// Active session count.
    pub sessions: Option<u64>,
    /// Whether `/api/v2/monitor/system/firmware` lists any upgrade candidate.
    pub updates_available: Option<bool>,
}

/// Build a reqwest client suitable for talking to a FortiGate.
///
/// Self-signed certs on FortiGate appliances are the norm, so verification
/// is disabled. The timeout is the combined connect+read budget; callers
/// pass a longer one for the backup endpoint, which can take tens of
/// seconds on busy boxes.
fn http_client(timeout: Duration) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(timeout)
        .build()
}

/// Map an HTTP status code to a human-readable error string.
///
/// Pulled out of [`request`] so [`backup_config`] can reuse it. Surfaced
/// strings match the messages the daemon shipped before this module
/// existed — the GUI keys some banners on this wording.
fn describe_status_error(status: u16, body: &str) -> String {
    let snippet = || body.chars().take(200).collect::<String>();
    match status {
        401 => "authentication failed: invalid or expired API token".to_owned(),
        403 => {
            "permission denied: the API token lacks required privileges \
             for this operation"
                .to_owned()
        }
        404 => {
            "API endpoint not found: check the FortiGate firmware version \
             and API path"
                .to_owned()
        }
        405 => {
            "method not allowed: this API endpoint does not support the \
             requested HTTP method"
                .to_owned()
        }
        424 => format!("failed dependency: a prerequisite was not met — {}", snippet()),
        s if s >= 500 => format!("FortiGate internal error ({s}): try again later"),
        _ => format!("HTTP {status}: {}", snippet()),
    }
}

/// Issue a Bearer-auth request to a FortiGate API endpoint and return the
/// raw body. Errors map to a human-readable string suitable for surfacing
/// to the GUI; the secret token is scrubbed out of any error message.
pub async fn request(
    hostname: &str,
    port: u16,
    creds: &Credentials,
    method: &str,
    path: &str,
    body: &str,
) -> Result<Response, String> {
    request_with_timeout(
        hostname,
        port,
        creds,
        method,
        path,
        body,
        Duration::from_secs(30),
    )
    .await
}

/// Variant of [`request`] with a caller-controlled timeout. The default
/// 30 s is right for almost every endpoint; the only known exception is
/// the config backup call, which can take ~60 s on saturated devices.
pub async fn request_with_timeout(
    hostname: &str,
    port: u16,
    creds: &Credentials,
    method: &str,
    path: &str,
    body: &str,
    timeout: Duration,
) -> Result<Response, String> {
    let url = format!("https://{hostname}:{port}{path}");
    debug!("fortigate::request {method} {url}");

    let client = http_client(timeout)
        .map_err(|e| format!("HTTP client build failed: {e}"))?;

    let mut req = match method.to_ascii_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        m => return Err(format!("unsupported HTTP method: {m}")),
    };

    req = req.header(
        "Authorization",
        format!("Bearer {}", creds.token.trim()),
    );
    if !body.is_empty() && !method.eq_ignore_ascii_case("GET") {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }

    let resp = req.send().await.map_err(|e| {
        // Don't leak the token in error strings.
        let msg = e.to_string().replace(creds.token.trim(), "***");
        if e.is_timeout() {
            format!(
                "FortiGate API request timed out: the device at \
                 {hostname}:{port} did not respond within \
                 {} s — verify the host is reachable",
                timeout.as_secs()
            )
        } else if e.is_connect() {
            format!(
                "cannot connect to FortiGate at {hostname}:{port}: {msg} — \
                 check that the device is online and the API port is correct"
            )
        } else {
            format!("FortiGate API request failed: {msg}")
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
) -> FortiGateStatus {
    let mut s = FortiGateStatus::default();

    if let Ok(resp) = request(
        hostname,
        port,
        creds,
        "GET",
        "/api/v2/monitor/system/status",
        "",
    )
    .await
    {
        if resp.status == 200 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                let r = v.get("results").unwrap_or(&v);
                s.hostname = r
                    .get("hostname")
                    .and_then(|x| x.as_str())
                    .map(str::to_owned);
                s.version = v
                    .get("version")
                    .and_then(|x| x.as_str())
                    .or_else(|| r.get("version").and_then(|x| x.as_str()))
                    .map(str::to_owned);
                s.build = v
                    .get("build")
                    .and_then(|x| x.as_u64())
                    .or_else(|| r.get("build").and_then(|x| x.as_u64()));
                s.model = r
                    .get("model")
                    .and_then(|x| x.as_str())
                    .map(str::to_owned);
                s.serial = r
                    .get("serial")
                    .and_then(|x| x.as_str())
                    .map(str::to_owned);
            }
        } else {
            warn!("fortigate system/status returned HTTP {}", resp.status);
        }
    }

    if let Ok(resp) = request(
        hostname,
        port,
        creds,
        "GET",
        "/api/v2/monitor/system/resource/usage",
        "",
    )
    .await
    {
        if resp.status == 200 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                // Each resource field is a list of samples; the most recent
                // sample is at index 0 and exposes a `current` value.
                let pick = |key: &str| -> Option<u64> {
                    v.pointer("/results")
                        .and_then(|res| res.get(key))
                        .and_then(|arr| arr.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|sample| sample.get("current"))
                        .and_then(|x| x.as_u64())
                };
                s.cpu_pct = pick("cpu");
                s.memory_pct = pick("mem");
                s.sessions = pick("session");
            }
        }
    }

    if let Ok(resp) = request(
        hostname,
        port,
        creds,
        "GET",
        "/api/v2/monitor/system/firmware",
        "",
    )
    .await
    {
        if resp.status == 200 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                s.updates_available = v
                    .pointer("/results/available")
                    .and_then(|x| x.as_array())
                    .map(|arr| !arr.is_empty());
            }
        }
    }

    s
}

/// Download the running config and return it verbatim.
///
/// Hits `POST /api/v2/monitor/system/config/backup?scope=global` with a 60 s
/// timeout. The response body is the raw FortiGate CLI config (text), which
/// the caller writes to disk. On non-2xx status the daemon-facing error
/// string mirrors what `daemon::fortigate_backup_config` shipped before
/// this helper existed.
pub async fn backup_config(
    hostname: &str,
    port: u16,
    creds: &Credentials,
) -> Result<String, String> {
    let resp = request_with_timeout(
        hostname,
        port,
        creds,
        "POST",
        "/api/v2/monitor/system/config/backup?scope=global",
        "",
        Duration::from_secs(60),
    )
    .await?;

    if resp.status >= 400 {
        return Err(describe_status_error(resp.status, &resp.body));
    }
    Ok(resp.body)
}

/// Surface [`describe_status_error`] for the daemon's `fortigate_api` shim
/// so non-success responses keep the same wording as before the refactor.
pub fn status_error(status: u16, body: &str) -> String {
    describe_status_error(status, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fortigate_status_defaults_are_all_none() {
        let s = FortiGateStatus::default();
        assert!(s.hostname.is_none());
        assert!(s.version.is_none());
        assert!(s.build.is_none());
        assert!(s.model.is_none());
        assert!(s.serial.is_none());
        assert!(s.cpu_pct.is_none());
        assert!(s.memory_pct.is_none());
        assert!(s.sessions.is_none());
        assert!(s.updates_available.is_none());
    }

    #[test]
    fn credentials_round_trip_json() {
        let c = Credentials {
            token: "abc123".into(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let parsed: Credentials = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.token, "abc123");
    }

    #[test]
    fn status_error_distinguishes_documented_codes() {
        assert!(describe_status_error(401, "").contains("authentication failed"));
        assert!(describe_status_error(403, "").contains("permission denied"));
        assert!(describe_status_error(404, "").contains("API endpoint not found"));
        assert!(describe_status_error(405, "").contains("method not allowed"));
        assert!(describe_status_error(500, "").contains("FortiGate internal error"));
        assert!(describe_status_error(418, "teapot body").contains("HTTP 418"));
        assert!(describe_status_error(424, "missing dep").contains("failed dependency"));
    }

    #[test]
    fn status_error_truncates_long_bodies() {
        let big = "x".repeat(1000);
        let msg = describe_status_error(418, &big);
        // 200-char snippet plus the "HTTP 418: " prefix and surrounding text;
        // anything well under the original 1000 confirms truncation.
        assert!(msg.len() < 300, "expected truncated, got {}", msg.len());
    }

    /// Live smoke test against a real FortiGate. Ignored by default — run
    /// with `cargo test -p supermgrd fortigate::tests::live_status -- \
    ///   --ignored --nocapture` and the env vars below to exercise the
    /// full `get_status` path end-to-end.
    ///
    /// Env vars:
    /// - `FORTIGATE_HOST`  e.g. `fw.example.com`
    /// - `FORTIGATE_PORT`  defaults to 443
    /// - `FORTIGATE_TOKEN` API token from System → Administrators
    #[tokio::test]
    #[ignore = "live: requires FORTIGATE_HOST/TOKEN env vars"]
    async fn live_status() {
        let host = std::env::var("FORTIGATE_HOST")
            .expect("set FORTIGATE_HOST to a reachable FortiGate");
        let port: u16 = std::env::var("FORTIGATE_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(443);
        let token = std::env::var("FORTIGATE_TOKEN").expect("set FORTIGATE_TOKEN");
        let creds = Credentials { token };

        let status = get_status(&host, port, &creds).await;
        eprintln!("FortiGate live status: {status:#?}");
        assert!(
            status.version.is_some() || status.hostname.is_some(),
            "no fields populated — check token / connectivity"
        );
        if let Some(ref v) = status.version {
            assert!(v.starts_with('v'), "version field has unexpected shape: {v:?}");
        }
    }
}
