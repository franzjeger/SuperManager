//! FortiGate REST-API + token-management glue.
//!
//! Exposes three primitives that the JSON-RPC server wraps:
//!
//! 1. [`api_request`]  — a generic REST proxy. Looks up the host's stored
//!    API token from the secret store, builds an HTTPS request with the
//!    `Authorization: Bearer <token>` header, and returns the raw response
//!    body (JSON for FortiOS).
//!
//! 2. [`generate_token`] — SSH into the device, run the FortiOS interactive
//!    `config system api-user` flow, parse the resulting `New API key:` line,
//!    and store it via `SecretStore`. Carries forward four bug fixes that
//!    landed on the Linux daemon's `fortigate_generate_api_token` over
//!    several iterations:
//!      - send each CLI line separately (FortiOS doesn't tolerate batched
//!        config commands in a shell session)
//!      - wait for the FortiOS prompt (`# `) between each line
//!      - request a PTY so the device behaves interactively
//!      - feed the admin password line-by-line when FortiOS prompts for it
//!
//! 3. [`get_token`]    — retrieve the stored token in cleartext for the GUI's
//!    "Copy token" / "Show token" affordance. Goes through the same
//!    `SecretStore` so the keychain ACL prompt is consistent.
//!
//! All three return `String`/`anyhow::Error` rather than the daemon-specific
//! `Response` type so the same module can be reused if we add a Tauri
//! frontend or CLI later. The `server` module wraps these into JSON-RPC
//! responses.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use supermgr_core::keyring::SecretStore;
use supermgr_core::host::Host;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::ssh::connection::SshSession;
use crate::state::DaemonState;

/// Default HTTP client timeout for FortiGate REST calls. FortiOS itself
/// usually answers in <1 s on healthy hardware, but DNS lookups + slow
/// WAN paths put us comfortably past that. 30 s mirrors the Linux
/// daemon's fortigate_api so behaviour is consistent.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Outcome of a `fortigate_api` call. `status` is the raw HTTP status
/// code (200, 401, 500, …); `body` is the response body (JSON for
/// FortiOS APIs, possibly HTML on error). The wrapper RPC only
/// surfaces an *error* response when the HTTP layer itself failed —
/// 4xx/5xx still return Ok so the GUI can show FortiOS's own error
/// JSON to the user.
#[derive(Debug)]
pub struct ApiResponse {
    pub status: u16,
    pub body: String,
}

/// Make a single REST call against a FortiGate host's API.
///
/// Looks up the host's API token from `secrets`, builds an HTTPS
/// request with `Authorization: Bearer <token>`, and returns the
/// response. The token never leaks into log output — error messages
/// are post-processed to substitute `***` for the token bytes.
///
/// `path` should start with `/api/v2/...`. `method` is the standard
/// HTTP verb (GET/POST/PUT/DELETE). `body` is a JSON string; pass
/// an empty string for GET.
pub async fn api_request(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
    method: &str,
    path: &str,
    body: &str,
) -> Result<ApiResponse> {
    // Snapshot connection params under lock; never call out to the
    // network with the state mutex held.
    let (hostname, api_port, _verify_tls, token_label) = {
        let st = state.lock().await;
        let host = st
            .ssh_hosts
            .get(&host_id)
            .ok_or_else(|| anyhow!("host not found: {host_id}"))?;
        let token_ref = host
            .api_token_ref
            .as_ref()
            .ok_or_else(|| anyhow!("no API token configured for host {host_id}"))?;
        (
            host.hostname.clone(),
            host.api_port.unwrap_or(443),
            host.api_verify_tls,
            token_ref.0.clone(),
        )
    };

    let token_bytes = secrets
        .retrieve(&token_label)
        .await
        .context("retrieve API token from keychain")?;
    let token = String::from_utf8(token_bytes.to_vec())
        .context("API token is not valid UTF-8")?;
    let token = token.trim().to_owned();

    let url = format!("https://{hostname}:{api_port}{path}");
    info!("fortigate_api: {method} {url}");

    // FortiGate appliances ship a self-signed cert by default. Enabling
    // `danger_accept_invalid_certs` is the operationally-correct choice
    // for the LAN-attached small-business segment we target — verifying
    // would require pinning a fingerprint per host (a feature we'll
    // add in a later phase). The token-bearer auth in the header is
    // what actually authenticates the request.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("build HTTP client")?;

    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        other => return Err(anyhow!("invalid HTTP method: {other}")),
    };

    req = req.header("Authorization", format!("Bearer {token}"));
    if !body.is_empty() && method.to_uppercase() != "GET" {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }

    let resp = req.send().await.map_err(|e| {
        // Strip the token from any error message before bubbling
        // out — reqwest sometimes embeds the URL in errors which
        // shouldn't leak even to logs.
        let msg = e.to_string().replace(&token, "***");
        warn!("fortigate_api: send failed: {msg}");
        anyhow!("API request failed: {msg}")
    })?;

    let status = resp.status().as_u16();
    let body_text = resp
        .text()
        .await
        .context("read response body")?;
    Ok(ApiResponse {
        status,
        body: body_text,
    })
}

/// Generate a new API token on the FortiGate via SSH, store it in
/// `secrets`, and return its label so the caller can update the
/// host record.
///
/// FortiOS exposes API tokens via the legacy CLI:
///
/// ```text
/// config system api-user
///   edit "<api_user>"
///     set accprofile "super_admin"
///     set vdom "root"
///   next
/// end
/// execute api-user generate-key <api_user>
/// ```
///
/// The `generate-key` command prompts for the admin password before
/// echoing the new key. We therefore drive an interactive shell
/// (`SshSession::shell_interact`) which is PTY-backed and waits for
/// the FortiOS prompt before sending each line.
///
/// Returns `(token, secret_label)` so the caller can both display the
/// token in the GUI (one-time, for "Copy") and persist the label on
/// the host record.
pub async fn generate_token(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    session: &SshSession,
    host: &Host,
    api_user: &str,
) -> Result<(String, String)> {
    info!(
        "fortigate_generate_api_token: generating for user '{}' on {}",
        api_user, host.hostname
    );

    // Pull the admin password if we have one — FortiOS requires it
    // for `generate-key`. If the host auths via SSH key we'll fall
    // through and the FortiOS prompt will time out, which is the
    // correct error to surface to the user (they need to add a
    // password, even if temporary, to derive the API token).
    let admin_password = if let Some(pw_ref) = host.auth_password_ref.clone() {
        let bytes = secrets
            .retrieve(&pw_ref.0)
            .await
            .context("retrieve admin password")?;
        Some(
            String::from_utf8(bytes.to_vec())
                .context("admin password is not valid UTF-8")?,
        )
    } else {
        None
    };

    let api_user_owned = api_user.to_owned();
    let cmd_lines: Vec<String> = vec![
        "config system api-user".into(),
        format!("edit \"{api_user_owned}\""),
        "set accprofile \"super_admin\"".into(),
        "set vdom \"root\"".into(),
        "next".into(),
        "end".into(),
        format!("execute api-user generate-key {api_user_owned}"),
    ];
    let mut lines: Vec<String> = cmd_lines;
    if let Some(ref pw) = admin_password {
        // The `generate-key` command asks "Password: " — append the
        // password line so shell_interact's send-and-wait loop fires
        // it once the prompt arrives.
        lines.push(pw.clone());
    }

    let output = {
        let line_refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        session
            .shell_interact(&line_refs, /* delay_ms */ 0, /* timeout_secs */ 30)
            .await
            .context("FortiGate interactive shell failed")?
    };
    info!(
        "fortigate_generate_api_token: shell output ({} bytes)",
        output.len()
    );

    // Parse the output for the `New API key:` line. FortiOS prints:
    //   New API key: <40-char-hex>
    //   This is the only time this API key will be displayed in plain text.
    let token = output
        .lines()
        .find_map(|l| {
            l.strip_prefix("New API key: ")
                .or_else(|| l.strip_prefix("New API key:"))
                .map(|s| s.trim().to_owned())
        })
        .ok_or_else(|| {
            // Truncate the dumped output so a wall of FortiOS banner
            // doesn't drown the actual error reason.
            let preview = output.lines().take(20).collect::<Vec<_>>().join("\n");
            anyhow!(
                "could not parse new API key from FortiGate output. First 20 lines:\n{preview}"
            )
        })?;

    // Persist under a deterministic label keyed by host id so multiple
    // hosts can have independent tokens without name collisions.
    let label = format!("ssh/{host_id}/fortigate-api-token", host_id = host.id.simple());
    secrets
        .store(&label, token.as_bytes())
        .await
        .context("store API token in keychain")?;

    // Update the host record so subsequent `api_request` calls find
    // the token. Save and persist via the daemon state's normal save
    // path so a daemon restart sees it too.
    {
        let mut st = state.lock().await;
        let host_mut = st
            .ssh_hosts
            .get_mut(&host.id)
            .ok_or_else(|| anyhow!("host vanished mid-call: {}", host.id))?;
        host_mut.api_token_ref = Some(supermgr_core::vpn::profile::SecretRef::new(label.clone()));
        // FortiOS REST defaults to the device's HTTPS admin port. We
        // don't know that without a separate query; default to 443 if
        // the user hasn't set one explicitly.
        host_mut.api_port.get_or_insert(443);
        host_mut.updated_at = chrono::Utc::now();
        let snapshot = host_mut.clone();
        st.save_ssh_host(&snapshot)
            .context("persist host with new API token")?;
    }

    info!("fortigate_generate_api_token: stored under label {label}");
    Ok((token, label))
}

/// Retrieve the stored API token in cleartext. Used by the "Copy
/// token" and "Reveal token" GUI affordances. Goes through the
/// `SecretStore` so the keychain ACL prompt is consistent with
/// other secret reads.
pub async fn get_token(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
) -> Result<String> {
    let label = {
        let st = state.lock().await;
        let host = st
            .ssh_hosts
            .get(&host_id)
            .ok_or_else(|| anyhow!("host not found: {host_id}"))?;
        host.api_token_ref
            .as_ref()
            .ok_or_else(|| anyhow!("no API token stored for host {host_id}"))?
            .0
            .clone()
    };
    let bytes = secrets.retrieve(&label).await.context("retrieve token")?;
    let s = String::from_utf8(bytes.to_vec())
        .context("token is not valid UTF-8")?;
    Ok(s.trim().to_owned())
}

/// Test the stored API token by making a low-cost authenticated
/// call to the device. Picks `/api/v2/monitor/system/status` which
/// every FortiGate exposes regardless of license tier and returns
/// quickly. Returns a small structured result so the GUI can
/// render "Connected to FortiGate-100F (FortiOS 7.4.3)" rather than
/// just a green dot.
pub async fn test_connection(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
) -> Result<TestResult> {
    let resp = api_request(
        state,
        secrets,
        host_id,
        "GET",
        "/api/v2/monitor/system/status",
        "",
    )
    .await?;

    if resp.status >= 400 {
        return Err(anyhow!(
            "FortiGate API returned HTTP {}: {}",
            resp.status,
            resp.body.chars().take(200).collect::<String>()
        ));
    }

    // FortiOS returns: { "results": { "version": "v7.4.3", "model": "FGT100F", "hostname": "FW01", ... }, ... }
    let parsed: serde_json::Value =
        serde_json::from_str(&resp.body).context("FortiOS status JSON parse")?;
    let results = parsed.get("results").unwrap_or(&parsed);
    let version = results
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_owned();
    let model = results
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_owned();
    let hostname = results
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_owned();
    let serial = results
        .get("serial")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_owned();
    Ok(TestResult {
        ok: true,
        version,
        model,
        hostname,
        serial,
    })
}

/// Result of [`test_connection`]. Serialized as JSON for the
/// JSON-RPC response so the Swift side can render rich status
/// instead of a generic OK/FAIL.
#[derive(Debug, serde::Serialize)]
pub struct TestResult {
    pub ok: bool,
    pub version: String,
    pub model: String,
    pub hostname: String,
    pub serial: String,
}

// ---------------------------------------------------------------------------
// Live dashboard
// ---------------------------------------------------------------------------

/// One point-in-time snapshot of a FortiGate's vitals. Aggregated
/// from four separate REST endpoints so the GUI gets a coherent
/// view in one round-trip rather than firing parallel calls and
/// discovering they don't all succeed.
///
/// Calls run concurrently inside [`get_dashboard`] via
/// `tokio::join!` so wall-clock latency is roughly the slowest
/// endpoint, not the sum.
///
/// Failure mode: each section is `Option<...>`. If `/monitor/vpn/ipsec`
/// is rejected (e.g. user-facing API token doesn't have VPN
/// scope) the rest of the dashboard still renders. The GUI can
/// show a tiny "—" for the missing card without an error toast.
#[derive(Debug, serde::Serialize)]
pub struct DashboardSnapshot {
    /// Identity block — same fields as `TestResult` but bundled
    /// in for the all-in-one fetch convenience.
    pub status: Option<DashboardStatus>,
    /// CPU / memory / session counts — fast-changing, the main
    /// "is this device under load right now?" data.
    pub resource: Option<DashboardResource>,
    /// Per-interface RX/TX bytes counters. Client computes deltas
    /// between snapshots to derive throughput rates.
    pub interfaces: Option<Vec<InterfaceStat>>,
    /// IPsec tunnel rollup — total + up. Detailed per-tunnel
    /// data lives in the existing `/monitor/vpn/ipsec` payload
    /// which we expose verbatim if the GUI wants it.
    pub vpn: Option<VpnSummary>,
    /// UTC time we fetched (set on the daemon side so the GUI
    /// doesn't depend on local clock skew).
    pub fetched_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Serialize)]
pub struct DashboardStatus {
    pub model: String,
    pub version: String,    // e.g. "v7.4.3,build0123"
    pub hostname: String,
    pub serial: String,
    pub uptime_seconds: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct DashboardResource {
    /// CPU usage in percent (0–100).
    pub cpu_pct: u8,
    /// Memory usage in percent (0–100).
    pub mem_pct: u8,
    /// Active session count.
    pub sessions: u64,
    /// Disk usage in percent. FortiGates with no log disk return
    /// 0 here — that's normal, not an error.
    pub disk_pct: u8,
}

#[derive(Debug, serde::Serialize)]
pub struct InterfaceStat {
    pub name: String,
    pub alias: String,
    /// Cumulative receive bytes since interface up.
    pub rx_bytes: u64,
    /// Cumulative transmit bytes since interface up.
    pub tx_bytes: u64,
    /// "up" / "down" / "unknown" — matches FortiOS link state.
    pub status: String,
    /// Negotiated link speed in Mbps. 0 means unknown / down.
    pub speed_mbps: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct VpnSummary {
    pub tunnels_total: u32,
    pub tunnels_up: u32,
}

/// Fetch a complete dashboard snapshot in one round-trip from the
/// GUI's perspective. The four underlying REST calls fire
/// concurrently; each fails independently so a transient quirk
/// in one endpoint doesn't blank the whole dashboard.
///
/// Total time is roughly max(call_a, call_b, call_c, call_d) —
/// usually under 800 ms on a healthy LAN-attached FortiGate.
pub async fn get_dashboard(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
) -> Result<DashboardSnapshot> {
    let (status_r, resource_r, interfaces_r, vpn_r) = tokio::join!(
        api_request(state, secrets, host_id, "GET", "/api/v2/monitor/system/status", ""),
        api_request(
            state,
            secrets,
            host_id,
            "GET",
            "/api/v2/monitor/system/resource/usage?scope=global",
            "",
        ),
        api_request(state, secrets, host_id, "GET", "/api/v2/monitor/system/interface", ""),
        api_request(state, secrets, host_id, "GET", "/api/v2/monitor/vpn/ipsec", ""),
    );

    let status = status_r.ok().and_then(|r| {
        if r.status >= 400 {
            warn!("dashboard: /system/status returned {}", r.status);
            return None;
        }
        parse_status(&r.body)
    });
    let resource = resource_r.ok().and_then(|r| {
        if r.status >= 400 {
            warn!("dashboard: /system/resource/usage returned {}", r.status);
            return None;
        }
        parse_resource(&r.body)
    });
    let interfaces = interfaces_r.ok().and_then(|r| {
        if r.status >= 400 {
            warn!("dashboard: /system/interface returned {}", r.status);
            return None;
        }
        parse_interfaces(&r.body)
    });
    let vpn = vpn_r.ok().and_then(|r| {
        if r.status >= 400 {
            // VPN endpoint is the most likely to 403 on tokens
            // without the right scope. Log at info, not warn,
            // so it doesn't pollute the steady-state log.
            info!("dashboard: /vpn/ipsec returned {}", r.status);
            return None;
        }
        parse_vpn(&r.body)
    });

    Ok(DashboardSnapshot {
        status,
        resource,
        interfaces,
        vpn,
        fetched_at: chrono::Utc::now(),
    })
}

/// Parse `/api/v2/monitor/system/status` into `DashboardStatus`.
/// FortiOS shape:
/// ```json
/// {
///   "results": {
///     "version": "v7.4.3,build0123",
///     "model": "FGT100F",
///     "hostname": "FW01",
///     "serial": "FGT100F1234567890",
///     "system_time": "...",
///     "uptime": 1234567
///   }
/// }
/// ```
fn parse_status(body: &str) -> Option<DashboardStatus> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let r = v.get("results").unwrap_or(&v);
    Some(DashboardStatus {
        model: r.get("model")?.as_str().unwrap_or("unknown").to_owned(),
        version: r.get("version")?.as_str().unwrap_or("unknown").to_owned(),
        hostname: r.get("hostname")?.as_str().unwrap_or("unknown").to_owned(),
        serial: r.get("serial")?.as_str().unwrap_or("unknown").to_owned(),
        uptime_seconds: r.get("uptime").and_then(|u| u.as_u64()).unwrap_or(0),
    })
}

/// Parse `/api/v2/monitor/system/resource/usage`. FortiOS returns
/// per-resource time series; we want the most recent value of each.
/// Shape:
/// ```json
/// {
///   "results": {
///     "cpu":      [{"current": 12, ...}, ...],
///     "memory":   [{"current": 45, ...}, ...],
///     "session":  [{"current": 1024, ...}, ...],
///     "disk":     [{"current": 7,  ...}, ...]
///   }
/// }
/// ```
fn parse_resource(body: &str) -> Option<DashboardResource> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let r = v.get("results")?;
    let pct = |key: &str| -> u8 {
        r.get(key)
            .and_then(|arr| arr.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| first.get("current"))
            .and_then(serde_json::Value::as_u64)
            .map_or(0, |n| n.min(100) as u8)
    };
    let count = |key: &str| -> u64 {
        r.get(key)
            .and_then(|arr| arr.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| first.get("current"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    Some(DashboardResource {
        cpu_pct: pct("cpu"),
        mem_pct: pct("memory"),
        sessions: count("session"),
        disk_pct: pct("disk"),
    })
}

/// Parse `/api/v2/monitor/system/interface`. We filter to physical
/// + aggregate interfaces and skip loopbacks / sub-VLANs to keep
/// the GUI table compact. Shape (results is keyed by ifname):
/// ```json
/// {
///   "results": {
///     "wan1": { "rx_bytes": 1234, "tx_bytes": 5678, "status": "up",
///               "speed": 1000, "alias": "WAN", ... },
///     "internal1": { ... }
///   }
/// }
/// ```
fn parse_interfaces(body: &str) -> Option<Vec<InterfaceStat>> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let r = v.get("results")?.as_object()?;
    let mut out = Vec::with_capacity(r.len());
    for (name, val) in r {
        // Skip noisy sub-interfaces / virtual stuff so the GUI
        // table doesn't drown in 50 rows. The web GUI shows the
        // same filter under "Network → Interfaces" by default.
        if name.starts_with("loop") || name.starts_with("ssl.") || name.starts_with("ipsec.") {
            continue;
        }
        let alias = val
            .get("alias")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_owned();
        let rx_bytes = val
            .get("rx_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let tx_bytes = val
            .get("tx_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let status = val
            .get("link")
            .and_then(|x| x.as_str())
            .or_else(|| val.get("status").and_then(|x| x.as_str()))
            .unwrap_or("unknown")
            .to_owned();
        let speed_mbps = val
            .get("speed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        out.push(InterfaceStat {
            name: name.clone(),
            alias,
            rx_bytes,
            tx_bytes,
            status,
            speed_mbps,
        });
    }
    // Stable order — ports first by name, so wan1 < wan2 < internal1.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Some(out)
}

/// Parse `/api/v2/monitor/vpn/ipsec`. Counts up tunnels by walking
/// the results array and summing `proxyid` entries that are up.
/// Shape:
/// ```json
/// {
///   "results": [
///     { "name": "...", "proxyid": [{"status": "up"}, {"status": "down"}], ... },
///     ...
///   ]
/// }
/// ```
fn parse_vpn(body: &str) -> Option<VpnSummary> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let r = v.get("results").and_then(|x| x.as_array())?;
    let mut total: u32 = 0;
    let mut up: u32 = 0;
    for tunnel in r {
        if let Some(proxies) = tunnel.get("proxyid").and_then(|p| p.as_array()) {
            for p in proxies {
                total += 1;
                if p.get("status").and_then(|s| s.as_str()) == Some("up") {
                    up += 1;
                }
            }
        } else {
            // No proxyid array — count the tunnel itself.
            total += 1;
            if tunnel.get("status").and_then(|s| s.as_str()) == Some("up") {
                up += 1;
            }
        }
    }
    Some(VpnSummary {
        tunnels_total: total,
        tunnels_up: up,
    })
}
