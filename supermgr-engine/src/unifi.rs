//! UniFi Controller integration — set-inform, controller setup,
//! REST proxy.
//!
//! # Adoption flow
//!
//! UniFi devices ship in factory-default mode and listen for
//! adoption messages on TCP 8080. To pull a device into a
//! controller you SSH in (default creds: `ubnt:ubnt` for older
//! gear, `ubnt` + customer-supplied for newer) and run:
//!
//! ```text
//! set-inform http://<controller-ip>:8080/inform
//! ```
//!
//! The device then shows up as "Pending Adoption" in the
//! controller, where the admin clicks Adopt. Post-adoption the
//! controller's REST API can configure SSIDs, VLANs, etc.
//!
//! This module wraps:
//!   - [`set_inform`] — SSH into the device, run the inform
//!     command. Used both for first-time adoption and to
//!     re-point a device at a new controller.
//!   - [`set_controller`] — store the controller URL +
//!     credentials per host. Validates by attempting a login.
//!   - [`api_request`] — REST proxy. Logs in (cookie jar) then
//!     forwards the call.
//!
//! # Why credentials, not API keys
//!
//! UniFi v8+ supports API keys via "Settings → System →
//! Advanced → API". Older controllers (v6/v7) only do
//! username/password. To support both v6+ controllers without
//! per-version branching, we use username/password — the cookie
//! jar handles session reuse so the per-call login overhead is
//! negligible.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use supermgr_core::keyring::SecretStore;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::ssh::connection::SshSession;
use crate::state::DaemonState;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Run `set-inform <inform_url>` on the device via SSH. Used
/// for first-time adoption (factory defaults) or to repoint a
/// device at a different controller.
///
/// `ssh_username` and `ssh_password` are the device-level
/// credentials — not the controller's. UniFi factory default
/// is `ubnt`/`ubnt`. After adoption these change to the
/// controller's adopted-device credentials.
pub async fn set_inform(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
    inform_url: &str,
) -> Result<String> {
    // Defensive sanitisation. The GUI sends whatever's in the
    // text field. If the operator pasted "set-inform http://…"
    // (e.g. copied the full command from a UniFi forum thread),
    // the naive `format!("set-inform {}", …)` below would build
    // `set-inform set-inform http://…` which the device parses
    // as a syntax error. Strip a leading prefix once, here.
    let url = inform_url
        .trim()
        .trim_start_matches("set-inform")
        .trim_start();
    if url.is_empty() {
        return Err(anyhow!("inform URL is empty"));
    }
    // Sanity-check it parses as a URL so we fail fast on
    // typos rather than getting an opaque shell exit.
    let _parsed: reqwest::Url = url.parse()
        .with_context(|| format!("invalid inform URL: {url:?}"))?;
    let (_host, session) = open_session(state, secrets, host_id).await?;

    // UniFi device shell is busybox `ash`. Bare `set-inform`
    // is only available inside the `mca-cli` interactive shell
    // and via login-shell PATH hacks — neither apply when we
    // SSH-exec a single command. The portable invocation is
    // `mca-cli-op set-inform <url>` (UniFi Network 5.x+); we
    // fall back to bare `set-inform` for very old firmware
    // that lacks mca-cli-op, and to /usr/bin/syswrapper.sh for
    // legacy AC-series gear that has neither.
    //
    // Trying them all in sequence at the device side (using
    // `||` short-circuit chain) means one SSH session does
    // the whole probe — saves a round-trip per failed try and
    // ensures the device's chosen variant runs in its own
    // shell environment.
    let cmd = format!(
        "mca-cli-op set-inform {url} 2>/dev/null \
            || /sbin/set-inform {url} 2>/dev/null \
            || /usr/bin/syswrapper.sh set-inform {url} 2>/dev/null \
            || set-inform {url}"
    );
    info!("unifi set_inform: {cmd}");
    let (exit, stdout, stderr) = session
        .exec(&cmd)
        .await
        .map_err(|e| anyhow!("ssh exec: {e}"))?;
    let _ = session.disconnect().await;
    if exit != 0 {
        return Err(anyhow!(
            "set-inform returned exit {exit}: stdout={stdout} stderr={stderr}"
        ));
    }
    Ok(stdout.trim().to_owned())
}

/// Persist the UniFi controller URL + credentials for a host.
/// Authenticates first to fail-fast on bad creds; only saves on
/// success. Credentials are stored as JSON in the macOS keychain.
pub async fn set_controller(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
    url: &str,
    username: &str,
    password: &str,
) -> Result<()> {
    // Sanity-check the URL parses.
    let _parsed: reqwest::Url = url.parse().context("invalid controller URL")?;

    // Validate by attempting login. UniFi controllers redirect
    // browser hits to /manage/ but the API endpoint is stable
    // at /api/auth/login on UniFi Network Application v6+.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("build HTTP client")?;
    let login_url = format!("{url}/api/auth/login");
    let body = serde_json::json!({
        "username": username,
        "password": password,
    });
    let resp = client
        .post(&login_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("login {login_url}"))?;
    let status = resp.status().as_u16();
    if status >= 400 {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("UniFi login failed ({status}): {text}"));
    }

    // Persist credentials under a host-keyed label.
    let creds = serde_json::json!({
        "username": username,
        "password": password,
    });
    let label = format!("ssh/{}/unifi-credentials", host_id.simple());
    secrets
        .store(&label, creds.to_string().as_bytes())
        .await
        .context("store credentials")?;

    // Update the host record.
    let mut st = state.lock().await;
    let host = st
        .ssh_hosts
        .get_mut(&host_id)
        .ok_or_else(|| anyhow!("host vanished: {host_id}"))?;
    host.unifi_controller_url = Some(url.to_owned());
    host.unifi_api_token_ref =
        Some(supermgr_core::vpn::profile::SecretRef::new(label.clone()));
    host.updated_at = chrono::Utc::now();
    let snapshot = host.clone();
    st.save_ssh_host(&snapshot).context("persist host")?;
    info!("stored UniFi controller credentials under {label}");
    Ok(())
}

/// Forget the stored controller credentials and clear the URL.
pub async fn clear_controller(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
) -> Result<()> {
    let label = {
        let st = state.lock().await;
        let host = st
            .ssh_hosts
            .get(&host_id)
            .ok_or_else(|| anyhow!("host not found: {host_id}"))?;
        host.unifi_api_token_ref.as_ref().map(|r| r.0.clone())
    };
    if let Some(ref l) = label {
        let _ = secrets.delete(l).await;
    }
    let mut st = state.lock().await;
    let host = st
        .ssh_hosts
        .get_mut(&host_id)
        .ok_or_else(|| anyhow!("host vanished: {host_id}"))?;
    host.unifi_controller_url = None;
    host.unifi_api_token_ref = None;
    host.updated_at = chrono::Utc::now();
    let snapshot = host.clone();
    st.save_ssh_host(&snapshot).context("persist host")?;
    Ok(())
}

#[derive(Debug, serde::Serialize)]
pub struct ApiResponse {
    pub status: u16,
    pub body: String,
}

/// Generic UniFi REST proxy. Logs in (cookie jar carries the
/// session forward), then forwards the call. Returns the
/// HTTP status alongside the body so callers can branch on
/// 4xx without losing the controller's error text.
pub async fn api_request(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
    method: &str,
    path: &str,
    body: &str,
) -> Result<ApiResponse> {
    let (controller_url, creds_label) = {
        let st = state.lock().await;
        let host = st
            .ssh_hosts
            .get(&host_id)
            .ok_or_else(|| anyhow!("host not found: {host_id}"))?;
        let url = host
            .unifi_controller_url
            .clone()
            .ok_or_else(|| anyhow!("no UniFi controller URL configured"))?;
        let label = host
            .unifi_api_token_ref
            .as_ref()
            .ok_or_else(|| anyhow!("no UniFi credentials configured"))?
            .0
            .clone();
        (url, label)
    };

    let creds_bytes = secrets
        .retrieve(&creds_label)
        .await
        .context("retrieve UniFi credentials")?;
    let creds_str =
        String::from_utf8(creds_bytes.to_vec()).context("decode credentials")?;
    let creds: serde_json::Value =
        serde_json::from_str(&creds_str).context("parse credentials")?;
    let username = creds["username"]
        .as_str()
        .ok_or_else(|| anyhow!("missing username in credentials"))?;
    let password = creds["password"]
        .as_str()
        .ok_or_else(|| anyhow!("missing password in credentials"))?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("build HTTP client")?;

    // Login first.
    let login_url = format!("{controller_url}/api/auth/login");
    let login_body = serde_json::json!({
        "username": username,
        "password": password,
    });
    let login_resp = client
        .post(&login_url)
        .json(&login_body)
        .send()
        .await
        .map_err(|e| anyhow!("login: {e}"))?;
    let login_status = login_resp.status().as_u16();
    if login_status >= 400 {
        let text = login_resp.text().await.unwrap_or_default();
        return Err(anyhow!("UniFi login failed ({login_status}): {text}"));
    }

    let url = format!("{controller_url}{path}");
    info!("unifi_api: {method} {url}");

    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        other => return Err(anyhow!("invalid method: {other}")),
    };
    if !body.is_empty() && method.to_uppercase() != "GET" {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }

    let resp = req.send().await.map_err(|e| {
        let msg = e.to_string().replace(password, "***");
        warn!("unifi_api: {msg}");
        anyhow!("API call failed: {msg}")
    })?;
    let status = resp.status().as_u16();
    let body_text = resp.text().await.context("read response")?;
    Ok(ApiResponse {
        status,
        body: body_text,
    })
}

/// Convenience: call `/api/self` on the controller. Cheap
/// authentication probe used by the GUI's "Test connection"
/// button. Returns rich info (controller version, site name,
/// admin role) so the success banner can be specific.
pub async fn test_connection(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
) -> Result<TestResult> {
    let resp = api_request(state, secrets, host_id, "GET", "/api/self", "").await?;
    if resp.status >= 400 {
        return Err(anyhow!(
            "Controller returned {}: {}",
            resp.status,
            resp.body.chars().take(200).collect::<String>()
        ));
    }
    // /api/self returns: { "data": [ { "name": "...", "site_name": "default", ... } ], "meta": {...} }
    let parsed: serde_json::Value = serde_json::from_str(&resp.body).context("parse self JSON")?;
    let data = parsed
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|arr| arr.first())
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let username = data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_owned();
    let site = data
        .get("site_name")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_owned();
    let admin_role = data
        .get("ui_role")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_owned();
    // Pull the server version from /status (different endpoint
    // but cheap and informative).
    let status_resp = api_request(state, secrets, host_id, "GET", "/status", "").await;
    let server_version = status_resp
        .ok()
        .and_then(|r| serde_json::from_str::<serde_json::Value>(&r.body).ok())
        .and_then(|v| {
            v.get("meta")
                .and_then(|m| m.get("server_version"))
                .and_then(|s| s.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".into());
    Ok(TestResult {
        ok: true,
        username,
        site,
        admin_role,
        server_version,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestResult {
    pub ok: bool,
    pub username: String,
    pub site: String,
    pub admin_role: String,
    pub server_version: String,
}

async fn open_session(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
) -> Result<(supermgr_core::host::Host, SshSession)> {
    crate::server::connect_to_host_owned(state, secrets, host_id)
        .await
        .map_err(|e| anyhow!("ssh connect: {e}"))
}
