//! Network-appliance REST APIs (FortiGate, UniFi).
//!
//! These methods are the "push SSH keys to network devices + take config
//! backups" flow that is SuperManager's headline feature. The HTTP logic
//! is identical to the Linux daemon's; only the secret-resolution and
//! host-lookup paths differ — Windows reads host JSON from disk under
//! `%PROGRAMDATA%\SuperManager\hosts\` and pulls credentials from
//! Credential Manager.
//!
//! # TLS verification
//!
//! All clients are built with `danger_accept_invalid_certs(true)`. That
//! matches the Linux daemon, which has the same default for the same
//! reason: most FortiGate / UniFi / OPNsense deployments ship with a
//! self-signed certificate during initial provisioning, and forcing the
//! user to import the CA into the Windows trust store before any
//! management action is hostile. A future flag on the `Host` JSON
//! (`api_verify_tls`) will let the user opt back into strict verification.

use std::{path::Path, sync::Arc, time::Duration};

use reqwest::Client;
use serde_json::{json, Value};
use tracing::{info, warn};

use supermgr_core::keyring::SecretStore;
use supermgr_core::protocol::RpcError;

use super::known_hosts::KnownHostsStore;
use super::ssh_exec;

/// Single-call request timeout for short FortiGate API operations.
const API_TIMEOUT_SHORT: Duration = Duration::from_secs(30);
/// Longer timeout for operations like config backup that can take
/// tens of seconds on busy devices.
const API_TIMEOUT_LONG: Duration = Duration::from_secs(60);

/// Read host JSON from `%PROGRAMDATA%\SuperManager\hosts\<id>.json`.
fn read_host(root: &Path, host_id: &str) -> Result<Value, RpcError> {
    let path = root.join("hosts").join(format!("{host_id}.json"));
    let bytes = std::fs::read(&path)
        .map_err(|_| RpcError::NotFound(format!("host {host_id}")))?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| RpcError::Other(format!("parse host json: {e}")))
}

/// Read SSH-key JSON from `%PROGRAMDATA%\SuperManager\keys\<id>.json`.
fn read_key(root: &Path, key_id: &str) -> Result<Value, RpcError> {
    let path = root.join("keys").join(format!("{key_id}.json"));
    let bytes = std::fs::read(&path)
        .map_err(|_| RpcError::NotFound(format!("ssh key {key_id}")))?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| RpcError::Other(format!("parse key json: {e}")))
}

/// Build a reqwest client with our standard settings (self-signed TLS,
/// generous timeout, optional cookie jar for session-based APIs).
fn http_client(timeout: Duration, cookies: bool) -> Result<Client, RpcError> {
    let mut builder = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(timeout);
    if cookies {
        builder = builder.cookie_store(true);
    }
    builder
        .build()
        .map_err(|e| RpcError::Other(format!("HTTP client build: {e}")))
}

// ===========================================================================
// FortiGate
// ===========================================================================

/// Generic FortiGate REST call. The token lives in Credential Manager
/// under `supermgr/host/<id>/api-token`; we attach it as
/// `Authorization: Bearer ...`.
pub async fn fortigate_api(
    root: &Path,
    secret_store: Arc<dyn SecretStore>,
    host_id: &str,
    method: &str,
    path: &str,
    body: &str,
) -> Result<String, RpcError> {
    let meta = read_host(root, host_id)?;
    let hostname = meta
        .get("hostname")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("host missing 'hostname'".into()))?;
    let api_port = meta
        .get("api_port")
        .and_then(Value::as_u64)
        .unwrap_or(443) as u16;

    let token_bytes = secret_store
        .retrieve(&format!("supermgr/host/{host_id}/api-token"))
        .await
        .map_err(|e| RpcError::Secret(format!("FortiGate API token: {e}")))?;
    let token = std::str::from_utf8(&token_bytes)
        .map_err(|_| RpcError::Other("FortiGate API token is not valid UTF-8".into()))?
        .trim()
        .to_owned();

    let url = format!("https://{hostname}:{api_port}{path}");
    info!("fortigate_api: {method} {url}");

    let client = http_client(API_TIMEOUT_SHORT, false)?;
    let mut req = match method.to_ascii_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        other => {
            return Err(RpcError::Other(format!("invalid HTTP method: {other}")));
        }
    };
    req = req.header("Authorization", format!("Bearer {token}"));
    if !body.is_empty() && !method.eq_ignore_ascii_case("GET") {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }

    let resp = req.send().await.map_err(|e| {
        // Scrub the token before it reaches the log/output.
        let msg = e.to_string().replace(&token, "***");
        if e.is_timeout() {
            RpcError::Backend(format!(
                "FortiGate {hostname}:{api_port} did not respond within {:?}",
                API_TIMEOUT_SHORT
            ))
        } else if e.is_connect() {
            RpcError::Backend(format!(
                "cannot connect to FortiGate at {hostname}:{api_port}: {msg}"
            ))
        } else {
            RpcError::Backend(format!("FortiGate request failed: {msg}"))
        }
    })?;

    let status = resp.status().as_u16();
    let resp_body = resp
        .text()
        .await
        .map_err(|e| RpcError::Backend(format!("read FortiGate response: {e}")))?;

    if status >= 400 {
        return Err(RpcError::Backend(map_fortigate_status(status, &resp_body)));
    }
    Ok(resp_body)
}

fn map_fortigate_status(status: u16, body: &str) -> String {
    match status {
        401 => "authentication failed: invalid or expired API token".into(),
        403 => "permission denied: API token lacks required privileges".into(),
        404 => "API endpoint not found (check FortiOS version and path)".into(),
        405 => "method not allowed for this endpoint".into(),
        424 => format!("failed dependency: {}", &body[..body.len().min(200)]),
        s if s >= 500 => format!("FortiGate internal error ({s}): try again later"),
        _ => format!("HTTP {status}: {}", &body[..body.len().min(300)]),
    }
}

/// Push an SSH public key to a FortiGate admin via
/// `PUT /api/v2/cmdb/system/admin/<user>`.
pub async fn fortigate_push_ssh_key(
    root: &Path,
    secret_store: Arc<dyn SecretStore>,
    host_id: &str,
    key_id: &str,
    admin_user: &str,
) -> Result<String, RpcError> {
    let key_meta = read_key(root, key_id)?;
    let public_key = key_meta
        .get("public_key")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("SSH key has no 'public_key' field".into()))?;
    let body = json!({ "ssh-public-key1": public_key }).to_string();
    let path = format!("/api/v2/cmdb/system/admin/{admin_user}");
    info!(host_id, key_id, admin_user, "fortigate_push_ssh_key");
    fortigate_api(root, secret_store, host_id, "PUT", &path, &body).await
}

/// Snapshot a FortiGate config to
/// `%PROGRAMDATA%\SuperManager\backups\<host>_<timestamp>.conf` and
/// return the filename.
pub async fn fortigate_backup_config(
    root: &Path,
    secret_store: Arc<dyn SecretStore>,
    host_id: &str,
) -> Result<String, RpcError> {
    let meta = read_host(root, host_id)?;
    let hostname = meta
        .get("hostname")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("host missing 'hostname'".into()))?;
    let api_port = meta
        .get("api_port")
        .and_then(Value::as_u64)
        .unwrap_or(443) as u16;

    let token_bytes = secret_store
        .retrieve(&format!("supermgr/host/{host_id}/api-token"))
        .await
        .map_err(|e| RpcError::Secret(format!("FortiGate API token: {e}")))?;
    let token = std::str::from_utf8(&token_bytes)
        .map_err(|_| RpcError::Other("FortiGate API token is not valid UTF-8".into()))?
        .trim()
        .to_owned();

    let url = format!(
        "https://{hostname}:{api_port}/api/v2/monitor/system/config/backup?scope=global"
    );
    info!("fortigate_backup_config: POST {url}");

    let client = http_client(API_TIMEOUT_LONG, false)?;
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Length", "0")
        .send()
        .await
        .map_err(|e| {
            let msg = e.to_string().replace(&token, "***");
            if e.is_timeout() {
                RpcError::Backend(format!(
                    "FortiGate {hostname}:{api_port} backup did not respond within {:?}",
                    API_TIMEOUT_LONG
                ))
            } else if e.is_connect() {
                RpcError::Backend(format!(
                    "cannot connect to FortiGate at {hostname}:{api_port}: {msg}"
                ))
            } else {
                RpcError::Backend(format!("FortiGate backup request failed: {msg}"))
            }
        })?;

    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| RpcError::Backend(format!("read backup response: {e}")))?;

    if status >= 400 {
        return Err(RpcError::Backend(map_fortigate_status(status, &body)));
    }

    let backup_dir = root.join("backups");
    std::fs::create_dir_all(&backup_dir)
        .map_err(|e| RpcError::Other(format!("create backups dir: {e}")))?;

    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    // Sanitise hostname for filesystem use — alphanumerics, dash, dot only.
    let safe_host: String = hostname
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let filename = format!("{safe_host}_{ts}.conf");
    let filepath = backup_dir.join(&filename);
    std::fs::write(&filepath, &body)
        .map_err(|e| RpcError::Other(format!("write backup file: {e}")))?;

    info!(
        "fortigate_backup_config: saved {} ({} bytes)",
        filepath.display(),
        body.len()
    );
    Ok(filename)
}

// ===========================================================================
// UniFi
// ===========================================================================

/// Proxy a call to a UniFi controller's REST API. The controller URL +
/// credentials live on the host JSON; we authenticate with
/// `POST /api/auth/login` (cookies persist on the client) before issuing
/// the requested call.
pub async fn unifi_api(
    root: &Path,
    secret_store: Arc<dyn SecretStore>,
    host_id: &str,
    method: &str,
    path: &str,
    body: &str,
) -> Result<String, RpcError> {
    let meta = read_host(root, host_id)?;
    let controller_url = meta
        .get("unifi_controller_url")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("no UniFi controller URL configured".into()))?
        .trim_end_matches('/');

    let creds_bytes = secret_store
        .retrieve(&format!("supermgr/host/{host_id}/unifi-credentials"))
        .await
        .map_err(|e| RpcError::Secret(format!("UniFi credentials: {e}")))?;
    let creds: Value = serde_json::from_slice(&creds_bytes)
        .map_err(|e| RpcError::Other(format!("parse UniFi credentials JSON: {e}")))?;
    let username = creds
        .get("username")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("missing username in UniFi credentials".into()))?;
    let password = creds
        .get("password")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("missing password in UniFi credentials".into()))?;

    info!("unifi_api: {method} {controller_url}{path}");
    let client = http_client(API_TIMEOUT_SHORT, true)?;

    // Authenticate first — the cookie store inside `client` captures the
    // session cookie for the follow-up call automatically.
    let login_url = format!("{controller_url}/api/auth/login");
    let login_body = json!({ "username": username, "password": password });
    let login_resp = client
        .post(&login_url)
        .json(&login_body)
        .send()
        .await
        .map_err(|e| RpcError::Backend(format!("UniFi login: {e}")))?;
    let login_status = login_resp.status().as_u16();
    if login_status >= 400 {
        let text = login_resp.text().await.unwrap_or_default();
        return Err(RpcError::Backend(format!(
            "UniFi login failed ({login_status}): {}",
            &text[..text.len().min(200)]
        )));
    }

    let url = format!("{controller_url}{path}");
    let mut req = match method.to_ascii_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        other => return Err(RpcError::Other(format!("invalid HTTP method: {other}"))),
    };
    if !body.is_empty() && !method.eq_ignore_ascii_case("GET") {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }
    let resp = req
        .send()
        .await
        .map_err(|e| RpcError::Backend(format!("UniFi request: {e}")))?;
    let status = resp.status().as_u16();
    let resp_body = resp
        .text()
        .await
        .map_err(|e| RpcError::Backend(format!("read UniFi response: {e}")))?;
    if status >= 400 {
        return Err(RpcError::Backend(format!(
            "UniFi API {status}: {}",
            &resp_body[..resp_body.len().min(300)]
        )));
    }
    Ok(resp_body)
}

// ===========================================================================
// OPNsense
// ===========================================================================
//
// OPNsense uses HTTP Basic auth with an API key + secret pair created
// per-user in the WebAdmin. The credentials live in Credential Manager
// as a JSON blob `{"key": "...", "secret": "..."}` under
// `supermgr/host/<id>/opnsense-credentials`.

#[derive(serde::Deserialize)]
struct OpnSenseCreds {
    key: String,
    secret: String,
}

async fn load_opnsense_creds(
    secret_store: &Arc<dyn SecretStore>,
    host_id: &str,
) -> Result<OpnSenseCreds, RpcError> {
    let bytes = secret_store
        .retrieve(&format!("supermgr/host/{host_id}/opnsense-credentials"))
        .await
        .map_err(|e| RpcError::Secret(format!("OPNsense credentials: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| RpcError::Other(format!("parse OPNsense credentials JSON: {e}")))
}

async fn opnsense_request(
    secret_store: &Arc<dyn SecretStore>,
    host_id: &str,
    hostname: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
) -> Result<(u16, String), RpcError> {
    let creds = load_opnsense_creds(secret_store, host_id).await?;
    let url = format!("https://{hostname}:{port}{path}");
    info!("opnsense::request {method} {url}");
    let client = http_client(API_TIMEOUT_SHORT, false)?;
    let mut req = match method.to_ascii_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        m => return Err(RpcError::Other(format!("invalid HTTP method: {m}"))),
    };
    req = req.basic_auth(&creds.key, Some(&creds.secret));
    if !body.is_empty() && !method.eq_ignore_ascii_case("GET") {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_owned());
    }
    let secret_clone = creds.secret.clone();
    let resp = req.send().await.map_err(|e| {
        let msg = e.to_string().replace(&secret_clone, "***");
        if e.is_timeout() {
            RpcError::Backend(format!("OPNsense {hostname}:{port} timeout: {msg}"))
        } else if e.is_connect() {
            RpcError::Backend(format!("cannot connect to OPNsense at {hostname}:{port}: {msg}"))
        } else {
            RpcError::Backend(format!("OPNsense request failed: {msg}"))
        }
    })?;
    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|e| RpcError::Backend(format!("read OPNsense response: {e}")))?;
    Ok((status, text))
}

/// Proxy an arbitrary OPNsense REST API call through the daemon.
pub async fn opnsense_api(
    root: &Path,
    secret_store: Arc<dyn SecretStore>,
    host_id: &str,
    method: &str,
    path: &str,
    body: &str,
) -> Result<String, RpcError> {
    let meta = read_host(root, host_id)?;
    let hostname = meta
        .get("hostname")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("host missing 'hostname'".into()))?;
    let port = meta
        .get("api_port")
        .and_then(Value::as_u64)
        .unwrap_or(443) as u16;
    let (status, body) =
        opnsense_request(&secret_store, host_id, hostname, port, method, path, body).await?;
    if status >= 400 {
        return Err(RpcError::Backend(format!(
            "OPNsense API HTTP {status}: {}",
            &body[..body.len().min(300)]
        )));
    }
    Ok(body)
}

/// Snapshot an OPNsense config to
/// `%PROGRAMDATA%\SuperManager\backups\<host>_<ts>.opnsense.xml`.
/// Returns the saved filename. Matches the Linux daemon's naming so
/// users with both can browse backups in one place.
pub async fn opnsense_backup_config(
    root: &Path,
    secret_store: Arc<dyn SecretStore>,
    host_id: &str,
) -> Result<String, RpcError> {
    let meta = read_host(root, host_id)?;
    let hostname = meta
        .get("hostname")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("host missing 'hostname'".into()))?;
    let port = meta
        .get("api_port")
        .and_then(Value::as_u64)
        .unwrap_or(443) as u16;
    let (status, body) = opnsense_request(
        &secret_store,
        host_id,
        hostname,
        port,
        "GET",
        "/api/core/backup/download/this",
        "",
    )
    .await?;
    if status != 200 {
        return Err(RpcError::Backend(format!(
            "OPNsense backup HTTP {status}: {}",
            &body[..body.len().min(300)]
        )));
    }
    let backup_dir = root.join("backups");
    std::fs::create_dir_all(&backup_dir)
        .map_err(|e| RpcError::Other(format!("create backups dir: {e}")))?;
    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let safe_host: String = hostname
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let filename = format!("{safe_host}_{ts}.opnsense.xml");
    let path = backup_dir.join(&filename);
    std::fs::write(&path, &body)
        .map_err(|e| RpcError::Other(format!("write OPNsense backup: {e}")))?;
    info!(
        "opnsense_backup_config: saved {} ({} bytes)",
        path.display(),
        body.len()
    );
    Ok(filename)
}

// ===========================================================================
// Sophos XG Firewall (XML Configuration API)
// ===========================================================================
//
// Sophos expects an XML envelope that includes the WebAdmin
// `<Login>` block on every call. Credentials live in Credential
// Manager as `{"username": "...", "password": "..."}` under
// `supermgr/host/<id>/sophos-credentials`. The default WebAdmin port
// is 4444, but the value is stored on the host JSON's `api_port`.

#[derive(serde::Deserialize)]
struct SophosCreds {
    username: String,
    password: String,
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Send an XML Configuration API request to a Sophos appliance. Wraps
/// `inner_xml` in the `<Request><Login>...</Login>` envelope. Sophos
/// always returns HTTP 200 even on errors — the actual success/failure
/// is in the `<Status code="N">` tag of the response body, which the
/// caller (GUI / MCP tool) parses.
pub async fn sophos_xml_api(
    root: &Path,
    secret_store: Arc<dyn SecretStore>,
    host_id: &str,
    inner_xml: &str,
) -> Result<String, RpcError> {
    let meta = read_host(root, host_id)?;
    let hostname = meta
        .get("hostname")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("host missing 'hostname'".into()))?;
    let port = meta
        .get("api_port")
        .and_then(Value::as_u64)
        .unwrap_or(4444) as u16;

    let creds_bytes = secret_store
        .retrieve(&format!("supermgr/host/{host_id}/sophos-credentials"))
        .await
        .map_err(|e| RpcError::Secret(format!("Sophos credentials: {e}")))?;
    let creds: SophosCreds = serde_json::from_slice(&creds_bytes)
        .map_err(|e| RpcError::Other(format!("parse Sophos credentials JSON: {e}")))?;

    let envelope = format!(
        "<Request>\
            <Login>\
                <Username>{user}</Username>\
                <Password>{pass}</Password>\
            </Login>\
            {inner}\
         </Request>",
        user = xml_escape(&creds.username),
        pass = xml_escape(&creds.password),
        inner = inner_xml,
    );

    let url = format!("https://{hostname}:{port}/webconsole/APIController");
    info!("sophos_xml_api -> {url}");
    let client = http_client(API_TIMEOUT_SHORT, false)?;
    let password_clone = creds.password.clone();
    let resp = client
        .post(&url)
        .form(&[("reqxml", envelope.as_str())])
        .send()
        .await
        .map_err(|e| {
            let msg = e.to_string().replace(&password_clone, "***");
            if e.is_timeout() {
                RpcError::Backend(format!("Sophos {hostname}:{port} timeout: {msg}"))
            } else if e.is_connect() {
                RpcError::Backend(format!("cannot connect to Sophos at {hostname}:{port}: {msg}"))
            } else {
                RpcError::Backend(format!("Sophos request failed: {msg}"))
            }
        })?;
    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| RpcError::Backend(format!("read Sophos response: {e}")))?;
    if status >= 400 {
        return Err(RpcError::Backend(format!(
            "Sophos HTTP {status}: {}",
            &body[..body.len().min(300)]
        )));
    }
    Ok(body)
}

/// Run `set-inform <url>` over SSH against a UniFi-adopted device.
/// Reuses the SSH-exec path so credentials come out of Credential Manager
/// just like `ssh_execute_command`.
pub async fn unifi_set_inform(
    root: &Path,
    secret_store: Arc<dyn SecretStore>,
    known_hosts: KnownHostsStore,
    host_id: &str,
    inform_url: &str,
) -> Result<String, RpcError> {
    let meta = read_host(root, host_id)?;
    let device_type = meta
        .get("device_type")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !device_type.eq_ignore_ascii_case("UniFi") && !device_type.eq_ignore_ascii_case("unifi") {
        warn!("unifi_set_inform on non-UniFi device_type {device_type:?}");
    }
    let cmd = format!("set-inform {inform_url}");
    let value = ssh_exec::execute(root, secret_store, known_hosts, host_id, &cmd).await?;
    Ok(value.to_string())
}
