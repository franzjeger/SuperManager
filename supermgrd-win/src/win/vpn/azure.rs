//! Azure Point-to-Site VPN backend (Windows).
//!
//! Connects to an Azure VPN gateway using Microsoft Entra ID
//! (PKCE authorization-code) auth, then drives `openvpn.exe` with a
//! generated `.ovpn` config — same protocol shape as the Linux daemon,
//! Windows-native plumbing for tempfiles, browser launch, and DNS.
//!
//! # Connection flow
//!
//! 1. **OAuth** — try to refresh a cached token via Credential Manager;
//!    fall back to the PKCE browser flow if the refresh fails or no
//!    cached token exists.
//! 2. **PKCE** — generate a code_verifier + code_challenge, bind a local
//!    TcpListener on `127.0.0.1:2023`, open the auth URL in the user's
//!    default browser, await the redirect, exchange the code for an
//!    access + refresh token.
//! 3. **Tempfiles** — write `tls-auth.key`, `auth.txt`, `client.ovpn` to
//!    `%PROGRAMDATA%\SuperManager\runtime\azure-<id>\`. The directory's
//!    ACL inherits from `%PROGRAMDATA%\SuperManager\` (SYSTEM +
//!    Administrators full control, Authenticated Users read+execute).
//! 4. **OpenVPN** — spawn `openvpn.exe --config client.ovpn`, capture
//!    stdout/stderr, wait for `Initialization Sequence Completed` (or
//!    a fatal error / timeout).
//! 5. **DNS** — push the profile's DNS servers via PowerShell's
//!    `Set-DnsClientServerAddress`, same pattern as the WireGuard backend.
//!
//! # Disconnect
//!
//! Kill the openvpn child, wait for exit, scrub the temp directory,
//! revert DNS.
//!
//! # Naming
//!
//! The type is called [`Ikev2Backend`] for backwards compatibility with
//! the `DaemonState` wiring set up in the earlier skeleton — the
//! `AzureVpnConfig` profile variant has historically routed through the
//! "ikev2" slot in [`super::VpnBackends`]. The struct name is the only
//! IKEv2-flavoured thing about this file; everything else is Azure P2S.

use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::Digest as _;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    process::{Child, Command},
    sync::Mutex,
    time::timeout,
};
use tracing::{info, warn};

use supermgr_core::keyring::SecretStore;
use supermgr_core::vpn::profile::{AzureVpnConfig, Profile, ProfileConfig};

use super::{VpnBackend, VpnError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Max time we wait for the user to complete browser auth. Device code
/// usually expires after 15 min; we give 20 to be safe.
const AUTH_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Max time we wait for openvpn to finish negotiating the tunnel.
const OPENVPN_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default install location of the OpenVPN Community binary.
const DEFAULT_OPENVPN_PATH: &str = r"C:\Program Files\OpenVPN\bin\openvpn.exe";

/// Loopback redirect URI used by the PKCE callback listener. Bound
/// BEFORE opening the browser so the redirect never races us.
const REDIRECT_URI: &str = "http://localhost:2023";
const REDIRECT_PORT: u16 = 2023;

// ---------------------------------------------------------------------------
// Active-tunnel state
// ---------------------------------------------------------------------------

struct AzActive {
    profile_id: uuid::Uuid,
    child: Child,
    /// Adapter name OpenVPN picks for the TAP/Wintun interface — sniffed
    /// out of the openvpn stdout. Used to revert DNS on disconnect.
    adapter_name: Option<String>,
    /// Temp directory holding the generated .ovpn + tls-auth key +
    /// auth-user-pass file. Cleaned up on disconnect.
    tmp_dir: PathBuf,
    /// Whether we pushed DNS that needs reverting.
    dns_overridden: bool,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Windows Azure VPN backend (named `Ikev2Backend` for legacy reasons —
/// see module docs).
pub struct Ikev2Backend {
    secret_store: Option<Arc<dyn SecretStore>>,
    active: Mutex<Option<AzActive>>,
}

impl Ikev2Backend {
    /// Construct with a secret store (required to cache the refresh token).
    pub fn with_store(secret_store: Arc<dyn SecretStore>) -> Self {
        Self {
            secret_store: Some(secret_store),
            active: Mutex::new(None),
        }
    }

    /// Whether a tunnel is currently up.
    pub async fn is_active(&self) -> bool {
        self.active.lock().await.is_some()
    }
}

impl Default for Ikev2Backend {
    fn default() -> Self {
        Self {
            secret_store: None,
            active: Mutex::new(None),
        }
    }
}

#[async_trait]
impl VpnBackend for Ikev2Backend {
    async fn connect(&self, profile_json: &str) -> Result<(), VpnError> {
        let profile: Profile = serde_json::from_str(profile_json).map_err(|e| {
            VpnError::MissingDependency(format!("parse Azure VPN profile JSON: {e}"))
        })?;
        self.bring_up(&profile).await
    }

    async fn disconnect(&self) -> Result<(), VpnError> {
        let active = self.active.lock().await.take();
        match active {
            Some(a) => {
                tear_down(a).await;
                Ok(())
            }
            None => Err(VpnError::NotImplemented("no active Azure VPN tunnel")),
        }
    }

    async fn status(&self) -> Result<String, VpnError> {
        let guard = self.active.lock().await;
        if let Some(a) = guard.as_ref() {
            Ok(serde_json::json!({
                "state": "Connected",
                "backend": "azure",
                "profile_id": a.profile_id.to_string(),
            })
            .to_string())
        } else {
            Ok(r#"{"state":"Disconnected","backend":"azure"}"#.to_owned())
        }
    }
}

impl Ikev2Backend {
    async fn bring_up(&self, profile: &Profile) -> Result<(), VpnError> {
        if let Some(prev) = self.active.lock().await.take() {
            tear_down(prev).await;
        }

        let cfg = match &profile.config {
            ProfileConfig::AzureVpn(c) => c.clone(),
            _ => {
                return Err(VpnError::MissingDependency(
                    "profile is not an Azure VPN profile".into(),
                ));
            }
        };

        let store = self.secret_store.as_ref().ok_or_else(|| {
            VpnError::MissingDependency(
                "Azure backend has no secret store; cannot cache the refresh token".into(),
            )
        })?;

        info!(profile_id = %profile.id, "Azure: starting connect");

        // ── Step 1 — OAuth ──────────────────────────────────────────────────
        let access_token =
            authenticate(&profile.id, &cfg.tenant_id, &cfg.client_id, store.as_ref()).await?;
        let upn = jwt_upn(&access_token);
        info!(upn, "Azure: authenticated");

        // ── Step 2 — Tempfiles ──────────────────────────────────────────────
        let tmp_dir = runtime_dir(&profile.id);
        std::fs::create_dir_all(&tmp_dir).map_err(VpnError::Io)?;

        let key_path = tmp_dir.join("tls-auth.key");
        let auth_path = tmp_dir.join("auth.txt");
        let ovpn_path = tmp_dir.join("client.ovpn");

        std::fs::write(&key_path, hex_to_openvpn_key(&cfg.server_secret_hex))
            .map_err(VpnError::Io)?;
        std::fs::write(&auth_path, format!("{upn}\n{access_token}\n")).map_err(VpnError::Io)?;

        let ovpn = build_ovpn_config(
            &cfg,
            key_path.to_string_lossy().as_ref(),
            auth_path.to_string_lossy().as_ref(),
            profile.full_tunnel,
        );
        std::fs::write(&ovpn_path, ovpn).map_err(VpnError::Io)?;

        // ── Step 3 — Spawn openvpn.exe ──────────────────────────────────────
        let openvpn_exe = locate_openvpn()?;
        let mut command = Command::new(&openvpn_exe);
        command
            .arg("--config")
            .arg(&ovpn_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().map_err(VpnError::Io)?;
        info!(?openvpn_exe, config = %ovpn_path.display(), "spawned openvpn for Azure tunnel");

        // ── Step 4 — Wait for "Initialization Sequence Completed" ──────────
        // We don't enable the management socket here — Azure's flow is
        // fully scripted, mid-flight controls aren't needed. Stdout
        // parsing is enough to detect success.
        let stdout = child.stdout.take().ok_or_else(|| VpnError::Subprocess {
            code: -1,
            stderr: "no stdout pipe from openvpn".into(),
        })?;

        let (sender, mut watcher) = tokio::sync::mpsc::unbounded_channel::<String>();
        let stdout_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = sender.send(line);
            }
        });

        let mut adapter_name: Option<String> = None;
        let mut connected = false;
        let deadline = tokio::time::Instant::now() + OPENVPN_CONNECT_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let line = match timeout(remaining, watcher.recv()).await {
                Ok(Some(line)) => line,
                Ok(None) => break, // stdout closed → process exited
                Err(_) => break,    // timeout
            };
            if line.contains("Initialization Sequence Completed") {
                connected = true;
                break;
            }
            if line.contains("AUTH_FAILED") {
                let _ = child.kill().await;
                cleanup_tmp(&tmp_dir);
                stdout_task.abort();
                return Err(VpnError::PermissionDenied("Azure auth rejected by gateway"));
            }
            if let Some(name) = extract_tap_adapter(&line) {
                adapter_name = Some(name);
            }
        }
        stdout_task.abort();

        if !connected {
            let _ = child.kill().await;
            cleanup_tmp(&tmp_dir);
            return Err(VpnError::Subprocess {
                code: -1,
                stderr: format!(
                    "openvpn did not reach \"Initialization Sequence Completed\" within {OPENVPN_CONNECT_TIMEOUT:?}"
                ),
            });
        }

        info!(profile_id = %profile.id, adapter = ?adapter_name, "Azure tunnel up");

        // ── Step 5 — DNS push (best-effort) ─────────────────────────────────
        let mut dns_overridden = false;
        if !cfg.dns_servers.is_empty() {
            if let Some(name) = adapter_name.as_deref() {
                match push_dns(name, &cfg.dns_servers).await {
                    Ok(()) => dns_overridden = true,
                    Err(e) => warn!("Azure DNS push failed for {name}: {e:#}"),
                }
            } else {
                warn!("Azure: no adapter name parsed from openvpn output; DNS not pushed");
            }
        }

        *self.active.lock().await = Some(AzActive {
            profile_id: profile.id,
            child,
            adapter_name,
            tmp_dir,
            dns_overridden,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

async fn tear_down(mut active: AzActive) {
    info!(profile_id = %active.profile_id, "Azure: tearing down tunnel");
    let _ = active.child.kill().await;
    let _ = active.child.wait().await;
    if active.dns_overridden {
        if let Some(name) = active.adapter_name.as_deref() {
            if let Err(e) = reset_dns(name).await {
                warn!("Azure DNS reset on {name} failed: {e:#}");
            }
        }
    }
    cleanup_tmp(&active.tmp_dir);
}

fn cleanup_tmp(tmp_dir: &std::path::Path) {
    if let Err(e) = std::fs::remove_dir_all(tmp_dir) {
        warn!("remove Azure tmp dir {}: {e}", tmp_dir.display());
    }
}

fn runtime_dir(profile_id: &uuid::Uuid) -> PathBuf {
    PathBuf::from(r"C:\ProgramData\SuperManager\runtime")
        .join(format!("azure-{}", profile_id.simple()))
}

// ---------------------------------------------------------------------------
// OAuth (PKCE authorization-code flow)
//
// Same protocol as the Linux daemon's `vpn::azure` module. We don't share
// the code today because the Linux daemon has the auth-tx channel and
// secret-store calls inline; pulling the OAuth helpers into
// `supermgr-core` is a separate cleanup PR.
// ---------------------------------------------------------------------------

fn refresh_token_label(profile_id: &uuid::Uuid) -> String {
    format!("supermgr/azure/{}/refresh_token", profile_id.simple())
}

async fn authenticate(
    profile_id: &uuid::Uuid,
    tenant_id: &str,
    audience: &str,
    secret_store: &dyn SecretStore,
) -> Result<String, VpnError> {
    let label = refresh_token_label(profile_id);

    // Fast path: cached refresh token.
    let cached = secret_store
        .retrieve(&label)
        .await
        .ok()
        .and_then(|b| String::from_utf8(b.to_vec()).ok());

    if let Some(rt) = cached {
        info!("Azure: trying cached refresh token");
        match refresh_access_token(tenant_id, audience, &rt).await {
            Ok((access, new_rt)) => {
                if let Err(e) = secret_store.store(&label, new_rt.as_bytes()).await {
                    warn!("Azure: failed to update cached refresh token: {e}");
                }
                return Ok(access);
            }
            Err(e) => warn!("Azure: cached refresh failed ({e}); falling back to browser auth"),
        }
    }

    let (access, refresh_opt) = pkce_browser_flow(tenant_id, audience).await?;
    if let Some(rt) = refresh_opt {
        if let Err(e) = secret_store.store(&label, rt.as_bytes()).await {
            warn!("Azure: failed to cache refresh token: {e}");
        }
    }
    Ok(access)
}

async fn refresh_access_token(
    tenant_id: &str,
    audience: &str,
    refresh_token: &str,
) -> Result<(String, String), VpnError> {
    let client = reqwest::Client::new();
    let url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let scope = format!("{audience}/.default openid offline_access profile");
    let resp = client
        .post(&url)
        .form(&[
            ("client_id", audience),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("scope", scope.as_str()),
        ])
        .send()
        .await
        .map_err(|e| VpnError::MissingDependency(format!("token refresh request: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| VpnError::MissingDependency(format!("token refresh parse: {e}")))?;
    match (body["access_token"].as_str(), body["refresh_token"].as_str()) {
        (Some(a), Some(r)) => Ok((a.to_owned(), r.to_owned())),
        _ => {
            let desc = body["error_description"]
                .as_str()
                .or_else(|| body["error"].as_str())
                .unwrap_or("unknown")
                .to_owned();
            Err(VpnError::MissingDependency(format!(
                "token refresh failed: {desc}"
            )))
        }
    }
}

async fn pkce_browser_flow(
    tenant_id: &str,
    audience: &str,
) -> Result<(String, Option<String>), VpnError> {
    let u1 = uuid::Uuid::new_v4();
    let u2 = uuid::Uuid::new_v4();
    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[..16].copy_from_slice(u1.as_bytes());
    verifier_bytes[16..].copy_from_slice(u2.as_bytes());
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let code_challenge =
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(code_verifier.as_bytes()));
    let state = uuid::Uuid::new_v4().to_string();
    let scope = format!("{audience}/.default openid offline_access profile");

    let auth_url = format!(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize\
         ?client_id={audience}\
         &code_challenge={code_challenge}\
         &code_challenge_method=S256\
         &prompt=select_account\
         &redirect_uri=http%3A%2F%2Flocalhost%3A2023\
         &response_type=code\
         &scope={scope_enc}\
         &state={state}",
        scope_enc = encode_query_value(&scope),
    );

    // Bind BEFORE opening the browser so we never miss the redirect.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", REDIRECT_PORT))
        .await
        .map_err(|e| {
            VpnError::MissingDependency(format!(
                "cannot listen on {REDIRECT_URI} for OAuth callback: {e}"
            ))
        })?;

    info!("Azure: opening browser at {auth_url}");
    open_url_in_browser(&auth_url)?;

    let code = timeout(AUTH_TIMEOUT, accept_auth_code(listener, &state))
        .await
        .map_err(|_| VpnError::Subprocess {
            code: -1,
            stderr: format!(
                "Entra ID browser authentication timed out after {AUTH_TIMEOUT:?}"
            ),
        })?
        .map_err(|e| VpnError::Subprocess {
            code: -1,
            stderr: format!("auth redirect: {e}"),
        })?;

    info!("Azure: authorization code received, exchanging for tokens");

    let client = reqwest::Client::new();
    let token_url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let resp = client
        .post(&token_url)
        .form(&[
            ("client_id", audience),
            ("client_info", "1"),
            ("code", code.as_str()),
            ("code_verifier", code_verifier.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", scope.as_str()),
        ])
        .send()
        .await
        .map_err(|e| VpnError::MissingDependency(format!("token exchange request: {e}")))?;
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| VpnError::MissingDependency(format!("token exchange parse: {e}")))?;
    match body["access_token"].as_str() {
        Some(a) => Ok((
            a.to_owned(),
            body["refresh_token"].as_str().map(str::to_owned),
        )),
        None => {
            let desc = body["error_description"]
                .as_str()
                .or_else(|| body["error"].as_str())
                .unwrap_or("unknown")
                .to_owned();
            Err(VpnError::MissingDependency(format!(
                "token exchange failed: {desc}"
            )))
        }
    }
}

/// Accept exactly one HTTP connection on `listener`, parse the OAuth2
/// `code` + `state` query parameters, respond with a friendly HTML, and
/// return the code.
async fn accept_auth_code(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, String> {
    let (stream, _) = listener
        .accept()
        .await
        .map_err(|e| format!("accept: {e}"))?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    let request_line = lines
        .next_line()
        .await
        .map_err(|e| format!("read: {e}"))?
        .ok_or_else(|| "empty HTTP request".to_string())?;

    let html = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "Connection: close\r\n\r\n",
        "<html><head><title>SuperManager</title></head><body>",
        "<h2>Authentication complete</h2>",
        "<p>You may close this tab and return to SuperManager.</p>",
        "</body></html>\r\n",
    );
    let _ = writer.write_all(html.as_bytes()).await;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "malformed HTTP request line".to_string())?;
    let query = path.splitn(2, '?').nth(1).unwrap_or("");

    let mut code: Option<String> = None;
    let mut returned_state: Option<String> = None;
    let mut error_desc: Option<String> = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let decoded = percent_decode(v);
            match k {
                "code" => code = Some(decoded),
                "state" => returned_state = Some(decoded),
                "error_description" => error_desc = Some(decoded),
                "error" if error_desc.is_none() => error_desc = Some(decoded),
                _ => {}
            }
        }
    }

    if let Some(e) = error_desc {
        return Err(e);
    }
    if let Some(s) = &returned_state {
        if s != expected_state {
            return Err("OAuth2 state mismatch — possible CSRF".to_string());
        }
    }
    code.ok_or_else(|| "no authorization code in redirect".into())
}

/// Open `url` in the user's default browser via `cmd /c start`. The
/// daemon runs as `LocalSystem`, which has no desktop session —
/// `ShellExecuteW` from Session 0 silently fails. Shelling out to
/// `cmd /c start "" "<url>"` posts the request through the shell
/// association machinery to the active interactive session.
///
/// In console-mode (interactive) runs this works the same way as a
/// regular foreground app.
fn open_url_in_browser(url: &str) -> Result<(), VpnError> {
    use std::process::Stdio;
    let status = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .map_err(VpnError::Io)?;
    if !status.success() {
        return Err(VpnError::Subprocess {
            code: status.code().unwrap_or(-1),
            stderr: format!("could not open browser for {url}"),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JWT + URL helpers
// ---------------------------------------------------------------------------

/// Extract `upn` or `preferred_username` from a JWT. Falls back to
/// `"AzureAD"` because openvpn accepts any non-empty username when the
/// password (the access token) is the real authenticator.
fn jwt_upn(token: &str) -> String {
    (|| -> Option<String> {
        let payload = token.split('.').nth(1)?;
        let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
        v["upn"]
            .as_str()
            .or_else(|| v["preferred_username"].as_str())
            .map(str::to_owned)
    })()
    .unwrap_or_else(|| "AzureAD".to_owned())
}

fn encode_query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"),
                16,
            ) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// .ovpn file generation
// ---------------------------------------------------------------------------

/// Convert the gateway's `server_secret_hex` to OpenVPN's static-key file
/// format (header + 64-char hex lines + footer). Identical to the Linux
/// daemon's helper.
fn hex_to_openvpn_key(hex: &str) -> String {
    let mut out = String::from("-----BEGIN OpenVPN Static key V1-----\n");
    for chunk in hex.as_bytes().chunks(32) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END OpenVPN Static key V1-----\n");
    out
}

/// Assemble the `.ovpn` text from the profile config + tempfile paths.
fn build_ovpn_config(
    cfg: &AzureVpnConfig,
    key_path: &str,
    auth_path: &str,
    full_tunnel: bool,
) -> String {
    let mut s = format!(
        "client\n\
         dev tun\n\
         proto tcp\n\
         remote {fqdn} 443\n\
         resolv-retry infinite\n\
         nobind\n\
         persist-tun\n\
         remote-cert-tls server\n\
         auth SHA256\n\
         cipher AES-256-GCM\n\
         data-ciphers AES-256-GCM\n\
         disable-dco\n\
         verb 3\n\
         <ca>\n",
        fqdn = cfg.gateway_fqdn,
    );
    s.push_str(&cfg.ca_cert_pem);
    if !cfg.ca_cert_pem.ends_with('\n') {
        s.push('\n');
    }
    s.push_str("</ca>\n");

    s.push_str(&format!("auth-user-pass {auth_path}\n"));
    s.push_str(&format!("tls-auth {key_path} 1\n"));

    if full_tunnel || cfg.routes.is_empty() {
        s.push_str("redirect-gateway def1\n");
    } else {
        for route in &cfg.routes {
            match route {
                ipnet::IpNet::V4(n) => {
                    s.push_str(&format!("route {} {}\n", n.network(), n.netmask()));
                }
                ipnet::IpNet::V6(n) => {
                    s.push_str(&format!("route-ipv6 {}/{}\n", n.network(), n.prefix_len()));
                }
            }
        }
    }

    if !cfg.dns_servers.is_empty() {
        s.push_str("dhcp-option DNS ");
        s.push_str(
            &cfg.dns_servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
        s.push('\n');
    }
    s
}

// ---------------------------------------------------------------------------
// openvpn.exe location + adapter parsing
// ---------------------------------------------------------------------------

fn locate_openvpn() -> Result<PathBuf, VpnError> {
    if let Some(p) = std::env::var_os("OPENVPN_EXE") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
    }
    if let Ok(p) = which::which("openvpn.exe") {
        return Ok(p);
    }
    let fallback = PathBuf::from(DEFAULT_OPENVPN_PATH);
    if fallback.exists() {
        return Ok(fallback);
    }
    Err(VpnError::MissingDependency(
        "openvpn.exe not found. Install OpenVPN Community Edition or set OPENVPN_EXE.".into(),
    ))
}

/// Sniff the TAP/Wintun adapter name out of openvpn's stdout. OpenVPN
/// prints one of:
///
/// ```text
/// TAP-WIN32 device [Local Area Connection 3] opened: \\.\Global\{guid}.tap
/// open_tun: opened Wintun adapter "SuperMgr-AZ-..." (driver ...)
/// ```
///
/// We extract the bracketed/quoted name.
fn extract_tap_adapter(line: &str) -> Option<String> {
    if let Some(start) = line.find("device [") {
        let rest = &line[start + "device [".len()..];
        if let Some(end) = rest.find(']') {
            return Some(rest[..end].to_owned());
        }
    }
    if let Some(start) = line.find("Wintun adapter \"") {
        let rest = &line[start + "Wintun adapter \"".len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_owned());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// DNS push (reuses the WireGuard backend's pattern)
// ---------------------------------------------------------------------------

async fn push_dns(adapter_name: &str, dns: &[std::net::IpAddr]) -> Result<(), VpnError> {
    if dns.is_empty() {
        return Ok(());
    }
    let servers = dns
        .iter()
        .map(|ip| format!("'{ip}'"))
        .collect::<Vec<_>>()
        .join(",");
    let cmd = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({})",
        adapter_name.replace('\'', "''"),
        servers,
    );
    run_powershell(&cmd).await
}

async fn reset_dns(adapter_name: &str) -> Result<(), VpnError> {
    let cmd = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
        adapter_name.replace('\'', "''"),
    );
    run_powershell(&cmd).await
}

async fn run_powershell(cmd: &str) -> Result<(), VpnError> {
    let output = tokio::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(cmd)
        .output()
        .await
        .map_err(VpnError::Io)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(VpnError::Subprocess {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}
