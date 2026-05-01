//! Azure Point-to-Site VPN backend — Entra ID (device-code) authentication
//! over OpenVPN.
//!
//! # Connection flow
//!
//! 1. POST to `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode`
//!    to receive a `user_code` + `verification_uri`.
//! 2. Send both over the `auth_tx` channel so the daemon can emit an
//!    `auth_challenge` D-Bus signal to the GUI.
//! 3. Poll `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
//!    every `interval` seconds until the user authenticates in the browser.
//! 4. Extract the UPN / preferred_username from the JWT access token payload.
//! 5. Write three temporary files to `/run/supermgrd/azure-<uuid>/`:
//!    - `tls-auth.key`   — OpenVPN static key converted from `server_secret_hex` (tls-auth dir 1, SHA256).
//!    - `ca.pem`         — PEM CA certificate from the profile.
//!    - `auth.txt`       — Two-line `openvpn --auth-user-pass` credentials file
//!                         (`<upn>\n<access_token>`).
//!    - `client.ovpn`    — Assembled OpenVPN configuration.
//! 6. Spawn `openvpn --config client.ovpn` and capture stdout/stderr until
//!    "Initialization Sequence Completed" appears (or the process exits with
//!    an error), with a 60-second timeout.
//! 7. Configure `systemd-resolved` DNS if `dns_servers` is non-empty.
//!
//! # Disconnect
//!
//! Kill the openvpn child, delete the temp directory, revert DNS.

use std::{
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use supermgr_core::{
    vpn::backend::{BackendStatus, Capabilities, VpnBackend},
    error::BackendError,
    vpn::profile::{AzureVpnConfig, Profile, ProfileConfig},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum time to wait for the user to complete browser auth (device code
/// expiry is usually 15 minutes; we give them 20 to be safe).
const AUTH_TIMEOUT_SECS: u64 = 20 * 60;

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct AzState {
    /// openvpn3 session D-Bus path (e.g. `/net/openvpn/v3/sessions/<id>`),
    /// used to disconnect via `openvpn3 session-manage --disconnect --path`.
    session_path: Option<String>,
    /// Temporary directory holding config/key files.
    tmp_dir: Option<PathBuf>,
    /// systemd-resolved interface index; set when DNS was configured.
    dns_configured_ifindex: Option<i32>,
    /// Kernel interface name opened by openvpn3 (e.g. `tun0`).
    interface: Option<String>,
    /// Virtual IP assigned to this client by the VPN (e.g. `10.134.2.3`).
    virtual_ip: String,
    /// Routes pushed by the server and installed in the kernel.
    active_routes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Backend struct
// ---------------------------------------------------------------------------

/// Azure P2S VPN backend.
pub struct AzureBackend {
    state: Arc<Mutex<AzState>>,
    /// Sender used to relay auth-challenge info to the daemon's D-Bus relay task.
    auth_tx: tokio::sync::mpsc::UnboundedSender<(String, String)>,
}

impl AzureBackend {
    /// Create a new backend.  `auth_tx` receives `(user_code, verification_url)`
    /// when the device-code flow needs the user to authenticate.
    #[must_use]
    pub fn new(auth_tx: tokio::sync::mpsc::UnboundedSender<(String, String)>) -> Self {
        Self {
            state: Arc::new(Mutex::new(AzState::default())),
            auth_tx,
        }
    }
}

// ---------------------------------------------------------------------------
// OAuth2 helpers  (PKCE authorization-code flow)
// ---------------------------------------------------------------------------
//
// The official Microsoft Azure VPN Client for Linux uses:
//   • client_id  = <audience from azurevpnconfig.xml>   (the app is its own client)
//   • scope      = <audience>/.default openid offline_access profile
//   • flow        = PKCE authorization-code, redirect_uri = http://localhost:2023
//
// Device-code flow causes AADSTS650057 because none of the other Azure VPN
// client app registrations have the VPN gateway resource in their permissions.
// Using the audience GUID as the client_id resolves this.

/// Label used to cache the refresh token in the secrets store.
fn refresh_token_label(profile_id: &uuid::Uuid) -> String {
    format!("supermgr/azure/{}/refresh_token", profile_id.simple())
}

/// Percent-encode a single OAuth2 query-parameter value.
///
/// Encodes `/` → `%2F` and space → `+`; leaves everything else as-is (GUIDs,
/// dots, hyphens and alphanumerics are all safe in query values).
fn encode_param(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '/' => out.push_str("%2F"),
            ' ' => out.push('+'),
            c => out.push(c),
        }
    }
    out
}

/// Minimal percent-decode for the OAuth2 redirect callback query string.
fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(hex) = u8::from_str_radix(
                std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
                out.push(hex as char);
                i += 3;
                continue;
            }
        } else if b[i] == b'+' {
            out.push(' ');
            i += 1;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Perform the OAuth2 PKCE authorization-code flow.
///
/// 1. Generates a PKCE `code_verifier` and `code_challenge` (S256).
/// 2. Starts a local HTTP server on `http://localhost:2023` to receive the
///    redirect callback.
/// 3. Opens the system browser pointing at the Entra ID authorization endpoint.
/// 4. Waits for the callback, then exchanges the code for tokens.
///
/// Returns `(access_token, refresh_token_opt)`.
async fn pkce_auth_code_flow(
    tenant_id: &str,
    audience: &str,
    auth_tx: &tokio::sync::mpsc::UnboundedSender<(String, String)>,
) -> Result<(String, Option<String>), BackendError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use sha2::Digest as _;

    // ── PKCE ─────────────────────────────────────────────────────────────────
    // code_verifier: two random UUIDs concatenated → 32 bytes of entropy,
    // base64url-encoded (no padding).
    let u1 = uuid::Uuid::new_v4();
    let u2 = uuid::Uuid::new_v4();
    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[..16].copy_from_slice(u1.as_bytes());
    verifier_bytes[16..].copy_from_slice(u2.as_bytes());
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    // code_challenge = BASE64URL(SHA-256(code_verifier))
    let code_challenge =
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(code_verifier.as_bytes()));

    let state = uuid::Uuid::new_v4().to_string();
    let scope = format!("{audience}/.default openid offline_access profile");

    // ── Authorization URL ────────────────────────────────────────────────────
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
        scope_enc = encode_param(&scope),
    );

    // ── Local redirect listener ───────────────────────────────────────────────
    // Bind BEFORE opening the browser to avoid losing the redirect.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:2023")
        .await
        .map_err(|e| {
            BackendError::Interface(format!(
                "cannot listen on localhost:2023 for OAuth2 callback: {e}"
            ))
        })?;

    // Send the URL to the GUI via D-Bus auth_challenge so it can open the
    // browser on behalf of the daemon (which has no display access).
    // Empty user_code signals PKCE flow (no code to enter manually).
    info!("Azure: sending browser auth URL to GUI");
    let _ = auth_tx.send(("".to_string(), auth_url.clone()));

    // ── Wait for the redirect callback ────────────────────────────────────────
    let code = tokio::time::timeout(
        std::time::Duration::from_secs(AUTH_TIMEOUT_SECS),
        accept_auth_code(listener, &state),
    )
    .await
    .map_err(|_| {
        BackendError::ConnectionFailed(
            "Entra ID browser authentication timed out after 20 minutes — \
             please reconnect and complete the sign-in promptly when the \
             browser window opens"
                .into(),
        )
    })?
    .map_err(|e| BackendError::ConnectionFailed(format!("auth redirect error: {e}")))?;

    info!("Azure: authorization code received, exchanging for tokens");

    // ── Token exchange ────────────────────────────────────────────────────────
    let client = reqwest::Client::new();
    let token_url =
        format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");

    let resp = client
        .post(&token_url)
        .form(&[
            ("client_id", audience),
            ("client_info", "1"),
            ("code", code.as_str()),
            ("code_verifier", code_verifier.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", "http://localhost:2023"),
            ("scope", scope.as_str()),
        ])
        .send()
        .await
        .map_err(|e| BackendError::Interface(format!("token exchange request failed: {e}")))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| BackendError::Interface(format!("token exchange response parse: {e}")))?;

    if let Some(access) = body["access_token"].as_str() {
        info!("Azure: access token obtained via PKCE authorization-code flow");
        let refresh = body["refresh_token"].as_str().map(str::to_owned);
        return Ok((access.to_owned(), refresh));
    }

    let err = body["error"].as_str().unwrap_or("unknown");
    let desc = body["error_description"].as_str().unwrap_or(err);
    Err(BackendError::ConnectionFailed(format!(
        "token exchange failed: {desc}"
    )))
}

/// Accept exactly one HTTP connection on `listener`, parse the OAuth2
/// `code` and `state` query parameters, send a "you may close this window"
/// HTML response, and return the code.
async fn accept_auth_code(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (stream, _) = listener
        .accept()
        .await
        .map_err(|e| format!("accept failed: {e}"))?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    // Read only the request line; we don't need headers.
    let request_line = lines
        .next_line()
        .await
        .map_err(|e| format!("read failed: {e}"))?
        .ok_or_else(|| "empty HTTP request".to_string())?;

    // Always send a friendly response so the browser shows something.
    let html = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "Connection: close\r\n\r\n",
        "<html><head><title>Super Manager</title></head><body>",
        "<h2>Authentication complete</h2>",
        "<p>You may close this tab and return to Super Manager.</p>",
        "</body></html>\r\n",
    );
    let _ = writer.write_all(html.as_bytes()).await;

    // Parse "GET /?code=XXX&state=YYY HTTP/1.1"
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

    code.ok_or_else(|| "no authorization code in redirect".to_string())
}

/// Try to silently refresh the access token using a cached refresh token.
///
/// Returns `(access_token, new_refresh_token)` on success.
async fn try_refresh_token(
    tenant_id: &str,
    audience: &str,
    refresh_token: &str,
) -> Result<(String, String), BackendError> {
    let client = reqwest::Client::new();
    let token_url =
        format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let scope = format!("{audience}/.default openid offline_access profile");

    let resp = client
        .post(&token_url)
        .form(&[
            ("client_id", audience),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("scope", scope.as_str()),
        ])
        .send()
        .await
        .map_err(|e| BackendError::Interface(format!("token refresh request failed: {e}")))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| BackendError::Interface(format!("token refresh response parse: {e}")))?;

    if let (Some(access), Some(refresh)) = (
        body["access_token"].as_str(),
        body["refresh_token"].as_str(),
    ) {
        info!("Azure: silent token refresh succeeded");
        return Ok((access.to_owned(), refresh.to_owned()));
    }

    let err = body["error"].as_str().unwrap_or("unknown");
    let desc = body["error_description"].as_str().unwrap_or(err);
    Err(BackendError::ConnectionFailed(format!(
        "token refresh failed: {desc}"
    )))
}

/// Obtain a valid access token, using the cached refresh token if available
/// and falling back to the full PKCE browser flow otherwise.
async fn authenticate(
    profile_id: &uuid::Uuid,
    tenant_id: &str,
    audience: &str,
    auth_tx: &tokio::sync::mpsc::UnboundedSender<(String, String)>,
) -> Result<String, BackendError> {
    let label = refresh_token_label(profile_id);

    let cached_rt = crate::secrets::retrieve_secret(&label)
        .await
        .ok()
        .and_then(|b| String::from_utf8(b).ok());

    if let Some(rt) = cached_rt {
        info!("Azure: trying cached refresh token");
        match try_refresh_token(tenant_id, audience, &rt).await {
            Ok((access, new_rt)) => {
                if let Err(e) = crate::secrets::store_secret(&label, new_rt.as_bytes()).await {
                    warn!("Azure: failed to update cached refresh token: {e}");
                }
                return Ok(access);
            }
            Err(e) => {
                warn!("Azure: cached refresh token failed ({e}), falling back to browser auth");
            }
        }
    }

    let (access, refresh_opt) = pkce_auth_code_flow(tenant_id, audience, auth_tx).await?;

    if let Some(rt) = refresh_opt {
        if let Err(e) = crate::secrets::store_secret(&label, rt.as_bytes()).await {
            warn!("Azure: failed to cache refresh token: {e}");
        } else {
            info!("Azure: refresh token cached for future connects");
        }
    }

    Ok(access)
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

/// Extract the UPN (user principal name) from a JWT access token.
///
/// Tries `upn` first (corporate tenants), then `preferred_username`
/// (consumer / personal accounts), then returns `"AzureAD"` as a fallback
/// (openvpn accepts any non-empty username when the real auth is the token).
fn jwt_upn(token: &str) -> String {
    let maybe = (|| -> Option<String> {
        let payload = token.split('.').nth(1)?;
        let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
        v["upn"]
            .as_str()
            .or_else(|| v["preferred_username"].as_str())
            .map(str::to_owned)
    })();
    maybe.unwrap_or_else(|| "AzureAD".to_owned())
}

// ---------------------------------------------------------------------------
// File-generation helpers
// ---------------------------------------------------------------------------

/// Convert the 512-hex-char `server_secret_hex` to the OpenVPN static key
/// file format (16 lines × 32 hex chars, wrapped in PEM-like header/footer).
fn hex_to_openvpn_key(hex: &str) -> String {
    let mut out = String::from("-----BEGIN OpenVPN Static key V1-----\n");
    for chunk in hex.as_bytes().chunks(32) {
        // SAFETY: chunks of ASCII hex bytes are valid UTF-8.
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END OpenVPN Static key V1-----\n");
    out
}

/// Assemble the `.ovpn` configuration text.
///
/// `auth-user-pass` is emitted without a path: openvpn3 prompts for the
/// username and password interactively, and we feed them via stdin.
fn build_ovpn_config(
    cfg: &AzureVpnConfig,
    _ca_path: &str,
    key_path: &str,
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
         verb 3\n\
         <ca>\n",
        fqdn = cfg.gateway_fqdn,
    );

    // Inline the CA cert rather than referencing the file path so the temp
    // file can be cleaned up after openvpn3 has started without breaking TLS.
    s.push_str(&cfg.ca_cert_pem);
    if !cfg.ca_cert_pem.ends_with('\n') {
        s.push('\n');
    }
    s.push_str("</ca>\n");

    s.push_str("auth-user-pass\n");
    s.push_str(&format!("tls-auth {key_path} 1\n"));

    // Routing decision matrix:
    //   full_tunnel=true                 → redirect-gateway, ignore route list
    //                                      (the user explicitly asked for "all
    //                                      traffic over VPN").
    //   full_tunnel=false, routes given  → push only those routes; LAN +
    //                                      internet stay on the local link.
    //   full_tunnel=false, routes empty  → push nothing locally; rely on
    //                                      whatever the gateway pushes via
    //                                      `push "route ..."`.  Do NOT silently
    //                                      promote to full-tunnel: Azure
    //                                      gateways don't NAT egress and the
    //                                      result is "VPN connected, internet
    //                                      dies" with no explanation.
    if full_tunnel {
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

    // Avoid overwriting the default route for DNS when using split tunnel.
    if !cfg.dns_servers.is_empty() {
        s.push_str("dhcp-option DNS ");
        s.push_str(&cfg.dns_servers.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(" "));
        s.push('\n');
    }

    s
}

// ---------------------------------------------------------------------------
// DNS helper (reused from fortigate backend pattern)
// ---------------------------------------------------------------------------

async fn configure_dns_for_link(iface_name: &str, dns_servers: &[IpAddr]) -> Option<i32> {
    if dns_servers.is_empty() {
        return None;
    }

    let ifindex: i32 = match nix::net::if_::if_nametoindex(iface_name) {
        Ok(idx) => idx as i32,
        Err(e) => {
            error!("Azure DNS: if_nametoindex({iface_name}): {e}");
            return None;
        }
    };

    let dns_addrs: Vec<(i32, Vec<u8>)> = dns_servers
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v4) => (2_i32, v4.octets().to_vec()),
            IpAddr::V6(v6) => (10_i32, v6.octets().to_vec()),
        })
        .collect();

    let conn = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            error!("Azure DNS: D-Bus connect: {e}");
            return None;
        }
    };
    let proxy = match zbus::Proxy::new(
        &conn,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            error!("Azure DNS: resolve1 proxy: {e}");
            return None;
        }
    };

    let domains: Vec<(String, bool)> = vec![("~.".to_owned(), true)];

    if let Err(e) = proxy.call_method("SetLinkDNS", &(ifindex, &dns_addrs)).await {
        error!("Azure DNS: SetLinkDNS({iface_name}): {e}");
        return None;
    }
    info!("Azure DNS: SetLinkDNS({iface_name}, {} servers) — ok", dns_addrs.len());

    if let Err(e) = proxy.call_method("SetLinkDomains", &(ifindex, &domains)).await {
        warn!("Azure DNS: SetLinkDomains({iface_name}): {e}");
    }

    Some(ifindex)
}

async fn revert_link_dns(ifindex: i32) {
    let Ok(conn) = zbus::Connection::system().await else { return };
    let Ok(proxy) = zbus::Proxy::new(
        &conn,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .await
    else {
        return;
    };
    match proxy.call_method("RevertLink", &(ifindex,)).await {
        Ok(_) => info!("Azure DNS: RevertLink(ifindex={ifindex}) — ok"),
        Err(e) => warn!("Azure DNS: RevertLink(ifindex={ifindex}): {e}"),
    }
}

// ---------------------------------------------------------------------------
// VpnBackend implementation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// openvpn3 session helpers
// ---------------------------------------------------------------------------

/// One row of `openvpn3 sessions-list`.
struct OpenVpn3Session {
    /// D-Bus path, e.g. `/net/openvpn/v3/sessions/<id>`.
    path: String,
    /// Kernel device name, e.g. `tun0`.
    device: String,
    /// Path to the .ovpn config file the session was started from.
    /// Field label varies by openvpn3 version: v27 prints `Config name:`,
    /// older versions printed `Session name:`.
    config_name: String,
    /// `tcp:<ip>:<port>` style remote.  v27 prints `Connected to:` for active
    /// sessions; absent for sessions still in the connecting phase.
    connected_to: String,
}

/// Run `openvpn3 sessions-list` and parse all active sessions.
///
/// The v27 output looks like:
/// ```text
/// -----------------------------------------------------------------------------
///         Path: /net/openvpn/v3/sessions/<id>
///      Created: <date>            PID: <pid>
///        Owner: root                  Device: tun0
///  Config name: /run/supermgrd/azure-<uuid>/client.ovpn  (Config not available)
/// Connected to: tcp:104.214.227.71:443
///       Status: Connection, Client connected
/// -----------------------------------------------------------------------------
/// ```
async fn list_openvpn3_sessions() -> Vec<OpenVpn3Session> {
    let out = match tokio::process::Command::new("openvpn3")
        .arg("sessions-list")
        .output()
        .await
    {
        Ok(o) if o.status.success() => o,
        Ok(_) | Err(_) => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&out.stdout);
    let mut sessions = Vec::new();
    let mut cur: Option<OpenVpn3Session> = None;

    let flush = |cur: &mut Option<OpenVpn3Session>, sessions: &mut Vec<OpenVpn3Session>| {
        if let Some(s) = cur.take() {
            if !s.path.is_empty() {
                sessions.push(s);
            }
        }
    };

    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("Path:") {
            flush(&mut cur, &mut sessions);
            cur = Some(OpenVpn3Session {
                path: rest.trim().to_string(),
                device: String::new(),
                config_name: String::new(),
                connected_to: String::new(),
            });
            continue;
        }
        let Some(s) = cur.as_mut() else { continue };
        if let Some(idx) = trimmed.find("Device:") {
            // `Device:` shares a line with `Owner:` in v27 — skip past the marker.
            s.device = trimmed[idx + "Device:".len()..].trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("Config name:") {
            // v27 strips the trailing "(Config not available)" annotation.
            let val = rest.trim();
            let val = val.split_whitespace().next().unwrap_or(val);
            s.config_name = val.to_string();
        } else if let Some(rest) = trimmed.strip_prefix("Session name:") {
            // Older openvpn3 versions used this label for the same field.
            if s.config_name.is_empty() {
                s.config_name = rest.trim().to_string();
            }
        } else if let Some(rest) = trimmed.strip_prefix("Connected to:") {
            s.connected_to = rest.trim().to_string();
        }
    }
    flush(&mut cur, &mut sessions);
    sessions
}

/// Find the session that was started from `ovpn_path`.
///
/// Polls for up to 5 s — on a fresh `session-start` the session can take a
/// moment to register with the session manager and acquire its tun device.
async fn find_openvpn3_session_for_config(ovpn_path: &std::path::Path) -> Option<OpenVpn3Session> {
    let target = ovpn_path.to_string_lossy().into_owned();
    for _ in 0..10 {
        for s in list_openvpn3_sessions().await {
            if s.config_name == target && !s.device.is_empty() {
                return Some(s);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    None
}

/// Disconnect a single openvpn3 session by D-Bus path.
async fn disconnect_openvpn3_session(path: &str) {
    let out = tokio::process::Command::new("openvpn3")
        .arg("session-manage")
        .arg("--disconnect")
        .arg("--path")
        .arg(path)
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            warn!(
                "openvpn3 session-manage --disconnect {path} failed: {}",
                stderr.trim()
            );
        }
        Err(e) => warn!("openvpn3 session-manage --disconnect {path}: {e}"),
    }
}

/// Read the first IPv4 address assigned to `iface` via `ip -4 addr show`.
async fn read_iface_ipv4(iface: &str) -> Option<String> {
    let out = tokio::process::Command::new("ip")
        .args(["-4", "addr", "show", "dev", iface])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            // `inet 10.134.2.3/24 brd 10.134.2.255 scope global tun0`
            let cidr = rest.split_whitespace().next()?;
            return Some(cidr.split('/').next()?.to_string());
        }
    }
    None
}

/// Read all routes installed on `iface` via `ip route show dev <iface>`.
async fn read_iface_routes(iface: &str) -> Vec<String> {
    let out = match tokio::process::Command::new("ip")
        .args(["route", "show", "dev", iface])
        .output()
        .await
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .filter(|net| net.contains('/') || net.contains('.'))
        .collect()
}

// ---------------------------------------------------------------------------
// VpnBackend impl
// ---------------------------------------------------------------------------

#[async_trait]
impl VpnBackend for AzureBackend {
    async fn connect(&self, profile: &Profile) -> Result<(), BackendError> {
        let cfg = match &profile.config {
            ProfileConfig::AzureVpn(c) => c,
            _ => return Err(BackendError::Interface("wrong profile type for AzureBackend".into())),
        };

        info!("Azure: connecting profile '{}' via openvpn3", profile.name);

        // ── Step 1: Authenticate (cached refresh token or PKCE) ─────────────
        let access_token =
            authenticate(&profile.id, &cfg.tenant_id, &cfg.client_id, &self.auth_tx)
                .await?;

        let upn = jwt_upn(&access_token);
        info!(
            "Azure: authenticated as '{upn}' (access token {} bytes)",
            access_token.len()
        );

        // ── Step 2: Write temporary files ────────────────────────────────────
        let tmp_dir = if nix::unistd::getuid().is_root() {
            PathBuf::from("/run/supermgrd").join(format!("azure-{}", profile.id.simple()))
        } else {
            std::env::temp_dir().join(format!("supermgrd-azure-{}", profile.id.simple()))
        };

        tokio::fs::create_dir_all(&tmp_dir).await.map_err(BackendError::Io)?;

        let key_path = tmp_dir.join("tls-auth.key");
        let ovpn_path = tmp_dir.join("client.ovpn");

        // tls-auth static key (direction 1, SHA256).  Tighten permissions —
        // this file embeds the gateway's pre-shared HMAC key, so even though
        // the daemon runs as root and `tmp_dir` is mode 0750, defense-in-
        // depth: belt + braces against an accidentally-permissive umask.
        tokio::fs::write(&key_path, hex_to_openvpn_key(&cfg.server_secret_hex))
            .await
            .map_err(BackendError::Io)?;
        tokio::fs::set_permissions(
            &key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .await
        .map_err(BackendError::Io)?;

        let ovpn_text = build_ovpn_config(
            cfg,
            "",
            &key_path.to_string_lossy(),
            profile.full_tunnel,
        );
        tokio::fs::write(&ovpn_path, &ovpn_text).await.map_err(BackendError::Io)?;

        info!("Azure: temp files written to {}", tmp_dir.display());

        // ── Step 3: Tear down stale openvpn3 sessions FROM THIS PROFILE ──────
        // A previous crash or interrupted connect can leave a session running
        // for the same profile (same tmp_dir).  Match by tmp_dir prefix so we
        // never touch unrelated openvpn3 sessions (other VPNs, manually-
        // imported configs, etc.).
        let tmp_dir_prefix = format!("{}/", tmp_dir.display());
        for stale in list_openvpn3_sessions().await {
            if stale.config_name.starts_with(&tmp_dir_prefix) {
                warn!(
                    "Azure: cleaning up stale openvpn3 session {} (config={})",
                    stale.path, stale.config_name
                );
                disconnect_openvpn3_session(&stale.path).await;
            }
        }

        // ── Step 4: Launch `openvpn3 session-start` with creds via stdin ─────
        // Username is the literal string "AzureAD" (Azure VPN gateway expects
        // this constant, not the UPN).  Password is the AAD access token JWT.
        // openvpn3 handles the large JWT cleanly — stock openvpn 2.x truncates
        // it at USER_PASS_LEN and produces "Key Method #2 write failed".
        let mut child = tokio::process::Command::new("openvpn3")
            .arg("session-start")
            .arg("--config").arg(&ovpn_path)
            .arg("--timeout").arg("30")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    BackendError::Interface(
                        "openvpn3 not found — install with: sudo dnf install openvpn3-client".into(),
                    )
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    BackendError::Interface(
                        "permission denied running openvpn3 — the daemon must run as root".into(),
                    )
                } else {
                    BackendError::Io(e)
                }
            })?;

        // Pipe credentials in the order openvpn3 prompts for them.
        {
            use tokio::io::AsyncWriteExt;
            let mut stdin = child.stdin.take().ok_or_else(|| {
                BackendError::Interface("openvpn3 stdin pipe unavailable".into())
            })?;
            let creds = format!("AzureAD\n{access_token}\n");
            stdin.write_all(creds.as_bytes()).await.map_err(BackendError::Io)?;
            stdin.flush().await.map_err(BackendError::Io)?;
            // Drop closes stdin — openvpn3 takes that as end of credentials.
        }

        // Wait for session-start to finish.  It returns once the connection
        // attempt is complete (success or failure within --timeout); the actual
        // tunnel keeps running in openvpn3-service-client.
        let output_result = tokio::time::timeout(
            std::time::Duration::from_secs(45),
            child.wait_with_output(),
        ).await;

        let output = match output_result {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
                return Err(BackendError::ConnectionFailed(format!(
                    "openvpn3 session-start failed: {e}"
                )));
            }
            Err(_timeout) => {
                let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
                return Err(BackendError::ConnectionFailed(
                    "Azure VPN connection timed out after 45 s — the gateway \
                     may be unreachable or firewalled; verify your network \
                     connection and the gateway address".into(),
                ));
            }
        };

        let stdout_text = String::from_utf8_lossy(&output.stdout);
        let stderr_text = String::from_utf8_lossy(&output.stderr);
        for line in stdout_text.lines() {
            if !line.trim().is_empty() {
                info!("openvpn3: {}", line.trim());
            }
        }
        for line in stderr_text.lines() {
            if !line.trim().is_empty() {
                info!("openvpn3 stderr: {}", line.trim());
            }
        }

        if !output.status.success() {
            let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
            // Common failure modes have specific signatures in the output.
            let combined = format!("{stdout_text}\n{stderr_text}");
            if combined.contains("AUTH_FAILED") || combined.to_lowercase().contains("auth failed") {
                return Err(BackendError::ConnectionFailed(
                    "Azure VPN authentication failed — your Entra ID session \
                     may have expired or been revoked; try reconnecting to \
                     re-authenticate in the browser".into(),
                ));
            }
            return Err(BackendError::ConnectionFailed(format!(
                "openvpn3 session-start exited with status {:?}",
                output.status.code(),
            )));
        }

        // ── Step 5: Find the session we just started, get the tun device ─────
        // Match by config-file path (we know it; uniquely identifies the
        // session we just started even if the user has other openvpn3 sessions
        // running for unrelated VPNs).
        let session = match find_openvpn3_session_for_config(&ovpn_path).await {
            Some(s) => s,
            None => {
                let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
                return Err(BackendError::ConnectionFailed(
                    "openvpn3 reports session-start succeeded but no matching \
                     active session was found in `openvpn3 sessions-list`".into(),
                ));
            }
        };
        info!(
            "Azure: openvpn3 session path={} device={} connected_to={}",
            session.path, session.device, session.connected_to
        );

        // ── Step 6: Discover virtual IP and routes from the tun device ───────
        let virtual_ip = read_iface_ipv4(&session.device).await.unwrap_or_default();
        let active_routes = read_iface_routes(&session.device).await;

        // ── Step 7: Configure DNS ────────────────────────────────────────────
        let dns_ifindex = configure_dns_for_link(&session.device, &cfg.dns_servers).await;

        // ── Step 8: Persist state ────────────────────────────────────────────
        {
            let mut st = self.state.lock().await;
            st.session_path = Some(session.path);
            st.tmp_dir = Some(tmp_dir);
            st.dns_configured_ifindex = dns_ifindex;
            st.interface = Some(session.device);
            st.virtual_ip = virtual_ip;
            st.active_routes = active_routes;
        }

        Ok(())
    }

    async fn disconnect(&self) -> Result<(), BackendError> {
        let (session_path_opt, tmp_dir_opt, dns_ifindex, _iface) = {
            let mut st = self.state.lock().await;
            (
                st.session_path.take(),
                st.tmp_dir.take(),
                st.dns_configured_ifindex.take(),
                st.interface.take(),
            )
        };

        // Revert DNS first (non-fatal).
        if let Some(ifindex) = dns_ifindex {
            revert_link_dns(ifindex).await;
        }

        if let Some(path) = session_path_opt {
            info!("Azure: disconnecting openvpn3 session {path}");
            disconnect_openvpn3_session(&path).await;
        }

        // Remove temp files.
        if let Some(dir) = tmp_dir_opt {
            if let Err(e) = tokio::fs::remove_dir_all(&dir).await {
                warn!("Azure: remove temp dir {}: {e}", dir.display());
            } else {
                info!("Azure: removed temp dir {}", dir.display());
            }
        }

        Ok(())
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let st = self.state.lock().await;

        let Some(ref _path) = st.session_path else {
            return Ok(BackendStatus::Inactive);
        };

        let iface = st.interface.clone().unwrap_or_default();
        let stats = super::read_iface_stats(&iface);
        Ok(BackendStatus::Active {
            interface: iface,
            stats,
            virtual_ip: st.virtual_ip.clone(),
            active_routes: st.active_routes.clone(),
        })
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            split_tunnel: true,
            full_tunnel: true,
            dns_push: true,
            persistent_keepalive: false,
            config_import: true,
        }
    }

    fn name(&self) -> &'static str {
        "Azure VPN (Entra ID)"
    }
}

