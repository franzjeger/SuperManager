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

/// Timeout waiting for openvpn to complete tunnel negotiation.
const OPENVPN_CONNECT_TIMEOUT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct AzState {
    /// Running openvpn child process.
    child: Option<tokio::process::Child>,
    /// Temporary directory holding config/key/credential files.
    tmp_dir: Option<PathBuf>,
    /// systemd-resolved interface index; set when DNS was configured.
    dns_configured_ifindex: Option<i32>,
    /// Kernel interface name opened by openvpn (e.g. `tun0`).
    interface: Option<String>,
    /// Virtual IP assigned to this client by the VPN (e.g. `10.134.2.3/24`).
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
fn build_ovpn_config(
    cfg: &AzureVpnConfig,
    _ca_path: &str,
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

    // Inline the CA cert rather than referencing the file path so the temp
    // file can be cleaned up after openvpn has started without breaking TLS.
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

#[async_trait]
impl VpnBackend for AzureBackend {
    async fn connect(&self, profile: &Profile) -> Result<(), BackendError> {
        let cfg = match &profile.config {
            ProfileConfig::AzureVpn(c) => c,
            _ => return Err(BackendError::Interface("wrong profile type for AzureBackend".into())),
        };

        info!("Azure: connecting profile '{}'", profile.name);

        // ── Step 1: Authenticate (cached refresh token or device-code flow) ──
        let access_token =
            authenticate(&profile.id, &cfg.tenant_id, &cfg.client_id, &self.auth_tx)
                .await?;

        let upn = jwt_upn(&access_token);
        info!("Azure: authenticated as '{upn}'");

        // ── Step 2: Write temporary files ────────────────────────────────────
        let tmp_dir = if nix::unistd::getuid().is_root() {
            PathBuf::from("/run/supermgrd").join(format!("azure-{}", profile.id.simple()))
        } else {
            std::env::temp_dir().join(format!("supermgrd-azure-{}", profile.id.simple()))
        };

        tokio::fs::create_dir_all(&tmp_dir).await.map_err(BackendError::Io)?;

        let key_path = tmp_dir.join("tls-auth.key");
        let auth_path = tmp_dir.join("auth.txt");
        let ovpn_path = tmp_dir.join("client.ovpn");

        // tls-auth static key (direction 1, SHA256)
        tokio::fs::write(&key_path, hex_to_openvpn_key(&cfg.server_secret_hex))
            .await
            .map_err(BackendError::Io)?;

        // auth-user-pass: <upn>\n<access_token>  (mode 0600 — openvpn warns otherwise)
        tokio::fs::write(&auth_path, format!("{upn}\n{access_token}\n"))
            .await
            .map_err(BackendError::Io)?;
        tokio::fs::set_permissions(
            &auth_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .await
        .map_err(BackendError::Io)?;

        // openvpn config
        let ovpn_text = build_ovpn_config(
            cfg,
            "",  // CA is inlined
            &key_path.to_string_lossy(),
            &auth_path.to_string_lossy(),
            profile.full_tunnel,
        );
        tokio::fs::write(&ovpn_path, &ovpn_text).await.map_err(BackendError::Io)?;

        info!(
            "Azure: temp files written to {}",
            tmp_dir.display()
        );

        // ── Step 3: Launch openvpn ────────────────────────────────────────────
        let mut child = tokio::process::Command::new("openvpn")
            .arg("--config")
            .arg(&ovpn_path)
            // The systemd unit uses PrivateTmp / ReadOnlyPaths so /tmp is
            // read-only; point openvpn at our already-writable run directory.
            .arg("--tmp-dir")
            .arg(&tmp_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    BackendError::Interface(
                        "openvpn not found — install the 'openvpn' package \
                         (Azure VPN requires the classic openvpn binary, not openvpn3)".into(),
                    )
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    BackendError::Interface(
                        "permission denied running openvpn — the daemon must run as root".into(),
                    )
                } else {
                    BackendError::Io(e)
                }
            })?;

        // ── Step 4: Wait for "Initialization Sequence Completed" ─────────────
        let stdout = child.stdout.take().ok_or_else(|| {
            BackendError::Interface("openvpn stdout pipe unavailable".into())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            BackendError::Interface("openvpn stderr pipe unavailable".into())
        })?;

        // Merge stdout + stderr into a single line stream.
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut out_lines = BufReader::new(stdout).lines();
        let mut err_lines = BufReader::new(stderr).lines();

        let mut interface: Option<String> = None;
        let mut virtual_ip = String::new();
        let mut active_routes: Vec<String> = Vec::new();
        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(OPENVPN_CONNECT_TIMEOUT_SECS),
            async {
                loop {
                    tokio::select! {
                        line = out_lines.next_line() => {
                            let Some(Some(line)) = line.ok().map(|l| l) else { break };
                            info!("openvpn: {}", line.trim());
                            if line.contains("TUN/TAP device") {
                                if let Some(iface) = extract_tun_iface(&line) {
                                    interface = Some(iface);
                                }
                            }
                            // "ip addr add dev tun0 10.134.2.3/24 broadcast +"
                            if let Some(ip) = extract_virtual_ip(&line) {
                                virtual_ip = ip;
                            }
                            // "ip route add 10.134.0.0/23 via 10.134.2.1"
                            if let Some(route) = extract_pushed_route(&line) {
                                if !active_routes.contains(&route) {
                                    active_routes.push(route);
                                }
                            }
                            if line.contains("Initialization Sequence Completed") {
                                return Ok(());
                            }
                            if line.contains("AUTH_FAILED") || line.contains("auth-failure") {
                                return Err(BackendError::ConnectionFailed(
                                    "Azure VPN authentication failed — your Entra ID session \
                                     may have expired or been revoked; try reconnecting to \
                                     re-authenticate in the browser".into(),
                                ));
                            }
                        }
                        line = err_lines.next_line() => {
                            let Some(Some(line)) = line.ok().map(|l| l) else { break };
                            info!("openvpn stderr: {}", line.trim());
                            if line.contains("Initialization Sequence Completed") {
                                return Ok(());
                            }
                        }
                    }
                }
                Err(BackendError::ConnectionFailed(
                    "openvpn process exited before the tunnel was established — \
                     check that the Azure VPN gateway is reachable and the \
                     configuration (CA cert, gateway FQDN) is correct".into(),
                ))
            },
        )
        .await;

        match connect_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill().await;
                drop(child);
                let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
                return Err(e);
            }
            Err(_timeout) => {
                let _ = child.kill().await;
                drop(child);
                let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
                return Err(BackendError::ConnectionFailed(
                    "Azure VPN connection timed out after 60 s — the gateway \
                     may be unreachable or firewalled; verify your network \
                     connection and the gateway address".into(),
                ));
            }
        }

        info!("Azure: tunnel established (interface: {:?})", interface);

        // ── Step 5: Configure DNS ─────────────────────────────────────────────
        let dns_ifindex = if let Some(ref iface) = interface {
            configure_dns_for_link(iface, &cfg.dns_servers).await
        } else {
            None
        };

        // ── Step 6: Persist state ─────────────────────────────────────────────
        {
            let mut st = self.state.lock().await;
            st.child = Some(child);
            st.tmp_dir = Some(tmp_dir);
            st.dns_configured_ifindex = dns_ifindex;
            st.interface = interface;
            st.virtual_ip = virtual_ip;
            st.active_routes = active_routes;
        }

        Ok(())
    }

    async fn disconnect(&self) -> Result<(), BackendError> {
        let (child_opt, tmp_dir_opt, dns_ifindex, _iface) = {
            let mut st = self.state.lock().await;
            (
                st.child.take(),
                st.tmp_dir.take(),
                st.dns_configured_ifindex.take(),
                st.interface.take(),
            )
        };

        // Revert DNS first (non-fatal).
        if let Some(ifindex) = dns_ifindex {
            revert_link_dns(ifindex).await;
        }

        // Kill the openvpn process.
        if let Some(mut child) = child_opt {
            info!("Azure: killing openvpn child");
            if let Err(e) = child.kill().await {
                warn!("Azure: kill openvpn: {e}");
            }
            // Reap to avoid zombie.
            let _ = child.wait().await;
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
        let mut st = self.state.lock().await;

        let Some(child) = st.child.as_mut() else {
            return Ok(BackendStatus::Inactive);
        };

        // Non-blocking check: did the process exit?
        match child.try_wait().map_err(BackendError::Io)? {
            Some(exit) => {
                warn!("Azure: openvpn exited unexpectedly: {exit}");
                Ok(BackendStatus::Inactive)
            }
            None => {
                let iface = st.interface.clone().unwrap_or_default();
                let stats = super::read_iface_stats(&iface);
                Ok(BackendStatus::Active {
                    interface: iface,
                    stats,
                    virtual_ip: st.virtual_ip.clone(),
                    active_routes: st.active_routes.clone(),
                })
            }
        }
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the tun interface name from an openvpn log line such as:
/// `TUN/TAP device tun0 opened`
fn extract_tun_iface(line: &str) -> Option<String> {
    let prefix = "TUN/TAP device ";
    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let name = rest[..end].trim().to_owned();
    if name.is_empty() { None } else { Some(name) }
}

/// Parse the virtual IP from an openvpn log line such as:
/// `/usr/bin/ip addr add dev tun0 10.134.2.3/24 broadcast +`
fn extract_virtual_ip(line: &str) -> Option<String> {
    // Look for "ip addr add dev <iface> <cidr>"
    let idx = line.find("ip addr add dev ")?;
    let rest = &line[idx + "ip addr add dev ".len()..];
    // Skip the interface name.
    let rest = rest.splitn(2, ' ').nth(1)?.trim();
    // Take the CIDR token (stops at space or end).
    let cidr = rest.split_whitespace().next()?;
    // Validate it looks like a CIDR.
    if cidr.contains('.') || cidr.contains(':') {
        Some(cidr.to_owned())
    } else {
        None
    }
}

/// Parse a pushed route from an openvpn log line such as:
/// `/usr/bin/ip route add 10.134.0.0/23 via 10.134.2.1`
fn extract_pushed_route(line: &str) -> Option<String> {
    let idx = line.find("ip route add ")?;
    let rest = &line[idx + "ip route add ".len()..];
    // The destination is the first token.
    let dest = rest.split_whitespace().next()?;
    if dest.contains('.') || dest.contains(':') {
        Some(dest.to_owned())
    } else {
        None
    }
}
