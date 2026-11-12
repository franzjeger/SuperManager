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

use std::{net::IpAddr, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use supermgr_core::{
    error::BackendError,
    vpn::backend::{BackendStatus, Capabilities, VpnBackend},
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
///
/// Defined in `supermgr_core::secret_lifecycle` rather than here because
/// nothing points a `SecretRef` at it: the profile delete path can only
/// clear this credential if it can derive the label, so the definition has
/// to live where deletion can see it.
use supermgr_core::secret_lifecycle::azure_refresh_token_label as refresh_token_label;

/// RFC-3986 percent-encode a single OAuth2 query-parameter value.
///
/// Leaves unreserved bytes `[A-Za-z0-9._~-]` verbatim and encodes every other
/// byte as uppercase `%XX`.
fn encode_param(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 16);
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Percent-decode an OAuth2 redirect callback query parameter as UTF-8.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut bytes = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(hex_str) = std::str::from_utf8(&b[i + 1..i + 3]) {
                if let Ok(decoded_byte) = u8::from_str_radix(hex_str, 16) {
                    bytes.push(decoded_byte);
                    i += 3;
                    continue;
                }
            }
        } else if b[i] == b'+' {
            bytes.push(b' ');
            i += 1;
            continue;
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
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
    let code_challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(code_verifier.as_bytes()));

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
    let token_url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");

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

/// Accept HTTP connections on `listener` until the OAuth2 redirect callback
/// arrives, ignoring browser TCP preconnects and `/favicon.ico` probes, verify
/// `state` against `expected_state`, send a response, and return `code`.
async fn accept_auth_code(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("accept failed: {e}"))?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();

        // Read the request line with a short timeout so an idle speculative TCP
        // preconnect socket cannot block the real redirect connection behind it.
        let request_line = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            lines.next_line(),
        )
        .await
        {
            Ok(Ok(Some(line))) if !line.trim().is_empty() => line,
            // 0-byte browser TCP preconnect close, read error, or idle socket.
            _ => continue,
        };

        // Parse "GET /?code=XXX&state=YYY HTTP/1.1"
        let Some(path) = request_line.split_whitespace().nth(1) else {
            let bad = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = writer.write_all(bad.as_bytes()).await;
            let _ = writer.shutdown().await;
            continue;
        };

        let (route, query) = path.split_once('?').unwrap_or((path, ""));

        // Ignore `/favicon.ico` and any other non-root browser probe.
        if route != "/" && !route.is_empty() {
            let not_found =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = writer.write_all(not_found.as_bytes()).await;
            let _ = writer.shutdown().await;
            continue;
        }

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

        if returned_state.as_deref() != Some(expected_state) {
            let bad = concat!(
                "HTTP/1.1 400 Bad Request\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "Connection: close\r\n\r\n",
                "OAuth2 state mismatch.\r\n",
            );
            let _ = writer.write_all(bad.as_bytes()).await;
            let _ = writer.shutdown().await;
            return Err("OAuth2 state mismatch — possible CSRF".to_string());
        }

        if let Some(e) = error_desc {
            let bad = concat!(
                "HTTP/1.1 400 Bad Request\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "Connection: close\r\n\r\n",
                "Authentication failed.\r\n",
            );
            let _ = writer.write_all(bad.as_bytes()).await;
            let _ = writer.shutdown().await;
            return Err(e);
        }

        let Some(code) = code.filter(|c| !c.is_empty()) else {
            let bad = concat!(
                "HTTP/1.1 400 Bad Request\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "Connection: close\r\n\r\n",
                "Missing authorization code.\r\n",
            );
            let _ = writer.write_all(bad.as_bytes()).await;
            let _ = writer.shutdown().await;
            return Err("no authorization code in redirect".to_string());
        };

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
        let _ = writer.shutdown().await;

        return Ok(code);
    }
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
    let token_url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let scope = format!("{audience}/.default openid offline_access profile");

    let resp = client
        .post(&token_url)
        .form(&[
            ("client_id", audience),
            ("client_info", "1"),
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
            .filter(|s| !s.is_empty() && !s.chars().any(char::is_control))
            .map(str::to_owned)
    })();
    maybe.unwrap_or_else(|| "AzureAD".to_owned())
}

// ---------------------------------------------------------------------------
// File-generation helpers
// ---------------------------------------------------------------------------

/// Validate untrusted fields on [`AzureVpnConfig`] before initiating OAuth or
/// rendering an OpenVPN configuration file.
fn validate_azure_config(cfg: &AzureVpnConfig) -> Result<(), BackendError> {
    supermgr_core::sanitize::validate_host_or_ip(&cfg.gateway_fqdn)
        .map_err(|e| BackendError::Config(format!("invalid Azure gateway FQDN: {e}")))?;
    supermgr_core::sanitize::validate_safe_ident(&cfg.tenant_id, "tenant_id")
        .map_err(|e| BackendError::Config(format!("invalid Azure tenant_id: {e}")))?;
    supermgr_core::sanitize::validate_safe_ident(&cfg.client_id, "client_id")
        .map_err(|e| BackendError::Config(format!("invalid Azure client_id: {e}")))?;
    if cfg.ca_cert_pem.to_ascii_lowercase().contains("</ca>") {
        return Err(BackendError::Config(
            "invalid Azure CA certificate: unexpected closing </ca> tag".into(),
        ));
    }
    Ok(())
}

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
) -> Result<String, BackendError> {
    validate_azure_config(cfg)?;
    if key_path.chars().any(char::is_control) || auth_path.chars().any(char::is_control) {
        return Err(BackendError::Config(
            "OpenVPN credential/key path contains control characters".into(),
        ));
    }

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
    //
    // Profiles imported before the import fell back to the DigiCert roots
    // hold no certificate at all (`azurevpnconfig.xml` pins the root by
    // thumbprint only). An empty `<ca>` is fatal to openvpn ("Cannot load CA
    // certificate file [[INLINE]] (no entries were read)"), so they get the
    // same roots a fresh import would.
    let ca_pem = if cfg.ca_cert_pem.contains("-----BEGIN CERTIFICATE-----") {
        cfg.ca_cert_pem.as_str()
    } else {
        supermgr_core::vpn::import::AZURE_DEFAULT_CA_PEM
    };
    s.push_str(ca_pem);
    if !ca_pem.ends_with('\n') {
        s.push('\n');
    }
    s.push_str("</ca>\n");

    s.push_str(&format!("auth-user-pass {auth_path}\n"));
    s.push_str(&format!("tls-auth {key_path} 1\n"));

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
        s.push_str(
            &cfg.dns_servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
        s.push('\n');
    }

    Ok(s)
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

    if let Err(e) = proxy
        .call_method("SetLinkDNS", &(ifindex, &dns_addrs))
        .await
    {
        error!("Azure DNS: SetLinkDNS({iface_name}): {e}");
        return None;
    }
    info!(
        "Azure DNS: SetLinkDNS({iface_name}, {} servers) — ok",
        dns_addrs.len()
    );

    if let Err(e) = proxy
        .call_method("SetLinkDomains", &(ifindex, &domains))
        .await
    {
        warn!("Azure DNS: SetLinkDomains({iface_name}): {e}");
    }

    Some(ifindex)
}

async fn revert_link_dns(ifindex: i32) {
    let Ok(conn) = zbus::Connection::system().await else {
        return;
    };
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
            _ => {
                return Err(BackendError::Interface(
                    "wrong profile type for AzureBackend".into(),
                ))
            }
        };

        validate_azure_config(cfg)?;

        info!("Azure: connecting profile '{}'", profile.name);

        // ── Step 1: Authenticate (cached refresh token or device-code flow) ──
        let access_token =
            authenticate(&profile.id, &cfg.tenant_id, &cfg.client_id, &self.auth_tx).await?;

        let upn = jwt_upn(&access_token);
        info!("Azure: authenticated as '{upn}'");

        // ── Step 2: Write temporary files ────────────────────────────────────
        let tmp_dir = if nix::unistd::getuid().is_root() {
            PathBuf::from("/run/supermgrd").join(format!("azure-{}", profile.id.simple()))
        } else {
            std::env::temp_dir().join(format!("supermgrd-azure-{}", profile.id.simple()))
        };

        // 0700: only this daemon and the `openvpn` it spawns as itself need
        // to get in. The directory used to come from `create_dir_all`, which
        // gives 0755 under the usual umask and succeeds just as happily on a
        // directory somebody else created first.
        crate::secure_file::ensure_private_dir(&tmp_dir, 0o700).map_err(BackendError::Io)?;

        let key_path = tmp_dir.join("tls-auth.key");
        let auth_path = tmp_dir.join("auth.txt");
        let ovpn_path = tmp_dir.join("client.ovpn");

        // tls-auth static key (direction 1, SHA256). A shared secret: with it
        // the TLS control channel can be forged. It was written at the umask
        // — 0644 — and kept private only by the mode of the directory above
        // it, whose profile-UUID name is listable over the bus.
        crate::secure_file::write_private(
            &key_path,
            hex_to_openvpn_key(&cfg.server_secret_hex).as_bytes(),
            None,
        )
        .map_err(BackendError::Io)?;

        // auth-user-pass: <upn>\n<access_token>. This was chmod'd to 0600,
        // but only after the write had finished — the Entra access token was
        // world-readable for the length of it.
        crate::secure_file::write_private(
            &auth_path,
            format!("{upn}\n{access_token}\n").as_bytes(),
            None,
        )
        .map_err(BackendError::Io)?;

        // openvpn config
        let ovpn_text = build_ovpn_config(
            cfg,
            "",
            &key_path.to_string_lossy(),
            &auth_path.to_string_lossy(),
            profile.full_tunnel,
        )?;
        // No secret of its own — the CA cert it inlines is public and the
        // credentials are referenced by path — but it names those paths, and
        // there is no reason for it to be the one file here anyone can read.
        crate::secure_file::write_private(&ovpn_path, ovpn_text.as_bytes(), None)
            .map_err(BackendError::Io)?;

        info!("Azure: temp files written to {}", tmp_dir.display());

        // ── Step 3: Launch openvpn ────────────────────────────────────────────
        let openvpn_bin = crate::subprocess::resolve_system_bin(&["openvpn"]).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BackendError::Interface(
                    "openvpn not found — install the 'openvpn' package \
                     (Azure VPN requires the classic openvpn binary, not openvpn3)"
                        .into(),
                )
            } else {
                BackendError::Io(e)
            }
        })?;
        let mut child = tokio::process::Command::new(&openvpn_bin)
            .env("PATH", "/usr/sbin:/sbin:/usr/bin:/bin")
            .arg("--config")
            .arg(&ovpn_path)
            .arg("--script-security")
            .arg("1")
            // The systemd unit uses PrivateTmp / ReadOnlyPaths so /tmp is
            // read-only; point openvpn at our already-writable run directory.
            .arg("--tmp-dir")
            .arg(&tmp_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    BackendError::Interface(
                        "openvpn not found — install the 'openvpn' package \
                         (Azure VPN requires the classic openvpn binary, not openvpn3)"
                            .into(),
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
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BackendError::Interface("openvpn stdout pipe unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BackendError::Interface("openvpn stderr pipe unavailable".into()))?;

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
                            let Some(Some(line)) = line.ok() else { break };
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
                            let Some(Some(line)) = line.ok() else { break };
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
                     configuration (CA cert, gateway FQDN) is correct"
                        .into(),
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
                     connection and the gateway address"
                        .into(),
                ));
            }
        }

        info!("Azure: tunnel established (interface: {:?})", interface);

        // ── Step 5: Configure DNS ─────────────────────────────────────────────
        let dns_ifindex = if profile.push_dns {
            if let Some(ref iface) = interface {
                configure_dns_for_link(iface, &cfg.dns_servers).await
            } else {
                None
            }
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

        // Send SIGTERM first so openvpn can clean up routes gracefully,
        // then wait briefly before falling back to SIGKILL.
        if let Some(mut child) = child_opt {
            if let Some(raw_pid) = child
                .id()
                .and_then(|id| i32::try_from(id).ok())
                .filter(|&pid| pid > 1)
            {
                info!("Azure: stopping openvpn child (pid={raw_pid})");
                // SIGTERM lets openvpn run its cleanup (delete routes, restore defaults).
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(raw_pid),
                    nix::sys::signal::Signal::SIGTERM,
                );
                match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
                    Ok(_) => info!("Azure: openvpn exited cleanly"),
                    Err(_) => {
                        warn!("Azure: openvpn did not exit in 5 s, killing");
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                    }
                }
            } else {
                // Child already reaped; never call kill(0, SIGTERM) which signals
                // supermgrd's entire process group.
                let _ = child.wait().await;
            }
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
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Parse the virtual IP from an openvpn log line.
///
/// OpenVPN 2.6: `/usr/bin/ip addr add dev tun0 10.134.2.3/24 broadcast +`
/// OpenVPN 2.7: `net_addr_v4_add: 10.134.2.2/24 dev tun0`
fn extract_virtual_ip(line: &str) -> Option<String> {
    // OpenVPN 2.7+ format: "net_addr_v4_add: <cidr> dev <iface>"
    if let Some(idx) = line.find("net_addr_v4_add: ") {
        let rest = &line[idx + "net_addr_v4_add: ".len()..];
        let cidr = rest.split_whitespace().next()?;
        if cidr.contains('.') {
            return Some(cidr.to_owned());
        }
    }
    // OpenVPN 2.6 format: "ip addr add dev <iface> <cidr>"
    if let Some(idx) = line.find("ip addr add dev ") {
        let rest = &line[idx + "ip addr add dev ".len()..];
        let rest = rest.split_once(' ')?.1.trim();
        let cidr = rest.split_whitespace().next()?;
        if cidr.contains('.') || cidr.contains(':') {
            return Some(cidr.to_owned());
        }
    }
    None
}

/// Parse a pushed route from an openvpn log line.
///
/// OpenVPN 2.6: `/usr/bin/ip route add 10.134.0.0/23 via 10.134.2.1`
/// OpenVPN 2.7: `net_route_v4_add: 10.134.0.0/23 via 10.134.2.1 dev [NULL] table 0 metric -1`
fn extract_pushed_route(line: &str) -> Option<String> {
    // OpenVPN 2.7+ format: "net_route_v4_add: <dest> via ..."
    if let Some(idx) = line.find("net_route_v4_add: ") {
        let rest = &line[idx + "net_route_v4_add: ".len()..];
        let dest = rest.split_whitespace().next()?;
        if dest.contains('.') || dest.contains(':') {
            return Some(dest.to_owned());
        }
    }
    // OpenVPN 2.6 format: "ip route add <dest> via ..."
    if let Some(idx) = line.find("ip route add ") {
        let rest = &line[idx + "ip route add ".len()..];
        let dest = rest.split_whitespace().next()?;
        if dest.contains('.') || dest.contains(':') {
            return Some(dest.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn sample_cfg() -> AzureVpnConfig {
        AzureVpnConfig {
            gateway_fqdn: "azurevpn.example.com".to_owned(),
            tenant_id: "11111111-2222-3333-4444-555555555555".to_owned(),
            client_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_owned(),
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
                .to_owned(),
            server_secret_hex: "00".repeat(256),
            dns_servers: Vec::new(),
            routes: Vec::new(),
        }
    }

    #[test]
    fn split_tunnel_with_empty_routes_does_not_emit_redirect_gateway() {
        let cfg = sample_cfg();
        let ovpn = build_ovpn_config(
            &cfg,
            "",
            "/run/supermgrd/tls-auth.key",
            "/run/supermgrd/auth.txt",
            false,
        )
        .unwrap();
        assert!(
            !ovpn.contains("redirect-gateway"),
            "split-tunnel Azure P2S relies on server-pushed routes and must not emit redirect-gateway:\n{ovpn}"
        );
    }

    #[test]
    fn full_tunnel_emits_redirect_gateway() {
        let cfg = sample_cfg();
        let ovpn = build_ovpn_config(
            &cfg,
            "",
            "/run/supermgrd/tls-auth.key",
            "/run/supermgrd/auth.txt",
            true,
        )
        .unwrap();
        assert!(ovpn.contains("redirect-gateway def1\n"), "{ovpn}");
    }

    #[test]
    fn split_tunnel_with_explicit_routes_emits_static_routes_without_redirect_gateway() {
        let mut cfg = sample_cfg();
        cfg.routes = vec![
            "10.134.0.0/16".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ];
        let ovpn = build_ovpn_config(
            &cfg,
            "",
            "/run/supermgrd/tls-auth.key",
            "/run/supermgrd/auth.txt",
            false,
        )
        .unwrap();
        assert!(!ovpn.contains("redirect-gateway"), "{ovpn}");
        assert!(ovpn.contains("route 10.134.0.0 255.255.0.0\n"), "{ovpn}");
        assert!(ovpn.contains("route-ipv6 2001:db8::/32\n"), "{ovpn}");
    }

    #[test]
    fn a_profile_without_a_ca_gets_the_azure_roots_not_an_empty_block() {
        let mut cfg = sample_cfg();
        cfg.ca_cert_pem = String::new();
        let ovpn = build_ovpn_config(&cfg, "", "/k", "/a", false).unwrap();
        let ca = ovpn
            .split("<ca>\n")
            .nth(1)
            .and_then(|rest| rest.split("</ca>").next())
            .unwrap();
        assert_eq!(ca, supermgr_core::vpn::import::AZURE_DEFAULT_CA_PEM);

        // A profile that has its own certificate keeps it.
        let ovpn = build_ovpn_config(&sample_cfg(), "", "/k", "/a", false).unwrap();
        assert!(ovpn.contains("<ca>\n-----BEGIN CERTIFICATE-----\nMIIB...\n"));
        assert!(!ovpn.contains("DigiCert") && !ovpn.contains("MIIDrzCCApeg"));
    }

    #[test]
    fn build_ovpn_config_rejects_injection_in_fqdn_ids_and_ca() {
        let mut bad_fqdn = sample_cfg();
        bad_fqdn.gateway_fqdn = "vpn.example.com 443\nscript-security 2\nup /bin/sh".to_owned();
        assert!(build_ovpn_config(&bad_fqdn, "", "/k", "/a", false).is_err());

        let mut bad_tenant = sample_cfg();
        bad_tenant.tenant_id = "../../evil".to_owned();
        assert!(build_ovpn_config(&bad_tenant, "", "/k", "/a", false).is_err());

        let mut bad_client = sample_cfg();
        bad_client.client_id = "bad&scope=evil".to_owned();
        assert!(build_ovpn_config(&bad_client, "", "/k", "/a", false).is_err());

        let mut bad_ca = sample_cfg();
        bad_ca.ca_cert_pem =
            "-----BEGIN CERTIFICATE-----\n</CA>\nscript-security 2\nup /bin/sh\n<ca>\n".to_owned();
        assert!(build_ovpn_config(&bad_ca, "", "/k", "/a", false).is_err());
    }

    #[test]
    fn percent_decode_handles_multibyte_utf8_and_plus_spaces() {
        assert_eq!(
            percent_decode("Kunnskap+m%C3%B8ter+sikkerhet+%E2%82%AC+%F0%9F%94%92"),
            "Kunnskap møter sikkerhet € 🔒"
        );
        assert_eq!(percent_decode("literal%ZZkeep%2"), "literal%ZZkeep%2");
    }

    #[test]
    fn encode_param_follows_rfc3986_and_roundtrips_utf8() {
        let unreserved = "AZaz09._~-";
        assert_eq!(encode_param(unreserved), unreserved);

        let scope = "41b23e61-6c1e-4545-b367-cd054e0ed4b4/.default openid";
        assert_eq!(
            encode_param(scope),
            "41b23e61-6c1e-4545-b367-cd054e0ed4b4%2F.default%20openid"
        );

        let tricky = "a&b=c+d/e?f#g blåbær 🔒";
        let encoded = encode_param(tricky);
        assert!(
            !encoded.contains('&') && !encoded.contains('=') && !encoded.contains(' '),
            "{encoded}"
        );
        assert_eq!(percent_decode(&encoded), tricky);
    }

    #[tokio::test]
    async fn oauth_callback_rejects_missing_or_mismatched_state() {
        // Missing `state` parameter must be rejected (CSRF protection).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(accept_auth_code(listener, "expected-state-123"));

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /?code=stolen_code HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        let _ = client.read_to_string(&mut resp).await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");

        let err = server.await.unwrap().expect_err("missing state must fail");
        assert!(err.contains("state"), "{err}");

        // Mismatched `state` parameter must also be rejected.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(accept_auth_code(listener, "expected-state-123"));

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /?code=stolen_code&state=wrong HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let err = server.await.unwrap().expect_err("wrong state must fail");
        assert!(err.contains("state"), "{err}");
    }

    #[tokio::test]
    async fn oauth_callback_survives_preconnect_and_favicon_before_real_redirect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(accept_auth_code(listener, "csrf-token-xyz"));

        // 1. Browser speculative TCP preconnect (0-byte close).
        let preconnect = tokio::net::TcpStream::connect(addr).await.unwrap();
        drop(preconnect);

        // 2. Browser `/favicon.ico` probe -> 404 and listener stays alive.
        let mut fav = tokio::net::TcpStream::connect(addr).await.unwrap();
        fav.write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut fav_resp = String::new();
        fav.read_to_string(&mut fav_resp).await.unwrap();
        assert!(fav_resp.starts_with("HTTP/1.1 404"), "{fav_resp}");

        // 3. Real OAuth2 callback arrives and succeeds.
        let mut real = tokio::net::TcpStream::connect(addr).await.unwrap();
        real.write_all(
            b"GET /?code=auth_code_ok&state=csrf-token-xyz HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await
        .unwrap();
        let mut ok_resp = String::new();
        real.read_to_string(&mut ok_resp).await.unwrap();
        assert!(ok_resp.starts_with("HTTP/1.1 200"), "{ok_resp}");

        let code = server.await.unwrap().expect("real callback should succeed");
        assert_eq!(code, "auth_code_ok");
    }
}
