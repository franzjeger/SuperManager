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
//! 2. **PKCE** — generate a `code_verifier` + `code_challenge`, bind a local
//!    `TcpListener` on `127.0.0.1:2023`, publish the auth URL for the GUI to
//!    open (see below), await the redirect, exchange the code for an
//!    access + refresh token.
//! 3. **Tempfiles** — write `tls-auth.key`, `auth.txt`, `client.ovpn` to
//!    a fresh directory under `%PROGRAMDATA%\SuperManager\runtime\`.
//!    A protected ACL grants access only to SYSTEM and Administrators from
//!    creation; a guard removes the files on failed connect or disconnect.
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
//! # Who opens the browser
//!
//! Not the daemon. It runs as `LocalSystem` in session 0, which has no
//! desktop, so a browser it starts — `cmd /c start` included — opens where
//! nobody can see it, and the connect used to wait out its full timeout
//! for a sign-in that could never happen. The URL goes into the shared
//! [`AuthPrompt`] instead; `get_status` carries it while the connect is
//! waiting, and the GUI, running in the operator's own session, opens it.
//! The redirect still reaches the listener here: 127.0.0.1 is the same
//! machine whichever session the browser runs in.
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

use super::session::AuthPrompt;
use super::{output, VpnBackend, VpnError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How long a connect waits for the operator to finish signing in. Ten
/// minutes is long enough for MFA on a phone left in another room; past
/// that, whoever started it has walked away. The GUI can cancel sooner.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long one connection to the callback listener may take to send its
/// request line. Browsers open speculative connections they may never use;
/// one of those must not hold up the one carrying the code.
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(5);

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
    tmp_dir: crate::win::paths::PrivateRuntimeDir,
    /// Whether we pushed DNS that needs reverting.
    dns_overridden: bool,
    /// What openvpn has been printing, for when it stops by itself.
    tail: output::Tail,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Windows Azure VPN backend (named `Ikev2Backend` for legacy reasons —
/// see module docs).
pub struct Ikev2Backend {
    secret_store: Option<Arc<dyn SecretStore>>,
    /// Where a sign-in URL goes for the GUI to open. `None` only for the
    /// `Default` backend, which then just logs the URL.
    auth_prompt: Option<AuthPrompt>,
    active: Mutex<Option<AzActive>>,
}

impl Ikev2Backend {
    /// Construct with a secret store (required to cache the refresh token)
    /// and the prompt slot the session reports sign-in URLs from.
    pub fn with_store(secret_store: Arc<dyn SecretStore>, auth_prompt: AuthPrompt) -> Self {
        Self {
            secret_store: Some(secret_store),
            auth_prompt: Some(auth_prompt),
            active: Mutex::new(None),
        }
    }

    /// Whether a tunnel is currently up.
    pub async fn is_active(&self) -> bool {
        self.active.lock().await.is_some()
    }

    /// Why the tunnel's openvpn exited, if it has. `None` while it runs,
    /// and when there is no tunnel.
    pub async fn exited(&self) -> Option<String> {
        let mut guard = self.active.lock().await;
        let active = guard.as_mut()?;
        match active.child.try_wait() {
            Ok(Some(status)) => Some(output::exit_reason("Azure VPN", status, &active.tail)),
            _ => None,
        }
    }
}

impl Default for Ikev2Backend {
    fn default() -> Self {
        Self {
            secret_store: None,
            auth_prompt: None,
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
                "adapter": a.adapter_name,
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
        let access_token = authenticate(
            &profile.id,
            &cfg.tenant_id,
            &cfg.client_id,
            store.as_ref(),
            self.auth_prompt.as_ref(),
        )
        .await?;
        let upn = jwt_upn(&access_token);
        info!(upn, "Azure: authenticated");

        // ── Step 2 — Tempfiles ──────────────────────────────────────────────
        let tmp_dir = crate::win::paths::create_private_runtime_dir("azure", &profile.id)
            .map_err(VpnError::Io)?;

        let key_path = tmp_dir.path().join("tls-auth.key");
        let auth_path = tmp_dir.path().join("auth.txt");
        let ovpn_path = tmp_dir.path().join("client.ovpn");

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
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|e| {
            VpnError::MissingDependency(format!("could not start {}: {e}", openvpn_exe.display()))
        })?;
        info!(?openvpn_exe, config = %ovpn_path.display(), "spawned openvpn for Azure tunnel");

        // ── Step 4 — Wait for "Initialization Sequence Completed" ──────────
        // We don't enable the management socket here — Azure's flow is
        // fully scripted, mid-flight controls aren't needed. The log is
        // enough to detect success, and it goes on being read after this
        // stops listening: an unread pipe fills and stalls the tunnel.
        let (tail, mut watcher) = output::capture(&mut child);

        let mut adapter_name: Option<String> = None;
        let mut connected = false;
        let deadline = tokio::time::Instant::now() + OPENVPN_CONNECT_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let Ok(Some(line)) = timeout(remaining, watcher.recv()).await else {
                // stdout closed (the process exited), or the time is up.
                break;
            };
            if line.contains("Initialization Sequence Completed") {
                connected = true;
                break;
            }
            if line.contains("AUTH_FAILED") {
                let _ = child.kill().await;
                return Err(VpnError::PermissionDenied(
                    "The VPN gateway rejected the Entra ID sign-in",
                ));
            }
            if let Some(name) = extract_tap_adapter(&line) {
                adapter_name = Some(name);
            }
        }
        drop(watcher);

        if !connected {
            let _ = child.kill().await;
            return Err(VpnError::Subprocess {
                code: -1,
                stderr: tail.reason().unwrap_or_else(|| {
                    format!(
                        "The Azure gateway did not complete the connection within {} s",
                        OPENVPN_CONNECT_TIMEOUT.as_secs()
                    )
                }),
            });
        }

        info!(profile_id = %profile.id, adapter = ?adapter_name, "Azure tunnel up");

        // ── Step 5 — DNS push (best-effort) ─────────────────────────────────
        let mut dns_overridden = false;
        if profile.push_dns && !cfg.dns_servers.is_empty() {
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
            tail,
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

async fn tear_down(mut active: AzActive) {
    info!(profile_id = %active.profile_id, "Azure: tearing down tunnel");
    if active.dns_overridden {
        if let Some(name) = active.adapter_name.as_deref() {
            if let Err(e) = reset_dns(name).await {
                warn!("Azure DNS reset on {name} failed: {e:#}");
            }
        }
    }
    let _ = active.child.kill().await;
    let _ = active.child.wait().await;
    drop(active.tmp_dir);
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
    prompt: Option<&AuthPrompt>,
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

    let (access, refresh_opt) = pkce_browser_flow(tenant_id, audience, prompt).await?;
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
    if let (Some(a), Some(r)) = (
        body["access_token"].as_str(),
        body["refresh_token"].as_str(),
    ) {
        Ok((a.to_owned(), r.to_owned()))
    } else {
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

/// Holds a published sign-in URL, and withdraws it however the wait ends —
/// signed in, timed out, or cancelled by the future being dropped. A stale
/// URL left behind would have the GUI open a sign-in nobody is listening
/// for.
struct Published<'a>(&'a AuthPrompt);

impl<'a> Published<'a> {
    fn new(prompt: &'a AuthPrompt, url: &str) -> Self {
        if let Ok(mut slot) = prompt.lock() {
            *slot = Some(url.to_owned());
        }
        Self(prompt)
    }
}

impl Drop for Published<'_> {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = None;
        }
    }
}

async fn pkce_browser_flow(
    tenant_id: &str,
    audience: &str,
    prompt: Option<&AuthPrompt>,
) -> Result<(String, Option<String>), VpnError> {
    let u1 = uuid::Uuid::new_v4();
    let u2 = uuid::Uuid::new_v4();
    let mut verifier_bytes = [0u8; 32];
    verifier_bytes[..16].copy_from_slice(u1.as_bytes());
    verifier_bytes[16..].copy_from_slice(u2.as_bytes());
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let code_challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(code_verifier.as_bytes()));
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

    // Bind BEFORE publishing the URL so we never miss the redirect.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", REDIRECT_PORT))
        .await
        .map_err(|e| {
            VpnError::MissingDependency(format!(
                "Cannot listen on {REDIRECT_URI} for the sign-in redirect ({e}). \
                 Another program is using port {REDIRECT_PORT} — the Azure VPN \
                 Client, if it is installed, is the usual one."
            ))
        })?;

    // The URL carries the PKCE challenge, not the verifier: nothing in it
    // lets anyone else redeem the code. Logged so a `--console` run with no
    // GUI attached can still be signed in by hand.
    info!("Azure: waiting for sign-in at {auth_url}");
    let _published = prompt.map(|p| Published::new(p, &auth_url));

    let code = timeout(AUTH_TIMEOUT, accept_auth_code(listener, &state))
        .await
        .map_err(|_| VpnError::Subprocess {
            code: -1,
            stderr: format!(
                "Nobody finished signing in to Microsoft Entra ID within {} minutes",
                AUTH_TIMEOUT.as_secs() / 60
            ),
        })?
        .map_err(|e| VpnError::Subprocess {
            code: -1,
            stderr: format!("Entra ID sign-in failed: {e}"),
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
    if let Some(a) = body["access_token"].as_str() {
        Ok((
            a.to_owned(),
            body["refresh_token"].as_str().map(str::to_owned),
        ))
    } else {
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

/// What one connection to the callback listener turned out to be.
#[derive(Debug, PartialEq, Eq)]
enum Callback {
    /// The redirect, carrying the authorization code.
    Code(String),
    /// The redirect, carrying Entra ID's refusal.
    Refused(String),
    /// Anything else: a speculative connection, a favicon request, a
    /// stale tab. Not an answer; keep listening.
    Other,
}

/// Wait for the redirect that carries the authorization code.
///
/// Accepts connections until one is the redirect. The first connection is
/// not necessarily it: browsers open sockets speculatively and ask for
/// `/favicon.ico`, and taking whichever came first failed the sign-in on
/// an empty request.
async fn accept_auth_code(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, String> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("accept: {e}"))?;
        match timeout(
            CALLBACK_READ_TIMEOUT,
            answer_callback(stream, expected_state),
        )
        .await
        {
            Ok(Callback::Code(code)) => return Ok(code),
            Ok(Callback::Refused(reason)) => return Err(reason),
            // Not the redirect (a favicon, a probe) or too slow: keep listening.
            Ok(Callback::Other) | Err(_) => {}
        }
    }
}

/// Read one request from the listener, answer it, and say what it was.
async fn answer_callback(stream: tokio::net::TcpStream, expected_state: &str) -> Callback {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    let Ok(Some(request_line)) = lines.next_line().await else {
        return Callback::Other;
    };
    let callback = parse_callback(&request_line, expected_state);
    let (status, heading, body) = match &callback {
        Callback::Code(_) => (
            "200 OK",
            "Signed in",
            "You can close this tab. SuperManager is connecting.",
        ),
        Callback::Refused(_) => (
            "200 OK",
            "Sign-in failed",
            "Microsoft Entra ID did not sign you in. SuperManager shows the reason.",
        ),
        Callback::Other => ("404 Not Found", "Not found", ""),
    };
    let page = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Connection: close\r\n\r\n\
         <html><head><title>SuperManager</title></head><body>\
         <h2>{heading}</h2><p>{body}</p></body></html>\r\n"
    );
    let _ = writer.write_all(page.as_bytes()).await;
    callback
}

/// Classify a callback request line.
///
/// The `state` must come back and must match: a redirect without it is
/// not one this connect asked for, whatever else it carries.
fn parse_callback(request_line: &str, expected_state: &str) -> Callback {
    let Some(target) = request_line.split_whitespace().nth(1) else {
        return Callback::Other;
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/" {
        return Callback::Other;
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

    if code.is_none() && error_desc.is_none() {
        return Callback::Other;
    }
    if returned_state.as_deref() != Some(expected_state) {
        return Callback::Refused("the sign-in reply did not match this request".into());
    }
    match (code, error_desc) {
        (_, Some(reason)) => Callback::Refused(reason),
        (Some(code), None) => Callback::Code(code),
        (None, None) => Callback::Other,
    }
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
         suppress-timestamps\n\
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

    // Split tunnel means what the gateway pushes — the networks behind it,
    // as the Azure VPN Client gets them — plus any routes the profile adds.
    // This used to force `redirect-gateway` whenever the profile listed no
    // routes, the usual case, and a P2S gateway not built for forced
    // tunnelling drops internet traffic: connected, and nothing loads.
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

    if !cfg.dns_servers.is_empty() {
        s.push_str("dhcp-option DNS ");
        s.push_str(
            &cfg.dns_servers
                .iter()
                .map(std::string::ToString::to_string)
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

#[cfg(test)]
mod tests {
    use super::{build_ovpn_config, parse_callback, Callback};
    use supermgr_core::vpn::profile::AzureVpnConfig;

    fn config(routes: &[&str]) -> AzureVpnConfig {
        AzureVpnConfig {
            gateway_fqdn: "azuregateway-x.vpn.azure.com".into(),
            tenant_id: "tenant".into(),
            client_id: "41b23e61-6c1e-4545-b367-cd054e0ed4b4".into(),
            server_secret_hex: "00".repeat(256),
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n".into(),
            dns_servers: Vec::new(),
            routes: routes.iter().map(|r| r.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn a_split_tunnel_with_no_listed_routes_takes_the_gateways() {
        let ovpn = build_ovpn_config(&config(&[]), "k", "a", false);
        assert!(!ovpn.contains("redirect-gateway"), "{ovpn}");
    }

    #[test]
    fn listed_routes_are_added_and_full_tunnel_redirects_everything() {
        let split = build_ovpn_config(&config(&["10.1.0.0/16"]), "k", "a", false);
        assert!(split.contains("route 10.1.0.0 255.255.0.0"), "{split}");
        let full = build_ovpn_config(&config(&["10.1.0.0/16"]), "k", "a", true);
        assert!(full.contains("redirect-gateway def1"), "{full}");
    }

    const STATE: &str = "5b1c1f9e-state";

    #[test]
    fn the_redirect_with_a_code_and_our_state_is_the_answer() {
        let line = format!("GET /?code=abc%2Fdef&state={STATE}&session_state=x HTTP/1.1");
        assert_eq!(
            parse_callback(&line, STATE),
            Callback::Code("abc/def".into())
        );
    }

    #[test]
    fn a_speculative_connection_or_favicon_is_not_an_answer() {
        // Taking the first connection as the redirect is what failed
        // sign-ins on browsers that preconnect.
        assert_eq!(
            parse_callback("GET /favicon.ico HTTP/1.1", STATE),
            Callback::Other
        );
        assert_eq!(parse_callback("GET / HTTP/1.1", STATE), Callback::Other);
        assert_eq!(parse_callback("", STATE), Callback::Other);
    }

    #[test]
    fn a_code_without_our_state_is_refused() {
        // The old check only compared a state that was present, so a reply
        // with none at all went through.
        let refused = |line: &str| matches!(parse_callback(line, STATE), Callback::Refused(_));
        assert!(refused("GET /?code=abc HTTP/1.1"));
        assert!(refused("GET /?code=abc&state=someone-else HTTP/1.1"));
    }

    #[test]
    fn entra_ids_refusal_is_passed_on_in_its_own_words() {
        let line = format!(
            "GET /?error=access_denied&error_description=User+cancelled+the+flow&state={STATE} HTTP/1.1"
        );
        assert_eq!(
            parse_callback(&line, STATE),
            Callback::Refused("User cancelled the flow".into())
        );
    }
}
