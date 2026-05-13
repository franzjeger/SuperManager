//! Standalone UniFi controller registry.
//!
//! Architectural note — controllers are NOT tied to an SSH host.
//! Earlier iterations of this codebase stored `unifi_controller_url`
//! + creds inline on each `Host`, conflating "an SSH host that
//! happens to be a UniFi controller machine" with "any UniFi
//! controller the MSP runs anywhere." The new model treats
//! controllers as first-class top-level entities. Reasoning:
//!
//!   - Most MSP UniFi controllers run on UDM-Pro / cloud-key /
//!     a hosted VM and we never SSH them directly.
//!   - One controller manages many devices; many devices are
//!     reached via one controller. Coupling those two scopes
//!     was just wrong.
//!   - Cross-referencing scan results against controller
//!     inventories (the whole point of controller-first
//!     adoption UX) needs the controller list to be the
//!     primary entity, not a per-host attribute.
//!
//! On-disk layout mirrors the rest of the daemon's state: each
//! controller is a `.toml` file in `<data_dir>/unifi/controllers/`,
//! atomically written via the shared `save_toml` helper. The
//! controller's HTTP password lives in the macOS keychain via
//! `SecretStore`, referenced by `creds_ref`.
//!
//! Public surface area:
//!   - `UnifiController` struct (the persisted record)
//!   - `UnifiManagedDevice` struct (one row of `/stat/device`)
//!   - `list_devices` / `devmgr_command` async helpers
//!   - `cross_reference` — given a list of MACs + the controller
//!     registry, return a map MAC → ManagedDevice for every
//!     match. Used by `active_scan` to annotate scan rows.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use reqwest::cookie::Jar;
use serde::{Deserialize, Serialize};
use supermgr_core::keyring::SecretStore;
use supermgr_core::vpn::profile::SecretRef;
use tracing::{info, warn};
use uuid::Uuid;

/// HTTP timeout for any single controller request. Controllers
/// running on a UDM-Pro under load can take ~1 s for `/stat/device`
/// with a hundred devices; 15 s is plenty.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a pending MFA challenge stays valid before the
/// operator has to restart the add-controller flow. UniFi's own
/// email codes time out at 5 minutes, so matching that.
const MFA_CHALLENGE_TTL: Duration = Duration::from_secs(300);

/// In-flight MFA challenge state. Holds the partially-
/// authenticated reqwest::Client (its cookie jar carries the
/// session ID UniFi opened during the initial password POST)
/// plus a pending `UnifiController` record that gets persisted
/// once the second factor verifies. Auto-evicted after
/// `MFA_CHALLENGE_TTL`.
pub struct InflightMfaChallenge {
    pub id: String,
    pub controller: UnifiController,
    pub client: reqwest::Client,
    pub authenticators: Vec<MfaAuthenticator>,
    pub created_at: std::time::Instant,
}

/// Process-global registry of in-flight MFA challenges, keyed
/// by opaque challenge ID. `OnceLock` (std-stable since 1.70)
/// gives us the lazy global without dragging in the once_cell
/// crate — same shape, no new dependency.
static MFA_CHALLENGES: std::sync::OnceLock<
    tokio::sync::Mutex<HashMap<String, InflightMfaChallenge>>,
> = std::sync::OnceLock::new();

fn mfa_registry() -> &'static tokio::sync::Mutex<HashMap<String, InflightMfaChallenge>> {
    MFA_CHALLENGES.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

/// Park a challenge in the registry, returning the opaque ID
/// the GUI uses to reference it on the follow-up calls.
async fn park_mfa_challenge(challenge: InflightMfaChallenge) -> String {
    evict_expired_challenges().await;
    let id = challenge.id.clone();
    mfa_registry().lock().await.insert(id.clone(), challenge);
    id
}

/// Look up + remove a challenge by ID. The caller takes
/// ownership of the partially-authenticated client.
async fn take_mfa_challenge(id: &str) -> Option<InflightMfaChallenge> {
    evict_expired_challenges().await;
    mfa_registry().lock().await.remove(id)
}

/// Borrow a challenge without consuming it — used by the
/// "send email" step which needs to fire a request but leave
/// the challenge in the registry for the eventual verify call.
async fn with_mfa_challenge<F, R>(id: &str, f: F) -> Option<R>
where
    F: FnOnce(&InflightMfaChallenge) -> R,
{
    evict_expired_challenges().await;
    let guard = mfa_registry().lock().await;
    guard.get(id).map(f)
}

async fn evict_expired_challenges() {
    let now = std::time::Instant::now();
    let mut guard = mfa_registry().lock().await;
    guard.retain(|_, c| now.duration_since(c.created_at) < MFA_CHALLENGE_TTL);
}

/// Outcome returned by save-with-MFA — either the save
/// completed in one round-trip (no MFA), or the caller needs
/// to drive the operator through an MFA challenge before the
/// controller can be persisted.
pub enum SaveOutcome {
    Saved {
        controller: UnifiController,
        sysinfo: UnifiSysInfo,
    },
    MfaRequired {
        challenge_id: String,
        authenticators: Vec<MfaAuthenticator>,
    },
}

/// Park a pending controller registration that hit an MFA
/// challenge. Returns the opaque challenge ID the GUI uses
/// to subsequently call `unifi_controller_mfa_send` +
/// `unifi_controller_mfa_complete`.
pub async fn park_pending_save(
    controller: UnifiController,
    client: reqwest::Client,
    authenticators: Vec<MfaAuthenticator>,
) -> String {
    let challenge = InflightMfaChallenge {
        id: uuid::Uuid::new_v4().to_string(),
        controller,
        client,
        authenticators,
        created_at: std::time::Instant::now(),
    };
    park_mfa_challenge(challenge).await
}

/// Trigger the email leg of an in-flight MFA challenge. The
/// challenge stays in the registry — the operator now waits
/// for the email, then submits the code via `complete_pending_save`.
pub async fn send_mfa_email_for_challenge(
    challenge_id: &str,
    authenticator_id: &str,
) -> Result<()> {
    let snapshot = with_mfa_challenge(challenge_id, |c| {
        (c.client.clone(), c.controller.url.clone())
    })
    .await
    .ok_or_else(|| {
        anyhow!("MFA challenge not found or expired (5-min TTL)")
    })?;
    let (client, url) = snapshot;
    mfa_send_email(&client, &url, authenticator_id).await
}

/// Complete a pending controller registration by submitting
/// the MFA code. On success: removes the challenge from the
/// registry, verifies the controller via sysinfo, and returns
/// the freshly-validated controller record + sysinfo.
pub async fn complete_pending_save(
    secrets: &Arc<dyn SecretStore>,
    challenge_id: &str,
    code: &str,
) -> Result<(UnifiController, UnifiSysInfo)> {
    let challenge = take_mfa_challenge(challenge_id).await.ok_or_else(|| {
        anyhow!("MFA challenge not found or expired (5-min TTL)")
    })?;
    let _client = mfa_complete_login(
        secrets,
        &challenge.controller,
        challenge.client,
        code,
    )
    .await?;
    let sysinfo = test_connection(secrets, &challenge.controller).await?;
    let mut verified = challenge.controller;
    verified.verified_at = Some(chrono::Utc::now());
    Ok((verified, sysinfo))
}

/// Which credential mechanism a controller uses. API key is
/// the recommended path because it sidesteps MFA, can be
/// rotated independently, and is what every modern integration
/// in the Ubiquiti ecosystem expects.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnifiAuthMethod {
    /// Long-lived `X-API-KEY` token minted in the controller UI
    /// under Admins → API. Sent as a header on every request;
    /// no /api/auth/login cookie dance required.
    ApiKey,
    /// Classic local-user or SSO username + password. Cookie-
    /// based session. Falls into the MFA flow when the
    /// controller demands a second factor.
    Password,
}

impl Default for UnifiAuthMethod {
    fn default() -> Self {
        Self::Password
    }
}

/// A configured UniFi controller. The struct is the canonical
/// on-disk record (one TOML file per controller); the
/// credential (API key OR password) is stored separately in
/// the keychain and referenced by `creds_ref`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiController {
    pub id: Uuid,
    /// Human-readable label shown in the UI. Operators pick this
    /// (e.g. "Main site", "ACME Corp", "Home lab").
    pub label: String,
    /// Base URL. Should NOT end with a slash. Scheme is
    /// honoured — https://… stays https. Default UniFi
    /// Network Application port is 8443.
    pub url: String,
    /// UniFi site identifier within the controller. Most
    /// single-site deploys use the literal string "default";
    /// multi-site deploys have distinct IDs per site.
    pub site_id: String,
    /// Which mechanism `creds_ref` resolves to.
    #[serde(default)]
    pub auth_method: UnifiAuthMethod,
    /// Username — only used when `auth_method == Password`.
    /// For API-key auth this stays empty.
    #[serde(default)]
    pub username: String,
    /// Keychain reference for the credential. For
    /// `auth_method == Password` this resolves to the user's
    /// password. For `auth_method == ApiKey` it resolves to
    /// the X-API-KEY token. Same field intentionally — the
    /// keychain doesn't care.
    pub creds_ref: SecretRef,
    /// Optional MSP scoping. When set, GUI filters this
    /// controller out unless the operator has the same customer
    /// selected. Single-tenant deploys leave it None.
    pub customer_slug: Option<String>,
    /// Timestamp of the last successful `test_connection`. None
    /// means the controller has never been verified.
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UnifiController {
    /// Build a `https://controller-host:8443/proxy/network/api/s/<site>/<path>`
    /// URL for the modern UniFi-OS proxy path, or the classic
    /// `https://controller-host:8443/api/s/<site>/<path>` for
    /// older standalone Network Applications.
    ///
    /// We can't tell which one applies without an API hit. The
    /// classic /api path works on every UniFi version since 5.x;
    /// the proxy path is a strict superset on UDM/UDM-Pro. We
    /// use classic /api as the default because it has the
    /// widest compatibility, and let callers override by passing
    /// `path` starting with `/proxy/...` if they know better.
    pub fn site_url(&self, path: &str) -> String {
        let base = self.url.trim_end_matches('/');
        let p = path.trim_start_matches('/');
        if p.starts_with("proxy/") || p.starts_with("/proxy/") {
            format!("{base}/{}", p.trim_start_matches('/'))
        } else {
            format!("{base}/api/s/{}/{}", self.site_id, p)
        }
    }
}

/// One row of `/api/s/<site>/stat/device`. We only deserialise
/// the fields we actually surface in the GUI; UniFi adds new
/// ones every release, so we don't fail on unknown keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiManagedDevice {
    /// MAC address normalised to lowercase, colon-separated.
    /// Cross-reference key against scan results.
    pub mac: String,
    pub ip: Option<String>,
    /// "U7-Pro", "USW-24-PRO", "UAP-AC-Lite", etc.
    pub model: Option<String>,
    /// Friendly name set in the controller UI.
    pub name: Option<String>,
    /// "connected" / "disconnected" / "pending" / "managed-by-other" / etc.
    pub state: String,
    /// Firmware version string.
    pub version: Option<String>,
    /// Adoption status. UniFi controller API exposes this as
    /// `adopted: bool`. Combined with `state == "pending"` we
    /// can render "pending adoption" vs "adopted" vs "orphaned".
    pub adopted: Option<bool>,
    /// Inform URL the device is currently pointed at.
    pub inform_url: Option<String>,
    /// Uptime in seconds.
    pub uptime: Option<u64>,
    /// Last-seen Unix timestamp (UniFi reports both `lastSeen`
    /// and `_last_seen`; serde tolerates either via alias).
    #[serde(alias = "lastSeen", alias = "_last_seen")]
    pub last_seen: Option<i64>,

    /// Filled in by `list_devices` when we know which controller
    /// this row came from; not part of the controller's JSON.
    #[serde(default)]
    pub controller_id: Option<Uuid>,
    #[serde(default)]
    pub controller_label: Option<String>,
}

/// Cross-reference annotation attached to an ActiveHost when a
/// scan match is found. The GUI uses this to show the controller
/// badge + replace SSH actions with controller-API ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerStateRef {
    pub controller_id: Uuid,
    pub controller_label: String,
    /// Echo of `UnifiManagedDevice.state` so the row can show
    /// "adopted" vs "pending" without re-querying.
    pub state: String,
    pub adopted: bool,
    pub model: Option<String>,
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// REST client helpers
// ---------------------------------------------------------------------------

/// One authenticator the controller offers during an MFA
/// challenge. Surfaced to the GUI verbatim so the operator
/// can pick which method to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaAuthenticator {
    pub id: String,
    /// `"email"`, `"webauthn"`, `"sms"`, `"push"`, `"totp"`, etc.
    #[serde(default)]
    pub kind: String,
    /// User-facing name: email address, device nickname, etc.
    pub name: String,
}

/// Structured outcome of an attempted password login.
pub enum PasswordLoginOutcome {
    /// Login succeeded — the `reqwest::Client` is fully
    /// authenticated and ready for API calls.
    Ok(reqwest::Client),
    /// Controller demands a second factor. The caller must
    /// route the operator through `mfa_send_email` then
    /// `mfa_complete_login`. Carries enough context to do
    /// that without re-prompting for the password.
    MfaRequired {
        client: reqwest::Client,
        authenticators: Vec<MfaAuthenticator>,
    },
}

/// Build an authenticated `reqwest::Client` for a controller.
/// Dispatches to the right strategy based on the controller's
/// `auth_method`:
///
///   - `ApiKey`: build a client with `X-API-KEY` as a default
///     header. No /api/auth/login round-trip; every request
///     carries the token. Skips MFA entirely. This is the
///     recommended path for any controller running UniFi
///     Network 8.x or later.
///   - `Password`: classic cookie-based login. Returns
///     `MfaRequired` if the controller answers with 499
///     `MFA_AUTH_REQUIRED` — the caller is expected to walk
///     the operator through email-MFA and call this again
///     after challenge completion (with the cookie jar
///     carried forward — see `login_with_mfa_token`).
async fn login_client(
    secrets: &Arc<dyn SecretStore>,
    controller: &UnifiController,
) -> Result<reqwest::Client> {
    match controller.auth_method {
        UnifiAuthMethod::ApiKey => api_key_client(secrets, controller).await,
        UnifiAuthMethod::Password => match password_login(secrets, controller).await? {
            PasswordLoginOutcome::Ok(client) => Ok(client),
            PasswordLoginOutcome::MfaRequired { .. } => Err(anyhow!(
                "controller demands MFA — register it via \
                 unifi_controller_save (which surfaces the challenge to the \
                 GUI) before trying device API calls. \
                 \
                 Quickest fix: in the controller UI go to Admins → API, \
                 mint a long-lived API key, then add the controller in \
                 SuperManager with auth_method=api_key. API keys bypass MFA."
            )),
        },
    }
}

/// Build a stateless client that carries `X-API-KEY` as a
/// default header on every request. No login dance, no cookies,
/// no MFA. The user mints the key in the controller UI under
/// Admins → API, pastes it into the GUI add sheet, done.
async fn api_key_client(
    secrets: &Arc<dyn SecretStore>,
    controller: &UnifiController,
) -> Result<reqwest::Client> {
    let secret = secrets
        .retrieve(&controller.creds_ref.0)
        .await
        .context("load API key from keychain")?;
    let token = std::str::from_utf8(secret.as_ref())
        .context("API key is not valid UTF-8")?
        .trim()
        .to_owned();
    if token.is_empty() {
        return Err(anyhow!("API key is empty"));
    }
    let mut headers = reqwest::header::HeaderMap::new();
    let value = reqwest::header::HeaderValue::from_str(&token)
        .context("API key contains invalid characters")?;
    headers.insert("X-API-KEY", value);
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .danger_accept_invalid_certs(true)
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("build api-key client")
}

/// Password login flow with MFA detection. Returns a structured
/// outcome so the caller can route the operator through the
/// challenge UI when needed.
pub async fn password_login(
    secrets: &Arc<dyn SecretStore>,
    controller: &UnifiController,
) -> Result<PasswordLoginOutcome> {
    let secret = secrets
        .retrieve(&controller.creds_ref.0)
        .await
        .context("load controller password from keychain")?;
    let password = std::str::from_utf8(secret.as_ref())
        .context("controller password is not valid UTF-8")?
        .to_owned();

    let jar = Arc::new(Jar::default());
    let client = reqwest::Client::builder()
        .cookie_provider(jar)
        .danger_accept_invalid_certs(true)
        .timeout(HTTP_TIMEOUT)
        .build()
        .context("build reqwest client")?;

    let login_url = format!("{}/api/auth/login", controller.url.trim_end_matches('/'));
    let body = serde_json::json!({
        "username": controller.username,
        "password": password,
    });
    let resp = client
        .post(&login_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {login_url}"))?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if status >= 200 && status < 300 {
        return Ok(PasswordLoginOutcome::Ok(client));
    }

    // Ubiquiti returns HTTP 499 with code MFA_AUTH_REQUIRED
    // when the account has a second factor enabled. Try to
    // parse the authenticators list out of the response.
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
        let code = json.get("code").and_then(|v| v.as_str()).unwrap_or("");
        if code == "MFA_AUTH_REQUIRED" || code == "MFA_REQUIRED" {
            let auths_raw = json
                .pointer("/data/authenticators")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let authenticators: Vec<MfaAuthenticator> = auths_raw
                .into_iter()
                .filter_map(|row| {
                    let id = row.get("id").and_then(|v| v.as_str())?.to_owned();
                    let kind = row
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let name = row
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                        .or_else(|| {
                            row.get("email").and_then(|v| v.as_str()).map(str::to_owned)
                        })
                        .or_else(|| {
                            row.get("provider_friendly_name")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned)
                        })
                        .unwrap_or_else(|| kind.clone());
                    Some(MfaAuthenticator { id, kind, name })
                })
                .collect();
            return Ok(PasswordLoginOutcome::MfaRequired {
                client,
                authenticators,
            });
        }
    }

    Err(anyhow!(
        "UniFi login to {} failed ({status}): {}",
        controller.url,
        text.chars().take(400).collect::<String>()
    ))
}

/// Trigger the controller to send the email-MFA challenge for
/// a specific authenticator. The cookie jar inside `client`
/// carries the partial-login session forward so the controller
/// knows which login attempt this challenge belongs to.
pub async fn mfa_send_email(
    client: &reqwest::Client,
    controller_url: &str,
    authenticator_id: &str,
) -> Result<()> {
    // Ubiquiti exposes this under /api/auth/mfa/email/.../send
    // on the Network Application, and /api/sso/v2/... on the
    // hosted Cloud variants. Try both endpoints so we work
    // across self-hosted, UDM-Pro, and SSO-mode controllers.
    let candidates = [
        format!(
            "{}/api/auth/mfa/email/authenticator/{}/send",
            controller_url.trim_end_matches('/'),
            authenticator_id
        ),
        format!(
            "{}/api/sso/v2/user/self/mfa/email/authenticator/{}/send",
            controller_url.trim_end_matches('/'),
            authenticator_id
        ),
    ];
    let mut last_err = anyhow!("no MFA-send endpoint reachable");
    for url in candidates {
        match client.post(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status >= 200 && status < 300 {
                    info!("MFA email triggered via {url}");
                    return Ok(());
                }
                let text = resp.text().await.unwrap_or_default();
                last_err = anyhow!(
                    "MFA-send {url} returned {status}: {}",
                    text.chars().take(200).collect::<String>()
                );
            }
            Err(e) => last_err = anyhow!("POST {url}: {e}"),
        }
    }
    Err(last_err)
}

/// Complete a password login by submitting the MFA code. The
/// `client` is the same one used for the initial password POST
/// (so its cookie jar carries the partial-auth state). Returns
/// a fully-authenticated client on success.
pub async fn mfa_complete_login(
    secrets: &Arc<dyn SecretStore>,
    controller: &UnifiController,
    client: reqwest::Client,
    code: &str,
) -> Result<reqwest::Client> {
    let secret = secrets.retrieve(&controller.creds_ref.0).await
        .context("load controller password from keychain")?;
    let password = std::str::from_utf8(secret.as_ref())
        .context("password is not valid UTF-8")?
        .to_owned();
    let login_url = format!("{}/api/auth/login", controller.url.trim_end_matches('/'));
    // Ubiquiti accepts the code under either `token` or
    // `ubic_2fa_token` depending on version; ship both so
    // we don't fail on the field-name change between releases.
    let body = serde_json::json!({
        "username": controller.username,
        "password": password,
        "token": code.trim(),
        "ubic_2fa_token": code.trim(),
    });
    let resp = client
        .post(&login_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {login_url}"))?;
    let status = resp.status().as_u16();
    if status >= 200 && status < 300 {
        return Ok(client);
    }
    let text = resp.text().await.unwrap_or_default();
    Err(anyhow!(
        "MFA verify failed ({status}): {}",
        text.chars().take(400).collect::<String>()
    ))
}

/// GET `/api/s/<site>/stat/device` and return every device the
/// controller manages. Each row gets `controller_id` and
/// `controller_label` annotated so callers can merge across
/// many controllers without losing provenance.
pub async fn list_devices(
    secrets: &Arc<dyn SecretStore>,
    controller: &UnifiController,
) -> Result<Vec<UnifiManagedDevice>> {
    let client = login_client(secrets, controller).await?;
    let url = controller.site_url("stat/device");
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if status >= 400 {
        return Err(anyhow!(
            "UniFi /stat/device returned {status}: {}",
            text.chars().take(300).collect::<String>()
        ));
    }

    // UniFi wraps every response in `{"meta": {...}, "data": [...]}`.
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .context("parse /stat/device JSON")?;
    let data = parsed
        .get("data")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("unexpected /stat/device shape — no `data` array"))?;

    let mut out = Vec::with_capacity(data.len());
    for row in data {
        // Each row is a fat object with ~80 fields. We pluck the
        // few we care about by string-name rather than via Serde
        // because UniFi's JSON has wildly inconsistent naming
        // and a flat struct deserialise was too brittle in
        // practice.
        let mac = row
            .get("mac")
            .and_then(|v| v.as_str())
            .map(str::to_ascii_lowercase);
        let Some(mac) = mac else { continue };
        let device = UnifiManagedDevice {
            mac,
            ip: row.get("ip").and_then(|v| v.as_str()).map(str::to_owned),
            model: row.get("model").and_then(|v| v.as_str()).map(str::to_owned),
            name: row.get("name").and_then(|v| v.as_str()).map(str::to_owned),
            state: state_label(row.get("state").and_then(|v| v.as_i64()).unwrap_or(0)),
            version: row.get("version").and_then(|v| v.as_str()).map(str::to_owned),
            adopted: row.get("adopted").and_then(|v| v.as_bool()),
            inform_url: row
                .get("inform_url")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            uptime: row.get("uptime").and_then(|v| v.as_u64()),
            last_seen: row.get("last_seen").and_then(|v| v.as_i64()),
            controller_id: Some(controller.id),
            controller_label: Some(controller.label.clone()),
        };
        out.push(device);
    }
    Ok(out)
}

/// Map UniFi's numeric device state codes to human labels.
/// Codes come from years of reverse-engineering the controller
/// API: 0/1 are pending or adopting variants, 2 is operating,
/// the rest are exception states.
fn state_label(code: i64) -> String {
    match code {
        0 => "disconnected",
        1 => "connected",
        2 => "pending-adoption",
        4 => "upgrading",
        5 => "provisioning",
        6 => "heartbeat-missed",
        7 => "adopting",
        9 => "managed-by-other",
        11 => "isolated",
        _ => "unknown",
    }
    .to_owned()
}

/// Common command names for `/cmd/devmgr`. Reject anything else
/// at the boundary so a typo can't fire an unintended action.
pub fn validate_devmgr_command(cmd: &str) -> Result<&str> {
    match cmd {
        "adopt" | "forget" | "restart" | "locate" | "unset-locate" | "upgrade"
        | "move" | "delete-device" | "set-inform" => Ok(cmd),
        _ => Err(anyhow!("unsupported devmgr command: {cmd}")),
    }
}

/// POST a `/api/s/<site>/cmd/devmgr` command keyed by MAC. The
/// `extra` map is merged into the body for commands that need
/// extra args (e.g. `set-inform` takes `url`, `move` takes
/// `site_id`).
pub async fn devmgr_command(
    secrets: &Arc<dyn SecretStore>,
    controller: &UnifiController,
    cmd: &str,
    mac: &str,
    extra: serde_json::Value,
) -> Result<serde_json::Value> {
    let validated = validate_devmgr_command(cmd)?;
    let client = login_client(secrets, controller).await?;
    let url = controller.site_url("cmd/devmgr");
    let mac_lower = mac.to_ascii_lowercase();
    let mut body = serde_json::json!({
        "cmd": validated,
        "mac": mac_lower,
    });
    if let serde_json::Value::Object(extras) = extra {
        if let serde_json::Value::Object(ref mut target) = body {
            for (k, v) in extras {
                target.insert(k, v);
            }
        }
    }
    info!(
        "unifi devmgr cmd='{cmd}' mac={mac_lower} controller={}",
        controller.label
    );
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if status >= 400 {
        return Err(anyhow!(
            "devmgr {cmd} {mac_lower} returned {status}: {}",
            text.chars().take(300).collect::<String>()
        ));
    }
    serde_json::from_str(&text).map_err(|e| anyhow!("parse devmgr response: {e}"))
}

/// Authenticate against the controller and return its sysinfo.
/// Used by the "Test connection" button to give the operator
/// immediate feedback that creds + URL work, plus the controller
/// version + site count for sanity.
pub async fn test_connection(
    secrets: &Arc<dyn SecretStore>,
    controller: &UnifiController,
) -> Result<UnifiSysInfo> {
    let client = login_client(secrets, controller).await?;
    let url = format!(
        "{}/api/s/{}/stat/sysinfo",
        controller.url.trim_end_matches('/'),
        controller.site_id
    );
    let resp = client.get(&url).send().await.context("GET sysinfo")?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if status >= 400 {
        return Err(anyhow!("sysinfo returned {status}: {text}"));
    }
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .context("parse sysinfo JSON")?;
    let data = parsed
        .get("data")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow!("unexpected sysinfo shape"))?;
    Ok(UnifiSysInfo {
        version: data
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_owned(),
        hostname: data
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        name: data
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiSysInfo {
    pub version: String,
    pub hostname: Option<String>,
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// Cross-reference (the scan-annotation entry point)
// ---------------------------------------------------------------------------

/// For each MAC in `macs`, return the first matching managed
/// device across all reachable controllers. Falls back to `None`
/// when no controller knows the MAC. Used by `active_scan` to
/// decorate scan rows with `ControllerStateRef` annotations.
///
/// Concurrent across controllers (one tokio task per controller)
/// with an overall timeout — so a slow/dead controller doesn't
/// block every scan from completing.
pub async fn cross_reference(
    secrets: &Arc<dyn SecretStore>,
    controllers: &[UnifiController],
    macs: &[String],
) -> HashMap<String, ControllerStateRef> {
    let macs_set: std::collections::HashSet<String> =
        macs.iter().map(|m| m.to_ascii_lowercase()).collect();
    let mut handles = Vec::new();
    for ctrl in controllers {
        let ctrl = ctrl.clone();
        let secrets = Arc::clone(secrets);
        handles.push(tokio::spawn(async move {
            (ctrl.id, ctrl.label.clone(), list_devices(&secrets, &ctrl).await)
        }));
    }
    let mut out: HashMap<String, ControllerStateRef> = HashMap::new();
    for h in handles {
        let (cid, clabel, result) = match h.await {
            Ok(t) => t,
            Err(e) => {
                warn!("unifi cross-reference join error: {e}");
                continue;
            }
        };
        let devices = match result {
            Ok(d) => d,
            Err(e) => {
                warn!("unifi controller {clabel} unreachable: {e:#}");
                continue;
            }
        };
        for d in devices {
            if !macs_set.contains(&d.mac) {
                continue;
            }
            // First controller to claim a MAC wins. Multiple
            // controllers claiming the same MAC is normally a
            // misconfiguration the operator wants to know
            // about, but we don't go out of our way to flag
            // it — the most recently-touched controller's
            // adoption state is what shows up.
            out.entry(d.mac.clone()).or_insert(ControllerStateRef {
                controller_id: cid,
                controller_label: clabel.clone(),
                state: d.state.clone(),
                adopted: d.adopted.unwrap_or(false),
                model: d.model.clone(),
                name: d.name.clone(),
            });
        }
    }
    out
}
