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

/// A configured UniFi controller. The struct is the canonical
/// on-disk record (one TOML file per controller); the password
/// is stored separately in the keychain.
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
    pub username: String,
    /// Keychain reference for the password.
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

/// Build a logged-in `reqwest::Client` for a given controller.
/// The cookie jar carries the auth session forward across
/// subsequent calls. We use `danger_accept_invalid_certs` because
/// UniFi controllers ship with self-signed certs out of the box;
/// the controller's URL is the trust anchor here, not the cert.
async fn login_client(
    secrets: &Arc<dyn SecretStore>,
    controller: &UnifiController,
) -> Result<reqwest::Client> {
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
    if status >= 400 {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!(
            "UniFi login to {} failed ({status}): {text}",
            controller.url
        ));
    }
    Ok(client)
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
