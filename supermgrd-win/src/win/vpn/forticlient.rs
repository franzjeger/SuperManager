//! FortiClient SSL VPN backend (Windows) — drives `openfortivpn`.
//!
//! [openfortivpn](https://github.com/adrienverge/openfortivpn) is the
//! open-source FortiGate SSL VPN client. Upstream does not provide a
//! Windows build. This backend is experimental and unavailable in the
//! standard installer until a compatible Windows client is integrated.
//!
//! # Lifecycle
//!
//! 1. Locate `openfortivpn.exe` (env var `OPENFORTIVPN_EXE`, `%PATH%`,
//!    or `%ProgramFiles%\SuperManager\bin\openfortivpn.exe` from the MSI).
//! 2. Resolve the user's password from Credential Manager.
//! 3. Spawn `openfortivpn <host>:<port> -u <user>` with `--pppd-no-peerdns`
//!    and `--no-routes` (split-tunnel) or `--set-routes` (full-tunnel),
//!    feeding the password on stdin.
//! 4. Stream stdout/stderr, looking for `Tunnel is up and running.` or a
//!    fatal error (`Could not authenticate`, `Connection refused`).
//! 5. After tunnel-up, optionally push DNS servers via PowerShell on the
//!    detected PPP interface.
//!
//! # TODO
//!
//! Integrate and validate a supported Windows SSL VPN client.

use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{
    io::AsyncWriteExt as _,
    process::{Child, Command},
    sync::Mutex,
    time::timeout,
};
use tracing::{info, warn};

use supermgr_core::keyring::SecretStore;
use supermgr_core::vpn::profile::{Profile, ProfileConfig};

use super::{output, VpnBackend, VpnError};

/// Soft cap on bring-up time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Fallback locations probed when `OPENFORTIVPN_EXE` is unset and the
/// binary is not on `%PATH%`. These are legacy/custom deployment paths;
/// the standard installer does not supply a Windows openfortivpn binary.
const DEFAULT_LOCATIONS: &[&str] = &[
    r"C:\Program Files\SuperManager\bin\openfortivpn.exe",
    r"C:\ProgramData\chocolatey\bin\openfortivpn.exe",
];

/// Marker in openfortivpn's stdout that signals a usable tunnel.
const SUCCESS_MARKER: &str = "Tunnel is up and running.";

/// Substring markers in stdout/stderr that signal fatal failures. The
/// first match becomes the error message surfaced to the caller.
const FATAL_MARKERS: &[&str] = &[
    "Could not authenticate to gateway",
    "Could not parse server response",
    "Connection refused",
    "Authentication failed",
];

/// Active tunnel state. Mirrors the OpenVPN/Azure backend pattern.
struct FcActive {
    profile_id: uuid::Uuid,
    child: Child,
    /// PPP/Wintun interface name openfortivpn picked. Populated during
    /// bring-up by stdout sniffing; used to revert DNS.
    iface: Option<String>,
    /// Whether we pushed DNS that needs reverting.
    dns_overridden: bool,
    /// What the client has been printing, for when it stops by itself.
    tail: output::Tail,
}

/// Windows openfortivpn backend.
pub struct ForticlientBackend {
    secret_store: Option<Arc<dyn SecretStore>>,
    active: Mutex<Option<FcActive>>,
}

impl ForticlientBackend {
    /// Construct with a secret store. Required for any real connect.
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

    /// Why the tunnel's client exited, if it has. `None` while it runs, and
    /// when there is no tunnel.
    pub async fn exited(&self) -> Option<String> {
        let mut guard = self.active.lock().await;
        let active = guard.as_mut()?;
        match active.child.try_wait() {
            Ok(Some(status)) => Some(output::exit_reason("SSL VPN", status, &active.tail)),
            _ => None,
        }
    }
}

impl Default for ForticlientBackend {
    fn default() -> Self {
        Self {
            secret_store: None,
            active: Mutex::new(None),
        }
    }
}

#[async_trait]
impl VpnBackend for ForticlientBackend {
    async fn connect(&self, profile_json: &str) -> Result<(), VpnError> {
        let profile: Profile = serde_json::from_str(profile_json).map_err(|e| {
            VpnError::MissingDependency(format!("parse FortiClient SSL VPN profile JSON: {e}"))
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
            None => Err(VpnError::NotImplemented("no active FortiClient tunnel")),
        }
    }

    async fn status(&self) -> Result<String, VpnError> {
        let guard = self.active.lock().await;
        if let Some(a) = guard.as_ref() {
            Ok(serde_json::json!({
                "state": "Connected",
                "backend": "forticlient-sslvpn",
                "profile_id": a.profile_id.to_string(),
            })
            .to_string())
        } else {
            Ok(r#"{"state":"Disconnected","backend":"forticlient-sslvpn"}"#.to_owned())
        }
    }
}

impl ForticlientBackend {
    async fn bring_up(&self, profile: &Profile) -> Result<(), VpnError> {
        if let Some(prev) = self.active.lock().await.take() {
            tear_down(prev).await;
        }

        let cfg = match &profile.config {
            ProfileConfig::ForticlientSslvpn(c) => c.clone(),
            _ => {
                return Err(VpnError::MissingDependency(
                    "profile is not a FortiClient SSL VPN profile".into(),
                ));
            }
        };

        let store = self.secret_store.as_ref().ok_or_else(|| {
            VpnError::MissingDependency(
                "FortiClient backend has no secret store; cannot resolve the password".into(),
            )
        })?;
        let password_bytes = store.retrieve(cfg.password.label()).await.map_err(|e| {
            VpnError::MissingDependency(format!(
                "FortiClient password lookup ({}): {e}",
                cfg.password.label()
            ))
        })?;
        let password = std::str::from_utf8(&password_bytes)
            .map_err(|_| {
                VpnError::MissingDependency("stored FortiClient password is not valid UTF-8".into())
            })?
            .to_owned();

        let openfortivpn_exe = locate_openfortivpn()?;
        let gateway = format!("{}:{}", cfg.host, cfg.port);

        let mut command = Command::new(&openfortivpn_exe);
        command
            .arg(&gateway)
            .arg("-u")
            .arg(&cfg.username)
            // Stop pppd from advertising the gateway's DNS as the system
            // resolver — we manage DNS push ourselves via PowerShell.
            .arg("--pppd-no-peerdns")
            .arg("--pppd-use-peerdns=no");

        if profile.full_tunnel {
            command.arg("--set-routes");
        } else {
            command.arg("--no-routes");
        }
        if let Some(fp) = &cfg.trusted_cert {
            command.arg("--trusted-cert").arg(fp);
        }

        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // A connect cancelled mid-handshake must not leave the client
            // running with the adapter.
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(VpnError::Io)?;
        info!(?openfortivpn_exe, gateway, user = %cfg.username, "spawned openfortivpn");

        // Feed the password on stdin (newline-terminated). Never put it on
        // argv — that would be visible to anyone with a process listing.
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(format!("{password}\n").as_bytes())
                .await
                .map_err(VpnError::Io)?;
            stdin.flush().await.map_err(VpnError::Io)?;
            drop(stdin);
        }

        // Both streams onto one channel, so the success marker and a fatal
        // error are watched in lockstep — and read for the client's whole
        // life, so it never blocks on a full pipe.
        let (tail, mut rx) = output::capture(&mut child);

        let mut iface: Option<String> = None;
        let mut connected = false;
        let mut last_err: Option<String> = None;
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let Ok(Some(line)) = timeout(remaining, rx.recv()).await else {
                break;
            };
            if let Some(name) = extract_ppp_iface(&line) {
                iface = Some(name);
            }
            if line.contains(SUCCESS_MARKER) {
                connected = true;
                break;
            }
            for marker in FATAL_MARKERS {
                if line.contains(marker) {
                    last_err = Some(line.clone());
                }
            }
            if line.contains("Gateway certificate validation failed") {
                last_err = Some(line.clone());
            }
            if line.contains("--trusted-cert") {
                if let Some(fp) = line.split("--trusted-cert").nth(1) {
                    let fp = fp.trim();
                    if !fp.is_empty() {
                        let _ = child.kill().await;
                        return Err(VpnError::TofuCertificateRequired(fp.to_string()));
                    }
                }
            }
        }

        if !connected {
            let _ = child.kill().await;
            return Err(match last_err.or_else(|| tail.reason()) {
                Some(msg)
                    if msg.contains("Authentication failed")
                        || msg.contains("Could not authenticate") =>
                {
                    VpnError::PermissionDenied("openfortivpn auth rejected")
                }
                Some(msg) => VpnError::Subprocess {
                    code: -1,
                    stderr: msg,
                },
                None => VpnError::Subprocess {
                    code: -1,
                    stderr: format!(
                        "openfortivpn did not reach \"{SUCCESS_MARKER}\" within {HANDSHAKE_TIMEOUT:?}"
                    ),
                },
            });
        }

        // Stop listening; `output` keeps reading until the client exits.
        drop(rx);
        info!(profile_id = %profile.id, iface = ?iface, "openfortivpn tunnel up");

        // DNS push, best-effort. If openfortivpn already negotiated DNS
        // through PPP we don't override.
        let mut dns_overridden = false;
        if profile.push_dns && !cfg.dns_servers.is_empty() {
            if let Some(name) = iface.as_deref() {
                match push_dns(name, &cfg.dns_servers).await {
                    Ok(()) => dns_overridden = true,
                    Err(e) => warn!("FortiClient DNS push failed for {name}: {e:#}"),
                }
            } else {
                warn!("openfortivpn: no PPP iface parsed; DNS not pushed");
            }
        }

        *self.active.lock().await = Some(FcActive {
            profile_id: profile.id,
            child,
            iface,
            dns_overridden,
            tail,
        });
        Ok(())
    }
}

async fn tear_down(mut active: FcActive) {
    info!(profile_id = %active.profile_id, "tearing down openfortivpn tunnel");
    // openfortivpn responds to SIGTERM by gracefully shutting down PPP.
    // On Windows there's no Ctrl-C-friendly entry point we can drive
    // from outside the process, so we fall back to a hard kill —
    // openfortivpn cleans up the Wintun adapter when its process exits.
    let _ = active.child.kill().await;
    let _ = active.child.wait().await;
    if active.dns_overridden {
        if let Some(name) = active.iface.as_deref() {
            if let Err(e) = reset_dns(name).await {
                warn!("FortiClient DNS reset on {name} failed: {e:#}");
            }
        }
    }
}

/// Whether an SSL VPN client can be found, and what to tell the operator
/// when it cannot.
pub fn availability() -> Result<(), String> {
    locate_openfortivpn().map(|_| ()).map_err(|e| match e {
        VpnError::MissingDependency(message) => message,
        other => other.to_string(),
    })
}

fn locate_openfortivpn() -> Result<PathBuf, VpnError> {
    if let Some(p) = std::env::var_os("OPENFORTIVPN_EXE") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
    }
    if let Ok(p) = which::which("openfortivpn.exe") {
        return Ok(p);
    }
    for fallback in DEFAULT_LOCATIONS {
        let path = PathBuf::from(fallback);
        if path.exists() {
            return Ok(path);
        }
    }
    Err(VpnError::MissingDependency(
        "FortiClient SSL VPN is unavailable in this Windows release. \
         A compatible Windows VPN client has not been integrated; \
         reinstalling SuperManager will not add one."
            .into(),
    ))
}

/// Sniff the PPP/Wintun interface name out of openfortivpn's stdout.
///
/// openfortivpn formats vary between versions; we recognise three:
///
/// ```text
/// Started PPP interface ppp0.
/// Setup interface: Wintun via ppp\<guid> as SuperFortiSSL
/// Got addresses: [192.0.2.5]
/// ```
fn extract_ppp_iface(line: &str) -> Option<String> {
    if let Some(start) = line.find("Started PPP interface ") {
        let rest = &line[start + "Started PPP interface ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '.')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    if let Some(start) = line.find("Setup interface: Wintun via ") {
        let rest = &line[start + "Setup interface: Wintun via ".len()..];
        if let Some(idx) = rest.find(" as ") {
            let after = &rest[idx + " as ".len()..];
            let alias: String = after.chars().take_while(|c| !c.is_whitespace()).collect();
            if !alias.is_empty() {
                return Some(alias);
            }
        }
        let chunk: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
        if !chunk.is_empty() {
            return Some(chunk);
        }
    }
    None
}

async fn push_dns(adapter: &str, dns: &[std::net::IpAddr]) -> Result<(), VpnError> {
    let servers = dns
        .iter()
        .map(|ip| format!("'{ip}'"))
        .collect::<Vec<_>>()
        .join(",");
    let cmd = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({})",
        adapter.replace('\'', "''"),
        servers,
    );
    run_powershell(&cmd).await
}

async fn reset_dns(adapter: &str) -> Result<(), VpnError> {
    let cmd = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
        adapter.replace('\'', "''"),
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
