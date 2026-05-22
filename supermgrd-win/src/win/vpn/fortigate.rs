//! FortiGate / generic IKEv2 backend (Windows).
//!
//! Drives the Windows built-in **RAS IKEv2** stack via PowerShell
//! cmdlets. The `FortiGateConfig` profile type maps onto a standard
//! IKEv2-with-EAP-MSCHAPv2 connection that Windows can dial natively —
//! no third-party client required.
//!
//! # When this works
//!
//! Modern FortiGate deployments that present a standards-compliant IKEv2
//! IKE_AUTH with EAP-MSCHAPv2 authentication and a PSK for the IKE SA.
//! That is the common case for greenfield FortiGate rollouts and for
//! Azure VPN gateways configured for "IKEv2 with built-in client".
//!
//! # When this does **not** work
//!
//! - FortiGate IPsec with XAuth + mode-config (legacy IKEv1 aggressive
//!   mode). Windows native IKEv2 doesn't speak it. Bundle FortiClient
//!   VPN free edition for those — tracked separately.
//! - FortiClient SSL VPN. Use `openfortivpn` instead.
//!
//! # Lifecycle
//!
//! Connect:
//! 1. Resolve PSK + EAP password from Credential Manager.
//! 2. `Add-VpnConnection` to register the connection (or replace any
//!    existing one with the same name).
//! 3. `rasdial <name> <user> <password>` to dial up.
//! 4. Poll `(Get-VpnConnection ...).ConnectionStatus` until `Connected`
//!    or we time out.
//!
//! Disconnect:
//! 1. `rasdial <name> /disconnect`.
//! 2. `Remove-VpnConnection -Name <name> -Force` so a future connect
//!    can re-register cleanly.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{process::Command, sync::Mutex, time::sleep};
use tracing::{info, warn};

use supermgr_core::keyring::SecretStore;
use supermgr_core::vpn::profile::{FortiGateConfig, Profile, ProfileConfig};

use super::{VpnBackend, VpnError};

/// Connection-status poll interval.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Cap on dial-up time. Windows IKEv2 typically completes in 2–6 s;
/// 30 s is comfortable for slow gateways and CRL-check timeouts.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Active IKEv2 tunnel — just the connection name (which is also how
/// PowerShell identifies it). The profile id is kept for status echo.
struct FgActive {
    profile_id: uuid::Uuid,
    connection_name: String,
}

/// Windows FortiGate / IKEv2 backend.
pub struct FortiGateBackend {
    secret_store: Option<Arc<dyn SecretStore>>,
    active: Mutex<Option<FgActive>>,
}

impl FortiGateBackend {
    /// Construct with a secret store. Required for any real connect
    /// (PSK + EAP both come from it). `Default` leaves it `None` so
    /// `DaemonState::load` can build the backend without knowing the
    /// secret store yet.
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

impl Default for FortiGateBackend {
    fn default() -> Self {
        Self {
            secret_store: None,
            active: Mutex::new(None),
        }
    }
}

impl FortiGateBackend {
    /// PowerShell-safe connection name built from the profile id.
    /// Windows VPN connection names are case-insensitive; the
    /// simple-form UUID keeps the name within the allowed charset.
    fn connection_name(profile_id: &uuid::Uuid) -> String {
        format!("SuperMgr-FG-{}", profile_id.simple())
    }

    async fn bring_up(&self, profile: &Profile) -> Result<(), VpnError> {
        if let Some(prev) = self.active.lock().await.take() {
            tear_down(prev).await;
        }

        let cfg = match &profile.config {
            ProfileConfig::FortiGate(c) => c,
            _ => {
                return Err(VpnError::MissingDependency(
                    "profile is not a FortiGate profile".into(),
                ));
            }
        };

        let store = self.secret_store.as_ref().ok_or_else(|| {
            VpnError::MissingDependency(
                "FortiGate backend has no secret store; cannot resolve EAP password".into(),
            )
        })?;
        let password = retrieve_string(store.as_ref(), &cfg.password, "EAP password").await?;

        let conn_name = Self::connection_name(&profile.id);
        register_connection(&conn_name, cfg).await?;
        rasdial_connect(&conn_name, &cfg.username, &password).await?;

        // Poll until Connected — rasdial returns when the dial-up
        // attempt has been initiated, not when the tunnel is fully up.
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() >= DIAL_TIMEOUT {
                let _ = rasdial_disconnect(&conn_name).await;
                let _ = remove_connection(&conn_name).await;
                return Err(VpnError::Subprocess {
                    code: -1,
                    stderr: format!(
                        "IKEv2 connection did not reach Connected within {DIAL_TIMEOUT:?}"
                    ),
                });
            }
            match get_connection_status(&conn_name).await {
                Ok(s) if s == "Connected" => break,
                Ok(s) if s == "Disconnected" && start.elapsed() > Duration::from_secs(2) => {
                    let _ = remove_connection(&conn_name).await;
                    return Err(VpnError::Subprocess {
                        code: -1,
                        stderr: "IKEv2 dial-up failed (status went back to Disconnected)".into(),
                    });
                }
                _ => {}
            }
            sleep(POLL_INTERVAL).await;
        }

        info!(profile_id = %profile.id, %conn_name, "IKEv2 tunnel up");
        *self.active.lock().await = Some(FgActive {
            profile_id: profile.id,
            connection_name: conn_name,
        });
        Ok(())
    }

    async fn bring_down(&self) -> Result<(), VpnError> {
        let active = self.active.lock().await.take();
        match active {
            Some(a) => {
                tear_down(a).await;
                Ok(())
            }
            None => Err(VpnError::NotImplemented("no active IKEv2 tunnel")),
        }
    }
}

#[async_trait]
impl VpnBackend for FortiGateBackend {
    async fn connect(&self, profile_json: &str) -> Result<(), VpnError> {
        let profile: Profile = serde_json::from_str(profile_json).map_err(|e| {
            VpnError::MissingDependency(format!("parse FortiGate profile JSON: {e}"))
        })?;
        self.bring_up(&profile).await
    }

    async fn disconnect(&self) -> Result<(), VpnError> {
        self.bring_down().await
    }

    async fn status(&self) -> Result<String, VpnError> {
        let guard = self.active.lock().await;
        if let Some(a) = guard.as_ref() {
            Ok(serde_json::json!({
                "state": "Connected",
                "backend": "fortigate-ikev2",
                "profile_id": a.profile_id.to_string(),
                "connection_name": a.connection_name,
            })
            .to_string())
        } else {
            Ok(r#"{"state":"Disconnected","backend":"fortigate"}"#.to_owned())
        }
    }
}

// ---------------------------------------------------------------------------
// PowerShell helpers
// ---------------------------------------------------------------------------

async fn retrieve_string(
    store: &dyn SecretStore,
    secret_ref: &supermgr_core::vpn::profile::SecretRef,
    what: &str,
) -> Result<String, VpnError> {
    let bytes = store
        .retrieve(secret_ref.label())
        .await
        .map_err(|e| VpnError::MissingDependency(format!("{what} lookup: {e}")))?;
    std::str::from_utf8(&bytes)
        .map(str::to_owned)
        .map_err(|_| VpnError::MissingDependency(format!("stored {what} is not valid UTF-8")))
}

/// Register the VPN connection. Idempotent — replaces any existing
/// connection with the same name first.
///
/// IKEv2 connections on Windows require `-AuthenticationMethod MSChapv2`
/// (which the RAS stack maps to EAP-MSCHAPv2) so that `rasdial` can supply
/// username/password non-interactively.  Using bare `-AuthenticationMethod Eap`
/// without a matching `Set-EapConfiguration` makes Windows default to EAP-TLS,
/// which requires an interactive certificate-selection dialog and causes
/// `rasdial` to exit with ERROR_INTERACTIVE_MODE (703).
async fn register_connection(conn_name: &str, cfg: &FortiGateConfig) -> Result<(), VpnError> {
    let _ = remove_connection(conn_name).await;
    let cmd = format!(
        "Add-VpnConnection -Name '{name}' \
            -ServerAddress '{host}' \
            -TunnelType Ikev2 \
            -EncryptionLevel Required \
            -AuthenticationMethod MSChapv2 \
            -RememberCredential \
            -AllUserConnection \
            -Force",
        name = ps_escape(conn_name),
        host = ps_escape(&cfg.host),
    );
    run_powershell(&cmd).await
}

/// Tear the registered connection down. Best effort — if it doesn't
/// exist the cmdlet errors, which we ignore.
async fn remove_connection(conn_name: &str) -> Result<(), VpnError> {
    let cmd = format!(
        "Remove-VpnConnection -Name '{name}' -AllUserConnection -Force",
        name = ps_escape(conn_name),
    );
    let _ = run_powershell(&cmd).await;
    Ok(())
}

async fn rasdial_connect(conn_name: &str, username: &str, password: &str) -> Result<(), VpnError> {
    let output = Command::new("rasdial.exe")
        .arg(conn_name)
        .arg(username)
        .arg(password)
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

async fn rasdial_disconnect(conn_name: &str) -> Result<(), VpnError> {
    let output = Command::new("rasdial.exe")
        .arg(conn_name)
        .arg("/disconnect")
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

/// PowerShell emits `(Get-VpnConnection ...).ConnectionStatus` as a
/// bare string (e.g. `Connected`, `Disconnected`, `Connecting`).
async fn get_connection_status(conn_name: &str) -> Result<String, VpnError> {
    let cmd = format!(
        "(Get-VpnConnection -AllUserConnection -Name '{name}' -ErrorAction Stop).ConnectionStatus",
        name = ps_escape(conn_name),
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(&cmd)
        .output()
        .await
        .map_err(VpnError::Io)?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        Err(VpnError::Subprocess {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

async fn run_powershell(cmd: &str) -> Result<(), VpnError> {
    let output = Command::new("powershell.exe")
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

/// Escape single quotes for PowerShell single-quoted string literals.
/// Inside single quotes the only special character is `'`, which is
/// escaped by doubling it.
fn ps_escape(s: &str) -> String {
    s.replace('\'', "''")
}

async fn tear_down(active: FgActive) {
    info!(profile_id = %active.profile_id, conn = %active.connection_name, "tearing down IKEv2 tunnel");
    if let Err(e) = rasdial_disconnect(&active.connection_name).await {
        warn!("rasdial /disconnect failed: {e:#}");
    }
    if let Err(e) = remove_connection(&active.connection_name).await {
        warn!("Remove-VpnConnection failed: {e:#}");
    }
}
