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
//! 1. Resolve the EAP password from Credential Manager. (A profile may
//!    carry a PSK for the Linux daemon's strongSwan path; Windows' IKEv2
//!    client authenticates with EAP alone and never asks for it.)
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
//!
//! A dial is the one bring-up that outlives the task running it: RAS owns
//! the connection, not this process. A connect cancelled mid-dial is
//! cleaned up by [`abandon`], which the session calls by profile id.

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

    /// Why the dialled connection is down, if Windows says it is.
    ///
    /// Only a definite "Disconnected" counts. A status query that fails —
    /// PowerShell slow to start on a loaded machine — says nothing about
    /// the tunnel, and tearing down a working one on that basis would be
    /// worse than reporting a dead one late.
    pub async fn dropped(&self) -> Option<String> {
        let name = self.active.lock().await.as_ref()?.connection_name.clone();
        match get_connection_status(&name).await {
            Ok(status) if status == "Disconnected" => Some(
                "The IKEv2 connection was dropped — the gateway ended it or the network went away"
                    .into(),
            ),
            _ => None,
        }
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
        connection_name(profile_id)
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

/// PowerShell-safe connection name built from the profile id.
fn connection_name(profile_id: &uuid::Uuid) -> String {
    format!("SuperMgr-FG-{}", profile_id.simple())
}

/// Hang up and unregister a dial that was cancelled before it finished.
///
/// The cancelled task never recorded the connection as active, so
/// `disconnect` does not know it exists; RAS may be mid-negotiation with
/// it all the same. Best effort, like every teardown: either step failing
/// usually means there was nothing left to undo.
pub async fn abandon(profile_id: &uuid::Uuid) {
    let name = connection_name(profile_id);
    info!(conn = %name, "abandoning a cancelled IKEv2 dial");
    let _ = rasdial_disconnect(&name).await;
    let _ = remove_connection(&name).await;
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
/// Register an IKEv2 + EAP-MSCHAPv2 connection.
///
/// Windows IKEv2 only accepts `Eap` or `MachineCertificate` — `MSChapv2` is
/// rejected with WIN32 87.  But bare `-AuthenticationMethod Eap` without an
/// explicit EAP type defaults to EAP-TLS (type 13), which tries to show a
/// certificate-selection dialog.  `rasdial` cannot display UI and exits with
/// error 703 (ERROR_INTERACTIVE_MODE).
///
/// Fix: supply `-EapConfigXmlStream` with EAP type 26 (MS-CHAPv2).  That pins
/// the inner auth method so `rasdial` can feed credentials non-interactively.
async fn register_connection(conn_name: &str, cfg: &FortiGateConfig) -> Result<(), VpnError> {
    let _ = remove_connection(conn_name).await;

    // PEAP (type 25) wrapping EAP-MSCHAPv2 (type 26).
    //
    // Windows IKEv2 EAP requires PEAP as the outer method; raw type-26
    // standalone XML is rejected by the EAP subsystem with
    // "Failed to generate the EAP Configuration" (WIN32 1).
    //
    // DisableUserPromptForServerValidation=true + PerformServerValidation=false
    // prevent an interactive certificate-trust dialog even if the FortiGate
    // presents a self-signed or private-CA certificate.
    //
    // All attribute values use double quotes, which are safe inside the
    // PowerShell single-quoted string wrapper.
    let eap_xml = concat!(
        r#"<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">"#,
        r#"<EapMethod>"#,
        r#"<Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type>"#,
        r#"<VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>"#,
        r#"<VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>"#,
        r#"<AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>"#,
        r#"</EapMethod>"#,
        r#"<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">"#,
        r#"<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">"#,
        r#"<Type>25</Type>"#,
        r#"<EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">"#,
        r#"<ServerValidation>"#,
        r#"<DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>"#,
        r#"<ServerNames></ServerNames>"#,
        r#"</ServerValidation>"#,
        r#"<FastReconnect>true</FastReconnect>"#,
        r#"<InnerEapOptional>false</InnerEapOptional>"#,
        r#"<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">"#,
        r#"<Type>26</Type>"#,
        r#"<EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">"#,
        r#"<UseWinLogonCredentials>false</UseWinLogonCredentials>"#,
        r#"</EapType>"#,
        r#"</Eap>"#,
        r#"<EnableQuarantineChecks>false</EnableQuarantineChecks>"#,
        r#"<RequireCryptoBinding>false</RequireCryptoBinding>"#,
        r#"<PeapExtensions>"#,
        r#"<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</PerformServerValidation>"#,
        r#"<AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</AcceptServerName>"#,
        r#"</PeapExtensions>"#,
        r#"</EapType>"#,
        r#"</Eap>"#,
        r#"</Config>"#,
        r#"</EapHostConfig>"#,
    );

    let cmd = format!(
        "$xml = [xml]'{eap_xml}'; \
         Add-VpnConnection \
           -Name '{name}' \
           -ServerAddress '{host}' \
           -TunnelType Ikev2 \
           -EncryptionLevel Required \
           -AuthenticationMethod Eap \
           -EapConfigXmlStream $xml \
           -RememberCredential \
           -AllUserConnection \
           -Force",
        eap_xml = eap_xml,
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
        .kill_on_drop(true)
        .output()
        .await
        .map_err(VpnError::Io)?;
    if output.status.success() {
        return Ok(());
    }
    // rasdial reports on stdout, not stderr, and exits with the RAS error
    // number. Reading only stderr is why a failed dial used to say nothing.
    let code = output.status.code().unwrap_or(-1);
    let printed = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Err(ras_error(code, &printed))
}

/// Turn a RAS error into what an operator can act on.
///
/// The common IKEv2 failures each have one usual cause, and Windows' own
/// text for them ("The network connection between your computer and the
/// VPN server could not be established because the remote server is not
/// responding") rarely names it.
fn ras_error(code: i32, printed: &str) -> VpnError {
    let known = match code {
        691 => return VpnError::PermissionDenied("The gateway rejected the username or password"),
        809 => Some(
            "The gateway did not answer. IKEv2 needs UDP ports 500 and 4500 open \
             between this PC and the gateway."
                .to_owned(),
        ),
        812 => Some(
            "The gateway's policy refused this connection. Check that EAP-MSCHAPv2 \
             is allowed for this user."
                .to_owned(),
        ),
        868 => Some("The gateway's name could not be looked up.".to_owned()),
        13801 => Some(
            "Windows does not trust the gateway's certificate. Import the CA that \
             issued it into the computer's Trusted Root Certification Authorities."
                .to_owned(),
        ),
        13806 => Some("Windows found no machine certificate to authenticate with.".to_owned()),
        13868 => Some(
            "Windows and the gateway share no IKE proposal. Add one Windows offers to \
             the gateway's phase 1, such as AES256-SHA256 with DH group 14."
                .to_owned(),
        ),
        _ => None,
    };
    let message = known
        .map(|hint| format!("{hint} (RAS error {code})"))
        .or_else(|| {
            printed
                .lines()
                .map(str::trim)
                .find(|l| l.starts_with("Remote Access error"))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("rasdial failed with RAS error {code}"));
    VpnError::Subprocess {
        code,
        stderr: message,
    }
}

async fn rasdial_disconnect(conn_name: &str) -> Result<(), VpnError> {
    let output = Command::new("rasdial.exe")
        .arg(conn_name)
        .arg("/disconnect")
        .kill_on_drop(true)
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

#[cfg(test)]
mod tests {
    use super::{ras_error, VpnError};

    fn message(e: VpnError) -> String {
        match e {
            VpnError::Subprocess { stderr, .. } => stderr,
            other => other.to_string(),
        }
    }

    #[test]
    fn a_known_ras_error_names_its_usual_cause() {
        let m = message(ras_error(
            809,
            "Remote Access error 809 - The network connection ...",
        ));
        assert!(m.contains("UDP ports 500 and 4500"), "{m}");
        assert!(m.contains("809"), "{m}");
    }

    #[test]
    fn a_rejected_password_is_an_authentication_failure() {
        assert!(matches!(ras_error(691, ""), VpnError::PermissionDenied(_)));
    }

    #[test]
    fn an_unknown_ras_error_keeps_windows_own_words() {
        // rasdial prints on stdout; this is the line that used to be lost.
        let printed = "Connecting to SuperMgr-FG-x...\n\
                       Remote Access error 720 - A connection to the remote computer could not be completed.\n\
                       For more help on this error:";
        let m = message(ras_error(720, printed));
        assert!(m.starts_with("Remote Access error 720"), "{m}");
    }

    #[test]
    fn silence_still_yields_the_error_number() {
        assert!(message(ras_error(4242, "")).contains("4242"));
    }
}
