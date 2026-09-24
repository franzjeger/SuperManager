//! The one tunnel the daemon is responsible for, and what it is doing.
//!
//! # Why this exists
//!
//! `connect` used to run the whole bring-up inside the RPC. A WireGuard
//! adapter comes up in a second, but an OpenVPN handshake can take 45, an
//! IKEv2 dial 30, and an Azure sign-in waits up to twenty minutes for the
//! browser. For all of that time the request held the client's single pipe
//! connection — and the GUI has exactly one — so its status poll, its
//! refresh, and every button queued behind it. The window looked frozen,
//! said nothing about what was happening, and then either reported a
//! timeout at 120 seconds while the tunnel was still coming up, or reported
//! nothing at all.
//!
//! There was also nowhere for a failure to go. `get_status` asked each
//! backend whether it was up; a connect that failed left no trace, so the
//! only record of *why* was an RPC error the GUI might already have stopped
//! waiting for.
//!
//! # What it does instead
//!
//! The daemon now owns one [`VpnState`] — the same type, and the same JSON,
//! as the Linux daemon — and `connect` does three things: checks it is not
//! already busy, sets `Connecting`, and spawns the bring-up. It returns in
//! milliseconds. The spawned task moves the state to `Connected` or to
//! `Error` with the backend's own message, and `get_status` reports it.
//!
//! A connect in flight can be cancelled by `disconnect`, which is what makes
//! the Azure sign-in wait something an operator can walk away from.
//!
//! Once a tunnel is up, a watcher checks that it stays up. A client process
//! that exits, or a RAS connection the gateway drops, used to leave the
//! daemon reporting "connected" until someone clicked Disconnect; now the
//! state becomes an error that says the tunnel dropped, and why if the
//! client said.
//!
//! # Azure sign-in
//!
//! The daemon runs as `LocalSystem` in session 0, which has no desktop. Any
//! browser it starts is invisible. So the Azure backend no longer tries: it
//! publishes the sign-in URL here, `get_status` carries it as `auth_url`
//! while the connect is waiting, and the GUI — which runs in the user's own
//! session — opens it. The loopback redirect still lands on the daemon's
//! listener, because 127.0.0.1 is the same machine whichever session the
//! browser is in.

use std::{sync::Arc, time::Duration};

use chrono::Utc;
use serde_json::Value;
use tokio::{sync::Mutex, task::JoinHandle};
use tracing::{info, warn};
use uuid::Uuid;

use supermgr_core::protocol::RpcError;
use supermgr_core::vpn::profile::{Profile, ProfileConfig, ProfileSummary};
use supermgr_core::vpn::state::{ErrorCode, VpnState};

use super::{VpnBackend as _, VpnError};
use crate::win::daemon::DaemonState;

/// How often the watcher checks that a tunnel is still up.
const WATCH_INTERVAL: Duration = Duration::from_secs(5);

/// Checking a RAS connection costs a PowerShell start, so it happens every
/// this-many watcher ticks rather than every one.
const RAS_CHECK_EVERY: u32 = 6;

/// Where the Azure backend leaves a sign-in URL for the GUI to open.
///
/// A plain `std` mutex: it is held for one assignment or one clone, never
/// across an await.
pub type AuthPrompt = Arc<std::sync::Mutex<Option<String>>>;

/// A connect in flight: which profile, and the task doing it.
struct InFlight {
    profile_id: Uuid,
    handle: JoinHandle<()>,
}

/// The daemon's single VPN session.
pub struct Session {
    state: Mutex<VpnState>,
    in_flight: Mutex<Option<InFlight>>,
    auth_prompt: AuthPrompt,
    /// Backend label of whatever the state refers to, for the GUI.
    backend: Mutex<String>,
}

impl Session {
    /// A session with nothing connected, sharing `auth_prompt` with the
    /// Azure backend.
    pub fn new(auth_prompt: AuthPrompt) -> Self {
        Self {
            state: Mutex::new(VpnState::Disconnected),
            in_flight: Mutex::new(None),
            auth_prompt,
            backend: Mutex::new(String::new()),
        }
    }

    /// What `get_status` reports.
    pub async fn snapshot(&self) -> Value {
        let state = self.state.lock().await.clone();
        let backend = self.backend.lock().await.clone();
        let auth_url = self
            .auth_prompt
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .filter(|_| matches!(state, VpnState::Connecting { .. }));
        status_json(&state, &backend, auth_url.as_deref())
    }

    async fn set(&self, next: VpnState) {
        *self.state.lock().await = next;
    }

    async fn set_phase(&self, profile_id: Uuid, phase: &str) {
        let mut state = self.state.lock().await;
        if let VpnState::Connecting { profile_id: p, .. } = &*state {
            if *p == profile_id {
                *state = VpnState::Connecting {
                    profile_id,
                    since: Utc::now(),
                    phase: phase.to_owned(),
                };
            }
        }
    }

    fn clear_auth_prompt(&self) {
        if let Ok(mut g) = self.auth_prompt.lock() {
            *g = None;
        }
    }

    /// Start connecting `profile`, and return as soon as it has started.
    ///
    /// # Errors
    ///
    /// When a connect or disconnect is already in progress. Two bring-ups
    /// racing for one set of routes is how an operator ends up with neither.
    pub async fn begin_connect(
        self: &Arc<Self>,
        daemon: Arc<DaemonState>,
        profile: Profile,
    ) -> Result<(), RpcError> {
        if matches!(profile.config, ProfileConfig::Generic(_)) {
            return Err(RpcError::Backend(
                "Generic VPN profiles have no Windows backend".into(),
            ));
        }

        {
            // Check and claim in one critical section, so two clicks cannot
            // both pass the check.
            let mut state = self.state.lock().await;
            match &*state {
                // Asking for the tunnel that is already up is not a reason
                // to take it down and bring it back.
                VpnState::Connected { profile_id, .. } if *profile_id == profile.id => {
                    return Ok(())
                }
                VpnState::Connecting { .. } => {
                    return Err(RpcError::Backend(
                        "a connection is already in progress — disconnect to cancel it first"
                            .into(),
                    ))
                }
                VpnState::Disconnecting { .. } => {
                    return Err(RpcError::Backend(
                        "the previous tunnel is still closing — try again in a moment".into(),
                    ))
                }
                _ => {}
            }
            *state = VpnState::Connecting {
                profile_id: profile.id,
                since: Utc::now(),
                phase: "Starting".into(),
            };
        }
        *self.backend.lock().await = ProfileSummary::from(&profile).backend;
        self.clear_auth_prompt();

        let session = Arc::clone(self);
        let profile_id = profile.id;
        // Held until the handle is stored: a disconnect arriving between the
        // spawn and the store would otherwise find nothing to cancel, and
        // the bring-up would finish into a session the operator had closed.
        let mut in_flight = self.in_flight.lock().await;
        let handle = tokio::spawn(async move {
            let outcome = session.run_connect(&daemon, profile).await;
            session.clear_auth_prompt();
            match outcome {
                Ok((interface, profile)) => {
                    info!(%profile_id, interface, "tunnel up");
                    session
                        .set(VpnState::Connected {
                            profile_id,
                            since: Utc::now(),
                            interface,
                        })
                        .await;
                    // "Last connected" in the profile list. Best effort: the
                    // tunnel is up either way.
                    let mut p = profile;
                    p.last_connected_at = Some(Utc::now());
                    if let Err(e) = daemon.profile_store.save(p).await {
                        warn!(%profile_id, "could not record last-connected time: {e}");
                    }
                    tokio::spawn(Arc::clone(&session).watch(daemon, profile_id));
                }
                Err(e) => {
                    let (code, message) = describe(&e);
                    warn!(%profile_id, "connect failed: {message}");
                    session
                        .set(VpnState::Error {
                            profile_id: Some(profile_id),
                            code,
                            message,
                        })
                        .await;
                }
            }
        });
        *in_flight = Some(InFlight { profile_id, handle });
        Ok(())
    }

    /// The bring-up itself. Runs inside the spawned task.
    async fn run_connect(
        &self,
        daemon: &Arc<DaemonState>,
        profile: Profile,
    ) -> Result<(String, Profile), VpnError> {
        // One tunnel at a time, as on Linux: switching profiles closes the
        // old one first rather than stacking a second set of routes on it.
        if any_active(daemon).await {
            self.set_phase(profile.id, "Closing the previous tunnel")
                .await;
            if let Err(e) = teardown_active(daemon).await {
                warn!("closing the previous tunnel: {e}");
            }
        }

        self.set_phase(profile.id, phase_for(&profile.config)).await;
        let json = serde_json::to_string(&profile)
            .map_err(|e| VpnError::MissingDependency(format!("serialise profile: {e}")))?;

        let vpn = &daemon.vpn;
        let status = match &profile.config {
            ProfileConfig::WireGuard(_) => {
                vpn.wireguard.connect(&json).await?;
                vpn.wireguard.status().await?
            }
            ProfileConfig::OpenVpn(_) => {
                vpn.openvpn.connect(&json).await?;
                vpn.openvpn.status().await?
            }
            ProfileConfig::AzureVpn(_) => {
                vpn.ikev2.connect(&json).await?;
                vpn.ikev2.status().await?
            }
            ProfileConfig::FortiGate(_) => {
                vpn.fortigate.connect(&json).await?;
                vpn.fortigate.status().await?
            }
            ProfileConfig::ForticlientSslvpn(_) => {
                match vpn.forticlient.connect(&json).await {
                    Ok(()) => {}
                    Err(VpnError::TofuCertificateRequired(fp)) => {
                        // First contact with this gateway: pin the
                        // certificate it presented and go again. Same
                        // behaviour as before this moved here.
                        info!(profile_id = %profile.id, fp = %fp, "TOFU: pinning gateway certificate");
                        let mut pinned = profile.clone();
                        if let ProfileConfig::ForticlientSslvpn(cfg) = &mut pinned.config {
                            cfg.trusted_cert = Some(fp);
                        }
                        if let Err(e) = daemon.profile_store.save(pinned.clone()).await {
                            warn!("failed to persist pinned certificate: {e}");
                        }
                        let pinned_json = serde_json::to_string(&pinned).map_err(|e| {
                            VpnError::MissingDependency(format!("serialise profile: {e}"))
                        })?;
                        vpn.forticlient.connect(&pinned_json).await?;
                    }
                    Err(e) => return Err(e),
                }
                vpn.forticlient.status().await?
            }
            ProfileConfig::Generic(_) => {
                return Err(VpnError::NotImplemented("Generic VPN profiles"));
            }
        };
        Ok((interface_from(&status), profile))
    }

    /// Disconnect — or cancel a connect that has not finished.
    ///
    /// # Errors
    ///
    /// When the active backend's teardown fails. The state still ends up
    /// `Disconnected`, because the alternative is a GUI that insists a
    /// tunnel is up after the operator has asked for it to be gone.
    pub async fn disconnect(&self, daemon: &Arc<DaemonState>) -> Result<(), RpcError> {
        // Cancel a bring-up first. Dropping its future is what stops it:
        // WireGuard's adapter, and the OpenVPN / openfortivpn / Azure child
        // processes (`kill_on_drop`), are all released by being dropped.
        // IKEv2 is the exception — a RAS dial survives the process that
        // started it — so it gets hung up by name.
        if let Some(in_flight) = self.in_flight.lock().await.take() {
            if !in_flight.handle.is_finished() {
                info!(profile_id = %in_flight.profile_id, "cancelling connect in progress");
                in_flight.handle.abort();
                let _ = in_flight.handle.await;
                self.clear_auth_prompt();
                if let Ok(profile) = daemon.profile_store.get(in_flight.profile_id).await {
                    if matches!(profile.config, ProfileConfig::FortiGate(_)) {
                        super::fortigate::abandon(&in_flight.profile_id).await;
                    }
                }
            }
        }

        let closing = self.state.lock().await.profile_id();
        if let Some(profile_id) = closing {
            self.set(VpnState::Disconnecting { profile_id }).await;
        }
        let result = teardown_active(daemon).await;
        self.set(VpnState::Disconnected).await;
        result.map_err(|e| RpcError::Backend(describe(&e).1))
    }
}

impl Session {
    /// Watch a tunnel that is up, and report it when it goes down on its
    /// own. Returns once the state has moved on from this tunnel, whether
    /// because it dropped or because someone disconnected it.
    async fn watch(self: Arc<Self>, daemon: Arc<DaemonState>, profile_id: Uuid) {
        let mut interval = tokio::time::interval(WATCH_INTERVAL);
        interval.tick().await; // the first tick is immediate
        let mut tick: u32 = 0;
        loop {
            interval.tick().await;
            tick = tick.wrapping_add(1);
            if !self.is_connected_to(profile_id).await {
                return;
            }
            let Some(reason) = dropped(&daemon, tick).await else {
                continue;
            };
            warn!(%profile_id, "tunnel dropped: {reason}");
            // Release what the backend still holds — the adapter name, the
            // DNS override — so the next connect starts clean.
            if let Err(e) = teardown_active(&daemon).await {
                warn!("cleaning up after a dropped tunnel: {e}");
            }
            let mut state = self.state.lock().await;
            // A disconnect may have got here first; its state stands.
            if matches!(&*state, VpnState::Connected { profile_id: p, .. } if *p == profile_id) {
                *state = VpnState::Error {
                    profile_id: Some(profile_id),
                    code: ErrorCode::Unreachable,
                    message: reason,
                };
            }
            return;
        }
    }

    /// Whether `profile_id` is the tunnel that is up, coming up, or going
    /// down — the profile the daemon must not lose while it does.
    pub async fn is_busy_with(&self, profile_id: Uuid) -> bool {
        match &*self.state.lock().await {
            VpnState::Connecting { profile_id: p, .. }
            | VpnState::Connected { profile_id: p, .. }
            | VpnState::Disconnecting { profile_id: p } => *p == profile_id,
            VpnState::Disconnected | VpnState::Error { .. } => false,
        }
    }

    async fn is_connected_to(&self, profile_id: Uuid) -> bool {
        matches!(&*self.state.lock().await, VpnState::Connected { profile_id: p, .. } if *p == profile_id)
    }
}

/// Why the active tunnel is no longer up, if it is not.
async fn dropped(daemon: &Arc<DaemonState>, tick: u32) -> Option<String> {
    let vpn = &daemon.vpn;
    if let Some(reason) = vpn.openvpn.exited().await {
        return Some(reason);
    }
    if let Some(reason) = vpn.ikev2.exited().await {
        return Some(reason);
    }
    if let Some(reason) = vpn.forticlient.exited().await {
        return Some(reason);
    }
    if tick.is_multiple_of(RAS_CHECK_EVERY) {
        if let Some(reason) = vpn.fortigate.dropped().await {
            return Some(reason);
        }
    }
    None
}

/// What the operator is told is happening, per backend.
///
/// Azure's first phase is the sign-in, but that is replaced by the URL being
/// published — the GUI says "sign in" as soon as `auth_url` appears.
fn phase_for(config: &ProfileConfig) -> &'static str {
    match config {
        ProfileConfig::WireGuard(_) => "Bringing up the WireGuard adapter",
        ProfileConfig::OpenVpn(_) => "Negotiating with the OpenVPN server",
        ProfileConfig::AzureVpn(_) => "Signing in to Microsoft Entra ID",
        ProfileConfig::FortiGate(_) => "Dialling the IKEv2 gateway",
        ProfileConfig::ForticlientSslvpn(_) => "Negotiating with the SSL VPN gateway",
        ProfileConfig::Generic(_) => "Starting",
    }
}

/// The interface name a backend's status JSON reports, if any.
fn interface_from(status: &str) -> String {
    serde_json::from_str::<Value>(status)
        .ok()
        .and_then(|v| {
            ["adapter", "interface", "adapter_name"]
                .iter()
                .find_map(|k| v.get(*k).and_then(Value::as_str).map(str::to_owned))
        })
        .unwrap_or_default()
}

/// Whether any backend currently holds a tunnel.
async fn any_active(daemon: &Arc<DaemonState>) -> bool {
    let vpn = &daemon.vpn;
    vpn.wireguard.is_active().await
        || vpn.openvpn.is_active().await
        || vpn.fortigate.is_active().await
        || vpn.ikev2.is_active().await
        || vpn.forticlient.is_active().await
}

/// Tear down whichever backend holds a tunnel. At most one does.
///
/// A backend with nothing to tear down answers `NotImplemented("no active
/// … tunnel")`. Between the `is_active` check and the call, the watcher
/// and a disconnect can both reach the same tunnel; the second to arrive
/// finds it gone, which is the outcome both wanted, not a failure.
async fn teardown_active(daemon: &Arc<DaemonState>) -> Result<(), VpnError> {
    let vpn = &daemon.vpn;
    let result = if vpn.wireguard.is_active().await {
        vpn.wireguard.disconnect().await
    } else if vpn.openvpn.is_active().await {
        vpn.openvpn.disconnect().await
    } else if vpn.fortigate.is_active().await {
        vpn.fortigate.disconnect().await
    } else if vpn.ikev2.is_active().await {
        vpn.ikev2.disconnect().await
    } else if vpn.forticlient.is_active().await {
        vpn.forticlient.disconnect().await
    } else {
        Ok(())
    };
    match result {
        Err(VpnError::NotImplemented(_)) => Ok(()),
        other => other,
    }
}

/// A backend failure as the operator should read it.
///
/// The prefixes `map_vpn_err` adds for the RPC transport ("backend failure:
/// win32: …") are for logs. What lands in the GUI is the reason, first.
pub fn describe(e: &VpnError) -> (ErrorCode, String) {
    match e {
        VpnError::NotImplemented(what) => (
            ErrorCode::Internal,
            format!("Not available on Windows: {what}"),
        ),
        VpnError::Subprocess { code, stderr } => {
            let detail = stderr.trim();
            let message = if detail.is_empty() {
                format!("The VPN client exited with code {code}")
            } else {
                detail.to_owned()
            };
            (ErrorCode::SubprocessError, message)
        }
        VpnError::MissingDependency(msg) => (ErrorCode::ConfigError, msg.clone()),
        VpnError::Win32(msg) => (ErrorCode::KernelError, msg.clone()),
        VpnError::PermissionDenied(msg) => (ErrorCode::AuthFailed, (*msg).to_owned()),
        VpnError::TofuCertificateRequired(fp) => (
            ErrorCode::AuthFailed,
            format!("The gateway's certificate needs approving: {fp}"),
        ),
        VpnError::Io(e) => (ErrorCode::Internal, e.to_string()),
    }
}

/// The JSON `get_status` returns.
///
/// Exactly `VpnState`'s own serialisation — the Linux daemon's shape, so the
/// MCP server and anything else reading it sees one format on both
/// platforms — plus two fields the Windows GUI needs: the backend label,
/// and the sign-in URL while an Azure connect is waiting for one.
pub fn status_json(state: &VpnState, backend: &str, auth_url: Option<&str>) -> Value {
    let mut v = serde_json::to_value(state)
        .unwrap_or_else(|_| serde_json::json!({ "state": "disconnected" }));
    if let Some(obj) = v.as_object_mut() {
        if !matches!(state, VpnState::Disconnected) && !backend.is_empty() {
            obj.insert("backend".into(), Value::String(backend.to_owned()));
        }
        if let Some(url) = auth_url {
            obj.insert("auth_url".into(), Value::String(url.to_owned()));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_json_is_the_linux_daemons_shape() {
        // One format on both platforms. The MCP server passes this straight
        // to the model, and a model that learned "connected" on Linux should
        // not meet "Connected" on Windows.
        let id = Uuid::new_v4();
        let v = status_json(
            &VpnState::Connected {
                profile_id: id,
                since: Utc::now(),
                interface: "wg0".into(),
            },
            "WireGuard",
            None,
        );
        assert_eq!(v["state"], "connected");
        assert_eq!(v["profile_id"], id.to_string());
        assert_eq!(v["interface"], "wg0");
        assert_eq!(v["backend"], "WireGuard");
    }

    #[test]
    fn an_error_carries_its_message_to_the_gui() {
        // The old status had nowhere to put this. A connect that failed left
        // `get_status` saying "Disconnected", indistinguishable from never
        // having tried.
        let v = status_json(
            &VpnState::Error {
                profile_id: Some(Uuid::new_v4()),
                code: ErrorCode::AuthFailed,
                message: "AUTH_FAILED".into(),
            },
            "OpenVPN",
            None,
        );
        assert_eq!(v["state"], "error");
        assert_eq!(v["message"], "AUTH_FAILED");
    }

    #[test]
    fn the_sign_in_url_is_offered_only_while_connecting() {
        let id = Uuid::new_v4();
        let connecting = VpnState::Connecting {
            profile_id: id,
            since: Utc::now(),
            phase: "Signing in".into(),
        };
        let v = status_json(
            &connecting,
            "Azure VPN",
            Some("https://login.microsoftonline.com/x"),
        );
        assert_eq!(v["auth_url"], "https://login.microsoftonline.com/x");
    }

    #[test]
    fn a_disconnected_status_names_no_backend() {
        // "Disconnected, backend WireGuard" reads as a WireGuard tunnel that
        // went down, not as nothing having been connected.
        let v = status_json(&VpnState::Disconnected, "WireGuard", None);
        assert_eq!(v["state"], "disconnected");
        assert!(v.get("backend").is_none());
    }

    #[test]
    fn the_interface_is_found_under_any_name_a_backend_uses() {
        assert_eq!(interface_from(r#"{"adapter":"wg-home"}"#), "wg-home");
        assert_eq!(interface_from(r#"{"interface":"tun0"}"#), "tun0");
        assert_eq!(interface_from(r#"{"state":"Connected"}"#), "");
        assert_eq!(interface_from("not json"), "");
    }

    #[test]
    fn a_certificate_to_approve_keeps_its_fingerprint_and_is_not_success() {
        let (code, msg) = describe(&VpnError::TofuCertificateRequired("sha256:example".into()));
        assert_eq!(code, ErrorCode::AuthFailed);
        assert!(msg.contains("sha256:example"), "{msg}");
    }

    #[test]
    fn failures_lead_with_the_reason() {
        let (code, msg) = describe(&VpnError::Subprocess {
            code: 1,
            stderr: "  TLS handshake failed\n".into(),
        });
        assert_eq!(code, ErrorCode::SubprocessError);
        assert_eq!(msg, "TLS handshake failed");

        // A subprocess that said nothing still says something.
        let (_, msg) = describe(&VpnError::Subprocess {
            code: 3,
            stderr: String::new(),
        });
        assert!(msg.contains('3'), "{msg}");
    }
}
