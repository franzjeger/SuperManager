//! The D-Bus service object that the daemon exposes on the session/system bus.
//!
//! [`DaemonService`] is registered at [`supermgr_core::dbus::DBUS_OBJECT_PATH`] and
//! implements the `org.supermgr.Daemon1` interface via `#[zbus::interface]`.
//!
//! # Threading model
//!
//! The `zbus` connection runs on the tokio runtime.  Method handlers are `async`
//! and acquire an `Arc<Mutex<DaemonState>>` to serialise access to the mutable
//! profile store and backend handle.  Long-running operations (connect/disconnect)
//! are spawned as separate tasks so the D-Bus method returns immediately.

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use tokio::sync::{watch, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use zbus::{fdo, interface, SignalContext};

use supermgr_core::{
    vpn::backend::{BackendStatus, VpnBackend},
    dbus::core_error_to_fdo,
    vpn::profile::{
        import_wireguard_conf, AzureVpnConfig, FortiGateConfig, OpenVpnConfig, Profile,
        ProfileConfig, ProfileSummary, SecretRef,
    },
    vpn::state::{state_to_json, stats_to_json, VpnState},
};

use supermgr_core::ssh::key::{SshKey, SshKeySummary, SshKeyType};
use supermgr_core::host::{AuthMethod, Host, HostSummary};

use crate::secrets;

// `backend_for_profile` lives in supermgrd's own vpn module.
use crate::vpn::backend_for_profile;


// ---------------------------------------------------------------------------
// Port forward tracking
// ---------------------------------------------------------------------------

/// Metadata and handle for an active port forward.
pub struct PortForwardEntry {
    /// UUID of the SSH host this forward belongs to.
    pub host_id: String,
    /// Local TCP port being listened on.
    pub local_port: u16,
    /// Remote host being forwarded to.
    pub remote_host: String,
    /// Remote port being forwarded to.
    pub remote_port: u16,
    /// Handle to the background task running the listener loop.
    /// Aborting this handle tears down the forward.
    pub task: tokio::task::JoinHandle<()>,
}

// ---------------------------------------------------------------------------
// Daemon-internal state (not exposed over D-Bus directly)
// ---------------------------------------------------------------------------

/// All mutable state owned by the daemon.
pub struct DaemonState {
    /// All known VPN profiles, keyed by UUID.
    pub profiles: std::collections::HashMap<Uuid, Profile>,

    /// Current VPN state.
    pub vpn_state: VpnState,

    /// Active VPN backend, if any.
    pub active_backend: Option<Arc<dyn VpnBackend>>,

    /// Directory where VPN profile TOML files are persisted.
    pub profile_dir: PathBuf,

    /// The kill-switch mode that was installed when the current VPN connected
    /// with kill_switch=true.  Stored so the monitor task can reinstall a
    /// stricter variant (without `ct state established,related accept`) when
    /// the VPN drops unexpectedly, ensuring existing connections are also cut.
    pub active_kill_switch_mode: Option<KillSwitchMode>,

    /// SSH keys, keyed by UUID.
    pub ssh_keys: std::collections::HashMap<Uuid, SshKey>,

    /// SSH hosts, keyed by UUID.
    pub hosts: std::collections::HashMap<Uuid, Host>,

    /// SSH host health (reachability) map: host UUID → reachable.
    pub host_health: std::collections::HashMap<Uuid, bool>,

    /// Directory where SSH key TOML files are stored.
    pub ssh_key_dir: PathBuf,

    /// Directory where managed-host JSON files are stored.
    ///
    /// On disk this is still `<base>/ssh/hosts/` for backward compatibility
    /// with deployments created before the `SshHost` → `Host` type rename;
    /// changing the path would orphan every existing user's saved hosts.
    pub host_dir: PathBuf,

    // ---- Active port forwards ----

    /// Active SSH port forwards, keyed by forward ID.
    /// The `JoinHandle` runs the local TCP listener + forwarding loop;
    /// dropping or aborting it tears down the forward.
    pub port_forwards: std::collections::HashMap<String, PortForwardEntry>,

    // ---- Webhook notification settings (set via D-Bus) ----

    /// Webhook URL for outgoing notifications (Slack/Teams/Discord).
    /// Empty string means disabled.
    pub webhook_url: String,
    /// Fire a webhook when an SSH host goes down.
    pub webhook_on_host_down: bool,
    /// Fire a webhook when a VPN tunnel disconnects unexpectedly.
    pub webhook_on_vpn_disconnect: bool,
}

impl DaemonState {
    /// Create daemon state with an empty profile table.
    #[must_use]
    pub fn new(profile_dir: PathBuf) -> Self {
        let base = profile_dir.parent().unwrap_or(&profile_dir).to_owned();
        Self {
            profiles: std::collections::HashMap::new(),
            vpn_state: VpnState::Disconnected,
            active_backend: None,
            profile_dir,
            active_kill_switch_mode: None,
            ssh_keys: std::collections::HashMap::new(),
            hosts: std::collections::HashMap::new(),
            host_health: std::collections::HashMap::new(),
            ssh_key_dir: base.join("ssh/keys"),
            host_dir: base.join("ssh/hosts"),
            port_forwards: std::collections::HashMap::new(),
            webhook_url: String::new(),
            webhook_on_host_down: true,
            webhook_on_vpn_disconnect: false,
        }
    }

    /// Load all `.toml` profile files from `profile_dir`.
    pub fn load_profiles(&mut self) -> anyhow::Result<()> {
        if !self.profile_dir.exists() {
            std::fs::create_dir_all(&self.profile_dir)?;
            return Ok(());
        }
        for entry in std::fs::read_dir(&self.profile_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            match toml::from_str::<Profile>(&text) {
                Ok(profile) => {
                    info!("loaded profile '{}' from {:?}", profile.name, path);
                    self.profiles.insert(profile.id, profile);
                }
                Err(e) => {
                    warn!("skipping malformed profile {:?}: {}", path, e);
                }
            }
        }
        Ok(())
    }

    /// Persist a single profile to disk as `{profile_dir}/{id}.toml`.
    ///
    /// The caller is responsible for ensuring `profile_dir` exists before
    /// calling this (see `import_wireguard` for the `create_dir_all` call).
    pub fn save_profile(&self, profile: &Profile) -> anyhow::Result<()> {
        let path = self.profile_dir.join(format!("{}.toml", profile.id));
        let text = toml::to_string_pretty(profile)?;
        std::fs::write(&path, text)?;
        Ok(())
    }

    /// Delete a profile's on-disk file.
    pub fn delete_profile_file(&self, id: Uuid) -> anyhow::Result<()> {
        let path = self.profile_dir.join(format!("{id}.toml"));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // SSH persistence
    // -----------------------------------------------------------------------

    /// Load all `.toml` SSH key files from `ssh_key_dir`.
    pub fn load_ssh_keys(&mut self) -> anyhow::Result<()> {
        if !self.ssh_key_dir.exists() {
            std::fs::create_dir_all(&self.ssh_key_dir)?;
            return Ok(());
        }
        for entry in std::fs::read_dir(&self.ssh_key_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            match toml::from_str::<SshKey>(&text) {
                Ok(key) => {
                    info!("loaded SSH key '{}' from {:?}", key.name, path);
                    self.ssh_keys.insert(key.id, key);
                }
                Err(e) => {
                    warn!("skipping malformed SSH key {:?}: {}", path, e);
                }
            }
        }
        Ok(())
    }

    /// Load all `.toml` SSH host files from `host_dir`.
    pub fn load_hosts(&mut self) -> anyhow::Result<()> {
        if !self.host_dir.exists() {
            std::fs::create_dir_all(&self.host_dir)?;
            return Ok(());
        }
        for entry in std::fs::read_dir(&self.host_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            match toml::from_str::<Host>(&text) {
                Ok(host) => {
                    info!("loaded SSH host '{}' from {:?}", host.label, path);
                    self.hosts.insert(host.id, host);
                }
                Err(e) => {
                    warn!("skipping malformed SSH host {:?}: {}", path, e);
                }
            }
        }
        Ok(())
    }

    /// Persist a single SSH key to disk as `{ssh_key_dir}/{id}.toml`.
    pub fn save_ssh_key(&self, key: &SshKey) -> anyhow::Result<()> {
        let path = self.ssh_key_dir.join(format!("{}.toml", key.id));
        let text = toml::to_string_pretty(key)?;
        std::fs::write(&path, text)?;
        Ok(())
    }

    /// Persist a single SSH host to disk as `{host_dir}/{id}.toml`.
    pub fn save_host(&self, host: &Host) -> anyhow::Result<()> {
        let path = self.host_dir.join(format!("{}.toml", host.id));
        let text = toml::to_string_pretty(host)?;
        std::fs::write(&path, text)?;
        Ok(())
    }

    /// Delete an SSH key's on-disk file.
    pub fn delete_ssh_key_file(&self, id: Uuid) -> anyhow::Result<()> {
        let path = self.ssh_key_dir.join(format!("{id}.toml"));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Delete an SSH host's on-disk file.
    pub fn delete_host_file(&self, id: Uuid) -> anyhow::Result<()> {
        let path = self.host_dir.join(format!("{id}.toml"));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// D-Bus service object
// ---------------------------------------------------------------------------

/// Callback type for dynamically changing the daemon's tracing log level at
/// runtime via the `reload` layer.
pub type LogLevelSetter = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// The D-Bus service object.  Registered at `/org/supermgr/Daemon`.
pub struct DaemonService {
    /// Shared mutable state.
    pub state: Arc<tokio::sync::Mutex<DaemonState>>,
    /// Channel the monitoring task uses to receive a termination signal.
    /// Held here to keep the sender alive; the receiver is passed to the monitor task.
    #[allow(dead_code)]
    pub shutdown_tx: watch::Sender<bool>,
    /// Ring buffer of recent log lines (filled by the `RingLayer` tracing layer).
    pub log_buffer: Arc<std::sync::Mutex<VecDeque<String>>>,
    /// Callback to dynamically change the tracing `EnvFilter` log level.
    pub set_log_level: LogLevelSetter,
}

impl DaemonService {
    /// Look up an OPNsense host's stored credentials and connection details.
    ///
    /// Returns `(hostname, port, credentials)`. Errors map to `fdo::Error`s
    /// suitable for returning straight from a D-Bus method.
    async fn load_opnsense_creds(
        &self,
        id: &Uuid,
    ) -> fdo::Result<(String, u16, crate::opnsense::Credentials)> {
        let (hostname, port, label) = {
            let state = self.state.lock().await;
            let host = state
                .hosts
                .get(id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
            let label = host
                .api_token_ref
                .as_ref()
                .ok_or_else(|| {
                    fdo::Error::Failed(
                        "no OPNsense credentials configured — call opnsense_set_credentials first"
                            .into(),
                    )
                })?
                .label()
                .to_owned();
            (
                host.hostname.clone(),
                host.api_port.unwrap_or(443),
                label,
            )
        };

        let blob = secrets::retrieve_secret(&label)
            .await
            .map_err(|e| fdo::Error::Failed(format!("retrieve credentials: {e}")))?;
        let blob = String::from_utf8(blob)
            .map_err(|e| fdo::Error::Failed(format!("invalid credentials encoding: {e}")))?;
        let creds: crate::opnsense::Credentials = serde_json::from_str(&blob).map_err(|e| {
            fdo::Error::Failed(format!(
                "stored credentials are not in OPNsense JSON format: {e}"
            ))
        })?;
        Ok((hostname, port, creds))
    }
}

#[interface(name = "org.supermgr.Daemon1")]
impl DaemonService {
    // =======================================================================
    // VPN Methods
    // =======================================================================

    /// List all known profiles as a JSON array of [`ProfileSummary`] objects.
    async fn list_profiles(&self) -> fdo::Result<String> {
        let state = self.state.lock().await;
        let summaries: Vec<ProfileSummary> = state
            .profiles
            .values()
            .map(ProfileSummary::from)
            .collect();
        serde_json::to_string(&summaries)
            .map_err(|e| fdo::Error::Failed(format!("serialisation failed: {e}")))
    }

    /// Initiate a connection for the profile identified by `profile_id`.
    ///
    /// Returns immediately; progress is reported via `StateChanged` signals.
    async fn connect(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        profile_id: &str,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        let profile = {
            let state = self.state.lock().await;

            if !state.vpn_state.is_idle() {
                return Err(fdo::Error::Failed(
                    "another connection is already active or in progress".into(),
                ));
            }

            state
                .profiles
                .get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?
                .clone()
        };

        connect_profile(profile, Arc::clone(&self.state), ctx).await
    }

    /// Tear down the active tunnel.
    async fn disconnect(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
    ) -> fdo::Result<()> {
        crate::audit::log_event("VPN_DISCONNECT", "");
        let backend = {
            let mut state = self.state.lock().await;
            match state.active_backend.take() {
                Some(b) => {
                    let profile_id = state.vpn_state.profile_id();
                    state.vpn_state = VpnState::Disconnecting {
                        profile_id: profile_id.unwrap_or_else(Uuid::new_v4),
                    };
                    Some(b)
                }
                // No active backend — VPN may have already dropped while the
                // kill switch is still active.  Clean up and set Disconnected
                // so the user is not permanently blocked.
                None => None,
            }
        };

        let state_arc = Arc::clone(&self.state);
        let ctx_owned = ctx.to_owned();

        if backend.is_none() {
            // VPN already dropped (kill switch may still be active); just clean up.
            tokio::spawn(async move {
                remove_kill_switch().await;
                let mut state = state_arc.lock().await;
                state.vpn_state = VpnState::Disconnected;
                state.active_kill_switch_mode = None;
                if let Ok(json) = state_to_json(&state.vpn_state) {
                    let _ = DaemonService::state_changed(&ctx_owned, json).await;
                }
            });
            return Ok(());
        }

        let state_json = {
            let state = self.state.lock().await;
            state_to_json(&state.vpn_state)
                .map_err(|e| fdo::Error::Failed(e.to_string()))?
        };
        Self::state_changed(&ctx, state_json)
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;

        tokio::spawn(async move {
            // Tear down the tunnel first, then remove the kill switch.
            // This order ensures there is no window where internet traffic can
            // bypass the (already-gone) VPN before the firewall rules are lifted.
            if let Some(b) = backend {
                match b.disconnect().await {
                    Ok(()) => info!("tunnel disconnected"),
                    Err(e) => error!("disconnect error: {}", e),
                }
            }
            remove_kill_switch().await;
            let mut state = state_arc.lock().await;
            state.vpn_state = VpnState::Disconnected;
            state.active_kill_switch_mode = None;
            if let Ok(json) = state_to_json(&state.vpn_state) {
                let _ = DaemonService::state_changed(&ctx_owned, json).await;
            }
        });

        Ok(())
    }

    /// Return the current VPN state as a JSON string.
    async fn get_status(&self) -> fdo::Result<String> {
        let state = self.state.lock().await;
        state_to_json(&state.vpn_state)
            .map_err(|e| fdo::Error::Failed(format!("serialisation failed: {e}")))
    }

    /// Return the most recent log lines captured by the ring-buffer tracing layer.
    ///
    /// Returns up to 500 lines, oldest first.  Each line is a pre-formatted
    /// string of the form `[HH:MM:SS] LEVEL target: message`.
    async fn get_logs(&self) -> fdo::Result<Vec<String>> {
        let buf = self.log_buffer.lock().map_err(|e| fdo::Error::Failed(e.to_string()))?;
        Ok(buf.iter().cloned().collect())
    }

    /// Clear the in-memory log buffer.
    async fn clear_logs(&self) -> fdo::Result<()> {
        let mut buf = self.log_buffer.lock().map_err(|e| fdo::Error::Failed(e.to_string()))?;
        buf.clear();
        Ok(())
    }

    /// Dynamically change the daemon's tracing log level at runtime.
    ///
    /// `level` is a tracing filter directive, e.g. `"error"`, `"warn"`,
    /// `"info"`, `"debug"`, or `"trace"`.
    async fn set_log_level(&self, level: &str) -> fdo::Result<()> {
        info!("set_log_level: changing to '{level}'");
        (self.set_log_level)(level).map_err(|e| fdo::Error::Failed(e))
    }

    // =======================================================================
    // Webhook / notification methods
    // =======================================================================

    /// Configure webhook notifications.
    ///
    /// `url` is the incoming-webhook URL (empty string to disable).
    /// `on_host_down` and `on_vpn_disconnect` control which events fire.
    async fn set_webhook(
        &self,
        url: String,
        on_host_down: bool,
        on_vpn_disconnect: bool,
    ) -> fdo::Result<()> {
        let mut state = self.state.lock().await;
        state.webhook_url = url;
        state.webhook_on_host_down = on_host_down;
        state.webhook_on_vpn_disconnect = on_vpn_disconnect;
        info!(
            "webhook config updated: url={}, host_down={}, vpn_disconnect={}",
            if state.webhook_url.is_empty() { "(disabled)" } else { "(set)" },
            state.webhook_on_host_down,
            state.webhook_on_vpn_disconnect,
        );
        Ok(())
    }

    /// Return the current webhook configuration as JSON.
    ///
    /// ```json
    /// {"url":"https://...","on_host_down":true,"on_vpn_disconnect":false}
    /// ```
    async fn get_webhook_config(&self) -> fdo::Result<String> {
        let state = self.state.lock().await;
        let obj = serde_json::json!({
            "url": state.webhook_url,
            "on_host_down": state.webhook_on_host_down,
            "on_vpn_disconnect": state.webhook_on_vpn_disconnect,
        });
        serde_json::to_string(&obj)
            .map_err(|e| fdo::Error::Failed(format!("serialisation failed: {e}")))
    }

    /// Send a test message to the configured webhook URL.
    ///
    /// Returns `"ok"` on success or an error if no URL is configured.
    async fn test_webhook(&self) -> fdo::Result<String> {
        let url = {
            let state = self.state.lock().await;
            state.webhook_url.clone()
        };
        if url.is_empty() {
            return Err(fdo::Error::Failed("no webhook URL configured".into()));
        }
        send_webhook(&url, "SuperManager: webhook test — if you see this, notifications are working!").await;
        Ok("ok".into())
    }

    /// Return live tunnel statistics as a compact JSON object.
    ///
    /// JSON shape:
    /// ```json
    /// {"bytes_sent": 0, "bytes_received": 0, "last_handshake_secs": 0}
    /// ```
    ///
    /// `last_handshake_secs` is a Unix epoch timestamp (seconds since
    /// 1970-01-01 UTC); `0` means no handshake has been observed yet.
    /// All fields are zero when no tunnel is active.
    ///
    /// Stats are gathered by summing `peer.stats.tx_bytes` / `rx_bytes` across
    /// all WireGuard peers and taking the most recent `last_handshake_time`.
    async fn get_stats(&self) -> fdo::Result<String> {
        let backend = {
            let state = self.state.lock().await;
            state.active_backend.clone()
        };

        let (bytes_sent, bytes_received, last_handshake_secs): (u64, u64, u64) =
            match backend {
                None => (0, 0, 0),
                Some(b) => match b.status().await {
                    Ok(BackendStatus::Active { stats, .. }) => {
                        let lhs = stats
                            .last_handshake
                            .map(|dt| dt.timestamp().max(0) as u64)
                            .unwrap_or(0);
                        (stats.bytes_sent, stats.bytes_received, lhs)
                    }
                    _ => (0, 0, 0),
                },
            };

        Ok(format!(
            "{{\"bytes_sent\":{bytes_sent},\
              \"bytes_received\":{bytes_received},\
              \"last_handshake_secs\":{last_handshake_secs}}}"
        ))
    }

    /// Import a WireGuard `.conf` file.
    ///
    /// `conf_text` is the raw `.conf` file contents; `name` is the desired
    /// display name.  Returns the new profile's UUID string on success.
    ///
    /// Every error path emits a `tracing::error!` so that nothing fails
    /// silently in the daemon log.
    async fn import_wireguard(&self, conf_text: &str, name: &str) -> fdo::Result<String> {
        info!("import_wireguard called, len={}", conf_text.len());

        let name = name.trim();
        if name.is_empty() {
            return Err(fdo::Error::InvalidArgs("name must not be empty".into()));
        }

        // Generate the profile UUID first so the keyring secret label and the
        // on-disk profile file share the same identifier.
        let profile_id = Uuid::new_v4();
        let secret_label = format!("supermgr/wg/{}", profile_id.simple());

        info!(
            "import_wireguard: parsing conf for profile '{}', id={}, label={}",
            name, profile_id, secret_label
        );

        // --- Validate format before parsing ---------------------------------
        // Give a clear error when the user uploads a non-WireGuard file.
        {
            let active: Vec<&str> = conf_text
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#') && !l.is_empty())
                .collect();
            let is_wg = active.iter().any(|l| *l == "[Interface]");
            let looks_like_ovpn = active.iter().any(|l| {
                let lc = l.to_ascii_lowercase();
                lc == "client" || lc.starts_with("remote ") || lc.starts_with("dev tun")
            });
            if !is_wg {
                let hint = if looks_like_ovpn {
                    " — this looks like an OpenVPN config; use 'Import OpenVPN' instead"
                } else {
                    " — expected a WireGuard .conf with an [Interface] section"
                };
                error!("import_wireguard: not a WireGuard config for '{}'{}", name, hint);
                return Err(fdo::Error::InvalidArgs(format!(
                    "not a valid WireGuard config{hint}"
                )));
            }
        }

        // --- Parse the .conf text -------------------------------------------
        let (wg_cfg, raw_key, psks) =
            import_wireguard_conf(conf_text, &secret_label).map_err(|e| {
                error!(
                    "import_wireguard: .conf parse failed for '{}': {:#}",
                    name, e
                );
                fdo::Error::Failed(format!("WireGuard import failed: {e}"))
            })?;

        info!(
            "import_wireguard: parsed ok — {} peer(s), {} address(es)",
            wg_cfg.peers.len(),
            wg_cfg.addresses.len()
        );

        // --- Store the private key in the secrets file ----------------------
        let raw_key_str = raw_key.take();

        secrets::store_secret(&secret_label, raw_key_str.as_bytes())
            .await
            .map_err(|e| {
                error!(
                    "import_wireguard: secrets store failed for '{}' ({}): {:#}",
                    name, profile_id, e
                );
                fdo::Error::Failed(format!("secrets store failed: {e}"))
            })?;

        info!(
            "import_wireguard: private key for '{}' stored under '{}'",
            name, secret_label
        );

        // --- Store any pre-shared keys in the secrets file ------------------
        for (psk_label, psk_value) in &psks {
            secrets::store_secret(psk_label, psk_value.as_bytes()).await.map_err(|e| {
                error!("import_wireguard: secrets store for PSK '{}': {:#}", psk_label, e);
                fdo::Error::Failed(format!("secrets store failed for PSK: {e}"))
            })?;
        }
        info!(
            "import_wireguard: stored {} PSK(s) for '{}'",
            psks.len(),
            name
        );

        // --- Build the Profile (no secrets on disk) -------------------------
        let profile = Profile {
            id: profile_id,
            name: name.to_owned(),
            auto_connect: false,
            full_tunnel: true,
            last_connected_at: None,
            kill_switch: false,
            customer: String::new(),
            config: ProfileConfig::WireGuard(wg_cfg),
            updated_at: chrono::Utc::now(),
        };
        let id_str = profile.id.to_string();

        // --- Ensure the profile directory exists ----------------------------
        let profile_dir = {
            let state = self.state.lock().await;
            state.profile_dir.clone()
        };

        info!("import_wireguard: ensuring profile dir {}", profile_dir.display());

        tokio::fs::create_dir_all(&profile_dir).await.map_err(|e| {
            error!(
                "import_wireguard: failed to create profile directory {}: {:#}",
                profile_dir.display(),
                e
            );
            fdo::Error::Failed(format!(
                "create profile directory {}: {e}",
                profile_dir.display()
            ))
        })?;

        // --- Persist and register the profile -------------------------------
        {
            let mut state = self.state.lock().await;
            state.save_profile(&profile).map_err(|e| {
                error!(
                    "import_wireguard: failed to save profile '{}' ({}) to {}: {:#}",
                    name,
                    profile.id,
                    state.profile_dir.display(),
                    e
                );
                fdo::Error::Failed(format!("save failed: {e}"))
            })?;
            state.profiles.insert(profile.id, profile);
        }

        info!(
            "import_wireguard: successfully imported profile '{}' -> {}",
            name, id_str
        );
        Ok(id_str)
    }

    /// Create and persist a FortiGate IPsec/IKEv2 profile.
    ///
    /// Returns the new profile's UUID string.
    async fn import_fortigate(
        &self,
        name: String,
        host: String,
        username: String,
        password: String,
        psk: String,
        dns_servers: String,
    ) -> fdo::Result<String> {
        let profile_id = Uuid::new_v4();

        let name = name.trim().to_string();
        let host = sanitize_fortigate_host(&host);
        let username = username.trim().to_string();
        let dns_servers = parse_dns_server_list(&dns_servers);

        info!(
            "import_fortigate: creating profile '{}' for host '{}', user '{}', \
             user-supplied DNS servers: {}",
            name,
            host,
            username,
            dns_servers.len()
        );

        if host.is_empty() {
            return Err(fdo::Error::InvalidArgs("host must not be empty".into()));
        }
        if username.is_empty() {
            return Err(fdo::Error::InvalidArgs("username must not be empty".into()));
        }

        // --- Store credentials in the secrets file --------------------------
        let pw_label = format!("supermgr/fg/{}/password", profile_id.simple());
        let psk_label = format!("supermgr/fg/{}/psk", profile_id.simple());

        secrets::store_secret(&pw_label, password.as_bytes()).await.map_err(|e| {
            error!("import_fortigate: secrets store for password '{}': {:#}", pw_label, e);
            fdo::Error::Failed(format!("secrets store failed for password: {e}"))
        })?;
        secrets::store_secret(&psk_label, psk.as_bytes()).await.map_err(|e| {
            error!("import_fortigate: secrets store for PSK '{}': {:#}", psk_label, e);
            fdo::Error::Failed(format!("secrets store failed for PSK: {e}"))
        })?;

        info!(
            "import_fortigate: credentials for '{}' stored ('{}', '{}')",
            name, pw_label, psk_label
        );

        let fg_cfg = FortiGateConfig {
            host,
            username,
            password: SecretRef::new(pw_label),
            psk: SecretRef::new(psk_label),
            dns_servers,
            routes: Vec::new(),
        };

        let profile = Profile {
            id: profile_id,
            name: name.clone(),
            auto_connect: false,
            full_tunnel: true,
            last_connected_at: None,
            kill_switch: false,
            customer: String::new(),
            config: ProfileConfig::FortiGate(fg_cfg),
            updated_at: chrono::Utc::now(),
        };
        let id_str = profile.id.to_string();

        let profile_dir = {
            let state = self.state.lock().await;
            state.profile_dir.clone()
        };

        tokio::fs::create_dir_all(&profile_dir).await.map_err(|e| {
            error!("import_fortigate: create_dir_all {}: {:#}", profile_dir.display(), e);
            fdo::Error::Failed(format!("create profile directory: {e}"))
        })?;

        {
            let mut state = self.state.lock().await;
            state.save_profile(&profile).map_err(|e| {
                error!("import_fortigate: save_profile '{}': {:#}", name, e);
                fdo::Error::Failed(format!("save failed: {e}"))
            })?;
            state.profiles.insert(profile.id, profile);
        }

        info!("import_fortigate: profile '{}' persisted -> {}", name, id_str);
        Ok(id_str)
    }

    /// Import an OpenVPN `.ovpn` configuration file.
    ///
    /// `conf_text` is the raw `.ovpn` file contents; `name` is the desired
    /// display name.  Returns the new profile's UUID string on success.
    ///
    /// The config file is written to the daemon's ovpn directory at
    /// `/etc/supermgrd/ovpn/<uuid>.ovpn` (or the XDG equivalent for non-root).
    ///
    /// `username` and `password` are optional — pass empty strings if the
    /// configuration does not require user authentication (e.g. certificate-only).
    async fn import_openvpn(
        &self,
        conf_text: &str,
        name: &str,
        username: &str,
        password: &str,
    ) -> fdo::Result<String> {
        let name = name.trim();
        let username = username.trim();
        if name.is_empty() {
            return Err(fdo::Error::InvalidArgs("name must not be empty".into()));
        }

        info!("import_openvpn called for profile '{}'", name);

        // Validate the config text before touching the filesystem.
        // This gives an immediate, descriptive error when the user accidentally
        // uploads a WireGuard conf, an SSH key, or an OpenVPN server config.
        validate_ovpn_config(conf_text).map_err(|e| {
            error!("import_openvpn: validation failed for '{}': {}", name, e);
            fdo::Error::InvalidArgs(format!("OpenVPN config validation failed: {e}"))
        })?;

        let profile_id = Uuid::new_v4();

        // Determine the ovpn config directory (sibling of profile_dir named "ovpn").
        let ovpn_dir = {
            let state = self.state.lock().await;
            state.profile_dir.parent()
                .unwrap_or(&state.profile_dir)
                .join("ovpn")
        };

        tokio::fs::create_dir_all(&ovpn_dir).await.map_err(|e| {
            fdo::Error::Failed(format!("create ovpn directory: {e}"))
        })?;

        let config_path = ovpn_dir.join(format!("{}.ovpn", profile_id));
        let config_path_str = config_path.to_string_lossy().into_owned();

        tokio::fs::write(&config_path, conf_text).await.map_err(|e| {
            fdo::Error::Failed(format!("write ovpn config: {e}"))
        })?;

        info!("import_openvpn: wrote config to {}", config_path_str);

        // Store password in keyring if provided.
        let (opt_username, opt_password) = if !username.is_empty() && !password.is_empty() {
            let pw_label = format!("supermgr/ovpn/{}/password", profile_id.simple());
            secrets::store_secret(&pw_label, password.as_bytes()).await.map_err(|e| {
                fdo::Error::Failed(format!("secrets store failed for OpenVPN password: {e}"))
            })?;
            info!("import_openvpn: credentials stored for '{}'", name);
            (Some(username.to_owned()), Some(SecretRef::new(pw_label)))
        } else {
            (None, None)
        };

        let profile = Profile {
            id: profile_id,
            name: name.to_owned(),
            auto_connect: false,
            full_tunnel: true,
            last_connected_at: None,
            kill_switch: false,
            customer: String::new(),
            config: ProfileConfig::OpenVpn(OpenVpnConfig {
                config_file: config_path_str,
                username: opt_username,
                password: opt_password,
            }),
            updated_at: chrono::Utc::now(),
        };
        let id_str = profile.id.to_string();

        let profile_dir = {
            let state = self.state.lock().await;
            state.profile_dir.clone()
        };

        tokio::fs::create_dir_all(&profile_dir).await.map_err(|e| {
            fdo::Error::Failed(format!("create profile directory: {e}"))
        })?;

        {
            let mut state = self.state.lock().await;
            state.save_profile(&profile).map_err(|e| {
                fdo::Error::Failed(format!("save failed: {e}"))
            })?;
            state.profiles.insert(profile.id, profile);
        }

        info!("import_openvpn: profile '{}' created -> {}", name, id_str);
        Ok(id_str)
    }

    /// Import a TOML configuration file.
    ///
    /// Detects whether the TOML represents a VPN profile, SSH key, or SSH host
    /// based on its contents and imports it accordingly.  Returns a JSON object
    /// with `{ "type": "vpn"|"ssh_key"|"ssh_host", "id": "<uuid>" }`.
    async fn import_toml(&self, toml_text: &str) -> fdo::Result<String> {
        use base64::Engine as _;

        // --- Parse into a generic TOML table to detect type -----------------
        let table: toml::map::Map<String, toml::Value> = toml::from_str(toml_text)
            .map_err(|e| fdo::Error::InvalidArgs(format!("invalid TOML: {e}")))?;

        if table.contains_key("config") {
            // ── VPN profile ────────────────────────────────────────────────
            let mut profile: Profile = toml::from_str(toml_text)
                .map_err(|e| fdo::Error::InvalidArgs(format!("invalid VPN profile TOML: {e}")))?;

            let original_name = profile.name.clone();

            // VPN-Manager compat: plaintext_private_key in [config].
            let plaintext_key = table.get("config")
                .and_then(|c| c.as_table())
                .and_then(|c| c.get("plaintext_private_key"))
                .and_then(|v| v.as_str())
                .map(String::from);

            let new_id = Uuid::new_v4();
            profile.id = new_id;
            profile.updated_at = chrono::Utc::now();

            // Re-label secrets for every backend type so imported profiles
            // that reference old (vpnr/…) labels get fresh supermgr/… labels
            // and the corresponding secret bytes are copied over.
            match profile.config {
                ProfileConfig::WireGuard(ref mut wg) => {
                    let new_label = format!("supermgr/wg/{}/privkey", new_id.simple());

                    if let Some(ref ptk) = plaintext_key {
                        let raw = base64::engine::general_purpose::STANDARD
                            .decode(ptk)
                            .map_err(|e| fdo::Error::Failed(format!("base64 decode private key: {e}")))?;
                        secrets::store_secret(&new_label, &raw).await
                            .map_err(|e| fdo::Error::Failed(format!("store secret: {e}")))?;
                    } else if let Ok(existing) = secrets::retrieve_secret(wg.private_key.label()).await {
                        secrets::store_secret(&new_label, &existing).await
                            .map_err(|e| fdo::Error::Failed(format!("store secret: {e}")))?;
                    } else {
                        warn!("import_toml: no WireGuard private key found for '{}'", original_name);
                    }
                    wg.private_key = SecretRef::new(new_label);

                    for peer in &mut wg.peers {
                        if let Some(ref old_psk) = peer.preshared_key {
                            let new_psk_label = format!(
                                "supermgr/wg/{}/psk/{}",
                                new_id.simple(),
                                &peer.public_key[..8.min(peer.public_key.len())]
                            );
                            if let Ok(existing) = secrets::retrieve_secret(old_psk.label()).await {
                                let _ = secrets::store_secret(&new_psk_label, &existing).await;
                            }
                            peer.preshared_key = Some(SecretRef::new(new_psk_label));
                        }
                    }
                }
                ProfileConfig::FortiGate(ref mut fg) => {
                    let new_pw = format!("supermgr/fg/{}/password", new_id.simple());
                    let new_psk = format!("supermgr/fg/{}/psk", new_id.simple());

                    if let Ok(existing) = secrets::retrieve_secret(fg.password.label()).await {
                        secrets::store_secret(&new_pw, &existing).await
                            .map_err(|e| fdo::Error::Failed(format!("store secret: {e}")))?;
                    } else {
                        warn!("import_toml: no FortiGate password found for '{}' (label '{}')", original_name, fg.password.label());
                    }
                    if let Ok(existing) = secrets::retrieve_secret(fg.psk.label()).await {
                        secrets::store_secret(&new_psk, &existing).await
                            .map_err(|e| fdo::Error::Failed(format!("store secret: {e}")))?;
                    } else {
                        warn!("import_toml: no FortiGate PSK found for '{}' (label '{}')", original_name, fg.psk.label());
                    }
                    fg.password = SecretRef::new(new_pw);
                    fg.psk = SecretRef::new(new_psk);
                }
                ProfileConfig::OpenVpn(ref mut ov) => {
                    if let Some(ref old_pw) = ov.password {
                        let new_pw = format!("supermgr/ov/{}/password", new_id.simple());
                        if let Ok(existing) = secrets::retrieve_secret(old_pw.label()).await {
                            secrets::store_secret(&new_pw, &existing).await
                                .map_err(|e| fdo::Error::Failed(format!("store secret: {e}")))?;
                        }
                        ov.password = Some(SecretRef::new(new_pw));
                    }
                }
                // AzureVpn and Generic have no SecretRef fields.
                _ => {}
            }

            let mut state = self.state.lock().await;
            std::fs::create_dir_all(&state.profile_dir)
                .map_err(|e| fdo::Error::Failed(format!("create profile dir: {e}")))?;
            state.save_profile(&profile)
                .map_err(|e| fdo::Error::Failed(format!("save profile: {e}")))?;
            state.profiles.insert(profile.id, profile);

            info!("import_toml: VPN profile '{}' -> {}", original_name, new_id);
            Ok(serde_json::json!({ "type": "vpn", "id": new_id.to_string() }).to_string())

        } else if table.contains_key("key_type") && table.contains_key("public_key") {
            // ── SSH key ────────────────────────────────────────────────────
            let mut key: SshKey = toml::from_str(toml_text)
                .map_err(|e| fdo::Error::InvalidArgs(format!("invalid SSH key TOML: {e}")))?;

            let new_id = Uuid::new_v4();
            let old_label = key.private_key_ref.label().to_owned();
            let new_label = format!("supermgr/ssh/{}/privkey", new_id.simple());

            if let Ok(existing) = secrets::retrieve_secret(&old_label).await {
                secrets::store_secret(&new_label, &existing).await
                    .map_err(|e| fdo::Error::Failed(format!("store secret: {e}")))?;
            } else {
                warn!("import_toml: no private key for SSH key '{}' (label '{}')", key.name, old_label);
            }

            {
                let state = self.state.lock().await;
                if state.ssh_keys.values().any(|k| k.fingerprint == key.fingerprint) {
                    return Err(fdo::Error::Failed(format!(
                        "SSH key with fingerprint {} already exists", key.fingerprint
                    )));
                }
            }

            let name = key.name.clone();
            key.id = new_id;
            key.private_key_ref = SecretRef::new(new_label);
            key.updated_at = chrono::Utc::now();
            key.deployed_to.clear();

            let mut state = self.state.lock().await;
            std::fs::create_dir_all(&state.ssh_key_dir)
                .map_err(|e| fdo::Error::Failed(format!("create ssh key dir: {e}")))?;
            state.save_ssh_key(&key)
                .map_err(|e| fdo::Error::Failed(format!("save SSH key: {e}")))?;
            state.ssh_keys.insert(key.id, key);

            info!("import_toml: SSH key '{}' -> {}", name, new_id);
            Ok(serde_json::json!({ "type": "ssh_key", "id": new_id.to_string() }).to_string())

        } else if table.contains_key("hostname") && table.contains_key("auth_method") {
            // ── SSH host ───────────────────────────────────────────────────
            let mut host: Host = toml::from_str(toml_text)
                .map_err(|e| fdo::Error::InvalidArgs(format!("invalid SSH host TOML: {e}")))?;

            let new_id = Uuid::new_v4();
            host.id = new_id;
            let now = chrono::Utc::now();
            host.created_at = now;
            host.updated_at = now;

            let label = host.label.clone();
            let mut state = self.state.lock().await;
            std::fs::create_dir_all(&state.host_dir)
                .map_err(|e| fdo::Error::Failed(format!("create ssh host dir: {e}")))?;
            state.save_host(&host)
                .map_err(|e| fdo::Error::Failed(format!("save SSH host: {e}")))?;
            state.hosts.insert(host.id, host);

            info!("import_toml: SSH host '{}' -> {}", label, new_id);
            Ok(serde_json::json!({ "type": "ssh_host", "id": new_id.to_string() }).to_string())

        } else {
            Err(fdo::Error::InvalidArgs(
                "unrecognised TOML config — expected a VPN profile, SSH key, or SSH host".into(),
            ))
        }
    }

    /// Rename a profile by UUID string.
    ///
    /// Updates the display name in memory and rewrites the TOML file on disk.
    /// Fails if the profile UUID is not found.
    async fn rename_profile(
        &self,
        profile_id: &str,
        new_name: &str,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        if new_name.trim().is_empty() {
            return Err(fdo::Error::InvalidArgs("name must not be empty".into()));
        }

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        profile.name = new_name.trim().to_owned();
        profile.updated_at = chrono::Utc::now();

        let profile_clone = profile.clone();
        state.save_profile(&profile_clone).map_err(|e| {
            fdo::Error::Failed(format!("save failed: {e}"))
        })?;

        info!("renamed profile {} to '{}'", id, new_name.trim());
        Ok(())
    }

    /// Set the auto_connect flag on a profile and persist it.
    async fn set_auto_connect(
        &self,
        profile_id: &str,
        auto_connect: bool,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        profile.auto_connect = auto_connect;
        profile.updated_at = chrono::Utc::now();

        let profile_clone = profile.clone();
        state.save_profile(&profile_clone).map_err(|e| {
            fdo::Error::Failed(format!("save failed: {e}"))
        })?;

        info!("profile {id}: auto_connect set to {auto_connect}");
        Ok(())
    }

    /// Set the kill_switch flag on a profile and persist it.
    async fn set_kill_switch(
        &self,
        profile_id: &str,
        enabled: bool,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        profile.kill_switch = enabled;
        profile.updated_at = chrono::Utc::now();

        let profile_clone = profile.clone();
        state.save_profile(&profile_clone).map_err(|e| {
            fdo::Error::Failed(format!("save failed: {e}"))
        })?;

        info!("profile {id}: kill_switch set to {enabled}");
        Ok(())
    }

    /// Set or clear the customer/tenant tag on a VPN profile.
    ///
    /// Pass an empty string to remove the tag (un-group the profile).
    async fn set_profile_customer(
        &self,
        profile_id: &str,
        customer: &str,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;
        let trimmed = customer.trim().to_owned();

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        profile.customer = trimmed.clone();
        profile.updated_at = chrono::Utc::now();

        let profile_clone = profile.clone();
        state.save_profile(&profile_clone).map_err(|e| {
            fdo::Error::Failed(format!("save failed: {e}"))
        })?;

        info!("profile {id}: customer set to {trimmed:?}");
        Ok(())
    }

    /// Update a FortiGate profile's connection details and credentials.
    async fn update_fortigate(
        &self,
        profile_id: &str,
        name: &str,
        host: &str,
        username: &str,
        password: &str,
        psk: &str,
        dns_servers: &str,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        if name.trim().is_empty() {
            return Err(fdo::Error::InvalidArgs("name must not be empty".into()));
        }
        if host.trim().is_empty() {
            return Err(fdo::Error::InvalidArgs("host must not be empty".into()));
        }
        if username.trim().is_empty() {
            return Err(fdo::Error::InvalidArgs("username must not be empty".into()));
        }

        let parsed_dns = parse_dns_server_list(dns_servers);

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        let fg = match &mut profile.config {
            ProfileConfig::FortiGate(fg) => fg,
            _ => return Err(fdo::Error::InvalidArgs("profile is not a FortiGate profile".into())),
        };

        fg.host = sanitize_fortigate_host(host);
        fg.username = username.trim().to_owned();
        fg.dns_servers = parsed_dns;

        // Update secrets only when the caller supplies a non-empty value.
        if !password.is_empty() {
            secrets::store_secret(fg.password.label(), password.as_bytes())
                .await
                .map_err(|e| fdo::Error::Failed(format!("store password: {e}")))?;
        }
        if !psk.is_empty() {
            secrets::store_secret(fg.psk.label(), psk.as_bytes())
                .await
                .map_err(|e| fdo::Error::Failed(format!("store PSK: {e}")))?;
        }

        profile.name = name.trim().to_owned();
        profile.updated_at = chrono::Utc::now();

        let profile_clone = profile.clone();
        state.save_profile(&profile_clone).map_err(|e| fdo::Error::Failed(format!("save failed: {e}")))?;

        info!("profile {id}: FortiGate settings updated (host={host}, user={username})");
        Ok(())
    }

    /// Update an OpenVPN profile's username and optionally its password.
    async fn update_openvpn_credentials(
        &self,
        profile_id: &str,
        username: &str,
        password: &str,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        let ov = match &mut profile.config {
            ProfileConfig::OpenVpn(ov) => ov,
            _ => return Err(fdo::Error::InvalidArgs("profile is not an OpenVPN profile".into())),
        };

        // Update username (allow empty to clear it).
        let username = username.trim();
        ov.username = if username.is_empty() { None } else { Some(username.to_owned()) };

        // Update password if supplied; keep existing secret ref if not.
        if !password.is_empty() {
            let label = ov.password
                .get_or_insert_with(|| {
                    SecretRef::new(format!("supermgr/ovpn/{}/password", id.simple()))
                })
                .label()
                .to_owned();
            secrets::store_secret(&label, password.as_bytes())
                .await
                .map_err(|e| fdo::Error::Failed(format!("store password: {e}")))?;
        }

        profile.updated_at = chrono::Utc::now();

        let profile_clone = profile.clone();
        state.save_profile(&profile_clone).map_err(|e| fdo::Error::Failed(format!("save failed: {e}")))?;

        info!("profile {id}: OpenVPN credentials updated (user={username})");
        Ok(())
    }

    /// Set the full_tunnel flag on a profile and persist it.
    async fn set_full_tunnel(
        &self,
        profile_id: &str,
        full_tunnel: bool,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        profile.full_tunnel = full_tunnel;
        profile.updated_at = chrono::Utc::now();

        let profile_clone = profile.clone();
        state.save_profile(&profile_clone).map_err(|e| {
            fdo::Error::Failed(format!("save failed: {e}"))
        })?;

        info!("profile {id}: full_tunnel set to {full_tunnel}");
        Ok(())
    }

    /// Set the split_routes list for a WireGuard profile and persist it.
    async fn set_split_routes(
        &self,
        profile_id: &str,
        routes: Vec<String>,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        let parsed: Result<Vec<ipnet::IpNet>, _> = routes
            .iter()
            .map(|r| r.parse::<ipnet::IpNet>())
            .collect();
        let parsed = parsed.map_err(|e| {
            fdo::Error::InvalidArgs(format!("invalid CIDR: {e}"))
        })?;

        match &mut profile.config {
            ProfileConfig::WireGuard(wg) => wg.split_routes = parsed,
            ProfileConfig::FortiGate(fg) => fg.routes = parsed,
            _ => return Err(fdo::Error::InvalidArgs(
                "set_split_routes is only supported for WireGuard and FortiGate profiles".into(),
            )),
        };
        profile.updated_at = chrono::Utc::now();

        let profile_clone = profile.clone();
        state.save_profile(&profile_clone).map_err(|e| {
            fdo::Error::Failed(format!("save failed: {e}"))
        })?;

        info!("profile {id}: split_routes updated ({} entries)", routes.len());
        Ok(())
    }

    /// Delete a profile by UUID string.
    async fn delete_profile(&self, profile_id: &str) -> fdo::Result<()> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        let mut state = self.state.lock().await;

        // Refuse to delete a profile that is currently in use.
        if state.vpn_state.profile_id() == Some(id) && !state.vpn_state.is_idle() {
            return Err(fdo::Error::Failed(
                "Cannot delete active profile — disconnect first".into(),
            ));
        }

        if state.profiles.remove(&id).is_none() {
            return Err(fdo::Error::UnknownObject(format!("profile {id} not found")));
        }

        state
            .delete_profile_file(id)
            .map_err(|e| fdo::Error::Failed(format!("delete file: {e}")))?;

        info!("deleted profile {}", id);
        Ok(())
    }

    /// Rotate the WireGuard private key for the given profile.
    ///
    /// Generates a new key pair, overwrites the stored private key in the
    /// secret service, updates the profile's `updated_at` timestamp, saves
    /// the profile to disk, and returns the new base64-encoded public key.
    async fn rotate_wireguard_key(&self, profile_id: &str) -> fdo::Result<String> {
        use wireguard_control::KeyPair;

        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        let secret_label = match &profile.config {
            ProfileConfig::WireGuard(wg) => wg.private_key.label().to_owned(),
            _ => return Err(fdo::Error::InvalidArgs(
                "rotate_wireguard_key only applies to WireGuard profiles".into(),
            )),
        };

        // Generate a new key pair.
        let new_pair = KeyPair::generate();
        let new_private_b64 = new_pair.private.to_base64();
        let new_public_b64 = new_pair.public.to_base64();

        // Store the new private key in the keyring (overwrites existing).
        secrets::store_secret(&secret_label, new_private_b64.as_bytes())
            .await
            .map_err(|e| fdo::Error::Failed(format!("store rotated key: {e}")))?;

        profile.updated_at = chrono::Utc::now();
        let profile_clone = profile.clone();
        state.save_profile(&profile_clone).map_err(|e| {
            fdo::Error::Failed(format!("save profile after key rotation: {e}"))
        })?;

        info!("profile {id}: WireGuard key rotated; new pubkey = {new_public_b64}");
        Ok(new_public_b64)
    }

    /// Export a profile as a TOML string (secrets replaced by their labels).
    async fn export_profile(&self, profile_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| fdo::Error::InvalidArgs(format!("invalid UUID: {profile_id}")))?;

        let state = self.state.lock().await;
        let profile = state
            .profiles
            .get(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        toml::to_string_pretty(profile)
            .map_err(|e| fdo::Error::Failed(format!("TOML serialisation failed: {e}")))
    }

    /// Import an Azure Point-to-Site VPN profile.
    ///
    /// `azure_xml` is the raw `AzureVPN/azurevpnconfig.xml` content;
    /// `vpn_settings_xml` is `Generic/VpnSettings.xml`.  Both are downloaded
    /// together when you click "Download VPN client" in the Azure portal.
    ///
    /// Returns the new profile's UUID string on success.
    async fn import_azure_vpn(
        &self,
        azure_xml: &str,
        vpn_settings_xml: &str,
        name: &str,
    ) -> fdo::Result<String> {
        let name = name.trim();
        if name.is_empty() {
            return Err(fdo::Error::InvalidArgs("name must not be empty".into()));
        }

        info!("import_azure_vpn: parsing config for profile '{name}'");

        let cfg = parse_azure_xml(azure_xml, vpn_settings_xml).map_err(|e| {
            error!("import_azure_vpn: XML parse error: {e}");
            fdo::Error::InvalidArgs(format!("Azure XML parse error: {e}"))
        })?;

        let profile_id = uuid::Uuid::new_v4();

        let profile = Profile {
            id: profile_id,
            name: name.to_owned(),
            auto_connect: false,
            full_tunnel: true,
            last_connected_at: None,
            kill_switch: false,
            customer: String::new(),
            config: ProfileConfig::AzureVpn(cfg),
            updated_at: chrono::Utc::now(),
        };
        let id_str = profile.id.to_string();

        let profile_dir = {
            let state = self.state.lock().await;
            state.profile_dir.clone()
        };

        tokio::fs::create_dir_all(&profile_dir).await.map_err(|e| {
            fdo::Error::Failed(format!("create profile directory: {e}"))
        })?;

        {
            let mut state = self.state.lock().await;
            state.save_profile(&profile).map_err(|e| {
                error!("import_azure_vpn: save_profile '{}': {:#}", name, e);
                fdo::Error::Failed(format!("save failed: {e}"))
            })?;
            state.profiles.insert(profile.id, profile);
        }

        info!("import_azure_vpn: profile '{name}' created -> {id_str}");
        Ok(id_str)
    }

    // =======================================================================
    // SSH Methods
    // =======================================================================

    /// Generate a new SSH key pair of the given type.
    async fn ssh_generate_key(&self, key_type: &str, name: &str, description: &str, tags_json: &str) -> fdo::Result<String> {
        let kt: SshKeyType = match key_type.to_ascii_lowercase().as_str() {
            "ed25519" | "ssh-ed25519" => SshKeyType::Ed25519,
            "rsa-2048" | "rsa2048" => SshKeyType::Rsa2048,
            "rsa-4096" | "rsa4096" | "rsa" | "ssh-rsa" => SshKeyType::Rsa4096,
            _ => return Err(fdo::Error::InvalidArgs(format!("unknown key type: {key_type}"))),
        };

        let generated = crate::ssh::keygen::generate_key(kt, name)
            .map_err(|e| fdo::Error::Failed(format!("key generation failed: {e}")))?;

        let key_id = Uuid::new_v4();
        let secret_label = format!("supermgr/ssh/{}/privkey", key_id.simple());

        // Store private key in secrets
        crate::secrets::store_secret(&secret_label, generated.private_key_pem.as_bytes())
            .await.map_err(|e| fdo::Error::Failed(format!("store secret: {e}")))?;

        let tags: Vec<String> = if tags_json.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(tags_json).unwrap_or_default()
        };

        let now = chrono::Utc::now();
        let key = SshKey {
            id: key_id,
            name: name.to_owned(),
            description: description.to_owned(),
            key_type: kt,
            public_key: generated.public_key,
            private_key_ref: SecretRef::new(secret_label),
            fingerprint: generated.fingerprint,
            tags,
            deployed_to: Vec::new(),
            created_at: now,
            updated_at: now,
        };

        let id_str = key.id.to_string();
        let mut state = self.state.lock().await;
        tokio::fs::create_dir_all(&state.ssh_key_dir).await
            .map_err(|e| fdo::Error::Failed(format!("create key dir: {e}")))?;
        state.save_ssh_key(&key).map_err(|e| fdo::Error::Failed(format!("save key: {e}")))?;
        state.ssh_keys.insert(key.id, key);

        Ok(id_str)
    }

    /// List all SSH keys as a JSON array of summaries.
    async fn ssh_list_keys(&self) -> fdo::Result<String> {
        let state = self.state.lock().await;
        let summaries: Vec<SshKeySummary> = state.ssh_keys.values().map(SshKeySummary::from).collect();
        serde_json::to_string(&summaries).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    // =======================================================================
    // Tailscale tailnet listing
    // =======================================================================

    /// List nodes in the local tailnet via `tailscale status --json`.
    ///
    /// Returns a JSON array of [`crate::tailscale::TailscaleNode`] objects.
    /// Errors when the tailscale CLI isn't installed or tailscaled isn't
    /// running — in either case the GUI surfaces the error string verbatim.
    async fn tailscale_list_nodes(&self) -> fdo::Result<String> {
        let nodes = crate::tailscale::list_nodes()
            .await
            .map_err(fdo::Error::Failed)?;
        serde_json::to_string(&nodes)
            .map_err(|e| fdo::Error::Failed(format!("serialise nodes: {e}")))
    }

    /// Return a single SSH key as JSON.
    async fn ssh_get_key(&self, key_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(key_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let state = self.state.lock().await;
        let key = state.ssh_keys.get(&id).ok_or_else(|| fdo::Error::UnknownObject("key not found".into()))?;
        serde_json::to_string(key).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    /// Delete an SSH key by UUID.
    async fn ssh_delete_key(&self, key_id: &str) -> fdo::Result<()> {
        let id = Uuid::parse_str(key_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let mut state = self.state.lock().await;
        if let Some(key) = state.ssh_keys.remove(&id) {
            let _ = crate::secrets::delete_secret(key.private_key_ref.label()).await;
            let _ = state.delete_ssh_key_file(id);
        }
        Ok(())
    }

    /// Export the public key in OpenSSH authorized_keys format.
    async fn ssh_export_public_key(&self, key_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(key_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let state = self.state.lock().await;
        let key = state.ssh_keys.get(&id).ok_or_else(|| fdo::Error::UnknownObject("key not found".into()))?;
        Ok(key.public_key.clone())
    }

    /// Export the PEM-encoded private key from the secret store.
    async fn ssh_export_private_key(&self, key_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(key_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let state = self.state.lock().await;
        let key = state.ssh_keys.get(&id).ok_or_else(|| fdo::Error::UnknownObject("key not found".into()))?;
        let bytes = crate::secrets::retrieve_secret(key.private_key_ref.label()).await
            .map_err(|e| fdo::Error::Failed(format!("retrieve secret: {e}")))?;
        String::from_utf8(bytes).map_err(|e| fdo::Error::Failed(format!("UTF-8: {e}")))
    }

    /// Scan a directory for SSH key files.
    async fn ssh_import_keys_scan(&self, directory: &str) -> fdo::Result<String> {
        let candidates = crate::ssh::import::scan_ssh_directory(std::path::Path::new(directory));
        serde_json::to_string(&candidates).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    /// Import an existing SSH key pair.
    async fn ssh_import_key(&self, name: &str, public_key: &str, private_key_pem: &str, key_type: &str) -> fdo::Result<String> {
        let kt: SshKeyType = match key_type {
            "ED25519" | "ed25519" | "ssh-ed25519" => SshKeyType::Ed25519,
            "RSA" | "rsa" | "ssh-rsa" => SshKeyType::Rsa4096, // default RSA to 4096
            _ => SshKeyType::Ed25519,
        };

        let fingerprint = crate::ssh::keygen::compute_fingerprint(public_key)
            .map_err(|e| fdo::Error::Failed(format!("fingerprint: {e}")))?;

        // Check for duplicates
        {
            let state = self.state.lock().await;
            if state.ssh_keys.values().any(|k| k.fingerprint == fingerprint) {
                return Err(fdo::Error::Failed(format!("duplicate fingerprint: {fingerprint}")));
            }
        }

        let key_id = Uuid::new_v4();
        let secret_label = format!("supermgr/ssh/{}/privkey", key_id.simple());

        crate::secrets::store_secret(&secret_label, private_key_pem.as_bytes())
            .await.map_err(|e| fdo::Error::Failed(format!("store secret: {e}")))?;

        let now = chrono::Utc::now();
        let key = SshKey {
            id: key_id,
            name: name.to_owned(),
            description: String::new(),
            key_type: kt,
            public_key: public_key.to_owned(),
            private_key_ref: SecretRef::new(secret_label),
            fingerprint,
            tags: Vec::new(),
            deployed_to: Vec::new(),
            created_at: now,
            updated_at: now,
        };

        let id_str = key.id.to_string();
        let mut state = self.state.lock().await;
        tokio::fs::create_dir_all(&state.ssh_key_dir).await
            .map_err(|e| fdo::Error::Failed(format!("create dir: {e}")))?;
        state.save_ssh_key(&key).map_err(|e| fdo::Error::Failed(format!("save: {e}")))?;
        state.ssh_keys.insert(key.id, key);

        Ok(id_str)
    }

    /// Add a new SSH host from a JSON-serialised object.
    async fn add_host(&self, host_json: &str) -> fdo::Result<String> {
        let mut host: Host = serde_json::from_str(host_json)
            .map_err(|e| fdo::Error::InvalidArgs(format!("invalid host JSON: {e}")))?;
        host.id = Uuid::new_v4();
        let now = chrono::Utc::now();
        host.created_at = now;
        host.updated_at = now;

        let id_str = host.id.to_string();
        let mut state = self.state.lock().await;
        tokio::fs::create_dir_all(&state.host_dir).await
            .map_err(|e| fdo::Error::Failed(format!("create dir: {e}")))?;
        state.save_host(&host).map_err(|e| fdo::Error::Failed(format!("save: {e}")))?;
        state.hosts.insert(host.id, host);

        Ok(id_str)
    }

    /// Update an existing SSH host.
    ///
    /// Merges the provided JSON fields into the existing host, preserving
    /// fields not present in the update (e.g. `api_token_ref`, `auth_password_ref`).
    async fn update_host(&self, host_id: &str, host_json: &str) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let updates: serde_json::Value = serde_json::from_str(host_json)
            .map_err(|e| fdo::Error::InvalidArgs(format!("invalid host JSON: {e}")))?;

        let mut state = self.state.lock().await;
        let host = state.hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;

        // Apply only the fields present in the update.
        if let Some(v) = updates.get("label").and_then(|v| v.as_str()) { host.label = v.to_owned(); }
        if let Some(v) = updates.get("hostname").and_then(|v| v.as_str()) { host.hostname = v.to_owned(); }
        if let Some(v) = updates.get("port").and_then(|v| v.as_u64()) { host.port = v as u16; }
        if let Some(v) = updates.get("username").and_then(|v| v.as_str()) { host.username = v.to_owned(); }
        if let Some(v) = updates.get("group").and_then(|v| v.as_str()) { host.group = v.to_owned(); }
        if let Some(v) = updates.get("device_type").and_then(|v| v.as_str()) {
            if let Ok(dt) = serde_json::from_value(serde_json::Value::String(v.to_owned())) {
                host.device_type = dt;
            }
        }
        if let Some(v) = updates.get("auth_method").and_then(|v| v.as_str()) {
            if let Ok(am) = serde_json::from_value::<AuthMethod>(serde_json::Value::String(v.to_owned())) {
                if am != host.auth_method {
                    // Clean up stale fields when switching auth method.
                    match am {
                        AuthMethod::Password => {
                            host.auth_key_id = None;
                            host.auth_cert_ref = None;
                        }
                        AuthMethod::Key => {
                            host.auth_password_ref = None;
                            host.auth_cert_ref = None;
                        }
                        AuthMethod::Certificate => {
                            host.auth_password_ref = None;
                        }
                    }
                }
                host.auth_method = am;
            }
        }
        if let Some(v) = updates.get("auth_key_id") {
            host.auth_key_id = v.as_str().and_then(|s| Uuid::parse_str(s).ok());
        }
        if let Some(v) = updates.get("vpn_profile_id") {
            host.vpn_profile_id = v.as_str().and_then(|s| Uuid::parse_str(s).ok());
        }
        if let Some(v) = updates.get("proxy_jump") {
            host.proxy_jump = v.as_str().and_then(|s| Uuid::parse_str(s).ok());
        }
        if let Some(v) = updates.get("api_port").and_then(|v| v.as_u64()) {
            host.api_port = Some(v as u16);
        }
        // RDP/VNC ports: 0 or null means "not configured".
        if let Some(v) = updates.get("rdp_port") {
            host.rdp_port = v.as_u64().filter(|&p| p > 0).map(|p| p as u16);
        }
        if let Some(v) = updates.get("vnc_port") {
            host.vnc_port = v.as_u64().filter(|&p| p > 0).map(|p| p as u16);
        }
        if let Some(v) = updates.get("pinned").and_then(|v| v.as_bool()) {
            host.pinned = v;
        }
        if let Some(v) = updates.get("port_forwards") {
            if let Ok(pf) = serde_json::from_value(v.clone()) {
                host.port_forwards = pf;
            }
        }
        host.updated_at = chrono::Utc::now();

        let host = host.clone();
        state.save_host(&host).map_err(|e| fdo::Error::Failed(format!("save: {e}")))?;
        Ok(())
    }

    /// Toggle the pinned/favourite state of an SSH host.
    ///
    /// Flips the `pinned` boolean and persists the change.  Returns the
    /// refreshed host list (JSON array of summaries) so the GUI can update.
    async fn toggle_host_pin(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let mut state = self.state.lock().await;
        let host = state.hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.pinned = !host.pinned;
        host.updated_at = chrono::Utc::now();
        let host = host.clone();
        state.save_host(&host).map_err(|e| fdo::Error::Failed(format!("save: {e}")))?;
        let summaries: Vec<HostSummary> = state.hosts.values().map(HostSummary::from).collect();
        serde_json::to_string(&summaries).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    /// Set or clear the customer/tenant tag on an SSH host.
    ///
    /// Pass an empty string to remove the tag (un-group the host).
    async fn ssh_set_host_customer(
        &self,
        host_id: &str,
        customer: &str,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let trimmed = customer.trim().to_owned();

        let mut state = self.state.lock().await;
        let host = state
            .hosts
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.customer = trimmed.clone();
        host.updated_at = chrono::Utc::now();
        let host = host.clone();
        state
            .save_host(&host)
            .map_err(|e| fdo::Error::Failed(format!("save: {e}")))?;
        info!("ssh host {id}: customer set to {trimmed:?}");
        Ok(())
    }

    /// Delete an SSH host by UUID.
    async fn delete_host(&self, host_id: &str) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let mut state = self.state.lock().await;
        state.hosts.remove(&id);
        let _ = state.delete_host_file(id);
        Ok(())
    }

    /// List all SSH hosts as a JSON array of summaries.
    async fn list_hosts(&self) -> fdo::Result<String> {
        let state = self.state.lock().await;
        let summaries: Vec<HostSummary> = state.hosts.values().map(HostSummary::from).collect();
        serde_json::to_string(&summaries).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    /// Return a single SSH host as JSON.
    async fn get_host(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let state = self.state.lock().await;
        let host = state.hosts.get(&id).ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        serde_json::to_string(host).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    /// Push a public key to one or more remote hosts' `authorized_keys`.
    ///
    /// Returns an operation ID; progress is reported via `SshOperationProgress` signals.
    async fn ssh_push_key(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        key_id: &str,
        host_ids_json: &str,
        use_sudo: bool,
    ) -> fdo::Result<String> {
        let kid = Uuid::parse_str(key_id).map_err(|_| fdo::Error::InvalidArgs("invalid key UUID".into()))?;
        let host_ids: Vec<String> = serde_json::from_str(host_ids_json)
            .map_err(|e| fdo::Error::InvalidArgs(format!("invalid host IDs JSON: {e}")))?;

        // Gather key + hosts + private key for auth
        let (public_key, key_name, key_fingerprint, hosts_info, private_key_pem_opt) = {
            let state = self.state.lock().await;
            let key = state.ssh_keys.get(&kid)
                .ok_or_else(|| fdo::Error::UnknownObject("key not found".into()))?;

            let mut hosts_info = Vec::new();
            for hid_str in &host_ids {
                let hid = Uuid::parse_str(hid_str)
                    .map_err(|_| fdo::Error::InvalidArgs(format!("invalid host UUID: {hid_str}")))?;
                let host = state.hosts.get(&hid)
                    .ok_or_else(|| fdo::Error::UnknownObject(format!("host {hid} not found")))?;
                hosts_info.push(host.clone());
            }

            // Get private key for hosts that use key-auth (to authenticate our SSH connection)
            let pem = if let Ok(bytes) = crate::secrets::retrieve_secret(key.private_key_ref.label()).await {
                String::from_utf8(bytes).ok()
            } else {
                None
            };

            (key.public_key.clone(), key.name.clone(), key.fingerprint.clone(), hosts_info, pem)
        };

        let state_arc = Arc::clone(&self.state);
        let ctx_owned = ctx.to_owned();
        let op_id = Uuid::new_v4().to_string();
        let op_id_clone = op_id.clone();

        // Spawn the batch push operation
        tokio::spawn(async move {
            let mut results = Vec::new();

            for host in &hosts_info {
                let _ = DaemonService::ssh_operation_progress(
                    &ctx_owned, op_id_clone.clone(), host.label.clone(),
                    format!("Connecting to {}...", host.hostname),
                ).await;

                // Connect to host
                let session_result = connect_to_ssh_host(
                    host, &private_key_pem_opt, &state_arc,
                ).await;

                let result = match session_result {
                    Err(e) => {
                        let msg = format!("Connection failed: {e}");
                        let _ = DaemonService::ssh_operation_progress(
                            &ctx_owned, op_id_clone.clone(), host.label.clone(), msg.clone(),
                        ).await;
                        crate::ssh::push::PushResult {
                            host_id: host.id.to_string(),
                            host_label: host.label.clone(),
                            success: false,
                            message: msg,
                        }
                    }
                    Ok(session) => {
                        let _ = DaemonService::ssh_operation_progress(
                            &ctx_owned, op_id_clone.clone(), host.label.clone(),
                            "Pushing key...".into(),
                        ).await;

                        match crate::ssh::push::push_public_key(&session, &public_key, use_sudo).await {
                            Ok(()) => {
                                // Record deployment
                                {
                                    let mut state = state_arc.lock().await;
                                    if let Some(k) = state.ssh_keys.get_mut(&kid) {
                                        if !k.deployed_to.contains(&host.id) {
                                            k.deployed_to.push(host.id);
                                        }
                                        let cloned = k.clone();
                                        let _ = state.save_ssh_key(&cloned);
                                    }
                                }
                                // Audit
                                crate::ssh::audit::append_audit(&supermgr_core::ssh::audit::AuditEntry {
                                    timestamp: chrono::Utc::now(),
                                    action: supermgr_core::ssh::audit::AuditAction::Push,
                                    key_name: key_name.clone(),
                                    key_fingerprint: key_fingerprint.clone(),
                                    host_label: host.label.clone(),
                                    hostname: host.hostname.clone(),
                                    port: host.port,
                                    success: true,
                                });

                                let msg = "Key pushed successfully".to_string();
                                let _ = DaemonService::ssh_operation_progress(
                                    &ctx_owned, op_id_clone.clone(), host.label.clone(), msg.clone(),
                                ).await;
                                crate::ssh::push::PushResult {
                                    host_id: host.id.to_string(),
                                    host_label: host.label.clone(),
                                    success: true,
                                    message: msg,
                                }
                            }
                            Err(e) => {
                                crate::ssh::audit::append_audit(&supermgr_core::ssh::audit::AuditEntry {
                                    timestamp: chrono::Utc::now(),
                                    action: supermgr_core::ssh::audit::AuditAction::Push,
                                    key_name: key_name.clone(),
                                    key_fingerprint: key_fingerprint.clone(),
                                    host_label: host.label.clone(),
                                    hostname: host.hostname.clone(),
                                    port: host.port,
                                    success: false,
                                });
                                let msg = format!("Push failed: {e}");
                                let _ = DaemonService::ssh_operation_progress(
                                    &ctx_owned, op_id_clone.clone(), host.label.clone(), msg.clone(),
                                ).await;
                                crate::ssh::push::PushResult {
                                    host_id: host.id.to_string(),
                                    host_label: host.label.clone(),
                                    success: false,
                                    message: msg,
                                }
                            }
                        }
                    }
                };

                results.push(result);
            }

            // Final progress signal
            let _ = DaemonService::ssh_operation_progress(
                &ctx_owned, op_id_clone, String::new(),
                "Push operation complete".into(),
            ).await;
        });

        Ok(op_id)
    }

    /// Revoke a public key from one or more remote hosts' `authorized_keys`.
    ///
    /// Returns an operation ID; progress is reported via `SshOperationProgress` signals.
    async fn ssh_revoke_key(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        key_id: &str,
        host_ids_json: &str,
        use_sudo: bool,
    ) -> fdo::Result<String> {
        let kid = Uuid::parse_str(key_id).map_err(|_| fdo::Error::InvalidArgs("invalid key UUID".into()))?;
        let host_ids: Vec<String> = serde_json::from_str(host_ids_json)
            .map_err(|e| fdo::Error::InvalidArgs(format!("invalid host IDs JSON: {e}")))?;

        // Gather key + hosts + private key for auth
        let (public_key, key_name, key_fingerprint, hosts_info, private_key_pem_opt) = {
            let state = self.state.lock().await;
            let key = state.ssh_keys.get(&kid)
                .ok_or_else(|| fdo::Error::UnknownObject("key not found".into()))?;

            let mut hosts_info = Vec::new();
            for hid_str in &host_ids {
                let hid = Uuid::parse_str(hid_str)
                    .map_err(|_| fdo::Error::InvalidArgs(format!("invalid host UUID: {hid_str}")))?;
                let host = state.hosts.get(&hid)
                    .ok_or_else(|| fdo::Error::UnknownObject(format!("host {hid} not found")))?;
                hosts_info.push(host.clone());
            }

            let pem = if let Ok(bytes) = crate::secrets::retrieve_secret(key.private_key_ref.label()).await {
                String::from_utf8(bytes).ok()
            } else {
                None
            };

            (key.public_key.clone(), key.name.clone(), key.fingerprint.clone(), hosts_info, pem)
        };

        let state_arc = Arc::clone(&self.state);
        let ctx_owned = ctx.to_owned();
        let op_id = Uuid::new_v4().to_string();
        let op_id_clone = op_id.clone();

        // Spawn the batch revoke operation
        tokio::spawn(async move {
            let mut _results = Vec::new();

            for host in &hosts_info {
                let _ = DaemonService::ssh_operation_progress(
                    &ctx_owned, op_id_clone.clone(), host.label.clone(),
                    format!("Connecting to {}...", host.hostname),
                ).await;

                let session_result = connect_to_ssh_host(
                    host, &private_key_pem_opt, &state_arc,
                ).await;

                let result = match session_result {
                    Err(e) => {
                        let msg = format!("Connection failed: {e}");
                        let _ = DaemonService::ssh_operation_progress(
                            &ctx_owned, op_id_clone.clone(), host.label.clone(), msg.clone(),
                        ).await;
                        crate::ssh::push::PushResult {
                            host_id: host.id.to_string(),
                            host_label: host.label.clone(),
                            success: false,
                            message: msg,
                        }
                    }
                    Ok(session) => {
                        let _ = DaemonService::ssh_operation_progress(
                            &ctx_owned, op_id_clone.clone(), host.label.clone(),
                            "Revoking key...".into(),
                        ).await;

                        match crate::ssh::revoke::revoke_public_key(&session, &public_key, use_sudo).await {
                            Ok(()) => {
                                // Remove from deployed_to
                                {
                                    let mut state = state_arc.lock().await;
                                    if let Some(k) = state.ssh_keys.get_mut(&kid) {
                                        k.deployed_to.retain(|id| *id != host.id);
                                        let cloned = k.clone();
                                        let _ = state.save_ssh_key(&cloned);
                                    }
                                }
                                // Audit
                                crate::ssh::audit::append_audit(&supermgr_core::ssh::audit::AuditEntry {
                                    timestamp: chrono::Utc::now(),
                                    action: supermgr_core::ssh::audit::AuditAction::Revoke,
                                    key_name: key_name.clone(),
                                    key_fingerprint: key_fingerprint.clone(),
                                    host_label: host.label.clone(),
                                    hostname: host.hostname.clone(),
                                    port: host.port,
                                    success: true,
                                });

                                let msg = "Key revoked successfully".to_string();
                                let _ = DaemonService::ssh_operation_progress(
                                    &ctx_owned, op_id_clone.clone(), host.label.clone(), msg.clone(),
                                ).await;
                                crate::ssh::push::PushResult {
                                    host_id: host.id.to_string(),
                                    host_label: host.label.clone(),
                                    success: true,
                                    message: msg,
                                }
                            }
                            Err(e) => {
                                crate::ssh::audit::append_audit(&supermgr_core::ssh::audit::AuditEntry {
                                    timestamp: chrono::Utc::now(),
                                    action: supermgr_core::ssh::audit::AuditAction::Revoke,
                                    key_name: key_name.clone(),
                                    key_fingerprint: key_fingerprint.clone(),
                                    host_label: host.label.clone(),
                                    hostname: host.hostname.clone(),
                                    port: host.port,
                                    success: false,
                                });
                                let msg = format!("Revoke failed: {e}");
                                let _ = DaemonService::ssh_operation_progress(
                                    &ctx_owned, op_id_clone.clone(), host.label.clone(), msg.clone(),
                                ).await;
                                crate::ssh::push::PushResult {
                                    host_id: host.id.to_string(),
                                    host_label: host.label.clone(),
                                    success: false,
                                    message: msg,
                                }
                            }
                        }
                    }
                };

                _results.push(result);
            }

            // Final progress signal
            let _ = DaemonService::ssh_operation_progress(
                &ctx_owned, op_id_clone, String::new(),
                "Revoke operation complete".into(),
            ).await;
        });

        Ok(op_id)
    }

    /// Store an SSH password for the given host.
    /// Retrieve the stored SSH password for a host (used for RDP/VNC login).
    async fn ssh_get_password(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let state = self.state.lock().await;
        let host = state.hosts.get(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        let label = match &host.auth_password_ref {
            Some(r) => r.label().to_owned(),
            None => return Err(fdo::Error::Failed("no password stored for this host".into())),
        };
        drop(state);
        let bytes = secrets::retrieve_secret(&label)
            .await
            .map_err(|e| fdo::Error::Failed(format!("retrieve password: {e}")))?;
        String::from_utf8(bytes)
            .map_err(|e| fdo::Error::Failed(format!("password is not valid UTF-8: {e}")))
    }

    async fn ssh_set_password(&self, host_id: &str, password: &str) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let label = format!("supermgr/ssh/{}/password", id.simple());
        secrets::store_secret(&label, password.as_bytes())
            .await
            .map_err(|e| fdo::Error::Failed(format!("store password: {e}")))?;

        let mut state = self.state.lock().await;
        let host = state.hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.auth_password_ref = Some(SecretRef::new(&label));
        host.updated_at = chrono::Utc::now();
        let host = host.clone();
        state.save_host(&host)
            .map_err(|e| fdo::Error::Failed(format!("save host: {e}")))?;

        info!("stored SSH password for host {id}");
        Ok(())
    }

    /// Store an OpenSSH certificate for the given host.
    async fn ssh_set_certificate(&self, host_id: &str, certificate: &str) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let label = format!("supermgr/ssh/{}/certificate", id.simple());
        secrets::store_secret(&label, certificate.as_bytes())
            .await
            .map_err(|e| fdo::Error::Failed(format!("store certificate: {e}")))?;

        let mut state = self.state.lock().await;
        let host = state.hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.auth_cert_ref = Some(SecretRef::new(&label));
        host.updated_at = chrono::Utc::now();
        let host = host.clone();
        state.save_host(&host)
            .map_err(|e| fdo::Error::Failed(format!("save host: {e}")))?;

        info!("stored SSH certificate for host {id}");
        Ok(())
    }

    /// Store a FortiGate REST API token and optional port for the given host.
    async fn ssh_set_api_token(&self, host_id: &str, token: &str, port: u16) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let label = format!("supermgr/fg/{}/api_token", id.simple());
        secrets::store_secret(&label, token.trim().as_bytes())
            .await
            .map_err(|e| fdo::Error::Failed(format!("store API token: {e}")))?;

        let mut state = self.state.lock().await;
        let host = state.hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.api_token_ref = Some(SecretRef::new(&label));
        host.api_port = Some(port);
        host.updated_at = chrono::Utc::now();
        state.save_host(&state.hosts[&id].clone())
            .map_err(|e| fdo::Error::Failed(format!("save host: {e}")))?;

        info!("stored FortiGate API token for host {id} (port {})", port);
        Ok(())
    }

    /// Generate a new FortiGate REST API token via SSH.
    ///
    /// SSHs into the device, creates the API user if needed, generates a key,
    /// stores it, and returns the token string.
    async fn fortigate_generate_api_token(
        &self,
        host_id: &str,
        api_user: &str,
        api_port: u16,
    ) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let host = {
            let state = self.state.lock().await;
            state.hosts.get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?
                .clone()
        };

        info!("fortigate_generate_api_token: generating for user '{}' on {}", api_user, host.hostname);

        // Retrieve the admin password — FortiGate requires it for generate-key.
        let admin_password = if let Some(ref pw_ref) = host.auth_password_ref {
            if let Ok(bytes) = secrets::retrieve_secret(pw_ref.label()).await {
                String::from_utf8(bytes).ok()
            } else {
                None
            }
        } else {
            None
        };

        let state_arc = Arc::clone(&self.state);
        let session = connect_to_ssh_host(&host, &None, &state_arc).await
            .map_err(|e| fdo::Error::Failed(format!("SSH connection failed: {e}")))?;

        // Use interactive shell — each CLI line sent separately, waiting
        // for the FortiGate prompt between each.
        let api_user_owned = api_user.to_owned();
        let cmd_lines: Vec<String> = vec![
            "config system api-user".into(),
            format!("edit \"{api_user_owned}\""),
            "set accprofile \"super_admin\"".into(),
            "set vdom \"root\"".into(),
            "next".into(),
            "end".into(),
            format!("execute api-user generate-key {api_user_owned}"),
        ];
        let mut lines: Vec<&str> = cmd_lines.iter().map(|s| s.as_str()).collect();

        // Add password if we have it (FortiGate will prompt for it).
        let pw_string;
        if let Some(ref pw) = admin_password {
            pw_string = pw.clone();
            lines.push(&pw_string);
        }

        let stdout = session.shell_interact(&lines, 1000, 30).await
            .map_err(|e| fdo::Error::Failed(format!("shell interaction failed: {e}")))?;

        info!("fortigate_generate_api_token: output={}", stdout.trim());
        let exit_code = 0u32; // shell_interact doesn't return exit code

        if exit_code != 0 {
            return Err(fdo::Error::Failed(format!(
                "generate-key failed: {}",
                stdout.trim(),
            )));
        }

        // Parse token from output: "New API key: <token>"
        let token = stdout.lines()
            .find_map(|line| {
                let line = line.trim();
                if line.contains("New API key:") || line.contains("API key:") {
                    line.rsplit(':').next().map(|t| t.trim().to_owned())
                } else {
                    None
                }
            })
            .or_else(|| {
                // Some FW versions just output the token on its own line.
                stdout.lines()
                    .map(str::trim)
                    .find(|l| l.len() > 20 && l.chars().all(|c| c.is_alphanumeric()))
                    .map(String::from)
            })
            .ok_or_else(|| fdo::Error::Failed(format!(
                "could not parse API token from output: {stdout}"
            )))?;

        // Store the token.
        let label = format!("supermgr/fg/{}/api_token", id.simple());
        secrets::store_secret(&label, token.trim().as_bytes())
            .await
            .map_err(|e| fdo::Error::Failed(format!("store token: {e}")))?;

        let mut state = self.state.lock().await;
        let host = state.hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.api_token_ref = Some(SecretRef::new(&label));
        if api_port > 0 {
            host.api_port = Some(api_port);
        }
        host.updated_at = chrono::Utc::now();
        let host = host.clone();
        state.save_host(&host)
            .map_err(|e| fdo::Error::Failed(format!("save host: {e}")))?;

        crate::audit::log_event("FG_API_KEYGEN", &format!("user={api_user} host={}", host.hostname));
        info!("fortigate_generate_api_token: token generated and stored for {}", host.hostname);

        Ok(token)
    }

    /// Retrieve the stored FortiGate API token for a host (for copying to clipboard).
    async fn fortigate_get_api_token(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let state = self.state.lock().await;
        let host = state.hosts.get(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;

        let label = host.api_token_ref.as_ref()
            .ok_or_else(|| fdo::Error::Failed("no API token configured".into()))?
            .label()
            .to_owned();
        drop(state);

        let bytes = secrets::retrieve_secret(&label).await
            .map_err(|e| fdo::Error::Failed(format!("retrieve token: {e}")))?;
        String::from_utf8(bytes)
            .map_err(|e| fdo::Error::Failed(format!("invalid token encoding: {e}")))
    }

    /// Call the FortiGate REST API on a host.
    async fn fortigate_api(
        &self,
        host_id: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let (hostname, api_port, _api_verify_tls, token_label) = {
            let state = self.state.lock().await;
            let host = state.hosts.get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
            let label = host.api_token_ref.as_ref()
                .ok_or_else(|| fdo::Error::Failed("no API token configured for this host".into()))?
                .label()
                .to_owned();
            (
                host.hostname.clone(),
                host.api_port.unwrap_or(443),
                host.api_verify_tls,
                label,
            )
        };

        let token_bytes = secrets::retrieve_secret(&token_label)
            .await
            .map_err(|e| fdo::Error::Failed(format!("retrieve API token: {e}")))?;
        let token = String::from_utf8(token_bytes)
            .map_err(|e| fdo::Error::Failed(format!("invalid API token encoding: {e}")))?;
        let token = token.trim().to_owned();

        let url = format!("https://{hostname}:{api_port}{path}");
        info!("fortigate_api: {method} {url}");
        crate::audit::log_event("FG_API", &format!("{method} {url}"));

        let client = match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!("fortigate_api: client build failed: {e:#}");
                return Err(fdo::Error::Failed(format!("HTTP client build failed: {e}")));
            }
        };

        let mut req = match method.to_uppercase().as_str() {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            "PUT" => client.put(&url),
            "DELETE" => client.delete(&url),
            _ => return Err(fdo::Error::InvalidArgs(format!("invalid method: {method}"))),
        };

        req = req.header("Authorization", format!("Bearer {token}"));
        if !body.is_empty() && method.to_uppercase() != "GET" {
            req = req
                .header("Content-Type", "application/json")
                .body(body.to_owned());
        }

        let resp = req.send().await
            .map_err(|e| {
                let msg = e.to_string().replace(&token, "***");
                error!("fortigate_api: send failed: {msg}");
                error!("fortigate_api: is_connect={} is_timeout={} is_request={}",
                    e.is_connect(), e.is_timeout(), e.is_request());
                if e.is_timeout() {
                    fdo::Error::Failed(format!(
                        "FortiGate API request timed out: the device at {hostname}:{api_port} \
                         did not respond within 30 s — verify the host is reachable"
                    ))
                } else if e.is_connect() {
                    fdo::Error::Failed(format!(
                        "cannot connect to FortiGate at {hostname}:{api_port}: {msg} — \
                         check that the device is online and the API port is correct"
                    ))
                } else {
                    fdo::Error::Failed(format!("FortiGate API request failed: {msg}"))
                }
            })?;

        let status = resp.status().as_u16();
        let resp_body = resp.text().await
            .map_err(|e| fdo::Error::Failed(format!("read response: {e}")))?;

        if status >= 400 {
            let detail = match status {
                401 => "authentication failed: invalid or expired API token".to_owned(),
                403 => "permission denied: the API token lacks required privileges for this operation".to_owned(),
                404 => "API endpoint not found: check the FortiGate firmware version and API path".to_owned(),
                405 => "method not allowed: this API endpoint does not support the requested HTTP method".to_owned(),
                424 => format!("failed dependency: a prerequisite was not met — {}", &resp_body[..resp_body.len().min(200)]),
                s if s >= 500 => format!("FortiGate internal error ({s}): try again later"),
                _ => format!("HTTP {status}: {}", &resp_body[..resp_body.len().min(300)]),
            };
            return Err(fdo::Error::Failed(detail));
        }

        Ok(resp_body)
    }

    /// Push an SSH public key to a FortiGate admin user via REST API.
    ///
    /// Calls `PUT /api/v2/cmdb/system/admin/{admin_user}` with the public key
    /// assigned to `ssh-public-key1`.  Returns a JSON result with status.
    async fn fortigate_push_ssh_key(
        &self,
        host_id: &str,
        key_id: &str,
        admin_user: &str,
    ) -> fdo::Result<String> {
        let hid = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid host UUID".into()))?;
        let kid = Uuid::parse_str(key_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid key UUID".into()))?;

        // Get the public key text.
        let pubkey = {
            let state = self.state.lock().await;
            let key = state.ssh_keys.get(&kid)
                .ok_or_else(|| fdo::Error::UnknownObject("SSH key not found".into()))?;
            key.public_key.clone()
        };

        // Build the request body for FortiGate admin update.
        let body = serde_json::json!({
            "ssh-public-key1": pubkey,
        });

        info!(
            "fortigate_push_ssh_key: pushing key {} to admin '{}' on host {}",
            kid, admin_user, hid
        );
        crate::audit::log_event(
            "FG_PUSH_KEY",
            &format!("key={kid} admin={admin_user} host={hid}"),
        );

        // Delegate to the existing fortigate_api method.
        let path = format!("/api/v2/cmdb/system/admin/{admin_user}");
        let resp = self
            .fortigate_api(host_id, "PUT", &path, &body.to_string())
            .await?;

        Ok(resp)
    }

    /// Execute a shell command on a remote SSH host and return the result.
    ///
    /// Returns JSON: `{ "stdout": "...", "stderr": "...", "exit_code": N }`.
    async fn ssh_execute_command(&self, host_id: &str, command: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let host = {
            let state = self.state.lock().await;
            state.hosts.get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?
                .clone()
        };

        info!("ssh_execute_command: {}@{}:{} $ {}", host.username, host.hostname, host.port, command);
        crate::audit::log_event("SSH_EXEC", &format!("{}@{} $ {}", host.username, host.hostname, command));

        let state_arc = Arc::clone(&self.state);
        let session = connect_to_ssh_host(&host, &None, &state_arc).await
            .map_err(|e| fdo::Error::Failed(format!("SSH connection failed: {e}")))?;

        let (exit_code, stdout, stderr) = session.exec(command).await
            .map_err(|e| fdo::Error::Failed(format!("command execution failed: {e}")))?;

        let result = serde_json::json!({
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
        });

        Ok(result.to_string())
    }

    /// Return recent SSH audit log entries.
    async fn ssh_get_audit_log(&self, max_lines: u32) -> fdo::Result<Vec<String>> {
        Ok(crate::ssh::audit::read_audit(max_lines as usize))
    }

    /// Return the SSH command string for connecting to the given host.
    async fn ssh_connect_command(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        host_id: &str,
    ) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        // --- Auto-VPN: connect the mapped VPN profile if needed -----------
        {
            let state = self.state.lock().await;
            if let Some(host) = state.hosts.get(&id) {
                if let Some(vpn_id) = host.vpn_profile_id {
                    let already_connected = match &state.vpn_state {
                        VpnState::Connected { profile_id, .. } if *profile_id == vpn_id => true,
                        _ => false,
                    };
                    if !already_connected {
                        if state.vpn_state.is_idle() {
                            if let Some(profile) = state.profiles.get(&vpn_id).cloned() {
                                // Drop the lock before the async connect call.
                                drop(state);
                                info!("auto-VPN: connecting profile {vpn_id} for SSH host {id}");
                                connect_profile(profile, Arc::clone(&self.state), ctx.clone()).await?;

                                // Poll for Connected state with a 30 s timeout.
                                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                                loop {
                                    tokio::time::sleep(Duration::from_millis(250)).await;
                                    let s = self.state.lock().await;
                                    match &s.vpn_state {
                                        VpnState::Connected { profile_id, .. } if *profile_id == vpn_id => {
                                            info!("auto-VPN: profile {vpn_id} connected");
                                            break;
                                        }
                                        VpnState::Error { message, .. } => {
                                            return Err(fdo::Error::Failed(
                                                format!("auto-VPN failed: {message}"),
                                            ));
                                        }
                                        VpnState::Disconnected => {
                                            return Err(fdo::Error::Failed(
                                                "auto-VPN: connection attempt ended without connecting".into(),
                                            ));
                                        }
                                        _ => {} // still connecting
                                    }
                                    if tokio::time::Instant::now() >= deadline {
                                        return Err(fdo::Error::Failed(
                                            "auto-VPN: timed out waiting for VPN to connect".into(),
                                        ));
                                    }
                                }
                            } else {
                                warn!("auto-VPN: profile {vpn_id} not found, skipping");
                            }
                        } else {
                            warn!("auto-VPN: VPN not idle, skipping auto-connect for profile {vpn_id}");
                        }
                    }
                }
            }
        }

        // Extract all needed data under the lock, then drop it before async I/O.
        let (port, username, hostname, auth_method, secret_label, password_label, proxy_jump_str) = {
            let state = self.state.lock().await;
            let host = state.hosts.get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;

            let key_label = if host.auth_method == AuthMethod::Key {
                host.auth_key_id.and_then(|kid| {
                    state.ssh_keys.get(&kid)
                        .map(|k| k.private_key_ref.label().to_owned())
                })
            } else {
                None
            };

            let pw_label = host.auth_password_ref.as_ref().map(|r| r.label().to_owned());

            // Build ProxyJump chain string for -J flag (e.g. "user1@jump1:22,user2@jump2:22").
            let jump_str = build_proxy_jump_chain(host.proxy_jump, &state.hosts);

            (host.port, host.username.clone(), host.hostname.clone(), host.auth_method, key_label, pw_label, jump_str)
        };

        crate::audit::log_event("SSH_CONNECT", &format!("{username}@{hostname}:{port}"));

        // Collect temp files created during this call so we can schedule cleanup.
        let mut tmp_files_to_clean: Vec<PathBuf> = Vec::new();

        let mut cmd = if auth_method == AuthMethod::Password {
            // Check if we have a stored password — use sshpass if available.
            let mut pw_cmd = String::new();
            if let Some(ref pw_label) = password_label {
                info!("ssh_connect_command: retrieving password from '{pw_label}'");
                match crate::secrets::retrieve_secret(pw_label).await {
                    Ok(pw_bytes) => {
                        if let Ok(pw) = String::from_utf8(pw_bytes) {
                            let tmp_dir = std::env::temp_dir().join("supermgrd");
                            let _ = std::fs::create_dir_all(&tmp_dir);
                            let tmp_path = tmp_dir.join(format!("pw_{}.txt", id.simple()));
                            info!("ssh_connect_command: writing password to {}", tmp_path.display());
                            if std::fs::write(&tmp_path, pw.as_bytes()).is_ok() {
                                #[cfg(unix)]
                                {
                                    // Readable by owner + group + other so the
                                    // user's sshpass process can read it.  The
                                    // file is deleted after 60 seconds.
                                    use std::os::unix::fs::PermissionsExt;
                                    let _ = std::fs::set_permissions(
                                        &tmp_path,
                                        std::fs::Permissions::from_mode(0o644),
                                    );
                                }
                                tmp_files_to_clean.push(tmp_path.clone());
                                pw_cmd = format!("sshpass -f {} ", tmp_path.display());
                            } else {
                                warn!("ssh_connect_command: failed to write password file");
                            }
                        }
                    }
                    Err(e) => {
                        warn!("ssh_connect_command: failed to retrieve password: {e}");
                    }
                }
            }
            let jump_flag = if let Some(ref j) = proxy_jump_str { format!(" -J {j}") } else { String::new() };
            format!(
                "{pw_cmd}ssh -p {port}{jump_flag} -o PreferredAuthentications=password \
                 -o PubkeyAuthentication=no {username}@{hostname}"
            )
        } else {
            let jump_flag = if let Some(ref j) = proxy_jump_str { format!(" -J {j}") } else { String::new() };
            format!("ssh -p {port}{jump_flag} {username}@{hostname}")
        };

        if auth_method == AuthMethod::Key {
            if let Some(label) = secret_label {
                if let Ok(bytes) = crate::secrets::retrieve_secret(&label).await {
                    let tmp_dir = std::env::temp_dir().join("supermgrd");
                    let _ = std::fs::create_dir_all(&tmp_dir);
                    let src_path = tmp_dir.join(format!("connect_{}.pem", id.simple()));
                    if std::fs::write(&src_path, &bytes).is_ok() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(
                                &src_path,
                                std::fs::Permissions::from_mode(0o644),
                            );
                        }
                        tmp_files_to_clean.push(src_path.clone());
                        // ssh requires 0600 on key files. The daemon writes as
                        // root, so we wrap the command: copy the key to a
                        // user-owned temp file with correct permissions, then ssh.
                        let user_key = format!("/tmp/.supermgr_key_{}", id.simple());
                        let jump_flag = if let Some(ref j) = proxy_jump_str { format!(" -J {j}") } else { String::new() };
                        cmd = format!(
                            "cp {src} {dst} && chmod 600 {dst} && ssh -p {port}{jump_flag} -i {dst} -o IdentitiesOnly=yes {username}@{hostname}; rm -f {dst}",
                            src = src_path.display(),
                            dst = user_key,
                        );
                    }
                }
            }
        }

        // Schedule cleanup of temp files after 60 seconds.
        for path in tmp_files_to_clean {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                if path.exists() {
                    let _ = std::fs::remove_file(&path);
                    debug!("cleaned up temp file: {}", path.display());
                }
            });
        }

        Ok(cmd)
    }

    // =======================================================================
    // SSH health check
    // =======================================================================

    /// Return a JSON map of `host_id → reachable(bool)` for all SSH hosts.
    async fn ssh_host_health(&self) -> fdo::Result<String> {
        let state = self.state.lock().await;
        let map: std::collections::HashMap<String, bool> = state
            .host_health
            .iter()
            .map(|(id, &reachable)| (id.to_string(), reachable))
            .collect();
        serde_json::to_string(&map).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    // =======================================================================
    // Config backup & restore
    // =======================================================================

    /// Export all configuration (profiles, SSH keys, SSH hosts) as a single
    /// JSON string.  Secret values (private keys, passwords) are **not**
    /// included -- only their `SecretRef` labels.  The caller (GUI) saves the
    /// returned string to a file chosen by the user.
    async fn export_all(&self) -> fdo::Result<String> {
        let state = self.state.lock().await;

        let profiles: Vec<&Profile> = state.profiles.values().collect();
        let ssh_keys: Vec<&SshKey> = state.ssh_keys.values().collect();
        let hosts: Vec<&Host> = state.hosts.values().collect();

        // Include all secrets so the backup is self-contained.
        let all_secrets: std::collections::HashMap<String, String> =
            match secrets::read_all_secrets().await {
                Ok(m) => m,
                Err(e) => {
                    warn!("export_all: could not read secrets: {e}");
                    std::collections::HashMap::new()
                }
            };

        // GUI settings (theme, API keys, RDP preference, etc.).
        let gui_settings = {
            let home = std::env::var("HOME").unwrap_or_default();
            let path = if home.is_empty() {
                std::path::PathBuf::from("/etc/supermgrd/gui-settings.json")
            } else {
                // Try common config paths for all users.
                let mut p = std::path::PathBuf::from(&home);
                p.push(".config/supermgr/settings.json");
                p
            };
            // Also check XDG_CONFIG_HOME.
            let paths = [
                std::env::var("XDG_CONFIG_HOME")
                    .map(|d| std::path::PathBuf::from(d).join("supermgr/settings.json"))
                    .ok(),
                Some(std::path::PathBuf::from(format!("{}/.config/supermgr/settings.json", home))),
            ];
            let mut settings_json = serde_json::Value::Null;
            for p in paths.iter().flatten() {
                if let Ok(text) = std::fs::read_to_string(p) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                        settings_json = val;
                        break;
                    }
                }
            }
            let _ = path; // suppress warning
            settings_json
        };

        // FortiGate config backups.
        let mut config_backups: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let backup_dir = std::path::Path::new("/etc/supermgrd/backups");
        if backup_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(backup_dir) {
                for entry in entries.flatten() {
                    if let Ok(name) = entry.file_name().into_string() {
                        if name.ends_with(".conf") {
                            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                                config_backups.insert(name, content);
                            }
                        }
                    }
                }
            }
        }

        let backup = serde_json::json!({
            "version": 3,
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "profiles": profiles,
            "ssh_keys": ssh_keys,
            "hosts": hosts,
            "secrets": all_secrets,
            "gui_settings": gui_settings,
            "config_backups": config_backups,
        });

        serde_json::to_string_pretty(&backup)
            .map_err(|e| fdo::Error::Failed(format!("JSON serialisation failed: {e}")))
    }

    /// Import configuration from a JSON backup string previously produced by
    /// [`Self::export_all`].
    ///
    /// Each imported item receives a new UUID so it never collides with
    /// existing data.  Returns a JSON summary:
    /// `{"profiles": N, "ssh_keys": N, "hosts": N}`.
    async fn import_all(&self, data: &str) -> fdo::Result<String> {
        let backup: serde_json::Value = serde_json::from_str(data)
            .map_err(|e| fdo::Error::InvalidArgs(format!("invalid JSON: {e}")))?;

        let mut imported_profiles: u32 = 0;
        let mut imported_keys: u32 = 0;
        let mut imported_hosts: u32 = 0;

        let mut state = self.state.lock().await;

        // --- Profiles ---
        if let Some(arr) = backup.get("profiles").and_then(|v| v.as_array()) {
            for item in arr {
                match serde_json::from_value::<Profile>(item.clone()) {
                    Ok(mut profile) => {
                        let new_id = Uuid::new_v4();
                        profile.id = new_id;
                        if let Err(e) = state.save_profile(&profile) {
                            warn!("import_all: failed to save profile '{}': {e}", profile.name);
                            continue;
                        }
                        info!("import_all: imported profile '{}' as {new_id}", profile.name);
                        state.profiles.insert(new_id, profile);
                        imported_profiles += 1;
                    }
                    Err(e) => {
                        warn!("import_all: skipping malformed profile: {e}");
                    }
                }
            }
        }

        // --- SSH keys ---
        if let Some(arr) = backup.get("ssh_keys").and_then(|v| v.as_array()) {
            for item in arr {
                match serde_json::from_value::<SshKey>(item.clone()) {
                    Ok(mut key) => {
                        let new_id = Uuid::new_v4();
                        key.id = new_id;
                        let path = state.ssh_key_dir.join(format!("{new_id}.toml"));
                        match toml::to_string_pretty(&key) {
                            Ok(text) => {
                                if let Err(e) = std::fs::create_dir_all(&state.ssh_key_dir) {
                                    warn!("import_all: mkdir ssh_key_dir: {e}");
                                    continue;
                                }
                                if let Err(e) = std::fs::write(&path, &text) {
                                    warn!("import_all: write SSH key file: {e}");
                                    continue;
                                }
                            }
                            Err(e) => {
                                warn!("import_all: TOML serialise SSH key: {e}");
                                continue;
                            }
                        }
                        info!("import_all: imported SSH key '{}' as {new_id}", key.name);
                        state.ssh_keys.insert(new_id, key);
                        imported_keys += 1;
                    }
                    Err(e) => {
                        warn!("import_all: skipping malformed SSH key: {e}");
                    }
                }
            }
        }

        // --- SSH hosts ---
        if let Some(arr) = backup.get("hosts").and_then(|v| v.as_array()) {
            for item in arr {
                match serde_json::from_value::<Host>(item.clone()) {
                    Ok(mut host) => {
                        let new_id = Uuid::new_v4();
                        host.id = new_id;
                        let path = state.host_dir.join(format!("{new_id}.toml"));
                        match toml::to_string_pretty(&host) {
                            Ok(text) => {
                                if let Err(e) = std::fs::create_dir_all(&state.host_dir) {
                                    warn!("import_all: mkdir host_dir: {e}");
                                    continue;
                                }
                                if let Err(e) = std::fs::write(&path, &text) {
                                    warn!("import_all: write SSH host file: {e}");
                                    continue;
                                }
                            }
                            Err(e) => {
                                warn!("import_all: TOML serialise SSH host: {e}");
                                continue;
                            }
                        }
                        info!("import_all: imported SSH host '{}' as {new_id}", host.label);
                        state.hosts.insert(new_id, host);
                        imported_hosts += 1;
                    }
                    Err(e) => {
                        warn!("import_all: skipping malformed SSH host: {e}");
                    }
                }
            }
        }

        // --- Secrets ---
        let mut imported_secrets: u32 = 0;
        if let Some(obj) = backup.get("secrets").and_then(|v| v.as_object()) {
            for (label, value) in obj {
                if let Some(encoded) = value.as_str() {
                    if let Err(e) = secrets::store_secret_raw(label, encoded).await {
                        warn!("import_all: failed to store secret '{label}': {e}");
                    } else {
                        imported_secrets += 1;
                    }
                }
            }
            info!("import_all: restored {imported_secrets} secret(s)");
        }

        // --- GUI settings ---
        let mut restored_settings = false;
        if let Some(settings_val) = backup.get("gui_settings") {
            if !settings_val.is_null() {
                // Write to all likely config paths.
                let home = std::env::var("HOME").unwrap_or_default();
                let config_dir = std::env::var("XDG_CONFIG_HOME")
                    .unwrap_or_else(|_| format!("{home}/.config"));
                let settings_dir = format!("{config_dir}/supermgr");
                let _ = std::fs::create_dir_all(&settings_dir);
                let path = format!("{settings_dir}/settings.json");
                if let Ok(text) = serde_json::to_string_pretty(settings_val) {
                    if std::fs::write(&path, &text).is_ok() {
                        info!("import_all: restored GUI settings to {path}");
                        restored_settings = true;
                    }
                }
            }
        }

        // --- FortiGate config backups ---
        let mut restored_backups: u32 = 0;
        if let Some(obj) = backup.get("config_backups").and_then(|v| v.as_object()) {
            let backup_dir = std::path::Path::new("/etc/supermgrd/backups");
            let _ = std::fs::create_dir_all(backup_dir);
            for (filename, content) in obj {
                if let Some(text) = content.as_str() {
                    let path = backup_dir.join(filename);
                    if !path.exists() {
                        if std::fs::write(&path, text).is_ok() {
                            restored_backups += 1;
                        }
                    }
                }
            }
            if restored_backups > 0 {
                info!("import_all: restored {restored_backups} config backup(s)");
            }
        }

        let summary = serde_json::json!({
            "profiles": imported_profiles,
            "ssh_keys": imported_keys,
            "hosts": imported_hosts,
            "secrets": imported_secrets,
            "settings": restored_settings,
            "config_backups": restored_backups,
        });

        info!(
            "import_all: imported {imported_profiles} profile(s), \
             {imported_keys} SSH key(s), {imported_hosts} SSH host(s), \
             {imported_secrets} secret(s), settings={restored_settings}, \
             {restored_backups} config backup(s)"
        );

        Ok(summary.to_string())
    }

    // =======================================================================
    // UniFi methods
    // =======================================================================

    /// Execute `set-inform <url>` on a UniFi device via SSH.
    ///
    /// The host must be a UniFi device type.  Connects via SSH and runs the
    /// `set-inform` command, returning the command output.
    async fn unifi_set_inform(&self, host_id: &str, inform_url: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let host = {
            let state = self.state.lock().await;
            state.hosts.get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?
                .clone()
        };

        if host.device_type != supermgr_core::ssh::DeviceType::UniFi {
            return Err(fdo::Error::Failed("host is not a UniFi device".into()));
        }

        let cmd = format!("set-inform {inform_url}");
        info!("unifi_set_inform: {}@{}:{} $ {cmd}", host.username, host.hostname, host.port);
        crate::audit::log_event("UNIFI_SET_INFORM", &format!("{}@{} url={inform_url}", host.username, host.hostname));

        let state_arc = Arc::clone(&self.state);
        let session = connect_to_ssh_host(&host, &None, &state_arc).await
            .map_err(|e| fdo::Error::Failed(format!("SSH connection failed: {e}")))?;

        let (exit_code, stdout, stderr) = session.exec(&cmd).await
            .map_err(|e| fdo::Error::Failed(format!("command execution failed: {e}")))?;

        let result = serde_json::json!({
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
        });

        Ok(result.to_string())
    }

    /// Call the UniFi Controller REST API.
    ///
    /// Authenticates with the stored credentials, then makes the API call.
    /// `method` is GET, POST, PUT, or DELETE.  `path` is the API path
    /// (e.g. `/proxy/network/api/s/default/stat/device`).  `body` is optional JSON.
    /// Returns the JSON response body.
    async fn unifi_api(
        &self,
        host_id: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let (controller_url, creds_label) = {
            let state = self.state.lock().await;
            let host = state.hosts.get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
            let url = host.unifi_controller_url.as_ref()
                .ok_or_else(|| fdo::Error::Failed("no UniFi controller URL configured".into()))?
                .clone();
            let label = host.unifi_api_token_ref.as_ref()
                .ok_or_else(|| fdo::Error::Failed("no UniFi credentials configured".into()))?
                .label()
                .to_owned();
            (url, label)
        };

        // Retrieve stored credentials (JSON: {"username": "...", "password": "..."}).
        let creds_bytes = secrets::retrieve_secret(&creds_label)
            .await
            .map_err(|e| fdo::Error::Failed(format!("retrieve UniFi credentials: {e}")))?;
        let creds_str = String::from_utf8(creds_bytes)
            .map_err(|e| fdo::Error::Failed(format!("invalid credentials encoding: {e}")))?;
        let creds: serde_json::Value = serde_json::from_str(&creds_str)
            .map_err(|e| fdo::Error::Failed(format!("parse credentials: {e}")))?;
        let username = creds["username"].as_str()
            .ok_or_else(|| fdo::Error::Failed("missing username in credentials".into()))?;
        let password = creds["password"].as_str()
            .ok_or_else(|| fdo::Error::Failed("missing password in credentials".into()))?;

        info!("unifi_api: {method} {controller_url}{path}");
        crate::audit::log_event("UNIFI_API", &format!("{method} {controller_url}{path}"));

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .cookie_store(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| fdo::Error::Failed(format!("HTTP client build failed: {e}")))?;

        // Authenticate: POST /api/auth/login.
        let login_url = format!("{controller_url}/api/auth/login");
        let login_body = serde_json::json!({
            "username": username,
            "password": password,
        });
        let login_resp = client.post(&login_url)
            .json(&login_body)
            .send()
            .await
            .map_err(|e| fdo::Error::Failed(format!("UniFi login request failed: {e}")))?;

        let login_status = login_resp.status().as_u16();
        if login_status >= 400 {
            let login_body_text = login_resp.text().await.unwrap_or_default();
            return Err(fdo::Error::Failed(format!(
                "UniFi login failed ({login_status}): {login_body_text}"
            )));
        }

        // Make the actual API call (session cookie is reused by the cookie jar).
        let url = format!("{controller_url}{path}");
        let mut req = match method.to_uppercase().as_str() {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            "PUT" => client.put(&url),
            "DELETE" => client.delete(&url),
            _ => return Err(fdo::Error::InvalidArgs(format!("invalid method: {method}"))),
        };

        if !body.is_empty() && method.to_uppercase() != "GET" {
            req = req
                .header("Content-Type", "application/json")
                .body(body.to_owned());
        }

        let resp = req.send().await
            .map_err(|e| fdo::Error::Failed(format!("UniFi API request failed: {e}")))?;

        let status = resp.status().as_u16();
        let resp_body = resp.text().await
            .map_err(|e| fdo::Error::Failed(format!("read response: {e}")))?;

        if status >= 400 {
            return Err(fdo::Error::Failed(format!(
                "UniFi API {status}: {resp_body}"
            )));
        }

        Ok(resp_body)
    }

    /// Store UniFi Controller URL and credentials for a host.
    ///
    /// Authenticates to verify the credentials are valid, then stores
    /// the URL on the host and the credentials in the secret service.
    async fn unifi_set_controller(
        &self,
        host_id: &str,
        url: &str,
        username: &str,
        password: &str,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        // Validate the URL by attempting login.
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| fdo::Error::Failed(format!("HTTP client: {e}")))?;

        let login_url = format!("{url}/api/auth/login");
        let login_body = serde_json::json!({
            "username": username,
            "password": password,
        });
        let resp = client.post(&login_url)
            .json(&login_body)
            .send()
            .await
            .map_err(|e| fdo::Error::Failed(format!("UniFi login failed: {e}")))?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body = resp.text().await.unwrap_or_default();
            return Err(fdo::Error::Failed(format!(
                "UniFi authentication failed ({status}): {body}"
            )));
        }

        // Store credentials as JSON in the secret service.
        let label = format!("supermgr/unifi/{}/credentials", id.simple());
        let creds = serde_json::json!({
            "username": username,
            "password": password,
        });
        secrets::store_secret(&label, creds.to_string().as_bytes())
            .await
            .map_err(|e| fdo::Error::Failed(format!("store credentials: {e}")))?;

        // Update the host record.
        let mut state = self.state.lock().await;
        let host = state.hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.unifi_controller_url = Some(url.to_owned());
        host.unifi_api_token_ref = Some(SecretRef::new(&label));
        host.updated_at = chrono::Utc::now();
        state.save_host(&state.hosts[&id].clone())
            .map_err(|e| fdo::Error::Failed(format!("save host: {e}")))?;

        info!("stored UniFi controller credentials for host {id} (url={url})");
        Ok(())
    }

    // =======================================================================
    // OPNsense REST API
    // =======================================================================

    /// Store OPNsense API credentials (key + secret) for an SSH host and
    /// validate them against the box. The credentials are persisted as a
    /// JSON blob in the system secret service under
    /// `supermgr/opnsense/<uuid>/credentials`; the host's `api_token_ref`
    /// is set to point at it and `api_port` is updated.
    async fn opnsense_set_credentials(
        &self,
        host_id: &str,
        port: u16,
        api_key: &str,
        api_secret: &str,
    ) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        if api_key.trim().is_empty() || api_secret.is_empty() {
            return Err(fdo::Error::InvalidArgs(
                "OPNsense API key and secret must not be empty".into(),
            ));
        }
        let port = if port == 0 { 443 } else { port };

        let hostname = {
            let state = self.state.lock().await;
            state
                .hosts
                .get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?
                .hostname
                .clone()
        };

        // Validate by hitting an inexpensive authenticated endpoint.
        let creds = crate::opnsense::Credentials {
            key: api_key.trim().to_owned(),
            secret: api_secret.to_owned(),
        };
        let resp = crate::opnsense::request(
            &hostname,
            port,
            &creds,
            "GET",
            "/api/diagnostics/system/system_information",
            "",
        )
        .await
        .map_err(fdo::Error::Failed)?;
        if resp.status == 401 || resp.status == 403 {
            return Err(fdo::Error::Failed(format!(
                "OPNsense rejected the credentials (HTTP {}); verify the API key+secret in System → Access → Users",
                resp.status
            )));
        }
        if resp.status >= 400 {
            return Err(fdo::Error::Failed(format!(
                "OPNsense API returned HTTP {} during credential validation: {}",
                resp.status,
                resp.body.chars().take(200).collect::<String>()
            )));
        }

        let label = format!("supermgr/opnsense/{}/credentials", id.simple());
        let blob = serde_json::to_string(&creds)
            .map_err(|e| fdo::Error::Failed(format!("serialise credentials: {e}")))?;
        secrets::store_secret(&label, blob.as_bytes())
            .await
            .map_err(|e| fdo::Error::Failed(format!("store credentials: {e}")))?;

        let mut state = self.state.lock().await;
        let host = state
            .hosts
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.api_token_ref = Some(SecretRef::new(&label));
        host.api_port = Some(port);
        host.updated_at = chrono::Utc::now();
        let host = host.clone();
        state
            .save_host(&host)
            .map_err(|e| fdo::Error::Failed(format!("save host: {e}")))?;

        info!("stored OPNsense credentials for host {id} ({hostname}:{port})");
        Ok(())
    }

    /// Issue a Basic-Auth API call to an OPNsense host and return the body as text.
    ///
    /// Mirrors `fortigate_api`: it's a thin authenticated HTTP proxy so the GUI
    /// can hit any endpoint without re-implementing credential handling.
    async fn opnsense_api(
        &self,
        host_id: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let (hostname, port, creds) = self.load_opnsense_creds(&id).await?;

        crate::audit::log_event("OPNSENSE_API", &format!("{method} {path} on {host_id}"));
        let resp = crate::opnsense::request(&hostname, port, &creds, method, path, body)
            .await
            .map_err(fdo::Error::Failed)?;
        if resp.status >= 400 {
            return Err(fdo::Error::Failed(format!(
                "OPNsense API returned HTTP {}: {}",
                resp.status,
                resp.body.chars().take(500).collect::<String>()
            )));
        }
        Ok(resp.body)
    }

    /// Composite status snapshot for the dashboard.
    ///
    /// Returns the [`crate::opnsense::OpnSenseStatus`] struct serialised as JSON.
    /// Individual underlying endpoint failures are tolerated and surface as
    /// missing fields in the returned struct rather than failing the whole call.
    async fn opnsense_get_status(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let (hostname, port, creds) = self.load_opnsense_creds(&id).await?;
        let status = crate::opnsense::get_status(&hostname, port, &creds).await;
        serde_json::to_string(&status)
            .map_err(|e| fdo::Error::Failed(format!("serialise status: {e}")))
    }

    // =======================================================================
    // SSH test connection
    // =======================================================================

    /// Test SSH and (optionally) FortiGate API connectivity for a host.
    ///
    /// Returns a JSON object like `{"ssh": "ok", "api": "ok"}` or
    /// `{"ssh": "timeout", "api": "auth_failed"}`.  The `api` field is only
    /// present when the host has a FortiGate API token configured.
    async fn test_host_connection(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let host = {
            let state = self.state.lock().await;
            state.hosts.get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?
                .clone()
        };

        info!("test_host_connection: testing {}@{}:{}", host.username, host.hostname, host.port);

        // --- Test SSH connectivity ---
        let state_arc = Arc::clone(&self.state);
        let ssh_result = match tokio::time::timeout(
            Duration::from_secs(10),
            connect_to_ssh_host(&host, &None, &state_arc),
        ).await {
            Ok(Ok(_session)) => "ok".to_string(),
            Ok(Err(e)) => {
                let msg = e.to_string();
                if msg.contains("auth") || msg.contains("Auth") {
                    "auth_failed".to_string()
                } else if msg.contains("refused") {
                    "connection_refused".to_string()
                } else {
                    format!("error: {msg}")
                }
            }
            Err(_) => "timeout".to_string(),
        };

        // --- Test FortiGate API connectivity (if configured) ---
        let api_result = if host.api_token_ref.is_some() {
            let token_label = host.api_token_ref.as_ref().unwrap().label().to_owned();
            let api_port = host.api_port.unwrap_or(443);

            match secrets::retrieve_secret(&token_label).await {
                Ok(token_bytes) => {
                    match String::from_utf8(token_bytes) {
                        Ok(token) => {
                            let token = token.trim().to_owned();
                            let url = format!(
                                "https://{}:{}/api/v2/monitor/system/status",
                                host.hostname, api_port,
                            );
                            let client = reqwest::Client::builder()
                                .danger_accept_invalid_certs(true)
                                .timeout(Duration::from_secs(10))
                                .build()
                                .map_err(|e| fdo::Error::Failed(format!("HTTP client: {e}")))?;

                            match client.get(&url)
                                .query(&[("access_token", &token)])
                                .send()
                                .await
                            {
                                Ok(resp) => {
                                    let status = resp.status().as_u16();
                                    if status == 200 {
                                        Some("ok".to_string())
                                    } else if status == 401 || status == 403 {
                                        Some("auth_failed".to_string())
                                    } else {
                                        Some(format!("http_{status}"))
                                    }
                                }
                                Err(e) => {
                                    if e.is_timeout() {
                                        Some("timeout".to_string())
                                    } else {
                                        Some(format!("error: {e}"))
                                    }
                                }
                            }
                        }
                        Err(_) => Some("error: invalid token encoding".to_string()),
                    }
                }
                Err(e) => Some(format!("error: retrieve token: {e}")),
            }
        } else {
            None
        };

        let mut result = serde_json::json!({ "ssh": ssh_result });
        if let Some(api) = api_result {
            result["api"] = serde_json::Value::String(api);
        }

        info!("test_host_connection result for {id}: {result}");
        Ok(result.to_string())
    }

    // =======================================================================
    // Config versioning
    // =======================================================================

    /// Save a generated config with a timestamp for later comparison.
    ///
    /// Stores the config text to `/etc/supermgrd/configs/{customer}_{timestamp}.conf`
    /// and returns the filename.
    async fn save_config_version(
        &self,
        customer: &str,
        device_type: &str,
        config: &str,
    ) -> fdo::Result<String> {
        use std::io::Write;

        let dir = PathBuf::from("/etc/supermgrd/configs");
        std::fs::create_dir_all(&dir)
            .map_err(|e| fdo::Error::Failed(format!("cannot create config dir: {e}")))?;

        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let sanitized = customer
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
            .collect::<String>();
        let filename = format!("{}_{}_{}_.conf", sanitized, device_type.to_lowercase(), ts);
        let path = dir.join(&filename);

        let mut f = std::fs::File::create(&path)
            .map_err(|e| fdo::Error::Failed(format!("cannot create config file: {e}")))?;
        f.write_all(config.as_bytes())
            .map_err(|e| fdo::Error::Failed(format!("cannot write config file: {e}")))?;

        info!("saved config version: {filename}");
        Ok(filename)
    }

    /// List saved config versions for a customer.
    ///
    /// Returns a JSON array of objects with `filename` and `timestamp` fields.
    async fn list_config_versions(&self, customer: &str) -> fdo::Result<String> {
        let dir = PathBuf::from("/etc/supermgrd/configs");
        if !dir.exists() {
            return Ok("[]".into());
        }

        let sanitized = customer
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
            .collect::<String>();

        let mut entries = Vec::new();
        let read_dir = std::fs::read_dir(&dir)
            .map_err(|e| fdo::Error::Failed(format!("cannot read config dir: {e}")))?;

        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&sanitized) && name.ends_with(".conf") {
                let meta = entry.metadata().ok();
                let modified = meta
                    .and_then(|m| m.modified().ok())
                    .map(|t| {
                        let dt: chrono::DateTime<chrono::Utc> = t.into();
                        dt.to_rfc3339()
                    })
                    .unwrap_or_default();
                entries.push(serde_json::json!({
                    "filename": name,
                    "timestamp": modified,
                }));
            }
        }

        // Sort newest first
        entries.sort_by(|a, b| {
            let ta = a["timestamp"].as_str().unwrap_or("");
            let tb = b["timestamp"].as_str().unwrap_or("");
            tb.cmp(ta)
        });

        serde_json::to_string(&entries)
            .map_err(|e| fdo::Error::Failed(format!("serialisation failed: {e}")))
    }

    /// Retrieve a previously saved config version by filename.
    async fn get_config_version(&self, filename: &str) -> fdo::Result<String> {
        // Sanitize: only allow simple filenames (no path traversal)
        if filename.contains('/') || filename.contains("..") {
            return Err(fdo::Error::InvalidArgs("invalid filename".into()));
        }
        let path = PathBuf::from("/etc/supermgrd/configs").join(filename);
        std::fs::read_to_string(&path)
            .map_err(|e| fdo::Error::Failed(format!("cannot read config file: {e}")))
    }

    // =======================================================================
    // Signals
    // =======================================================================

    /// Emitted on every VPN state transition.  `state_json` is a JSON-encoded
    /// [`supermgr_core::vpn::state::VpnState`].
    #[zbus(signal)]
    async fn state_changed(ctx: &SignalContext<'_>, state_json: String) -> zbus::Result<()>;

    /// Emitted approximately every 5 seconds while a tunnel is active.
    /// `stats_json` is a JSON-encoded [`supermgr_core::vpn::state::TunnelStats`].
    #[zbus(signal)]
    async fn stats_updated(ctx: &SignalContext<'_>, stats_json: String) -> zbus::Result<()>;

    /// Emitted during Azure Entra ID authentication to present the device-code
    /// challenge to the user.  The GUI should show `user_code` and direct the
    /// user to `verification_url` (typically `https://microsoft.com/devicelogin`).
    #[zbus(signal)]
    async fn auth_challenge(
        ctx: &SignalContext<'_>,
        user_code: String,
        verification_url: String,
    ) -> zbus::Result<()>;

    /// Emitted during multi-host SSH operations (push/revoke) to report
    /// per-host progress.
    #[zbus(signal)]
    async fn ssh_operation_progress(
        ctx: &SignalContext<'_>,
        operation_id: String,
        host_label: String,
        message: String,
    ) -> zbus::Result<()>;

    // =======================================================================
    // FortiGate config backup
    // =======================================================================

    /// Download the FortiGate running config and save it to disk.
    ///
    /// Calls `GET /api/v2/monitor/system/config/backup?scope=global` and
    /// saves to `/etc/supermgrd/backups/{hostname}_{timestamp}.conf`.
    async fn fortigate_backup_config(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let (hostname, api_port, token_label) = {
            let state = self.state.lock().await;
            let host = state
                .hosts
                .get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
            let label = host
                .api_token_ref
                .as_ref()
                .ok_or_else(|| {
                    fdo::Error::Failed("no API token configured for this host".into())
                })?
                .label()
                .to_owned();
            (
                host.hostname.clone(),
                host.api_port.unwrap_or(443),
                label,
            )
        };

        let token_bytes = secrets::retrieve_secret(&token_label)
            .await
            .map_err(|e| fdo::Error::Failed(format!("retrieve API token: {e}")))?;
        let token = String::from_utf8(token_bytes)
            .map_err(|e| fdo::Error::Failed(format!("invalid API token encoding: {e}")))?;
        let token = token.trim().to_owned();

        let url = format!(
            "https://{hostname}:{api_port}/api/v2/monitor/system/config/backup?scope=global"
        );
        info!("fortigate_backup_config: POST {url}");
        crate::audit::log_event("FG_BACKUP", &format!("POST {url}"));

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| fdo::Error::Failed(format!("HTTP client build failed: {e}")))?;

        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(|e| {
                let msg = e.to_string().replace(&token, "***");
                error!("fortigate_backup_config: request failed: {msg}");
                if e.is_timeout() {
                    fdo::Error::Failed(format!(
                        "backup request timed out: the FortiGate at {hostname}:{api_port} \
                         did not respond within 60 s — the device may be under heavy load"
                    ))
                } else if e.is_connect() {
                    fdo::Error::Failed(format!(
                        "cannot connect to FortiGate at {hostname}:{api_port}: {msg} — \
                         check that the device is online and the API port is correct"
                    ))
                } else {
                    fdo::Error::Failed(format!("backup request failed: {msg}"))
                }
            })?;

        let status = resp.status().as_u16();
        info!("fortigate_backup_config: HTTP {status}");
        let body = resp
            .text()
            .await
            .map_err(|e| fdo::Error::Failed(format!("read response: {e}")))?;

        if status >= 400 {
            error!("fortigate_backup_config: API error {status}: {}", &body[..body.len().min(200)]);
            let detail = match status {
                401 => "authentication failed: invalid or expired API token",
                403 => "permission denied: the API token lacks backup privileges",
                404 => "backup endpoint not found: check FortiGate firmware version",
                _ if status >= 500 => "FortiGate internal error: try again later",
                _ => "",
            };
            return Err(fdo::Error::Failed(if detail.is_empty() {
                format!("FortiGate backup API error (HTTP {status}): {}", &body[..body.len().min(200)])
            } else {
                format!("FortiGate backup failed: {detail} (HTTP {status})")
            }));
        }

        // Save to /etc/supermgrd/backups/
        let backup_dir = PathBuf::from("/etc/supermgrd/backups");
        tokio::fs::create_dir_all(&backup_dir)
            .await
            .map_err(|e| fdo::Error::Failed(format!("create backup dir: {e}")))?;

        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        // Sanitise hostname for use in filename.
        let safe_host: String = hostname
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
            .collect();
        let filename = format!("{safe_host}_{ts}.conf");
        let filepath = backup_dir.join(&filename);

        tokio::fs::write(&filepath, &body)
            .await
            .map_err(|e| fdo::Error::Failed(format!("write backup: {e}")))?;

        info!("fortigate_backup_config: saved {filepath:?} ({} bytes)", body.len());
        Ok(filename)
    }

    // =======================================================================
    // FortiGate CIS compliance check
    // =======================================================================

    /// Run CIS benchmark checks against a FortiGate device via SSH.
    ///
    /// SSHes into the device and runs a series of `show` commands, checking the
    /// output against CIS FortiGate hardening recommendations.
    ///
    /// Returns a JSON object with individual check results and a summary score.
    async fn fortigate_compliance_check(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let host = {
            let state = self.state.lock().await;
            state
                .hosts
                .get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?
                .clone()
        };

        info!(
            "fortigate_compliance_check: {}@{}:{}",
            host.username, host.hostname, host.port
        );
        crate::audit::log_event(
            "FG_COMPLIANCE",
            &format!("{}@{}", host.username, host.hostname),
        );

        let state_arc = Arc::clone(&self.state);
        let session = connect_to_ssh_host(&host, &None, &state_arc)
            .await
            .map_err(|e| fdo::Error::Failed(format!("SSH connection failed: {e}")))?;

        let mut checks: Vec<serde_json::Value> = Vec::new();

        // --- Check 1: admin-sport (non-default HTTPS port) ---
        let (_, out, _) = session
            .exec("show system global | grep admin-sport")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let port_val = out
            .lines()
            .find(|l| l.contains("admin-sport"))
            .and_then(|l| l.split_whitespace().last())
            .unwrap_or("443");
        checks.push(serde_json::json!({
            "name": "Admin HTTPS non-default port",
            "status": if port_val.trim() != "443" { "pass" } else { "fail" },
            "detail": format!("Port {}", port_val.trim()),
        }));

        // --- Check 2: strong-crypto ---
        let (_, out, _) = session
            .exec("show system global | grep strong-crypto")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let strong_crypto = out.contains("enable");
        checks.push(serde_json::json!({
            "name": "Strong crypto enabled",
            "status": if strong_crypto { "pass" } else { "fail" },
            "detail": if strong_crypto { "strong-crypto enabled" } else { "strong-crypto not enabled" },
        }));

        // --- Check 3: admin-telnet disabled ---
        let (_, out, _) = session
            .exec("show system global | grep admin-telnet")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let telnet_disabled = out.contains("disable");
        checks.push(serde_json::json!({
            "name": "Telnet disabled",
            "status": if telnet_disabled { "pass" } else { "fail" },
            "detail": if telnet_disabled { "admin-telnet disabled" } else { "admin-telnet not disabled" },
        }));

        // --- Check 4: password-policy min-length >= 14 ---
        let (_, out, _) = session
            .exec("show system password-policy | grep min-length")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let min_len: u32 = out
            .lines()
            .find(|l| l.contains("min-length"))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        checks.push(serde_json::json!({
            "name": "Password min-length >= 14",
            "status": if min_len >= 14 { "pass" } else { "fail" },
            "detail": format!("min-length {}", min_len),
        }));

        // --- Check 5: password expiry enabled ---
        let (_, out, _) = session
            .exec("show system password-policy | grep expire-status")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let expire_enabled = out.contains("enable");
        checks.push(serde_json::json!({
            "name": "Password expiry enabled",
            "status": if expire_enabled { "pass" } else { "fail" },
            "detail": if expire_enabled { "expire-status enabled" } else { "expire-status not enabled" },
        }));

        // --- Check 6: implicit firewall policy logging ---
        let (_, out, _) = session
            .exec("show log setting | grep fwpolicy-implicit-log")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let implicit_log = out.contains("enable");
        checks.push(serde_json::json!({
            "name": "Implicit policy logging",
            "status": if implicit_log { "pass" } else { "fail" },
            "detail": if implicit_log { "fwpolicy-implicit-log enabled" } else { "fwpolicy-implicit-log not enabled" },
        }));

        // --- Check 7: WAN1 allowaccess has no https ---
        let (_, out, _) = session
            .exec("show system interface wan1 | grep allowaccess")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let wan_has_https = out.to_lowercase().contains("https");
        checks.push(serde_json::json!({
            "name": "WAN1 no HTTPS management",
            "status": if !wan_has_https { "pass" } else { "fail" },
            "detail": if wan_has_https { "https found in WAN1 allowaccess" } else { "https not in WAN1 allowaccess" },
        }));

        // --- Check 8: WAN1 allowaccess has no ssh ---
        let wan_has_ssh = out.to_lowercase().contains("ssh");
        checks.push(serde_json::json!({
            "name": "WAN1 no SSH management",
            "status": if !wan_has_ssh { "pass" } else { "fail" },
            "detail": if wan_has_ssh { "ssh found in WAN1 allowaccess" } else { "ssh not in WAN1 allowaccess" },
        }));

        // --- Check 9: DoS policy exists ---
        let (_, out, _) = session
            .exec("show firewall DoS-policy")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let has_dos_policy = out.contains("edit ");
        checks.push(serde_json::json!({
            "name": "DoS policy configured",
            "status": if has_dos_policy { "pass" } else { "fail" },
            "detail": if has_dos_policy { "DoS policy entries found" } else { "no DoS policy entries" },
        }));

        // --- Check 10: admin-maintainer disabled ---
        let (_, out, _) = session
            .exec("show system global | grep admin-maintainer")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let maintainer_disabled = out.contains("disable");
        checks.push(serde_json::json!({
            "name": "Admin maintainer disabled",
            "status": if maintainer_disabled { "pass" } else { "fail" },
            "detail": if maintainer_disabled { "admin-maintainer disabled" } else { "admin-maintainer not disabled" },
        }));

        // --- Check 11: NTP configured ---
        let (_, out, _) = session
            .exec("show system ntp | grep ntpsync")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let ntp_enabled = out.contains("enable");
        checks.push(serde_json::json!({
            "name": "NTP synchronisation enabled",
            "status": if ntp_enabled { "pass" } else { "fail" },
            "detail": if ntp_enabled { "ntpsync enabled" } else { "ntpsync not enabled" },
        }));

        // --- Check 12: Idle timeout <= 15 minutes ---
        let (_, out, _) = session
            .exec("show system global | grep admintimeout")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let timeout: u32 = out
            .lines()
            .find(|l| l.contains("admintimeout"))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        checks.push(serde_json::json!({
            "name": "Admin idle timeout <= 15 min",
            "status": if timeout > 0 && timeout <= 15 { "pass" } else { "fail" },
            "detail": format!("admintimeout {}", timeout),
        }));

        // --- Check 13: Local-in policy present ---
        let (_, out, _) = session
            .exec("show firewall local-in-policy")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let has_local_in = out.contains("edit ");
        checks.push(serde_json::json!({
            "name": "Local-in policy configured",
            "status": if has_local_in { "pass" } else { "fail" },
            "detail": if has_local_in { "local-in-policy entries found" } else { "no local-in-policy entries" },
        }));

        // --- Check 14: SSL/SSH inspection profile exists ---
        let (_, out, _) = session
            .exec("show firewall ssl-ssh-profile")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let has_ssl_profile = out.contains("edit ");
        checks.push(serde_json::json!({
            "name": "SSL/SSH inspection profile",
            "status": if has_ssl_profile { "pass" } else { "fail" },
            "detail": if has_ssl_profile { "SSL/SSH inspection profiles found" } else { "no custom SSL/SSH profiles" },
        }));

        // --- Check 15: USB auto-install disabled ---
        let (_, out, _) = session
            .exec("show system auto-install | grep auto-install-config")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let usb_disabled = out.contains("disable");
        checks.push(serde_json::json!({
            "name": "USB auto-install disabled",
            "status": if usb_disabled { "pass" } else { "fail" },
            "detail": if usb_disabled { "auto-install-config disabled" } else { "auto-install-config not disabled" },
        }));

        // --- Check 16: Antivirus profile configured ---
        let (_, out, _) = session
            .exec("show antivirus profile")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let has_av = out.contains("edit ");
        checks.push(serde_json::json!({
            "name": "Antivirus profile configured",
            "status": if has_av { "pass" } else { "fail" },
            "detail": if has_av { "antivirus profiles found" } else { "no custom antivirus profiles" },
        }));

        // --- Check 17: IPS sensor configured ---
        let (_, out, _) = session
            .exec("show ips sensor")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let has_ips = out.contains("edit ");
        checks.push(serde_json::json!({
            "name": "IPS sensor configured",
            "status": if has_ips { "pass" } else { "fail" },
            "detail": if has_ips { "IPS sensors found" } else { "no IPS sensors configured" },
        }));

        // --- Check 18: HA configured (if applicable) ---
        let (_, out, _) = session
            .exec("show system ha | grep mode")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let ha_active = !out.contains("standalone");
        checks.push(serde_json::json!({
            "name": "High availability mode",
            "status": if ha_active { "pass" } else { "info" },
            "detail": if ha_active { "HA configured" } else { "standalone mode" },
        }));

        // --- Check 19: Logging to remote syslog ---
        let (_, out, _) = session
            .exec("show log syslogd setting | grep status")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let syslog_enabled = out.contains("enable");
        checks.push(serde_json::json!({
            "name": "Remote syslog enabled",
            "status": if syslog_enabled { "pass" } else { "fail" },
            "detail": if syslog_enabled { "syslog logging enabled" } else { "syslog logging not enabled" },
        }));

        // --- Check 20: DNS filtering configured ---
        let (_, out, _) = session
            .exec("show dnsfilter profile")
            .await
            .map_err(|e| fdo::Error::Failed(format!("exec failed: {e}")))?;
        let has_dns_filter = out.contains("edit ");
        checks.push(serde_json::json!({
            "name": "DNS filter profile",
            "status": if has_dns_filter { "pass" } else { "fail" },
            "detail": if has_dns_filter { "DNS filter profiles found" } else { "no DNS filter profiles" },
        }));

        // Summarise.
        let passed = checks.iter().filter(|c| c["status"] == "pass").count();
        let total = checks.len();
        let failed = total - passed;

        let result = serde_json::json!({
            "checks": checks,
            "score": format!("{passed}/{total}"),
            "passed": passed,
            "failed": failed,
            "total": total,
        });

        Ok(result.to_string())
    }

    // ===================================================================
    // SSH port forwarding
    // ===================================================================

    /// Start a local TCP port forward through an SSH tunnel.
    ///
    /// Returns a unique forward ID string.
    async fn ssh_start_port_forward(
        &self,
        host_id: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> fdo::Result<String> {
        let hid = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        // Clone the data we need before starting the background task.
        let state = self.state.lock().await;
        let host = state
            .hosts
            .get(&hid)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?
            .clone();
        drop(state);

        // Bind the local TCP listener first so we fail fast on port conflicts.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port))
            .await
            .map_err(|e| fdo::Error::Failed(format!("bind 127.0.0.1:{local_port}: {e}")))?;

        let forward_id = Uuid::new_v4().to_string();
        let fwd_id_for_task = forward_id.clone();
        let remote_host_owned = remote_host.to_owned();
        let state_arc = Arc::clone(&self.state);

        let task = tokio::spawn(async move {
            let forward_id = fwd_id_for_task;
            info!(
                "port forward {}: listening on 127.0.0.1:{} → {}:{}",
                forward_id, local_port, remote_host_owned, remote_port
            );

            // Establish one SSH session for this forward's lifetime.
            let session = match connect_to_ssh_host(&host, &None, &state_arc).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    error!("port forward: SSH connect failed: {e}");
                    return;
                }
            };

            loop {
                let (tcp_stream, _peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("port forward: accept failed: {e}");
                        break;
                    }
                };

                let session = Arc::clone(&session);
                let rhost = remote_host_owned.clone();

                tokio::spawn(async move {
                    let channel = match session
                        .channel_open_direct_tcpip(&rhost, remote_port)
                        .await
                    {
                        Ok(ch) => ch,
                        Err(e) => {
                            error!("port forward: direct-tcpip open failed: {e}");
                            return;
                        }
                    };

                    let mut stream = channel.into_stream();
                    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);
                    let (mut ch_read, mut ch_write) = tokio::io::split(&mut stream);

                    let _ = tokio::select! {
                        r = tokio::io::copy(&mut tcp_read, &mut ch_write) => r,
                        r = tokio::io::copy(&mut ch_read, &mut tcp_write) => r,
                    };
                });
            }
        });

        let fwd_id = forward_id.clone();
        let mut state = self.state.lock().await;
        state.port_forwards.insert(
            fwd_id.clone(),
            PortForwardEntry {
                host_id: host_id.to_owned(),
                local_port,
                remote_host: remote_host.to_owned(),
                remote_port,
                task,
            },
        );

        info!("started port forward {fwd_id}: 127.0.0.1:{local_port} → {remote_host}:{remote_port} via {host_id}");
        Ok(fwd_id)
    }

    /// Stop an active port forward.
    async fn ssh_stop_port_forward(&self, forward_id: &str) -> fdo::Result<()> {
        let mut state = self.state.lock().await;
        let entry = state
            .port_forwards
            .remove(forward_id)
            .ok_or_else(|| fdo::Error::UnknownObject("forward not found".into()))?;
        entry.task.abort();
        info!("stopped port forward {forward_id}");
        Ok(())
    }

    /// List active port forwards as a JSON array.
    async fn ssh_list_port_forwards(&self) -> fdo::Result<String> {
        let state = self.state.lock().await;
        let list: Vec<serde_json::Value> = state
            .port_forwards
            .iter()
            .map(|(id, entry)| {
                serde_json::json!({
                    "forward_id": id,
                    "host_id": entry.host_id,
                    "local_port": entry.local_port,
                    "remote_host": entry.remote_host,
                    "remote_port": entry.remote_port,
                })
            })
            .collect();
        Ok(serde_json::to_string(&list)
            .map_err(|e| fdo::Error::Failed(e.to_string()))?)
    }

    /// Emitted when the reachability of an SSH host changes.
    #[zbus(signal)]
    async fn host_health_changed(
        ctx: &SignalContext<'_>,
        host_id: String,
        reachable: bool,
    ) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// SSH connection helper (shared by push and revoke)
// ---------------------------------------------------------------------------

/// Connect to an SSH host using its configured authentication method.
///
/// Tries the key being pushed first (if available), then falls back to the
/// host's own auth key or password.
///
/// If the host has a `proxy_jump` configured, the connection is tunnelled
/// through the jump host (recursively, to support chaining).
async fn connect_to_ssh_host(
    host: &Host,
    push_key_pem: &Option<String>,
    state_arc: &Arc<Mutex<DaemonState>>,
) -> Result<crate::ssh::connection::SshSession, supermgr_core::error::SshError> {
    // If a jump host is configured, connect through it.
    if let Some(jump_id) = host.proxy_jump {
        return connect_via_jump(host, jump_id, push_key_pem, state_arc, 0).await;
    }

    connect_direct(host, push_key_pem, state_arc).await
}

/// Connect directly to a host (no jump host).
async fn connect_direct(
    host: &Host,
    push_key_pem: &Option<String>,
    state_arc: &Arc<Mutex<DaemonState>>,
) -> Result<crate::ssh::connection::SshSession, supermgr_core::error::SshError> {
    match host.auth_method {
        AuthMethod::Key | AuthMethod::Certificate => {
            // Resolve the private key PEM.
            let pem = if let Some(ref p) = push_key_pem {
                Some(p.clone())
            } else if let Some(auth_key_id) = host.auth_key_id {
                let state = state_arc.lock().await;
                if let Some(auth_key) = state.ssh_keys.get(&auth_key_id) {
                    let label = auth_key.private_key_ref.label().to_owned();
                    drop(state);
                    crate::secrets::retrieve_secret(&label).await.ok()
                        .and_then(|b| String::from_utf8(b).ok())
                } else {
                    None
                }
            } else {
                None
            };

            let pem = pem.ok_or_else(|| {
                supermgr_core::error::SshError::AuthFailed("no auth key available".into())
            })?;

            // For certificate auth, also retrieve the certificate.
            if host.auth_method == AuthMethod::Certificate {
                if let Some(ref cert_ref) = host.auth_cert_ref {
                    if let Ok(cert_bytes) = crate::secrets::retrieve_secret(cert_ref.label()).await {
                        if let Ok(cert_str) = String::from_utf8(cert_bytes) {
                            return crate::ssh::connection::SshSession::connect_certificate(
                                &host.hostname, host.port, &host.username, &pem, &cert_str, 30,
                            ).await;
                        }
                    }
                }
                // Fall through to plain key auth if cert unavailable.
                warn!("certificate not found for host {}, falling back to key auth", host.hostname);
            }

            crate::ssh::connection::SshSession::connect_key(
                &host.hostname, host.port, &host.username, &pem, 30,
            ).await
        }
        AuthMethod::Password => {
            if let Some(ref pw_ref) = host.auth_password_ref {
                if let Ok(bytes) = crate::secrets::retrieve_secret(pw_ref.label()).await {
                    if let Ok(pw) = String::from_utf8(bytes) {
                        return crate::ssh::connection::SshSession::connect_password(
                            &host.hostname, host.port, &host.username, &pw, 30,
                        ).await;
                    }
                }
            }
            Err(supermgr_core::error::SshError::AuthFailed("no password configured".into()))
        }
    }
}

/// Build a ProxyJump chain string for the `-J` flag of the `ssh` CLI.
///
/// Walks the chain of jump hosts and returns something like
/// `"user1@host1:22,user2@host2:22"`, or `None` if no jump host is set.
fn build_proxy_jump_chain(
    proxy_jump: Option<uuid::Uuid>,
    hosts: &std::collections::HashMap<uuid::Uuid, Host>,
) -> Option<String> {
    let mut current = proxy_jump?;
    let mut parts = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for _ in 0..MAX_PROXY_JUMP_DEPTH {
        if !seen.insert(current) {
            break; // cycle detected
        }
        let host = hosts.get(&current)?;
        parts.push(format!("{}@{}:{}", host.username, host.hostname, host.port));
        match host.proxy_jump {
            Some(next) => current = next,
            None => break,
        }
    }

    // Reverse so the outermost jump host is first (SSH -J expects this order).
    parts.reverse();
    Some(parts.join(","))
}

/// Maximum proxy jump chain depth to prevent infinite loops.
const MAX_PROXY_JUMP_DEPTH: u8 = 10;

/// Connect to a host by first establishing a tunnel through a jump host.
///
/// Supports recursive chaining: if the jump host itself has a `proxy_jump`,
/// we connect through that chain first.
async fn connect_via_jump(
    target: &Host,
    jump_id: uuid::Uuid,
    push_key_pem: &Option<String>,
    state_arc: &Arc<Mutex<DaemonState>>,
    depth: u8,
) -> Result<crate::ssh::connection::SshSession, supermgr_core::error::SshError> {
    use supermgr_core::error::SshError;

    if depth >= MAX_PROXY_JUMP_DEPTH {
        return Err(SshError::ConnectionFailed {
            host: target.hostname.clone(),
            reason: "proxy jump chain too deep (possible loop)".into(),
        });
    }

    // Look up the jump host.
    let jump_host = {
        let state = state_arc.lock().await;
        state.hosts.get(&jump_id).cloned().ok_or_else(|| SshError::ConnectionFailed {
            host: target.hostname.clone(),
            reason: format!("jump host {jump_id} not found"),
        })?
    };

    info!(
        "ProxyJump: connecting to {} via jump host {} (depth {depth})",
        target.hostname, jump_host.hostname,
    );

    // Connect to the jump host (recursively if it also has a proxy_jump).
    let jump_session = if let Some(next_jump_id) = jump_host.proxy_jump {
        Box::pin(connect_via_jump(&jump_host, next_jump_id, push_key_pem, state_arc, depth + 1)).await?
    } else {
        connect_direct(&jump_host, push_key_pem, state_arc).await?
    };

    // Open a tunnel through the jump host to the target.
    let tunnel_stream = jump_session
        .open_tunnel(&target.hostname, target.port)
        .await?;

    let target_addr = format!("{}:{}", target.hostname, target.port);

    // Authenticate through the tunnel to the target host.
    if target.auth_method == AuthMethod::Key || target.auth_method == AuthMethod::Certificate {
        if let Some(ref pem) = push_key_pem {
            return crate::ssh::connection::SshSession::connect_key_stream(
                tunnel_stream, &target_addr, &target.username, pem,
            ).await;
        }
        if let Some(auth_key_id) = target.auth_key_id {
            let state = state_arc.lock().await;
            if let Some(auth_key) = state.ssh_keys.get(&auth_key_id) {
                let label = auth_key.private_key_ref.label().to_owned();
                drop(state);
                if let Ok(bytes) = crate::secrets::retrieve_secret(&label).await {
                    if let Ok(pem) = String::from_utf8(bytes) {
                        return crate::ssh::connection::SshSession::connect_key_stream(
                            tunnel_stream, &target_addr, &target.username, &pem,
                        ).await;
                    }
                }
            }
        }
        Err(SshError::AuthFailed("no auth key available for target host".into()))
    } else {
        if let Some(ref pw_ref) = target.auth_password_ref {
            if let Ok(bytes) = crate::secrets::retrieve_secret(pw_ref.label()).await {
                if let Ok(pw) = String::from_utf8(bytes) {
                    return crate::ssh::connection::SshSession::connect_password_stream(
                        tunnel_stream, &target_addr, &target.username, &pw,
                    ).await;
                }
            }
        }
        Err(SshError::AuthFailed("no password configured for target host".into()))
    }
}

// ---------------------------------------------------------------------------
// Kill-switch helpers
// ---------------------------------------------------------------------------

/// How the kill switch should allow VPN traffic through.
#[derive(Clone)]
pub(crate) enum KillSwitchMode {
    /// Traffic goes through a named virtual NIC (WireGuard, OpenVPN tun).
    ///
    /// `allowed_ips` contains additional server/endpoint IPs whose traffic
    /// must be allowed through the *physical* NIC (e.g. WireGuard's encrypted
    /// UDP packets to peer endpoints, which are sent on the physical NIC, not
    /// through the tunnel interface).
    Interface {
        iface: String,
        allowed_ips: Vec<String>,
    },
    /// Kernel IPsec via xfrm — no separate virtual interface.
    ///
    /// Allows IKE packets to the VPN server, all IPsec-destined traffic
    /// (`rt ipsec exists`), and any extra IPs (e.g. DNS servers on the local
    /// network that are not routed through the tunnel).
    IPsec {
        /// The VPN server's public IP (for IKE allow rule).
        server_ip: String,
        /// Extra IPs that must be reachable directly (e.g. local DNS servers).
        allowed_ips: Vec<String>,
    },
}

/// Return the IP addresses of the DNS servers currently configured on the
/// system (via `resolvectl dns`).  Used to populate the FortiGate kill-switch
/// allow-list so that DNS continues to work when the profile has no
/// `dns_servers` configured and the system DNS is on the local network (not
/// routed through IPsec).
async fn current_system_dns_ips() -> Vec<String> {
    let out = match tokio::process::Command::new("resolvectl")
        .args(["dns", "--no-pager"])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            warn!("could not query resolvectl dns: {e}");
            return Vec::new();
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut ips: Vec<String> = Vec::new();
    for line in stdout.lines() {
        // Each line looks like: "Link 2 (enp14s0): 192.168.200.13"
        // or "Global: 9.9.9.9"
        if let Some(colon_pos) = line.rfind(':') {
            for token in line[colon_pos + 1..].split_whitespace() {
                // Validate it is a bare IP address (v4 or v6).
                if token.parse::<std::net::IpAddr>().is_ok() && !ips.contains(&token.to_owned()) {
                    ips.push(token.to_owned());
                }
            }
        }
    }
    ips
}

/// Parse `remote <host> <port>` directives from an OpenVPN config file and
/// resolve each host to an IP address string.  Used to populate the kill-switch
/// allow-list so that the OpenVPN client can reach the server even when the
/// kill switch is active (e.g. during reconnection after an unexpected drop).
async fn openvpn_server_ips(config_file: &str) -> Vec<String> {
    let content = match tokio::fs::read_to_string(config_file).await {
        Ok(c) => c,
        Err(e) => {
            warn!("kill-switch: could not read OpenVPN config '{}': {e}", config_file);
            return Vec::new();
        }
    };
    let mut ips = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("remote ") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let host = parts[1];
        let port = parts.get(2).copied().unwrap_or("1194");
        match tokio::net::lookup_host(format!("{host}:{port}")).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    let ip = addr.ip().to_string();
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
            Err(e) => warn!("kill-switch: could not resolve OpenVPN remote '{host}': {e}"),
        }
    }
    ips
}

/// Parse a user-supplied list of DNS servers.
///
/// Accepts comma-, semicolon-, or whitespace-separated IPv4/IPv6 addresses
/// (the GUI text field doesn't enforce a separator and a paste from
/// `resolvectl status` uses spaces). Invalid tokens are silently skipped
/// rather than rejected wholesale: a typo in one entry shouldn't make the
/// whole import fail. An empty input returns an empty Vec, which the
/// connect path treats as "fall back to mode-config DNS from the gateway".
fn parse_dns_server_list(raw: &str) -> Vec<std::net::IpAddr> {
    raw.split(|c: char| c == ',' || c == ';' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
        .collect()
}

/// Normalize the host string supplied for a FortiGate profile.
///
/// Users frequently paste hostnames with a stray scheme (`https://`), trailing
/// slash, or a `:port` / bare trailing `:` from a copy/paste boundary. The
/// IKE backend always uses ports 500/4500, so any port qualifier is wrong;
/// any leftover `:` would cause `tokio::net::lookup_host("host::500")` to
/// fail with "Name or service not known" on connect.
fn sanitize_fortigate_host(raw: &str) -> String {
    let mut s = raw.trim();

    for scheme in ["https://", "http://", "ipsec://"] {
        if let Some(rest) = s.strip_prefix(scheme) {
            s = rest;
        }
    }
    s = s.trim_end_matches('/');

    // Strip a trailing :port (decimal) but preserve a bracketed-IPv6 literal.
    // We don't accept arbitrary user-supplied ports — the IKE port is fixed.
    if !s.starts_with('[') {
        if let Some((host, tail)) = s.rsplit_once(':') {
            // Don't mistake an IPv6 colon for a port separator.
            let looks_like_port = !tail.is_empty()
                && tail.chars().all(|c| c.is_ascii_digit())
                && !host.contains(':');
            if looks_like_port || tail.is_empty() {
                s = host;
            }
        }
    }

    s.trim_end_matches(':').to_owned()
}

/// Install an nftables kill-switch that drops all non-VPN traffic.
///
/// All rules are applied atomically via a single `nft -f -` invocation so
/// there is no window where the DROP policy is active but the allow rules
/// are not yet installed.
async fn install_kill_switch(mode: &KillSwitchMode) {
    use tokio::io::AsyncWriteExt as _;

    // Best-effort removal of any stale table from a previous run.
    let _ = tokio::process::Command::new("nft")
        .args(["delete", "table", "inet", "supermgr_killswitch"])
        .status()
        .await;

    // Build the complete ruleset as a single nft script so the table, chain,
    // and all allow rules are created atomically.  This prevents the race
    // where the chain's DROP policy is active before the accept rules are in
    // place (which would temporarily block all traffic, including established
    // connections).
    let mut script = String::from(
        "table inet supermgr_killswitch {\n\
         \tchain output {\n\
         \t\ttype filter hook output priority -1;\n\
         \t\tpolicy drop;\n\
         \t\toif lo accept;\n",
    );

    match &mode {
        KillSwitchMode::Interface { iface, allowed_ips } => {
            if !iface.is_empty() {
                script.push_str(&format!("\t\toif \"{iface}\" accept;\n"));
            }
            for ip in allowed_ips {
                // Distinguish IPv4 vs IPv6 for the nft address-family keyword.
                if ip.contains(':') {
                    script.push_str(&format!("\t\tip6 daddr {ip} accept;\n"));
                } else {
                    script.push_str(&format!("\t\tip daddr {ip} accept;\n"));
                }
            }
        }
        KillSwitchMode::IPsec { server_ip, allowed_ips } => {
            // Allow IKE key-exchange packets to reach the VPN server.
            script.push_str(&format!("\t\tip daddr {server_ip} accept;\n"));
            // Allow all traffic that the kernel's xfrm/IPsec policy will
            // encrypt and send through the tunnel.
            script.push_str("\t\trt ipsec exists accept;\n");
            // Allow extra IPs (e.g. local DNS servers not routed via IPsec).
            for ip in allowed_ips {
                if ip.contains(':') {
                    script.push_str(&format!("\t\tip6 daddr {ip} accept;\n"));
                } else {
                    script.push_str(&format!("\t\tip daddr {ip} accept;\n"));
                }
            }
        }
    }

    script.push_str("\t}\n}\n");

    // Feed the script to nft as a single atomic transaction.
    let spawn_result = tokio::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn();

    let mut child = match spawn_result {
        Ok(c) => c,
        Err(e) => {
            warn!("kill-switch: nft -f - spawn failed: {e}");
            return;
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(script.as_bytes()).await {
            warn!("kill-switch: nft stdin write failed: {e}");
        }
    }

    match child.wait().await {
        Ok(s) if s.success() => match mode {
            KillSwitchMode::Interface { iface, allowed_ips } => {
                info!(
                    "kill-switch installed (iface={iface}, {} extra server IP(s))",
                    allowed_ips.len()
                );
            }
            KillSwitchMode::IPsec { server_ip, allowed_ips } => {
                info!(
                    "kill-switch installed (IPsec, server={server_ip}, {} extra DNS IP(s))",
                    allowed_ips.len()
                );
            }
        },
        Ok(s) => warn!("kill-switch: nft -f - exited {s}; kill-switch may not be active"),
        Err(e) => warn!("kill-switch: nft -f - wait error: {e}"),
    }
}

/// Remove the nftables kill-switch table (idempotent — ignores errors).
pub(crate) async fn remove_kill_switch() {
    match tokio::process::Command::new("nft")
        .args(["delete", "table", "inet", "supermgr_killswitch"])
        .status()
        .await
    {
        Ok(s) if s.success() => info!("kill-switch table removed"),
        Ok(_) => debug!("kill-switch table did not exist (no-op)"),
        Err(e) => warn!("remove kill-switch: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Shared connect helper
// ---------------------------------------------------------------------------

/// Drive a profile connect: sets state to Connecting, stores the active
/// backend, and emits `StateChanged` signals on every transition.
///
/// This is the shared implementation used by both the D-Bus `connect` method
/// and the auto-reconnect task.
///
/// # Precondition
///
/// The caller is responsible for verifying that the VPN is idle **before**
/// calling this function; if the state has changed in the meantime the function
/// re-checks under the lock and returns an appropriate error.
pub async fn connect_profile(
    profile: Profile,
    state: Arc<Mutex<DaemonState>>,
    ctx: SignalContext<'_>,
) -> fdo::Result<()> {
    let id = profile.id;

    // For Azure profiles, set up an mpsc channel so the backend can relay
    // auth-challenge events back to this task, which then emits the D-Bus signal.
    let (auth_tx_opt, auth_rx_opt) = if matches!(profile.config, ProfileConfig::AzureVpn(_)) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<(String, String)>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let backend = {
        let mut s = state.lock().await;

        // Re-check idleness under the lock to guard against races.
        if !s.vpn_state.is_idle() {
            return Err(fdo::Error::Failed(
                "another connection is already active or in progress".into(),
            ));
        }

        let backend = backend_for_profile(&profile, auth_tx_opt).map_err(core_error_to_fdo)?;

        s.vpn_state = VpnState::Connecting {
            profile_id: id,
            since: chrono::Utc::now(),
            phase: "initialising".into(),
        };
        s.active_backend = Some(Arc::clone(&backend));
        backend
    };

    // Spawn the auth-challenge relay task (Azure only).
    if let Some(mut rx) = auth_rx_opt {
        let ctx_relay = ctx.to_owned();
        tokio::spawn(async move {
            while let Some((user_code, url)) = rx.recv().await {
                info!("auth_challenge relay: user_code='{user_code}' url='{url}'");
                let _ = DaemonService::auth_challenge(&ctx_relay, user_code, url).await;
            }
        });
    }

    info!("=== [{}] connecting ===", profile.name);
    crate::audit::log_event("VPN_CONNECT", &profile.name);

    // Emit StateChanged(Connecting) before spawning so the client sees it promptly.
    let state_json = {
        let s = state.lock().await;
        state_to_json(&s.vpn_state).map_err(|e| fdo::Error::Failed(e.to_string()))?
    };
    DaemonService::state_changed(&ctx, state_json)
        .await
        .map_err(|e| fdo::Error::Failed(e.to_string()))?;

    // Run the actual connect in a background task.
    let state_arc = Arc::clone(&state);
    let ctx_owned = ctx.to_owned();
    tokio::spawn(async move {
        // Feature 4: retry transient errors up to 3 times.
        let result = 'retry: {
            for attempt in 0..3u32 {
                match backend.connect(&profile).await {
                    Ok(()) => break 'retry Ok(()),
                    Err(e) => {
                        let transient = !matches!(
                            e,
                            supermgr_core::error::BackendError::AlreadyConnected
                        );
                        if !transient || attempt == 2 {
                            break 'retry Err(e);
                        }
                        warn!(
                            "connect attempt {} failed: {e}, retrying...",
                            attempt + 1
                        );
                        let delay = std::time::Duration::from_secs(2u64.pow(attempt + 1));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
            unreachable!()
        };

        // Determine the display interface name and kill-switch mode *before*
        // re-acquiring the state lock, since this may involve DNS resolution
        // or an `openvpn3 sessions-list` call.
        let (display_iface, kill_mode) = if result.is_ok() {
            match &profile.config {
                ProfileConfig::WireGuard(wg_cfg) => {
                    let iface = profile.wg_interface_name().unwrap_or_default();
                    let mode = if profile.kill_switch {
                        let mut endpoint_ips: Vec<String> = Vec::new();
                        for peer in &wg_cfg.peers {
                            if let Some(ref ep) = peer.endpoint {
                                match tokio::net::lookup_host(ep.as_str()).await {
                                    Ok(mut addrs) => {
                                        if let Some(addr) = addrs.next() {
                                            endpoint_ips.push(addr.ip().to_string());
                                        }
                                    }
                                    Err(e) => {
                                        warn!("kill-switch: could not resolve WireGuard endpoint '{ep}': {e}");
                                    }
                                }
                            }
                        }
                        Some(KillSwitchMode::Interface {
                            iface: iface.clone(),
                            allowed_ips: endpoint_ips,
                        })
                    } else {
                        None
                    };
                    (iface, mode)
                }
                ProfileConfig::FortiGate(fg) => {
                    let server_ip = tokio::net::lookup_host(format!("{}:500", fg.host))
                        .await
                        .ok()
                        .and_then(|mut it| it.next())
                        .map(|sa| sa.ip().to_string())
                        .unwrap_or_else(|| fg.host.clone());
                    let mode = if profile.kill_switch {
                        let dns_ips = if fg.dns_servers.is_empty() {
                            current_system_dns_ips().await
                        } else {
                            current_system_dns_ips().await
                        };
                        Some(KillSwitchMode::IPsec { server_ip, allowed_ips: dns_ips })
                    } else {
                        None
                    };
                    (String::new(), mode)
                }
                _ => {
                    let iface = match backend.status().await {
                        Ok(BackendStatus::Active { interface, .. }) if !interface.is_empty() => {
                            interface
                        }
                        _ => String::new(),
                    };
                    let mode = if profile.kill_switch {
                        let server_ips = if let ProfileConfig::OpenVpn(cfg) = &profile.config {
                            openvpn_server_ips(&cfg.config_file).await
                        } else {
                            Vec::new()
                        };
                        if iface.is_empty() {
                            info!(
                                "kill-switch: '{}' — no tun device (DCO mode), \
                                 installing in server-IP-only mode",
                                profile.name
                            );
                        }
                        Some(KillSwitchMode::Interface {
                            iface: iface.clone(),
                            allowed_ips: server_ips,
                        })
                    } else {
                        None
                    };
                    (iface, mode)
                }
            }
        } else {
            (String::new(), None)
        };

        let mut s = state_arc.lock().await;

        // Only update state if we are still in the Connecting phase for this
        // profile.  A concurrent Disconnect() call may have already moved the
        // state to Disconnecting/Disconnected — don't overwrite that.
        let still_connecting = matches!(
            &s.vpn_state,
            VpnState::Connecting { profile_id: pid, .. } if *pid == id
        );
        if !still_connecting {
            return;
        }

        match result {
            Ok(()) => {
                s.vpn_state = VpnState::Connected {
                    profile_id: id,
                    since: chrono::Utc::now(),
                    interface: display_iface,
                };
                info!("=== [{}] connected ===", profile.name);
                // Persist last_connected_at.
                if let Some(p) = s.profiles.get_mut(&id) {
                    p.last_connected_at = Some(chrono::Utc::now());
                    let clone = p.clone();
                    if let Err(e) = s.save_profile(&clone) {
                        warn!("failed to persist last_connected_at for '{}': {e}", profile.name);
                    }
                }
                // Feature 3: install kill switch if enabled.
                if let Some(mode) = kill_mode {
                    drop(s); // release the lock before the subprocess
                    install_kill_switch(&mode).await;
                    s = state_arc.lock().await;
                    s.active_kill_switch_mode = Some(mode);
                }
            }
            Err(e) => {
                error!("=== [{}] failed: {} ===", profile.name, e);
                // Clean up any partial state left by the failed connect
                // (e.g. WG interface created, default route deleted, endpoint
                // host routes installed).  Without this the system can be left
                // without a default route if the connect failed after Phase 3
                // of add_routes.
                drop(s); // release lock — disconnect may need time
                if let Err(de) = backend.disconnect().await {
                    warn!("cleanup after failed connect: {de}");
                }
                s = state_arc.lock().await;
                s.vpn_state = VpnState::Error {
                    profile_id: Some(id),
                    code: supermgr_core::vpn::state::ErrorCode::Internal,
                    message: e.to_string(),
                };
                s.active_backend = None;
            }
        }

        if let Ok(json) = state_to_json(&s.vpn_state) {
            let _ = DaemonService::state_changed(&ctx_owned, json).await;
        }
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// Auto-reconnect task
// ---------------------------------------------------------------------------

/// Spawn a background task that watches NetworkManager for network-up events
/// and reconnects profiles with `auto_connect = true`.
///
/// Uses the D-Bus system bus to subscribe to `org.freedesktop.NetworkManager`
/// `StateChanged` signals.  When the state reaches >= 60
/// (`NM_STATE_CONNECTED_SITE` or `NM_STATE_CONNECTED_GLOBAL`), and the VPN is
/// currently `Disconnected`, this task connects the first `auto_connect` profile
/// it finds.
///
/// Non-fatal: if NetworkManager is unavailable the task simply exits.
pub fn spawn_autoconnect_task(state: Arc<Mutex<DaemonState>>, conn: zbus::Connection) {
    tokio::spawn(async move {
        if let Err(e) = run_autoconnect_loop(state, conn).await {
            warn!("auto-connect task exited: {e}");
        }
    });
}

async fn run_autoconnect_loop(
    state: Arc<Mutex<DaemonState>>,
    conn: zbus::Connection,
) -> anyhow::Result<()> {
    use futures_util::StreamExt as _;

    // Build a proxy for NetworkManager — bail if NM is not present.
    let nm_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    )
    .await?;

    let mut state_stream = nm_proxy.receive_signal("StateChanged").await?;
    info!("auto-connect: subscribed to NetworkManager StateChanged");

    // Track the previous NM state to detect transitions TO connected (not
    // repeated fires while already connected).
    let mut prev_nm_state: u32 = 0;

    while let Some(signal) = state_stream.next().await {
        // NM's StateChanged signal body has D-Bus signature `u` (single uint32).
        let new_nm_state: u32 = match signal.body().deserialize::<u32>() {
            Ok(s) => s,
            Err(_) => continue,
        };

        debug!("auto-connect: NM state {} -> {}", prev_nm_state, new_nm_state);

        // Only act on transitions that reach >= 60 (NM_STATE_CONNECTED_SITE /
        // NM_STATE_CONNECTED_GLOBAL).
        let was_connected = prev_nm_state >= 60;
        let now_connected = new_nm_state >= 60;
        prev_nm_state = new_nm_state;

        if now_connected && !was_connected {
            info!(
                "auto-connect: network up (NM state {new_nm_state}), \
                 checking auto-connect profiles"
            );
            try_autoconnect(&state, &conn).await;
        }
    }

    Ok(())
}

async fn try_autoconnect(state: &Arc<Mutex<DaemonState>>, conn: &zbus::Connection) {
    use zbus::zvariant::ObjectPath;

    // Grab a consistent snapshot under the lock.
    let (profile, vpn_idle) = {
        let s = state.lock().await;
        let is_idle = s.vpn_state.is_idle();
        let profile = s.profiles.values().find(|p| p.auto_connect).cloned();
        (profile, is_idle)
    };

    if !vpn_idle {
        debug!("auto-connect: VPN already active, skipping");
        return;
    }

    let Some(profile) = profile else {
        debug!("auto-connect: no auto_connect profile found");
        return;
    };

    info!(
        "auto-connect: triggering connect for profile '{}'",
        profile.name
    );

    let object_path = match ObjectPath::try_from(supermgr_core::dbus::DBUS_OBJECT_PATH) {
        Ok(p) => p,
        Err(e) => {
            error!("auto-connect: bad object path: {e}");
            return;
        }
    };
    let ctx = match SignalContext::new(conn, object_path) {
        Ok(c) => c,
        Err(e) => {
            error!("auto-connect: SignalContext: {e}");
            return;
        }
    };

    if let Err(e) = connect_profile(profile, Arc::clone(state), ctx).await {
        error!("auto-connect: connect_profile failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// Config-format validators
// ---------------------------------------------------------------------------

/// Validate that `text` looks like an OpenVPN client configuration.
///
/// Checks for the minimum set of directives required by openvpn3:
/// - `client` or `tls-client` (identifies this as a client-mode config)
/// - at least one `remote` line (server address)
/// - a `dev` line (`tun` or `tap`)
/// - a CA certificate (either a `<ca>` inline block or a `ca <file>` directive)
///
/// Returns `Ok(())` when all checks pass, or `Err(human-readable message)`.
///
/// This catches the most common mistakes — importing a WireGuard `.conf`,
/// an SSH key, a plain-text file, or an OpenVPN _server_ config — before
/// any file is written to disk.
fn validate_ovpn_config(text: &str) -> Result<(), String> {
    // Strip comment lines (starting with `#` or `;`) for all checks.
    let active_lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';') && !l.is_empty())
        .collect();

    let has_directive = |name: &str| -> bool {
        active_lines.iter().any(|l| {
            let lc = l.to_ascii_lowercase();
            lc == name || lc.starts_with(&format!("{name} ")) || lc.starts_with(&format!("{name}\t"))
        })
    };

    // Must be a client config, not a server config.
    if !has_directive("client") && !has_directive("tls-client") {
        if active_lines.iter().any(|l| *l == "[Interface]") {
            return Err(
                "this looks like a WireGuard config — use 'Import WireGuard' instead".into(),
            );
        }
        return Err(
            "not a valid OpenVPN client config: missing 'client' or 'tls-client' directive".into(),
        );
    }

    if !has_directive("remote") {
        return Err(
            "not a valid OpenVPN client config: missing 'remote' directive (no server address)"
                .into(),
        );
    }

    if !has_directive("dev") {
        return Err(
            "not a valid OpenVPN client config: missing 'dev' directive (tun or tap)".into(),
        );
    }

    // A CA certificate must be present either inline or as a file reference.
    let has_ca_directive = has_directive("ca");
    let has_ca_inline = text.contains("<ca>") && text.contains("</ca>");
    if !has_ca_directive && !has_ca_inline {
        return Err(
            "not a valid OpenVPN client config: missing CA certificate \
             ('ca <file>' directive or '<ca>...</ca>' inline block)"
                .into(),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Azure XML parser
// ---------------------------------------------------------------------------

/// Extract the first text content of the given XML `tag` from `xml`.
///
/// Returns `None` if the tag is absent or has no content.  This is a
/// minimal, dependency-free parser sufficient for the well-known Azure VPN
/// XML format — it does not handle CDATA, attributes, or namespaces.
fn xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open).map(|i| i + open.len())?;
    let end = xml[start..].find(&close).map(|i| i + start)?;
    let value = xml[start..end].trim();
    if value.is_empty() { None } else { Some(value) }
}

/// Extract all occurrences of `<tag>content</tag>` from `xml`.
fn xml_tags_all<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut results = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let after = &rest[s + open.len()..];
        if let Some(e) = after.find(&close) {
            let value = after[..e].trim();
            if !value.is_empty() {
                results.push(value);
            }
            rest = &after[e + close.len()..];
        } else {
            break;
        }
    }
    results
}

/// Wrap a raw base64 string (no headers) as a PEM certificate block,
/// folding at 64 characters per line.
fn base64_to_pem_cert(b64: &str) -> String {
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Parse `azurevpnconfig.xml` and `VpnSettings.xml` into an [`AzureVpnConfig`].
fn parse_azure_xml(
    azure_xml: &str,
    vpn_settings_xml: &str,
) -> Result<AzureVpnConfig, String> {
    use std::net::IpAddr;
    use std::str::FromStr;

    // -- Fields from azurevpnconfig.xml --
    let client_id = xml_tag(azure_xml, "audience")
        .ok_or("missing <audience> in azurevpnconfig.xml")?
        .to_owned();

    let tenant_url = xml_tag(azure_xml, "tenant")
        .or_else(|| xml_tag(azure_xml, "issuer"))
        .ok_or("missing <tenant>/<issuer> in azurevpnconfig.xml")?;
    let tenant_id = tenant_url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or("cannot extract tenant ID from tenant URL")?
        .to_owned();

    let gateway_fqdn = xml_tag(azure_xml, "fqdn")
        .or_else(|| xml_tag(vpn_settings_xml, "VpnServer"))
        .ok_or("missing <fqdn> / <VpnServer>")?
        .to_owned();

    let server_secret_hex = xml_tag(azure_xml, "serversecret")
        .ok_or("missing <serversecret> in azurevpnconfig.xml")?
        .to_owned();

    // DNS servers: prefer VpnSettings comma list, fall back to individual tags.
    let dns_servers: Vec<IpAddr> = {
        let mut servers = Vec::new();
        if let Some(csv) = xml_tag(vpn_settings_xml, "CustomDnsServers") {
            for part in csv.split(',') {
                if let Ok(ip) = part.trim().parse::<IpAddr>() {
                    servers.push(ip);
                }
            }
        }
        if servers.is_empty() {
            for tag in xml_tags_all(azure_xml, "dnsserver") {
                if let Ok(ip) = tag.parse::<IpAddr>() {
                    servers.push(ip);
                }
            }
        }
        servers
    };

    // -- CA certificate from VpnSettings.xml --
    let ca_cert_pem = xml_tags_all(vpn_settings_xml, "string")
        .into_iter()
        .find(|s| s.len() > 100) // all actual certs are long base64 blobs
        .map(base64_to_pem_cert)
        .unwrap_or_default();

    // -- Split-tunnel routes from VpnSettings.xml --
    let routes: Vec<ipnet::IpNet> = xml_tag(vpn_settings_xml, "Routes")
        .map(|csv| {
            csv.split(',')
                .filter_map(|r| ipnet::IpNet::from_str(r.trim()).ok())
                .collect()
        })
        .unwrap_or_default();

    if server_secret_hex.len() != 512 {
        return Err(format!(
            "<serversecret> must be 512 hex chars (got {})",
            server_secret_hex.len()
        ));
    }
    if !server_secret_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("<serversecret> contains non-hex characters".into());
    }

    Ok(AzureVpnConfig {
        gateway_fqdn,
        tenant_id,
        client_id,
        server_secret_hex,
        ca_cert_pem,
        routes,
        dns_servers,
    })
}

// ---------------------------------------------------------------------------
// Status polling task
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Webhook notification helper
// ---------------------------------------------------------------------------

/// Fire-and-forget POST to a webhook URL.
///
/// The payload includes both `text` (Slack/Teams) and `content` (Discord) keys
/// so it works with all three platforms out of the box.
async fn send_webhook(url: &str, message: &str) {
    if url.is_empty() {
        return;
    }
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "text": message,
        "content": message,
    });
    match client.post(url).json(&body).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                warn!("webhook returned HTTP {}", resp.status());
            }
        }
        Err(e) => warn!("webhook POST failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// SSH host health-check background task
// ---------------------------------------------------------------------------

/// Health-check polling interval.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// TCP connect timeout per host.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// Spawn a background task that periodically probes each SSH host's
/// `hostname:port` via TCP connect and emits `host_health_changed` signals
/// when reachability changes.
pub fn spawn_health_check_task(state: Arc<Mutex<DaemonState>>, conn: zbus::Connection) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEALTH_CHECK_INTERVAL);
        loop {
            ticker.tick().await;

            // Snapshot the hosts we need to probe.
            let hosts: Vec<(Uuid, String, u16)> = {
                let s = state.lock().await;
                s.hosts
                    .values()
                    .map(|h| (h.id, h.hostname.clone(), h.port))
                    .collect()
            };

            if hosts.is_empty() {
                continue;
            }

            // Probe all hosts concurrently.
            let mut results: Vec<(Uuid, bool)> = Vec::with_capacity(hosts.len());
            let mut join_set = tokio::task::JoinSet::new();
            for (id, hostname, port) in hosts {
                join_set.spawn(async move {
                    let addr = format!("{hostname}:{port}");
                    let reachable = tokio::time::timeout(
                        HEALTH_CHECK_TIMEOUT,
                        tokio::net::TcpStream::connect(&addr),
                    )
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);
                    (id, reachable)
                });
            }
            while let Some(Ok((id, reachable))) = join_set.join_next().await {
                results.push((id, reachable));
            }

            // Compare with previous state, update, and emit signals.
            let mut state_guard = state.lock().await;

            // Snapshot webhook config once per cycle.
            let wh_url = state_guard.webhook_url.clone();
            let wh_on_host_down = state_guard.webhook_on_host_down;

            for (id, reachable) in &results {
                let prev_reachable = state_guard.host_health.get(id).copied();
                let changed = prev_reachable.map_or(true, |prev| prev != *reachable);
                state_guard.host_health.insert(*id, *reachable);
                if changed {
                    let object_path = zbus::zvariant::ObjectPath::try_from(
                        supermgr_core::dbus::DBUS_OBJECT_PATH,
                    )
                    .expect("static object path is valid");
                    if let Ok(ctx) = SignalContext::new(&conn, object_path) {
                        let _ = DaemonService::host_health_changed(
                            &ctx,
                            id.to_string(),
                            *reachable,
                        )
                        .await;
                    }

                    // Webhook: host went DOWN (was reachable or first-time unreachable).
                    if !reachable && wh_on_host_down && !wh_url.is_empty() {
                        let host_label = state_guard
                            .hosts
                            .get(id)
                            .map(|h| format!("{} ({}:{})", h.label, h.hostname, h.port))
                            .unwrap_or_else(|| id.to_string());
                        let msg = format!(
                            "\u{26a0}\u{fe0f} SuperManager: SSH host **{host_label}** is unreachable"
                        );
                        let url = wh_url.clone();
                        tokio::spawn(async move { send_webhook(&url, &msg).await });
                    }
                }
            }
            drop(state_guard);
        }
    });
}

/// Spawns a task that polls the active backend every `interval` and:
/// - Emits `StatsUpdated` signals if the tunnel is active.
/// - Triggers a state transition if the tunnel has disappeared unexpectedly.
pub fn spawn_monitor_task(
    state: Arc<Mutex<DaemonState>>,
    conn: zbus::Connection,
    mut shutdown_rx: watch::Receiver<bool>,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                Ok(()) = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("monitor task shutting down");
                        break;
                    }
                }
            }

            let (backend, current_state) = {
                let state = state.lock().await;
                (state.active_backend.clone(), state.vpn_state.clone())
            };

            let Some(backend) = backend else { continue };

            match backend.status().await {
                Ok(backend_status) => {
                    // Reconcile and emit stats if connected.
                    if let supermgr_core::vpn::backend::BackendStatus::Active {
                        stats,
                        virtual_ip,
                        active_routes,
                        ..
                    } = &backend_status
                    {
                        let uptime_secs = match &current_state {
                            VpnState::Connected { since, .. } => {
                                (chrono::Utc::now() - *since).num_seconds().max(0) as u64
                            }
                            _ => 0,
                        };
                        let mut extended = stats.clone();
                        extended.virtual_ip = virtual_ip.clone();
                        extended.active_routes = active_routes.clone();
                        extended.uptime_secs = uptime_secs;
                        if let Ok(json) = stats_to_json(&extended) {
                            let object_path = zbus::zvariant::ObjectPath::try_from(
                                supermgr_core::dbus::DBUS_OBJECT_PATH,
                            )
                            .expect("static object path is valid");
                            if let Ok(ctx) = SignalContext::new(&conn, object_path) {
                                let _ = DaemonService::stats_updated(&ctx, json).await;
                            }
                        }
                    }

                    // Check for unexpected disconnects.
                    if let Some(_) =
                        supermgr_core::vpn::backend::reconcile_status(&current_state, &backend_status)
                    {
                        // The VPN dropped unexpectedly.  Run backend.disconnect()
                        // to restore the original default route, revert DNS, and
                        // remove endpoint host routes.  This is safe even if the
                        // WG interface is already gone — disconnect() handles
                        // "not found" gracefully.  Without this cleanup the system
                        // is left without a default route (= no internet).
                        info!("VPN dropped unexpectedly — running backend cleanup");
                        if let Err(e) = backend.disconnect().await {
                            warn!("cleanup after unexpected VPN drop: {e}");
                        }

                        // Webhook: VPN disconnected unexpectedly.
                        {
                            let s = state.lock().await;
                            if s.webhook_on_vpn_disconnect && !s.webhook_url.is_empty() {
                                let profile_name = if let VpnState::Connected {
                                    profile_id, ..
                                } = &current_state
                                {
                                    s.profiles
                                        .get(profile_id)
                                        .map(|p| p.name.clone())
                                        .unwrap_or_else(|| profile_id.to_string())
                                } else {
                                    "unknown".to_string()
                                };
                                let msg = format!(
                                    "\u{26a0}\u{fe0f} SuperManager: VPN profile **{profile_name}** disconnected unexpectedly"
                                );
                                let url = s.webhook_url.clone();
                                tokio::spawn(
                                    async move { send_webhook(&url, &msg).await },
                                );
                            }
                        }

                        let profile_kill_switch = {
                            let s = state.lock().await;
                            if let VpnState::Connected { profile_id, .. } = &current_state {
                                s.profiles
                                    .get(profile_id)
                                    .map_or(false, |p| p.kill_switch)
                            } else {
                                false
                            }
                        };

                        if profile_kill_switch {
                            let _stored_mode = {
                                let s = state.lock().await;
                                s.active_kill_switch_mode.clone()
                            };
                            warn!(
                                "VPN dropped unexpectedly — kill switch is active, \
                                 all traffic is blocked until reconnect or disconnect"
                            );
                        } else {
                            remove_kill_switch().await;
                        }

                        let error_state = if profile_kill_switch {
                            VpnState::Error {
                                profile_id: current_state.profile_id(),
                                code: supermgr_core::vpn::state::ErrorCode::Internal,
                                message: "VPN dropped — kill switch is blocking all traffic. \
                                          Reconnect to restore VPN, or Disconnect to lift the block."
                                    .into(),
                            }
                        } else {
                            VpnState::Disconnected
                        };

                        let object_path = zbus::zvariant::ObjectPath::try_from(
                            supermgr_core::dbus::DBUS_OBJECT_PATH,
                        )
                        .expect("static path");
                        if let Ok(ctx) = SignalContext::new(&conn, object_path) {
                            if let Ok(json) = state_to_json(&error_state) {
                                let _ = DaemonService::state_changed(&ctx, json).await;
                            }
                        }
                        // Auto-reconnect: if the profile has auto_connect and
                        // the kill switch is NOT active, attempt to reconnect
                        // after a short delay.
                        let auto_reconnect_profile = if !profile_kill_switch {
                            let s = state.lock().await;
                            if let VpnState::Connected { profile_id, .. } = &current_state {
                                s.profiles.get(profile_id)
                                    .filter(|p| p.auto_connect)
                                    .cloned()
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        {
                            let mut s = state.lock().await;
                            s.vpn_state = error_state;
                            s.active_backend = None;
                        }

                        // Attempt auto-reconnect with backoff.
                        if let Some(profile) = auto_reconnect_profile {
                            info!("auto-reconnect: will retry '{}' in 5 s", profile.name);
                            let state_c = Arc::clone(&state);
                            let conn_c = conn.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                // Only reconnect if still idle.
                                let idle = {
                                    let s = state_c.lock().await;
                                    s.vpn_state.is_idle()
                                };
                                if !idle {
                                    info!("auto-reconnect: skipped, tunnel already active");
                                    return;
                                }
                                let object_path = zbus::zvariant::ObjectPath::try_from(
                                    supermgr_core::dbus::DBUS_OBJECT_PATH,
                                ).expect("static path");
                                if let Ok(ctx) = SignalContext::new(&conn_c, object_path) {
                                    info!("auto-reconnect: connecting '{}'", profile.name);
                                    if let Err(e) = connect_profile(
                                        profile.clone(), Arc::clone(&state_c), ctx,
                                    ).await {
                                        warn!("auto-reconnect failed: {e}");
                                    }
                                }
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!("status poll error: {}", e);
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Scheduled config backup task
// ---------------------------------------------------------------------------

/// Default backup interval: 24 hours.
const BACKUP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Spawn a background task that periodically backs up all FortiGate hosts
/// with API tokens configured.
///
/// Runs every `BACKUP_INTERVAL` (24 h by default).  Failures for individual
/// hosts are logged but do not stop the loop.
pub fn spawn_backup_scheduler(state: Arc<Mutex<DaemonState>>, conn: zbus::Connection) {
    tokio::spawn(async move {
        // Wait a bit after daemon start before the first backup run.
        tokio::time::sleep(Duration::from_secs(120)).await;
        let mut ticker = tokio::time::interval(BACKUP_INTERVAL);
        loop {
            ticker.tick().await;

            // Collect FortiGate hosts with API tokens.
            let fg_hosts: Vec<(Uuid, String)> = {
                let s = state.lock().await;
                s.hosts
                    .values()
                    .filter(|h| {
                        h.device_type == supermgr_core::ssh::DeviceType::Fortigate
                            && h.api_token_ref.is_some()
                    })
                    .map(|h| (h.id, h.label.clone()))
                    .collect()
            };

            if fg_hosts.is_empty() {
                debug!("backup scheduler: no FortiGate hosts with API, skipping");
                continue;
            }

            info!(
                "backup scheduler: starting scheduled backup for {} host(s)",
                fg_hosts.len()
            );

            for (id, label) in &fg_hosts {
                let host_id = id.to_string();
                // Use the D-Bus proxy to call our own backup method — this
                // reuses the same auth/HTTP logic and avoids code duplication.
                match async {
                    let proxy = supermgr_core::dbus::DaemonProxy::new(&conn).await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let filename = proxy.fortigate_backup_config(&host_id).await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    Ok::<String, anyhow::Error>(filename)
                }
                .await
                {
                    Ok(filename) => {
                        info!("backup scheduler: backed up '{label}' -> {filename}");
                    }
                    Err(e) => {
                        warn!("backup scheduler: failed to back up '{label}': {e}");
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_server_list_handles_common_separators() {
        assert_eq!(
            parse_dns_server_list("1.1.1.1, 8.8.8.8"),
            vec![
                "1.1.1.1".parse::<std::net::IpAddr>().unwrap(),
                "8.8.8.8".parse().unwrap()
            ]
        );
        // Whitespace-only — matches what `resolvectl status` prints.
        assert_eq!(
            parse_dns_server_list("1.1.1.1 8.8.8.8"),
            vec![
                "1.1.1.1".parse::<std::net::IpAddr>().unwrap(),
                "8.8.8.8".parse().unwrap()
            ]
        );
        // Semicolon — friendly for paste from /etc/resolv.conf-style notes.
        assert_eq!(
            parse_dns_server_list("1.1.1.1;8.8.8.8"),
            vec![
                "1.1.1.1".parse::<std::net::IpAddr>().unwrap(),
                "8.8.8.8".parse().unwrap()
            ]
        );
    }

    #[test]
    fn parse_dns_server_list_skips_garbage_tokens_without_failing() {
        // A single typo shouldn't sink the whole import.
        assert_eq!(
            parse_dns_server_list("1.1.1.1, not-an-ip, 8.8.8.8"),
            vec![
                "1.1.1.1".parse::<std::net::IpAddr>().unwrap(),
                "8.8.8.8".parse().unwrap()
            ]
        );
    }

    #[test]
    fn parse_dns_server_list_accepts_ipv6() {
        assert_eq!(
            parse_dns_server_list("2606:4700:4700::1111, 2001:4860:4860::8888"),
            vec![
                "2606:4700:4700::1111".parse::<std::net::IpAddr>().unwrap(),
                "2001:4860:4860::8888".parse().unwrap()
            ]
        );
    }

    #[test]
    fn parse_dns_server_list_empty_input_returns_empty_vec() {
        assert!(parse_dns_server_list("").is_empty());
        assert!(parse_dns_server_list("   ").is_empty());
        assert!(parse_dns_server_list(",,,").is_empty());
    }
}
