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
use supermgr_core::ssh::host::{AuthMethod, SshHost, SshHostSummary};

use crate::secrets;

// `backend_for_profile` lives in supermgrd's own vpn module.
use crate::vpn::backend_for_profile;


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
    pub ssh_hosts: std::collections::HashMap<Uuid, SshHost>,

    /// SSH host health (reachability) map: host UUID → reachable.
    pub host_health: std::collections::HashMap<Uuid, bool>,

    /// Directory where SSH key TOML files are stored.
    pub ssh_key_dir: PathBuf,

    /// Directory where SSH host TOML files are stored.
    pub ssh_host_dir: PathBuf,
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
            ssh_hosts: std::collections::HashMap::new(),
            host_health: std::collections::HashMap::new(),
            ssh_key_dir: base.join("ssh/keys"),
            ssh_host_dir: base.join("ssh/hosts"),
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

    /// Load all `.toml` SSH host files from `ssh_host_dir`.
    pub fn load_ssh_hosts(&mut self) -> anyhow::Result<()> {
        if !self.ssh_host_dir.exists() {
            std::fs::create_dir_all(&self.ssh_host_dir)?;
            return Ok(());
        }
        for entry in std::fs::read_dir(&self.ssh_host_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            match toml::from_str::<SshHost>(&text) {
                Ok(host) => {
                    info!("loaded SSH host '{}' from {:?}", host.label, path);
                    self.ssh_hosts.insert(host.id, host);
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

    /// Persist a single SSH host to disk as `{ssh_host_dir}/{id}.toml`.
    pub fn save_ssh_host(&self, host: &SshHost) -> anyhow::Result<()> {
        let path = self.ssh_host_dir.join(format!("{}.toml", host.id));
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
    pub fn delete_ssh_host_file(&self, id: Uuid) -> anyhow::Result<()> {
        let path = self.ssh_host_dir.join(format!("{id}.toml"));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// D-Bus service object
// ---------------------------------------------------------------------------

/// The D-Bus service object.  Registered at `/org/supermgr/Daemon`.
pub struct DaemonService {
    /// Shared mutable state.
    pub state: Arc<tokio::sync::Mutex<DaemonState>>,
    /// Channel the monitoring task uses to receive a termination signal.
    pub shutdown_tx: watch::Sender<bool>,
    /// Ring buffer of recent log lines (filled by the `RingLayer` tracing layer).
    pub log_buffer: Arc<std::sync::Mutex<VecDeque<String>>>,
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
    ) -> fdo::Result<String> {
        let profile_id = Uuid::new_v4();

        info!(
            "import_fortigate: creating profile '{}' for host '{}', user '{}'",
            name, host, username
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
            dns_servers: Vec::new(),
            routes: Vec::new(),
        };

        let profile = Profile {
            id: profile_id,
            name: name.clone(),
            auto_connect: false,
            full_tunnel: true,
            last_connected_at: None,
            kill_switch: false,
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
            let mut host: SshHost = toml::from_str(toml_text)
                .map_err(|e| fdo::Error::InvalidArgs(format!("invalid SSH host TOML: {e}")))?;

            let new_id = Uuid::new_v4();
            host.id = new_id;
            let now = chrono::Utc::now();
            host.created_at = now;
            host.updated_at = now;

            let label = host.label.clone();
            let mut state = self.state.lock().await;
            std::fs::create_dir_all(&state.ssh_host_dir)
                .map_err(|e| fdo::Error::Failed(format!("create ssh host dir: {e}")))?;
            state.save_ssh_host(&host)
                .map_err(|e| fdo::Error::Failed(format!("save SSH host: {e}")))?;
            state.ssh_hosts.insert(host.id, host);

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

    /// Update a FortiGate profile's connection details and credentials.
    async fn update_fortigate(
        &self,
        profile_id: &str,
        name: &str,
        host: &str,
        username: &str,
        password: &str,
        psk: &str,
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

        let mut state = self.state.lock().await;
        let profile = state
            .profiles
            .get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject(format!("profile {id} not found")))?;

        let fg = match &mut profile.config {
            ProfileConfig::FortiGate(fg) => fg,
            _ => return Err(fdo::Error::InvalidArgs("profile is not a FortiGate profile".into())),
        };

        fg.host = host.trim().to_owned();
        fg.username = username.trim().to_owned();

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
    async fn ssh_add_host(&self, host_json: &str) -> fdo::Result<String> {
        let mut host: SshHost = serde_json::from_str(host_json)
            .map_err(|e| fdo::Error::InvalidArgs(format!("invalid host JSON: {e}")))?;
        host.id = Uuid::new_v4();
        let now = chrono::Utc::now();
        host.created_at = now;
        host.updated_at = now;

        let id_str = host.id.to_string();
        let mut state = self.state.lock().await;
        tokio::fs::create_dir_all(&state.ssh_host_dir).await
            .map_err(|e| fdo::Error::Failed(format!("create dir: {e}")))?;
        state.save_ssh_host(&host).map_err(|e| fdo::Error::Failed(format!("save: {e}")))?;
        state.ssh_hosts.insert(host.id, host);

        Ok(id_str)
    }

    /// Update an existing SSH host.
    ///
    /// Merges the provided JSON fields into the existing host, preserving
    /// fields not present in the update (e.g. `api_token_ref`, `auth_password_ref`).
    async fn ssh_update_host(&self, host_id: &str, host_json: &str) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let updates: serde_json::Value = serde_json::from_str(host_json)
            .map_err(|e| fdo::Error::InvalidArgs(format!("invalid host JSON: {e}")))?;

        let mut state = self.state.lock().await;
        let host = state.ssh_hosts.get_mut(&id)
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
            if let Ok(am) = serde_json::from_value(serde_json::Value::String(v.to_owned())) {
                host.auth_method = am;
            }
        }
        if let Some(v) = updates.get("auth_key_id") {
            host.auth_key_id = v.as_str().and_then(|s| Uuid::parse_str(s).ok());
        }
        if let Some(v) = updates.get("vpn_profile_id") {
            host.vpn_profile_id = v.as_str().and_then(|s| Uuid::parse_str(s).ok());
        }
        if let Some(v) = updates.get("api_port").and_then(|v| v.as_u64()) {
            host.api_port = Some(v as u16);
        }
        if let Some(v) = updates.get("pinned").and_then(|v| v.as_bool()) {
            host.pinned = v;
        }
        host.updated_at = chrono::Utc::now();

        let host = host.clone();
        state.save_ssh_host(&host).map_err(|e| fdo::Error::Failed(format!("save: {e}")))?;
        Ok(())
    }

    /// Toggle the pinned/favourite state of an SSH host.
    ///
    /// Flips the `pinned` boolean and persists the change.  Returns the
    /// refreshed host list (JSON array of summaries) so the GUI can update.
    async fn ssh_toggle_pin(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let mut state = self.state.lock().await;
        let host = state.ssh_hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.pinned = !host.pinned;
        host.updated_at = chrono::Utc::now();
        let host = host.clone();
        state.save_ssh_host(&host).map_err(|e| fdo::Error::Failed(format!("save: {e}")))?;
        let summaries: Vec<SshHostSummary> = state.ssh_hosts.values().map(SshHostSummary::from).collect();
        serde_json::to_string(&summaries).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    /// Delete an SSH host by UUID.
    async fn ssh_delete_host(&self, host_id: &str) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let mut state = self.state.lock().await;
        state.ssh_hosts.remove(&id);
        let _ = state.delete_ssh_host_file(id);
        Ok(())
    }

    /// List all SSH hosts as a JSON array of summaries.
    async fn ssh_list_hosts(&self) -> fdo::Result<String> {
        let state = self.state.lock().await;
        let summaries: Vec<SshHostSummary> = state.ssh_hosts.values().map(SshHostSummary::from).collect();
        serde_json::to_string(&summaries).map_err(|e| fdo::Error::Failed(e.to_string()))
    }

    /// Return a single SSH host as JSON.
    async fn ssh_get_host(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id).map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;
        let state = self.state.lock().await;
        let host = state.ssh_hosts.get(&id).ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
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
                let host = state.ssh_hosts.get(&hid)
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
                let host = state.ssh_hosts.get(&hid)
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
    async fn ssh_set_password(&self, host_id: &str, password: &str) -> fdo::Result<()> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let label = format!("supermgr/ssh/{}/password", id.simple());
        secrets::store_secret(&label, password.as_bytes())
            .await
            .map_err(|e| fdo::Error::Failed(format!("store password: {e}")))?;

        let mut state = self.state.lock().await;
        let host = state.ssh_hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.auth_password_ref = Some(SecretRef::new(&label));
        host.updated_at = chrono::Utc::now();
        let host = host.clone();
        state.save_ssh_host(&host)
            .map_err(|e| fdo::Error::Failed(format!("save host: {e}")))?;

        info!("stored SSH password for host {id}");
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
        let host = state.ssh_hosts.get_mut(&id)
            .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?;
        host.api_token_ref = Some(SecretRef::new(&label));
        host.api_port = Some(port);
        host.updated_at = chrono::Utc::now();
        state.save_ssh_host(&state.ssh_hosts[&id].clone())
            .map_err(|e| fdo::Error::Failed(format!("save host: {e}")))?;

        info!("stored FortiGate API token for host {id} (port {})", port);
        Ok(())
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

        let (hostname, api_port, api_verify_tls, token_label) = {
            let state = self.state.lock().await;
            let host = state.ssh_hosts.get(&id)
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
                fdo::Error::Failed(format!("API request failed: {msg}"))
            })?;

        let status = resp.status().as_u16();
        let resp_body = resp.text().await
            .map_err(|e| fdo::Error::Failed(format!("read response: {e}")))?;

        if status >= 400 {
            return Err(fdo::Error::Failed(format!(
                "FortiGate API {status}: {resp_body}"
            )));
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
            state.ssh_hosts.get(&id)
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
            if let Some(host) = state.ssh_hosts.get(&id) {
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
        let (port, username, hostname, auth_method, secret_label, password_label) = {
            let state = self.state.lock().await;
            let host = state.ssh_hosts.get(&id)
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

            (host.port, host.username.clone(), host.hostname.clone(), host.auth_method, key_label, pw_label)
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
            format!(
                "{pw_cmd}ssh -p {port} -o PreferredAuthentications=password \
                 -o PubkeyAuthentication=no {username}@{hostname}"
            )
        } else {
            format!("ssh -p {port} {username}@{hostname}")
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
                        cmd = format!(
                            "cp {src} {dst} && chmod 600 {dst} && ssh -p {port} -i {dst} -o IdentitiesOnly=yes {username}@{hostname}; rm -f {dst}",
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
        let ssh_hosts: Vec<&SshHost> = state.ssh_hosts.values().collect();

        // Include all secrets so the backup is self-contained.
        let all_secrets: std::collections::HashMap<String, String> =
            match secrets::read_all_secrets().await {
                Ok(m) => m,
                Err(e) => {
                    warn!("export_all: could not read secrets: {e}");
                    std::collections::HashMap::new()
                }
            };

        let backup = serde_json::json!({
            "version": 2,
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "profiles": profiles,
            "ssh_keys": ssh_keys,
            "ssh_hosts": ssh_hosts,
            "secrets": all_secrets,
        });

        serde_json::to_string_pretty(&backup)
            .map_err(|e| fdo::Error::Failed(format!("JSON serialisation failed: {e}")))
    }

    /// Import configuration from a JSON backup string previously produced by
    /// [`Self::export_all`].
    ///
    /// Each imported item receives a new UUID so it never collides with
    /// existing data.  Returns a JSON summary:
    /// `{"profiles": N, "ssh_keys": N, "ssh_hosts": N}`.
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
        if let Some(arr) = backup.get("ssh_hosts").and_then(|v| v.as_array()) {
            for item in arr {
                match serde_json::from_value::<SshHost>(item.clone()) {
                    Ok(mut host) => {
                        let new_id = Uuid::new_v4();
                        host.id = new_id;
                        let path = state.ssh_host_dir.join(format!("{new_id}.toml"));
                        match toml::to_string_pretty(&host) {
                            Ok(text) => {
                                if let Err(e) = std::fs::create_dir_all(&state.ssh_host_dir) {
                                    warn!("import_all: mkdir ssh_host_dir: {e}");
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
                        state.ssh_hosts.insert(new_id, host);
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

        let summary = serde_json::json!({
            "profiles": imported_profiles,
            "ssh_keys": imported_keys,
            "ssh_hosts": imported_hosts,
            "secrets": imported_secrets,
        });

        info!(
            "import_all: imported {imported_profiles} profile(s), \
             {imported_keys} SSH key(s), {imported_hosts} SSH host(s), \
             {imported_secrets} secret(s)"
        );

        Ok(summary.to_string())
    }

    // =======================================================================
    // SSH test connection
    // =======================================================================

    /// Test SSH and (optionally) FortiGate API connectivity for a host.
    ///
    /// Returns a JSON object like `{"ssh": "ok", "api": "ok"}` or
    /// `{"ssh": "timeout", "api": "auth_failed"}`.  The `api` field is only
    /// present when the host has a FortiGate API token configured.
    async fn ssh_test_connection(&self, host_id: &str) -> fdo::Result<String> {
        let id = Uuid::parse_str(host_id)
            .map_err(|_| fdo::Error::InvalidArgs("invalid UUID".into()))?;

        let host = {
            let state = self.state.lock().await;
            state.ssh_hosts.get(&id)
                .ok_or_else(|| fdo::Error::UnknownObject("host not found".into()))?
                .clone()
        };

        info!("ssh_test_connection: testing {}@{}:{}", host.username, host.hostname, host.port);

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

        info!("ssh_test_connection result for {id}: {result}");
        Ok(result.to_string())
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
async fn connect_to_ssh_host(
    host: &SshHost,
    push_key_pem: &Option<String>,
    state_arc: &Arc<Mutex<DaemonState>>,
) -> Result<crate::ssh::connection::SshSession, supermgr_core::error::SshError> {
    if host.auth_method == AuthMethod::Key {
        if let Some(ref pem) = push_key_pem {
            return crate::ssh::connection::SshSession::connect_key(
                &host.hostname, host.port, &host.username, pem, 30,
            ).await;
        }
        // Try to use the host's own auth key
        if let Some(auth_key_id) = host.auth_key_id {
            let state = state_arc.lock().await;
            if let Some(auth_key) = state.ssh_keys.get(&auth_key_id) {
                let label = auth_key.private_key_ref.label().to_owned();
                drop(state);
                if let Ok(bytes) = crate::secrets::retrieve_secret(&label).await {
                    if let Ok(pem) = String::from_utf8(bytes) {
                        return crate::ssh::connection::SshSession::connect_key(
                            &host.hostname, host.port, &host.username, &pem, 30,
                        ).await;
                    }
                }
            }
        }
        Err(supermgr_core::error::SshError::AuthFailed("no auth key available".into()))
    } else {
        // Password auth
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

// ---------------------------------------------------------------------------
// Kill-switch helpers
// ---------------------------------------------------------------------------

/// How the kill switch should allow VPN traffic through.
#[derive(Clone)]
enum KillSwitchMode {
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
            let mut last_err = None;
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
                        last_err = Some(e);
                        let delay = std::time::Duration::from_secs(2u64.pow(attempt + 1));
                        tokio::time::sleep(delay).await;
                        let _ = last_err; // avoid unused warning
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
                s.ssh_hosts
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
            for (id, reachable) in &results {
                let changed = state_guard
                    .host_health
                    .get(id)
                    .map_or(true, |prev| prev != reachable);
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
                        let mut state = state.lock().await;
                        state.vpn_state = error_state;
                        state.active_backend = None;
                    }
                }
                Err(e) => {
                    warn!("status poll error: {}", e);
                }
            }
        }
    });
}
