//! Daemon state management — profiles, SSH keys, SSH hosts.
//!
//! This module contains the mutable state and TOML persistence logic
//! extracted from the Linux daemon, without any D-Bus dependencies.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tracing::{info, warn};
use uuid::Uuid;

use supermgr_core::host::Host;
use supermgr_core::ssh::key::SshKey;
use supermgr_core::vpn::profile::{Profile, ProfileConfig};
use supermgr_core::vpn::state::VpnState;

use crate::ssh::known_hosts::KnownHostsStore;

/// All mutable state owned by the daemon.
pub struct DaemonState {
    /// All known VPN profiles, keyed by UUID.
    pub profiles: HashMap<Uuid, Profile>,

    /// Current VPN state.
    pub vpn_state: VpnState,

    /// Directory where VPN profile TOML files are persisted.
    pub profile_dir: PathBuf,

    /// Where imported OpenVPN configurations live, as `<profile id>.ovpn`.
    pub ovpn_dir: PathBuf,

    /// SSH keys, keyed by UUID.
    pub ssh_keys: HashMap<Uuid, SshKey>,

    /// SSH hosts, keyed by UUID.
    pub ssh_hosts: HashMap<Uuid, Host>,

    /// SSH host health (reachability) map: host UUID → reachable.
    pub host_health: HashMap<Uuid, bool>,

    /// Directory where SSH key TOML files are stored.
    pub ssh_key_dir: PathBuf,

    /// Directory where SSH host TOML files are stored.
    pub ssh_host_dir: PathBuf,

    /// First-class `UniFi` controller registry. Keyed by UUID
    /// and persisted as TOML in `unifi_controller_dir`. NOT
    /// tied to an SSH host — see `unifi_controllers.rs` for
    /// the architectural reasoning.
    pub unifi_controllers: HashMap<Uuid, crate::unifi_controllers::UnifiController>,
    pub unifi_controller_dir: PathBuf,

    /// Operator-set device-type overrides (per MAC). Used by
    /// `active_scan` to override the OUI-based vendor sniffer
    /// when the human knows better than our heuristics.
    pub device_type_overrides: crate::device_type_overrides::DeviceTypeOverrides,

    /// Webhook URL for outgoing notifications.
    pub webhook_url: String,
    /// Fire a webhook when an SSH host goes down.
    pub webhook_on_host_down: bool,
    /// Fire a webhook when a VPN tunnel disconnects unexpectedly.
    pub webhook_on_vpn_disconnect: bool,

    /// Persistent record of accepted SSH host keys. The SSH client handler
    /// consults this on every connection: TOFU on first sight, reject on
    /// fingerprint mismatch, accept on match. Wrapped in `Arc` so the
    /// (sync) handler can hold a reference cheaply across the russh task.
    pub known_hosts: Arc<KnownHostsStore>,
}

impl DaemonState {
    /// Create daemon state with the given base data directory.
    ///
    /// On Linux: `/etc/supermgrd/` (root) or `$XDG_DATA_HOME/supermgrd/`.
    /// On macOS: `~/Library/Application Support/SuperManager/`.
    pub fn new(
        data_dir: PathBuf,
    ) -> Result<Self, supermgr_core::ssh::known_hosts::KnownHostsError> {
        // Losing trust state must stop startup, not silently re-enroll every
        // host against an empty or shared temporary store.
        let known_hosts = Arc::new(KnownHostsStore::open(&data_dir)?);
        Ok(Self {
            profiles: HashMap::new(),
            vpn_state: VpnState::Disconnected,
            profile_dir: data_dir.join("profiles"),
            ovpn_dir: data_dir.join("ovpn"),
            ssh_keys: HashMap::new(),
            ssh_hosts: HashMap::new(),
            host_health: HashMap::new(),
            ssh_key_dir: data_dir.join("ssh/keys"),
            ssh_host_dir: data_dir.join("ssh/hosts"),
            unifi_controllers: HashMap::new(),
            unifi_controller_dir: data_dir.join("unifi/controllers"),
            device_type_overrides: crate::device_type_overrides::DeviceTypeOverrides::open(
                &data_dir,
            ),
            webhook_url: String::new(),
            webhook_on_host_down: true,
            webhook_on_vpn_disconnect: false,
            known_hosts,
        })
    }

    // -----------------------------------------------------------------------
    // Profile persistence
    // -----------------------------------------------------------------------

    /// Load all `.toml` profile files from `profile_dir`.
    pub fn load_profiles(&mut self) -> anyhow::Result<()> {
        let mut relocated = Vec::new();
        load_toml_dir(&self.profile_dir, |text, path| {
            match toml::from_str::<Profile>(&text) {
                Ok(mut profile) => {
                    info!("loaded profile '{}' from {:?}", profile.name, path);
                    if relocate_openvpn_config(&mut profile, &self.ovpn_dir) {
                        relocated.push(profile.id);
                    }
                    self.profiles.insert(profile.id, profile);
                }
                Err(e) => {
                    warn!("skipping malformed profile {:?}: {}", path, e);
                }
            }
        })?;
        for id in relocated {
            if let Err(e) = self.save_profile(&self.profiles[&id]) {
                warn!("could not save relocated profile {id}: {e}");
            }
        }
        Ok(())
    }

    /// Persist a single profile to disk.
    pub fn save_profile(&self, profile: &Profile) -> anyhow::Result<()> {
        save_toml(&self.profile_dir, &profile.id.to_string(), profile)
    }

    /// Delete a profile's on-disk file.
    pub fn delete_profile_file(&self, id: Uuid) -> anyhow::Result<()> {
        delete_toml(&self.profile_dir, &id.to_string())
    }

    // -----------------------------------------------------------------------
    // SSH key persistence
    // -----------------------------------------------------------------------

    /// Load all `.toml` SSH key files.
    pub fn load_ssh_keys(&mut self) -> anyhow::Result<()> {
        load_toml_dir(&self.ssh_key_dir, |text, path| {
            match toml::from_str::<SshKey>(&text) {
                Ok(key) => {
                    info!("loaded SSH key '{}' from {:?}", key.name, path);
                    self.ssh_keys.insert(key.id, key);
                }
                Err(e) => {
                    warn!("skipping malformed SSH key {:?}: {}", path, e);
                }
            }
        })
    }

    /// Persist a single SSH key to disk.
    pub fn save_ssh_key(&self, key: &SshKey) -> anyhow::Result<()> {
        save_toml(&self.ssh_key_dir, &key.id.to_string(), key)
    }

    /// Delete an SSH key's on-disk file.
    pub fn delete_ssh_key_file(&self, id: Uuid) -> anyhow::Result<()> {
        delete_toml(&self.ssh_key_dir, &id.to_string())
    }

    // -----------------------------------------------------------------------
    // SSH host persistence
    // -----------------------------------------------------------------------

    /// Load all `.toml` SSH host files.
    pub fn load_ssh_hosts(&mut self) -> anyhow::Result<()> {
        load_toml_dir(&self.ssh_host_dir, |text, path| {
            match toml::from_str::<Host>(&text) {
                Ok(host) => {
                    info!("loaded SSH host '{}' from {:?}", host.label, path);
                    self.ssh_hosts.insert(host.id, host);
                }
                Err(e) => {
                    warn!("skipping malformed SSH host {:?}: {}", path, e);
                }
            }
        })
    }

    /// Persist a single SSH host to disk.
    pub fn save_ssh_host(&self, host: &Host) -> anyhow::Result<()> {
        save_toml(&self.ssh_host_dir, &host.id.to_string(), host)
    }

    /// Delete an SSH host's on-disk file.
    pub fn delete_ssh_host_file(&self, id: Uuid) -> anyhow::Result<()> {
        delete_toml(&self.ssh_host_dir, &id.to_string())
    }

    // -----------------------------------------------------------------------
    // UniFi controller registry (separate from SSH hosts)
    // -----------------------------------------------------------------------

    pub fn load_unifi_controllers(&mut self) -> anyhow::Result<()> {
        load_toml_dir(
            &self.unifi_controller_dir,
            |text, path| match toml::from_str::<crate::unifi_controllers::UnifiController>(&text) {
                Ok(ctrl) => {
                    info!("loaded UniFi controller '{}' from {:?}", ctrl.label, path);
                    self.unifi_controllers.insert(ctrl.id, ctrl);
                }
                Err(e) => {
                    warn!("skipping malformed UniFi controller {:?}: {}", path, e);
                }
            },
        )
    }

    pub fn save_unifi_controller(
        &self,
        ctrl: &crate::unifi_controllers::UnifiController,
    ) -> anyhow::Result<()> {
        save_toml(&self.unifi_controller_dir, &ctrl.id.to_string(), ctrl)
    }

    pub fn delete_unifi_controller_file(&self, id: Uuid) -> anyhow::Result<()> {
        delete_toml(&self.unifi_controller_dir, &id.to_string())
    }
}

// ---------------------------------------------------------------------------
// TOML persistence helpers
// ---------------------------------------------------------------------------

/// Point an OpenVPN profile at its configuration in `ovpn_dir` when the
/// path it records is gone. Import and duplicate write the configuration
/// to `ovpn_dir/<profile id>.ovpn` and record the absolute path, so a data
/// directory copied to another account or Mac keeps profiles naming the
/// old home, and they cannot connect. Only that one file is taken, never
/// another by a similar name. Returns whether the profile changed.
fn relocate_openvpn_config(profile: &mut Profile, ovpn_dir: &std::path::Path) -> bool {
    let ProfileConfig::OpenVpn(config) = &mut profile.config else {
        return false;
    };
    if std::path::Path::new(&config.config_file).exists() {
        return false;
    }
    let own = ovpn_dir.join(format!("{}.ovpn", profile.id));
    if !own.is_file() {
        return false;
    }
    info!(
        "profile '{}': configuration moved from {} to {}",
        profile.name,
        config.config_file,
        own.display()
    );
    config.config_file = own.to_string_lossy().into_owned();
    true
}

fn load_toml_dir(dir: &PathBuf, mut on_entry: impl FnMut(String, PathBuf)) -> anyhow::Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        on_entry(text, path);
    }
    Ok(())
}

/// Write a TOML record atomically: serialize to a sibling `.tmp` file,
/// fsync, then rename over the target. A power loss / kill -9 mid-write
/// no longer truncates the canonical file — the worst case is an orphan
/// `<name>.toml.tmp` next to a still-valid `<name>.toml`. The next loader
/// pass at startup ignores `.tmp` files (it only globs `*.toml`).
fn save_toml<T: serde::Serialize>(dir: &PathBuf, name: &str, value: &T) -> anyhow::Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{name}.toml"));
    let tmp = dir.join(format!("{name}.toml.tmp"));
    let text = toml::to_string_pretty(value)?;

    // Open with truncate + write + fsync.
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.flush()?;
        f.sync_all()?;
    }

    std::fs::rename(&tmp, &path)?;
    // Best-effort: fsync the directory so the rename is durable on
    // ext4/APFS. Failure here is non-fatal.
    if let Ok(dir_handle) = std::fs::File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

fn delete_toml(dir: &PathBuf, name: &str) -> anyhow::Result<()> {
    let path = dir.join(format!("{name}.toml"));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod trust_startup_tests {
    use super::*;

    #[test]
    fn corrupt_trust_store_blocks_engine_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        std::fs::write(&path, "invalid JSON").unwrap();
        assert!(DaemonState::new(dir.path().to_owned()).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "invalid JSON");
    }
}

#[cfg(test)]
mod relocation_tests {
    use super::*;
    use supermgr_core::vpn::profile::OpenVpnConfig;

    fn openvpn_profile(config_file: &str) -> Profile {
        Profile::new(
            "OpenVPN-Server",
            ProfileConfig::OpenVpn(OpenVpnConfig {
                config_file: config_file.into(),
                username: None,
                password: None,
            }),
        )
    }

    fn config_file(state: &DaemonState, id: Uuid) -> String {
        match &state.profiles[&id].config {
            ProfileConfig::OpenVpn(config) => config.config_file.clone(),
            _ => unreachable!(),
        }
    }

    /// A data directory copied from another account: the profile names the
    /// old home, and its configuration is here under the profile's id.
    #[test]
    fn a_profile_naming_a_moved_home_finds_its_configuration_here() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = DaemonState::new(dir.path().to_owned()).unwrap();
        let mut profile = openvpn_profile("");
        let old_home = format!(
            "/Users/someone-else/Library/Application Support/SuperManager/ovpn/{}.ovpn",
            profile.id
        );
        if let ProfileConfig::OpenVpn(config) = &mut profile.config {
            config.config_file = old_home;
        }
        std::fs::create_dir_all(&state.ovpn_dir).unwrap();
        let own = state.ovpn_dir.join(format!("{}.ovpn", profile.id));
        std::fs::write(&own, "client\n").unwrap();
        state.save_profile(&profile).unwrap();

        state.load_profiles().unwrap();
        assert_eq!(config_file(&state, profile.id), own.to_string_lossy());
        // Saved that way, so the next start finds it directly.
        let saved = std::fs::read_to_string(state.profile_dir.join(format!("{}.toml", profile.id)))
            .unwrap();
        assert!(saved.contains(&*own.to_string_lossy()), "{saved}");
    }

    /// A path that exists stays, and a missing path with no copy here is
    /// not replaced by a guess.
    #[test]
    fn a_path_that_exists_or_has_no_copy_here_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = DaemonState::new(dir.path().to_owned()).unwrap();
        let elsewhere = dir.path().join("client.ovpn");
        std::fs::write(&elsewhere, "client\n").unwrap();
        let existing = openvpn_profile(&elsewhere.to_string_lossy());
        let missing = openvpn_profile("/nowhere/other.ovpn");
        std::fs::create_dir_all(&state.ovpn_dir).unwrap();
        // A file here, but under another profile's id.
        std::fs::write(state.ovpn_dir.join("other.ovpn"), "client\n").unwrap();
        state.save_profile(&existing).unwrap();
        state.save_profile(&missing).unwrap();

        state.load_profiles().unwrap();
        assert_eq!(
            config_file(&state, existing.id),
            elsewhere.to_string_lossy()
        );
        assert_eq!(config_file(&state, missing.id), "/nowhere/other.ovpn");
    }
}
