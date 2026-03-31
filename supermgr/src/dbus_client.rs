//! D-Bus helper functions — async wrappers over the `DaemonProxy`.
#![allow(missing_docs)]

use std::sync::{mpsc, Arc, Mutex};

use anyhow::Context as _;
use tracing::{error, info};

use supermgr_core::{
    dbus::DaemonProxy,
    vpn::profile::ProfileSummary,
    vpn::state::{state_from_json, VpnState},
    ssh::key::SshKeySummary,
    ssh::host::SshHostSummary,
};

use crate::app::{AppMsg, AppState};

// ---------------------------------------------------------------------------
// Daemon auto-start helpers
// ---------------------------------------------------------------------------

/// Try a single D-Bus call to the daemon on the system bus.
/// Returns `true` if the daemon responds successfully.
pub async fn ping_daemon() -> bool {
    let Ok(conn) = zbus::Connection::system().await else {
        return false;
    };
    let Ok(proxy) = DaemonProxy::new(&conn).await else {
        return false;
    };
    proxy.get_status().await.is_ok()
}

/// Ensure `supermgrd` is running, starting it via `pkexec` if necessary.
///
/// 1. If the daemon is already reachable on the system bus, return `true`.
/// 2. Locate `supermgrd` next to this executable.
/// 3. Spawn `pkexec /path/to/supermgrd` — pkexec resolves the polkit action from
///    the binary path declared in `org.supermgr.daemon.policy`.  Wheel-group
///    members are granted automatically via the installed polkit rules file.
/// 4. Retry the ping every 100 ms for up to 30 seconds so the user has time
///    to complete the polkit password dialog.
/// 5. Return `true` if the daemon became available, `false` otherwise.
pub async fn ensure_daemon_running() -> bool {
    // Fast path: daemon already up.
    if ping_daemon().await {
        info!("supermgrd is already running");
        return true;
    }

    // Locate the supermgrd binary next to this executable.
    let daemon_path = match std::env::current_exe() {
        Ok(exe) => exe.with_file_name("supermgrd"),
        Err(e) => {
            error!("cannot determine current exe path: {e}");
            return false;
        }
    };

    if !daemon_path.exists() {
        error!("supermgrd not found at {} — cannot auto-start", daemon_path.display());
        return false;
    }

    info!("auto-starting daemon via pkexec: {}", daemon_path.display());

    match std::process::Command::new("pkexec")
        .arg(&daemon_path)
        .spawn()
    {
        Ok(_child) => {
            // Child handle dropped; pkexec (and the daemon it launches)
            // continue running — std::process::Child::drop does NOT kill
            // the child process.
            info!("pkexec launched, waiting for daemon D-Bus registration...");
        }
        Err(e) => {
            error!("failed to spawn pkexec {}: {e}", daemon_path.display());
            return false;
        }
    }

    // Retry up to 300 × 100 ms = 30 seconds to give the user time to
    // complete the pkexec password dialog before we give up.
    for attempt in 1u32..=300 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if ping_daemon().await {
            info!("supermgrd became available after {}ms", attempt * 100);
            return true;
        }
    }

    error!("supermgrd did not become available within 30 seconds after pkexec");
    false
}

// ---------------------------------------------------------------------------
// D-Bus helpers — run inside tokio tasks, all use the system bus
// ---------------------------------------------------------------------------

/// Auto-start the daemon if needed, then connect via the system bus and
/// populate `app_state` with profiles and VPN state.
pub async fn fetch_initial_state(app_state: &Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    if !ensure_daemon_running().await {
        anyhow::bail!("supermgrd is not running and could not be started");
    }

    let conn = zbus::Connection::system()
        .await
        .context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("DaemonProxy::new")?;

    let profiles_json = proxy.list_profiles().await.context("ListProfiles")?;
    let profiles: Vec<ProfileSummary> =
        serde_json::from_str(&profiles_json).context("deserialise profiles")?;

    let status_json = proxy.get_status().await.context("GetStatus")?;
    let mut vpn_state = state_from_json(&status_json).context("deserialise VpnState")?;

    info!(
        "fetched {} profile(s), state = {:?}",
        profiles.len(),
        vpn_state
    );

    // A Connected state on startup means a tunnel from a previous session was
    // left running (e.g. the GUI crashed without disconnecting).  Tear it down
    // so the UI starts from a clean Disconnected state.
    if vpn_state.is_connected() {
        info!("found stale tunnel on startup, disconnecting");
        proxy.disconnect().await.context("Disconnect stale tunnel")?;
        let status_json = proxy.get_status().await.context("GetStatus after stale disconnect")?;
        vpn_state = state_from_json(&status_json).context("deserialise VpnState after stale disconnect")?;
        info!("state after stale disconnect: {:?}", vpn_state);
    }

    let mut s = app_state.lock().unwrap_or_else(|e| e.into_inner());
    s.profiles = profiles;
    s.vpn_state = vpn_state;
    s.daemon_available = true;
    Ok(())
}

/// Fetch SSH keys and hosts from the daemon.
pub async fn fetch_initial_ssh_state(app_state: &Arc<Mutex<AppState>>) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;

    let keys_json = proxy.ssh_list_keys().await.context("SshListKeys")?;
    let keys: Vec<SshKeySummary> = serde_json::from_str(&keys_json).context("parse SSH keys")?;

    let hosts_json = proxy.ssh_list_hosts().await.context("SshListHosts")?;
    let hosts: Vec<SshHostSummary> = serde_json::from_str(&hosts_json).context("parse SSH hosts")?;

    let mut s = app_state.lock().unwrap_or_else(|e| e.into_inner());
    s.ssh_keys = keys;
    s.ssh_hosts = hosts;
    Ok(())
}

/// Read a `.conf` file from `path`, call `ImportWireGuard` on the daemon,
/// then return a refreshed profile list.
///
/// All I/O and D-Bus work runs on the tokio thread pool.
pub async fn dbus_import_wireguard(
    path: std::path::PathBuf,
    name: String,
) -> anyhow::Result<Vec<ProfileSummary>> {
    info!("dbus_import_wireguard: reading {}", path.display());

    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("read {}", path.display()))?;

    info!(
        "dbus_import_wireguard: read {} bytes, calling daemon for profile '{}'",
        contents.len(),
        name
    );

    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;

    let new_uuid = proxy
        .import_wireguard(&contents, &name)
        .await
        .with_context(|| {
            error!(
                "import_wireguard D-Bus call failed for profile '{}'",
                name
            );
            format!("ImportWireGuard D-Bus call failed for '{name}'")
        })?;

    info!(
        "dbus_import_wireguard: daemon accepted profile '{}' → uuid {}",
        name, new_uuid
    );

    let profiles_json = proxy.list_profiles().await.context("ListProfiles")?;
    let profiles: Vec<ProfileSummary> =
        serde_json::from_str(&profiles_json).context("deserialise profiles")?;

    info!(
        "dbus_import_wireguard: profile list refreshed ({} profiles)",
        profiles.len()
    );

    Ok(profiles)
}

/// Import a TOML configuration file via the daemon.
///
/// Returns a JSON object `{ "type": "...", "id": "..." }`.
pub async fn dbus_import_toml(
    path: std::path::PathBuf,
) -> anyhow::Result<String> {
    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("read {}", path.display()))?;

    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    let result = proxy.import_toml(&contents).await
        .with_context(|| format!("ImportToml D-Bus call failed for '{}'", path.display()))?;

    info!("dbus_import_toml: imported {} → {}", path.display(), result);
    Ok(result)
}

/// Open a fresh system-bus connection and issue `Connect(profile_id)`.
pub async fn dbus_connect(profile_id: String) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy.connect(&profile_id).await.context("Connect")?;
    Ok(())
}

/// Open a fresh system-bus connection and issue `Disconnect()`.
pub async fn dbus_disconnect() -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy.disconnect().await.context("Disconnect")?;
    Ok(())
}

/// Fetch only the current [`VpnState`] from the daemon via the system bus.
pub async fn dbus_get_state() -> anyhow::Result<VpnState> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    let json = proxy.get_status().await.context("GetStatus")?;
    state_from_json(&json).context("deserialise VpnState")
}

/// Call `DeleteProfile(profile_id)` on the daemon.
pub async fn dbus_delete_profile(profile_id: String) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy.delete_profile(&profile_id).await.context("DeleteProfile")?;
    Ok(())
}

/// Call `RenameProfile(profile_id, new_name)` on the daemon.
pub async fn dbus_rename_profile(profile_id: String, new_name: String) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy.rename_profile(&profile_id, &new_name).await.context("RenameProfile")?;
    Ok(())
}

/// Call `SetAutoConnect(profile_id, auto_connect)` on the daemon.
pub async fn dbus_set_auto_connect(profile_id: String, auto_connect: bool) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy.set_auto_connect(&profile_id, auto_connect).await.context("SetAutoConnect")?;
    Ok(())
}

/// Call `UpdateFortigate` on the daemon.
pub async fn dbus_update_fortigate(
    profile_id: String,
    name: String,
    host: String,
    username: String,
    password: String,
    psk: String,
) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy
        .update_fortigate(&profile_id, &name, &host, &username, &password, &psk)
        .await
        .context("UpdateFortigate")?;
    Ok(())
}

/// Call `UpdateOpenvpnCredentials` on the daemon.
pub async fn dbus_update_openvpn_credentials(
    profile_id: String,
    username: String,
    password: String,
) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy
        .update_openvpn_credentials(&profile_id, &username, &password)
        .await
        .context("UpdateOpenvpnCredentials")?;
    Ok(())
}

/// Call `SetFullTunnel(profile_id, full_tunnel)` on the daemon.
pub async fn dbus_set_full_tunnel(profile_id: String, full_tunnel: bool) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy.set_full_tunnel(&profile_id, full_tunnel).await.context("SetFullTunnel")?;
    Ok(())
}

/// Call `SetSplitRoutes(profile_id, routes)` on the daemon.
pub async fn dbus_set_split_routes(
    profile_id: String,
    routes: Vec<String>,
) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy.set_split_routes(&profile_id, routes).await.context("SetSplitRoutes")?;
    Ok(())
}

/// Call `GetLogs` on the daemon and return the log lines.
pub async fn dbus_get_logs() -> anyhow::Result<Vec<String>> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy.get_logs().await.context("GetLogs")
}

/// Call `ListProfiles` on the daemon and return the deserialized list.
pub async fn dbus_list_profiles() -> anyhow::Result<Vec<ProfileSummary>> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    let json = proxy.list_profiles().await.context("ListProfiles")?;
    serde_json::from_str(&json).context("parse profiles")
}

/// Call `ImportFortigate` then `ListProfiles` on the daemon.
pub async fn dbus_import_fortigate(
    name: String,
    host: String,
    username: String,
    password: String,
    psk: String,
) -> anyhow::Result<Vec<ProfileSummary>> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    let _uuid = proxy
        .import_fortigate(&name, &host, &username, &password, &psk)
        .await
        .context("ImportFortigate")?;
    let json = proxy.list_profiles().await.context("ListProfiles")?;
    let profiles: Vec<ProfileSummary> =
        serde_json::from_str(&json).context("parse profiles")?;
    Ok(profiles)
}

/// Read both Azure VPN XML config files, call `ImportAzureVpn` on the daemon,
/// then return a refreshed profile list.
///
/// `azure_xml_path` is the path to `AzureVPN/azurevpnconfig.xml`;
/// `vpn_settings_path` is the path to `Generic/VpnSettings.xml`.
pub async fn dbus_import_azure_vpn(
    azure_xml_path: std::path::PathBuf,
    vpn_settings_path: std::path::PathBuf,
    name: String,
) -> anyhow::Result<Vec<ProfileSummary>> {
    use anyhow::Context as _;

    let azure_xml = tokio::fs::read_to_string(&azure_xml_path)
        .await
        .with_context(|| format!("read {}", azure_xml_path.display()))?;

    let vpn_settings_xml = tokio::fs::read_to_string(&vpn_settings_path)
        .await
        .with_context(|| format!("read {}", vpn_settings_path.display()))?;

    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;

    proxy
        .import_azure_vpn(&azure_xml, &vpn_settings_xml, &name)
        .await
        .context("ImportAzureVpn")?;

    let json = proxy.list_profiles().await.context("ListProfiles")?;
    serde_json::from_str(&json).context("parse profiles")
}

/// Read an `.ovpn` file from `path`, call `ImportOpenVpn` on the daemon,
/// then return a refreshed profile list.
///
/// `username` and `password` may be empty strings to import without credentials.
pub(crate) async fn dbus_import_openvpn(
    path: std::path::PathBuf,
    name: String,
    username: String,
    password: String,
) -> anyhow::Result<Vec<ProfileSummary>> {
    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("read {}", path.display()))?;

    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy
        .import_openvpn(&contents, &name, &username, &password)
        .await
        .context("ImportOpenVpn")?;

    let json = proxy.list_profiles().await.context("ListProfiles")?;
    serde_json::from_str(&json).context("parse profiles")
}

/// Call `SetKillSwitch(profile_id, enabled)` on the daemon.
pub async fn dbus_set_kill_switch(profile_id: String, enabled: bool) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    proxy.set_kill_switch(&profile_id, enabled).await.context("SetKillSwitch")?;
    Ok(())
}

/// Call `RotateWireguardKey(profile_id)` on the daemon.
/// Returns the new base64-encoded public key.
pub async fn dbus_rotate_wireguard_key(profile_id: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    Ok(proxy.rotate_wireguard_key(&profile_id).await.context("RotateWireguardKey")?)
}

/// Call `ExportProfile(profile_id)` on the daemon.
/// Returns the profile as a TOML string.
pub async fn dbus_export_profile(profile_id: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    Ok(proxy.export_profile(&profile_id).await.context("ExportProfile")?)
}

// ---------------------------------------------------------------------------
// Config backup & restore
// ---------------------------------------------------------------------------

/// Call `ExportAll` on the daemon.  Returns the full backup JSON string.
pub async fn dbus_export_all() -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    Ok(proxy.export_all().await.context("ExportAll")?)
}

/// Call `ImportAll(data)` on the daemon.  Returns the summary JSON string
/// (e.g. `{"profiles": 2, "ssh_keys": 1, "ssh_hosts": 3}`).
pub async fn dbus_import_all(data: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await.context("D-Bus system connection")?;
    let proxy = DaemonProxy::new(&conn).await.context("proxy")?;
    Ok(proxy.import_all(&data).await.context("ImportAll")?)
}

// ---------------------------------------------------------------------------
// SSH D-Bus wrappers
// ---------------------------------------------------------------------------

pub async fn dbus_ssh_generate_key(
    name: String, key_type: String, description: String, tags: Vec<String>,
) -> anyhow::Result<(Vec<SshKeySummary>, String)> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let tags_json = serde_json::to_string(&tags)?;
    let uuid = proxy.ssh_generate_key(&key_type, &name, &description, &tags_json).await?;
    let json = proxy.ssh_list_keys().await?;
    let keys: Vec<SshKeySummary> = serde_json::from_str(&json)?;
    Ok((keys, uuid))
}

pub async fn dbus_ssh_list_keys() -> anyhow::Result<Vec<SshKeySummary>> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let json = proxy.ssh_list_keys().await?;
    Ok(serde_json::from_str(&json)?)
}

pub async fn dbus_ssh_list_hosts() -> anyhow::Result<Vec<SshHostSummary>> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let json = proxy.ssh_list_hosts().await?;
    Ok(serde_json::from_str(&json)?)
}

pub async fn dbus_ssh_delete_key(key_id: String) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    proxy.ssh_delete_key(&key_id).await?;
    Ok(())
}

pub async fn dbus_ssh_delete_host(host_id: String) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    proxy.ssh_delete_host(&host_id).await?;
    Ok(())
}

pub async fn dbus_ssh_toggle_pin(host_id: String) -> anyhow::Result<Vec<SshHostSummary>> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let json = proxy.ssh_toggle_pin(&host_id).await?;
    Ok(serde_json::from_str(&json)?)
}

pub async fn dbus_ssh_add_host(host_json: String) -> anyhow::Result<(Vec<SshHostSummary>, String)> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let uuid = proxy.ssh_add_host(&host_json).await?;
    let json = proxy.ssh_list_hosts().await?;
    let hosts: Vec<SshHostSummary> = serde_json::from_str(&json)?;
    Ok((hosts, uuid))
}

pub async fn dbus_ssh_push_key(
    key_id: String, host_ids: Vec<String>, use_sudo: bool,
) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let hosts_json = serde_json::to_string(&host_ids)?;
    Ok(proxy.ssh_push_key(&key_id, &hosts_json, use_sudo).await?)
}

pub async fn dbus_ssh_revoke_key(
    key_id: String, host_ids: Vec<String>, use_sudo: bool,
) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let hosts_json = serde_json::to_string(&host_ids)?;
    Ok(proxy.ssh_revoke_key(&key_id, &hosts_json, use_sudo).await?)
}

pub async fn dbus_ssh_connect_command(host_id: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    Ok(proxy.ssh_connect_command(&host_id).await?)
}

pub async fn dbus_ssh_test_connection(host_id: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    Ok(proxy.ssh_test_connection(&host_id).await?)
}

pub async fn dbus_ssh_export_public_key(key_id: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    Ok(proxy.ssh_export_public_key(&key_id).await?)
}

pub async fn dbus_ssh_export_private_key(key_id: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    Ok(proxy.ssh_export_private_key(&key_id).await?)
}

pub async fn dbus_ssh_set_password(host_id: String, password: String) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    proxy.ssh_set_password(&host_id, &password).await?;
    Ok(())
}

pub async fn dbus_ssh_set_api_token(host_id: String, token: String, port: u16) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    proxy.ssh_set_api_token(&host_id, &token, port).await?;
    Ok(())
}

pub async fn dbus_ssh_import_scan(directory: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    Ok(proxy.ssh_import_keys_scan(&directory).await?)
}

pub async fn dbus_ssh_import_key(
    name: String, public_key: String, private_key_pem: String, key_type: String,
) -> anyhow::Result<Vec<SshKeySummary>> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    proxy.ssh_import_key(&name, &public_key, &private_key_pem, &key_type).await?;
    let json = proxy.ssh_list_keys().await?;
    Ok(serde_json::from_str(&json)?)
}

pub async fn dbus_ssh_get_audit_log(max_lines: u32) -> anyhow::Result<Vec<String>> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    Ok(proxy.ssh_get_audit_log(max_lines).await?)
}

pub async fn dbus_ssh_update_host(host_id: String, host_json: String) -> anyhow::Result<()> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    proxy.ssh_update_host(&host_id, &host_json).await?;
    Ok(())
}

pub async fn dbus_ssh_get_key(key_id: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    Ok(proxy.ssh_get_key(&key_id).await?)
}

pub async fn dbus_ssh_get_host(host_id: String) -> anyhow::Result<String> {
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    Ok(proxy.ssh_get_host(&host_id).await?)
}

// ---------------------------------------------------------------------------
// Signal listener
// ---------------------------------------------------------------------------

/// Subscribe to `StateChanged`, `StatsUpdated`, `AuthChallenge`, and
/// `SshOperationProgress` D-Bus signals from the daemon and forward them to
/// the GTK drain loop.
///
/// Runs indefinitely, reconnecting automatically whenever the daemon disappears
/// and comes back.  Returns only when `tx` is dropped (GTK window destroyed).
pub async fn run_signal_listener(app_state: Arc<Mutex<AppState>>, tx: mpsc::Sender<AppMsg>) {
    use futures_util::StreamExt as _;

    loop {
        // --- Open a connection and subscribe to all signal streams ----------
        let conn = match zbus::Connection::system().await {
            Ok(c) => c,
            Err(e) => {
                error!("signal listener: D-Bus connect: {e}");
                if tx.send(AppMsg::DaemonUnavailable).is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        let proxy = match DaemonProxy::new(&conn).await {
            Ok(p) => p,
            Err(e) => {
                error!("signal listener: proxy: {e}");
                if tx.send(AppMsg::DaemonUnavailable).is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        let mut state_stream = match proxy.receive_state_changed().await {
            Ok(s) => s,
            Err(e) => {
                error!("signal listener: receive_state_changed: {e}");
                if tx.send(AppMsg::DaemonUnavailable).is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        let mut stats_stream = match proxy.receive_stats_updated().await {
            Ok(s) => s,
            Err(e) => {
                error!("signal listener: receive_stats_updated: {e}");
                if tx.send(AppMsg::DaemonUnavailable).is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        let mut auth_stream = match proxy.receive_auth_challenge().await {
            Ok(s) => s,
            Err(e) => {
                error!("signal listener: receive_auth_challenge: {e}");
                if tx.send(AppMsg::DaemonUnavailable).is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        let mut ssh_progress_stream = match proxy.receive_ssh_operation_progress().await {
            Ok(s) => s,
            Err(e) => {
                error!("signal listener: receive_ssh_operation_progress: {e}");
                if tx.send(AppMsg::DaemonUnavailable).is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        let mut health_stream = match proxy.receive_host_health_changed().await {
            Ok(s) => s,
            Err(e) => {
                error!("signal listener: receive_host_health_changed: {e}");
                if tx.send(AppMsg::DaemonUnavailable).is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        info!("signal listener: subscribed to daemon signals");

        // --- Forward signals until a stream ends (daemon gone) --------------
        loop {
            tokio::select! {
                maybe = state_stream.next() => {
                    let Some(signal) = maybe else { break };
                    match signal.args() {
                        Ok(args) => match state_from_json(&args.state_json) {
                            Ok(state) => {
                                if tx.send(AppMsg::StateUpdated(state)).is_err() {
                                    return;
                                }
                            }
                            Err(e) => error!("signal listener: parse StateChanged: {e}"),
                        },
                        Err(e) => error!("signal listener: StateChanged args: {e}"),
                    }
                }
                maybe = stats_stream.next() => {
                    let Some(signal) = maybe else { break };
                    match signal.args() {
                        Ok(args) => {
                            match serde_json::from_str::<serde_json::Value>(&args.stats_json) {
                                Ok(v) => {
                                    // last_handshake is ISO-8601 in the JSON (from chrono).
                                    // We convert it to a unix epoch second by parsing only
                                    // the numeric components without an external crate.
                                    let lh_secs = v["last_handshake"]
                                        .as_str()
                                        .and_then(parse_rfc3339_secs)
                                        .unwrap_or(0);
                                    let active_routes: Vec<String> = v["active_routes"]
                                        .as_array()
                                        .map(|arr| {
                                            arr.iter()
                                                .filter_map(|r| r.as_str().map(str::to_owned))
                                                .collect()
                                        })
                                        .unwrap_or_default();
                                    let msg = AppMsg::StatsUpdated {
                                        bytes_sent: v["bytes_sent"].as_u64().unwrap_or(0),
                                        bytes_received: v["bytes_received"].as_u64().unwrap_or(0),
                                        last_handshake_secs: lh_secs,
                                        virtual_ip: v["virtual_ip"]
                                            .as_str()
                                            .unwrap_or("")
                                            .to_owned(),
                                        active_routes,
                                        uptime_secs: v["uptime_secs"].as_u64().unwrap_or(0),
                                    };
                                    if tx.send(msg).is_err() {
                                        return;
                                    }
                                }
                                Err(e) => error!("signal listener: parse StatsUpdated: {e}"),
                            }
                        }
                        Err(e) => error!("signal listener: StatsUpdated args: {e}"),
                    }
                }
                maybe = auth_stream.next() => {
                    let Some(signal) = maybe else { break };
                    match signal.args() {
                        Ok(args) => {
                            let msg = AppMsg::AuthChallenge {
                                user_code: args.user_code.to_owned(),
                                verification_url: args.verification_url.to_owned(),
                            };
                            if tx.send(msg).is_err() {
                                return;
                            }
                        }
                        Err(e) => error!("signal listener: AuthChallenge args: {e}"),
                    }
                }
                maybe = ssh_progress_stream.next() => {
                    let Some(signal) = maybe else { break };
                    match signal.args() {
                        Ok(args) => {
                            let msg = AppMsg::SshOperationProgress {
                                operation_id: args.operation_id.to_owned(),
                                host_label: args.host_label.to_owned(),
                                message: args.message.to_owned(),
                            };
                            if tx.send(msg).is_err() {
                                return;
                            }
                        }
                        Err(e) => error!("signal listener: SshOperationProgress args: {e}"),
                    }
                }
                maybe = health_stream.next() => {
                    let Some(signal) = maybe else { break };
                    match signal.args() {
                        Ok(args) => {
                            let msg = AppMsg::HostHealthChanged {
                                host_id: args.host_id.to_owned(),
                                reachable: args.reachable,
                            };
                            if tx.send(msg).is_err() {
                                return;
                            }
                        }
                        Err(e) => error!("signal listener: HostHealthChanged args: {e}"),
                    }
                }
            }
        }

        // --- Stream ended — daemon disappeared ------------------------------
        info!("signal listener: stream ended; daemon may have stopped");
        drop(state_stream);
        drop(stats_stream);
        drop(auth_stream);
        drop(ssh_progress_stream);
        drop(health_stream);
        drop(proxy);
        if tx.send(AppMsg::DaemonUnavailable).is_err() {
            return;
        }

        // Poll until the daemon becomes reachable again.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if ping_daemon().await {
                break;
            }
        }

        // Fetch fresh VPN + SSH state, then notify the GTK thread.
        match fetch_initial_state(&app_state).await {
            Ok(()) => {
                // Also refresh SSH state so the GUI is fully up-to-date.
                let _ = fetch_initial_ssh_state(&app_state).await;

                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
                let msg = AppMsg::DaemonConnected {
                    profiles: s.profiles.clone(),
                    state: s.vpn_state.clone(),
                };
                if tx.send(msg).is_err() {
                    return;
                }
                let keys = s.ssh_keys.clone();
                let hosts = s.ssh_hosts.clone();
                drop(s);
                // Send SSH refresh messages so the GUI sidebar updates.
                if tx.send(AppMsg::SshKeysRefreshed(keys)).is_err() {
                    return;
                }
                if tx.send(AppMsg::SshHostsRefreshed(hosts)).is_err() {
                    return;
                }
            }
            Err(e) => {
                error!("signal listener: fetch_initial_state after reconnect: {:#}", e);
                // Loop back to re-subscribe; will fail and keep retrying.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse an RFC-3339 / ISO-8601 datetime string like `"2026-03-17T20:31:06Z"`
/// into Unix epoch seconds without an external time crate.
///
/// Handles only the subset that `chrono` produces: `YYYY-MM-DDTHH:MM:SS[.f]Z`
/// or `YYYY-MM-DDTHH:MM:SS[.f]+HH:MM`.  Returns `None` on malformed input.
fn parse_rfc3339_secs(s: &str) -> Option<u64> {
    // Minimum: "2006-01-02T15:04:05Z" = 20 chars
    if s.len() < 20 { return None; }
    let (date, rest) = s.split_once('T')?;
    let mut parts = date.splitn(3, '-');
    let year:  u64 = parts.next()?.parse().ok()?;
    let month: u64 = parts.next()?.parse().ok()?;
    let day:   u64 = parts.next()?.parse().ok()?;

    // Strip timezone suffix (Z or ±HH:MM) and optional fractional seconds.
    let time_part = rest
        .split_once('Z').map(|(t, _)| t)
        .or_else(|| rest.split_once('+').map(|(t, _)| t))
        .or_else(|| rest.rfind('-').map(|i| &rest[..i]))
        .unwrap_or(rest);
    let time_part = time_part.split('.').next().unwrap_or(time_part);

    let mut tparts = time_part.splitn(3, ':');
    let hour:   u64 = tparts.next()?.parse().ok()?;
    let minute: u64 = tparts.next()?.parse().ok()?;
    let second: u64 = tparts.next()?.parse().ok()?;

    // Days since Unix epoch (1970-01-01) using the proleptic Gregorian calendar.
    // Algorithm: days from year 0 to given date, minus days from year 0 to epoch.
    let days_to_year = |y: u64| {
        let y = y - 1;
        y * 365 + y / 4 - y / 100 + y / 400
    };
    let days_in_month = [0u64, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let day_of_year: u64 = days_in_month[..month as usize].iter().sum::<u64>()
        + if leap && month > 2 { 1 } else { 0 }
        + day
        - 1;

    const EPOCH_DAYS: u64 = 719_162; // days from year 0 to 1970-01-01
    let days = days_to_year(year) + day_of_year;
    if days < EPOCH_DAYS { return None; }
    Some((days - EPOCH_DAYS) * 86_400 + hour * 3_600 + minute * 60 + second)
}
