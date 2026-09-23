//! Method dispatcher.
//!
//! Each incoming [`PipeRequest`] is routed to one of the handlers below.
//! Handler bodies are intentionally short — they extract arguments from
//! `req.args`, call into the appropriate subsystem (SSH key store, profile
//! manager, VPN backend), and serialise the result. Heavy logic lives in
//! the subsystem modules, not here.
//!
//! # Method-name parity with Linux
//!
//! The Linux `supermgrd` exposes its API via D-Bus method names. To keep
//! the MCP server and GUI cross-platform, the Windows daemon must accept
//! the **same** method names with the **same** semantics. When porting a
//! new method:
//!
//! 1. Find the Linux method signature in `supermgr-core::dbus`.
//! 2. Add a `PipeClient` wrapper in `supermgr-core::pipe` (so the GUI/MCP
//!    don't have to call `invoke()` directly).
//! 3. Add a `match` arm here with the matching name.
//!
//! The dispatcher returns [`RpcError::Protocol`] for unknown methods so
//! mismatches surface immediately during development.

use std::sync::Arc;

use serde_json::{json, Value};
use tracing::{info, warn};

use supermgr_core::protocol::{PipeRequest, PipeResponse, RpcError, PROTOCOL_VERSION};
use supermgr_core::secret_lifecycle::SecretOwner;

use super::daemon::DaemonState;
use super::{appliance, known_hosts, ssh_exec};
use crate::rpc_args::arg_id;

/// Clear every credential an entity owned, after its record is gone.
///
/// Windows keeps these in Credential Manager, so a label that outlives its
/// record is a credential that survives uninstalling the profile it belonged
/// to. `secret_labels` is the shared definition of what an entity owns, so
/// this daemon cannot drift from the Linux and macOS ones the way it had.
///
/// Best-effort by design: a missing label is normal (the operator may have
/// cleared it by hand, or the record predates the field), while a label that
/// fails to delete is worth a line in the log because the credential is
/// still readable.
async fn clear_owned_secrets<T: SecretOwner>(state: &Arc<DaemonState>, owner: &T, what: &str) {
    for label in owner.secret_labels() {
        if let Err(e) = state.secret_store.delete(&label).await {
            warn!("{what}: credential {label} not removed: {e}");
        }
    }
}

/// Route a single request to the appropriate handler and produce the
/// matching response envelope.
pub async fn dispatch(state: &Arc<DaemonState>, req: &PipeRequest) -> PipeResponse {
    let result: Result<Value, RpcError> = match req.method.as_str() {
        // ----- VPN profile lifecycle -----
        "list_profiles" => handle_list_profiles(state).await,
        "connect" => handle_connect(state, &req.args).await,
        "disconnect" => handle_disconnect(state).await,
        "get_status" => handle_get_status(state).await,
        "delete_profile" => handle_delete_profile(state, &req.args).await,
        "rename_profile" => handle_rename_profile(state, &req.args).await,
        "set_push_dns" => handle_set_push_dns(state, &req.args).await,
        "set_full_tunnel" => handle_set_full_tunnel(state, &req.args).await,
        "vpn_capabilities" => Ok(handle_vpn_capabilities()),
        "import_wireguard" => handle_import_wireguard(state, &req.args).await,
        "import_openvpn" => handle_import_openvpn(state, &req.args).await,
        "import_azure_vpn" => handle_import_azure_vpn(state, &req.args).await,
        "import_forticlient_sslvpn" => handle_import_forticlient_sslvpn(state, &req.args).await,
        "import_fortigate" => handle_import_fortigate(state, &req.args).await,

        // ----- SSH keys -----
        "ssh_generate_key" => handle_ssh_generate_key(state, &req.args).await,
        "ssh_list_keys" => handle_ssh_list_keys(state).await,
        "ssh_delete_key" => handle_ssh_delete_key(state, &req.args).await,
        "ssh_export_public_key" => handle_ssh_export_public_key(state, &req.args).await,

        // ----- Hosts -----
        "list_hosts" => handle_list_hosts(state).await,
        "get_host" => handle_get_host(state, &req.args).await,
        "add_host" => handle_add_host(state, &req.args).await,
        "delete_host" => handle_delete_host(state, &req.args).await,
        "ssh_execute_command" => handle_ssh_execute_command(state, &req.args).await,
        "test_host_connection" => handle_test_host_connection(state, &req.args).await,
        "toggle_host_pin" => handle_toggle_host_pin(state, &req.args).await,
        "ssh_list_known_hosts" => handle_ssh_list_known_hosts(state).await,
        "ssh_forget_host_key" => handle_ssh_forget_host_key(state, &req.args).await,
        "ssh_trust_host_key" => handle_ssh_trust_host_key(state, &req.args).await,
        "ssh_set_password" => handle_ssh_set_password(state, &req.args).await,
        "ssh_set_api_token" => handle_ssh_set_api_token(state, &req.args).await,

        // ----- Network appliances (UniFi / FortiGate / OPNsense / Sophos) -----
        "unifi_set_inform" => handle_unifi_set_inform(state, &req.args).await,
        "unifi_api" => handle_unifi_api(state, &req.args).await,
        "fortigate_api" => handle_fortigate_api(state, &req.args).await,
        "fortigate_push_ssh_key" => handle_fortigate_push_ssh_key(state, &req.args).await,
        "fortigate_backup_config" => handle_fortigate_backup_config(state, &req.args).await,
        "opnsense_api" => handle_opnsense_api(state, &req.args).await,
        "opnsense_backup_config" => handle_opnsense_backup_config(state, &req.args).await,
        "sophos_xml_api" => handle_sophos_xml_api(state, &req.args).await,

        other => {
            warn!("unknown method: {other}");
            Err(RpcError::Protocol(format!("unknown method: {other}")))
        }
    };

    match result {
        Ok(value) => PipeResponse {
            v: PROTOCOL_VERSION,
            id: req.id,
            result: Some(value),
            error: None,
        },
        Err(e) => PipeResponse {
            v: PROTOCOL_VERSION,
            id: req.id,
            result: None,
            error: Some(e),
        },
    }
}

/// Boilerplate-saver: extract a required string arg, returning a typed
/// protocol error on miss.
fn arg_str<'a>(args: &'a Value, name: &str) -> Result<&'a str, RpcError> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Protocol(format!("missing string arg: {name}")))
}

/// Boilerplate-saver: extract a required u64 arg.
fn arg_u64(args: &Value, name: &str) -> Result<u64, RpcError> {
    args.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::Protocol(format!("missing integer arg: {name}")))
}

/// Standard response for methods that aren't ported yet. Lets the GUI/MCP
/// fail with a clear message instead of "unknown method". Currently
/// unused — every dispatch arm has a real implementation — but kept
/// available for future RPC methods that land before their handlers.
#[allow(dead_code)]
fn stub(method: &'static str) -> Result<Value, RpcError> {
    Err(RpcError::Other(format!(
        "{method} is not yet implemented in supermgrd-win — see TODO in dispatch.rs"
    )))
}

// ---------------------------------------------------------------------------
// VPN handlers. Connecting and disconnecting go through the session
// (`vpn::session`), which owns the tunnel's state and runs the backends;
// the handlers here only find the profile and report.
// ---------------------------------------------------------------------------

async fn handle_list_profiles(state: &Arc<DaemonState>) -> Result<Value, RpcError> {
    let summaries = state.profile_store.list_summaries().await;
    let json = serde_json::to_string(&summaries)
        .map_err(|e| RpcError::Other(format!("serialise profile summaries: {e}")))?;
    Ok(Value::String(json))
}

/// A profile id from the request, as a UUID.
fn arg_profile_id(args: &Value) -> Result<uuid::Uuid, RpcError> {
    let id = arg_id(args, "profile_id")?;
    uuid::Uuid::parse_str(id).map_err(|e| RpcError::Protocol(format!("invalid profile_id: {e}")))
}

/// Start connecting a profile.
///
/// Returns as soon as the bring-up has started — in milliseconds, where it
/// used to hold the caller's pipe for the whole handshake. Progress, the
/// outcome, and the reason for a failure are in `get_status`.
async fn handle_connect(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let profile_id = arg_profile_id(args)?;
    let profile = state
        .profile_store
        .get(profile_id)
        .await
        .map_err(|_| RpcError::NotFound(format!("profile {profile_id}")))?;
    state
        .session
        .begin_connect(Arc::clone(state), profile)
        .await?;
    Ok(json!({ "status": "connecting", "profile_id": profile_id.to_string() }))
}

/// Disconnect the tunnel, or cancel a connect still in progress. Also how
/// the GUI clears an error: afterwards the state is `disconnected`.
async fn handle_disconnect(state: &Arc<DaemonState>) -> Result<Value, RpcError> {
    state.session.disconnect(state).await?;
    Ok(Value::Null)
}

/// The session's state, in the Linux daemon's `VpnState` shape plus the
/// backend label and, while an Azure connect waits, the sign-in URL.
///
/// A JSON string, like every other structured result on this pipe, so
/// `PipeClient::get_status` hands both platforms' callers the same text.
async fn handle_get_status(state: &Arc<DaemonState>) -> Result<Value, RpcError> {
    Ok(Value::String(state.session.snapshot().await.to_string()))
}

/// Which backends can actually run on this machine, and why not when one
/// cannot.
///
/// The GUI asks before offering an import: a profile type whose client is
/// missing used to import fine and then fail on every connect.
fn handle_vpn_capabilities() -> Value {
    use super::vpn::{forticlient, openvpn, wireguard};

    fn entry(check: Result<(), String>) -> Value {
        match check {
            Ok(()) => json!({ "available": true }),
            Err(reason) => json!({ "available": false, "reason": reason }),
        }
    }
    let openvpn = openvpn::availability();
    Value::String(
        json!({
            "wireguard": entry(wireguard::availability()),
            "openvpn": entry(openvpn.clone()),
            // Azure P2S runs the same openvpn.exe.
            "azure": entry(openvpn),
            // Windows' own IKEv2 client; nothing to install.
            "fortigate": entry(Ok(())),
            "forticlient": entry(forticlient::availability()),
        })
        .to_string(),
    )
}

/// Rename a profile. Same contract as the Linux daemon's `rename_profile`.
async fn handle_rename_profile(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let id = arg_profile_id(args)?;
    let new_name = arg_str(args, "new_name")?.trim();
    if new_name.is_empty() {
        return Err(RpcError::Other("profile name must not be empty".into()));
    }
    let mut profile = state
        .profile_store
        .get(id)
        .await
        .map_err(|_| RpcError::NotFound(format!("profile {id}")))?;
    new_name.clone_into(&mut profile.name);
    profile.updated_at = chrono::Utc::now();
    state
        .profile_store
        .save(profile)
        .await
        .map_err(|e| RpcError::Other(format!("persist profile: {e}")))?;
    Ok(Value::Null)
}

/// Whether connecting a profile also points Windows at the VPN's DNS
/// servers. Takes effect on the next connect.
///
/// Without it a split tunnel resolves nothing on the far side: the
/// tunnel is up and every internal name still goes to the LAN's resolver.
async fn handle_set_push_dns(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let id = arg_profile_id(args)?;
    let enabled = args
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| RpcError::Protocol("missing bool arg: enabled".into()))?;
    let mut profile = state
        .profile_store
        .get(id)
        .await
        .map_err(|_| RpcError::NotFound(format!("profile {id}")))?;
    profile.push_dns = enabled;
    profile.updated_at = chrono::Utc::now();
    state
        .profile_store
        .save(profile)
        .await
        .map_err(|e| RpcError::Other(format!("persist profile: {e}")))?;
    Ok(Value::Null)
}

async fn handle_delete_profile(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let id_str = arg_str(args, "profile_id")?;
    let id = uuid::Uuid::parse_str(id_str)
        .map_err(|e| RpcError::Other(format!("invalid profile_id uuid: {e}")))?;

    // Read the record before destroying it: removing the TOML was all this
    // did, so the interface key, every peer PSK, and any FortiGate or
    // OpenVPN password stayed in Credential Manager for good. `get` also
    // makes deleting a profile that isn't there a `NotFound` — `delete`
    // treats a missing file as success, so the arm below never fired and
    // the Windows daemon answered `null` where Linux answers "no such
    // profile".
    let profile = state
        .profile_store
        .get(id)
        .await
        .map_err(|_| RpcError::NotFound(format!("profile {id}")))?;

    // As on Linux: a tunnel that is up, or coming up, keeps its profile.
    // Deleting it would clear the credentials the backend is still using
    // and leave a tunnel the GUI can no longer name.
    if state.session.is_busy_with(id).await {
        return Err(RpcError::Backend(
            "This profile is connected or connecting — disconnect it first".into(),
        ));
    }

    state.profile_store.delete(id).await.map_err(|e| match e {
        super::profile_store::StoreError::NotFound(_) => {
            RpcError::NotFound(format!("profile {id}"))
        }
        other => RpcError::Other(other.to_string()),
    })?;

    clear_owned_secrets(state, &profile, &format!("profile {id}")).await;
    remove_imported_config(&profile).await;
    Ok(Value::Null)
}

/// Delete the `.ovpn` an OpenVPN import wrote, along with its profile.
///
/// Only a file in the daemon's own private config directory: a profile
/// that points at a config somewhere else — one copied from another
/// machine, or written by hand — refers to a file this daemon did not
/// create and has no business removing.
async fn remove_imported_config(profile: &supermgr_core::vpn::profile::Profile) {
    use supermgr_core::vpn::profile::ProfileConfig;

    let ProfileConfig::OpenVpn(cfg) = &profile.config else {
        return;
    };
    let Ok(dir) = super::paths::private_config_dir() else {
        return;
    };
    let path = std::path::Path::new(&cfg.config_file);
    if path.parent() != Some(dir.as_path()) {
        return;
    }
    if let Err(e) = tokio::fs::remove_file(path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(
                "profile {}: config {} not removed: {e}",
                profile.id,
                path.display()
            );
        }
    }
}

/// Whether connecting a profile sends all traffic through the tunnel, or
/// only what the tunnel routes. Takes effect on the next connect.
///
/// Meaningful for the backends that decide it themselves — Azure and the
/// SSL VPN. WireGuard and OpenVPN take it from their own config
/// (`AllowedIPs`, `redirect-gateway`), and Windows' IKEv2 client always
/// sends everything.
async fn handle_set_full_tunnel(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let id = arg_profile_id(args)?;
    let enabled = args
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| RpcError::Protocol("missing bool arg: enabled".into()))?;
    let mut profile = state
        .profile_store
        .get(id)
        .await
        .map_err(|_| RpcError::NotFound(format!("profile {id}")))?;
    profile.full_tunnel = enabled;
    profile.updated_at = chrono::Utc::now();
    state
        .profile_store
        .save(profile)
        .await
        .map_err(|e| RpcError::Other(format!("persist profile: {e}")))?;
    Ok(Value::Null)
}

/// Parse a wg-quick `.conf` text, persist the private key + any PSKs to
/// Credential Manager, save the profile TOML, and return the new
/// profile's UUID. Mirrors the Linux daemon's `import_wireguard` method
/// so the GUI and MCP server can use the same call on both OSes.
async fn handle_import_wireguard(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    use supermgr_core::vpn::profile::{import_wireguard_conf, Profile, ProfileConfig};

    let conf_text = arg_str(args, "conf_text")?;
    let name = arg_str(args, "name")?.trim();
    if name.is_empty() {
        return Err(RpcError::Other("profile name must not be empty".into()));
    }

    // Lightweight pre-check so the user gets a clear "this isn't a
    // WireGuard config" message instead of a cryptic parser error.
    let looks_like_wg = conf_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .any(|l| l.eq_ignore_ascii_case("[Interface]"));
    if !looks_like_wg {
        return Err(RpcError::Other(
            "not a valid WireGuard config (no [Interface] section found)".into(),
        ));
    }

    let profile_id = uuid::Uuid::new_v4();
    let secret_label = format!("supermgr/wg/{}", profile_id.simple());

    let (wg_cfg, raw_key, psks) = import_wireguard_conf(conf_text, &secret_label)
        .map_err(|e| RpcError::Other(format!("parse WireGuard conf: {e}")))?;

    state
        .secret_store
        .store(&secret_label, raw_key.take().as_bytes())
        .await
        .map_err(|e| RpcError::Secret(format!("store WireGuard private key: {e}")))?;

    for (label, value) in &psks {
        state
            .secret_store
            .store(label, value.as_bytes())
            .await
            .map_err(|e| RpcError::Secret(format!("store PSK {label}: {e}")))?;
    }

    // A `DNS =` line is part of what the config asks for, and the official
    // WireGuard client applies it. Importing it switched off meant internal
    // names never resolved over a split tunnel — "connected, nothing works".
    let push_dns = !wg_cfg.dns.is_empty();
    let profile = Profile {
        id: profile_id,
        name: name.to_owned(),
        auto_connect: false,
        full_tunnel: true,
        last_connected_at: None,
        kill_switch: false,
        push_dns,
        customer: String::new(),
        config: ProfileConfig::WireGuard(wg_cfg),
        updated_at: chrono::Utc::now(),
    };

    state
        .profile_store
        .save(profile)
        .await
        .map_err(|e| RpcError::Other(format!("persist profile: {e}")))?;

    Ok(Value::String(profile_id.to_string()))
}

/// Import an OpenVPN client config.
///
/// Mirrors the Linux daemon's `import_openvpn`: the text is validated, kept
/// whole as a file the profile points at, and a username and password —
/// when both are given — go to Credential Manager, where the backend
/// answers the server's credential prompt from.
///
/// The file goes in the private `ovpn` directory, not beside the profile
/// TOMLs: those are readable by every signed-in user, and a client config
/// usually carries its private key inline.
async fn handle_import_openvpn(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    use supermgr_core::vpn::profile::{OpenVpnConfig, Profile, ProfileConfig, SecretRef};

    let conf_text = arg_str(args, "conf_text")?;
    let name = arg_str(args, "name")?.trim();
    if name.is_empty() {
        return Err(RpcError::Other("profile name must not be empty".into()));
    }
    let username = args
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let password = args.get("password").and_then(Value::as_str).unwrap_or("");

    supermgr_core::vpn::import::validate_ovpn_config(conf_text)
        .map_err(|e| RpcError::Other(format!("not a usable OpenVPN client config: {e}")))?;

    let profile_id = uuid::Uuid::new_v4();
    let dir = super::paths::private_config_dir()
        .map_err(|e| RpcError::Other(format!("prepare the OpenVPN config directory: {e}")))?;
    let config_path = dir.join(format!("{profile_id}.ovpn"));
    tokio::fs::write(&config_path, conf_text)
        .await
        .map_err(|e| RpcError::Other(format!("write the OpenVPN config: {e}")))?;

    let (opt_username, opt_password) = if !username.is_empty() && !password.is_empty() {
        let label = format!("supermgr/ovpn/{}/password", profile_id.simple());
        if let Err(e) = state.secret_store.store(&label, password.as_bytes()).await {
            let _ = tokio::fs::remove_file(&config_path).await;
            return Err(RpcError::Secret(format!("store OpenVPN password: {e}")));
        }
        (Some(username.to_owned()), Some(SecretRef::new(label)))
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
        push_dns: false,
        customer: String::new(),
        config: ProfileConfig::OpenVpn(OpenVpnConfig {
            config_file: config_path.to_string_lossy().into_owned(),
            username: opt_username,
            password: opt_password,
        }),
        updated_at: chrono::Utc::now(),
    };
    if let Err(e) = state.profile_store.save(profile.clone()).await {
        let _ = tokio::fs::remove_file(&config_path).await;
        clear_owned_secrets(state, &profile, "unsaved OpenVPN import").await;
        return Err(RpcError::Other(format!("persist profile: {e}")));
    }
    Ok(Value::String(profile_id.to_string()))
}

/// Import an Azure VPN (Entra ID) profile from the `azurevpnconfig.xml` in
/// the gateway's profile package, plus its `VpnSettings.xml` when there is
/// one. Same parser as the Linux daemon.
///
/// Imported as a split tunnel: the gateway pushes the routes for the
/// networks behind it, which is what the Azure VPN Client uses too. Sending
/// everything through a P2S gateway takes internet access with it unless
/// the gateway was built for forced tunnelling, and that is the operator's
/// call to make with `set_full_tunnel`, not a default.
async fn handle_import_azure_vpn(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    use supermgr_core::vpn::profile::{Profile, ProfileConfig};

    let azure_xml = arg_str(args, "azure_xml")?;
    let vpn_settings_xml = args
        .get("vpn_settings_xml")
        .and_then(Value::as_str)
        .unwrap_or("");
    let name = arg_str(args, "name")?.trim();
    if name.is_empty() {
        return Err(RpcError::Other("profile name must not be empty".into()));
    }

    let cfg = supermgr_core::vpn::import::parse_azure_xml(azure_xml, vpn_settings_xml)
        .map_err(|e| RpcError::Other(format!("not a usable Azure VPN profile: {e}")))?;

    let profile_id = uuid::Uuid::new_v4();
    let profile = Profile {
        id: profile_id,
        name: name.to_owned(),
        auto_connect: false,
        full_tunnel: false,
        last_connected_at: None,
        kill_switch: false,
        push_dns: false,
        customer: String::new(),
        config: ProfileConfig::AzureVpn(cfg),
        updated_at: chrono::Utc::now(),
    };
    state
        .profile_store
        .save(profile)
        .await
        .map_err(|e| RpcError::Other(format!("persist profile: {e}")))?;
    Ok(Value::String(profile_id.to_string()))
}

/// Import a FortiGate SSL VPN profile. Stores the user's password in
/// Credential Manager under `supermgr/fc/<id>/password`, then writes
/// the TOML profile to disk. The optional `dns_servers` / `routes` /
/// `trusted_cert` fields are JSON-encoded strings on the wire so the
/// pipe contract stays a flat string-keyed map.
async fn handle_import_forticlient_sslvpn(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    use supermgr_core::vpn::profile::{ForticlientSslvpnConfig, Profile, ProfileConfig, SecretRef};

    let name = arg_str(args, "name")?.trim();
    if name.is_empty() {
        return Err(RpcError::Other("profile name must not be empty".into()));
    }
    let host = arg_str(args, "host")?;
    let port = args.get("port").and_then(Value::as_u64).unwrap_or(443) as u16;
    let username = arg_str(args, "username")?;
    let password = arg_str(args, "password")?;
    let trusted_cert = args
        .get("trusted_cert")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let dns_servers_json = args
        .get("dns_servers_json")
        .and_then(Value::as_str)
        .unwrap_or("[]");
    let routes_json = args
        .get("routes_json")
        .and_then(Value::as_str)
        .unwrap_or("[]");

    let dns_servers: Vec<std::net::IpAddr> = serde_json::from_str(dns_servers_json)
        .map_err(|e| RpcError::Other(format!("parse dns_servers_json: {e}")))?;
    let routes: Vec<ipnet::IpNet> = serde_json::from_str(routes_json)
        .map_err(|e| RpcError::Other(format!("parse routes_json: {e}")))?;

    let profile_id = uuid::Uuid::new_v4();
    let secret_label = format!("supermgr/fc/{}/password", profile_id.simple());
    state
        .secret_store
        .store(&secret_label, password.as_bytes())
        .await
        .map_err(|e| RpcError::Secret(format!("store FortiClient password: {e}")))?;

    let cfg = ForticlientSslvpnConfig {
        host: host.to_owned(),
        port,
        username: username.to_owned(),
        password: SecretRef::new(secret_label),
        trusted_cert,
        dns_servers,
        routes,
    };
    let profile = Profile {
        id: profile_id,
        name: name.to_owned(),
        auto_connect: false,
        full_tunnel: true,
        last_connected_at: None,
        kill_switch: false,
        push_dns: false,
        customer: String::new(),
        config: ProfileConfig::ForticlientSslvpn(cfg),
        updated_at: chrono::Utc::now(),
    };

    state
        .profile_store
        .save(profile)
        .await
        .map_err(|e| RpcError::Other(format!("persist profile: {e}")))?;
    Ok(Value::String(profile_id.to_string()))
}

/// Import a FortiGate IKEv2 IPsec profile. Stores the EAP password (and a
/// PSK, if one is given) in Credential Manager, persists a
/// `FortiGateConfig` profile that the FortiGateBackend then dials via
/// Windows RAS (`Add-VpnConnection` + `rasdial`) — no third-party client
/// needed on a standards-compliant FortiGate deployment (EAP-MSCHAPv2).
///
/// The PSK is optional here: Windows' IKEv2 client authenticates with EAP
/// and never uses it. It is kept when supplied so the same profile still
/// works if it is exported to the Linux daemon, whose strongSwan path
/// does. Demanding it made operators invent one to get past the form.
async fn handle_import_fortigate(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    use supermgr_core::vpn::profile::{FortiGateConfig, Profile, ProfileConfig, SecretRef};

    let name = arg_str(args, "name")?.trim();
    if name.is_empty() {
        return Err(RpcError::Other("profile name must not be empty".into()));
    }
    let host = arg_str(args, "host")?;
    let username = arg_str(args, "username")?;
    let password = arg_str(args, "password")?;
    let psk = args.get("psk").and_then(Value::as_str).unwrap_or("");

    let profile_id = uuid::Uuid::new_v4();
    let pw_label = format!("supermgr/fg/{}/password", profile_id.simple());
    let psk_label = format!("supermgr/fg/{}/psk", profile_id.simple());

    state
        .secret_store
        .store(&pw_label, password.as_bytes())
        .await
        .map_err(|e| RpcError::Secret(format!("store FortiGate password: {e}")))?;
    if !psk.is_empty() {
        state
            .secret_store
            .store(&psk_label, psk.as_bytes())
            .await
            .map_err(|e| RpcError::Secret(format!("store FortiGate PSK: {e}")))?;
    }

    let cfg = FortiGateConfig {
        host: host.to_owned(),
        username: username.to_owned(),
        password: SecretRef::new(pw_label),
        psk: SecretRef::new(psk_label),
        dns_servers: Vec::new(),
        routes: Vec::new(),
        local_id: String::new(),
    };
    let profile = Profile {
        id: profile_id,
        name: name.to_owned(),
        auto_connect: false,
        full_tunnel: true,
        last_connected_at: None,
        kill_switch: false,
        push_dns: false,
        customer: String::new(),
        config: ProfileConfig::FortiGate(cfg),
        updated_at: chrono::Utc::now(),
    };
    state
        .profile_store
        .save(profile)
        .await
        .map_err(|e| RpcError::Other(format!("persist profile: {e}")))?;
    Ok(Value::String(profile_id.to_string()))
}

// ---------------------------------------------------------------------------
// SSH-key handlers — partial, real implementation.
//
// Key metadata (id, fingerprint, name, tags, created_at) lives on disk
// under `%PROGRAMDATA%\SuperManager\keys\<uuid>.toml`. Private key material
// goes into Credential Manager via `DaemonState::secret_store`.
// ---------------------------------------------------------------------------

async fn handle_ssh_generate_key(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    use ssh_key::private::{KeypairData, RsaKeypair};
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    let key_type = arg_str(args, "key_type")?;
    let name = arg_str(args, "name")?;
    let description = args
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let tags_json = args
        .get("tags_json")
        .and_then(Value::as_str)
        .unwrap_or("[]");

    // ssh-key's own OsRng (rand_core 0.6), not rand 0.9's — same reason as
    // supermgr-core::ssh::keygen: ssh-key's `random` requires rand_core 0.6's
    // CryptoRng, which rand 0.9's OsRng doesn't implement.
    let mut rng = ssh_key::rand_core::OsRng;

    // Mirror the existing Linux daemon's generator (see supermgrd/src/ssh/keygen.rs)
    // so the on-disk artefacts produced on Windows are bit-for-bit compatible
    // with the Linux/macOS apps. Heavy keygen (RSA-4096 takes ~1s) runs on a
    // blocking thread so we don't park the async runtime.
    let key_type_owned = key_type.to_owned();
    let name_owned = name.to_owned();
    let generated =
        tokio::task::spawn_blocking(move || -> Result<(String, String, String), RpcError> {
            let private = match key_type_owned.to_ascii_lowercase().as_str() {
                "ed25519" => {
                    let mut pk = PrivateKey::random(&mut rng, Algorithm::Ed25519)
                        .map_err(|e| RpcError::Other(format!("ed25519 keygen: {e}")))?;
                    if !name_owned.is_empty() {
                        pk.set_comment(&name_owned);
                    }
                    pk
                }
                "rsa" | "rsa4096" | "rsa-4096" => {
                    let kp = RsaKeypair::random(&mut rng, 4096)
                        .map_err(|e| RpcError::Other(format!("rsa-4096 keygen: {e}")))?;
                    PrivateKey::new(KeypairData::from(kp), &name_owned)
                        .map_err(|e| RpcError::Other(format!("rsa-4096 wrap: {e}")))?
                }
                "rsa2048" | "rsa-2048" => {
                    let kp = RsaKeypair::random(&mut rng, 2048)
                        .map_err(|e| RpcError::Other(format!("rsa-2048 keygen: {e}")))?;
                    PrivateKey::new(KeypairData::from(kp), &name_owned)
                        .map_err(|e| RpcError::Other(format!("rsa-2048 wrap: {e}")))?
                }
                other => {
                    return Err(RpcError::Other(format!(
                        "unsupported key_type {other:?} (supported: ed25519, rsa2048, rsa4096)"
                    )));
                }
            };
            let public_openssh = private
                .public_key()
                .to_openssh()
                .map_err(|e| RpcError::Other(format!("public openssh encode: {e}")))?;
            let fingerprint = private
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string();
            let private_pem = private
                .to_openssh(LineEnding::LF)
                .map_err(|e| RpcError::Other(format!("private openssh encode: {e}")))?
                .to_string();
            Ok((public_openssh, fingerprint, private_pem))
        })
        .await
        .map_err(|e| RpcError::Other(format!("keygen spawn_blocking: {e}")))??;

    let (public_openssh, fingerprint, private_pem) = generated;
    let key_id = uuid::Uuid::new_v4().to_string();

    let now = chrono::Utc::now().to_rfc3339();
    let meta = json!({
        "id": key_id,
        "name": name,
        "description": description,
        "key_type": key_type,
        "fingerprint": fingerprint,
        "public_key": public_openssh,
        "tags": serde_json::from_str::<Value>(tags_json).unwrap_or(json!([])),
        "created_at": now,
    });
    let path = state.root.join("keys").join(format!("{key_id}.json"));
    std::fs::write(&path, meta.to_string())
        .map_err(|e| RpcError::Other(format!("write key metadata: {e}")))?;

    let label = format!("supermgr/ssh/{key_id}/privkey");
    state
        .secret_store
        .store(&label, private_pem.as_bytes())
        .await
        .map_err(|e| RpcError::Secret(e.to_string()))?;

    Ok(Value::String(meta.to_string()))
}

async fn handle_ssh_list_keys(state: &Arc<DaemonState>) -> Result<Value, RpcError> {
    let dir = state.root.join("keys");
    let mut out: Vec<Value> = Vec::new();
    let entries =
        std::fs::read_dir(&dir).map_err(|e| RpcError::Other(format!("read keys dir: {e}")))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                warn!("read {}: {e}", path.display());
                continue;
            }
        };
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
            out.push(v);
        }
    }
    Ok(Value::String(Value::Array(out).to_string()))
}

async fn handle_ssh_delete_key(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let key_id = arg_id(args, "key_id")?;
    let path = state.root.join("keys").join(format!("{key_id}.json"));
    if !path.exists() {
        return Err(RpcError::NotFound(format!("ssh key {key_id}")));
    }

    // Take the label from the record's own `private_key_ref`, not from a
    // rebuilt `supermgr/ssh/<id>/privkey`. An imported key keeps whatever
    // label it was stored under, so the guessed form missed it entirely and
    // the PEM stayed in Credential Manager.
    let key: Option<supermgr_core::ssh::key::SshKey> = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());

    std::fs::remove_file(&path)
        .map_err(|e| RpcError::Other(format!("delete key metadata: {e}")))?;

    if let Some(key) = key {
        clear_owned_secrets(state, &key, &format!("ssh key {key_id}")).await;
    } else {
        // Unreadable record: fall back to the conventional label rather
        // than leaving a private key behind for certain.
        warn!("ssh key {key_id}: record unreadable, trying the default label");
        let _ = state
            .secret_store
            .delete(&format!("supermgr/ssh/{key_id}/privkey"))
            .await;
    }
    Ok(Value::Null)
}

async fn handle_ssh_export_public_key(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let key_id = arg_id(args, "key_id")?;
    let path = state.root.join("keys").join(format!("{key_id}.json"));
    let bytes =
        std::fs::read(&path).map_err(|_| RpcError::NotFound(format!("ssh key {key_id}")))?;
    let meta: Value = serde_json::from_slice(&bytes)
        .map_err(|e| RpcError::Other(format!("parse key metadata: {e}")))?;
    let public = meta
        .get("public_key")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("missing public_key field".into()))?;
    Ok(Value::String(public.to_owned()))
}

// ---------------------------------------------------------------------------
// Host handlers — partial, on-disk JSON store.
// ---------------------------------------------------------------------------

async fn handle_list_hosts(state: &Arc<DaemonState>) -> Result<Value, RpcError> {
    let dir = state.root.join("hosts");
    let mut out: Vec<Value> = Vec::new();
    let entries =
        std::fs::read_dir(&dir).map_err(|e| RpcError::Other(format!("read hosts dir: {e}")))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                out.push(v);
            }
        }
    }
    Ok(Value::String(Value::Array(out).to_string()))
}

async fn handle_get_host(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let path = state.root.join("hosts").join(format!("{host_id}.json"));
    let bytes = std::fs::read(&path).map_err(|_| RpcError::NotFound(format!("host {host_id}")))?;
    let v: Value =
        serde_json::from_slice(&bytes).map_err(|e| RpcError::Other(format!("parse host: {e}")))?;
    Ok(Value::String(v.to_string()))
}

async fn handle_add_host(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_json = arg_str(args, "host_json")?;
    let mut value: Value = serde_json::from_str(host_json)
        .map_err(|e| RpcError::Other(format!("parse host_json: {e}")))?;
    let id = uuid::Uuid::new_v4().to_string();
    if let Some(obj) = value.as_object_mut() {
        obj.insert("id".into(), Value::String(id.clone()));
        obj.insert(
            "created_at".into(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );
    } else {
        return Err(RpcError::Other("host_json must be an object".into()));
    }
    let path = state.root.join("hosts").join(format!("{id}.json"));
    std::fs::write(&path, value.to_string())
        .map_err(|e| RpcError::Other(format!("write host: {e}")))?;
    Ok(Value::String(id))
}

async fn handle_delete_host(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let path = state.root.join("hosts").join(format!("{host_id}.json"));
    if !path.exists() {
        return Err(RpcError::NotFound(format!("host {host_id}")));
    }

    // Parse before unlinking: the record is the only thing that knows which
    // credentials this host owns, and deleting the file used to be the whole
    // operation — leaving the SSH password, the OpenSSH certificate, the
    // firewall API token and the UniFi credentials in Credential Manager
    // with nothing left pointing at them.
    //
    // A record that will not parse still gets deleted. Refusing would leave
    // the operator unable to remove a host at all, and the credentials are
    // no more reachable either way — but say so, because they are the ones
    // this cannot clean up.
    let host: Option<supermgr_core::host::Host> = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    if host.is_none() {
        warn!("host {host_id}: record unreadable, deleting it without clearing its credentials");
    }

    std::fs::remove_file(&path).map_err(|e| RpcError::Other(format!("delete host: {e}")))?;

    if let Some(host) = host {
        clear_owned_secrets(state, &host, &format!("host {host_id}")).await;
    }
    Ok(Value::Null)
}

async fn handle_ssh_execute_command(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let command = arg_str(args, "command")?;
    let result = ssh_exec::execute(
        &state.root,
        state.secret_store.clone(),
        state.known_hosts.clone(),
        host_id,
        command,
    )
    .await?;
    Ok(Value::String(result.to_string()))
}

/// Connect to the host and sign in, without running anything. Same result
/// shape as the Linux daemon: `{"ssh": "ok" | "auth_failed" | …}`.
async fn handle_test_host_connection(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let result = ssh_exec::test(
        &state.root,
        state.secret_store.clone(),
        state.known_hosts.clone(),
        host_id,
    )
    .await;
    Ok(Value::String(result.to_string()))
}

/// The SSH host keys on file, as `{"host:port": "SHA256:…"}` — the Linux
/// daemon's shape.
async fn handle_ssh_list_known_hosts(state: &Arc<DaemonState>) -> Result<Value, RpcError> {
    let entries: serde_json::Map<String, Value> = state
        .known_hosts
        .entries()
        .await
        .into_iter()
        .map(|(address, known)| (address, Value::String(known.fingerprint)))
        .collect();
    Ok(Value::String(Value::Object(entries).to_string()))
}

/// Drop the key on file for `hostname:port`, so the next connection records
/// the key the host presents then. Returns whether there was one.
///
/// The way back from a changed key the operator has checked — a
/// reinstalled server, a replaced appliance, a deliberate rotation — and
/// the Linux daemon's method of the same name.
async fn handle_ssh_forget_host_key(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let hostname = arg_str(args, "hostname")?;
    let port = u16::try_from(arg_u64(args, "port")?)
        .map_err(|_| RpcError::Protocol("port must be from 0 to 65535".into()))?;
    let removed = state
        .known_hosts
        .forget(hostname, port)
        .await
        .map_err(|e| RpcError::Backend(format!("could not update the known-hosts file: {e}")))?;
    if removed {
        info!("forgot the SSH host key of {hostname}:{port} on request");
    }
    Ok(Value::Bool(removed))
}

/// Trust exactly the key given for `hostname:port` from now on, in place of
/// the one on file.
///
/// What the GUI's "Trust the new key" sends once the operator has compared
/// the key a changed host presented with the host's own. Where
/// `ssh_forget_host_key` trusts whichever key answers next, this trusts
/// the key they checked and nothing else. The fingerprint is the one
/// `test_host_connection` reported, with or without OpenSSH's `SHA256:`.
async fn handle_ssh_trust_host_key(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let hostname = arg_str(args, "hostname")?;
    let port = u16::try_from(arg_u64(args, "port")?)
        .map_err(|_| RpcError::Protocol("port must be from 0 to 65535".into()))?;
    let algorithm = arg_str(args, "algorithm")?;
    let fingerprint = arg_str(args, "fingerprint")?;
    let fingerprint = fingerprint.strip_prefix("SHA256:").unwrap_or(fingerprint);
    if !known_hosts::is_sha256_fingerprint(fingerprint) {
        return Err(RpcError::Protocol(format!(
            "{fingerprint:?} is not a SHA-256 host-key fingerprint"
        )));
    }
    let algorithm_ok = !algorithm.is_empty()
        && algorithm.len() <= 64
        && algorithm
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-@.".contains(&b));
    if !algorithm_ok {
        return Err(RpcError::Protocol(format!(
            "{algorithm:?} is not an SSH key algorithm"
        )));
    }
    state
        .known_hosts
        .trust(hostname, port, algorithm, fingerprint)
        .await
        .map_err(|e| RpcError::Backend(format!("could not update the known-hosts file: {e}")))?;
    info!("trusted SSH host key SHA256:{fingerprint} for {hostname}:{port} on request");
    Ok(Value::Null)
}

async fn handle_toggle_host_pin(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let path = state.root.join("hosts").join(format!("{host_id}.json"));
    let bytes = std::fs::read(&path).map_err(|_| RpcError::NotFound(format!("host {host_id}")))?;
    let mut v: Value =
        serde_json::from_slice(&bytes).map_err(|e| RpcError::Other(format!("parse host: {e}")))?;
    let new_state = !v.get("pinned").and_then(Value::as_bool).unwrap_or(false);
    if let Some(obj) = v.as_object_mut() {
        obj.insert("pinned".into(), Value::Bool(new_state));
    }
    std::fs::write(&path, v.to_string())
        .map_err(|e| RpcError::Other(format!("write host: {e}")))?;
    Ok(Value::String(
        json!({ "host_id": host_id, "pinned": new_state }).to_string(),
    ))
}

async fn handle_ssh_set_password(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let password = arg_str(args, "password")?;
    let label = format!("supermgr/host/{host_id}/password");
    state
        .secret_store
        .store(&label, password.as_bytes())
        .await
        .map_err(|e| RpcError::Secret(e.to_string()))?;
    Ok(Value::Null)
}

async fn handle_ssh_set_api_token(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let token = arg_str(args, "token")?;
    let port = arg_u64(args, "port")? as u16;
    let label = format!("supermgr/host/{host_id}/api-token");
    state
        .secret_store
        .store(&label, token.as_bytes())
        .await
        .map_err(|e| RpcError::Secret(e.to_string()))?;
    // Persist the port alongside the host metadata so subsequent calls
    // know where to hit the appliance.
    let host_path = state.root.join("hosts").join(format!("{host_id}.json"));
    if let Ok(bytes) = std::fs::read(&host_path) {
        if let Ok(mut v) = serde_json::from_slice::<Value>(&bytes) {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("api_port".into(), Value::Number(port.into()));
            }
            let _ = std::fs::write(&host_path, v.to_string());
        }
    }
    Ok(Value::Null)
}

// ---------------------------------------------------------------------------
// Appliance APIs (FortiGate REST, UniFi REST, UniFi set-inform).
//
// Thin wrappers that pull arguments out of the JSON args object and
// hand them to `crate::win::appliance`. The dispatcher stays declarative
// while the HTTP/SSH plumbing lives in `appliance.rs`.
// ---------------------------------------------------------------------------

async fn handle_fortigate_api(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let method = arg_str(args, "method")?;
    let path = arg_str(args, "path")?;
    let body = args.get("body").and_then(Value::as_str).unwrap_or("");
    let resp = appliance::fortigate_api(
        &state.root,
        state.secret_store.clone(),
        host_id,
        method,
        path,
        body,
    )
    .await?;
    Ok(Value::String(resp))
}

async fn handle_fortigate_push_ssh_key(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let key_id = arg_id(args, "key_id")?;
    let admin_user = arg_str(args, "admin_user")?;
    let resp = appliance::fortigate_push_ssh_key(
        &state.root,
        state.secret_store.clone(),
        host_id,
        key_id,
        admin_user,
    )
    .await?;
    Ok(Value::String(resp))
}

async fn handle_fortigate_backup_config(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let filename =
        appliance::fortigate_backup_config(&state.root, state.secret_store.clone(), host_id)
            .await?;
    Ok(Value::String(filename))
}

async fn handle_unifi_api(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let method = arg_str(args, "method")?;
    let path = arg_str(args, "path")?;
    let body = args.get("body").and_then(Value::as_str).unwrap_or("");
    let resp = appliance::unifi_api(
        &state.root,
        state.secret_store.clone(),
        host_id,
        method,
        path,
        body,
    )
    .await?;
    Ok(Value::String(resp))
}

async fn handle_unifi_set_inform(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let inform_url = arg_str(args, "inform_url")?;
    let resp = appliance::unifi_set_inform(
        &state.root,
        state.secret_store.clone(),
        state.known_hosts.clone(),
        host_id,
        inform_url,
    )
    .await?;
    Ok(Value::String(resp))
}

async fn handle_opnsense_api(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let method = arg_str(args, "method")?;
    let path = arg_str(args, "path")?;
    let body = args.get("body").and_then(Value::as_str).unwrap_or("");
    let resp = appliance::opnsense_api(
        &state.root,
        state.secret_store.clone(),
        host_id,
        method,
        path,
        body,
    )
    .await?;
    Ok(Value::String(resp))
}

async fn handle_opnsense_backup_config(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let filename =
        appliance::opnsense_backup_config(&state.root, state.secret_store.clone(), host_id).await?;
    Ok(Value::String(filename))
}

async fn handle_sophos_xml_api(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_id = arg_id(args, "host_id")?;
    let inner_xml = arg_str(args, "inner_xml")?;
    let resp =
        appliance::sophos_xml_api(&state.root, state.secret_store.clone(), host_id, inner_xml)
            .await?;
    Ok(Value::String(resp))
}
