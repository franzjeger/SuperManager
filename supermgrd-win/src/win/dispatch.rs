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
use tracing::warn;

use supermgr_core::protocol::{PipeRequest, PipeResponse, RpcError, PROTOCOL_VERSION};

use super::daemon::DaemonState;
use super::{appliance, ssh_exec};

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
        "import_wireguard" => handle_import_wireguard(state, &req.args).await,
        "import_forticlient_sslvpn" => {
            handle_import_forticlient_sslvpn(state, &req.args).await
        }
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
// VPN handlers — stubs until the Windows VPN backends land. The trait and
// concrete WireGuard/OpenVPN/IKEv2/FortiGate implementations live under
// `crate::vpn`.
// ---------------------------------------------------------------------------

async fn handle_list_profiles(state: &Arc<DaemonState>) -> Result<Value, RpcError> {
    let summaries = state.profile_store.list_summaries().await;
    let json = serde_json::to_string(&summaries)
        .map_err(|e| RpcError::Other(format!("serialise profile summaries: {e}")))?;
    Ok(Value::String(json))
}

async fn handle_connect(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    use supermgr_core::vpn::profile::ProfileConfig;
    use super::vpn::VpnBackend as _;

    let profile_id_str = arg_str(args, "profile_id")?;
    let profile_id = uuid::Uuid::parse_str(profile_id_str)
        .map_err(|e| RpcError::Other(format!("invalid profile_id uuid: {e}")))?;
    let profile = state
        .profile_store
        .get(profile_id)
        .await
        .map_err(|_| RpcError::NotFound(format!("profile {profile_id}")))?;

    let profile_json = serde_json::to_string(&profile)
        .map_err(|e| RpcError::Other(format!("serialise profile: {e}")))?;

    match &profile.config {
        ProfileConfig::WireGuard(_) => state
            .vpn
            .wireguard
            .connect(&profile_json)
            .await
            .map_err(map_vpn_err)?,
        ProfileConfig::OpenVpn(_) => state
            .vpn
            .openvpn
            .connect(&profile_json)
            .await
            .map_err(map_vpn_err)?,
        ProfileConfig::AzureVpn(_) => state
            .vpn
            .ikev2
            .connect(&profile_json)
            .await
            .map_err(map_vpn_err)?,
        ProfileConfig::FortiGate(_) => state
            .vpn
            .fortigate
            .connect(&profile_json)
            .await
            .map_err(map_vpn_err)?,
        ProfileConfig::ForticlientSslvpn(_) => state
            .vpn
            .forticlient
            .connect(&profile_json)
            .await
            .map_err(map_vpn_err)?,
        ProfileConfig::Generic(_) => {
            return Err(RpcError::Backend(
                "Generic VPN profiles have no Windows backend".into(),
            ));
        }
    }
    Ok(json!({ "status": "connected", "profile_id": profile_id.to_string() }))
}

async fn handle_disconnect(state: &Arc<DaemonState>) -> Result<Value, RpcError> {
    use super::vpn::VpnBackend as _;

    // We know there is at most one tunnel up at a time, so we ask each
    // backend whether it's active and route the call to the matching
    // one. Cheaper than tracking "which backend is active" on the
    // daemon, and the dispatch surface stays trivial.
    if state.vpn.wireguard.is_active().await {
        return state
            .vpn
            .wireguard
            .disconnect()
            .await
            .map(|()| Value::Null)
            .map_err(map_vpn_err);
    }
    if state.vpn.openvpn.is_active().await {
        return state
            .vpn
            .openvpn
            .disconnect()
            .await
            .map(|()| Value::Null)
            .map_err(map_vpn_err);
    }
    if state.vpn.fortigate.is_active().await {
        return state
            .vpn
            .fortigate
            .disconnect()
            .await
            .map(|()| Value::Null)
            .map_err(map_vpn_err);
    }
    if state.vpn.ikev2.is_active().await {
        return state
            .vpn
            .ikev2
            .disconnect()
            .await
            .map(|()| Value::Null)
            .map_err(map_vpn_err);
    }
    if state.vpn.forticlient.is_active().await {
        return state
            .vpn
            .forticlient
            .disconnect()
            .await
            .map(|()| Value::Null)
            .map_err(map_vpn_err);
    }
    Ok(Value::Null)
}

async fn handle_get_status(state: &Arc<DaemonState>) -> Result<Value, RpcError> {
    use super::vpn::VpnBackend as _;

    // Return the status of whichever backend is currently active.
    // Fall back to WireGuard's "Disconnected" status when nothing is up
    // so the GUI gets a well-formed JSON either way.
    if state.vpn.wireguard.is_active().await {
        return state
            .vpn
            .wireguard
            .status()
            .await
            .map(Value::String)
            .map_err(map_vpn_err);
    }
    if state.vpn.openvpn.is_active().await {
        return state
            .vpn
            .openvpn
            .status()
            .await
            .map(Value::String)
            .map_err(map_vpn_err);
    }
    if state.vpn.fortigate.is_active().await {
        return state
            .vpn
            .fortigate
            .status()
            .await
            .map(Value::String)
            .map_err(map_vpn_err);
    }
    if state.vpn.ikev2.is_active().await {
        return state
            .vpn
            .ikev2
            .status()
            .await
            .map(Value::String)
            .map_err(map_vpn_err);
    }
    if state.vpn.forticlient.is_active().await {
        return state
            .vpn
            .forticlient
            .status()
            .await
            .map(Value::String)
            .map_err(map_vpn_err);
    }
    let wg = state
        .vpn
        .wireguard
        .status()
        .await
        .map_err(map_vpn_err)?;
    Ok(Value::String(wg))
}

/// Map a [`super::vpn::VpnError`] to the transport's [`RpcError`] taxonomy.
fn map_vpn_err(e: super::vpn::VpnError) -> RpcError {
    use super::vpn::VpnError;
    match e {
        VpnError::NotImplemented(what) => {
            RpcError::Backend(format!("not implemented on Windows: {what}"))
        }
        VpnError::MissingDependency(msg) => RpcError::Backend(format!("missing dependency: {msg}")),
        VpnError::Win32(msg) => RpcError::Backend(format!("win32: {msg}")),
        VpnError::Subprocess { code, stderr } => {
            RpcError::Backend(format!("subprocess exited {code}: {stderr}"))
        }
        VpnError::PermissionDenied(msg) => RpcError::PermissionDenied(msg.to_owned()),
        VpnError::Io(e) => RpcError::Backend(format!("io: {e}")),
    }
}

async fn handle_delete_profile(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let id_str = arg_str(args, "profile_id")?;
    let id = uuid::Uuid::parse_str(id_str)
        .map_err(|e| RpcError::Other(format!("invalid profile_id uuid: {e}")))?;
    state
        .profile_store
        .delete(id)
        .await
        .map_err(|e| match e {
            super::profile_store::StoreError::NotFound(_) => {
                RpcError::NotFound(format!("profile {id}"))
            }
            other => RpcError::Other(other.to_string()),
        })?;
    Ok(Value::Null)
}

/// Parse a wg-quick `.conf` text, persist the private key + any PSKs to
/// Credential Manager, save the profile TOML, and return the new
/// profile's UUID. Mirrors the Linux daemon's `import_wireguard` method
/// so the GUI and MCP server can use the same call on both OSes.
async fn handle_import_wireguard(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    use supermgr_core::vpn::profile::{
        import_wireguard_conf, Profile, ProfileConfig,
    };

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
    use supermgr_core::vpn::profile::{
        ForticlientSslvpnConfig, Profile, ProfileConfig, SecretRef,
    };

    let name = arg_str(args, "name")?.trim();
    if name.is_empty() {
        return Err(RpcError::Other("profile name must not be empty".into()));
    }
    let host = arg_str(args, "host")?;
    let port = args
        .get("port")
        .and_then(Value::as_u64)
        .unwrap_or(443) as u16;
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
    let routes_json = args.get("routes_json").and_then(Value::as_str).unwrap_or("[]");

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

/// Import a FortiGate IKEv2 IPsec profile. Stores the EAP password + group
/// PSK in Credential Manager, persists a `FortiGateConfig` profile that
/// the FortiGateBackend then dials via Windows RAS (`Add-VpnConnection`
/// + `rasdial`) — no third-party client needed on a standards-compliant
/// FortiGate deployment (EAP-MSCHAPv2 + PSK).
async fn handle_import_fortigate(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    use supermgr_core::vpn::profile::{FortiGateConfig, Profile, ProfileConfig, SecretRef};

    let name = arg_str(args, "name")?.trim();
    if name.is_empty() {
        return Err(RpcError::Other("profile name must not be empty".into()));
    }
    let host = arg_str(args, "host")?;
    let username = arg_str(args, "username")?;
    let password = arg_str(args, "password")?;
    let psk = arg_str(args, "psk")?;

    let profile_id = uuid::Uuid::new_v4();
    let pw_label = format!("supermgr/fg/{}/password", profile_id.simple());
    let psk_label = format!("supermgr/fg/{}/psk", profile_id.simple());

    state
        .secret_store
        .store(&pw_label, password.as_bytes())
        .await
        .map_err(|e| RpcError::Secret(format!("store FortiGate password: {e}")))?;
    state
        .secret_store
        .store(&psk_label, psk.as_bytes())
        .await
        .map_err(|e| RpcError::Secret(format!("store FortiGate PSK: {e}")))?;

    let cfg = FortiGateConfig {
        host: host.to_owned(),
        username: username.to_owned(),
        password: SecretRef::new(pw_label),
        psk: SecretRef::new(psk_label),
        dns_servers: Vec::new(),
        routes: Vec::new(),
    };
    let profile = Profile {
        id: profile_id,
        name: name.to_owned(),
        auto_connect: false,
        full_tunnel: true,
        last_connected_at: None,
        kill_switch: false,
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

async fn handle_ssh_generate_key(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    use ssh_key::private::{KeypairData, RsaKeypair};
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    let key_type = arg_str(args, "key_type")?;
    let name = arg_str(args, "name")?;
    let description = args.get("description").and_then(Value::as_str).unwrap_or("");
    let tags_json = args.get("tags_json").and_then(Value::as_str).unwrap_or("[]");

    let mut rng = rand::rngs::OsRng;

    // Mirror the existing Linux daemon's generator (see supermgrd/src/ssh/keygen.rs)
    // so the on-disk artefacts produced on Windows are bit-for-bit compatible
    // with the Linux/macOS apps. Heavy keygen (RSA-4096 takes ~1s) runs on a
    // blocking thread so we don't park the async runtime.
    let key_type_owned = key_type.to_owned();
    let name_owned = name.to_owned();
    let generated = tokio::task::spawn_blocking(move || -> Result<(String, String, String), RpcError> {
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
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| RpcError::Other(format!("read keys dir: {e}")))?;
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
    let key_id = arg_str(args, "key_id")?;
    let path = state.root.join("keys").join(format!("{key_id}.json"));
    if !path.exists() {
        return Err(RpcError::NotFound(format!("ssh key {key_id}")));
    }
    std::fs::remove_file(&path)
        .map_err(|e| RpcError::Other(format!("delete key metadata: {e}")))?;
    let label = format!("supermgr/ssh/{key_id}/privkey");
    // Best-effort: the secret may have been deleted manually; don't fail the
    // whole operation if it's missing.
    let _ = state.secret_store.delete(&label).await;
    Ok(Value::Null)
}

async fn handle_ssh_export_public_key(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let key_id = arg_str(args, "key_id")?;
    let path = state.root.join("keys").join(format!("{key_id}.json"));
    let bytes = std::fs::read(&path)
        .map_err(|_| RpcError::NotFound(format!("ssh key {key_id}")))?;
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
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| RpcError::Other(format!("read hosts dir: {e}")))?;
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
    let host_id = arg_str(args, "host_id")?;
    let path = state.root.join("hosts").join(format!("{host_id}.json"));
    let bytes = std::fs::read(&path)
        .map_err(|_| RpcError::NotFound(format!("host {host_id}")))?;
    let v: Value = serde_json::from_slice(&bytes)
        .map_err(|e| RpcError::Other(format!("parse host: {e}")))?;
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
    let host_id = arg_str(args, "host_id")?;
    let path = state.root.join("hosts").join(format!("{host_id}.json"));
    if !path.exists() {
        return Err(RpcError::NotFound(format!("host {host_id}")));
    }
    std::fs::remove_file(&path)
        .map_err(|e| RpcError::Other(format!("delete host: {e}")))?;
    Ok(Value::Null)
}

async fn handle_ssh_execute_command(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_str(args, "host_id")?;
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

async fn handle_test_host_connection(
    _state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let _ = arg_str(args, "host_id")?;
    Ok(Value::String(
        json!({ "reachable": false, "reason": "not implemented yet on Windows" }).to_string(),
    ))
}

async fn handle_toggle_host_pin(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_id = arg_str(args, "host_id")?;
    let path = state.root.join("hosts").join(format!("{host_id}.json"));
    let bytes = std::fs::read(&path)
        .map_err(|_| RpcError::NotFound(format!("host {host_id}")))?;
    let mut v: Value = serde_json::from_slice(&bytes)
        .map_err(|e| RpcError::Other(format!("parse host: {e}")))?;
    let new_state = !v
        .get("pinned")
        .and_then(Value::as_bool)
        .unwrap_or(false);
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
    let host_id = arg_str(args, "host_id")?;
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
    let host_id = arg_str(args, "host_id")?;
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
    let host_id = arg_str(args, "host_id")?;
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
    let host_id = arg_str(args, "host_id")?;
    let key_id = arg_str(args, "key_id")?;
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
    let host_id = arg_str(args, "host_id")?;
    let filename = appliance::fortigate_backup_config(
        &state.root,
        state.secret_store.clone(),
        host_id,
    )
    .await?;
    Ok(Value::String(filename))
}

async fn handle_unifi_api(state: &Arc<DaemonState>, args: &Value) -> Result<Value, RpcError> {
    let host_id = arg_str(args, "host_id")?;
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
    let host_id = arg_str(args, "host_id")?;
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
    let host_id = arg_str(args, "host_id")?;
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
    let host_id = arg_str(args, "host_id")?;
    let filename = appliance::opnsense_backup_config(
        &state.root,
        state.secret_store.clone(),
        host_id,
    )
    .await?;
    Ok(Value::String(filename))
}

async fn handle_sophos_xml_api(
    state: &Arc<DaemonState>,
    args: &Value,
) -> Result<Value, RpcError> {
    let host_id = arg_str(args, "host_id")?;
    let inner_xml = arg_str(args, "inner_xml")?;
    let resp = appliance::sophos_xml_api(
        &state.root,
        state.secret_store.clone(),
        host_id,
        inner_xml,
    )
    .await?;
    Ok(Value::String(resp))
}
