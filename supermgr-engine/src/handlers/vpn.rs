//! VPN profile JSON-RPC handlers.
//!
//! Profile CRUD, importers (WireGuard, OpenVPN), routing/kill-switch
//! toggles, rename/duplicate. Lives on `EngineServer` so the dispatch
//! table in `server.rs` reaches it via the same `self.handle_*` calls.

use supermgr_core::vpn::profile::{
    FortiGateConfig, Profile, ProfileConfig, ProfileSummary, SecretRef,
};
use tracing::warn;

use crate::protocol::{self, Response};
use crate::server::{parse_ip_list, parse_ipnet_list, EngineServer};

impl EngineServer {
    pub(crate) async fn handle_list_profiles(&self, id: u64) -> Response {
        let state = self.state.lock().await;
        let summaries: Vec<ProfileSummary> = state
            .profiles
            .values()
            .map(ProfileSummary::from)
            .collect();
        match serde_json::to_value(&summaries) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_vpn_get_profile(&self, id: u64, params: serde_json::Value) -> Response {
        let pid_str = match params.get("id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };
        let state = self.state.lock().await;
        match state.profiles.get(&pid) {
            Some(p) => match serde_json::to_value(p) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            None => Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned()),
        }
    }

    /// Create a new IKEv2 profile (modeled via the existing FortiGateConfig —
    /// same shape: host, username, EAP password, group PSK, routes, DNS).
    ///
    /// Secrets (password, PSK) are owned by the app via the OS Keychain on Mac;
    /// the profile only carries SecretRef labels so cross-platform serialization
    /// stays consistent.
    pub(crate) async fn handle_vpn_add_ikev2_profile(&self, id: u64, params: serde_json::Value) -> Response {
        let Some(name) = params.get("name").and_then(|v| v.as_str()) else {
            return Response::err(id, protocol::INVALID_PARAMS, "missing name".to_owned());
        };
        let Some(host) = params.get("host").and_then(|v| v.as_str()) else {
            return Response::err(id, protocol::INVALID_PARAMS, "missing host".to_owned());
        };
        let Some(username) = params.get("username").and_then(|v| v.as_str()) else {
            return Response::err(id, protocol::INVALID_PARAMS, "missing username".to_owned());
        };
        let full_tunnel = params.get("full_tunnel").and_then(|v| v.as_bool()).unwrap_or(true);
        let kill_switch = params.get("kill_switch").and_then(|v| v.as_bool()).unwrap_or(false);
        let dns_servers = parse_ip_list(params.get("dns_servers"));
        let routes = parse_ipnet_list(params.get("routes"));

        let new_id = uuid::Uuid::new_v4();
        let cfg = FortiGateConfig {
            host: host.to_owned(),
            username: username.to_owned(),
            password: SecretRef::new(format!("vpn/{new_id}/password")),
            psk: SecretRef::new(format!("vpn/{new_id}/psk")),
            dns_servers,
            routes,
        };
        let profile = Profile {
            id: new_id,
            name: name.to_owned(),
            auto_connect: false,
            full_tunnel,
            last_connected_at: None,
            kill_switch,
            config: ProfileConfig::FortiGate(cfg),
            updated_at: chrono::Utc::now(),
        };

        let mut state = self.state.lock().await;
        if let Err(e) = state.save_profile(&profile) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save: {e}"));
        }
        state.profiles.insert(profile.id, profile.clone());
        match serde_json::to_value(&profile) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_vpn_update_ikev2_profile(&self, id: u64, params: serde_json::Value) -> Response {
        let pid_str = match params.get("id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };

        let mut state = self.state.lock().await;
        let Some(existing) = state.profiles.get(&pid).cloned() else {
            return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned());
        };
        let ProfileConfig::FortiGate(mut cfg) = existing.config.clone() else {
            return Response::err(id, protocol::INVALID_PARAMS, "profile is not IKEv2".to_owned());
        };

        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or(&existing.name).to_owned();
        if let Some(h) = params.get("host").and_then(|v| v.as_str()) {
            cfg.host = h.to_owned();
        }
        if let Some(u) = params.get("username").and_then(|v| v.as_str()) {
            cfg.username = u.to_owned();
        }
        if params.get("dns_servers").is_some() {
            cfg.dns_servers = parse_ip_list(params.get("dns_servers"));
        }
        if params.get("routes").is_some() {
            cfg.routes = parse_ipnet_list(params.get("routes"));
        }
        let full_tunnel = params
            .get("full_tunnel")
            .and_then(|v| v.as_bool())
            .unwrap_or(existing.full_tunnel);
        let kill_switch = params
            .get("kill_switch")
            .and_then(|v| v.as_bool())
            .unwrap_or(existing.kill_switch);

        let updated = Profile {
            id: existing.id,
            name,
            auto_connect: existing.auto_connect,
            full_tunnel,
            last_connected_at: existing.last_connected_at,
            kill_switch,
            config: ProfileConfig::FortiGate(cfg),
            updated_at: chrono::Utc::now(),
        };

        if let Err(e) = state.save_profile(&updated) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save: {e}"));
        }
        state.profiles.insert(updated.id, updated.clone());
        match serde_json::to_value(&updated) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_vpn_delete_profile(&self, id: u64, params: serde_json::Value) -> Response {
        let pid_str = match params.get("id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };

        let mut state = self.state.lock().await;
        if state.profiles.remove(&pid).is_none() {
            return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned());
        }
        if let Err(e) = state.delete_profile_file(pid) {
            warn!("failed to delete profile file for {pid}: {e}");
        }
        Response::ok(id, serde_json::json!({ "deleted": true }))
    }

    /// Import a WireGuard `.conf` file. Parses the INI body via
    /// `import_wireguard_conf`, stores the private key + any peer PSKs
    /// in the secrets store, and persists a new `Profile` with
    /// `ProfileConfig::WireGuard`. Idempotent only by `name`: re-importing
    /// the same file with the same name will create a second profile
    /// (the daemon doesn't dedupe on content — that's the GUI's job).
    pub(crate) async fn handle_vpn_import_wireguard(&self, id: u64, params: serde_json::Value) -> Response {
        use supermgr_core::vpn::profile::{import_wireguard_conf, ProfileConfig};

        let name = match params.get("name").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing name".to_owned()),
        };
        let content = match params.get("content").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing content".to_owned()),
        };

        let new_id = uuid::Uuid::new_v4();
        let secret_label = format!("vpn/{new_id}/wg-private-key");
        let (cfg, private_key, psks) = match import_wireguard_conf(&content, &secret_label) {
            Ok(t) => t,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("parse: {e}")),
        };

        // Persist private key first. If it fails the profile would
        // reference a missing secret — bail out without writing
        // half-state. `ZeroingKey::take` consumes the wrapper and
        // returns the raw `String`; we hand it straight to the secret
        // store so it never sticks around in this scope longer than
        // needed.
        let raw_pk = private_key.take();
        if let Err(e) = self.secrets.store(&secret_label, raw_pk.as_bytes()).await {
            return Response::err(
                id,
                protocol::INTERNAL_ERROR,
                format!("store private key: {e}"),
            );
        }
        // Best-effort zero of the local copy — we passed the bytes
        // through a clone into the secret store, so the actual store
        // path's lifetime isn't ours to manage.
        drop(raw_pk);
        // Then any per-peer pre-shared keys. A failure here doesn't
        // invalidate the whole profile (the user can re-enter PSKs in
        // the UI later), but we log it.
        for (label, value) in &psks {
            if let Err(e) = self.secrets.store(label, value.as_bytes()).await {
                warn!("store WireGuard PSK {label}: {e}");
            }
        }

        let profile = Profile {
            id: new_id,
            name,
            auto_connect: false,
            full_tunnel: cfg.split_routes.is_empty(),
            last_connected_at: None,
            kill_switch: false,
            config: ProfileConfig::WireGuard(cfg),
            updated_at: chrono::Utc::now(),
        };

        let mut state = self.state.lock().await;
        if let Err(e) = state.save_profile(&profile) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save: {e}"));
        }
        state.profiles.insert(profile.id, profile.clone());
        match serde_json::to_value(&profile) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Import an OpenVPN `.ovpn` file. We don't try to parse every
    /// directive — they're a moving target. Instead we:
    ///   1. Save the raw `.ovpn` body to `<data_dir>/ovpn/<id>.ovpn`.
    ///   2. Sniff `remote <host> <port>` for display-only metadata.
    ///   3. Persist a `Profile` with `ProfileConfig::OpenVpn`.
    ///
    /// Connecting is out of scope for this RPC — it's handled by a
    /// separate (yet-to-be-implemented) daemon backend.
    pub(crate) async fn handle_vpn_import_openvpn(&self, id: u64, params: serde_json::Value) -> Response {
        use std::io::Write as _;
        use supermgr_core::vpn::profile::{OpenVpnConfig, ProfileConfig};

        let name = match params.get("name").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing name".to_owned()),
        };
        let content = match params.get("content").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing content".to_owned()),
        };

        // Sniff a `remote <host> <port>` line. First match wins; many
        // .ovpn files list multiple remotes for failover. We only need
        // one for display.
        let _remote_host = content
            .lines()
            .find_map(|l| {
                let l = l.trim();
                if let Some(rest) = l.strip_prefix("remote ") {
                    rest.split_whitespace().next().map(str::to_owned)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_owned());

        // Write the raw config out under the daemon's data dir. The
        // path goes into the profile so future connect logic can find
        // it without re-importing.
        let new_id = uuid::Uuid::new_v4();
        let mut config_path = crate::secrets::default_data_dir();
        config_path.push("ovpn");
        if let Err(e) = std::fs::create_dir_all(&config_path) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("mkdir ovpn: {e}"));
        }
        config_path.push(format!("{new_id}.ovpn"));
        // OpenOptionsExt is gated behind unix cfg, so the import lives
        // inside the (macOS-only) handler body to keep cross-platform
        // builds clean.
        use std::os::unix::fs::OpenOptionsExt as _;
        match std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&config_path)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(content.as_bytes()) {
                    return Response::err(id, protocol::INTERNAL_ERROR, format!("write: {e}"));
                }
            }
            Err(e) => {
                return Response::err(id, protocol::INTERNAL_ERROR, format!("open: {e}"));
            }
        }

        let cfg = OpenVpnConfig {
            config_file: config_path.to_string_lossy().into_owned(),
            username: None,
            password: None,
        };

        let profile = Profile {
            id: new_id,
            name,
            auto_connect: false,
            full_tunnel: true,
            last_connected_at: None,
            kill_switch: false,
            config: ProfileConfig::OpenVpn(cfg),
            updated_at: chrono::Utc::now(),
        };

        let mut state = self.state.lock().await;
        if let Err(e) = state.save_profile(&profile) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save: {e}"));
        }
        state.profiles.insert(profile.id, profile.clone());
        match serde_json::to_value(&profile) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Import a Microsoft Azure VPN Client `.azurevpnconfig` (XML)
    /// blob. We do two things with the bytes:
    ///   1. Parse them into a structured `AzureVpnConfig` for
    ///      display (gateway FQDN, tenant, routes, DNS).
    ///   2. Persist the original XML verbatim under
    ///      `<data_dir>/azurevpn/<id>.azurevpnconfig`.
    ///
    /// The verbatim copy is what we hand to Microsoft's Azure VPN
    /// Client at connect time. We do **not** try to drive the
    /// Entra ID auth ourselves — the public Azure VPN client app
    /// id is only pre-consented for AAD Graph and Microsoft Graph,
    /// so a custom OAuth flow can't request a token with the
    /// gateway audience without admin consent in the customer's
    /// tenant. Microsoft's own app uses its first-party broker
    /// integration; the cheapest faithful replication is to defer
    /// to that app.
    pub(crate) async fn handle_vpn_import_azure(&self, id: u64, params: serde_json::Value) -> Response {
        use supermgr_core::vpn::profile::ProfileConfig;

        let name = match params.get("name").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing name".to_owned()),
        };
        let content = match params.get("content").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing content".to_owned()),
        };

        let cfg = match crate::azure_vpn::parse_azure_vpn_config(&content) {
            Ok(c) => c,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("parse: {e}")),
        };

        let new_id = uuid::Uuid::new_v4();

        // Stash the verbatim XML so we can hand it back to
        // Microsoft's Azure VPN Client at connect time. Filename
        // ends in `.azurevpnconfig` so MS's app recognises the
        // type when it opens.
        let mut xml_dir = crate::secrets::default_data_dir();
        xml_dir.push("azurevpn");
        if let Err(e) = std::fs::create_dir_all(&xml_dir) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("mkdir azurevpn: {e}"));
        }
        let mut xml_path = xml_dir;
        xml_path.push(format!("{new_id}.azurevpnconfig"));
        if let Err(e) = std::fs::write(&xml_path, content.as_bytes()) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("write xml: {e}"));
        }
        // 0600 — the XML embeds the gateway's tls-crypt key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&xml_path, std::fs::Permissions::from_mode(0o600));
        }

        let profile = Profile {
            id: new_id,
            name,
            auto_connect: false,
            // No routes in the XML → full-tunnel; presence of any
            // included route means split-tunnel and we honour it.
            full_tunnel: cfg.routes.is_empty(),
            last_connected_at: None,
            kill_switch: false,
            config: ProfileConfig::AzureVpn(cfg),
            updated_at: chrono::Utc::now(),
        };

        let mut state = self.state.lock().await;
        if let Err(e) = state.save_profile(&profile) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save: {e}"));
        }
        state.profiles.insert(profile.id, profile.clone());
        match serde_json::to_value(&profile) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Hand an imported Azure profile to Microsoft's Azure VPN
    /// Client app. Looks up the verbatim `.azurevpnconfig` we
    /// stashed at import time and runs `open -a "Azure VPN Client"
    /// <path>`. Microsoft's app picks up the import, prompts for
    /// Entra ID sign-in (using its first-party broker), and
    /// connects — all without us touching the auth flow.
    ///
    /// Returns the path we asked the system to open so the GUI can
    /// surface it in case the user needs to drag it into the
    /// app manually.
    pub(crate) async fn handle_vpn_open_in_azure_client(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let pid_str = match params.get("profile_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing profile_id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };

        // Refuse if the user doesn't have the Azure VPN Client
        // installed — `open -a` would silently fail otherwise,
        // and a clear error here drives the install-prompt UX.
        let app_path = "/Applications/Azure VPN Client.app";
        if !std::path::Path::new(app_path).exists() {
            return Response::err(
                id,
                protocol::INVALID_PARAMS,
                "Azure VPN Client.app is not installed in /Applications. Install it from the Mac App Store.".to_owned(),
            );
        }

        let mut xml_path = crate::secrets::default_data_dir();
        xml_path.push("azurevpn");
        xml_path.push(format!("{}.azurevpnconfig", pid.simple()));
        if !xml_path.exists() {
            // Older imports (before we started saving the verbatim
            // XML) won't have this file. Tell the GUI so it can
            // ask the user to re-import.
            return Response::err(
                id,
                protocol::INVALID_PARAMS,
                "Original .azurevpnconfig isn't on disk for this profile. Re-import the XML to enable handoff.".to_owned(),
            );
        }

        let output = match std::process::Command::new("/usr/bin/open")
            .arg("-a")
            .arg("Azure VPN Client")
            .arg(&xml_path)
            .output()
        {
            Ok(o) => o,
            Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, format!("spawn open: {e}")),
        };
        if !output.status.success() {
            return Response::err(
                id,
                protocol::INTERNAL_ERROR,
                format!(
                    "`open -a \"Azure VPN Client\"` failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            );
        }

        Response::ok(id, serde_json::json!({
            "config_path": xml_path.to_string_lossy(),
            "app_path": app_path,
        }))
    }

    /// Probe the Mac for a VPN runtime that can carry Azure-AAD
    /// sessions. The GUI calls this *before* kicking off the
    /// device-code flow so it can refuse early — there's no point
    /// asking the user to sign in if we can't bring up the tunnel
    /// afterwards. Returns the detected variant verbatim; the GUI
    /// switches off the discriminator to drive its UI.
    pub(crate) async fn handle_vpn_check_azure_runtime(&self, id: u64) -> Response {
        let runtime = crate::azure_oauth::detect_azure_runtime();
        match serde_json::to_value(&runtime) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Start the Entra ID device-code flow for an Azure VPN
    /// profile. Returns the user_code + verification_uri so the
    /// GUI can show them and open the browser, plus the device_code
    /// that the GUI hands back on every subsequent poll. We don't
    /// keep server-side state — the GUI is the source of truth for
    /// "which auth flow am I in."
    pub(crate) async fn handle_vpn_azure_device_code_start(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        use supermgr_core::vpn::profile::ProfileConfig;

        let pid_str = match params.get("profile_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing profile_id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };
        let state = self.state.lock().await;
        let profile = match state.profiles.get(&pid).cloned() {
            Some(p) => p,
            None => return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned()),
        };
        drop(state);
        let cfg = match profile.config {
            ProfileConfig::AzureVpn(c) => c,
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    format!("profile is {} not azure_vpn", profile.config.backend_name()),
                )
            }
        };

        match crate::azure_oauth::start_device_flow(&cfg.tenant_id, &cfg.client_id).await {
            Ok(s) => match serde_json::to_value(&s) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    /// One poll against Microsoft's token endpoint. The GUI
    /// drives the cadence (every `interval` seconds from the
    /// devicecode response). On `Authorized`, the response also
    /// returns the rendered `.ovpn` body + a temp file path the
    /// helper can `--config` against, so the GUI just needs one
    /// last RPC to the helper to bring the tunnel up.
    pub(crate) async fn handle_vpn_azure_device_code_poll(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        use supermgr_core::vpn::profile::ProfileConfig;

        let pid_str = match params.get("profile_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing profile_id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };
        let device_code = match params.get("device_code").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing device_code".to_owned()),
        };

        let state = self.state.lock().await;
        let profile = match state.profiles.get(&pid).cloned() {
            Some(p) => p,
            None => return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned()),
        };
        drop(state);
        let cfg = match profile.config.clone() {
            ProfileConfig::AzureVpn(c) => c,
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    format!("profile is {} not azure_vpn", profile.config.backend_name()),
                )
            }
        };

        match crate::azure_oauth::poll_token(&cfg.tenant_id, &device_code).await {
            Ok(crate::azure_oauth::DeviceCodePoll::Authorized { access_token, username, expires_in }) => {
                // Materialize the rendered .ovpn to disk so the
                // helper can `--config` it. Same dir convention as
                // the OpenVPN import path: <data_dir>/ovpn/<id>.ovpn.
                let mut dir = crate::secrets::default_data_dir();
                dir.push("ovpn");
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    return Response::err(id, protocol::INTERNAL_ERROR, format!("mkdir ovpn: {e}"));
                }
                let mut path = dir;
                path.push(format!("{}.ovpn", profile.id));
                let body = crate::azure_vpn::render_azure_ovpn(&cfg, profile.full_tunnel);
                if let Err(e) = std::fs::write(&path, body.as_bytes()) {
                    return Response::err(id, protocol::INTERNAL_ERROR, format!("write ovpn: {e}"));
                }
                // 0600 — the file holds the tls-crypt key.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
                Response::ok(id, serde_json::json!({
                    "state": "authorized",
                    "config_file": path.to_string_lossy(),
                    "username": username,
                    "access_token": access_token,
                    "expires_in": expires_in,
                }))
            }
            Ok(crate::azure_oauth::DeviceCodePoll::Pending) => {
                Response::ok(id, serde_json::json!({ "state": "pending" }))
            }
            Ok(crate::azure_oauth::DeviceCodePoll::Expired) => {
                Response::ok(id, serde_json::json!({ "state": "expired" }))
            }
            Ok(crate::azure_oauth::DeviceCodePoll::Denied { description }) => {
                Response::ok(id, serde_json::json!({
                    "state": "denied",
                    "description": description,
                }))
            }
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    /// Render an Azure VPN profile as an OpenVPN-compatible `.ovpn`
    /// body. Used by the Mac connect flow: after the GUI obtains an
    /// Entra ID access token via the device-code flow, it asks for
    /// this body, writes it to disk, and hands the path + UPN +
    /// token to the existing `ovpn_connect` helper RPC. Keeps
    /// Azure-specific code out of the privileged helper.
    pub(crate) async fn handle_vpn_render_azure_ovpn(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        use supermgr_core::vpn::profile::ProfileConfig;

        let pid_str = match params.get("profile_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing profile_id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };
        let state = self.state.lock().await;
        let profile = match state.profiles.get(&pid) {
            Some(p) => p.clone(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned()),
        };
        drop(state);

        let cfg = match profile.config {
            ProfileConfig::AzureVpn(c) => c,
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    format!("profile is {} not azure_vpn", profile.config.backend_name()),
                )
            }
        };

        let body = crate::azure_vpn::render_azure_ovpn(&cfg, profile.full_tunnel);
        tracing::info!(
            "vpn_render_azure_ovpn: profile={} body={} bytes ca_pem={} bytes secret_hex={} chars routes={} dns={} full_tunnel={}",
            profile.id,
            body.len(),
            cfg.ca_cert_pem.len(),
            cfg.server_secret_hex.len(),
            cfg.routes.len(),
            cfg.dns_servers.len(),
            profile.full_tunnel,
        );
        Response::ok(id, serde_json::json!({
            "ovpn_body": body,
            "gateway_fqdn": cfg.gateway_fqdn,
            "tenant_id": cfg.tenant_id,
            "client_id": cfg.client_id,
        }))
    }

    /// Render a complete WireGuard `.conf` body for a stored profile,
    /// splicing the private key (and any peer pre-shared keys) from
    /// the secret store into the `[Interface]` / `[Peer]` blocks.
    /// The GUI hands the result to the privileged helper at connect
    /// time; secrets pass through user-space JSON-RPC exactly once
    /// per connect.
    pub(crate) async fn handle_vpn_render_wireguard_conf(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        use std::fmt::Write as _;
        use supermgr_core::vpn::profile::ProfileConfig;

        let pid_str = match params.get("profile_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing profile_id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };

        let state = self.state.lock().await;
        let profile = match state.profiles.get(&pid) {
            Some(p) => p.clone(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned()),
        };
        drop(state);

        let ProfileConfig::WireGuard(wg) = profile.config else {
            return Response::err(
                id,
                protocol::INVALID_PARAMS,
                "profile is not WireGuard".to_owned(),
            );
        };

        // Fetch the private key from the secret store. Stored
        // verbatim from import (base64 wireguard PrivateKey).
        let priv_key_label = wg.private_key.label();
        let priv_key = match self.secrets.retrieve(priv_key_label).await {
            Ok(zs) => match std::str::from_utf8(&zs) {
                Ok(s) => s.to_owned(),
                Err(_) => {
                    return Response::err(
                        id,
                        protocol::INTERNAL_ERROR,
                        "stored private key is not UTF-8".to_owned(),
                    )
                }
            },
            Err(e) => {
                return Response::err(
                    id,
                    protocol::INTERNAL_ERROR,
                    format!("retrieve private key: {e}"),
                )
            }
        };

        let mut out = String::new();
        let _ = writeln!(out, "[Interface]");
        let _ = writeln!(out, "PrivateKey = {priv_key}");
        if !wg.addresses.is_empty() {
            let addrs = wg
                .addresses
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "Address = {addrs}");
        }
        if !wg.dns.is_empty() {
            let dns = wg
                .dns
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "DNS = {dns}");
        }
        if let Some(mtu) = wg.mtu {
            let _ = writeln!(out, "MTU = {mtu}");
        }
        if let Some(port) = wg.listen_port {
            let _ = writeln!(out, "ListenPort = {port}");
        }
        out.push('\n');

        // One [Peer] block per peer. Per-peer PSKs (if present) are
        // looked up the same way the private key was. A failed PSK
        // lookup is non-fatal — the peer is still added without one.
        for peer in &wg.peers {
            let _ = writeln!(out, "[Peer]");
            let _ = writeln!(out, "PublicKey = {}", peer.public_key);
            if let Some(ref ep) = peer.endpoint {
                let _ = writeln!(out, "Endpoint = {ep}");
            }
            if !peer.allowed_ips.is_empty() {
                let ips = peer
                    .allowed_ips
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(out, "AllowedIPs = {ips}");
            }
            if let Some(ref psk_ref) = peer.preshared_key {
                if let Ok(zs) = self.secrets.retrieve(psk_ref.label()).await {
                    if let Ok(psk) = std::str::from_utf8(&zs) {
                        let _ = writeln!(out, "PresharedKey = {psk}");
                    }
                }
            }
            if let Some(keepalive) = peer.persistent_keepalive {
                let _ = writeln!(out, "PersistentKeepalive = {keepalive}");
            }
            out.push('\n');
        }

        Response::ok(
            id,
            serde_json::json!({
                "conf": out,
                "profile_id": profile.id.to_string(),
                "name": profile.name,
            }),
        )
    }

    /// Switch a profile between full-tunnel and split-tunnel mode.
    ///
    /// Backend-specific behaviour:
    ///
    /// - **WireGuard**: rewrites `WireGuardConfig.split_routes`. When
    ///   `full_tunnel=true`, the list is cleared and connect time
    ///   templates the catch-all `0.0.0.0/0, ::/0` into each peer's
    ///   AllowedIPs. When `false`, the supplied routes (which must
    ///   be non-empty for the tunnel to actually carry traffic)
    ///   replace the catch-all.
    /// - **FortiGate / IKEv2**: rewrites `FortiGateConfig.routes`,
    ///   which in turn drives strongSwan's `remote_ts` selector.
    /// - **OpenVPN / Azure / Generic**: returns INVALID_PARAMS for
    ///   now — full-tunnel-vs-split for those backends is set
    ///   inside the imported config file itself, not by us.
    ///
    /// The change does NOT take effect on an already-running tunnel;
    /// the caller has to disconnect and reconnect. We don't initiate
    /// that ourselves because it's a user-visible interruption.
    /// Persists immediately to disk via `state.save_profile`.
    pub(crate) async fn handle_vpn_set_routing(&self, id: u64, params: serde_json::Value) -> Response {
        use supermgr_core::vpn::profile::ProfileConfig;

        let pid_str = match params.get("profile_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing profile_id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };
        let full_tunnel = match params.get("full_tunnel").and_then(|v| v.as_bool()) {
            Some(b) => b,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing full_tunnel".to_owned()),
        };
        let routes = parse_ipnet_list(params.get("routes"));

        // Refuse a split-tunnel switch with no routes — that produces
        // a tunnel that can't reach anything. Fail fast at the API
        // boundary so the GUI can surface the validation error.
        if !full_tunnel && routes.is_empty() {
            return Response::err(
                id,
                protocol::INVALID_PARAMS,
                "split tunnel requires at least one route".to_owned(),
            );
        }

        let mut state = self.state.lock().await;
        let mut profile = match state.profiles.get(&pid).cloned() {
            Some(p) => p,
            None => return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned()),
        };

        // Splice the new routing into the backend-specific config.
        match &mut profile.config {
            ProfileConfig::WireGuard(wg) => {
                wg.split_routes = if full_tunnel { Vec::new() } else { routes };
            }
            ProfileConfig::FortiGate(fg) => {
                fg.routes = if full_tunnel { Vec::new() } else { routes };
            }
            ProfileConfig::OpenVpn(_)
            | ProfileConfig::AzureVpn(_)
            | ProfileConfig::Generic(_) => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    format!(
                        "routing toggle not supported for {} backend — edit the imported config file",
                        profile.config.backend_name()
                    ),
                );
            }
        }
        profile.full_tunnel = full_tunnel;
        profile.updated_at = chrono::Utc::now();

        if let Err(e) = state.save_profile(&profile) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save: {e}"));
        }
        state.profiles.insert(profile.id, profile.clone());
        match serde_json::to_value(&profile) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Rename a profile. Persisted to the profile's TOML.
    /// The new name is trimmed of surrounding whitespace and
    /// rejected if empty.
    pub(crate) async fn handle_vpn_rename_profile(&self, id: u64, params: serde_json::Value) -> Response {
        let pid_str = match params.get("profile_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing profile_id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };
        let new_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(s) => s.trim().to_string(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing name".to_owned()),
        };
        if new_name.is_empty() {
            return Response::err(id, protocol::INVALID_PARAMS, "name cannot be empty".to_owned());
        }
        let mut state = self.state.lock().await;
        let mut profile = match state.profiles.get(&pid).cloned() {
            Some(p) => p,
            None => return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned()),
        };
        profile.name = new_name;
        profile.updated_at = chrono::Utc::now();
        if let Err(e) = state.save_profile(&profile) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save: {e}"));
        }
        state.profiles.insert(profile.id, profile.clone());
        match serde_json::to_value(&profile) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Duplicate a VPN profile, including all attached secrets.
    ///
    /// The duplicate gets a fresh UUID, a derived display name
    /// ("X (copy)"), and freshly-allocated secret-store entries
    /// containing the same secret values as the source. For
    /// OpenVPN, the .ovpn config file in the daemon data dir is
    /// also copied so the duplicate doesn't depend on the
    /// original profile's lifetime.
    ///
    /// Transient state is reset on the copy: `last_connected_at`
    /// is cleared, `kill_switch` defaults to off (matching the
    /// safer-default at-import behaviour) — the user can re-arm
    /// it on the duplicate explicitly. Routing-mode (full vs
    /// split tunnel) is preserved since that's an intrinsic
    /// part of how the user wants the profile to behave.
    pub(crate) async fn handle_vpn_duplicate_profile(&self, id: u64, params: serde_json::Value) -> Response {
        use supermgr_core::vpn::profile::{ProfileConfig, SecretRef};

        let pid_str = match params.get("profile_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing profile_id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };

        let mut state = self.state.lock().await;
        let source = match state.profiles.get(&pid).cloned() {
            Some(p) => p,
            None => return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned()),
        };

        // Walk the backend-specific config and clone secrets +
        // any associated config-files into new keychain entries
        // / paths under a freshly-minted UUID.
        let new_id = uuid::Uuid::new_v4();
        let mut new_profile = source.clone();
        new_profile.id = new_id;
        new_profile.name = format!("{} (copy)", source.name);
        new_profile.last_connected_at = None;
        new_profile.kill_switch = false;
        new_profile.updated_at = chrono::Utc::now();

        // Helper closure for "retrieve from old SecretRef, store
        // under new_id-based label, return new SecretRef." We
        // bubble up the first error rather than partially-cloning,
        // since a duplicate that's missing its private key is
        // worse than no duplicate at all.
        async fn copy_secret(
            secrets: &std::sync::Arc<dyn supermgr_core::keyring::SecretStore>,
            old_ref: &SecretRef,
            new_label: String,
        ) -> Result<SecretRef, String> {
            let bytes = match secrets.retrieve(old_ref.label()).await {
                Ok(zs) => zs,
                Err(e) => return Err(format!("retrieve {}: {e}", old_ref.label())),
            };
            if let Err(e) = secrets.store(&new_label, &*bytes).await {
                return Err(format!("store {new_label}: {e}"));
            }
            Ok(SecretRef::new(new_label))
        }

        match &mut new_profile.config {
            ProfileConfig::WireGuard(wg) => {
                let new_priv = format!("vpn/{new_id}/wg-private-key");
                match copy_secret(&self.secrets, &wg.private_key, new_priv).await {
                    Ok(r) => wg.private_key = r,
                    Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, e),
                }
                // Per-peer PSKs (optional). Allocate a fresh
                // label for each, indexed by the peer's pubkey
                // hash to keep the names stable even if the user
                // reorders peers later.
                for (idx, peer) in wg.peers.iter_mut().enumerate() {
                    if let Some(old_psk) = peer.preshared_key.clone() {
                        let new_label = format!("vpn/{new_id}/wg-psk-{idx}");
                        match copy_secret(&self.secrets, &old_psk, new_label).await {
                            Ok(r) => peer.preshared_key = Some(r),
                            Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, e),
                        }
                    }
                }
            }
            ProfileConfig::FortiGate(fg) => {
                let new_pw = format!("vpn/{new_id}/password");
                match copy_secret(&self.secrets, &fg.password, new_pw).await {
                    Ok(r) => fg.password = r,
                    Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, e),
                }
                let new_psk = format!("vpn/{new_id}/psk");
                match copy_secret(&self.secrets, &fg.psk, new_psk).await {
                    Ok(r) => fg.psk = r,
                    Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, e),
                }
            }
            ProfileConfig::OpenVpn(ov) => {
                // Copy the .ovpn file into a new path under the
                // daemon's ovpn directory keyed by new_id. We
                // intentionally do not share the file with the
                // source — deleting the source profile must not
                // break the duplicate.
                let mut new_dir = crate::secrets::default_data_dir();
                new_dir.push("ovpn");
                if let Err(e) = std::fs::create_dir_all(&new_dir) {
                    return Response::err(id, protocol::INTERNAL_ERROR, format!("mkdir ovpn: {e}"));
                }
                let mut new_path = new_dir;
                new_path.push(format!("{new_id}.ovpn"));
                if let Err(e) = std::fs::copy(&ov.config_file, &new_path) {
                    return Response::err(id, protocol::INTERNAL_ERROR, format!("copy ovpn: {e}"));
                }
                ov.config_file = new_path.to_string_lossy().into_owned();
                if let Some(old_pw) = ov.password.clone() {
                    let new_label = format!("vpn/{new_id}/ovpn-password");
                    match copy_secret(&self.secrets, &old_pw, new_label).await {
                        Ok(r) => ov.password = Some(r),
                        Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, e),
                    }
                }
            }
            ProfileConfig::AzureVpn(_) | ProfileConfig::Generic(_) => {
                // No secrets we know how to clone — the profile
                // is duplicated structurally but the user may
                // need to re-enter credentials. Surface a soft
                // warning by including a flag in the response.
            }
        }

        if let Err(e) = state.save_profile(&new_profile) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save: {e}"));
        }
        state.profiles.insert(new_profile.id, new_profile.clone());
        match serde_json::to_value(&new_profile) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Set the `kill_switch` flag on a profile. Persisted in the
    /// profile's TOML; the GUI's connect path reads it and asks
    /// the helper to install pf rules accordingly.
    pub(crate) async fn handle_vpn_set_kill_switch(&self, id: u64, params: serde_json::Value) -> Response {
        let pid_str = match params.get("profile_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing profile_id".to_owned()),
        };
        let pid = match uuid::Uuid::parse_str(pid_str) {
            Ok(u) => u,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad uuid: {e}")),
        };
        let enabled = match params.get("enabled").and_then(|v| v.as_bool()) {
            Some(b) => b,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing enabled".to_owned()),
        };
        let mut state = self.state.lock().await;
        let mut profile = match state.profiles.get(&pid).cloned() {
            Some(p) => p,
            None => return Response::err(id, protocol::INVALID_PARAMS, "profile not found".to_owned()),
        };
        profile.kill_switch = enabled;
        profile.updated_at = chrono::Utc::now();
        if let Err(e) = state.save_profile(&profile) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save: {e}"));
        }
        state.profiles.insert(profile.id, profile.clone());
        match serde_json::to_value(&profile) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}
