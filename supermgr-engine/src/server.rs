//! JSON-RPC server over Unix domain socket.
//!
//! Accepts connections, reads length-prefixed JSON-RPC requests,
//! dispatches to handler methods, and writes responses back.
//!
//! Handler bodies live under `crate::handlers`; this module owns the
//! struct, the listener loop, the connection state machine, and the
//! `dispatch()` match that routes method names to `self.handle_*`.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use supermgr_core::keyring::SecretStore;
use supermgr_core::host::{AuthMethod, Host};

use crate::protocol::{self, Request, Response};
use crate::ssh::connection::SshSession;
use crate::state::DaemonState;

/// The engine server: holds shared state and secret store.
pub struct EngineServer {
    pub state: Arc<Mutex<DaemonState>>,
    pub secrets: Arc<dyn SecretStore>,
}

impl EngineServer {
    /// Create a new engine server.
    pub fn new(state: DaemonState, secrets: Arc<dyn SecretStore>) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
            secrets,
        }
    }

    /// Start listening on a Unix domain socket.
    pub async fn serve(self: Arc<Self>, socket_path: &str) -> anyhow::Result<()> {
        // Remove stale socket file.
        let _ = std::fs::remove_file(socket_path);

        // Ensure parent directory exists.
        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(socket_path)?;

        // Restrict the socket file to owner-only access. On Unix
        // sockets, file-mode permissions are enforced at connect()
        // — anyone without `r+w` on the path gets EACCES. With 0o600
        // only processes running as the same UID as the daemon can
        // connect, blocking sandboxed-app + cross-user attacks.
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(socket_path, perms) {
                warn!("could not chmod 0600 socket {socket_path}: {e}");
            }
        }

        info!("JSON-RPC server listening on {socket_path} (mode 0600)");

        // Bound concurrent client connections so a runaway caller
        // (or malicious one) can't exhaust file descriptors and
        // task slots. 256 is far above realistic single-user load.
        let conn_sema = Arc::new(tokio::sync::Semaphore::new(256));

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let server = Arc::clone(&self);
                    let permit = match Arc::clone(&conn_sema).try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!("connection refused: 256 concurrent clients reached");
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        let _permit = permit; // released on task end
                        if let Err(e) = server.handle_connection(stream).await {
                            warn!("connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("accept error: {e}");
                }
            }
        }
    }

    /// Handle a single client connection.
    async fn handle_connection(
        &self,
        mut stream: tokio::net::UnixStream,
    ) -> anyhow::Result<()> {
        debug!("new client connected");

        loop {
            // Read 4-byte length prefix (big-endian).
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("client disconnected");
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            }
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if msg_len > 10 * 1024 * 1024 {
                warn!("message too large: {msg_len} bytes");
                return Ok(());
            }

            // Read the JSON payload.
            let mut buf = vec![0u8; msg_len];
            stream.read_exact(&mut buf).await?;

            // Parse the request.
            let response = match serde_json::from_slice::<Request>(&buf) {
                Ok(req) => self.dispatch(req).await,
                Err(e) => Response::err(0, protocol::PARSE_ERROR, format!("parse error: {e}")),
            };

            // Write response with length prefix.
            let resp_bytes = serde_json::to_vec(&response)?;
            let len = (resp_bytes.len() as u32).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&resp_bytes).await?;
        }
    }

    /// Dispatch a JSON-RPC request to the appropriate handler.
    async fn dispatch(&self, req: Request) -> Response {
        let id = req.id;
        match req.method.as_str() {
            // -- Profile methods --
            "list_profiles" => self.handle_list_profiles(id).await,
            "vpn_get_profile" => self.handle_vpn_get_profile(id, req.params).await,
            "vpn_add_ikev2_profile" => self.handle_vpn_add_ikev2_profile(id, req.params).await,
            "vpn_update_ikev2_profile" => self.handle_vpn_update_ikev2_profile(id, req.params).await,
            "vpn_delete_profile" => self.handle_vpn_delete_profile(id, req.params).await,
            "vpn_import_wireguard" => self.handle_vpn_import_wireguard(id, req.params).await,
            "vpn_import_openvpn" => self.handle_vpn_import_openvpn(id, req.params).await,
            "vpn_import_azure" => self.handle_vpn_import_azure(id, req.params).await,
            "vpn_render_wireguard_conf" => self.handle_vpn_render_wireguard_conf(id, req.params).await,
            "vpn_render_azure_ovpn" => self.handle_vpn_render_azure_ovpn(id, req.params).await,
            "vpn_check_azure_runtime" => self.handle_vpn_check_azure_runtime(id).await,
            "vpn_set_routing" => self.handle_vpn_set_routing(id, req.params).await,
            "vpn_set_kill_switch" => self.handle_vpn_set_kill_switch(id, req.params).await,
            "vpn_rename_profile" => self.handle_vpn_rename_profile(id, req.params).await,
            "vpn_duplicate_profile" => self.handle_vpn_duplicate_profile(id, req.params).await,

            // -- SSH key methods --
            "ssh_generate_key" => self.handle_ssh_generate_key(id, req.params).await,
            "ssh_list_keys" => self.handle_ssh_list_keys(id).await,
            "ssh_get_key" => self.handle_ssh_get_key(id, req.params).await,
            "ssh_delete_key" => self.handle_ssh_delete_key(id, req.params).await,
            "ssh_export_public_key" => self.handle_ssh_export_public_key(id, req.params).await,
            "ssh_import_key" => self.handle_ssh_import_key(id, req.params).await,
            "ssh_import_keys_scan" => self.handle_ssh_import_keys_scan(id, req.params).await,

            // -- SSH host methods --
            "ssh_add_host" => self.handle_ssh_add_host(id, req.params).await,
            "ssh_update_host" => self.handle_ssh_update_host(id, req.params).await,
            "ssh_list_hosts" => self.handle_ssh_list_hosts(id).await,
            "ssh_get_host" => self.handle_ssh_get_host(id, req.params).await,
            "ssh_delete_host" => self.handle_ssh_delete_host(id, req.params).await,
            "ssh_toggle_pin" => self.handle_ssh_toggle_pin(id, req.params).await,
            "ssh_set_password" => self.handle_ssh_set_password(id, req.params).await,

            // -- SSH operations --
            "ssh_execute_command" => self.handle_ssh_execute_command(id, req.params).await,
            "ssh_test_connection" => self.handle_ssh_test_connection(id, req.params).await,
            "ssh_push_key" => self.handle_ssh_push_key(id, req.params).await,
            "ssh_revoke_key" => self.handle_ssh_revoke_key(id, req.params).await,
            "ssh_host_health" => self.handle_ssh_host_health(id).await,
            "ssh_set_api_token" => self.handle_ssh_set_api_token(id, req.params).await,
            "ssh_clear_api_token" => self.handle_ssh_clear_api_token(id, req.params).await,

            // -- FortiGate REST API methods --
            "fortigate_api" => self.handle_fortigate_api(id, req.params).await,
            "fortigate_generate_api_token" => {
                self.handle_fortigate_generate_api_token(id, req.params).await
            }
            "fortigate_get_api_token" => {
                self.handle_fortigate_get_api_token(id, req.params).await
            }
            "fortigate_test_connection" => {
                self.handle_fortigate_test_connection(id, req.params).await
            }
            "fortigate_get_dashboard" => {
                self.handle_fortigate_get_dashboard(id, req.params).await
            }

            // -- Compliance methods --
            "compliance_run" => self.handle_compliance_run(id, req.params).await,
            "compliance_history" => self.handle_compliance_history(id, req.params).await,
            "compliance_get_run" => self.handle_compliance_get_run(id, req.params).await,
            "compliance_list_checks" => self.handle_compliance_list_checks(id).await,
            "compliance_drift" => self.handle_compliance_drift(id, req.params).await,
            "compliance_render_report" => {
                self.handle_compliance_render_report(id, req.params).await
            }
            "compliance_scan_all" => self.handle_compliance_scan_all(id, req.params).await,
            "compliance_run_linux" => self.handle_compliance_run_linux(id, req.params).await,
            "compliance_list_linux_checks" => self.handle_compliance_list_linux_checks(id).await,

            // -- Customer / Provisioning methods --
            "customer_list" => self.handle_customer_list(id).await,
            "customer_save" => self.handle_customer_save(id, req.params).await,
            "customer_delete" => self.handle_customer_delete(id, req.params).await,
            "customer_report" => self.handle_customer_report(id, req.params).await,
            "provisioning_list_templates" => {
                self.handle_provisioning_list_templates(id).await
            }
            "provisioning_render" => {
                self.handle_provisioning_render(id, req.params).await
            }
            "provisioning_diff_preview" => {
                self.handle_provisioning_diff_preview(id, req.params).await
            }
            "provisioning_pre_deploy_backup" => {
                self.handle_provisioning_pre_deploy_backup(id, req.params).await
            }
            "provisioning_deploy" => {
                self.handle_provisioning_deploy(id, req.params).await
            }
            "provisioning_list_deployments" => {
                self.handle_provisioning_list_deployments(id, req.params).await
            }
            "provisioning_rollback" => {
                self.handle_provisioning_rollback(id, req.params).await
            }

            // -- UniFi methods --
            "unifi_set_inform" => self.handle_unifi_set_inform(id, req.params).await,
            "unifi_set_controller" => {
                self.handle_unifi_set_controller(id, req.params).await
            }
            "unifi_clear_controller" => {
                self.handle_unifi_clear_controller(id, req.params).await
            }
            "unifi_test" => self.handle_unifi_test(id, req.params).await,
            "unifi_api" => self.handle_unifi_api(id, req.params).await,

            // -- Engagement / Security methods --
            "engagement_list" => self.handle_engagement_list(id).await,
            "engagement_save" => self.handle_engagement_save(id, req.params).await,
            "engagement_delete" => self.handle_engagement_delete(id, req.params).await,
            "discovery_passive_scan" => {
                self.handle_discovery_passive_scan(id, req.params).await
            }
            "discovery_inventory" => {
                self.handle_discovery_inventory(id, req.params).await
            }
            "discovery_active_scan" => {
                self.handle_discovery_active_scan(id, req.params).await
            }
            "discovery_findings" => {
                self.handle_discovery_findings(id, req.params).await
            }
            "security_test_default_creds" => {
                self.handle_security_test_default_creds(id, req.params).await
            }

            // -- Track A: findings management --
            "findings_list" => self.handle_findings_list(id, req.params).await,
            "findings_summary" => self.handle_findings_summary(id, req.params).await,
            "findings_risk_hosts" => self.handle_findings_risk_hosts(id, req.params).await,
            "findings_set_disposition" => {
                self.handle_findings_set_disposition(id, req.params).await
            }
            "engagement_report" => self.handle_engagement_report(id, req.params).await,
            "notify_get_config" => self.handle_notify_get_config(id).await,
            "notify_set_webhook" => self.handle_notify_set_webhook(id, req.params).await,
            "notify_set_pagerduty" => self.handle_notify_set_pagerduty(id, req.params).await,
            "notify_set_opsgenie" => self.handle_notify_set_opsgenie(id, req.params).await,
            "engagement_set_schedule" => {
                self.handle_engagement_set_schedule(id, req.params).await
            }
            "api_version" => Response::ok(
                id,
                serde_json::json!({
                    "major": protocol::API_VERSION_MAJOR,
                    "minor": protocol::API_VERSION_MINOR,
                }),
            ),
            "network_detect" => self.handle_network_detect(id).await,
            "tools_status" => self.handle_tools_status(id).await,
            "dns_health_audit" => self.handle_dns_health_audit(id, req.params).await,
            "cve_feed_refresh" => self.handle_cve_feed_refresh(id).await,
            "cve_feed_status" => self.handle_cve_feed_status(id).await,
            "subdomain_enum" => self.handle_subdomain_enum(id, req.params).await,
            "asset_enrich" => self.handle_asset_enrich(id, req.params).await,
            "engagement_report_pdf" => self.handle_engagement_report_pdf(id, req.params).await,
            "activity_timeline" => self.handle_activity_timeline(id, req.params).await,
            "remediation_script" => self.handle_remediation_script(id, req.params).await,

            _ => Response::err(id, protocol::METHOD_NOT_FOUND, format!("unknown method: {}", req.method)),
        }
    }

    // =======================================================================
    // Helpers
    // =======================================================================

    /// Connect to an SSH host using its stored credentials. Trampolines
    /// into the free-function form so spawned tasks (which can't easily
    /// borrow `&self`) can share the same code path.
    pub(crate) async fn connect_to_host(&self, host_id: uuid::Uuid) -> Result<(Host, SshSession), String> {
        connect_to_host_owned(&self.state, &self.secrets, host_id).await
    }
}

/// Free-function variant of `EngineServer::connect_to_host` that takes the
/// daemon state and secret store as `Arc`s. Spawned tasks (e.g. inside
/// `handle_ssh_fanout_key_op`) own clones of these handles, so they can
/// call this without holding `&self`. The body is identical to what
/// `connect_to_host` used to inline.
pub async fn connect_to_host_owned(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
) -> Result<(Host, SshSession), String> {
    // Snapshot the host AND the known-hosts handle in one lock pass. The
    // handle is cheap (`Arc::clone`) and lets us drop the state mutex
    // before we make the (potentially slow) network call.
    let (host, known_hosts) = {
        let st = state.lock().await;
        let host = st
            .ssh_hosts
            .get(&host_id)
            .cloned()
            .ok_or_else(|| format!("host not found: {host_id}"))?;
        (host, Arc::clone(&st.known_hosts))
    };

    let session = match host.auth_method {
        AuthMethod::Password => {
            let password_ref = host
                .auth_password_ref
                .as_ref()
                .ok_or_else(|| "no password configured".to_string())?;
            let password_bytes = secrets
                .retrieve(&password_ref.0)
                .await
                .map_err(|e| format!("retrieve password: {e}"))?;
            let password = String::from_utf8_lossy(&password_bytes).to_string();
            SshSession::connect_password(
                &host.hostname,
                host.port,
                &host.username,
                &password,
                10,
                known_hosts,
            )
            .await
            .map_err(|e| e.to_string())?
        }
        AuthMethod::Key => {
            let key_id = host
                .auth_key_id
                .ok_or_else(|| "no SSH key configured".to_string())?;
            let privkey_pem = {
                let st = state.lock().await;
                let ssh_key = st
                    .ssh_keys
                    .get(&key_id)
                    .ok_or_else(|| format!("SSH key not found: {key_id}"))?;
                let priv_ref = ssh_key.private_key_ref.0.clone();
                drop(st);
                let privkey_bytes = secrets
                    .retrieve(&priv_ref)
                    .await
                    .map_err(|e| format!("retrieve private key: {e}"))?;
                String::from_utf8_lossy(&privkey_bytes).to_string()
            };
            SshSession::connect_key(
                &host.hostname,
                host.port,
                &host.username,
                &privkey_pem,
                10,
                known_hosts,
            )
            .await
            .map_err(|e| e.to_string())?
        }
        AuthMethod::Certificate => {
            // Certificate auth (SSH cert signed by a CA) is a Linux
            // path that hasn't been ported to the Mac engine yet.
            // Fail loudly rather than silently mis-route to one of
            // the other arms.
            return Err("ssh certificate auth not yet implemented in supermgr-engine".to_string());
        }
    };

    Ok((host, session))
}

/// Extract a UUID parameter from JSON-RPC params.
pub(crate) fn get_uuid_param(params: &serde_json::Value, name: &str) -> Result<uuid::Uuid, Response> {
    let s = params
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Response::err(0, protocol::INVALID_PARAMS, format!("missing {name}")))?;
    uuid::Uuid::parse_str(s)
        .map_err(|_| Response::err(0, protocol::INVALID_PARAMS, format!("invalid UUID: {s}")))
}

/// Parse a JSON array of IP-address strings. Invalid entries are silently dropped.
pub(crate) fn parse_ip_list(v: Option<&serde_json::Value>) -> Vec<std::net::IpAddr> {
    v.and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().and_then(|s| s.parse().ok()))
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a JSON array of CIDR strings. Invalid entries are silently dropped.
pub(crate) fn parse_ipnet_list(v: Option<&serde_json::Value>) -> Vec<ipnet::IpNet> {
    v.and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().and_then(|s| s.parse().ok()))
                .collect()
        })
        .unwrap_or_default()
}

/// Apply a partial host update from the GUI to an existing record.
///
/// CRITICAL: this is a MERGE, not a replace. The GUI's edit form sends
/// only the fields the user can change in that form (`label`, `hostname`,
/// `port`, `username`, `group`, `device_type`, `auth_method`,
/// `auth_key_id`, `vpn_profile_id`). Every other field on the existing
/// `Host` — `auth_password_ref`, `pinned`, `created_at`, `has_api`,
/// `api_token_ref`, etc. — is preserved.
///
/// The previous "deserialize the JSON as a whole `Host` and replace"
/// approach silently destroyed those fields on every edit, which meant
/// editing a host's port wiped its stored password. We now whitelist the
/// editable fields explicitly.
pub fn merge_host_update(host: &mut Host, incoming: &serde_json::Value) {
    if let Some(s) = incoming.get("label").and_then(|v| v.as_str()) {
        host.label = s.to_owned();
    }
    if let Some(s) = incoming.get("hostname").and_then(|v| v.as_str()) {
        host.hostname = s.to_owned();
    }
    if let Some(n) = incoming.get("port").and_then(|v| v.as_u64()) {
        host.port = n as u16;
    }
    if let Some(s) = incoming.get("username").and_then(|v| v.as_str()) {
        host.username = s.to_owned();
    }
    if let Some(s) = incoming.get("group").and_then(|v| v.as_str()) {
        host.group = s.to_owned();
    }
    if let Some(v) = incoming.get("device_type") {
        if let Ok(dt) = serde_json::from_value(v.clone()) {
            host.device_type = dt;
        }
    }
    if let Some(v) = incoming.get("auth_method") {
        if let Ok(am) = serde_json::from_value(v.clone()) {
            host.auth_method = am;
        }
    }
    if let Some(v) = incoming.get("auth_key_id") {
        host.auth_key_id = serde_json::from_value(v.clone()).ok();
    }
    if let Some(v) = incoming.get("vpn_profile_id") {
        host.vpn_profile_id = serde_json::from_value(v.clone()).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supermgr_core::host::AuthMethod;
    use supermgr_core::ssh::device_type::DeviceType;
    use supermgr_core::vpn::profile::SecretRef;

    fn password_ref() -> SecretRef {
        SecretRef("supermgr/ssh/host/<id>/password".to_owned())
    }
    fn api_ref() -> SecretRef {
        SecretRef("supermgr/ssh/host/<id>/api_token".to_owned())
    }

    fn full_host() -> Host {
        // A "richly populated" host that exercises every field the merge
        // logic could be tempted to clobber. New `Host` fields should
        // be added here too — this is the canonical "all fields
        // populated" fixture.
        Host {
            id: uuid::Uuid::nil(),
            label: "old-label".to_owned(),
            hostname: "10.0.0.1".to_owned(),
            port: 22,
            username: "olduser".to_owned(),
            group: String::new(),
            device_type: DeviceType::Linux,
            auth_method: AuthMethod::Password,
            auth_key_id: None,
            auth_password_ref: Some(password_ref()),
            auth_cert_ref: None,
            vpn_profile_id: Some(uuid::Uuid::nil()),
            api_port: None,
            api_token_ref: Some(api_ref()),
            api_verify_tls: true,
            unifi_controller_url: None,
            unifi_api_token_ref: None,
            rdp_port: None,
            vnc_port: None,
            port_forwards: Vec::new(),
            proxy_jump: None,
            pinned: true,
            customer: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn merge_preserves_password_ref_when_form_omits_it() {
        // The exact regression: GUI sends `{label, hostname, port, username,
        // group, device_type, auth_method, auth_key_id}` but no
        // `auth_password_ref`. Old code wiped the password. New code must
        // not.
        let mut host = full_host();
        let incoming = serde_json::json!({
            "label": "new-label",
            "hostname": "10.0.0.2",
            "port": 2200,
            "username": "newuser",
            "group": "production",
            "device_type": "linux",
            "auth_method": "password",
            "auth_key_id": null,
        });
        merge_host_update(&mut host, &incoming);

        // Editable fields took the new value
        assert_eq!(host.label, "new-label");
        assert_eq!(host.hostname, "10.0.0.2");
        assert_eq!(host.port, 2200);
        assert_eq!(host.username, "newuser");
        assert_eq!(host.group, "production");

        // Critical: secret refs and pin/state must survive
        assert_eq!(
            host.auth_password_ref.as_ref().map(|s| &s.0),
            Some(&password_ref().0),
            "merge_host_update wiped auth_password_ref — the old replace bug is back"
        );
        assert_eq!(
            host.api_token_ref.as_ref().map(|s| &s.0),
            Some(&api_ref().0),
            "merge_host_update wiped api_token_ref"
        );
        assert!(host.pinned, "merge_host_update reset the pin flag");
        assert!(host.vpn_profile_id.is_some(), "merge_host_update wiped vpn_profile_id");
    }

    #[test]
    fn merge_ignores_unknown_fields() {
        // A future GUI sending `{ "weird_field": ... }` shouldn't crash
        // or leak that field into the model.
        let mut host = full_host();
        let original_label = host.label.clone();
        let incoming = serde_json::json!({
            "weird_field": "hello",
            "another_unknown": 42,
        });
        merge_host_update(&mut host, &incoming);
        assert_eq!(host.label, original_label, "unknown fields should be a no-op");
    }

    #[test]
    fn merge_can_clear_optional_fields() {
        // Setting auth_key_id to null in the JSON DOES clear it.
        let mut host = full_host();
        host.auth_key_id = Some(uuid::Uuid::nil());
        let incoming = serde_json::json!({ "auth_key_id": null });
        merge_host_update(&mut host, &incoming);
        assert!(host.auth_key_id.is_none());
    }
}
