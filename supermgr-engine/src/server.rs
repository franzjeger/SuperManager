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

use crate::operations::OperationRegistry;
use crate::protocol::{self, Request, Response};
use crate::ssh::connection::SshSession;
use crate::state::DaemonState;

/// The engine server: holds shared state and secret store.
pub struct EngineServer {
    pub state: Arc<Mutex<DaemonState>>,
    pub secrets: Arc<dyn SecretStore>,
    /// Process-wide registry of cancellable long-running operations.
    /// Handlers register here at the start of an active scan,
    /// compliance run, etc.; the UI lists + cancels via the
    /// `operation_list` / `operation_cancel` RPC methods.
    pub operations: Arc<OperationRegistry>,
}

impl EngineServer {
    /// Create a new engine server.
    pub fn new(state: DaemonState, secrets: Arc<dyn SecretStore>) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
            secrets,
            operations: Arc::new(OperationRegistry::new()),
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
                    let permit = if let Ok(p) = Arc::clone(&conn_sema).try_acquire_owned() { p } else {
                        warn!("connection refused: 256 concurrent clients reached");
                        continue;
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
            "vpn_set_push_dns" => self.handle_vpn_set_push_dns(id, req.params).await,
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
            "ssh_set_certificate" => self.handle_ssh_set_certificate(id, req.params).await,

            // -- SSH operations --
            "ssh_execute_command" => self.handle_ssh_execute_command(id, req.params).await,
            "ssh_test_connection" => self.handle_ssh_test_connection(id, req.params).await,
            "ssh_push_key" => self.handle_ssh_push_key(id, req.params).await,
            "ssh_revoke_key" => self.handle_ssh_revoke_key(id, req.params).await,
            "ssh_probe_hosts" => self.handle_ssh_probe_hosts(id).await,
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

            // -- Standalone UniFi controller registry --
            "unifi_controller_list" => self.handle_unifi_controller_list(id).await,
            "unifi_controller_save" => {
                self.handle_unifi_controller_save(id, req.params).await
            }
            "unifi_controller_delete" => {
                self.handle_unifi_controller_delete(id, req.params).await
            }
            "unifi_controller_test" => {
                self.handle_unifi_controller_test(id, req.params).await
            }
            "unifi_controller_devices" => {
                self.handle_unifi_controller_devices(id, req.params).await
            }
            "unifi_controller_devmgr" => {
                self.handle_unifi_controller_devmgr(id, req.params).await
            }
            "unifi_controller_mfa_send" => {
                self.handle_unifi_controller_mfa_send(id, req.params).await
            }
            "unifi_controller_mfa_complete" => {
                self.handle_unifi_controller_mfa_complete(id, req.params).await
            }

            // -- Device-type override store --
            "device_type_overrides_list" => {
                self.handle_device_type_overrides_list(id).await
            }
            "device_type_override_set" => {
                self.handle_device_type_override_set(id, req.params).await
            }

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
            "discovery_dns_axfr" => {
                self.handle_discovery_dns_axfr(id, req.params).await
            }
            "discovery_analyse_pcap" => {
                self.handle_discovery_analyse_pcap(id, req.params).await
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
            "engagement_report_html" => self.handle_engagement_report_html(id, req.params).await,
            "operation_list" => self.handle_operation_list(id).await,
            "operation_cancel" => self.handle_operation_cancel(id, req.params).await,
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

    /// Same as `connect_to_host` but surfaces a structured
    /// `EngineError` so the handler can emit
    /// `Response::err_engine` with a stable `kind` (e.g.
    /// `ssh_auth` vs `ssh_network`). Existing call sites stay
    /// on the String-returning variant until they're migrated
    /// to structured errors individually.
    pub(crate) async fn connect_to_host_typed(
        &self,
        host_id: uuid::Uuid,
    ) -> Result<(Host, SshSession), crate::error::EngineError> {
        connect_to_host_owned_typed(&self.state, &self.secrets, host_id).await
    }
}

/// Retrieve the OpenSSH certificate for a certificate-auth host.
///
/// Returns `None` for every host that isn't on
/// `AuthMethod::Certificate`, and — with a warning — for a cert-auth
/// host whose certificate is unconfigured or unreadable. Callers treat
/// `None` as "use plain public-key auth with the same key".
///
/// Degrading instead of erroring is deliberate and matches the Linux
/// daemon: the private key is the thing that actually authenticates,
/// the certificate only carries the CA's signature over it. A host
/// that also has the bare key in `authorized_keys` stays reachable
/// when the cert is missing, expired or unreadable from the keychain,
/// which is the difference between a degraded login and an operator
/// locked out mid-incident. The server still decides whether the bare
/// key is acceptable, so this cannot turn a rejected cert into
/// unauthorised access.
async fn cert_pem_for_host(host: &Host, secrets: &Arc<dyn SecretStore>) -> Option<String> {
    if host.auth_method != AuthMethod::Certificate {
        return None;
    }
    let Some(cert_ref) = host.auth_cert_ref.as_ref() else {
        warn!(
            host = %host.hostname,
            "certificate auth selected but no certificate configured — falling back to key auth"
        );
        return None;
    };
    match secrets.retrieve(&cert_ref.0).await {
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).to_string()),
        Err(e) => {
            warn!(
                host = %host.hostname,
                error = %e,
                "could not retrieve SSH certificate — falling back to key auth"
            );
            None
        }
    }
}

/// Same as `connect_to_host_owned` but returns a structured
/// `EngineError` instead of a stringified error. Used by handlers
/// that emit `Response::err_engine` so the Swift client can
/// distinguish `ssh_auth` (wrong creds — show retry) from
/// `ssh_network` (host unreachable — suggest VPN) without
/// regex-matching the human message.
pub async fn connect_to_host_owned_typed(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
) -> Result<(Host, SshSession), crate::error::EngineError> {
    use crate::error::EngineError;
    

    let (host, known_hosts) = {
        let st = state.lock().await;
        let host = st
            .ssh_hosts
            .get(&host_id)
            .cloned()
            .ok_or_else(|| EngineError::Other(anyhow::anyhow!("host not found: {host_id}")))?;
        (host, Arc::clone(&st.known_hosts))
    };

    let session = match host.auth_method {
        AuthMethod::Password => {
            let password_ref = host.auth_password_ref.as_ref().ok_or_else(|| {
                EngineError::Other(anyhow::anyhow!("no password configured"))
            })?;
            let password_bytes = secrets.retrieve(&password_ref.0).await.map_err(|e| {
                EngineError::Other(anyhow::anyhow!("retrieve password: {e}"))
            })?;
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
            .map_err(|e| ssh_error_to_engine(&host.hostname, e))?
        }
        // Both arms need the same private key; certificate auth just
        // presents a CA-signed cert alongside it. See
        // `cert_pem_for_host` for why a missing cert degrades to plain
        // key auth rather than failing here.
        AuthMethod::Key | AuthMethod::Certificate => {
            let key_id = host.auth_key_id.ok_or_else(|| {
                EngineError::Other(anyhow::anyhow!("no SSH key configured"))
            })?;
            let privkey_pem = {
                let st = state.lock().await;
                let ssh_key = st.ssh_keys.get(&key_id).ok_or_else(|| {
                    EngineError::Other(anyhow::anyhow!("SSH key not found: {key_id}"))
                })?;
                let priv_ref = ssh_key.private_key_ref.0.clone();
                drop(st);
                let privkey_bytes = secrets.retrieve(&priv_ref).await.map_err(|e| {
                    EngineError::Other(anyhow::anyhow!("retrieve private key: {e}"))
                })?;
                String::from_utf8_lossy(&privkey_bytes).to_string()
            };
            match cert_pem_for_host(&host, secrets).await {
                Some(cert_pem) => SshSession::connect_certificate(
                    &host.hostname,
                    host.port,
                    &host.username,
                    &privkey_pem,
                    &cert_pem,
                    10,
                    known_hosts,
                )
                .await
                .map_err(|e| ssh_error_to_engine(&host.hostname, e))?,
                None => SshSession::connect_key(
                    &host.hostname,
                    host.port,
                    &host.username,
                    &privkey_pem,
                    10,
                    known_hosts,
                )
                .await
                .map_err(|e| ssh_error_to_engine(&host.hostname, e))?,
            }
        }
    };

    Ok((host, session))
}

/// Maps `SshError` → `EngineError` for the typed connect path.
/// The shape of `SshError` already distinguishes auth-vs-network
/// failures, so we just route each variant to the matching
/// `EngineError` kind. Other / unknown variants fall through to
/// `Other` so the existing UI behaviour is preserved.
fn ssh_error_to_engine(
    host: &str,
    err: supermgr_core::error::SshError,
) -> crate::error::EngineError {
    use crate::error::EngineError;
    use supermgr_core::error::SshError;
    match err {
        SshError::AuthFailed(reason) => EngineError::SshAuth { reason },
        SshError::ConnectionFailed { reason, .. } => EngineError::SshNetwork { reason },
        // SshError has no explicit "session closed mid-handshake"
        // variant — the russh client surfaces those as either
        // AuthFailed or ConnectionFailed. SshDisconnected on
        // EngineError stays in the enum for future use; nothing
        // produces it from this path today.
        other => EngineError::Other(anyhow::anyhow!("{host}: {other}")),
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
        // See the typed variant above — same key fetch, same
        // cert-degrades-to-key rule.
        AuthMethod::Key | AuthMethod::Certificate => {
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
            match cert_pem_for_host(&host, secrets).await {
                Some(cert_pem) => SshSession::connect_certificate(
                    &host.hostname,
                    host.port,
                    &host.username,
                    &privkey_pem,
                    &cert_pem,
                    10,
                    known_hosts,
                )
                .await
                .map_err(|e| e.to_string())?,
                None => SshSession::connect_key(
                    &host.hostname,
                    host.port,
                    &host.username,
                    &privkey_pem,
                    10,
                    known_hosts,
                )
                .await
                .map_err(|e| e.to_string())?,
            }
        }
    };

    Ok((host, session))
}

/// Extract a UUID parameter from JSON-RPC params.
// See the note on `resolve_findings_scope`: boxing `Response` is a
// wide change for an unmeasured win.
#[allow(clippy::result_large_err)]
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
pub fn merge_host_update(host: &mut Host, incoming: &serde_json::Value) -> Result<(), String> {
    if let Some(s) = incoming.get("label").and_then(|v| v.as_str()) {
        host.label = s.to_owned();
    }
    if let Some(s) = incoming.get("hostname").and_then(|v| v.as_str()) {
        host.hostname = s.to_owned();
    }
    if let Some(n) = incoming.get("port").and_then(serde_json::Value::as_u64) {
        if !(1..=65535).contains(&n) {
            return Err(format!("port {n} out of range 1-65535"));
        }
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
    Ok(())
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
    fn cert_ref() -> SecretRef {
        SecretRef("supermgr/ssh/host/<id>/cert".to_owned())
    }

    /// In-memory `SecretStore` for the `cert_pem_for_host` tests:
    /// resolves the labels it was seeded with, `NotFound` for the rest.
    struct MapSecretStore(std::collections::HashMap<String, Vec<u8>>);

    impl MapSecretStore {
        fn with(label: &str, value: &str) -> Arc<dyn SecretStore> {
            let mut m = std::collections::HashMap::new();
            m.insert(label.to_owned(), value.as_bytes().to_vec());
            Arc::new(Self(m))
        }
        fn empty() -> Arc<dyn SecretStore> {
            Arc::new(Self(std::collections::HashMap::new()))
        }
    }

    #[async_trait::async_trait]
    impl SecretStore for MapSecretStore {
        async fn store(
            &self,
            _label: &str,
            _secret: &[u8],
        ) -> Result<(), supermgr_core::error::SecretError> {
            unreachable!("cert_pem_for_host never stores")
        }
        async fn retrieve(
            &self,
            label: &str,
        ) -> Result<supermgr_core::keyring::ZeroizingSecret, supermgr_core::error::SecretError>
        {
            self.0
                .get(label)
                .map(|b| supermgr_core::keyring::ZeroizingSecret::from_vec(b.clone()))
                .ok_or_else(|| supermgr_core::error::SecretError::NotFound {
                    label: label.to_owned(),
                })
        }
        async fn delete(&self, _label: &str) -> Result<(), supermgr_core::error::SecretError> {
            unreachable!("cert_pem_for_host never deletes")
        }
    }

    const FAKE_CERT: &str = "ssh-ed25519-cert-v01@openssh.com AAAAfake== user@example";

    #[tokio::test]
    async fn cert_fetch_returns_cert_for_certificate_auth_host() {
        let mut host = full_host();
        host.auth_method = AuthMethod::Certificate;
        host.auth_cert_ref = Some(cert_ref());
        let secrets = MapSecretStore::with(&cert_ref().0, FAKE_CERT);

        assert_eq!(
            cert_pem_for_host(&host, &secrets).await.as_deref(),
            Some(FAKE_CERT),
            "a cert-auth host with a readable certificate must present it"
        );
    }

    #[tokio::test]
    async fn cert_fetch_skips_non_certificate_auth_methods() {
        // The guard that keeps a stray `auth_cert_ref` on a Key- or
        // Password-auth host from silently switching the connection to
        // certificate auth. `auth_method` is the only thing that
        // decides, not the presence of a cert.
        let secrets = MapSecretStore::with(&cert_ref().0, FAKE_CERT);
        for method in [AuthMethod::Password, AuthMethod::Key] {
            let mut host = full_host();
            host.auth_method = method;
            host.auth_cert_ref = Some(cert_ref());
            assert!(
                cert_pem_for_host(&host, &secrets).await.is_none(),
                "{method:?} auth must not pick up a certificate"
            );
        }
    }

    #[tokio::test]
    async fn cert_fetch_degrades_when_certificate_missing_or_unreadable() {
        // Both degradation paths documented on `cert_pem_for_host`:
        // no cert configured, and a cert_ref the store can't resolve.
        // Either way the caller falls back to plain key auth instead of
        // failing the connection — an operator with the bare key in
        // authorized_keys stays able to log in.
        let mut unconfigured = full_host();
        unconfigured.auth_method = AuthMethod::Certificate;
        unconfigured.auth_cert_ref = None;
        assert!(
            cert_pem_for_host(&unconfigured, &MapSecretStore::empty())
                .await
                .is_none(),
            "cert auth with no configured certificate must degrade, not error"
        );

        let mut dangling = full_host();
        dangling.auth_method = AuthMethod::Certificate;
        dangling.auth_cert_ref = Some(cert_ref());
        assert!(
            cert_pem_for_host(&dangling, &MapSecretStore::empty())
                .await
                .is_none(),
            "an unreadable certificate must degrade, not error"
        );
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
            // Populated so the merge tests below actually exercise it.
            // This fixture documents itself as "every field populated";
            // leaving the cert ref None meant an edit that silently
            // dropped it would have passed.
            auth_cert_ref: Some(cert_ref()),
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
        merge_host_update(&mut host, &incoming).unwrap();

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
        assert_eq!(
            host.auth_cert_ref.as_ref().map(|s| &s.0),
            Some(&cert_ref().0),
            "merge_host_update wiped auth_cert_ref — editing any field \
             would strip a certificate host's certificate"
        );
        assert!(host.pinned, "merge_host_update reset the pin flag");
        assert!(host.vpn_profile_id.is_some(), "merge_host_update wiped vpn_profile_id");
    }

    #[test]
    fn merge_never_takes_a_client_supplied_cert_ref() {
        // Secret labels are the engine's to mint — `ssh_set_certificate`
        // and the `certificate` param on `ssh_add_host` both derive the
        // label from the host id. If `auth_cert_ref` ever became a
        // merge-able field, a caller could repoint a host at an arbitrary
        // keychain entry and have the connect path read it. Same reasoning
        // guards `auth_password_ref` and `api_token_ref`.
        let mut host = full_host();
        let incoming = serde_json::json!({
            "auth_cert_ref": "supermgr/ssh/host/somebody-elses-host/certificate",
            "auth_password_ref": "supermgr/ssh/host/somebody-elses-host/password",
        });
        merge_host_update(&mut host, &incoming).unwrap();

        assert_eq!(
            host.auth_cert_ref.as_ref().map(|s| &s.0),
            Some(&cert_ref().0),
            "merge_host_update accepted an auth_cert_ref off the wire"
        );
        assert_eq!(
            host.auth_password_ref.as_ref().map(|s| &s.0),
            Some(&password_ref().0),
            "merge_host_update accepted an auth_password_ref off the wire"
        );
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
        merge_host_update(&mut host, &incoming).unwrap();
        assert_eq!(host.label, original_label, "unknown fields should be a no-op");
    }

    #[test]
    fn merge_can_clear_optional_fields() {
        // Setting auth_key_id to null in the JSON DOES clear it.
        let mut host = full_host();
        host.auth_key_id = Some(uuid::Uuid::nil());
        let incoming = serde_json::json!({ "auth_key_id": null });
        merge_host_update(&mut host, &incoming).unwrap();
        assert!(host.auth_key_id.is_none());
    }
}
