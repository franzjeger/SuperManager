//! SSH key, host, and operation JSON-RPC handlers.
//!
//! Covers the full SSH surface area: key generation/import/export,
//! host CRUD with merge semantics, command execution, connection
//! testing, API-token storage, and the parallel push/revoke fan-out.

use std::collections::HashMap;
use std::sync::Arc;

use supermgr_core::host::{Host, HostSummary};
// The one definition of "which secrets does this entity own", shared with
// the daemon and covered by the invariant tests in `supermgr-core`.
use supermgr_core::secret_lifecycle::SecretOwner;
use supermgr_core::ssh::audit::{AuditAction, AuditEntry};
use supermgr_core::ssh::authorized_keys::{push_public_key, revoke_public_key, PushResult};
use supermgr_core::ssh::key::{SshKey, SshKeySummary, SshKeyType};
use supermgr_core::ssh::keygen;

use crate::protocol::{self, Response};
use crate::server::{
    connect_to_host_owned, get_uuid_param, merge_host_update, EngineServer,
};

/// Two operations share fan-out plumbing in `handle_ssh_fanout_key_op`.
/// Encoded as an enum so we can branch the inner SSH call without
/// duplicating the connect/disconnect/error-collect scaffolding.
#[derive(Copy, Clone)]
pub(crate) enum FanoutOp {
    Push,
    Revoke,
}

/// Reject anything that isn't a parseable OpenSSH certificate before it
/// reaches the keychain, returning a message fit for a dialog.
///
/// The common mistake this catches is handing over the public key
/// (`id_ed25519.pub`) instead of the certificate (`id_ed25519-cert.pub`);
/// both are one line of base64 with a similar shape, and only the second
/// carries a CA signature. `from_openssh` rejects the plain key because
/// its algorithm name lacks the `-cert-v01@openssh.com` suffix.
fn validate_openssh_certificate(cert: &str) -> Result<(), String> {
    ssh_key::Certificate::from_openssh(cert.trim()).map(|_| ()).map_err(|e| {
        format!(
            "not a valid OpenSSH certificate ({e}). Expected the contents of a \
             `*-cert.pub` file — the CA-signed certificate, not the public key."
        )
    })
}

/// Audit line for a key-lifecycle event. These have no target host, so
/// the host columns stay empty and the UI omits them.
fn audit_key_event(action: AuditAction, key_name: &str, fingerprint: &str) {
    crate::ssh::audit::append_audit(&AuditEntry {
        timestamp: chrono::Utc::now(),
        action,
        key_name: key_name.to_owned(),
        key_fingerprint: fingerprint.to_owned(),
        host_label: String::new(),
        hostname: String::new(),
        port: 0,
        success: true,
    });
}

impl EngineServer {
    pub(crate) async fn handle_ssh_generate_key(&self, id: u64, params: serde_json::Value) -> Response {
        let key_type_str = params.get("key_type").and_then(|v| v.as_str()).unwrap_or("ed25519");
        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("Unnamed");
        let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("");
        let tags_json = params.get("tags_json").and_then(|v| v.as_str()).unwrap_or("[]");

        let key_type = match key_type_str {
            "rsa2048" | "rsa" => SshKeyType::Rsa2048,
            "rsa4096" => SshKeyType::Rsa4096,
            _ => SshKeyType::Ed25519,
        };

        let generated = match keygen::generate_key(key_type, name) {
            Ok(g) => g,
            Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        };

        // Store private key in secret store.
        let key_id = uuid::Uuid::new_v4();
        let secret_label = format!("supermgr/ssh/{key_id}/privkey");
        if let Err(e) = self.secrets.store(&secret_label, generated.private_key_pem.as_bytes()).await {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("store secret: {e}"));
        }

        let tags: Vec<String> = serde_json::from_str(tags_json).unwrap_or_default();

        let ssh_key = SshKey {
            id: key_id,
            name: name.to_owned(),
            description: description.to_owned(),
            key_type,
            public_key: generated.public_key,
            private_key_ref: supermgr_core::vpn::profile::SecretRef(secret_label),
            fingerprint: generated.fingerprint,
            tags,
            deployed_to: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let mut state = self.state.lock().await;
        if let Err(e) = state.save_ssh_key(&ssh_key) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save key: {e}"));
        }
        let fingerprint = ssh_key.fingerprint.clone();
        state.ssh_keys.insert(key_id, ssh_key);
        audit_key_event(AuditAction::Generate, name, &fingerprint);

        Response::ok(id, serde_json::json!(key_id.to_string()))
    }

    pub(crate) async fn handle_ssh_list_keys(&self, id: u64) -> Response {
        let state = self.state.lock().await;
        let summaries: Vec<SshKeySummary> = state.ssh_keys.values().map(SshKeySummary::from).collect();
        match serde_json::to_value(&summaries) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_ssh_get_key(&self, id: u64, params: serde_json::Value) -> Response {
        let key_id = match get_uuid_param(&params, "key_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let state = self.state.lock().await;
        match state.ssh_keys.get(&key_id) {
            Some(key) => match serde_json::to_value(key) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            None => Response::err(id, protocol::INVALID_PARAMS, format!("key not found: {key_id}")),
        }
    }

    pub(crate) async fn handle_ssh_delete_key(&self, id: u64, params: serde_json::Value) -> Response {
        let key_id = match get_uuid_param(&params, "key_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let removed = {
            let mut state = self.state.lock().await;
            match state.ssh_keys.remove(&key_id) {
                Some(k) => {
                    let _ = state.delete_ssh_key_file(key_id);
                    Some(k)
                }
                None => None,
            }
        };
        if let Some(removed) = removed {
            // The private key itself outlived every delete until now, so
            // the store accumulated PEMs for keys the UI no longer showed
            // — and the backup archive tars that store whole. Taken from
            // the record's own `SecretRef` rather than a rebuilt label, so
            // an imported key with a non-default label is cleaned too.
            for label in removed.secret_labels() {
                if let Err(e) = self.secrets.delete(&label).await {
                    tracing::warn!("deleting key {key_id}: secret {label} not removed: {e}");
                }
            }
            // Recorded from the removed key, since after this point the
            // name and fingerprint exist nowhere else.
            audit_key_event(AuditAction::Delete, &removed.name, &removed.fingerprint);
        }
        Response::ok(id, serde_json::json!(null))
    }

    pub(crate) async fn handle_ssh_export_public_key(&self, id: u64, params: serde_json::Value) -> Response {
        let key_id = match get_uuid_param(&params, "key_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let state = self.state.lock().await;
        match state.ssh_keys.get(&key_id) {
            Some(key) => Response::ok(id, serde_json::json!(key.public_key)),
            None => Response::err(id, protocol::INVALID_PARAMS, format!("key not found: {key_id}")),
        }
    }

    pub(crate) async fn handle_ssh_import_key(&self, id: u64, params: serde_json::Value) -> Response {
        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("Imported");
        let public_key = match params.get("public_key").and_then(|v| v.as_str()) {
            Some(pk) => pk,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing public_key"),
        };
        let private_key_pem = match params.get("private_key_pem").and_then(|v| v.as_str()) {
            Some(pk) => pk,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing private_key_pem"),
        };
        let key_type_str = params.get("key_type").and_then(|v| v.as_str()).unwrap_or("ed25519");

        let key_type = match key_type_str {
            "rsa2048" | "rsa" => SshKeyType::Rsa2048,
            "rsa4096" => SshKeyType::Rsa4096,
            _ => SshKeyType::Ed25519,
        };

        let fingerprint = match keygen::compute_fingerprint(public_key) {
            Ok(fp) => fp,
            Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        };

        let key_id = uuid::Uuid::new_v4();
        let secret_label = format!("supermgr/ssh/{key_id}/privkey");
        if let Err(e) = self.secrets.store(&secret_label, private_key_pem.as_bytes()).await {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("store secret: {e}"));
        }

        let ssh_key = SshKey {
            id: key_id,
            name: name.to_owned(),
            description: String::new(),
            key_type,
            public_key: public_key.to_owned(),
            private_key_ref: supermgr_core::vpn::profile::SecretRef(secret_label),
            fingerprint,
            tags: Vec::new(),
            deployed_to: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let mut state = self.state.lock().await;
        if let Err(e) = state.save_ssh_key(&ssh_key) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save key: {e}"));
        }
        let fingerprint = ssh_key.fingerprint.clone();
        state.ssh_keys.insert(key_id, ssh_key);
        audit_key_event(AuditAction::Import, name, &fingerprint);

        Response::ok(id, serde_json::json!(key_id.to_string()))
    }

    pub(crate) async fn handle_ssh_import_keys_scan(&self, id: u64, params: serde_json::Value) -> Response {
        let directory = params.get("directory").and_then(|v| v.as_str()).unwrap_or("~/.ssh");
        let expanded = if directory.starts_with("~/") {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
            format!("{}/{}", home, &directory[2..])
        } else {
            directory.to_owned()
        };
        let candidates = supermgr_core::ssh::import::scan_ssh_directory(std::path::Path::new(&expanded));
        match serde_json::to_value(&candidates) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_ssh_add_host(&self, id: u64, params: serde_json::Value) -> Response {
        let host_json = match params.get("host_json").and_then(|v| v.as_str()) {
            Some(j) => j,
            None => {
                // Try parsing params directly as a host.
                match serde_json::from_value::<Host>(params.clone()) {
                    Ok(mut host) => {
                        host.id = uuid::Uuid::new_v4();
                        host.created_at = chrono::Utc::now();
                        host.updated_at = chrono::Utc::now();
                        let mut state = self.state.lock().await;
                        if let Err(e) = state.save_ssh_host(&host) {
                            return Response::err(id, protocol::INTERNAL_ERROR, format!("save host: {e}"));
                        }
                        let host_id = host.id;
                        state.ssh_hosts.insert(host.id, host);
                        return Response::ok(id, serde_json::json!(host_id.to_string()));
                    }
                    Err(_) => return Response::err(id, protocol::INVALID_PARAMS, "missing host_json"),
                }
            }
        };

        let mut host: Host = match serde_json::from_str(host_json) {
            Ok(h) => h,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("invalid host JSON: {e}")),
        };

        host.id = uuid::Uuid::new_v4();
        host.created_at = chrono::Utc::now();
        host.updated_at = chrono::Utc::now();

        // Store password if provided alongside host_json
        if let Some(password) = params.get("password").and_then(|v| v.as_str()) {
            if !password.is_empty() {
                let secret_label = format!("supermgr/ssh/host/{}/password", host.id);
                if let Err(e) = self.secrets.store(&secret_label, password.as_bytes()).await {
                    return Response::err(id, protocol::INTERNAL_ERROR, format!("store password: {e}"));
                }
                host.auth_password_ref = Some(supermgr_core::vpn::profile::SecretRef(secret_label));
            }
        }

        // Same for an OpenSSH certificate. The engine owns the secret
        // label rather than accepting `auth_cert_ref` off the wire, so a
        // caller can't aim a host's cert ref at an arbitrary keychain
        // entry — identical reasoning to the password above.
        if let Some(cert) = params.get("certificate").and_then(|v| v.as_str()) {
            if !cert.trim().is_empty() {
                if let Err(msg) = validate_openssh_certificate(cert) {
                    return Response::err(id, protocol::INVALID_PARAMS, msg);
                }
                let secret_label = format!("supermgr/ssh/host/{}/certificate", host.id);
                if let Err(e) = self.secrets.store(&secret_label, cert.as_bytes()).await {
                    return Response::err(
                        id,
                        protocol::INTERNAL_ERROR,
                        format!("store certificate: {e}"),
                    );
                }
                host.auth_cert_ref = Some(supermgr_core::vpn::profile::SecretRef(secret_label));
            }
        }

        let mut state = self.state.lock().await;
        if let Err(e) = state.save_ssh_host(&host) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save host: {e}"));
        }
        let host_id = host.id;
        state.ssh_hosts.insert(host.id, host);

        Response::ok(id, serde_json::json!(host_id.to_string()))
    }

    pub(crate) async fn handle_ssh_update_host(&self, id: u64, params: serde_json::Value) -> Response {
        // First step in the typed-RPC migration. The wire format is
        // unchanged — the param dict is the same — but we deserialise
        // it via `protocol::rpc::SshUpdateHostParams` up front. Future
        // callers can't accidentally mistype `host_id` as `hostId` or
        // forget `host_json` without serde flagging it at parse time
        // with a useful error message.
        let p: protocol::rpc::SshUpdateHostParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("bad params: {e}")),
        };

        // Parse the incoming JSON as an arbitrary object so we can MERGE the
        // editable fields into the existing host instead of replacing the
        // whole record. The previous "deserialize-as-Host-and-replace"
        // approach silently clobbered fields that the GUI doesn't send
        // (auth_password_ref, vpn_profile_id, has_api, pinned, created_at,
        // …), destroying stored secrets and pin state on every edit.
        let incoming: serde_json::Value = match serde_json::from_str(&p.host_json) {
            Ok(v) => v,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("invalid host JSON: {e}")),
        };

        let mut state = self.state.lock().await;
        let mut host = match state.ssh_hosts.get(&p.host_id).cloned() {
            Some(h) => h,
            None => return Response::err(id, protocol::INVALID_PARAMS, format!("host not found: {}", p.host_id)),
        };

        merge_host_update(&mut host, &incoming);
        host.updated_at = chrono::Utc::now();

        if let Err(e) = state.save_ssh_host(&host) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save host: {e}"));
        }
        state.ssh_hosts.insert(p.host_id, host);

        Response::ok(id, serde_json::json!(null))
    }

    pub(crate) async fn handle_ssh_list_hosts(&self, id: u64) -> Response {
        let state = self.state.lock().await;
        let summaries: Vec<HostSummary> = state.ssh_hosts.values().map(HostSummary::from).collect();
        match serde_json::to_value(&summaries) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_ssh_get_host(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let state = self.state.lock().await;
        match state.ssh_hosts.get(&host_id) {
            Some(host) => match serde_json::to_value(host) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            None => Response::err(id, protocol::INVALID_PARAMS, format!("host not found: {host_id}")),
        }
    }

    pub(crate) async fn handle_ssh_delete_host(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let mut state = self.state.lock().await;
        let removed = state.ssh_hosts.remove(&host_id);
        if removed.is_some() {
            let _ = state.delete_ssh_host_file(host_id);
        }
        drop(state);

        // Same omission the key path had: the host record went away and
        // its stored password stayed behind forever. Every `SecretRef`
        // the host owns is cleared, not just the password — a FortiGate
        // or UniFi API token is just as much a credential.
        if let Some(host) = removed {
            for label in host.secret_labels() {
                if let Err(e) = self.secrets.delete(&label).await {
                    tracing::warn!("deleting host {host_id}: secret {label} not removed: {e}");
                }
            }
        }
        Response::ok(id, serde_json::json!(null))
    }

    pub(crate) async fn handle_ssh_toggle_pin(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let mut state = self.state.lock().await;
        if let Some(host) = state.ssh_hosts.get_mut(&host_id) {
            host.pinned = !host.pinned;
            host.updated_at = chrono::Utc::now();
            let host_clone = host.clone();
            let _ = state.save_ssh_host(&host_clone);
        }
        let summaries: Vec<HostSummary> = state.ssh_hosts.values().map(HostSummary::from).collect();
        match serde_json::to_value(&summaries) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_ssh_set_password(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let password = match params.get("password").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing password"),
        };

        let secret_label = format!("supermgr/ssh/host/{host_id}/password");
        if let Err(e) = self.secrets.store(&secret_label, password.as_bytes()).await {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("store secret: {e}"));
        }

        let mut state = self.state.lock().await;
        if let Some(host) = state.ssh_hosts.get_mut(&host_id) {
            host.auth_password_ref = Some(supermgr_core::vpn::profile::SecretRef(secret_label));
            host.updated_at = chrono::Utc::now();
            let host_clone = host.clone();
            let _ = state.save_ssh_host(&host_clone);
        }

        Response::ok(id, serde_json::json!(null))
    }

    /// Store an OpenSSH certificate for an existing host and point
    /// `auth_cert_ref` at it. The edit-path counterpart to the
    /// `certificate` param on `ssh_add_host`, and the exact shape of
    /// `ssh_set_password` — including the engine owning the label.
    ///
    /// Validated before it is stored. The connect path treats an
    /// unparseable certificate as non-fatal and falls back to plain key
    /// auth, which is right at connect time but would make a typo here
    /// look like a working save followed by a mysteriously
    /// key-authenticated session. Rejecting on write is where the
    /// operator can still act on the error.
    pub(crate) async fn handle_ssh_set_certificate(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let certificate = match params.get("certificate").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing certificate"),
        };
        if let Err(msg) = validate_openssh_certificate(certificate) {
            return Response::err(id, protocol::INVALID_PARAMS, msg);
        }

        let secret_label = format!("supermgr/ssh/host/{host_id}/certificate");
        let mut state = self.state.lock().await;
        // Check the host exists BEFORE storing the secret. Storing first
        // and returning success for an unknown host_id (a stale id, or a
        // host removed between list and set) left a certificate secret no
        // Host references — which the secret_labels()-driven cleanup on
        // host delete never reaches. Held under the one lock so the host
        // cannot vanish between the check and the update.
        if !state.ssh_hosts.contains_key(&host_id) {
            return Response::err(id, protocol::INVALID_PARAMS, "host not found".to_owned());
        }
        if let Err(e) = self.secrets.store(&secret_label, certificate.as_bytes()).await {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("store secret: {e}"));
        }
        if let Some(host) = state.ssh_hosts.get_mut(&host_id) {
            host.auth_cert_ref = Some(supermgr_core::vpn::profile::SecretRef(secret_label));
            host.updated_at = chrono::Utc::now();
            let host_clone = host.clone();
            let _ = state.save_ssh_host(&host_clone);
        }

        Response::ok(id, serde_json::json!(null))
    }

    pub(crate) async fn handle_ssh_execute_command(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let command = match params.get("command").and_then(|v| v.as_str()) {
            Some(c) => c.to_owned(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing command"),
        };

        let (_host, session) = match self.connect_to_host(host_id).await {
            Ok(hs) => hs,
            Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, e),
        };

        match session.exec(&command).await {
            Ok((exit_code, stdout, stderr)) => {
                let _ = session.disconnect().await;
                Response::ok(id, serde_json::json!({
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                }))
            }
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_ssh_test_connection(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };

        // Use the typed connect path so the Swift client can
        // distinguish `ssh_auth` (wrong password — pop a re-enter
        // sheet) from `ssh_network` (host unreachable — suggest
        // connecting the VPN). Previously this swallowed the error
        // into the *success* payload with `{"ssh": e}` so the UI
        // had to string-match.
        match self.connect_to_host_typed(host_id).await {
            Ok((_host, session)) => {
                let _ = session.disconnect().await;
                Response::ok(id, serde_json::json!({"ssh": "ok"}))
            }
            Err(e) => Response::err_engine(id, &e),
        }
    }

    /// Manually set an API token for a host. Used when the FortiGate
    /// admin generates a token outside SuperManager and the user
    /// pastes it into the GUI. The token is stored in the keychain
    /// under a label keyed by host id; the host record gains a
    /// `SecretRef` pointing at it.
    pub(crate) async fn handle_ssh_set_api_token(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let token = match params.get("token").and_then(|v| v.as_str()) {
            Some(s) if !s.trim().is_empty() => s.trim().to_owned(),
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing or empty token".to_owned(),
                )
            }
        };
        let api_port = params
            .get("api_port")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as u16)
            .unwrap_or(443);

        let label = format!("ssh/{}/fortigate-api-token", host_id.simple());
        let mut state = self.state.lock().await;
        // Check the host exists before storing — same reason as
        // set_certificate. This handler already errored on a missing host,
        // but only after storing the token, orphaning it.
        if !state.ssh_hosts.contains_key(&host_id) {
            return Response::err(id, protocol::INVALID_PARAMS, "host not found".to_owned());
        }
        if let Err(e) = self.secrets.store(&label, token.as_bytes()).await {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("store token: {e}"));
        }
        let host = match state.ssh_hosts.get_mut(&host_id) {
            Some(h) => h,
            None => return Response::err(id, protocol::INVALID_PARAMS, "host not found".to_owned()),
        };
        host.api_token_ref =
            Some(supermgr_core::vpn::profile::SecretRef::new(label.clone()));
        host.api_port = Some(api_port);
        host.updated_at = chrono::Utc::now();
        let snapshot = host.clone();
        if let Err(e) = state.save_ssh_host(&snapshot) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save host: {e}"));
        }

        Response::ok(
            id,
            serde_json::json!({
                "stored": true,
                "label": label,
                "api_port": api_port,
            }),
        )
    }

    /// Forget the stored API token for a host. The keychain entry
    /// is deleted (best-effort — a leftover entry is harmless and
    /// will be overwritten by the next set/generate call) and the
    /// host record's `api_token_ref` is cleared.
    pub(crate) async fn handle_ssh_clear_api_token(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };

        let label = {
            let state = self.state.lock().await;
            let host = match state.ssh_hosts.get(&host_id) {
                Some(h) => h,
                None => return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "host not found".to_owned(),
                ),
            };
            host.api_token_ref.as_ref().map(|r| r.0.clone())
        };

        // Best-effort delete; ignore the result so a missing entry
        // doesn't surface as an error to the user. The important
        // thing is the host record stops referencing the secret.
        if let Some(ref l) = label {
            let _ = self.secrets.delete(l).await;
        }

        let mut state = self.state.lock().await;
        let host = match state.ssh_hosts.get_mut(&host_id) {
            Some(h) => h,
            None => return Response::err(id, protocol::INVALID_PARAMS, "host not found".to_owned()),
        };
        host.api_token_ref = None;
        host.updated_at = chrono::Utc::now();
        let snapshot = host.clone();
        if let Err(e) = state.save_ssh_host(&snapshot) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("save host: {e}"));
        }

        Response::ok(id, serde_json::json!({"cleared": true}))
    }

    pub(crate) async fn handle_ssh_push_key(&self, id: u64, params: serde_json::Value) -> Response {
        self.handle_ssh_fanout_key_op(id, params, FanoutOp::Push).await
    }

    pub(crate) async fn handle_ssh_revoke_key(&self, id: u64, params: serde_json::Value) -> Response {
        self.handle_ssh_fanout_key_op(id, params, FanoutOp::Revoke).await
    }

    /// Shared fan-out implementation for `ssh_push_key` and `ssh_revoke_key`.
    ///
    /// **Why fan-out:** the previous implementation iterated hosts in a
    /// for-loop, making the wall-clock cost N × (connect + push) seconds.
    /// On 30-host pushes that's a coffee-break. We now spawn one task per
    /// host and run up to `MAX_CONCURRENT_SSH_OPS` in parallel via
    /// `tokio::task::JoinSet`, so 30 hosts finishes in roughly ⌈30/8⌉
    /// rounds — about 5× faster on the realistic case.
    ///
    /// **Why a cap:** a free-for-all of `tokio::spawn` would let one slow
    /// gateway hold open 100 file descriptors and exhaust the daemon's
    /// resource limits. 8 is a number that's comfortably sub-`ulimit -n`,
    /// matches what most CI tools default to, and is fast enough that no
    /// human will notice the difference vs. truly unbounded.
    ///
    /// The state mutex is touched only twice per call: once up-front to
    /// snapshot the public key, and once at the end to update
    /// `key.deployed_to`. None of the SSH I/O happens with the lock held.
    async fn handle_ssh_fanout_key_op(
        &self,
        id: u64,
        params: serde_json::Value,
        op: FanoutOp,
    ) -> Response {
        const MAX_CONCURRENT_SSH_OPS: usize = 8;

        let key_id = match get_uuid_param(&params, "key_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let host_ids_json = params.get("host_ids_json").and_then(|v| v.as_str()).unwrap_or("[]");
        let use_sudo = params.get("use_sudo").and_then(|v| v.as_bool()).unwrap_or(false);

        let host_ids: Vec<uuid::Uuid> = match serde_json::from_str(host_ids_json) {
            Ok(ids) => ids,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, format!("invalid host_ids: {e}")),
        };

        // Name and fingerprint travel with the public key so each spawned
        // probe can write its own audit line without re-locking state.
        let (public_key, key_name, key_fingerprint) = {
            let state = self.state.lock().await;
            match state.ssh_keys.get(&key_id) {
                Some(key) => (
                    key.public_key.clone(),
                    key.name.clone(),
                    key.fingerprint.clone(),
                ),
                None => return Response::err(id, protocol::INVALID_PARAMS, format!("key not found: {key_id}")),
            }
        };

        // Bound the parallelism with a semaphore. This is cheaper than
        // batching with `chunks(N)` because slow hosts don't hold up
        // a whole batch — a fast host that finishes early frees its
        // permit immediately for the next pending host.
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SSH_OPS));
        let mut joinset = tokio::task::JoinSet::new();
        for hid in host_ids {
            let permits = Arc::clone(&permits);
            let public_key = public_key.clone();
            let key_name = key_name.clone();
            let key_fingerprint = key_fingerprint.clone();
            // Spawn-friendly handle: clone just the two Arcs we need so
            // the closure is `'static`. Cheap — these are reference-counted
            // pointers to the same shared state and secret store.
            let state = Arc::clone(&self.state);
            let secrets = Arc::clone(&self.secrets);
            joinset.spawn(async move {
                let _permit = permits.acquire().await.expect("semaphore not closed");
                match connect_to_host_owned(&state, &secrets, hid).await {
                    Ok((host, session)) => {
                        let outcome = match op {
                            FanoutOp::Push => push_public_key(&session, &public_key, use_sudo).await,
                            FanoutOp::Revoke => revoke_public_key(&session, &public_key, use_sudo).await,
                        };
                        let result = match outcome {
                            Ok(()) => PushResult {
                                host_id: hid.to_string(),
                                host_label: host.label.clone(),
                                success: true,
                                message: match op {
                                    FanoutOp::Push => "key pushed".into(),
                                    FanoutOp::Revoke => "key revoked".into(),
                                },
                            },
                            Err(e) => PushResult {
                                host_id: hid.to_string(),
                                host_label: host.label.clone(),
                                success: false,
                                message: e.to_string(),
                            },
                        };
                        let _ = session.disconnect().await;
                        // The audit log's whole purpose: which key reached
                        // which host, when, and whether it took. Written for
                        // failures too — "we tried and it was refused" is the
                        // entry you want when a customer asks.
                        crate::ssh::audit::append_audit(&AuditEntry {
                            timestamp: chrono::Utc::now(),
                            action: match op {
                                FanoutOp::Push => AuditAction::Push,
                                FanoutOp::Revoke => AuditAction::Revoke,
                            },
                            key_name: key_name.clone(),
                            key_fingerprint: key_fingerprint.clone(),
                            host_label: host.label.clone(),
                            hostname: host.hostname.clone(),
                            port: host.port,
                            success: result.success,
                        });
                        result
                    }
                    Err(e) => {
                        // Connect-time failures: look up the label via the
                        // shared state so the GUI shows a useful row.
                        let (label, hostname, port) = {
                            let st = state.lock().await;
                            st.ssh_hosts
                                .get(&hid)
                                .map(|h| (h.label.clone(), h.hostname.clone(), h.port))
                                .unwrap_or_default()
                        };
                        // A host we could not even reach is still an audit
                        // event — the attempt happened.
                        crate::ssh::audit::append_audit(&AuditEntry {
                            timestamp: chrono::Utc::now(),
                            action: match op {
                                FanoutOp::Push => AuditAction::Push,
                                FanoutOp::Revoke => AuditAction::Revoke,
                            },
                            key_name: key_name.clone(),
                            key_fingerprint: key_fingerprint.clone(),
                            host_label: label.clone(),
                            hostname,
                            port,
                            success: false,
                        });
                        PushResult {
                            host_id: hid.to_string(),
                            host_label: label,
                            success: false,
                            message: e,
                        }
                    }
                }
            });
        }

        let mut results = Vec::with_capacity(joinset.len());
        while let Some(joined) = joinset.join_next().await {
            match joined {
                Ok(r) => results.push(r),
                Err(e) => {
                    // A panicked task is a daemon bug; surface it loudly.
                    tracing::error!(error = %e, "SSH fan-out task panicked");
                }
            }
        }

        // Update deployed_to on the key. Push appends, revoke removes.
        {
            let mut state = self.state.lock().await;
            if let Some(key) = state.ssh_keys.get_mut(&key_id) {
                for r in &results {
                    if r.success {
                        let hid = uuid::Uuid::parse_str(&r.host_id).unwrap_or_default();
                        match op {
                            FanoutOp::Push => {
                                if !key.deployed_to.contains(&hid) {
                                    key.deployed_to.push(hid);
                                }
                            }
                            FanoutOp::Revoke => {
                                key.deployed_to.retain(|d| *d != hid);
                            }
                        }
                    }
                }
                key.updated_at = chrono::Utc::now();
                let key_clone = key.clone();
                let _ = state.save_ssh_key(&key_clone);
            }
        }

        match serde_json::to_value(&results) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Probe every SSH host's reachability, store the result, and return it.
    ///
    /// This is the writer `host_health` never had on this side. The Linux
    /// D-Bus daemon has run the same loop for a long time
    /// (`supermgrd/src/daemon.rs`, `spawn_health_check_task`), but the engine
    /// — which is what the macOS app talks to via supermgrd-mac — only ever
    /// had the reader. `ssh_host_health` therefore returned an empty map
    /// forever, and the health dot beside every host in the app was
    /// permanently "never measured".
    ///
    /// **TCP connect, not SSH.** Reachability here means "something is
    /// listening on hostname:port" — a three-way handshake and nothing more.
    /// The obvious alternative, reusing `ssh_test_connection`, performs a full
    /// SSH authentication: at a 30-second interval across a handful of hosts
    /// that is tens of thousands of logins a day, each one a line (often
    /// several) in the customer's auth log, with fail2ban and account-lockout
    /// exposure to match. A monitoring feature must not be a self-inflicted
    /// denial of service on the equipment it monitors.
    ///
    /// **Caller-driven, not a background ticker.** The Linux daemon owns its
    /// own 60-second schedule. Here the app calls this on whatever interval
    /// the operator chose, which is what lets "off" genuinely mean off: no
    /// call, no probe, no traffic. A daemon-side ticker would keep probing
    /// customer equipment after the operator switched the feature off.
    ///
    /// Returns the full map so one round-trip both refreshes and reads;
    /// `ssh_host_health` remains for reading the cache without probing.
    pub(crate) async fn handle_ssh_probe_hosts(&self, id: u64) -> Response {
        /// Same budget the Linux loop uses. Long enough for a sleepy gateway
        /// over a VPN, short enough that one dead host can't stall the sweep.
        const PROBE_TIMEOUT_MS: u64 = 3_000;
        /// Higher than the SSH fan-out's cap because a TCP connect is far
        /// cheaper than an SSH session, but still bounded: an unbounded spawn
        /// over a large fleet would hold one file descriptor per host.
        const MAX_CONCURRENT_PROBES: usize = 16;

        // Snapshot under the lock, probe without it. None of the network I/O
        // happens while the state mutex is held — the same discipline the key
        // fan-out above follows.
        let hosts: Vec<(uuid::Uuid, String, u16)> = {
            let state = self.state.lock().await;
            state
                .ssh_hosts
                .values()
                .map(|h| (h.id, h.hostname.clone(), h.port))
                .collect()
        };

        if hosts.is_empty() {
            return match serde_json::to_value(HashMap::<String, bool>::new()) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            };
        }

        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
        let mut joinset = tokio::task::JoinSet::new();
        for (host_id, hostname, port) in hosts {
            let permits = Arc::clone(&permits);
            joinset.spawn(async move {
                let _permit = permits.acquire().await.expect("semaphore not closed");
                let reachable = crate::probes::tcp_check(&hostname, port, PROBE_TIMEOUT_MS).await;
                (host_id, reachable)
            });
        }

        let mut results: Vec<(uuid::Uuid, bool)> = Vec::new();
        while let Some(joined) = joinset.join_next().await {
            // A panicking probe task must not lose the whole sweep; the other
            // hosts' results are still worth returning.
            if let Ok(pair) = joined {
                results.push(pair);
            }
        }

        let health: HashMap<String, bool> = {
            let mut state = self.state.lock().await;
            for (host_id, reachable) in &results {
                state.host_health.insert(*host_id, *reachable);
            }
            // Deliberately return the whole map rather than just this sweep's
            // results: a host deleted mid-sweep should not linger, and a
            // caller that missed a tick still gets a complete picture.
            state
                .host_health
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect()
        };

        match serde_json::to_value(&health) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Read the cached reachability map without probing anything.
    /// Populated by `ssh_probe_hosts`; empty until the first sweep runs.
    pub(crate) async fn handle_ssh_host_health(&self, id: u64) -> Response {
        let state = self.state.lock().await;
        let health: HashMap<String, bool> = state
            .host_health
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        match serde_json::to_value(&health) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real ed25519 certificate from `ssh-keygen -s ca -I testid -n root`.
    /// Only parsed, never validity-checked, so the embedded expiry can't
    /// rot the test.
    const CERT: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIJ9a/RUT34M6KpfmIHf+OOJMzRUEfVeqUOI02LzMhfNtAAAAIOUk18Uqim7mDZikSU6bmR7b9zjAFqL88V8dFZXWCen/AAAAAAAAAAAAAAABAAAABnRlc3RpZAAAAAgAAAAEcm9vdAAAAABqd03QAAAAAGxXMCUAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDzWHnfe5a0E+lvGZ9ye+4ItyAp57rjW9E01WbNw7fkoAAAAFMAAAALc3NoLWVkMjU1MTkAAABATEJm0QvR/7+XQ0ya/o9gNs+Ew6HvmNhR3hbiW0jwuVL2Fbpc/cMxapnKqUzZAzNkMvxPQGtpUWcXxx5Q4siCDg== testkey";

    /// The public key the certificate above was signed over. Shape-alike,
    /// and the thing an operator reaches for by mistake.
    const PLAIN_PUBKEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOUk18Uqim7mDZikSU6bmR7b9zjAFqL88V8dFZXWCen/ testkey";

    #[test]
    fn accepts_a_real_openssh_certificate() {
        assert!(validate_openssh_certificate(CERT).is_ok());
    }

    #[test]
    fn accepts_a_certificate_with_surrounding_whitespace() {
        // `cat`-ing a *-cert.pub into a text field brings a trailing
        // newline with it; a save must not fail on that.
        let padded = format!("\n  {CERT}\n\n");
        assert!(validate_openssh_certificate(&padded).is_ok());
    }

    /// The property the connect path relies on: `from_openssh` only trims
    /// the END, so LEADING whitespace makes it fail. validate accepts such
    /// a cert (it trims first) and the value is stored as-is, so connect
    /// must trim before parsing or cert auth silently downgrades to plain
    /// pubkey. If a future ssh-key release starts tolerating leading
    /// whitespace this test flags that the connect-side trim is redundant.
    #[test]
    fn from_openssh_requires_leading_whitespace_trimmed() {
        let leading = format!("  {CERT}");
        assert!(
            ssh_key::Certificate::from_openssh(&leading).is_err(),
            "from_openssh tolerated leading whitespace — the connect-side trim may be unnecessary"
        );
        assert!(ssh_key::Certificate::from_openssh(leading.trim()).is_ok());
    }

    #[test]
    fn rejects_the_plain_public_key() {
        // The mistake worth catching: handing over id_ed25519.pub
        // instead of id_ed25519-cert.pub. Without this, the material
        // stores fine and the host silently key-authenticates forever.
        let err = validate_openssh_certificate(PLAIN_PUBKEY)
            .expect_err("a plain public key is not a certificate");
        assert!(
            err.contains("*-cert.pub"),
            "the error must point at the right file, got: {err}"
        );
    }

    #[test]
    fn rejects_empty_and_garbage() {
        for bad in ["", "   ", "not a cert", "ssh-ed25519-cert-v01@openssh.com !!!"] {
            assert!(
                validate_openssh_certificate(bad).is_err(),
                "should have rejected {bad:?}"
            );
        }
    }
}
