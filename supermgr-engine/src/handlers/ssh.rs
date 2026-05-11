//! SSH key, host, and operation JSON-RPC handlers.
//!
//! Covers the full SSH surface area: key generation/import/export,
//! host CRUD with merge semantics, command execution, connection
//! testing, API-token storage, and the parallel push/revoke fan-out.

use std::collections::HashMap;
use std::sync::Arc;

use supermgr_core::host::{Host, HostSummary};
use supermgr_core::ssh::key::{SshKey, SshKeySummary, SshKeyType};

use crate::protocol::{self, Response};
use crate::server::{
    connect_to_host_owned, get_uuid_param, merge_host_update, EngineServer,
};
use crate::ssh::{keygen, push, revoke};

/// Two operations share fan-out plumbing in `handle_ssh_fanout_key_op`.
/// Encoded as an enum so we can branch the inner SSH call without
/// duplicating the connect/disconnect/error-collect scaffolding.
#[derive(Copy, Clone)]
pub(crate) enum FanoutOp {
    Push,
    Revoke,
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
        state.ssh_keys.insert(key_id, ssh_key);

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
        let mut state = self.state.lock().await;
        if state.ssh_keys.remove(&key_id).is_some() {
            let _ = state.delete_ssh_key_file(key_id);
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
        state.ssh_keys.insert(key_id, ssh_key);

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
        let candidates = crate::ssh::import::scan_ssh_directory(std::path::Path::new(&expanded));
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
        if state.ssh_hosts.remove(&host_id).is_some() {
            let _ = state.delete_ssh_host_file(host_id);
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
        if let Err(e) = self.secrets.store(&label, token.as_bytes()).await {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("store token: {e}"));
        }

        let mut state = self.state.lock().await;
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

        let public_key = {
            let state = self.state.lock().await;
            match state.ssh_keys.get(&key_id) {
                Some(key) => key.public_key.clone(),
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
                            FanoutOp::Push => push::push_public_key(&session, &public_key, use_sudo).await,
                            FanoutOp::Revoke => revoke::revoke_public_key(&session, &public_key, use_sudo).await,
                        };
                        let result = match outcome {
                            Ok(()) => push::PushResult {
                                host_id: hid.to_string(),
                                host_label: host.label.clone(),
                                success: true,
                                message: match op {
                                    FanoutOp::Push => "key pushed".into(),
                                    FanoutOp::Revoke => "key revoked".into(),
                                },
                            },
                            Err(e) => push::PushResult {
                                host_id: hid.to_string(),
                                host_label: host.label.clone(),
                                success: false,
                                message: e.to_string(),
                            },
                        };
                        let _ = session.disconnect().await;
                        result
                    }
                    Err(e) => {
                        // Connect-time failures: look up the label via the
                        // shared state so the GUI shows a useful row.
                        let label = {
                            let st = state.lock().await;
                            st.ssh_hosts.get(&hid).map(|h| h.label.clone()).unwrap_or_default()
                        };
                        push::PushResult {
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
