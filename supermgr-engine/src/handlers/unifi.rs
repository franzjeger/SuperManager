//! `UniFi` controller JSON-RPC handlers.
//!
//! Inform-URL push, controller credential CRUD, connection test, and
//! the generic `unifi_api` REST proxy.

use crate::protocol::{self, Response};
use crate::server::{get_uuid_param, EngineServer};

impl EngineServer {
    pub(crate) async fn handle_unifi_set_inform(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let inform_url = match params.get("inform_url").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing inform_url".to_owned(),
                )
            }
        };
        match crate::unifi::set_inform(&self.state, &self.secrets, host_id, &inform_url).await {
            Ok(stdout) => Response::ok(id, serde_json::json!({ "stdout": stdout })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_unifi_set_controller(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let url = match params.get("url").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing url".to_owned()),
        };
        let username = match params.get("username").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing username".to_owned()),
        };
        let password = match params.get("password").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing password".to_owned()),
        };
        match crate::unifi::set_controller(
            &self.state,
            &self.secrets,
            host_id,
            &url,
            &username,
            &password,
        )
        .await
        {
            Ok(()) => Response::ok(id, serde_json::json!({ "saved": true })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_unifi_clear_controller(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        match crate::unifi::clear_controller(&self.state, &self.secrets, host_id).await {
            Ok(()) => Response::ok(id, serde_json::json!({ "cleared": true })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_unifi_test(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        match crate::unifi::test_connection(&self.state, &self.secrets, host_id).await {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_unifi_api(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let method = params
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_owned();
        let path = match params.get("path").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing path".to_owned()),
        };
        let body = params
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        match crate::unifi::api_request(&self.state, &self.secrets, host_id, &method, &path, &body)
            .await
        {
            Ok(resp) => Response::ok(
                id,
                serde_json::json!({ "status": resp.status, "body": resp.body }),
            ),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    // -----------------------------------------------------------------------
    // Standalone controller registry handlers
    // -----------------------------------------------------------------------

    pub(crate) async fn handle_unifi_controller_list(&self, id: u64) -> Response {
        let st = self.state.lock().await;
        let list: Vec<crate::unifi_controllers::UnifiController> =
            st.unifi_controllers.values().cloned().collect();
        match serde_json::to_value(&list) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Upsert a controller. Behaviour:
    ///   - `auth_method == "api_key"`: simple — store the
    ///     token, verify via sysinfo, persist.
    ///   - `auth_method == "password"` (default): attempt the
    ///     login. If the controller demands MFA, park the
    ///     in-flight session and return `{mfa_required: true,
    ///     challenge_id, authenticators}` — the GUI then
    ///     drives the operator through the email flow via
    ///     `unifi_controller_mfa_send` + `unifi_controller_mfa_complete`.
    ///
    /// Credential is required on first save. On edit, omit it
    /// to leave the existing keychain entry intact.
    pub(crate) async fn handle_unifi_controller_save(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        use crate::unifi_controllers::{test_connection, UnifiAuthMethod, UnifiController};
        use supermgr_core::vpn::profile::SecretRef;

        let label = match params.get("label").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing label".to_owned()),
        };
        let url = match params.get("url").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.trim_end_matches('/').to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing url".to_owned()),
        };
        let auth_method = match params.get("auth_method").and_then(|v| v.as_str()) {
            Some("api_key") => UnifiAuthMethod::ApiKey,
            _ => UnifiAuthMethod::Password,
        };
        // Username is required for password auth, optional for
        // api-key (where the key itself identifies the caller).
        let username = params
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        if auth_method == UnifiAuthMethod::Password && username.is_empty() {
            return Response::err(
                id,
                protocol::INVALID_PARAMS,
                "missing username (required for password auth)".to_owned(),
            );
        }
        let site_id = params
            .get("site_id")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_owned();
        let customer_slug = params
            .get("customer_slug")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let supplied_id = params
            .get("id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok());
        // The credential param is named after the auth method —
        // `password` for password auth, `api_key` for api-key.
        // We accept either name on either method for forgiveness.
        let credential = params
            .get("password")
            .and_then(|v| v.as_str())
            .or_else(|| params.get("api_key").and_then(|v| v.as_str()));

        // Distinguish "fresh save" from "update existing".
        let now = chrono::Utc::now();
        let (controller_id, created_at, existing_label) = {
            let st = self.state.lock().await;
            if let Some(id) = supplied_id {
                if let Some(existing) = st.unifi_controllers.get(&id) {
                    (
                        existing.id,
                        existing.created_at,
                        existing.creds_ref.0.clone(),
                    )
                } else {
                    (id, now, format!("unifi/controller/{}", id.simple()))
                }
            } else {
                let new_id = uuid::Uuid::new_v4();
                (new_id, now, format!("unifi/controller/{}", new_id.simple()))
            }
        };

        if let Some(cred) = credential {
            if let Err(e) = self.secrets.store(&existing_label, cred.as_bytes()).await {
                return Response::err(
                    id,
                    protocol::INTERNAL_ERROR,
                    format!("store credential: {e:#}"),
                );
            }
        } else if supplied_id.is_none() {
            return Response::err(
                id,
                protocol::INVALID_PARAMS,
                "credential is required on first save (`password` or `api_key`)".to_owned(),
            );
        }

        let controller = UnifiController {
            id: controller_id,
            label,
            url,
            site_id,
            auth_method,
            username,
            creds_ref: SecretRef::new(existing_label),
            customer_slug,
            verified_at: None,
            created_at,
            updated_at: now,
        };

        // One sysinfo round trip verifies either kind of credential. A
        // password account with a second factor fails here, with
        // directions to an API key.
        match test_connection(&self.secrets, &controller).await {
            Ok(sysinfo) => self.persist_verified(id, controller, sysinfo).await,
            Err(e) => Response::err(
                id,
                protocol::INTERNAL_ERROR,
                format!("controller test failed: {e:#}"),
            ),
        }
    }

    /// Persist a freshly-verified controller (regardless of
    /// auth path) and return the standard success shape.
    async fn persist_verified(
        &self,
        id: u64,
        controller: crate::unifi_controllers::UnifiController,
        sysinfo: crate::unifi_controllers::UnifiSysInfo,
    ) -> Response {
        let mut final_controller = controller;
        final_controller.verified_at = Some(chrono::Utc::now());
        {
            let mut st = self.state.lock().await;
            st.unifi_controllers
                .insert(final_controller.id, final_controller.clone());
            if let Err(e) = st.save_unifi_controller(&final_controller) {
                return Response::err(id, protocol::INTERNAL_ERROR, format!("persist: {e:#}"));
            }
        }
        Response::ok(
            id,
            serde_json::json!({
                "controller": final_controller,
                "sysinfo": sysinfo,
            }),
        )
    }

    pub(crate) async fn handle_unifi_controller_delete(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let cid = match get_uuid_param(&params, "id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let creds_label = {
            let st = self.state.lock().await;
            st.unifi_controllers
                .get(&cid)
                .map(|c| c.creds_ref.0.clone())
        };
        if let Some(label) = creds_label {
            let _ = self.secrets.delete(&label).await;
        }
        let mut st = self.state.lock().await;
        st.unifi_controllers.remove(&cid);
        if let Err(e) = st.delete_unifi_controller_file(cid) {
            return Response::err(id, protocol::INTERNAL_ERROR, format!("delete file: {e:#}"));
        }
        Response::ok(id, serde_json::json!({ "deleted": true }))
    }

    pub(crate) async fn handle_unifi_controller_test(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let cid = match get_uuid_param(&params, "id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let controller = {
            let st = self.state.lock().await;
            match st.unifi_controllers.get(&cid).cloned() {
                Some(c) => c,
                None => {
                    return Response::err(
                        id,
                        protocol::INVALID_PARAMS,
                        "controller not found".to_owned(),
                    )
                }
            }
        };
        match crate::unifi_controllers::test_connection(&self.secrets, &controller).await {
            Ok(sysinfo) => {
                // Bump verified_at on success.
                let mut st = self.state.lock().await;
                if let Some(c) = st.unifi_controllers.get_mut(&cid) {
                    c.verified_at = Some(chrono::Utc::now());
                    let snapshot = c.clone();
                    let _ = st.save_unifi_controller(&snapshot);
                }
                Response::ok(id, serde_json::json!({ "ok": true, "sysinfo": sysinfo }))
            }
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_unifi_controller_devices(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let cid = match get_uuid_param(&params, "id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let controller = {
            let st = self.state.lock().await;
            match st.unifi_controllers.get(&cid).cloned() {
                Some(c) => c,
                None => {
                    return Response::err(
                        id,
                        protocol::INVALID_PARAMS,
                        "controller not found".to_owned(),
                    )
                }
            }
        };
        match crate::unifi_controllers::list_devices(&self.secrets, &controller).await {
            Ok(devices) => match serde_json::to_value(&devices) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_unifi_controller_devmgr(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let cid = match get_uuid_param(&params, "id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let cmd = match params.get("cmd").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing cmd".to_owned()),
        };
        let mac = match params.get("mac").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing mac".to_owned()),
        };
        let extra = params
            .get("extra")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let controller = {
            let st = self.state.lock().await;
            match st.unifi_controllers.get(&cid).cloned() {
                Some(c) => c,
                None => {
                    return Response::err(
                        id,
                        protocol::INVALID_PARAMS,
                        "controller not found".to_owned(),
                    )
                }
            }
        };
        match crate::unifi_controllers::devmgr_command(
            &self.secrets,
            &controller,
            &cmd,
            &mac,
            extra,
        )
        .await
        {
            Ok(body) => Response::ok(id, body),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }
}
