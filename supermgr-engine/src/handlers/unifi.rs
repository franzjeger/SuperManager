//! UniFi controller JSON-RPC handlers.
//!
//! Inform-URL push, controller credential CRUD, connection test, and
//! the generic `unifi_api` REST proxy.

use crate::protocol::{self, Response};
use crate::server::{get_uuid_param, EngineServer};

impl EngineServer {
    pub(crate) async fn handle_unifi_set_inform(&self, id: u64, params: serde_json::Value) -> Response {
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
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing username".to_owned(),
                )
            }
        };
        let password = match params.get("password").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing password".to_owned(),
                )
            }
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
}
