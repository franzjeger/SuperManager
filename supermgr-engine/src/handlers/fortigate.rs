//! FortiGate REST API JSON-RPC handlers.
//!
//! Token generation/test/get, dashboard fetch, and the generic
//! `fortigate_api` proxy live here. The heavy lifting is in
//! `crate::fortigate`; these methods just adapt JSON params to the
//! typed helpers and convert the result back into a `Response`.

use crate::protocol::{self, Response};
use crate::server::{get_uuid_param, EngineServer};

impl EngineServer {
    /// Generic FortiGate REST proxy. Looks up the host's stored API
    /// token and forwards the request. Returns the raw response body
    /// (JSON for FortiOS APIs) along with the HTTP status code so
    /// the GUI can branch on 4xx/5xx without a separate error field.
    pub(crate) async fn handle_fortigate_api(&self, id: u64, params: serde_json::Value) -> Response {
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
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing path".to_owned(),
                )
            }
        };
        let body = params
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        match crate::fortigate::api_request(
            &self.state,
            &self.secrets,
            host_id,
            &method,
            &path,
            &body,
        )
        .await
        {
            Ok(resp) => Response::ok(
                id,
                serde_json::json!({
                    "status": resp.status,
                    "body": resp.body,
                }),
            ),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Generate a fresh API token via the FortiOS interactive CLI
    /// (`config system api-user … execute api-user generate-key`)
    /// and persist it under a host-keyed keychain label. Returns
    /// the cleartext token *once* so the GUI can offer "Copy" — on
    /// subsequent reads the GUI must call `fortigate_get_api_token`.
    pub(crate) async fn handle_fortigate_generate_api_token(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let api_user = params
            .get("api_user")
            .and_then(|v| v.as_str())
            .unwrap_or("supermgr-api")
            .to_owned();

        // SSH-connect to the device; the helper does its own state
        // lock for the host record so we don't double-lock here.
        let (host, session) = match self.connect_to_host(host_id).await {
            Ok(p) => p,
            Err(e) => {
                return Response::err(
                    id,
                    protocol::INTERNAL_ERROR,
                    format!("SSH connect failed: {e}"),
                )
            }
        };

        let result = crate::fortigate::generate_token(
            &self.state,
            &self.secrets,
            &session,
            &host,
            &api_user,
        )
        .await;
        let _ = session.disconnect().await;

        match result {
            Ok((token, label)) => Response::ok(
                id,
                serde_json::json!({
                    "token": token,
                    "label": label,
                    "api_user": api_user,
                }),
            ),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Retrieve the stored token in cleartext for "Copy" / "Show".
    pub(crate) async fn handle_fortigate_get_api_token(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        match crate::fortigate::get_token(&self.state, &self.secrets, host_id).await {
            Ok(token) => Response::ok(id, serde_json::json!({"token": token})),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Verify the stored token works by hitting `/monitor/system/status`.
    /// Returns rich device info (model, version, hostname, serial)
    /// so the GUI can render meaningful confirmation text rather
    /// than "OK".
    pub(crate) async fn handle_fortigate_test_connection(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        match crate::fortigate::test_connection(&self.state, &self.secrets, host_id).await {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// One-shot dashboard fetch — runs four FortiOS REST calls in
    /// parallel and returns a coherent snapshot. Each section is
    /// nullable so a partial failure (e.g. VPN endpoint forbidden
    /// due to token scope) still lets the GUI render the rest.
    /// The Swift side polls this every 5 s while a host detail is
    /// open and computes throughput rates from successive snapshots.
    pub(crate) async fn handle_fortigate_get_dashboard(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        match crate::fortigate::get_dashboard(&self.state, &self.secrets, host_id).await {
            Ok(snapshot) => match serde_json::to_value(&snapshot) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}
