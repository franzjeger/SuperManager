//! Provisioning JSON-RPC handlers.
//!
//! Template listing, render, diff-preview, pre-deploy-backup, deploy,
//! list-deployments, and rollback. Each method delegates to
//! `crate::provisioning` for the heavy lifting.

use crate::protocol::{self, Response};
use crate::server::{get_uuid_param, EngineServer};

impl EngineServer {
    pub(crate) async fn handle_provisioning_list_templates(&self, id: u64) -> Response {
        match crate::provisioning::list_templates() {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_provisioning_render(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let req: crate::provisioning::RenderRequest = match serde_json::from_value(params) {
            Ok(r) => r,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, e.to_string()),
        };
        match crate::provisioning::render(&req) {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    /// Render the template, fetch live config via SSH, return
    /// per-section diff. Heavy operation (one full SSH session
    /// + a `show full-configuration`) so the GUI surfaces a
    /// spinner while it runs.
    pub(crate) async fn handle_provisioning_diff_preview(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        // Outer params: { host_id, render_request: {...} }.
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let render_value = match params.get("render_request").cloned() {
            Some(v) => v,
            None => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing render_request".to_owned(),
                )
            }
        };
        let req: crate::provisioning::RenderRequest = match serde_json::from_value(render_value)
        {
            Ok(r) => r,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, e.to_string()),
        };
        match crate::provisioning::diff_preview(&self.state, &self.secrets, host_id, &req)
            .await
        {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_provisioning_pre_deploy_backup(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        match crate::provisioning::pre_deploy_backup(&self.state, &self.secrets, host_id).await
        {
            Ok(path) => Response::ok(id, serde_json::json!({ "backup_path": path })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_provisioning_deploy(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let render_value = match params.get("render_request").cloned() {
            Some(v) => v,
            None => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing render_request".to_owned(),
                )
            }
        };
        let req: crate::provisioning::RenderRequest = match serde_json::from_value(render_value)
        {
            Ok(r) => r,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, e.to_string()),
        };
        match crate::provisioning::deploy(&self.state, &self.secrets, host_id, &req).await {
            Ok(record) => match serde_json::to_value(&record) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_provisioning_list_deployments(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let limit = params
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(50) as usize;
        match crate::provisioning::list_deployments(
            &host_id.simple().to_string(),
            limit,
        ) {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_provisioning_rollback(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let backup_path = match params.get("backup_path").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing backup_path".to_owned(),
                )
            }
        };
        match crate::provisioning::rollback(&self.state, &self.secrets, host_id, &backup_path)
            .await
        {
            Ok(record) => match serde_json::to_value(&record) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }
}
