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
        match crate::provisioning::diff_preview(&self.state, &self.secrets, &self.deployment_plans, host_id, &req)
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
        // Legacy render_request deployments are intentionally rejected: a fresh
        // server-owned preview is required, including after an engine restart.
        let plan_id = match params.get("plan_id").and_then(serde_json::Value::as_str)
            .and_then(|s| uuid::Uuid::parse_str(s).ok()) {
            Some(id) => id,
            None => return Response::err(id, protocol::INVALID_PARAMS,
                "A valid plan_id from a new deployment preview is required".to_owned()),
        };
        match crate::provisioning::deploy(&self.state, &self.secrets, &self.deployment_plans, plan_id).await {
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
        let _ = params;
        Response::err(id, protocol::INVALID_PARAMS,
            "Direct rollback is disabled. Use provisioning_restore_preview and deploy its plan_id.".to_owned())
    }

    pub(crate) async fn handle_provisioning_restore_preview(&self, id: u64, params: serde_json::Value) -> Response {
        let parse_id = |key| params.get(key).and_then(serde_json::Value::as_str).and_then(|s| uuid::Uuid::parse_str(s).ok());
        let (Some(host_id), Some(deployment_id), Some(customer), Some(site)) = (
            parse_id("host_id"), parse_id("deployment_id"),
            params.get("customer_slug").and_then(serde_json::Value::as_str),
            params.get("site_id").and_then(serde_json::Value::as_str),
        ) else { return Response::err(id, protocol::INVALID_PARAMS, "host_id, deployment_id, customer_slug and site_id are required".to_owned()); };
        match crate::provisioning::restore_preview(&self.state, &self.secrets, &self.deployment_plans,
            host_id, deployment_id, customer.to_owned(), site.to_owned()).await {
            Ok(result) => match serde_json::to_value(result) {
                Ok(value) => Response::ok(id, value),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }
}
