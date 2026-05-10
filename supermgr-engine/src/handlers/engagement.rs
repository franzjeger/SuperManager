//! Engagement JSON-RPC handlers.
//!
//! Engagement CRUD, schedule management, and the markdown / PDF
//! report renderers. Pulls findings from the findings store via
//! the engagement's natural scope (customer slug or engagement id).

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    pub(crate) async fn handle_engagement_list(&self, id: u64) -> Response {
        match crate::engagement::list_all() {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_engagement_save(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let mut engagement: crate::engagement::Engagement = match serde_json::from_value(params)
        {
            Ok(e) => e,
            Err(e) => return Response::err(id, protocol::INVALID_PARAMS, e.to_string()),
        };
        if engagement.id.is_empty() {
            engagement.id = uuid::Uuid::new_v4().simple().to_string();
        }
        if let Err(e) = crate::engagement::save(&engagement) {
            return Response::err(id, protocol::INTERNAL_ERROR, e.to_string());
        }
        match serde_json::to_value(&engagement) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_engagement_delete(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let engagement_id = match params.get("id").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing id".to_owned()),
        };
        match crate::engagement::delete(&engagement_id) {
            Ok(()) => Response::ok(id, serde_json::json!({ "deleted": true })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_engagement_set_schedule(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let engagement_id = match params.get("engagement_id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing engagement_id".to_owned(),
                )
            }
        };
        // cadence: null/missing = clear schedule.
        let cadence: Option<crate::engagement::Cadence> =
            match params.get("cadence").cloned().unwrap_or(serde_json::Value::Null) {
                serde_json::Value::Null => None,
                v => match serde_json::from_value(v) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        return Response::err(
                            id,
                            protocol::INVALID_PARAMS,
                            format!("cadence: {e}"),
                        )
                    }
                },
            };
        match crate::scheduler::set_schedule(&engagement_id, cadence) {
            Ok(updated) => match serde_json::to_value(&updated) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_engagement_report(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let engagement_id = match params.get("engagement_id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing engagement_id".to_owned(),
                )
            }
        };
        let engagement = match crate::engagement::load(&engagement_id) {
            Ok(e) => e,
            Err(e) => {
                return Response::err(id, protocol::INTERNAL_ERROR, format!("load engagement: {e:#}"))
            }
        };
        // Pull findings for the engagement's natural scope.
        let scope = if engagement.customer_slug.is_empty() {
            engagement_id.clone()
        } else {
            engagement.customer_slug.clone()
        };
        let findings = crate::findings_store::list_findings(&scope).unwrap_or_default();
        let customer_slug = if engagement.customer_slug.is_empty() {
            None
        } else {
            Some(engagement.customer_slug.as_str())
        };
        let input = crate::report::ReportInput {
            engagement: &engagement,
            customer_slug,
            findings,
        };
        match crate::report::render_markdown(&input) {
            Ok(md) => Response::ok(id, serde_json::json!({ "markdown": md })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_engagement_report_pdf(&self, id: u64, params: serde_json::Value) -> Response {
        let engagement_id = match params.get("engagement_id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing engagement_id".to_owned()),
        };
        let engagement = match crate::engagement::load(&engagement_id) {
            Ok(e) => e,
            Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        };
        let scope = if engagement.customer_slug.is_empty() {
            engagement_id.clone()
        } else {
            engagement.customer_slug.clone()
        };
        let findings = crate::findings_store::list_findings(&scope).unwrap_or_default();
        let customer_slug = if engagement.customer_slug.is_empty() {
            None
        } else {
            Some(engagement.customer_slug.as_str())
        };
        let input = crate::report::ReportInput {
            engagement: &engagement,
            customer_slug,
            findings,
        };
        match crate::report::render_pdf(&input).await {
            Ok(bytes) => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                Response::ok(id, serde_json::json!({ "pdf_base64": b64, "size": bytes.len() }))
            }
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }
}
