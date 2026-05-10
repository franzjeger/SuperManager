//! Activity timeline and asset enrichment handlers.

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    pub(crate) async fn handle_asset_enrich(&self, id: u64, params: serde_json::Value) -> Response {
        let ips: Vec<String> = match params.get("ips").and_then(|v| v.as_array()) {
            Some(arr) => arr.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing ips".to_owned()),
        };
        let enriched = crate::asset_enrich::enrich_many(&ips).await;
        match serde_json::to_value(&enriched) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_activity_timeline(&self, id: u64, params: serde_json::Value) -> Response {
        let slug = match params.get("customer_slug").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing customer_slug".to_owned()),
        };
        let limit = params
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(200);
        let events = crate::activity_log::timeline(&slug, limit);
        match serde_json::to_value(&events) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}
