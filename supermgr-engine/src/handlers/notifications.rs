//! Notification config handlers (webhooks, PagerDuty, OpsGenie).

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    pub(crate) async fn handle_notify_get_config(&self, id: u64) -> Response {
        let cfg = crate::notify::load_config();
        match serde_json::to_value(&cfg) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_notify_set_webhook(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let scope = match params.get("scope").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                return Response::err(id, protocol::INVALID_PARAMS, "missing scope".to_owned())
            }
        };
        let webhook = params
            .get("webhook_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let mut cfg = crate::notify::load_config();
        if webhook.is_empty() {
            cfg.webhooks.remove(&scope);
        } else {
            cfg.webhooks.insert(scope, webhook);
        }
        match crate::notify::save_config(&cfg) {
            Ok(()) => Response::ok(id, serde_json::json!({ "ok": true })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    /// Set/clear PagerDuty Events API v2 routing key for a customer
    /// scope. Empty `key` removes the entry (no escalation).
    pub(crate) async fn handle_notify_set_pagerduty(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let scope = match params.get("scope").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing scope".to_owned()),
        };
        let key = params.get("key").and_then(|v| v.as_str()).unwrap_or("").to_owned();
        let mut cfg = crate::notify::load_config();
        if key.is_empty() {
            cfg.pagerduty_keys.remove(&scope);
        } else {
            cfg.pagerduty_keys.insert(scope, key);
        }
        match crate::notify::save_config(&cfg) {
            Ok(()) => Response::ok(id, serde_json::json!({ "ok": true })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    /// Set/clear OpsGenie Genie API key for a customer scope.
    pub(crate) async fn handle_notify_set_opsgenie(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let scope = match params.get("scope").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing scope".to_owned()),
        };
        let key = params.get("key").and_then(|v| v.as_str()).unwrap_or("").to_owned();
        let mut cfg = crate::notify::load_config();
        if key.is_empty() {
            cfg.opsgenie_keys.remove(&scope);
        } else {
            cfg.opsgenie_keys.insert(scope, key);
        }
        match crate::notify::save_config(&cfg) {
            Ok(()) => Response::ok(id, serde_json::json!({ "ok": true })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }
}
