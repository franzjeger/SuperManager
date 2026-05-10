//! Tools, CVE feed, DNS health, subdomain enum, and network detect handlers.

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    pub(crate) async fn handle_tools_status(&self, id: u64) -> Response {
        let info = crate::tools::status().await;
        match serde_json::to_value(&info) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_dns_health_audit(&self, id: u64, params: serde_json::Value) -> Response {
        let domain = match params.get("domain").and_then(|v| v.as_str()) {
            Some(d) if !d.is_empty() => d.to_owned(),
            _ => {
                return Response::err(id, protocol::INVALID_PARAMS, "missing domain".to_owned())
            }
        };
        // Optional persistence scope — when given, the domain
        // findings reconcile into the customer's findings store
        // alongside other findings.
        let scope = params.get("scope").and_then(|v| v.as_str()).map(str::to_owned);
        let report = crate::dns_health::audit(&domain).await;
        if let Some(s) = scope.as_deref() {
            if let Err(e) = crate::findings_store::reconcile(s, &report.findings) {
                tracing::warn!("dns_health reconcile failed: {e:#}");
            }
        }
        match serde_json::to_value(&report) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_cve_feed_refresh(&self, id: u64) -> Response {
        match crate::cve_feed::refresh().await {
            Ok(added) => Response::ok(
                id,
                serde_json::json!({ "ok": true, "added": added }),
            ),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_cve_feed_status(&self, id: u64) -> Response {
        let cache = crate::cve_feed::load();
        let payload = serde_json::json!({
            "total": cache.entries.len(),
            "last_fetched_at": cache.last_fetched_at,
        });
        Response::ok(id, payload)
    }

    pub(crate) async fn handle_subdomain_enum(&self, id: u64, params: serde_json::Value) -> Response {
        let domain = match params.get("domain").and_then(|v| v.as_str()) {
            Some(d) if !d.is_empty() => d.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing domain".to_owned()),
        };
        match crate::subdomain_enum::enumerate(&domain).await {
            Ok(r) => match serde_json::to_value(&r) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_network_detect(&self, id: u64) -> Response {
        let info = crate::netdetect::detect().await;
        match serde_json::to_value(&info) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}
