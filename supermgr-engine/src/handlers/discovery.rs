//! Network discovery JSON-RPC handlers.
//!
//! Passive scan (cert/SNI sweep), inventory loader, active port-scan
//! fan-out, and the persisted-findings loader for the discovery scope.

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    pub(crate) async fn handle_discovery_passive_scan(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let customer_slug = params
            .get("customer_slug")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let engagement_id = params
            .get("engagement_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        match crate::discovery::passive_scan(
            &self.state,
            customer_slug.as_deref(),
            engagement_id.as_deref(),
        )
        .await
        {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_discovery_active_scan(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let customer_slug = params
            .get("customer_slug")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let engagement_id = params
            .get("engagement_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let targets_raw: Vec<String> = params
            .get("targets")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let ports: Vec<u16> = params
            .get("ports")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|n| n as u16))
                    .collect()
            })
            .unwrap_or_else(|| crate::probes::COMMON_PORTS.to_vec());
        let cap = params
            .get("max_targets")
            .and_then(|v| v.as_u64())
            .unwrap_or(512) as usize;
        let targets = crate::discovery::expand_targets(&targets_raw, cap);
        if targets.is_empty() {
            return Response::err(
                id,
                protocol::INVALID_PARAMS,
                "no targets after expansion".to_owned(),
            );
        }
        // Register the scan as a cancellable operation. The guard
        // unregisters on drop so we don't have to remember to
        // clean up on error paths.
        let label = format!(
            "Active scan — {} targets, {} ports",
            targets.len(),
            ports.len(),
        );
        let guard = self.operations.start("active_scan", label);
        let cancel = Some(guard.cancel_flag());
        match crate::discovery::active_scan(
            &targets,
            &ports,
            customer_slug.as_deref(),
            engagement_id.as_deref(),
            cancel,
        )
        .await
        {
            Ok(result) => match serde_json::to_value(&result) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_discovery_findings(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let slug = match params.get("customer_slug").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing customer_slug".to_owned(),
                )
            }
        };
        match crate::discovery::load_findings(&slug) {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_discovery_inventory(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let slug = match params.get("customer_slug").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing customer_slug".to_owned(),
                )
            }
        };
        match crate::discovery::load_inventory(&slug) {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}
