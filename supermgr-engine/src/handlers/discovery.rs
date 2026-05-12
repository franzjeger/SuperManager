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

        // Strict-scope enforcement. If the engagement has
        // `strict_scope = true` AND `scope_cidrs` non-empty, every
        // target must fall within some scope CIDR and none can fall
        // inside an exclusion. Reject the WHOLE scan if any target
        // violates — partial-execute would defeat the audit guarantee
        // strict mode is there to provide.
        if let Some(eid) = engagement_id.as_deref() {
            if let Ok(engagement) = crate::engagement::load(eid) {
                if engagement.strict_scope {
                    let violations = crate::engagement::targets_outside_scope(
                        &targets,
                        &engagement.scope_cidrs,
                        &engagement.exclusions,
                    );
                    if !violations.is_empty() {
                        let sample = violations.iter()
                            .take(5)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ");
                        let extra = if violations.len() > 5 {
                            format!(" (+ {} more)", violations.len() - 5)
                        } else {
                            String::new()
                        };
                        return Response::err_engine(
                            id,
                            &crate::error::EngineError::InvalidScope {
                                reason: format!(
                                    "Strict scope: {} target(s) outside engagement scope or inside exclusions: {sample}{extra}",
                                    violations.len()
                                ),
                            },
                        );
                    }
                }
            }
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

    /// DNS zone-transfer (AXFR) probe — Kali-style recon. Tries
    /// to pull the full zone from each of the domain's authoritative
    /// nameservers. Returns one finding per leaking NS.
    pub(crate) async fn handle_discovery_dns_axfr(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let domain = match params.get("domain").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing or empty `domain` parameter".to_owned(),
                );
            }
        };
        let findings = crate::dns_axfr::check(&domain).await;
        match serde_json::to_value(&findings) {
            Ok(v) => Response::ok(id, serde_json::json!({"findings": v})),
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
