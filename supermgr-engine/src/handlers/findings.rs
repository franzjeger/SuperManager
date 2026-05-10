//! Persisted-findings management JSON-RPC handlers (Track A).
//!
//! Provides list / summary / set-disposition over the findings store
//! plus the `resolve_findings_scope` helper that turns a free-form
//! `scope | customer_slug | engagement_id` into the storage scope key.

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    /// Resolve a "scope" parameter — either an explicit `scope`,
    /// or an `engagement_id` whose customer_slug we pull from disk,
    /// or a customer_slug. Returns the storage scope string.
    pub(crate) fn resolve_findings_scope(
        params: &serde_json::Value,
    ) -> Result<String, Response> {
        if let Some(s) = params.get("scope").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Ok(s.to_owned());
            }
        }
        if let Some(slug) = params.get("customer_slug").and_then(|v| v.as_str()) {
            if !slug.is_empty() {
                return Ok(slug.to_owned());
            }
        }
        if let Some(eid) = params.get("engagement_id").and_then(|v| v.as_str()) {
            // Prefer engagement's customer_slug if the engagement
            // has one; else fall back to engagement_id as scope.
            match crate::engagement::load(eid) {
                Ok(e) if !e.customer_slug.is_empty() => return Ok(e.customer_slug),
                _ => return Ok(eid.to_owned()),
            }
        }
        Err(Response::err(
            0,
            protocol::INVALID_PARAMS,
            "missing scope|customer_slug|engagement_id".to_owned(),
        ))
    }

    pub(crate) async fn handle_findings_list(&self, id: u64, params: serde_json::Value) -> Response {
        let scope = match Self::resolve_findings_scope(&params) {
            Ok(s) => s,
            Err(mut r) => {
                r.id = id;
                return r;
            }
        };
        match crate::findings_store::list_findings(&scope) {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_findings_summary(&self, id: u64, params: serde_json::Value) -> Response {
        let scope = match Self::resolve_findings_scope(&params) {
            Ok(s) => s,
            Err(mut r) => {
                r.id = id;
                return r;
            }
        };
        match crate::findings_store::summary(&scope) {
            Ok(s) => match serde_json::to_value(&s) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_findings_set_disposition(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let scope = match Self::resolve_findings_scope(&params) {
            Ok(s) => s,
            Err(mut r) => {
                r.id = id;
                return r;
            }
        };
        let key = match params.get("key").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                return Response::err(id, protocol::INVALID_PARAMS, "missing key".to_owned())
            }
        };
        let disposition_raw = params.get("disposition").cloned().unwrap_or_default();
        let new_disposition: crate::findings_store::Disposition =
            match serde_json::from_value(disposition_raw) {
                Ok(d) => d,
                Err(e) => {
                    return Response::err(
                        id,
                        protocol::INVALID_PARAMS,
                        format!("disposition: {e}"),
                    )
                }
            };
        let by = params
            .get("by")
            .and_then(|v| v.as_str())
            .unwrap_or("user")
            .to_owned();
        let note = params
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        match crate::findings_store::set_disposition(&scope, &key, new_disposition, &by, &note) {
            Ok(updated) => match serde_json::to_value(&updated) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    /// Compute per-host risk scores for a customer scope. Combines
    /// the persisted findings + (when available) the discovered-host
    /// inventory's `zone` field for exposure weighting.
    pub(crate) async fn handle_findings_risk_hosts(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let scope = match Self::resolve_findings_scope(&params) {
            Ok(s) => s,
            Err(mut r) => {
                r.id = id;
                return r;
            }
        };
        let findings = crate::findings_store::list_findings(&scope).unwrap_or_default();
        // Pull host zones from the most recent inventory snapshot —
        // best-effort; missing inventory just means no exposure
        // multiplier (factor stays 1.0).
        let zones: std::collections::HashMap<String, String> =
            crate::discovery::load_inventory(&scope)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|h| h.zone.map(|z| (h.ip, z)))
                .collect();
        let scored = crate::risk::score_hosts(&findings, &zones);
        match serde_json::to_value(&scored) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}
