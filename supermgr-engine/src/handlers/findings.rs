//! Persisted-findings read JSON-RPC handlers (`findings_list`, `findings_summary`).

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    /// Resolve a "scope" parameter — either an explicit `scope`,
    /// a `customer_slug`, or an `engagement_id`.
    // Boxing `Response` here would ripple through every `?` in the
    // handler layer for an unmeasured stack-size win.
    #[allow(clippy::result_large_err)]
    pub(crate) fn resolve_findings_scope(params: &serde_json::Value) -> Result<String, Response> {
        for key in ["scope", "customer_slug", "engagement_id"] {
            if let Some(s) = params.get(key).and_then(|v| v.as_str()) {
                if !s.is_empty() {
                    return Ok(s.to_owned());
                }
            }
        }
        Err(Response::err(
            0,
            protocol::INVALID_PARAMS,
            "missing scope|customer_slug|engagement_id".to_owned(),
        ))
    }

    pub(crate) async fn handle_findings_list(
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
        match crate::findings_store::list_findings(&scope) {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err_engine(id, &crate::error::EngineError::from_findings_anyhow(e)),
        }
    }

    pub(crate) async fn handle_findings_summary(
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
        match crate::findings_store::summary(&scope) {
            Ok(s) => match serde_json::to_value(&s) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err_engine(id, &crate::error::EngineError::from_findings_anyhow(e)),
        }
    }
}
