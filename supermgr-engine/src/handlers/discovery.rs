//! Passive network discovery and device-type override JSON-RPC handlers.

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

    /// List every device-type override the operator has set,
    /// returned as a flat map MAC → device-type string.
    pub(crate) async fn handle_device_type_overrides_list(&self, id: u64) -> Response {
        let store = {
            let st = self.state.lock().await;
            st.device_type_overrides.clone()
        };
        let map = store.snapshot().await;
        match serde_json::to_value(&map) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Set (or clear, when `device_type` is null/empty) a
    /// manual device-type override. Params:
    ///   - `mac` (or `key`) — the MAC the override applies to
    ///   - `scope` — `"mac"` (default) for exact-MAC match,
    ///     `"oui"` to apply to every device with the same
    ///     three-octet OUI prefix
    ///   - `device_type` — type string (or empty to clear)
    pub(crate) async fn handle_device_type_override_set(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let key = match params
            .get("mac")
            .or_else(|| params.get("key"))
            .and_then(|v| v.as_str())
        {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing mac".to_owned()),
        };
        let scope = match params.get("scope").and_then(|v| v.as_str()) {
            Some("oui") => crate::device_type_overrides::OverrideScope::Oui,
            _ => crate::device_type_overrides::OverrideScope::Mac,
        };
        let device_type = params.get("device_type").and_then(|v| v.as_str());
        let store = {
            let st = self.state.lock().await;
            st.device_type_overrides.clone()
        };
        let dt = device_type.filter(|s| !s.is_empty());
        match store.set(&key, scope, dt).await {
            Ok(()) => Response::ok(
                id,
                serde_json::json!({ "ok": true, "scope": scope.as_str() }),
            ),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }
}
