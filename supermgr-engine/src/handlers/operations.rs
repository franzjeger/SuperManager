//! JSON-RPC handlers for the operation registry.
//!
//! Surfaces the list of running long-running operations + lets
//! the UI request cancellation. Workers honour the request at
//! their next safe checkpoint — cancellation is cooperative, not
//! `task.abort()`-style termination.

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    pub(crate) async fn handle_operation_list(&self, id: u64) -> Response {
        let list = self.operations.list();
        match serde_json::to_value(&list) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_operation_cancel(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let op_id = match params.get("id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing id".to_owned()),
        };
        let found = self.operations.cancel(&op_id);
        Response::ok(
            id,
            serde_json::json!({
                "cancelled": found,
                "id": op_id,
            }),
        )
    }
}
