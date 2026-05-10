//! Customer JSON-RPC handlers.
//!
//! List/save/delete and the markdown render-report helper. The
//! provisioning side of "customer + provisioning" lives in
//! `provisioning.rs`.

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    pub(crate) async fn handle_customer_list(&self, id: u64) -> Response {
        match crate::customer::list_all() {
            Ok(list) => match serde_json::to_value(&list) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Save a customer record. The `slug` is derived from
    /// `display_name` if absent — the GUI usually passes both
    /// from the edit dialog, but we'll synthesize one if needed
    /// so JSON-RPC clients without slug-derivation logic still
    /// work.
    pub(crate) async fn handle_customer_save(&self, id: u64, params: serde_json::Value) -> Response {
        let display_name = match params
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s) => s.to_owned(),
            None => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    "missing display_name".to_owned(),
                )
            }
        };
        // Pull a fully-formed Customer if the GUI sent one;
        // otherwise build a minimal record and let the engine
        // fill gaps.
        let mut customer: crate::customer::Customer = match params.get("customer").cloned() {
            Some(v) => match serde_json::from_value(v) {
                Ok(c) => c,
                Err(e) => return Response::err(id, protocol::INVALID_PARAMS, e.to_string()),
            },
            None => crate::customer::Customer {
                slug: String::new(),
                display_name: display_name.clone(),
                contact_name: String::new(),
                contact_email: String::new(),
                notes: String::new(),
                default_template: None,
                mgmt_allowlist_domains: Vec::new(),
                primary_domain: String::new(),
                sites: Vec::new(),
            },
        };
        if customer.display_name.is_empty() {
            customer.display_name = display_name.clone();
        }
        if customer.slug.is_empty() {
            customer.slug = crate::customer::slugify(&customer.display_name);
        }
        if let Err(e) = crate::customer::save(&customer) {
            return Response::err(id, protocol::INTERNAL_ERROR, e.to_string());
        }
        match serde_json::to_value(&customer) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_customer_report(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let slug = match params.get("slug").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing slug".to_owned()),
        };
        match crate::customer::render_customer_report(&self.state, &slug).await {
            Ok(markdown) => Response::ok(id, serde_json::json!({ "markdown": markdown })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, format!("{e:#}")),
        }
    }

    pub(crate) async fn handle_customer_delete(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let slug = match params.get("slug").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing slug".to_owned()),
        };
        match crate::customer::delete(&slug) {
            Ok(()) => Response::ok(id, serde_json::json!({ "deleted": true })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}
