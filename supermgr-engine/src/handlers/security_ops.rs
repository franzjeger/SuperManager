//! Remediation script generation and security default-creds test handlers.

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    pub(crate) async fn handle_remediation_script(&self, id: u64, params: serde_json::Value) -> Response {
        // Two modes: single finding key, or batch by host_ip.
        let scope = match params.get("scope").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => return Response::err(id, protocol::INVALID_PARAMS, "missing scope".to_owned()),
        };
        let host_filter = params.get("host").and_then(|v| v.as_str()).map(str::to_owned);
        let key_filter = params.get("key").and_then(|v| v.as_str()).map(str::to_owned);

        let findings = crate::findings_store::list_findings(&scope).unwrap_or_default();
        let selected: Vec<crate::vuln::Finding> = findings
            .into_iter()
            .filter(|f| {
                if let Some(k) = &key_filter { return f.key == *k; }
                if let Some(h) = &host_filter { return f.finding.host_ip == *h; }
                true
            })
            .filter_map(|f| {
                // Only include open findings — don't generate scripts for
                // already-fixed/accepted-risk items.
                matches!(f.disposition, crate::findings_store::Disposition::Open)
                    .then_some(f.finding)
            })
            .collect();

        if selected.is_empty() {
            return Response::ok(id, serde_json::json!({
                "script": "",
                "applied": 0,
                "message": "No open findings match the scope."
            }));
        }
        let host = host_filter.clone().unwrap_or_else(|| selected[0].host_ip.clone());
        let script = crate::remediation::batch_script(&host, &selected);
        let recipes_available = selected.iter()
            .filter(|f| crate::remediation::script_for_finding(f).is_some())
            .count();
        Response::ok(id, serde_json::json!({
            "script": script,
            "applied": recipes_available,
            "total_findings": selected.len(),
        }))
    }

    pub(crate) async fn handle_security_test_default_creds(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host = match params.get("host").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => {
                return Response::err(id, protocol::INVALID_PARAMS, "missing host".to_owned())
            }
        };
        let port = params
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as u16)
            .unwrap_or(22);
        let service = params
            .get("service")
            .and_then(|v| v.as_str())
            .unwrap_or("ssh")
            .to_owned();
        let findings = match service.as_str() {
            "ssh" => crate::creds::ssh_test_defaults(&host, port).await,
            "http" => crate::creds::http_test_defaults(&host, port, false).await,
            "https" => crate::creds::http_test_defaults(&host, port, true).await,
            other => {
                return Response::err(
                    id,
                    protocol::INVALID_PARAMS,
                    format!("unsupported service: {other}"),
                )
            }
        };
        match serde_json::to_value(&findings) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }
}
