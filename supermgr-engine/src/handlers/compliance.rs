//! Compliance JSON-RPC handlers.
//!
//! Wraps `crate::compliance` (run/history/drift/render/scan_all) and
//! exposes them as `EngineServer` methods routed from the dispatch
//! match in `server.rs`.

use crate::protocol::{self, Response};
use crate::server::{get_uuid_param, EngineServer};

impl EngineServer {
    /// Run all baseline compliance checks against a host. Returns
    /// the run record (with full check breakdown), and persists
    /// it under the app support directory for later history view.
    pub(crate) async fn handle_compliance_run(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let triggered_by = match params
            .get("triggered_by")
            .and_then(|v| v.as_str())
            .unwrap_or("manual")
        {
            "scheduled" => crate::compliance::TriggerKind::Scheduled,
            "post_deploy" => crate::compliance::TriggerKind::PostDeploy,
            _ => crate::compliance::TriggerKind::Manual,
        };

        // Open an SSH session up-front so any CLI checks in the
        // run can reuse it without each opening their own. For
        // the v1 check set everything is API-driven and SSH is
        // unused; this is forward-looking for L2 / custom checks
        // that need to grep `show` output.
        let ssh_session = match self.connect_to_host(host_id).await {
            Ok((_, sess)) => Some(sess),
            Err(e) => {
                // Don't bail — most checks are API-only. Log so
                // the user knows why CLI checks (when present)
                // would all error.
                tracing::info!("compliance: SSH unavailable for run ({e}); CLI checks will error");
                None
            }
        };

        let result = crate::compliance::run(
            &self.state,
            &self.secrets,
            host_id,
            triggered_by,
            ssh_session.as_ref(),
        )
        .await;

        if let Some(sess) = ssh_session {
            let _ = sess.disconnect().await;
        }

        match result {
            Ok(run) => match serde_json::to_value(&run) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_compliance_history(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let limit = params
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(50);
        match crate::compliance::load_history(&host_id.simple().to_string(), limit) {
            Ok(history) => match serde_json::to_value(&history) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_compliance_get_run(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let run_id = match params.get("run_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing run_id".to_owned()),
        };
        match crate::compliance::load_run(&host_id.simple().to_string(), &run_id) {
            Ok(run) => match serde_json::to_value(&run) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    pub(crate) async fn handle_compliance_list_checks(&self, id: u64) -> Response {
        let checks = crate::compliance::list_checks();
        match serde_json::to_value(&checks) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Compute a drift report between the given run and the run
    /// immediately preceding it on the same host. The first run
    /// for a host has no baseline; the report renders all current
    /// failures as "newly failing" in that case.
    pub(crate) async fn handle_compliance_drift(&self, id: u64, params: serde_json::Value) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let run_id = match params.get("run_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing run_id".to_owned()),
        };
        match crate::compliance::drift_against_previous(
            &host_id.simple().to_string(),
            &run_id,
        ) {
            Ok(report) => match serde_json::to_value(&report) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Run compliance against every FortiGate host with an API
    /// token configured. `min_age_hours` (optional) skips hosts
    /// whose last run is more recent than the threshold —
    /// the GUI's "Run all" button passes None for unconditional
    /// scanning, the auto-scan-on-launch path passes 24h to
    /// avoid duplicate scans within the same day.
    pub(crate) async fn handle_compliance_scan_all(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let triggered_by = match params
            .get("triggered_by")
            .and_then(|v| v.as_str())
            .unwrap_or("manual")
        {
            "scheduled" => crate::compliance::TriggerKind::Scheduled,
            "post_deploy" => crate::compliance::TriggerKind::PostDeploy,
            _ => crate::compliance::TriggerKind::Manual,
        };
        let min_age_hours = params
            .get("min_age_hours")
            .and_then(serde_json::Value::as_i64);

        match crate::compliance::scan_all(
            &self.state,
            &self.secrets,
            triggered_by,
            min_age_hours,
        )
        .await
        {
            Ok(results) => match serde_json::to_value(&results) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
            },
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Run the CIS-Linux baseline against a Linux SSH host. Distinct
    /// from `compliance_run` (FortiGate) because the check execution
    /// model is different — we shell out over SSH rather than calling
    /// a REST API.
    ///
    /// **1.12a:** returns a full `ComplianceRun` (same shape the
    /// FortiGate path produces) and persists it via `persist_run`
    /// before responding, so subsequent `compliance_history` /
    /// `compliance_get_run` / `compliance_drift` calls see Linux
    /// rows alongside FortiGate rows.
    ///
    /// **Known exposed gap — TODO(1.12b):** `compliance_render_report`
    /// looks up CIS reference / description / remediation in the
    /// library returned by `compliance_list_checks`, which today only
    /// contains FortiGate checks. Linux runs render through that
    /// path with their per-check `detail` field intact, but with no
    /// remediation block — the most valuable column for the operator.
    /// The fix is either widening `compliance_list_checks` to merge
    /// in `ssh_compliance::LINUX_CHECKS` (preferred — the GUI's
    /// library browser benefits too), or carrying the recommendation
    /// inline on `CheckResult`. Land in 1.12b before exposing the
    /// "Export report" button for Linux hosts.
    pub(crate) async fn handle_compliance_run_linux(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let triggered_by = match params
            .get("triggered_by")
            .and_then(|v| v.as_str())
            .unwrap_or("manual")
        {
            "scheduled" => crate::compliance::TriggerKind::Scheduled,
            "post_deploy" => crate::compliance::TriggerKind::PostDeploy,
            _ => crate::compliance::TriggerKind::Manual,
        };

        let (host, session) = match self.connect_to_host(host_id).await {
            Ok(pair) => pair,
            Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, format!("ssh: {e}")),
        };

        let host_id_str = host_id.simple().to_string();
        let host_hostname = host.hostname.clone();
        let run = crate::ssh_compliance::run_baseline(
            &host_id_str,
            Some(&host_hostname),
            triggered_by,
            |cmd| {
                let session = &session;
                async move {
                    let (_status, stdout, stderr) = session
                        .exec(&cmd)
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    // Combine — checks grep against stdout but error
                    // messages tend to land on stderr.
                    Ok(if stderr.is_empty() {
                        stdout
                    } else {
                        format!("{stdout}\n{stderr}")
                    })
                }
            },
        )
        .await;
        let _ = session.disconnect().await;

        // Persist before returning so a GUI crash doesn't lose the
        // result. Same non-fatal pattern as the FortiGate path —
        // we still return the run to the caller even if writing
        // the history file fails.
        if let Err(e) = crate::compliance::persist_run(&run) {
            tracing::warn!(
                "compliance(linux): failed to persist run {}: {e:#}",
                run.id
            );
        }

        match serde_json::to_value(&run) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// List the static set of Linux baseline checks (titles + count)
    /// without running them — handy for the UI's "About this baseline"
    /// disclosure before the user kicks off a scan.
    pub(crate) async fn handle_compliance_list_linux_checks(&self, id: u64) -> Response {
        let titles = crate::ssh_compliance::check_titles();
        Response::ok(
            id,
            serde_json::json!({
                "count": crate::ssh_compliance::check_count(),
                "titles": titles,
            }),
        )
    }

    /// Render a single run as a Markdown report. The GUI calls
    /// this when the user clicks "Export report"; we keep
    /// rendering server-side so the same logic runs whether the
    /// trigger is GUI, scheduled watchdog, or future CLI tool.
    pub(crate) async fn handle_compliance_render_report(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        let host_id = match get_uuid_param(&params, "host_id") {
            Ok(id) => id,
            Err(r) => return r,
        };
        let run_id = match params.get("run_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => return Response::err(id, protocol::INVALID_PARAMS, "missing run_id".to_owned()),
        };
        let host_str = host_id.simple().to_string();
        let run = match crate::compliance::load_run(&host_str, &run_id) {
            Ok(r) => r,
            Err(e) => return Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        };
        // Best-effort drift — first run has none, that's fine.
        let drift = crate::compliance::drift_against_previous(&host_str, &run_id).ok();
        let library = crate::compliance::list_checks();
        let markdown =
            crate::compliance::render_markdown_report(&run, drift.as_ref(), &library);
        Response::ok(id, serde_json::json!({ "markdown": markdown }))
    }
}
