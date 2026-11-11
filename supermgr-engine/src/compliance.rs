//! `FortiGate` compliance runners.
//!
//! The model, the check library, scoring, drift, report rendering and
//! persistence all live in [`supermgr_core::compliance`] now — none of it is
//! macOS-specific, and the Linux daemon needs the same definitions rather than
//! a second set that can disagree.
//!
//! What stays here is what genuinely cannot move: the four functions that
//! reach into engine state (`DaemonState`), the `FortiGate` REST client, or an
//! engine SSH session. Everything they operate on comes from core, re-exported
//! below so existing `compliance::Status` style paths keep resolving.

pub use supermgr_core::compliance::*;

use std::sync::Arc;

use anyhow::{anyhow, Context as _, Result};
use chrono::Utc;
use supermgr_core::keyring::SecretStore;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::fortigate;
use crate::state::DaemonState;

/// Run all applicable checks for a host. `triggered_by` is
/// captured into the run record so the GUI can distinguish a
/// manual run from a daily-watchdog run when rendering the
/// history.
async fn extract_cli(
    def: &CheckDefinition,
    ssh_session: Option<&crate::ssh::connection::SshSession>,
) -> Result<String> {
    let session = ssh_session.ok_or_else(|| {
        anyhow!(
            "CLI check {} requires SSH but no session was provided",
            def.id
        )
    })?;
    let command = def
        .cli_command
        .as_deref()
        .ok_or_else(|| anyhow!("cli check {} missing cli_command", def.id))?;
    let grep = def
        .cli_grep
        .as_deref()
        .ok_or_else(|| anyhow!("cli check {} missing cli_grep", def.id))?;
    // A `show` read: seconds, even on a busy unit.
    let (_, stdout, _) = session
        .exec(command, Some(std::time::Duration::from_secs(60)))
        .await
        .context("ssh exec")?;
    // Find the first line containing the grep token, then return
    // the LAST whitespace-separated token from that line. FortiOS
    // `show` output looks like `    set admin-sport 8443`, so the
    // last token is the value.
    let value = stdout
        .lines()
        .find(|l| l.to_lowercase().contains(&grep.to_lowercase()))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or("")
        .trim_matches('"')
        .to_owned();
    Ok(value)
}

/// Whether a run reads anything over SSH. Includes custom user TOML checks (`P2-27`).
#[must_use]
pub fn needs_ssh() -> bool {
    fortigate_effective_checks()
        .iter()
        .any(|def| matches!(def.channel, Channel::Cli))
}

pub async fn run(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
    triggered_by: TriggerKind,
    ssh_session: Option<&crate::ssh::connection::SshSession>,
) -> Result<ComplianceRun> {
    let started_at = Utc::now();
    info!(
        "compliance: starting run for host {} ({:?})",
        host_id, triggered_by
    );

    // Run built-in FortiGate checks merged with any user-defined custom checks (`P2-27`).
    let defs = fortigate_effective_checks();
    let any_api_check = defs.iter().any(|d| matches!(d.channel, Channel::Api));

    // Open ONE shared FortiGate API session for the entire run (`P3-10`),
    // caching each unique `api_path` JSON payload and aborting remaining API
    // probes immediately on transport/connection failure so an unreachable
    // firewall fails in a single timeout rather than 47 × 30s.
    let mut firmware: Option<String> = None;
    let mut model: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut transport_abort_reason: Option<String> = None;
    let mut api_session: Option<fortigate::FortigateApiSession> = None;

    if any_api_check {
        match fortigate::FortigateApiSession::open(state, secrets, host_id).await {
            Ok(sess) => {
                match sess
                    .request("GET", "/api/v2/monitor/system/status", "")
                    .await
                {
                    Ok(resp) if resp.status < 400 => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                            let r = v.get("results").unwrap_or(&v);
                            firmware = r.get("version").and_then(|x| x.as_str()).map(str::to_owned);
                            model = r.get("model").and_then(|x| x.as_str()).map(str::to_owned);
                            hostname = r
                                .get("hostname")
                                .and_then(|x| x.as_str())
                                .map(str::to_owned);
                        }
                    }
                    Ok(_) => {}
                    Err(fortigate::FortigateRequestError::Transport(reason)) => {
                        transport_abort_reason = Some(reason);
                    }
                    Err(fortigate::FortigateRequestError::Other(_)) => {}
                }
                api_session = Some(sess);
            }
            Err(e) => {
                transport_abort_reason = Some(e.to_string());
            }
        }
    }

    let mut api_cache: std::collections::HashMap<String, Result<serde_json::Value, String>> =
        std::collections::HashMap::new();
    let mut results: Vec<CheckResult> = Vec::with_capacity(defs.len());

    for def in &defs {
        let raw = match def.channel {
            Channel::Api => {
                if let Some(reason) = &transport_abort_reason {
                    Err(anyhow!("{reason}"))
                } else if let Some(sess) = api_session.as_ref() {
                    extract_api_cached(sess, &mut api_cache, &mut transport_abort_reason, def).await
                } else {
                    Err(anyhow!("API session unavailable"))
                }
            }
            Channel::Cli => extract_cli(def, ssh_session).await,
        };

        let (status, detail, raw_value) = match raw {
            Ok(value) => evaluate(def, &value),
            Err(e) => (Status::Error, format!("could not extract value: {e}"), None),
        };

        results.push(CheckResult {
            check_id: def.id.clone(),
            title: def.title.clone(),
            category: def.category.clone(),
            severity: def.severity.clone(),
            status,
            detail,
            raw_value,
        });
    }

    let finished_at = Utc::now();
    let score = score(&results);
    let (passed, failed, errored, skipped) = tally(&results);
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let run = ComplianceRun {
        id: run_id.clone(),
        host_id: host_id.simple().to_string(),
        started_at,
        finished_at,
        firmware,
        model,
        hostname,
        triggered_by,
        baseline_kind: BaselineKind::Fortigate,
        score,
        passed,
        failed,
        errored,
        skipped,
        checks: results,
    };

    // Persist before returning so a GUI crash doesn't lose the
    // result. Failures here are non-fatal — we still return the
    // run to the caller (it's better to show data than to error
    // because we couldn't write the history file).
    if let Err(e) = persist_run(&run) {
        warn!("compliance: failed to persist run: {e:#}");
    }
    info!(
        "compliance: finished run {} score={} ({}/{} passed, {} failed, {} errored)",
        run_id,
        score,
        passed,
        passed + failed,
        failed,
        errored
    );
    Ok(run)
}

async fn extract_api_cached(
    session: &fortigate::FortigateApiSession,
    cache: &mut std::collections::HashMap<String, Result<serde_json::Value, String>>,
    transport_abort_reason: &mut Option<String>,
    def: &CheckDefinition,
) -> Result<String> {
    let path = def
        .api_path
        .as_deref()
        .ok_or_else(|| anyhow!("api check {} missing api_path", def.id))?;
    let pointer = def
        .api_pointer
        .as_deref()
        .ok_or_else(|| anyhow!("api check {} missing api_pointer", def.id))?;

    if !cache.contains_key(path) {
        let fetched = match session.request("GET", path, "").await {
            Ok(resp) if resp.status >= 400 => Err(format!(
                "API returned HTTP {}: {}",
                resp.status,
                resp.body.chars().take(200).collect::<String>()
            )),
            Ok(resp) => serde_json::from_str::<serde_json::Value>(&resp.body)
                .map_err(|e| format!("response is not JSON: {e}")),
            Err(fortigate::FortigateRequestError::Transport(reason)) => {
                *transport_abort_reason = Some(reason.clone());
                Err(reason)
            }
            Err(fortigate::FortigateRequestError::Other(e)) => Err(e.to_string()),
        };
        cache.insert(path.to_owned(), fetched);
    }

    let v = match cache.get(path).expect("inserted above") {
        Ok(v) => v,
        Err(msg) => return Err(anyhow!("{msg}")),
    };
    let pointed = v
        .pointer(pointer)
        .ok_or_else(|| anyhow!("pointer {pointer} not found in response"))?;
    Ok(match pointed {
        serde_json::Value::String(s) => s.trim().to_owned(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    })
}

/// Run compliance against every `FortiGate` host that has an API
/// token configured. Hosts run in parallel up to a small cap so
/// we don't open hundreds of `FortiOS` sessions concurrently.
///
/// `min_age_hours` is honoured: a host whose last run is more
/// recent than this threshold gets `error: "skipped (recent)"`,
/// not a fresh run. Pass `None` for unconditional scanning (i.e.
/// the manual "Run all" button); pass `Some(24)` for the daily
/// scheduler.
pub async fn scan_all(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    triggered_by: TriggerKind,
    min_age_hours: Option<i64>,
) -> Result<Vec<ScanAllResult>> {
    use supermgr_core::ssh::DeviceType;

    // Snapshot the host list under lock then drop.
    let candidates: Vec<(uuid::Uuid, String)> = {
        let st = state.lock().await;
        st.ssh_hosts
            .values()
            .filter(|h| h.device_type == DeviceType::Fortigate && h.api_token_ref.is_some())
            .map(|h| (h.id, h.label.clone()))
            .collect()
    };

    if candidates.is_empty() {
        info!("compliance scan_all: no FortiGate hosts with API token configured");
        return Ok(Vec::new());
    }

    info!(
        "compliance scan_all: scanning {} hosts ({:?})",
        candidates.len(),
        triggered_by
    );

    // Run sequentially for now. Concurrent scans against multiple
    // FortiGates would race on shared mutex regions in the FortiOS
    // REST layer (the device serializes config-read APIs). 8 hosts
    // × ~5s/scan is 40s — tolerable for the daily watchdog use case.
    let mut results = Vec::with_capacity(candidates.len());
    for (host_id, host_label) in candidates {
        // Recency check.
        if let Some(min_h) = min_age_hours {
            let last_run = load_history(&host_id.simple().to_string(), 1)
                .ok()
                .and_then(|v| v.into_iter().next())
                .map(|s| s.started_at);
            if let Some(last) = last_run {
                let age = chrono::Utc::now().signed_duration_since(last).num_hours();
                if age < min_h {
                    info!(
                        "compliance scan_all: skipping {host_id} (last run {age}h ago, threshold {min_h}h)"
                    );
                    results.push(ScanAllResult {
                        host_id: host_id.simple().to_string(),
                        host_label,
                        run_id: None,
                        score: None,
                        error: Some(format!("skipped (last run {age}h ago)")),
                    });
                    continue;
                }
            }
        }

        match run(state, secrets, host_id, triggered_by.clone(), None).await {
            Ok(run_record) => {
                results.push(ScanAllResult {
                    host_id: host_id.simple().to_string(),
                    host_label,
                    run_id: Some(run_record.id),
                    score: Some(run_record.score),
                    error: None,
                });
            }
            Err(e) => {
                warn!("compliance scan_all: host {host_id} failed: {e:#}");
                results.push(ScanAllResult {
                    host_id: host_id.simple().to_string(),
                    host_label,
                    run_id: None,
                    score: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    Ok(results)
}
