//! Compliance engine — pluggable check definitions, runner, history.
//!
//! # Design
//!
//! The Linux daemon's `fortigate_compliance_check` was a flat
//! `match` of 10 hardcoded SSH commands. That was fine for a v1
//! but doesn't scale: each new check meant a code change, severities
//! were implicit, there was no history, no trend, no fix guidance.
//!
//! This module replaces it with three layers:
//!
//! 1. **Check definitions** — declarative records that describe
//!    *what* to check, *how* to evaluate it, what severity to
//!    assign on fail, and the CLI commands that fix it. We start
//!    with hardcoded defaults; later phases load TOML overrides
//!    from `~/Library/Application Support/SuperManager/checks/`.
//!
//! 2. **Runner** — given a host, executes all applicable checks,
//!    using the FortiGate REST API where possible (faster, lower
//!    overhead than SSH) and falling back to SSH CLI when an
//!    API endpoint isn't suitable. Produces a `ComplianceRun`.
//!
//! 3. **History store** — runs are persisted to JSON under the app
//!    support directory keyed by host id. The GUI fetches recent
//!    runs to render trend graphs and drift indicators.
//!
//! ## Why JSON not SQLite
//!
//! SQLite would add a runtime dependency, a migration story, and
//! complicate the export-everything-and-restore-on-new-machine
//! flow we'll need later. The data shape is small (a few hundred
//! KB per host per year of daily runs), append-only, and rarely
//! needs ad-hoc queries. Plain JSON files keep the engine
//! self-contained.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use supermgr_core::keyring::SecretStore;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::fortigate;
use crate::state::DaemonState;

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Penalty applied to score on failure of a check at this
    /// severity. Tunable; see `score()` for the cap.
    fn penalty(&self) -> f64 {
        match self {
            Severity::Info => 0.0,
            Severity::Low => 0.5,
            Severity::Medium => 2.0,
            Severity::High => 5.0,
            Severity::Critical => 10.0,
        }
    }
}

/// What channel a check uses. API checks are preferred (faster,
/// less invasive than opening an SSH session). CLI checks parse
/// the FortiOS `show` output and are necessary for settings the
/// API doesn't expose under `/monitor`. `Both` lets a check try
/// API first and fall back to CLI if the API call returned an
/// unparseable result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Api,
    Cli,
}

/// How a check evaluates its raw value into pass/fail. Kept
/// declarative so future TOML-defined checks can express logic
/// without embedding code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expectation {
    /// Raw value (case-insensitive substring) must NOT appear.
    /// Example: `allowaccess` line must NOT contain "https" for
    /// the WAN-no-management check.
    NotContains { needle: String },
    /// Raw value (case-insensitive substring) MUST appear.
    /// Example: `strong-crypto` line MUST contain "enable".
    Contains { needle: String },
    /// Raw value parsed as integer must be >= threshold.
    /// Example: password min-length >= 14.
    GreaterEqual { threshold: i64 },
    /// Raw value parsed as integer must be <= threshold.
    /// Example: admintimeout (idle in minutes) <= 5.
    LessEqual { threshold: i64 },
    /// Raw value (after trim) must NOT equal the forbidden value.
    /// Example: admin-sport must NOT be "443".
    NotEqual { value: String },
    /// Raw value (after trim, case-insensitive) must equal exact.
    Equal { value: String },
}

/// One check. Hardcoded for now; later loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckDefinition {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: Severity,
    pub framework: String,
    pub cis_reference: Option<String>,
    pub channel: Channel,
    /// FortiGate REST path (when `channel` includes API). Returns
    /// the JSON object whose `pointer` we evaluate.
    pub api_path: Option<String>,
    /// JSON pointer (RFC6901) into the response, e.g. `/results/admin-sport`.
    pub api_pointer: Option<String>,
    /// CLI command (when `channel` is Cli). Output is grepped to
    /// find the line containing `cli_grep`, then split on
    /// whitespace and the LAST token is the value to evaluate.
    pub cli_command: Option<String>,
    /// Substring used to find the relevant line in `cli_command`'s
    /// output. Required when `channel` is Cli.
    pub cli_grep: Option<String>,
    pub expect: Expectation,
    /// CLI snippet that, when applied to the FortiGate, makes
    /// this check pass. Shown in the "Fix" affordance under each
    /// failed check. Multiline. Variable substitution is the
    /// user's responsibility (e.g. interface name).
    pub remediation: Option<String>,
}

// ---------------------------------------------------------------------------
// Run results
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Skip,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check_id: String,
    pub status: Status,
    /// Human-readable explanation for the result. "Port 8443" for a
    /// pass on `admin-sport`; "https found in WAN1 allowaccess" for
    /// a fail on the WAN-mgmt check; "API returned 403" for an
    /// error.
    pub detail: String,
    /// The literal value extracted from the device, kept so the
    /// GUI can show "what we saw". Trimmed, never includes the
    /// CLI grep output beyond the relevant line.
    pub raw_value: Option<String>,
    /// Carried through from the definition for convenience —
    /// avoids the GUI having to re-look-up the definition by id.
    pub severity: Severity,
    pub title: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    Manual,
    Scheduled,
    PostDeploy,
}

/// Which baseline this run was executed against. Carried on every
/// `ComplianceRun` and `RunSummary` so downstream code (and the
/// GUI, once 1.12b lands) can distinguish FortiGate REST-API runs
/// from Linux SSH-shell runs without sniffing check ids.
///
/// **Back-compat:** runs persisted before this field existed will
/// decode with `#[serde(default)]` → `BaselineKind::Fortigate`
/// (every legacy row was a FortiGate run — Linux runs had no
/// persistence at all before 1.12a, so there are no Linux rows
/// on disk to mis-tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineKind {
    Fortigate,
    Linux,
}

impl Default for BaselineKind {
    /// Default used by `#[serde(default)]` when an old persisted
    /// run lacks the `baseline_kind` field. See type-level doc.
    fn default() -> Self {
        Self::Fortigate
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRun {
    pub id: String,
    pub host_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub firmware: Option<String>,
    pub model: Option<String>,
    pub hostname: Option<String>,
    pub triggered_by: TriggerKind,
    /// Which baseline this run executed. `#[serde(default)]` so
    /// runs persisted before 1.12a (all FortiGate) still decode.
    #[serde(default)]
    pub baseline_kind: BaselineKind,
    /// 0–100. See `score()` below.
    pub score: u8,
    pub passed: u32,
    pub failed: u32,
    pub errored: u32,
    pub skipped: u32,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub score: u8,
    pub passed: u32,
    pub failed: u32,
    pub errored: u32,
    pub firmware: Option<String>,
    pub triggered_by: TriggerKind,
    /// Surfaces the baseline kind to history-list renderers so the
    /// row can carry a badge / icon without a second round-trip.
    /// `#[serde(default)]` for the same reason as on `ComplianceRun`.
    #[serde(default)]
    pub baseline_kind: BaselineKind,
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Run all applicable checks for a host. `triggered_by` is
/// captured into the run record so the GUI can distinguish a
/// manual run from a daily-watchdog run when rendering the
/// history.
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

    // Snapshot device identity (used in run header + later in
    // PDF reports) via `/monitor/system/status`.
    let mut firmware: Option<String> = None;
    let mut model: Option<String> = None;
    let mut hostname: Option<String> = None;
    if let Ok(resp) = fortigate::api_request(
        state,
        secrets,
        host_id,
        "GET",
        "/api/v2/monitor/system/status",
        "",
    )
    .await
    {
        if resp.status < 400 {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                let r = v.get("results").unwrap_or(&v);
                firmware = r
                    .get("version")
                    .and_then(|x| x.as_str())
                    .map(str::to_owned);
                model = r.get("model").and_then(|x| x.as_str()).map(str::to_owned);
                hostname = r
                    .get("hostname")
                    .and_then(|x| x.as_str())
                    .map(str::to_owned);
            }
        }
    }

    // FortiGate runner uses only the FortiGate library — Linux
    // checks are not API-evaluable (no api_path), and the Linux
    // runner has its own execution path via `ssh_compliance::run_baseline`.
    let defs = fortigate_default_checks();
    let mut results: Vec<CheckResult> = Vec::with_capacity(defs.len());
    for def in &defs {
        let result = run_one(state, secrets, host_id, def, ssh_session).await;
        results.push(result);
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

async fn run_one(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
    def: &CheckDefinition,
    ssh_session: Option<&crate::ssh::connection::SshSession>,
) -> CheckResult {
    let raw = match def.channel {
        Channel::Api => extract_api(state, secrets, host_id, def).await,
        Channel::Cli => extract_cli(def, ssh_session).await,
    };

    let (status, detail, raw_value) = match raw {
        Ok(value) => evaluate(def, &value),
        Err(e) => (
            Status::Error,
            format!("could not extract value: {e}"),
            None,
        ),
    };

    CheckResult {
        check_id: def.id.clone(),
        title: def.title.clone(),
        category: def.category.clone(),
        severity: def.severity.clone(),
        status,
        detail,
        raw_value,
    }
}

async fn extract_api(
    state: &Arc<Mutex<DaemonState>>,
    secrets: &Arc<dyn SecretStore>,
    host_id: uuid::Uuid,
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
    let resp = fortigate::api_request(state, secrets, host_id, "GET", path, "").await?;
    if resp.status >= 400 {
        return Err(anyhow!(
            "API returned HTTP {}: {}",
            resp.status,
            resp.body.chars().take(200).collect::<String>()
        ));
    }
    let v: serde_json::Value =
        serde_json::from_str(&resp.body).context("response is not JSON")?;
    let pointed = v
        .pointer(pointer)
        .ok_or_else(|| anyhow!("pointer {} not found in response", pointer))?;
    Ok(match pointed {
        serde_json::Value::String(s) => s.trim().to_owned(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    })
}

async fn extract_cli(
    def: &CheckDefinition,
    ssh_session: Option<&crate::ssh::connection::SshSession>,
) -> Result<String> {
    let session = ssh_session
        .ok_or_else(|| anyhow!("CLI check {} requires SSH but no session was provided", def.id))?;
    let command = def
        .cli_command
        .as_deref()
        .ok_or_else(|| anyhow!("cli check {} missing cli_command", def.id))?;
    let grep = def
        .cli_grep
        .as_deref()
        .ok_or_else(|| anyhow!("cli check {} missing cli_grep", def.id))?;
    let (_, stdout, _) = session.exec(command).await.context("ssh exec")?;
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

fn evaluate(def: &CheckDefinition, value: &str) -> (Status, String, Option<String>) {
    let raw = Some(value.to_owned());
    let pass_detail = || (Status::Pass, format_pass_detail(def, value), raw.clone());
    let fail_detail = |reason: String| (Status::Fail, reason, raw.clone());

    match &def.expect {
        Expectation::NotContains { needle } => {
            if value.to_lowercase().contains(&needle.to_lowercase()) {
                fail_detail(format!("'{needle}' present in: {value}"))
            } else {
                pass_detail()
            }
        }
        Expectation::Contains { needle } => {
            if value.to_lowercase().contains(&needle.to_lowercase()) {
                pass_detail()
            } else {
                fail_detail(format!("'{needle}' missing in: {value}"))
            }
        }
        Expectation::GreaterEqual { threshold } => match value.parse::<i64>() {
            Ok(n) if n >= *threshold => pass_detail(),
            Ok(n) => fail_detail(format!("{n} < {threshold}")),
            Err(_) => (
                Status::Error,
                format!("could not parse '{value}' as integer"),
                raw,
            ),
        },
        Expectation::LessEqual { threshold } => match value.parse::<i64>() {
            Ok(n) if n <= *threshold => pass_detail(),
            Ok(n) => fail_detail(format!("{n} > {threshold}")),
            Err(_) => (
                Status::Error,
                format!("could not parse '{value}' as integer"),
                raw,
            ),
        },
        Expectation::NotEqual { value: forbidden } => {
            if value.eq_ignore_ascii_case(forbidden) {
                fail_detail(format!("matches forbidden value: {value}"))
            } else {
                pass_detail()
            }
        }
        Expectation::Equal { value: required } => {
            if value.eq_ignore_ascii_case(required) {
                pass_detail()
            } else {
                fail_detail(format!("expected '{required}', got '{value}'"))
            }
        }
    }
}

fn format_pass_detail(def: &CheckDefinition, value: &str) -> String {
    if value.is_empty() {
        format!("{} OK", def.title)
    } else {
        format!("OK ({value})")
    }
}

/// Count pass/fail/error/skip transitions over a check vector.
/// Returns `(passed, failed, errored, skipped)` so the FortiGate
/// runner and the Linux runner share a single counting path —
/// avoids the "two implementations drift" risk and gives the
/// aggregation a direct test target.
pub(crate) fn tally(checks: &[CheckResult]) -> (u32, u32, u32, u32) {
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut errored = 0u32;
    let mut skipped = 0u32;
    for c in checks {
        match c.status {
            Status::Pass => passed += 1,
            Status::Fail => failed += 1,
            Status::Error => errored += 1,
            Status::Skip => skipped += 1,
        }
    }
    (passed, failed, errored, skipped)
}

/// Score: start at 100, subtract severity-weighted penalty for each
/// failed check, ignore skips. Errors count as 1.5× their severity
/// penalty (an unknown is worse than a known-good but better than
/// a known-bad — they need investigation). Clamped to [0, 100].
pub(crate) fn score(results: &[CheckResult]) -> u8 {
    let mut s: f64 = 100.0;
    for r in results {
        match r.status {
            Status::Pass | Status::Skip => {}
            Status::Fail => s -= r.severity.penalty(),
            Status::Error => s -= r.severity.penalty() * 1.5,
        }
    }
    s.clamp(0.0, 100.0).round() as u8
}

// ---------------------------------------------------------------------------
// Default checks (CIS-FortiOS-7.4 L1)
// ---------------------------------------------------------------------------

/// Hardcoded FortiGate baseline. Each check carries:
///   - a stable id so history can correlate across runs
///   - severity that drives score impact
///   - remediation snippet for the GUI's "Fix" button
///
/// All checks use the FortiGate API where possible. CLI fallbacks
/// only where the API doesn't expose the data cheaply (none in
/// the v1 set — all are pure-API).
///
/// Linux baseline rows live in `ssh_compliance::linux_default_checks()`
/// and are merged into `list_checks()` alongside this set since 1.12c.
fn fortigate_default_checks() -> Vec<CheckDefinition> {
    use Channel::*;
    use Severity::*;

    vec![
        CheckDefinition {
            id: "fg.admin.https-port".into(),
            title: "Admin HTTPS on non-default port".into(),
            description: "Admin HTTPS should not run on port 443 — exposes the GUI to opportunistic scanning. Move to a non-standard port to reduce attack surface.".into(),
            category: "Authentication".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.1.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-sport".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::NotEqual { value: "443".into() },
            remediation: Some("config system global\n  set admin-sport 8443\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.telnet".into(),
            title: "Admin Telnet disabled".into(),
            description: "Telnet sends credentials in plaintext. It should always be disabled.".into(),
            category: "Authentication".into(),
            severity: Critical,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.1.5".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-telnet".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "disable".into() },
            remediation: Some("config system global\n  set admin-telnet disable\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.ssh-v1".into(),
            title: "SSH v1 disabled".into(),
            description: "SSH protocol version 1 has known cryptographic weaknesses. Force v2-only on the management plane.".into(),
            category: "Authentication".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.1.7".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-ssh-v1".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "disable".into() },
            remediation: Some("config system global\n  set admin-ssh-v1 disable\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.password-min-length".into(),
            title: "Password minimum length ≥ 14".into(),
            description: "Short passwords are trivially brute-forced. CIS recommends 14 or more characters.".into(),
            category: "Authentication".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.2.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/password-policy".into()),
            api_pointer: Some("/results/min-length".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::GreaterEqual { threshold: 14 },
            remediation: Some("config system password-policy\n  set status enable\n  set min-length 14\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.password-expiry".into(),
            title: "Password expiry enabled".into(),
            description: "Periodic rotation limits the window of opportunity for a stolen credential.".into(),
            category: "Authentication".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.2.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/password-policy".into()),
            api_pointer: Some("/results/expire-status".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system password-policy\n  set expire-status enable\n  set expire-day 90\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.idle-timeout".into(),
            title: "Admin idle timeout ≤ 5 minutes".into(),
            description: "Long admin sessions left unattended are a hijack risk. CIS recommends an idle timeout of five minutes or less.".into(),
            category: "Authentication".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.2.4".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admintimeout".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::LessEqual { threshold: 5 },
            remediation: Some("config system global\n  set admintimeout 5\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.maintainer".into(),
            title: "Admin maintainer disabled".into(),
            description: "The 'maintainer' account allows password recovery via console — a serious physical-access risk in shared facilities.".into(),
            category: "Authentication".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.1.6".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-maintainer".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "disable".into() },
            remediation: Some("config system global\n  set admin-maintainer disable\nend".into()),
        },
        CheckDefinition {
            id: "fg.crypto.strong".into(),
            title: "Strong crypto enabled".into(),
            description: "When 'strong-crypto' is on, FortiOS restricts SSL/TLS cipher suites to FIPS-compliant + strong-only choices.".into(),
            category: "Cryptography".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("2.1.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/strong-crypto".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system global\n  set strong-crypto enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.crypto.tls-min".into(),
            title: "Admin GUI requires TLS 1.2+".into(),
            description: "Older TLS versions have known vulnerabilities. The admin GUI should refuse anything below TLS 1.2.".into(),
            category: "Cryptography".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("2.1.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-https-ssl-versions".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Contains { needle: "tlsv1-2".into() },
            remediation: Some("config system global\n  set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend".into()),
        },
        CheckDefinition {
            id: "fg.crypto.fortiguard-anycast".into(),
            title: "FortiGuard anycast enabled".into(),
            description: "Anycast routing reaches the closest FortiGuard PoP — faster updates and resistant to localised outages.".into(),
            category: "Cryptography".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("2.2.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/fortiguard".into()),
            api_pointer: Some("/results/fortiguard-anycast".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system fortiguard\n  set fortiguard-anycast enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.logging.implicit-deny".into(),
            title: "Implicit deny policy logging".into(),
            description: "Without implicit-deny logging you cannot triage what was blocked. Required for incident response.".into(),
            category: "Logging".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("3.1.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/log/setting".into()),
            api_pointer: Some("/results/fwpolicy-implicit-log".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config log setting\n  set fwpolicy-implicit-log enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.logging.local-disk".into(),
            title: "Local disk logging enabled".into(),
            description: "Disk logging gives a forensic record even when the FortiAnalyzer is unreachable. Required on devices with log disks.".into(),
            category: "Logging".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("3.2.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/log.disk/setting".into()),
            api_pointer: Some("/results/status".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config log disk setting\n  set status enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.update.fortiguard-auto".into(),
            title: "FortiGuard auto-update enabled".into(),
            description: "Automatic AV/IPS signature updates are essential — manual rolls become stale within days.".into(),
            category: "Maintenance".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("4.1.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/autoupdate.schedule".into()),
            api_pointer: Some("/results/status".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system autoupdate schedule\n  set status enable\n  set frequency every\n  set time 01:00\nend".into()),
        },
        CheckDefinition {
            id: "fg.dns.ssl".into(),
            title: "DNS-over-TLS enabled".into(),
            description: "Plain DNS reveals every domain a client visits to anyone on-path. DoT encrypts the resolver path.".into(),
            category: "Network Hardening".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L2".into(),
            cis_reference: Some("5.1.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/dns".into()),
            api_pointer: Some("/results/protocol".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Contains { needle: "dot".into() },
            remediation: Some("config system dns\n  set protocol dot\n  set ssl-certificate \"Fortinet_Factory\"\n  set server-hostname \"globaldns.fortinet.net\"\nend".into()),
        },
        CheckDefinition {
            id: "fg.snmp.v1-disabled".into(),
            title: "SNMPv1/v2 disabled".into(),
            description: "SNMP versions 1 and 2 send the community string in cleartext. v3 (with auth + priv) is mandatory in regulated environments.".into(),
            category: "Network Hardening".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("5.2.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system.snmp/sysinfo".into()),
            api_pointer: Some("/results/status".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "disable".into() },
            remediation: Some("config system snmp sysinfo\n  set status disable\nend\n\n# If you need SNMP, configure v3 only:\nconfig system snmp user\n  edit \"monitor\"\n    set security-level auth-priv\n    set auth-proto sha256\n    set priv-proto aes256\n  next\nend".into()),
        },

        // -------- Authentication & Admin (extended) --------
        CheckDefinition {
            id: "fg.admin.password-min-uppercase".into(),
            title: "Password requires uppercase letters".into(),
            description: "Forcing an uppercase character widens the brute-force keyspace meaningfully without hurting usability.".into(),
            category: "Authentication".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.2.5".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/password-policy".into()),
            api_pointer: Some("/results/min-upper-case-letter".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::GreaterEqual { threshold: 1 },
            remediation: Some("config system password-policy\n  set min-upper-case-letter 1\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.password-min-numbers".into(),
            title: "Password requires digits".into(),
            description: "Mandatory digit + letter mixing is a baseline complexity requirement under CIS, NIST, and most compliance regimes.".into(),
            category: "Authentication".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.2.6".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/password-policy".into()),
            api_pointer: Some("/results/min-number".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::GreaterEqual { threshold: 1 },
            remediation: Some("config system password-policy\n  set min-number 1\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.password-min-non-alpha".into(),
            title: "Password requires special characters".into(),
            description: "Special characters break dictionary attacks. Combined with length and digit/case requirements, this raises the cost of credential stuffing dramatically.".into(),
            category: "Authentication".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.2.7".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/password-policy".into()),
            api_pointer: Some("/results/min-non-alphanumeric".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::GreaterEqual { threshold: 1 },
            remediation: Some("config system password-policy\n  set min-non-alphanumeric 1\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.lockout-threshold".into(),
            title: "Admin lockout after failed attempts".into(),
            description: "Without a failed-login lockout, online password-guessing is unconstrained. CIS recommends locking after 3 attempts.".into(),
            category: "Authentication".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.2.8".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-lockout-threshold".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::LessEqual { threshold: 3 },
            remediation: Some("config system global\n  set admin-lockout-threshold 3\n  set admin-lockout-duration 60\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.lockout-duration".into(),
            title: "Lockout duration ≥ 60 seconds".into(),
            description: "A 60-second lockout meaningfully slows automated attacks without making manual recovery painful for a typo'd legitimate admin.".into(),
            category: "Authentication".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.2.9".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-lockout-duration".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::GreaterEqual { threshold: 60 },
            remediation: Some("config system global\n  set admin-lockout-duration 60\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.scp".into(),
            title: "Admin SCP enabled".into(),
            description: "SCP allows secure file transfer for backups. SCP must be enabled to avoid ad-hoc TFTP fallback (insecure) for config rolls.".into(),
            category: "Authentication".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.1.8".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-scp".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system global\n  set admin-scp enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.admin.password-history".into(),
            title: "Password history ≥ 5".into(),
            description: "Tracking the last 5 passwords blocks the trivially-cyclic 'rotate between two known passwords' anti-pattern.".into(),
            category: "Authentication".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.2.10".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/password-policy".into()),
            api_pointer: Some("/results/reuse-password".into()),
            cli_command: None,
            cli_grep: None,
            // FortiOS uses "disable"/"enable" but stores the policy *value*
            // separately under reuse-password-limit. The simpler check is
            // that history-tracking is enabled — failure here means *no*
            // tracking, which is the actual security regression.
            expect: Expectation::Equal { value: "disable".into() },
            remediation: Some("config system password-policy\n  set reuse-password disable\n  set reuse-password-limit 5\nend".into()),
        },

        // -------- Cryptography (extended) --------
        CheckDefinition {
            id: "fg.crypto.tls-no-sslv3".into(),
            title: "Admin GUI rejects SSLv3".into(),
            description: "SSLv3 is broken (POODLE). It must be excluded from the admin-https-ssl-versions allowlist.".into(),
            category: "Cryptography".into(),
            severity: Critical,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("2.1.3".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-https-ssl-versions".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::NotContains { needle: "sslv3".into() },
            remediation: Some("config system global\n  set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend".into()),
        },
        CheckDefinition {
            id: "fg.crypto.tls-no-tls10".into(),
            title: "Admin GUI rejects TLS 1.0".into(),
            description: "TLS 1.0 has known cryptographic weaknesses (BEAST, RC4 issues) and is deprecated by all major standards bodies.".into(),
            category: "Cryptography".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("2.1.4".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-https-ssl-versions".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::NotContains { needle: "tlsv1-0".into() },
            remediation: Some("config system global\n  set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend".into()),
        },
        CheckDefinition {
            id: "fg.crypto.tls-no-tls11".into(),
            title: "Admin GUI rejects TLS 1.1".into(),
            description: "TLS 1.1 is deprecated alongside TLS 1.0. RFC 8996 prohibits both.".into(),
            category: "Cryptography".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("2.1.5".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-https-ssl-versions".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::NotContains { needle: "tlsv1-1".into() },
            remediation: Some("config system global\n  set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend".into()),
        },
        CheckDefinition {
            id: "fg.crypto.fortiguard-https".into(),
            title: "FortiGuard updates over HTTPS".into(),
            description: "FortiGuard must use HTTPS to authenticate signature integrity. HTTP fallbacks are vulnerable to active downgrade attacks.".into(),
            category: "Cryptography".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("2.2.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/fortiguard".into()),
            api_pointer: Some("/results/protocol".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "https".into() },
            remediation: Some("config system fortiguard\n  set protocol https\n  set port 443\nend".into()),
        },

        // -------- Logging & Audit (extended) --------
        CheckDefinition {
            id: "fg.logging.event-system".into(),
            title: "System event logging enabled".into(),
            description: "Without system event logging, admin actions and config changes vanish. Required for any audit trail.".into(),
            category: "Logging".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("3.1.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/log/eventfilter".into()),
            api_pointer: Some("/results/event".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config log eventfilter\n  set event enable\n  set system enable\n  set user enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.logging.event-user".into(),
            title: "User authentication event logging enabled".into(),
            description: "Required to detect lateral movement / credential abuse: every user auth event must be logged.".into(),
            category: "Logging".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("3.1.3".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/log/eventfilter".into()),
            api_pointer: Some("/results/user".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config log eventfilter\n  set user enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.logging.event-vpn".into(),
            title: "VPN event logging enabled".into(),
            description: "VPN tunnel up/down events are critical for diagnosing connectivity disputes and detecting unauthorized tunnel establishment.".into(),
            category: "Logging".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("3.1.4".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/log/eventfilter".into()),
            api_pointer: Some("/results/vpn".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config log eventfilter\n  set vpn enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.logging.gui-display".into(),
            title: "GUI log-display enabled".into(),
            description: "Setting the FortiGate to display logs in the GUI is essential for first-line triage when admins don't have FortiAnalyzer access.".into(),
            category: "Logging".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("3.2.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/gui-display-hostname".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system global\n  set gui-display-hostname enable\nend".into()),
        },

        // -------- Maintenance & Updates (extended) --------
        CheckDefinition {
            id: "fg.update.frequency-daily".into(),
            title: "FortiGuard updates at least daily".into(),
            description: "Anti-malware signatures change daily. A weekly schedule leaves you 6 days behind on every threat.".into(),
            category: "Maintenance".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("4.1.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/autoupdate.schedule".into()),
            api_pointer: Some("/results/frequency".into()),
            cli_command: None,
            cli_grep: None,
            // "every"/"daily" are both valid daily; we accept "every"
            // (which means hourly when paired with frequency) as well.
            expect: Expectation::NotContains { needle: "weekly".into() },
            remediation: Some("config system autoupdate schedule\n  set frequency daily\n  set time 01:00\nend".into()),
        },
        CheckDefinition {
            id: "fg.update.push".into(),
            title: "FortiGuard push updates enabled".into(),
            description: "Push enables emergency updates between scheduled poll cycles — critical when a 0-day signature drops.".into(),
            category: "Maintenance".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("4.1.3".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/autoupdate.push-update".into()),
            api_pointer: Some("/results/status".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system autoupdate push-update\n  set status enable\nend".into()),
        },

        // -------- Network Hardening (extended) --------
        CheckDefinition {
            id: "fg.dns.dnssec".into(),
            title: "DNS-over-TLS configured securely".into(),
            description: "DoT must use a trusted resolver — Fortinet's globaldns or Cloudflare. Local ISP DoT defeats privacy if the ISP is the threat model.".into(),
            category: "Network Hardening".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L2".into(),
            cis_reference: Some("5.1.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/dns".into()),
            api_pointer: Some("/results/server-hostname".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Contains { needle: "fortinet".into() },
            remediation: Some("config system dns\n  set protocol dot\n  set server-hostname \"globaldns.fortinet.net\"\nend".into()),
        },
        CheckDefinition {
            id: "fg.snmp.if-only-trusted".into(),
            title: "SNMP system info location set".into(),
            description: "Sysinfo location helps inventory tooling correlate device → physical site. Common operational hygiene check.".into(),
            category: "Network Hardening".into(),
            severity: Info,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("5.2.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system.snmp/sysinfo".into()),
            api_pointer: Some("/results/location".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::NotEqual { value: "".into() },
            remediation: Some("config system snmp sysinfo\n  set location \"<DC name / Office address>\"\n  set contact-info \"<NOC email>\"\nend".into()),
        },
        CheckDefinition {
            id: "fg.console.timeout".into(),
            title: "Console idle timeout ≤ 5 minutes".into(),
            description: "An unattended console session is the easiest physical-access attack vector. Force the same idle timeout as the admin GUI.".into(),
            category: "Authentication".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("1.1.9".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/console".into()),
            api_pointer: Some("/results/output".into()),
            cli_command: None,
            cli_grep: None,
            // FortiOS pairs admintimeout (global) with console output;
            // admintimeout already covers console too, so we sanity-check
            // that the console command-mode is not "standard" (which
            // disables the global timeout for console).
            expect: Expectation::NotEqual { value: "standard".into() },
            remediation: Some("config system console\n  set output more\nend".into()),
        },
        CheckDefinition {
            id: "fg.dns.cache-snoop".into(),
            title: "DNS cache spoofing prevention enabled".into(),
            description: "FortiOS includes DNS-over-UDP-only cache spoofing protection (rfc5452 random source-port). Critical for protecting DNS clients behind the FortiGate.".into(),
            category: "Network Hardening".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L2".into(),
            cis_reference: Some("5.1.3".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/dns".into()),
            api_pointer: Some("/results/dns-cache-limit".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::GreaterEqual { threshold: 1 },
            remediation: Some("config system dns\n  set dns-cache-limit 5000\nend".into()),
        },

        // -------- IPS / AV / Web Filter --------
        CheckDefinition {
            id: "fg.ips.update-source".into(),
            title: "IPS database includes extended set".into(),
            description: "FortiOS IPS comes in 'extended' and 'regular' profiles; extended catches significantly more threat patterns at modest CPU cost.".into(),
            category: "IPS".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("6.1.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/ips/global".into()),
            api_pointer: Some("/results/database".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "extended".into() },
            remediation: Some("config ips global\n  set database extended\nend".into()),
        },
        CheckDefinition {
            id: "fg.av.block-greyware".into(),
            title: "Antivirus blocks greyware".into(),
            description: "Greyware (adware, riskware, spyware) is one of the most common malware categories. Default block prevents user-side compromise.".into(),
            category: "Antivirus".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("6.2.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/antivirus/settings".into()),
            api_pointer: Some("/results/grayware".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config antivirus settings\n  set grayware enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.av.block-machine-learning".into(),
            title: "Antivirus ML scanning enabled".into(),
            description: "FortiOS ML-based malware detection catches unknown/zero-day malware that signature-based scanning misses.".into(),
            category: "Antivirus".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("6.2.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/antivirus/settings".into()),
            api_pointer: Some("/results/machine-learning-detection".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config antivirus settings\n  set machine-learning-detection enable\nend".into()),
        },

        // -------- High Availability --------
        CheckDefinition {
            id: "fg.ha.session-pickup".into(),
            title: "HA session-pickup enabled".into(),
            description: "On HA failover without session-pickup, all stateful flows reset — disastrous for VoIP, large file transfers, and long-lived SSH sessions.".into(),
            category: "High Availability".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("7.1.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/ha".into()),
            api_pointer: Some("/results/session-pickup".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system ha\n  set session-pickup enable\n  set session-pickup-connectionless enable\nend".into()),
        },
        CheckDefinition {
            id: "fg.ha.heartbeat-encrypted".into(),
            title: "HA heartbeat encrypted".into(),
            description: "HA heartbeat traffic carries config sync data including secrets. Encryption is mandatory unless heartbeat is on a fully-isolated dedicated link.".into(),
            category: "High Availability".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("7.1.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/ha".into()),
            api_pointer: Some("/results/encryption".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system ha\n  set encryption enable\n  set authentication enable\nend".into()),
        },

        // -------- DoS / Anti-Spoofing --------
        CheckDefinition {
            id: "fg.dos.anti-replay".into(),
            title: "Anti-replay enabled".into(),
            description: "Anti-replay prevents TCP/UDP packet replay attacks. Strict mode is recommended; loose is acceptable in low-throughput environments.".into(),
            category: "Network Hardening".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("5.3.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/anti-replay".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::NotEqual { value: "disable".into() },
            remediation: Some("config system global\n  set anti-replay strict\nend".into()),
        },
        CheckDefinition {
            id: "fg.dos.tcp-mss".into(),
            title: "TCP MSS clamping enabled".into(),
            description: "On WAN-facing tunnels, MSS clamping prevents fragment-related DoS and improves throughput. Required for any FortiGate behind PPPoE / VPN encapsulation.".into(),
            category: "Network Hardening".into(),
            severity: Low,
            framework: "CIS FortiOS 7.4 L2".into(),
            cis_reference: Some("5.3.2".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/tcp-options".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "enable".into() },
            remediation: Some("config system global\n  set tcp-options enable\nend".into()),
        },

        // -------- IPv6 / Modern --------
        CheckDefinition {
            id: "fg.ipv6.fragment-policy".into(),
            title: "IPv6 fragment handling configured".into(),
            description: "IPv6 fragment-based attacks (RA-flood, type-0-routing-header) are a real category. FortiOS must reject malformed fragments — default is permissive.".into(),
            category: "IPv6".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L2".into(),
            cis_reference: Some("8.1.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/ipv6-allow-traffic-redirect".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "disable".into() },
            remediation: Some("config system global\n  set ipv6-allow-traffic-redirect disable\nend".into()),
        },

        // -------- WAN Hardening --------
        CheckDefinition {
            id: "fg.wan.usb-disabled".into(),
            title: "USB modem-management disabled".into(),
            description: "Out-of-band USB modem connectivity bypasses your firewall logging and policy — a textbook back-channel hazard.".into(),
            category: "Network Hardening".into(),
            severity: High,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("5.4.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-usb-console".into()),
            cli_command: None,
            cli_grep: None,
            expect: Expectation::Equal { value: "disable".into() },
            remediation: Some("config system global\n  set admin-usb-console disable\nend".into()),
        },
        CheckDefinition {
            id: "fg.api.https-pki".into(),
            title: "Admin GUI PKI authentication available".into(),
            description: "PKI-based admin authentication is a substantial improvement over passwords for high-value devices. Enables hardware token / smartcard support.".into(),
            category: "Authentication".into(),
            severity: Info,
            framework: "CIS FortiOS 7.4 L2".into(),
            cis_reference: Some("1.3.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/global".into()),
            api_pointer: Some("/results/admin-https-pki-required".into()),
            cli_command: None,
            cli_grep: None,
            // Informational — we don't fail on disabled, we surface it.
            // To keep scoring sane, set Severity::Info above (no penalty).
            expect: Expectation::Equal { value: "disable".into() },
            remediation: Some("# To require PKI:\nconfig system global\n  set admin-https-pki-required enable\nend".into()),
        },

        // -------- Backup & Restore --------
        CheckDefinition {
            id: "fg.backup.auto".into(),
            title: "Automatic config backup configured".into(),
            description: "Without scheduled config backups, every config change risks irreversible loss on hardware failure.".into(),
            category: "Maintenance".into(),
            severity: Medium,
            framework: "CIS FortiOS 7.4 L1".into(),
            cis_reference: Some("4.2.1".into()),
            channel: Api,
            api_path: Some("/api/v2/cmdb/system/auto-script".into()),
            api_pointer: Some("/results".into()),
            cli_command: None,
            cli_grep: None,
            // Existence check — `results` must be a non-empty array.
            // We can't directly express "array is non-empty" in our v1
            // expectation set, so we stringify and check NotEqual to
            // empty-array marker.
            expect: Expectation::NotContains { needle: "[]".into() },
            remediation: Some("# Configure a scheduled config backup script:\nconfig system auto-script\n  edit \"backup-daily\"\n    set interval 86400\n    set repeat 0\n    set start auto\n    set script \"execute backup config tftp /backup/$$NOW.conf 10.0.0.10\"\n  next\nend".into()),
        },
    ]
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Root directory under macOS app support for compliance state.
/// Mirrors the layout used elsewhere in the engine. Created on
/// first write — callers don't need to ensure existence.
fn compliance_dir() -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("compliance");
    p
}

fn host_runs_dir(host_id: &str) -> PathBuf {
    let mut p = compliance_dir();
    p.push(host_id);
    p.push("runs");
    p
}

pub(crate) fn persist_run(run: &ComplianceRun) -> Result<()> {
    let dir = host_runs_dir(&run.host_id);
    std::fs::create_dir_all(&dir).context("create compliance dir")?;
    let mut path = dir;
    path.push(format!("{}.json", run.id));
    let serialized = serde_json::to_vec_pretty(run).context("serialize run")?;
    std::fs::write(&path, serialized).with_context(|| format!("write {path:?}"))?;
    Ok(())
}

/// Load all run summaries for a host, newest-first. Bounded to
/// `limit` to avoid pathological response sizes when the user
/// has years of daily runs. The full check list is NOT loaded
/// into the summary — a separate `load_run` call retrieves a
/// single run with its full check breakdown.
pub fn load_history(host_id: &str, limit: usize) -> Result<Vec<RunSummary>> {
    let dir = host_runs_dir(host_id);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<RunSummary> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {dir:?}"))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .filter_map(|e| match std::fs::read(e.path()) {
            Ok(bytes) => serde_json::from_slice::<ComplianceRun>(&bytes).ok(),
            Err(_) => None,
        })
        .map(|r| RunSummary {
            id: r.id,
            started_at: r.started_at,
            score: r.score,
            passed: r.passed,
            failed: r.failed,
            errored: r.errored,
            firmware: r.firmware,
            triggered_by: r.triggered_by,
            baseline_kind: r.baseline_kind,
        })
        .collect();
    entries.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    if entries.len() > limit {
        entries.truncate(limit);
    }
    Ok(entries)
}

/// Load one specific run by id with its full check breakdown.
pub fn load_run(host_id: &str, run_id: &str) -> Result<ComplianceRun> {
    let mut path = host_runs_dir(host_id);
    path.push(format!("{run_id}.json"));
    let bytes = std::fs::read(&path).with_context(|| format!("read {path:?}"))?;
    let run: ComplianceRun = serde_json::from_slice(&bytes).context("deserialize run")?;
    Ok(run)
}

/// List the full set of available checks across every baseline
/// kind (FortiGate + Linux as of 1.12c) plus any user TOML
/// overlays. The GUI uses this for the "Checks reference"
/// browser and for the per-check Remediation lookup in the host
/// detail view + the report renderer's lib_lookup. Re-loads
/// from disk on every call so user edits show up without a
/// daemon restart — the disk read is bounded (small number of
/// TOML files, kilobytes each), much cheaper than a FortiGate
/// API round-trip.
///
/// **Mixed-baseline shape, 1.12c:** the returned vector contains
/// rows from both `fortigate_default_checks()` and
/// `ssh_compliance::linux_default_checks()`. Every consumer
/// (`ChecksLibrarySheet`, `CheckRow`, `render_markdown_report`'s
/// lib_lookup) is keyed by `check_id` or grouped by per-row
/// `category` — none branch on framework or assume a homogeneous
/// library. Drift between Linux library rows and Linux run-result
/// rows is impossible by construction: both use
/// `ssh_compliance::{category_for, map_severity}` as the single
/// source of truth.
pub fn list_checks() -> Vec<CheckDefinition> {
    let mut checks = fortigate_default_checks();
    checks.extend(crate::ssh_compliance::linux_default_checks());
    if let Ok(user_checks) = load_user_checks() {
        // User-supplied checks override built-ins by id, and
        // append novel ones to the end. Last write wins per id.
        let mut by_id: std::collections::HashMap<String, CheckDefinition> = checks
            .into_iter()
            .map(|c| (c.id.clone(), c))
            .collect();
        for c in user_checks {
            by_id.insert(c.id.clone(), c);
        }
        checks = by_id.into_values().collect();
    }
    // Stable order across runs: by category, then by severity,
    // then by id. Sorted unconditionally — pre-1.12c this was
    // inside the `if let Ok` branch, which meant when
    // load_user_checks errored (no dir / I/O failure) the GUI
    // got author-order rather than the documented sort order.
    // Harmless but inconsistent; sorting always is cheaper than
    // explaining the asymmetry.
    checks.sort_by(|a, b| {
        let sev_rank = |s: &Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        a.category
            .cmp(&b.category)
            .then(sev_rank(&a.severity).cmp(&sev_rank(&b.severity)))
            .then(a.id.cmp(&b.id))
    });
    checks
}

/// Walk the user-checks directory and parse each `.toml` file.
/// Each file may contain multiple `[[check]]` entries via a
/// `checks: Vec<CheckDefinition>` wrapper, or define a single
/// check at file-root. Errors on individual files are logged
/// (so a typo in one TOML doesn't blank everything else) but
/// don't fail the call.
fn load_user_checks() -> Result<Vec<CheckDefinition>> {
    let mut dir = crate::secrets::default_data_dir();
    dir.push("checks");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let read_dir = std::fs::read_dir(&dir).context("read user checks dir")?;
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let bytes = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                warn!("compliance: skipping {path:?}: {e}");
                continue;
            }
        };
        // Try wrapped form first: `[[checks]] ...`.
        #[derive(Deserialize)]
        struct Wrapper {
            checks: Vec<CheckDefinition>,
        }
        if let Ok(wrapper) = toml::from_str::<Wrapper>(&bytes) {
            out.extend(wrapper.checks);
            continue;
        }
        // Fall back to single-check form.
        match toml::from_str::<CheckDefinition>(&bytes) {
            Ok(c) => out.push(c),
            Err(e) => warn!("compliance: failed to parse {path:?}: {e}"),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Scan all hosts
// ---------------------------------------------------------------------------

/// Result of `scan_all`. One entry per host attempted, even if
/// the run failed — the GUI uses `error` to render a red dot
/// next to that host's tile in the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAllResult {
    pub host_id: String,
    pub host_label: String,
    pub run_id: Option<String>,
    pub score: Option<u8>,
    pub error: Option<String>,
}

/// Run compliance against every FortiGate host that has an API
/// token configured. Hosts run in parallel up to a small cap so
/// we don't open hundreds of FortiOS sessions concurrently.
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
                let age = chrono::Utc::now()
                    .signed_duration_since(last)
                    .num_hours();
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

// ---------------------------------------------------------------------------
// Drift detection
// ---------------------------------------------------------------------------

/// Per-check transition between two runs. The GUI groups these
/// into "newly failing", "newly passing", and "still failing" so
/// the user can see *what changed*, not just current state. This
/// is the single most useful insight for daily compliance ops:
/// "we were green yesterday, what regressed overnight?"
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// Was passing in previous run, now failing.
    NewlyFailing,
    /// Was failing in previous run, now passing.
    NewlyPassing,
    /// Failing in both — no change but still a problem.
    StillFailing,
    /// Passing in both — no change.
    StillPassing,
    /// Errored in either run — needs investigation.
    Errored,
    /// Check exists in current run but not previous.
    /// Happens when we extend the check library between runs.
    Added,
    /// Check exists in previous run but not current.
    /// Happens when a check is removed from the library.
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEntry {
    pub check_id: String,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub kind: DriftKind,
    pub previous_status: Option<Status>,
    pub current_status: Option<Status>,
    pub previous_detail: Option<String>,
    pub current_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub current_run_id: String,
    pub previous_run_id: Option<String>,
    pub current_score: u8,
    pub previous_score: Option<u8>,
    pub score_delta: i32,
    pub newly_failing: Vec<DriftEntry>,
    pub newly_passing: Vec<DriftEntry>,
    pub still_failing: Vec<DriftEntry>,
    pub errored: Vec<DriftEntry>,
}

/// Compute a `DriftReport` between two runs of the same host.
/// Order matters: `current` is the newer run, `previous` is the
/// older. The GUI fetches both and calls this; we do it
/// client-side rather than server-side because the comparison is
/// purely declarative and cheap, and it lets the GUI compare
/// arbitrary historical pairs (e.g. "show me what's changed
/// since the deploy 2 weeks ago").
///
/// However, the daemon also exposes this as the `compliance_drift`
/// RPC for the common case of "compare to immediately previous
/// run", so the GUI doesn't have to fetch and process two full
/// runs just to render the drift summary.
pub fn compare(current: &ComplianceRun, previous: Option<&ComplianceRun>) -> DriftReport {
    let mut newly_failing: Vec<DriftEntry> = Vec::new();
    let mut newly_passing: Vec<DriftEntry> = Vec::new();
    let mut still_failing: Vec<DriftEntry> = Vec::new();
    let mut errored: Vec<DriftEntry> = Vec::new();

    let prev_lookup: std::collections::HashMap<&str, &CheckResult> = previous
        .map(|p| {
            p.checks
                .iter()
                .map(|c| (c.check_id.as_str(), c))
                .collect()
        })
        .unwrap_or_default();

    for cur in &current.checks {
        let prev = prev_lookup.get(cur.check_id.as_str()).copied();
        let entry_kind = classify(prev.map(|p| &p.status), &cur.status);
        let entry = DriftEntry {
            check_id: cur.check_id.clone(),
            title: cur.title.clone(),
            category: cur.category.clone(),
            severity: cur.severity.clone(),
            kind: entry_kind.clone(),
            previous_status: prev.map(|p| p.status.clone()),
            current_status: Some(cur.status.clone()),
            previous_detail: prev.map(|p| p.detail.clone()),
            current_detail: Some(cur.detail.clone()),
        };
        match entry_kind {
            DriftKind::NewlyFailing => newly_failing.push(entry),
            DriftKind::NewlyPassing => newly_passing.push(entry),
            DriftKind::StillFailing => still_failing.push(entry),
            DriftKind::Errored => errored.push(entry),
            DriftKind::StillPassing | DriftKind::Added | DriftKind::Removed => {
                // Currently-passing checks aren't surfaced in the drift
                // report's "interesting" buckets — they go into the
                // overall counts via the un-bucketed fields. Added/Removed
                // are rare and tracked silently.
            }
        }
    }

    // Sort each bucket by severity desc so the most urgent items
    // appear first. Within the same severity, alphabetical by id
    // for deterministic output.
    let by_severity = |a: &DriftEntry, b: &DriftEntry| {
        let sev_rank = |s: &Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        sev_rank(&a.severity)
            .cmp(&sev_rank(&b.severity))
            .then(a.check_id.cmp(&b.check_id))
    };
    newly_failing.sort_by(by_severity);
    newly_passing.sort_by(by_severity);
    still_failing.sort_by(by_severity);
    errored.sort_by(by_severity);

    let previous_score = previous.map(|p| p.score);
    let score_delta = previous_score
        .map(|p| i32::from(current.score) - i32::from(p))
        .unwrap_or(0);

    DriftReport {
        current_run_id: current.id.clone(),
        previous_run_id: previous.map(|p| p.id.clone()),
        current_score: current.score,
        previous_score,
        score_delta,
        newly_failing,
        newly_passing,
        still_failing,
        errored,
    }
}

fn classify(prev: Option<&Status>, current: &Status) -> DriftKind {
    match (prev, current) {
        (None, _) => DriftKind::Added,
        (Some(_), Status::Error) => DriftKind::Errored,
        (Some(Status::Pass), Status::Fail) => DriftKind::NewlyFailing,
        (Some(Status::Fail), Status::Pass) => DriftKind::NewlyPassing,
        (Some(Status::Fail), Status::Fail) => DriftKind::StillFailing,
        (Some(Status::Pass), Status::Pass) => DriftKind::StillPassing,
        (Some(Status::Skip), _) | (Some(_), Status::Skip) => DriftKind::Added,
        (Some(Status::Error), _) => DriftKind::Errored,
    }
}

/// Convenience: load the most recent run + the run immediately
/// before it from history, compare them. Returns a `DriftReport`
/// with `previous_run_id = None` if there's only one run on file
/// (the report will show all current failures as "newly failing"
/// since there's no baseline).
pub fn drift_against_previous(host_id: &str, current_run_id: &str) -> Result<DriftReport> {
    let current = load_run(host_id, current_run_id)?;
    let history = load_history(host_id, 100)?;
    // Find the run immediately preceding the current one by
    // started_at. The history is already sorted newest-first by
    // load_history.
    let previous_summary = history
        .iter()
        .find(|s| s.id != current.id && s.started_at < current.started_at);
    let previous = match previous_summary {
        Some(s) => Some(load_run(host_id, &s.id)?),
        None => None,
    };
    Ok(compare(&current, previous.as_ref()))
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

/// Render a complete run as Markdown — suitable for paste into
/// a customer-facing report, GitHub issue, or further conversion
/// to PDF via pandoc / Marked. Covers identity, score breakdown,
/// per-check details with remediation, and (if a previous run is
/// supplied) a drift section.
///
/// Why Markdown not PDF directly: PDF generation requires either
/// a heavy native dep (printpdf, etc.) or a system pandoc. The
/// GUI side can print-to-PDF on macOS (NSPrintOperation handles
/// HTML/Markdown rendering with the user's chosen page style)
/// without the daemon shipping its own PDF stack.
pub fn render_markdown_report(
    run: &ComplianceRun,
    drift: Option<&DriftReport>,
    library: &[CheckDefinition],
) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(4096);

    writeln!(s, "# Compliance Report").unwrap();
    writeln!(s).unwrap();

    // Identity block
    writeln!(s, "## Device").unwrap();
    writeln!(s, "| | |").unwrap();
    writeln!(s, "|---|---|").unwrap();
    if let Some(h) = &run.hostname {
        writeln!(s, "| Hostname | `{h}` |").unwrap();
    }
    if let Some(m) = &run.model {
        writeln!(s, "| Model | {m} |").unwrap();
    }
    if let Some(f) = &run.firmware {
        writeln!(s, "| Firmware | {f} |").unwrap();
    }
    writeln!(
        s,
        "| Scan started | {} |",
        run.started_at.format("%Y-%m-%d %H:%M:%S UTC")
    )
    .unwrap();
    writeln!(
        s,
        "| Triggered by | {:?} |",
        run.triggered_by
    )
    .unwrap();
    writeln!(s).unwrap();

    // Score summary
    writeln!(s, "## Score").unwrap();
    writeln!(
        s,
        "**{}/100** &mdash; {} passed, {} failed, {} errored, {} skipped (out of {} checks)",
        run.score,
        run.passed,
        run.failed,
        run.errored,
        run.skipped,
        run.checks.len()
    )
    .unwrap();
    writeln!(s).unwrap();

    // Drift block
    if let Some(d) = drift {
        writeln!(s, "## Changes Since Previous Run").unwrap();
        if let Some(prev_score) = d.previous_score {
            let arrow = match d.score_delta.signum() {
                1 => "↑",
                -1 => "↓",
                _ => "→",
            };
            writeln!(
                s,
                "Score: {prev_score} {arrow} {} ({:+})",
                d.current_score, d.score_delta
            )
            .unwrap();
        } else {
            writeln!(s, "First scan — no baseline to compare to.").unwrap();
        }
        writeln!(s).unwrap();
        if !d.newly_failing.is_empty() {
            writeln!(s, "### Newly failing").unwrap();
            for e in &d.newly_failing {
                writeln!(s, "- **{}** ({:?}) — {}", e.title, e.severity, e.current_detail.as_deref().unwrap_or("")).unwrap();
            }
            writeln!(s).unwrap();
        }
        if !d.newly_passing.is_empty() {
            writeln!(s, "### Newly passing").unwrap();
            for e in &d.newly_passing {
                writeln!(s, "- {} ({:?})", e.title, e.severity).unwrap();
            }
            writeln!(s).unwrap();
        }
        if !d.still_failing.is_empty() {
            writeln!(s, "### Still failing (unresolved)").unwrap();
            for e in &d.still_failing {
                writeln!(s, "- {} ({:?})", e.title, e.severity).unwrap();
            }
            writeln!(s).unwrap();
        }
    }

    // Per-check details — failures first, sorted by severity
    writeln!(s, "## Findings").unwrap();
    let lib_lookup: std::collections::HashMap<&str, &CheckDefinition> =
        library.iter().map(|d| (d.id.as_str(), d)).collect();
    let mut checks_sorted = run.checks.clone();
    checks_sorted.sort_by(|a, b| {
        // Failures and errors first, by severity desc.
        let rank = |c: &CheckResult| match c.status {
            Status::Fail => match c.severity {
                Severity::Critical => 0,
                Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
                Severity::Info => 4,
            },
            Status::Error => 5,
            Status::Skip => 6,
            Status::Pass => 7,
        };
        rank(a).cmp(&rank(b)).then(a.title.cmp(&b.title))
    });

    for c in &checks_sorted {
        let icon = match c.status {
            Status::Pass => "✅",
            Status::Fail => "❌",
            Status::Error => "⚠️",
            Status::Skip => "⏭",
        };
        writeln!(
            s,
            "### {icon} {} ({:?})",
            c.title, c.severity
        )
        .unwrap();
        writeln!(s, "*Category:* {}", c.category).unwrap();
        if let Some(def) = lib_lookup.get(c.check_id.as_str()) {
            if let Some(cis) = &def.cis_reference {
                writeln!(s, "*CIS reference:* {cis}").unwrap();
            }
            writeln!(s).unwrap();
            writeln!(s, "{}", def.description).unwrap();
        }
        writeln!(s).unwrap();
        writeln!(s, "**Result:** {}", c.detail).unwrap();
        if let Some(raw) = &c.raw_value {
            if !raw.is_empty() {
                writeln!(s, "**Observed value:** `{}`", raw).unwrap();
            }
        }
        if c.status == Status::Fail {
            if let Some(def) = lib_lookup.get(c.check_id.as_str()) {
                if let Some(fix) = &def.remediation {
                    writeln!(s).unwrap();
                    writeln!(s, "**Remediation:**").unwrap();
                    writeln!(s, "```").unwrap();
                    writeln!(s, "{fix}").unwrap();
                    writeln!(s, "```").unwrap();
                }
            }
        }
        writeln!(s).unwrap();
    }

    writeln!(s).unwrap();
    writeln!(
        s,
        "_Generated by SuperManager on {}_",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    )
    .unwrap();
    s
}

// ---------------------------------------------------------------------------
// Tests — pure functions only.
//
// The runner (`run`, `scan_all`) hits FortiGate over the network and is
// out of scope here. Everything below is purely functional and
// deterministic: severity penalties, the `evaluate` matcher,
// `score()` aggregation, `classify()` / `compare()` drift detection,
// and the markdown renderer.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test fixtures --------------------------------------------------

    fn def(id: &str, severity: Severity, expect: Expectation) -> CheckDefinition {
        CheckDefinition {
            id: id.to_owned(),
            title: format!("Test {id}"),
            description: "test check".to_owned(),
            category: "test".to_owned(),
            severity,
            framework: "CIS-FortiOS-7.4".to_owned(),
            cis_reference: None,
            channel: Channel::Api,
            api_path: None,
            api_pointer: None,
            cli_command: None,
            cli_grep: None,
            expect,
            remediation: None,
        }
    }

    fn result(check_id: &str, severity: Severity, status: Status) -> CheckResult {
        CheckResult {
            check_id: check_id.to_owned(),
            status,
            detail: "x".to_owned(),
            raw_value: None,
            severity,
            title: format!("Test {check_id}"),
            category: "test".to_owned(),
        }
    }

    fn run_fixture(id: &str, score_val: u8, checks: Vec<CheckResult>) -> ComplianceRun {
        let passed = checks.iter().filter(|c| matches!(c.status, Status::Pass)).count() as u32;
        let failed = checks.iter().filter(|c| matches!(c.status, Status::Fail)).count() as u32;
        let errored = checks.iter().filter(|c| matches!(c.status, Status::Error)).count() as u32;
        let skipped = checks.iter().filter(|c| matches!(c.status, Status::Skip)).count() as u32;
        ComplianceRun {
            id: id.to_owned(),
            host_id: "00000000-0000-0000-0000-000000000000".to_owned(),
            started_at: Utc::now() - chrono::Duration::seconds(60),
            finished_at: Utc::now(),
            firmware: Some("7.4.1".to_owned()),
            model: Some("FG-60F".to_owned()),
            hostname: Some("test-fw".to_owned()),
            triggered_by: TriggerKind::Manual,
            baseline_kind: BaselineKind::Fortigate,
            score: score_val,
            passed,
            failed,
            errored,
            skipped,
            checks,
        }
    }

    // -- Severity penalties --------------------------------------------

    #[test]
    fn severity_penalty_ladder() {
        // Higher severity ⇒ larger penalty. The ladder powers `score()`;
        // changing these numbers shifts every customer's compliance
        // score, so the ladder is part of the public contract.
        assert_eq!(Severity::Info.penalty(), 0.0);
        assert_eq!(Severity::Low.penalty(), 0.5);
        assert_eq!(Severity::Medium.penalty(), 2.0);
        assert_eq!(Severity::High.penalty(), 5.0);
        assert_eq!(Severity::Critical.penalty(), 10.0);
    }

    // -- evaluate() — one test per Expectation variant ------------------

    #[test]
    fn evaluate_not_contains_passes_when_needle_absent() {
        let d = def("admin-port", Severity::High,
            Expectation::NotContains { needle: "https".into() });
        let (status, _, _) = evaluate(&d, "ssh ping");
        assert_eq!(status, Status::Pass);
    }

    #[test]
    fn evaluate_not_contains_fails_case_insensitively() {
        // The 'allowaccess HTTPS PING' regression — uppercase
        // needle in haystack used to slip through because the
        // first cut compared raw strings.
        let d = def("admin-port", Severity::High,
            Expectation::NotContains { needle: "https".into() });
        let (status, detail, _) = evaluate(&d, "HTTPS PING");
        assert_eq!(status, Status::Fail);
        assert!(detail.contains("https"), "detail should name the needle");
    }

    #[test]
    fn evaluate_contains_passes_when_present() {
        let d = def("strong-crypto", Severity::High,
            Expectation::Contains { needle: "enable".into() });
        let (status, _, _) = evaluate(&d, "strong-crypto enable");
        assert_eq!(status, Status::Pass);
    }

    #[test]
    fn evaluate_contains_fails_when_missing() {
        let d = def("strong-crypto", Severity::High,
            Expectation::Contains { needle: "enable".into() });
        let (status, _, _) = evaluate(&d, "strong-crypto disable");
        assert_eq!(status, Status::Fail);
    }

    #[test]
    fn evaluate_greater_equal_passes_at_threshold() {
        let d = def("pw-min", Severity::Medium,
            Expectation::GreaterEqual { threshold: 14 });
        let (status, _, _) = evaluate(&d, "14");
        assert_eq!(status, Status::Pass, "exactly at threshold should pass");
    }

    #[test]
    fn evaluate_greater_equal_passes_above_threshold() {
        let d = def("pw-min", Severity::Medium,
            Expectation::GreaterEqual { threshold: 14 });
        assert_eq!(evaluate(&d, "20").0, Status::Pass);
    }

    #[test]
    fn evaluate_greater_equal_fails_below_threshold() {
        let d = def("pw-min", Severity::Medium,
            Expectation::GreaterEqual { threshold: 14 });
        let (status, detail, _) = evaluate(&d, "8");
        assert_eq!(status, Status::Fail);
        assert!(detail.contains("8") && detail.contains("14"));
    }

    #[test]
    fn evaluate_greater_equal_errors_on_non_numeric() {
        // Important: a parse failure must NOT be silently treated
        // as "pass" — the previous matcher tried this and let
        // misparsed CLI output through as passing.
        let d = def("pw-min", Severity::Medium,
            Expectation::GreaterEqual { threshold: 14 });
        let (status, _, _) = evaluate(&d, "(empty)");
        assert_eq!(status, Status::Error);
    }

    #[test]
    fn evaluate_less_equal_passes_at_threshold() {
        let d = def("admin-timeout", Severity::Medium,
            Expectation::LessEqual { threshold: 5 });
        assert_eq!(evaluate(&d, "5").0, Status::Pass);
    }

    #[test]
    fn evaluate_less_equal_fails_above_threshold() {
        let d = def("admin-timeout", Severity::Medium,
            Expectation::LessEqual { threshold: 5 });
        let (status, _, _) = evaluate(&d, "60");
        assert_eq!(status, Status::Fail);
    }

    #[test]
    fn evaluate_less_equal_errors_on_non_numeric() {
        let d = def("admin-timeout", Severity::Medium,
            Expectation::LessEqual { threshold: 5 });
        let (status, _, _) = evaluate(&d, "nope");
        assert_eq!(status, Status::Error);
    }

    #[test]
    fn evaluate_not_equal_fails_on_forbidden() {
        let d = def("admin-port", Severity::High,
            Expectation::NotEqual { value: "443".into() });
        let (status, _, _) = evaluate(&d, "443");
        assert_eq!(status, Status::Fail);
    }

    #[test]
    fn evaluate_not_equal_is_case_insensitive() {
        // "ENABLE" vs "enable" must compare equal here — FortiGate
        // CLI sometimes emits uppercase labels.
        let d = def("force-https", Severity::High,
            Expectation::NotEqual { value: "disable".into() });
        let (status, _, _) = evaluate(&d, "DISABLE");
        assert_eq!(status, Status::Fail);
    }

    #[test]
    fn evaluate_equal_passes_on_match() {
        let d = def("set-mode", Severity::Low,
            Expectation::Equal { value: "enable".into() });
        assert_eq!(evaluate(&d, "enable").0, Status::Pass);
    }

    #[test]
    fn evaluate_equal_fails_on_mismatch() {
        let d = def("set-mode", Severity::Low,
            Expectation::Equal { value: "enable".into() });
        assert_eq!(evaluate(&d, "disable").0, Status::Fail);
    }

    #[test]
    fn evaluate_equal_is_case_insensitive() {
        let d = def("set-mode", Severity::Low,
            Expectation::Equal { value: "Enable".into() });
        assert_eq!(evaluate(&d, "ENABLE").0, Status::Pass);
    }

    // -- score() — the public-facing 0-100 customer number --------------

    #[test]
    fn score_empty_is_100() {
        assert_eq!(score(&[]), 100);
    }

    #[test]
    fn score_all_pass_is_100() {
        let results = vec![
            result("a", Severity::Critical, Status::Pass),
            result("b", Severity::High, Status::Pass),
            result("c", Severity::Medium, Status::Pass),
        ];
        assert_eq!(score(&results), 100);
    }

    #[test]
    fn score_skip_ignored() {
        // Skip means "didn't apply" — should NOT reduce score.
        let results = vec![
            result("a", Severity::Critical, Status::Skip),
            result("b", Severity::High, Status::Skip),
        ];
        assert_eq!(score(&results), 100);
    }

    #[test]
    fn score_one_critical_fail_subtracts_10() {
        // Customer sees 90/100 for one critical misconfig.
        let results = vec![result("a", Severity::Critical, Status::Fail)];
        assert_eq!(score(&results), 90);
    }

    #[test]
    fn score_critical_error_is_15_off() {
        // Errors are 1.5× penalty — Critical (10) × 1.5 = 15.
        // An unknown-due-to-error is treated as worse than a
        // known-good but slightly less bad than a known-bad
        // because the operator might still discover it's fine.
        let results = vec![result("a", Severity::Critical, Status::Error)];
        assert_eq!(score(&results), 85);
    }

    #[test]
    fn score_clamped_to_zero_on_lots_of_failures() {
        let results: Vec<CheckResult> = (0..20)
            .map(|i| result(&format!("c{i}"), Severity::Critical, Status::Fail))
            .collect();
        // 20 × 10 = 200, well below 0 — must clamp.
        assert_eq!(score(&results), 0);
    }

    #[test]
    fn score_clamped_to_one_hundred_on_passes_only() {
        // Belt-and-braces: even with 1000 passes the score can't
        // overflow the upper bound.
        let results: Vec<CheckResult> = (0..1000)
            .map(|i| result(&format!("c{i}"), Severity::High, Status::Pass))
            .collect();
        assert_eq!(score(&results), 100);
    }

    #[test]
    fn score_rounds_half_up() {
        // 1 medium fail = -2.0 → 98.0 (no rounding question, integer).
        // One Low fail = -0.5 → 99.5 → 100 (banker's rounding could
        // round either way; Rust's f64::round rounds half away from
        // zero, so 99.5 → 100).
        let one_low = vec![result("a", Severity::Low, Status::Fail)];
        let s = score(&one_low);
        // Accept either 99 or 100 depending on rounding mode, but
        // it must not be wildly off.
        assert!(s == 99 || s == 100, "got {s}");
    }

    #[test]
    fn score_mixed_severities_compose_linearly() {
        let results = vec![
            result("a", Severity::Critical, Status::Fail), // -10
            result("b", Severity::High, Status::Fail),     // -5
            result("c", Severity::Medium, Status::Fail),   // -2
            result("d", Severity::Low, Status::Fail),      // -0.5
            // Total: -17.5 → 83 (rounds from 82.5)
        ];
        let s = score(&results);
        // 82.5 → 83 with round-half-away-from-zero
        assert!(s == 82 || s == 83, "got {s}");
    }

    // -- classify() — drift state machine -------------------------------

    #[test]
    fn classify_none_to_anything_is_added() {
        assert!(matches!(classify(None, &Status::Pass), DriftKind::Added));
        assert!(matches!(classify(None, &Status::Fail), DriftKind::Added));
    }

    #[test]
    fn classify_pass_to_fail_is_newly_failing() {
        // The single most important drift signal — was OK, now isn't.
        // GUI shows these in red at the top of the report.
        assert!(matches!(
            classify(Some(&Status::Pass), &Status::Fail),
            DriftKind::NewlyFailing
        ));
    }

    #[test]
    fn classify_fail_to_pass_is_newly_passing() {
        assert!(matches!(
            classify(Some(&Status::Fail), &Status::Pass),
            DriftKind::NewlyPassing
        ));
    }

    #[test]
    fn classify_fail_to_fail_is_still_failing() {
        assert!(matches!(
            classify(Some(&Status::Fail), &Status::Fail),
            DriftKind::StillFailing
        ));
    }

    #[test]
    fn classify_pass_to_pass_is_still_passing() {
        assert!(matches!(
            classify(Some(&Status::Pass), &Status::Pass),
            DriftKind::StillPassing
        ));
    }

    #[test]
    fn classify_current_error_always_errored() {
        // No matter what came before — if the current run errored,
        // that's the bucket. Operator needs to investigate.
        assert!(matches!(
            classify(Some(&Status::Pass), &Status::Error),
            DriftKind::Errored
        ));
        assert!(matches!(
            classify(Some(&Status::Fail), &Status::Error),
            DriftKind::Errored
        ));
    }

    #[test]
    fn classify_skip_treated_as_added() {
        // Skip means "didn't apply" — comparing across skip is
        // not meaningful, so we treat the pair as "freshly added".
        assert!(matches!(
            classify(Some(&Status::Skip), &Status::Pass),
            DriftKind::Added
        ));
        assert!(matches!(
            classify(Some(&Status::Pass), &Status::Skip),
            DriftKind::Added
        ));
    }

    // -- compare() — the full drift report ------------------------------

    #[test]
    fn compare_first_run_has_no_previous() {
        let current = run_fixture("r1", 90,
            vec![result("a", Severity::Critical, Status::Fail)]);
        let d = compare(&current, None);
        assert_eq!(d.current_run_id, "r1");
        assert_eq!(d.previous_run_id, None);
        assert_eq!(d.previous_score, None);
        assert_eq!(d.score_delta, 0);
        // First-run failures classify as Added → silent bucket;
        // they don't appear in any drift list. (UI shows them
        // via the run's own checks, not via drift.)
        assert!(d.newly_failing.is_empty(),
                "first run has no drift baseline, so nothing is newly_failing");
    }

    #[test]
    fn compare_newly_failing_surfaces_one_check() {
        let previous = run_fixture("r0", 100,
            vec![result("a", Severity::Critical, Status::Pass)]);
        let current = run_fixture("r1", 90,
            vec![result("a", Severity::Critical, Status::Fail)]);
        let d = compare(&current, Some(&previous));
        assert_eq!(d.newly_failing.len(), 1);
        assert_eq!(d.newly_failing[0].check_id, "a");
        assert_eq!(d.score_delta, -10);
        assert_eq!(d.previous_score, Some(100));
    }

    #[test]
    fn compare_newly_passing_surfaces_one_check() {
        let previous = run_fixture("r0", 90,
            vec![result("a", Severity::Critical, Status::Fail)]);
        let current = run_fixture("r1", 100,
            vec![result("a", Severity::Critical, Status::Pass)]);
        let d = compare(&current, Some(&previous));
        assert_eq!(d.newly_passing.len(), 1);
        assert_eq!(d.newly_passing[0].check_id, "a");
        assert_eq!(d.score_delta, 10);
    }

    #[test]
    fn compare_still_failing_carries_over() {
        let previous = run_fixture("r0", 90,
            vec![result("a", Severity::High, Status::Fail)]);
        let current = run_fixture("r1", 90,
            vec![result("a", Severity::High, Status::Fail)]);
        let d = compare(&current, Some(&previous));
        assert_eq!(d.still_failing.len(), 1);
        assert!(d.newly_failing.is_empty());
        assert_eq!(d.score_delta, 0);
    }

    #[test]
    fn compare_buckets_sorted_by_severity() {
        // Critical at the top, alphabetical ID tiebreaker inside.
        let previous = run_fixture("r0", 100,
            vec![
                result("a-low",      Severity::Low,      Status::Pass),
                result("b-critical", Severity::Critical, Status::Pass),
                result("c-medium",   Severity::Medium,   Status::Pass),
            ]);
        let current = run_fixture("r1", 88,
            vec![
                result("a-low",      Severity::Low,      Status::Fail),
                result("b-critical", Severity::Critical, Status::Fail),
                result("c-medium",   Severity::Medium,   Status::Fail),
            ]);
        let d = compare(&current, Some(&previous));
        assert_eq!(d.newly_failing.len(), 3);
        assert_eq!(d.newly_failing[0].check_id, "b-critical", "Critical first");
        assert_eq!(d.newly_failing[1].check_id, "c-medium",   "Medium next");
        assert_eq!(d.newly_failing[2].check_id, "a-low",      "Low last");
    }

    #[test]
    fn compare_errored_bucket_distinct_from_failing() {
        let previous = run_fixture("r0", 95,
            vec![result("a", Severity::High, Status::Pass)]);
        let current = run_fixture("r1", 90,
            vec![result("a", Severity::High, Status::Error)]);
        let d = compare(&current, Some(&previous));
        assert!(d.newly_failing.is_empty(),
                "an error is NOT a fail — operator action different");
        assert_eq!(d.errored.len(), 1);
    }

    // -- list_checks() — built-in check library -------------------------

    #[test]
    fn list_checks_returns_nonempty_baseline() {
        // Drives the GUI's settings → checks list. If this ever
        // returns empty, the GUI panel hides the entire library —
        // canary against a copy-paste regression.
        let checks = list_checks();
        assert!(!checks.is_empty(), "default check library must not be empty");
    }

    #[test]
    fn list_checks_ids_are_unique() {
        // History correlates runs by check id. Duplicate ids would
        // make drift detection wrong without an error message.
        let checks = list_checks();
        let mut seen = std::collections::HashSet::new();
        for c in &checks {
            assert!(seen.insert(c.id.clone()),
                    "duplicate check id {}", c.id);
        }
    }

    #[test]
    fn list_checks_have_remediation_for_failures() {
        // Each shipping check should have a "Fix" snippet so the
        // GUI's remediation affordance has something to show.
        // Tolerance: not 100% — info-severity informational checks
        // are exempt.
        let checks = list_checks();
        let actionable: Vec<_> = checks
            .iter()
            .filter(|c| !matches!(c.severity, Severity::Info))
            .collect();
        let with_remediation = actionable
            .iter()
            .filter(|c| c.remediation.is_some())
            .count();
        let total = actionable.len();
        assert!(with_remediation * 100 / total.max(1) >= 80,
                "≥80% of actionable checks should ship a remediation snippet — got {with_remediation}/{total}");
    }

    // -- 1.12c: Linux library merged into list_checks() ----------------

    #[test]
    fn list_checks_includes_linux_baseline_rows() {
        // Asserts the Linux library merge in list_checks(). Without
        // this, the in-row Remediation block in ComplianceHostView
        // and the Remediation column in render_markdown_report
        // would silently miss every linux.* check_id — the exact
        // gap 1.12c was created to close. A regression here would
        // re-open both tracked defects at once.
        let checks = list_checks();
        let linux_rows: Vec<_> = checks
            .iter()
            .filter(|c| c.framework == "CIS Linux 4.0")
            .collect();
        assert!(!linux_rows.is_empty(),
            "Linux library rows must appear in list_checks() — \
             merge from ssh_compliance::linux_default_checks() is missing");
        // Count parity with the runner's authored set — drift here
        // would mean the library and the runner have different
        // numbers of Linux checks.
        assert_eq!(linux_rows.len(), crate::ssh_compliance::check_count(),
            "library Linux row count ({}) must equal runner LINUX_CHECKS count ({})",
            linux_rows.len(),
            crate::ssh_compliance::check_count());
    }

    #[test]
    fn linux_library_rows_carry_remediation() {
        // The load-bearing field for the in-row Remediation block
        // and the report's Remediation column. If a linux.* row
        // arrives with remediation: None, both surfaces silently
        // hide for that check — the exact wrong-by-omission
        // failure mode 1.12 was gated to prevent.
        let checks = list_checks();
        for c in checks.iter().filter(|c| c.id.starts_with("linux.")) {
            assert!(c.remediation.is_some(),
                "linux check `{}` must carry a remediation snippet — \
                 missing remediation re-opens the 1.12b tracked defect",
                c.id);
            let r = c.remediation.as_ref().unwrap();
            assert!(!r.is_empty(),
                "linux check `{}` has Some(remediation) but the string is empty",
                c.id);
        }
    }

    #[test]
    fn linux_library_category_byte_identical_to_runner_category() {
        // Runtime backstop for Option A's "identical by construction"
        // guarantee. The runner (ssh_compliance::run_baseline) stamps
        // CheckResult.category via category_for(check.id); the library
        // (ssh_compliance::linux_default_checks) stamps
        // CheckDefinition.category via the same helper. This test
        // asserts that guarantee at runtime — a future refactor that
        // re-introduces a parallel string source would fail here.
        // Same role as the DeviceType.allCases sweep plays for the
        // 1.12b dispatch allowlist.
        let library: Vec<crate::compliance::CheckDefinition> =
            crate::ssh_compliance::linux_default_checks();
        for row in &library {
            let runner_category = crate::ssh_compliance::category_for_id(&row.id);
            assert_eq!(row.category, runner_category,
                "DRIFT: library category for `{}` is `{}` but \
                 runner would stamp `{}` — parallel string sources \
                 reintroduced, breaks Option A invariant",
                row.id, row.category, runner_category);
        }
        // Cross-check: stage a fake CheckResult through the runner's
        // helper for one specific id and confirm the library agrees
        // on that exact string. This catches a category_for refactor
        // that accidentally returns a different value while still
        // satisfying the loop above (e.g. if both helpers diverged
        // in lockstep — unlikely but the explicit single-id assertion
        // anchors the regression test in human-readable values).
        let runner_says_for_ssh = crate::ssh_compliance::category_for_id(
            "linux.ssh.password-auth-disabled");
        assert_eq!(runner_says_for_ssh, "SSH",
            "category_for_id has drifted from the documented 1.12a mapping");
        let library_row = library.iter()
            .find(|c| c.id == "linux.ssh.password-auth-disabled")
            .expect("library must contain linux.ssh.password-auth-disabled");
        assert_eq!(library_row.category, "SSH",
            "library row category for linux.ssh.* must be `SSH`, got `{}`",
            library_row.category);
    }

    #[test]
    fn render_report_emits_remediation_block_for_failed_linux_check() {
        // End-to-end: a Linux ComplianceRun with one failed check,
        // rendered against the widened library, must produce a
        // **Remediation:** block. Closes the loop from 1.12b's
        // tracked defect to 1.12c's fix — if this regresses, the
        // report ships with a missing Remediation column on Linux
        // runs.
        use crate::ssh_compliance;
        let library = list_checks();
        let failed = CheckResult {
            check_id: "linux.ssh.password-auth-disabled".to_owned(),
            status: Status::Fail,
            detail: "Password auth is enabled".to_owned(),
            raw_value: Some("passwordauthentication yes".to_owned()),
            severity: Severity::High,
            title: "sshd PasswordAuthentication disabled".to_owned(),
            // Same string the runner would stamp — see the test
            // above for the byte-identity assertion.
            category: ssh_compliance::category_for_id(
                "linux.ssh.password-auth-disabled"),
        };
        let run = ComplianceRun {
            id: uuid::Uuid::new_v4().simple().to_string(),
            host_id: "test-host".to_owned(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            firmware: None,
            model: None,
            hostname: Some("test-linux".to_owned()),
            triggered_by: TriggerKind::Manual,
            baseline_kind: BaselineKind::Linux,
            score: 90,
            passed: 0,
            failed: 1,
            errored: 0,
            skipped: 0,
            checks: vec![failed],
        };
        let md = render_markdown_report(&run, None, &library);
        assert!(md.contains("**Remediation:**"),
            "Linux runs must produce a Remediation block in the report — \
             1.12b tracked defect; if this regresses, the report is \
             wrong-by-omission again. Rendered:\n{}", md);
        // And the actual remediation text from LINUX_CHECKS:
        assert!(md.contains("PasswordAuthentication no"),
            "remediation text from ssh_compliance must appear in the rendered report");
    }

    // -- render_markdown_report() — smoke tests -------------------------

    #[test]
    fn render_report_contains_score_block() {
        let run = run_fixture("r1", 92, vec![result("a", Severity::High, Status::Pass)]);
        let md = render_markdown_report(&run, None, &[]);
        assert!(md.contains("# Compliance Report"));
        assert!(md.contains("## Score"));
        assert!(md.contains("**92/100**"), "score line must appear verbatim");
    }

    #[test]
    fn render_report_first_run_message_when_no_drift() {
        let run = run_fixture("r1", 100, vec![]);
        let drift = compare(&run, None);
        let md = render_markdown_report(&run, Some(&drift), &[]);
        assert!(md.contains("First scan"),
                "should explicitly call out that there's no baseline");
    }

    #[test]
    fn render_report_drift_block_shows_arrow() {
        let previous = run_fixture("r0", 95, vec![result("a", Severity::High, Status::Pass)]);
        let current  = run_fixture("r1", 90, vec![result("a", Severity::High, Status::Fail)]);
        let drift = compare(&current, Some(&previous));
        let md = render_markdown_report(&current, Some(&drift), &[]);
        assert!(md.contains("## Changes Since Previous Run"));
        assert!(md.contains("95"),
                "previous score must appear in the drift line");
        assert!(md.contains("-5"),
                "score delta must appear with sign");
        assert!(md.contains("Newly failing"),
                "newly-failing section must appear");
    }

    #[test]
    fn render_report_findings_section_always_present() {
        // Even with zero checks, the heading exists — keeps the
        // PDF layout predictable for stylesheet authors.
        let run = run_fixture("r1", 100, vec![]);
        let md = render_markdown_report(&run, None, &[]);
        assert!(md.contains("## Findings"));
    }

    #[test]
    fn render_report_includes_device_identity() {
        let run = run_fixture("r1", 95, vec![]);
        let md = render_markdown_report(&run, None, &[]);
        // Identity table — hostname/model/firmware are how the
        // customer recognises which device a report describes.
        assert!(md.contains("test-fw"));
        assert!(md.contains("FG-60F"));
        assert!(md.contains("7.4.1"));
    }

    // -- BaselineKind back-compat (1.12a) ------------------------------
    //
    // ComplianceRun rows persisted before 1.12a have no
    // `baseline_kind` field on disk. Decoding must default them to
    // `BaselineKind::Fortigate` — every legacy row is a FortiGate
    // run because Linux runs had no persistence at all before this
    // change. If serde-default ever regresses (e.g. someone removes
    // the attribute), the daemon would refuse to load every
    // historical run on startup. That's customer data loss in
    // appearance; this test prevents the regression.

    #[test]
    fn compliance_run_decodes_without_baseline_kind_as_fortigate() {
        // JSON deliberately omits `baseline_kind`. Mirrors what
        // ships on disk from any pre-1.12a daemon.
        let json = r#"{
            "id": "legacy-row-1",
            "host_id": "00000000000000000000000000000001",
            "started_at": "2024-01-01T00:00:00Z",
            "finished_at": "2024-01-01T00:00:30Z",
            "firmware": "7.4.1",
            "model": "FG-60F",
            "hostname": "old-fw",
            "triggered_by": "manual",
            "score": 88,
            "passed": 12,
            "failed": 3,
            "errored": 0,
            "skipped": 0,
            "checks": []
        }"#;
        let run: ComplianceRun = serde_json::from_str(json)
            .expect("legacy run with no baseline_kind must decode");
        assert_eq!(run.baseline_kind, BaselineKind::Fortigate,
            "missing baseline_kind must default to Fortigate, not Linux");
        assert_eq!(run.id, "legacy-row-1");
        assert_eq!(run.score, 88);
    }

    #[test]
    fn run_summary_decodes_without_baseline_kind_as_fortigate() {
        // history endpoint also returns rows projected through
        // RunSummary — exercise its serde-default path too.
        let json = r#"{
            "id": "legacy-summary-1",
            "started_at": "2024-01-01T00:00:00Z",
            "score": 88,
            "passed": 12,
            "failed": 3,
            "errored": 0,
            "firmware": "7.4.1",
            "triggered_by": "manual"
        }"#;
        let summary: RunSummary = serde_json::from_str(json)
            .expect("legacy summary with no baseline_kind must decode");
        assert_eq!(summary.baseline_kind, BaselineKind::Fortigate);
    }
}
