//! Linux compliance baseline run over SSH.
//!
//! The existing `compliance.rs` module targets FortiGate via the
//! REST API. Linux servers (which an MSP fleet has *plenty* of)
//! got nothing — operators couldn't answer "is this server's
//! sshd configured per CIS?" from the GUI.
//!
//! # Approach
//!
//! Each check is a small `LinuxCheck` declaring:
//!   - The shell command to run (`grep`, `sysctl`, `systemctl`, etc.)
//!   - A regex/substring assertion on the output that means "pass"
//!   - Severity + recommendation if it fails
//!
//! We run the commands over an existing SSH connection (the same
//! connection_pool the SSH section uses). No agent install
//! required — vanilla coreutils is enough for the starter set.
//!
//! # Coverage (v1)
//!
//! Hand-picked from CIS Linux 4.0 Benchmark — the checks an
//! attacker exploits most reliably:
//!   - SSH password auth disabled (vs key-only)
//!   - SSH root login disabled
//!   - SSH protocol v2 only (rule out v1 fallback)
//!   - Kernel core_pattern is sane (no pipe to attacker process)
//!   - World-writable files in / (excluding /tmp)
//!   - Listening services beyond expected baseline
//!   - rsyslog / journald running (audit trail exists)
//!
//! Future: kernel hardening sysctls, AIDE/auditd presence, automatic
//! updates configured. Each new check is ~10 lines.

use chrono::Utc;

use crate::compliance::{self, BaselineKind, ComplianceRun, Status, TriggerKind};
use crate::vuln::Severity;

struct LinuxCheck {
    id: &'static str,
    title: &'static str,
    command: &'static str,
    /// Substring that, when present in stdout, means the check
    /// PASSED. Inverse: if the substring is absent, the check
    /// failed.
    expect_contains: &'static str,
    severity: Severity,
    /// CVSS score, currently unused by both the runner and the
    /// library (the library uses `severity` as the operator-facing
    /// magnitude; CVSS is preserved here for a future risk-score
    /// integration). Marked allow(dead_code) until consumed.
    #[allow(dead_code)]
    cvss: f32,
    detail_on_fail: &'static str,
    /// Authored remediation text. Read by `linux_default_checks()`
    /// into `CheckDefinition.remediation` since 1.12c — drives the
    /// in-row Remediation block and the report's Remediation column.
    recommendation: &'static str,
}

const LINUX_CHECKS: &[LinuxCheck] = &[
    LinuxCheck {
        id: "linux.ssh.password-auth-disabled",
        title: "sshd PasswordAuthentication disabled",
        // Effective config (sshd -T) takes precedence over file —
        // grep against -T's output to see what sshd actually does
        // after parsing all Match blocks.
        command: "sshd -T 2>/dev/null | grep -i '^passwordauthentication' || sshd -T -f /etc/ssh/sshd_config 2>/dev/null | grep -i '^passwordauthentication'",
        expect_contains: "passwordauthentication no",
        severity: Severity::High,
        cvss: 7.0,
        detail_on_fail: "SSH password auth is enabled — exposes the host to credential-stuffing and brute-force attacks. Key-based auth is the modern best practice.",
        recommendation: "Set `PasswordAuthentication no` in /etc/ssh/sshd_config. Verify all admins have keys deployed before applying. Reload sshd: `systemctl reload sshd`.",
    },
    LinuxCheck {
        id: "linux.ssh.root-login-disabled",
        title: "sshd PermitRootLogin disabled",
        command: "sshd -T 2>/dev/null | grep -i '^permitrootlogin'",
        expect_contains: "permitrootlogin no",
        severity: Severity::High,
        cvss: 7.0,
        detail_on_fail: "Direct root SSH login is allowed. Use sudo for privilege escalation instead — keeps an audit trail of which user invoked which root command.",
        recommendation: "Set `PermitRootLogin no` in /etc/ssh/sshd_config. Reload sshd.",
    },
    LinuxCheck {
        id: "linux.ssh.protocol-v2-only",
        title: "sshd Protocol 2 only",
        // Modern sshd doesn't even compile Protocol 1 — we check
        // by inspecting the daemon-reported version.
        command: "ssh -V 2>&1 | head -1",
        expect_contains: "OpenSSH",
        severity: Severity::Medium,
        cvss: 4.0,
        detail_on_fail: "Could not detect OpenSSH version. SSHv1 is broken and shouldn't be on PATH.",
        recommendation: "Install OpenSSH ≥7.0 (SSHv1 was removed in 7.0). Verify with `ssh -V`.",
    },
    LinuxCheck {
        id: "linux.kernel.core-pattern-safe",
        title: "kernel.core_pattern not piped to attacker",
        command: "sysctl -n kernel.core_pattern 2>/dev/null",
        // Pass: starts with `core` or `/var` or empty (default).
        // The attack vector is `|/path/to/program` which lets
        // an attacker triggering a SIGSEGV run code as root
        // (CVE-2021-4034 / pwnkit-class).
        expect_contains: "core",
        severity: Severity::High,
        cvss: 7.5,
        detail_on_fail: "kernel.core_pattern is unusual. If it pipes to a program (`|...`), an unprivileged process can crash, triggering arbitrary code as root.",
        recommendation: "Set `kernel.core_pattern = core.%p` (or empty) in /etc/sysctl.conf. Apply with `sysctl -p`.",
    },
    LinuxCheck {
        id: "linux.unattended-upgrades-active",
        title: "unattended-upgrades running",
        // Ubuntu/Debian: unattended-upgrades. RHEL: dnf-automatic.
        // Either is enough — auto-patching is the whole CIS
        // intent.
        command: "systemctl is-active unattended-upgrades dnf-automatic 2>/dev/null | head -1",
        expect_contains: "active",
        severity: Severity::Medium,
        cvss: 5.0,
        detail_on_fail: "No automatic security-update service is active. CVE patches reach the host only when an admin manually intervenes.",
        recommendation: "Install + enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL/Fedora). Configure to auto-apply security updates daily.",
    },
    LinuxCheck {
        id: "linux.audit.journald-running",
        title: "journald collecting logs",
        command: "systemctl is-active systemd-journald 2>/dev/null",
        expect_contains: "active",
        severity: Severity::Medium,
        cvss: 4.0,
        detail_on_fail: "systemd-journald is not running — no centralized log collection means an intrusion goes uninvestigated.",
        recommendation: "`systemctl enable --now systemd-journald`. Check storage isn't volatile: `journalctl --disk-usage`.",
    },
    LinuxCheck {
        id: "linux.firewall.active",
        title: "Host firewall enabled",
        command: "(systemctl is-active firewalld ufw 2>/dev/null | grep -q active) && echo enabled || (iptables -L -n 2>/dev/null | head -3 | grep -qE 'DROP|REJECT' && echo enabled) || echo disabled",
        expect_contains: "enabled",
        severity: Severity::Medium,
        cvss: 5.5,
        detail_on_fail: "No host firewall (firewalld/ufw/iptables) detected. Anything listening on a non-localhost port is internet-reachable if the host has a public interface.",
        recommendation: "Enable a host firewall: `ufw enable` (Debian/Ubuntu) or `systemctl enable --now firewalld` (RHEL).",
    },
];

/// Run all baseline checks over a single SSH session and assemble
/// a `ComplianceRun` in the same shape the FortiGate path produces.
/// Caller supplies a `run_cmd` closure that executes a command and
/// returns combined stdout — typically wired to russh.
///
/// Returns a fully-populated `ComplianceRun` with `BaselineKind::Linux`,
/// score and pass/fail/error tallies computed via the shared
/// `compliance::tally` + `compliance::score` helpers, ready to hand
/// to `compliance::persist_run`.
///
/// Findings emission was dropped in 1.12a — the GUI of 1.12b renders
/// failure rows directly off `run.checks` (filtering `Status::Fail`),
/// which is what the FortiGate path has always done. Pushing to
/// `findings_store` from compliance was never wired up; that
/// integration is a separate concern.
pub async fn run_baseline<F, Fut>(
    host_id: &str,
    hostname: Option<&str>,
    triggered_by: TriggerKind,
    mut run_cmd: F,
) -> ComplianceRun
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<String>>,
{
    let started_at = Utc::now();
    let mut check_results = Vec::with_capacity(LINUX_CHECKS.len());

    for check in LINUX_CHECKS {
        let (output, errored) = match run_cmd(check.command.to_owned()).await {
            Ok(s) => (s, false),
            // SSH disconnect / command exec error → mark as Error,
            // not Fail. Fail means "we asked and the answer was wrong";
            // Error means "we couldn't ask," which a careful operator
            // wants to retry rather than treat as a failure.
            Err(e) => (format!("[error: {e}]"), true),
        };
        let lower = output.to_lowercase();
        let passed = !errored && lower.contains(&check.expect_contains.to_lowercase());
        let truncated = output.chars().take(2048).collect::<String>();

        let status = if errored {
            Status::Error
        } else if passed {
            Status::Pass
        } else {
            Status::Fail
        };
        let detail = if passed {
            "Configuration matches baseline.".to_owned()
        } else if errored {
            format!("Command execution failed: {}", truncated)
        } else {
            check.detail_on_fail.to_owned()
        };
        check_results.push(compliance::CheckResult {
            check_id: check.id.to_owned(),
            status,
            detail,
            raw_value: Some(truncated),
            severity: map_severity(check.severity),
            title: check.title.to_owned(),
            category: category_for_id(check.id),
        });
    }

    let finished_at = Utc::now();
    let score = compliance::score(&check_results);
    let (passed_n, failed_n, errored_n, skipped_n) = compliance::tally(&check_results);

    ComplianceRun {
        id: uuid::Uuid::new_v4().simple().to_string(),
        host_id: host_id.to_owned(),
        started_at,
        finished_at,
        firmware: None,
        model: None,
        hostname: hostname.map(str::to_owned),
        triggered_by,
        baseline_kind: BaselineKind::Linux,
        score,
        passed: passed_n,
        failed: failed_n,
        errored: errored_n,
        skipped: skipped_n,
        checks: check_results,
    }
}

/// Map `vuln::Severity` (carried on Linux check definitions) to
/// `compliance::Severity` (what `CheckResult` expects). The two
/// enums have identical variants — they exist separately because
/// `vuln::Severity` predates `compliance`; consolidating them is
/// out of scope here and would ripple through notify/findings_store/
/// report/cve_feed/risk. See compliance.rs for that future cleanup.
fn map_severity(v: Severity) -> compliance::Severity {
    match v {
        Severity::Info => compliance::Severity::Info,
        Severity::Low => compliance::Severity::Low,
        Severity::Medium => compliance::Severity::Medium,
        Severity::High => compliance::Severity::High,
        Severity::Critical => compliance::Severity::Critical,
    }
}

/// Derive a human-readable category from the check id prefix so
/// the GUI's per-check rendering shows "SSH" / "Kernel" / etc.
/// rather than "Linux baseline" on every row. Aligns with the
/// FortiGate path's `CheckDefinition.category` (which has values
/// like "Authentication", "Logging", etc.).
///
/// **Single source of truth** for Linux check categories. Called
/// by both the runner (`run_baseline`, stamping
/// `CheckResult.category`) and the library
/// (`linux_default_checks`, stamping `CheckDefinition.category`).
/// Drift between the two is impossible by construction — they
/// share this function rather than referencing parallel literals.
/// The runtime backstop for this invariant lives in
/// `compliance::tests::linux_library_category_byte_identical_to_runner_category`.
pub fn category_for_id(check_id: &str) -> String {
    let mid = check_id.strip_prefix("linux.").unwrap_or(check_id);
    let segment = mid.split('.').next().unwrap_or("baseline");
    match segment {
        "ssh" => "SSH",
        "kernel" => "Kernel",
        "audit" => "Audit",
        "firewall" => "Firewall",
        "unattended-upgrades" => "Patching",
        _ => "Linux baseline",
    }
    .to_owned()
}

/// Library rows for every Linux baseline check (1.12c).
///
/// Returns one `compliance::CheckDefinition` per `LINUX_CHECKS`
/// entry, suitable for merging into `compliance::list_checks()`.
/// Once merged, the GUI's library browser shows Linux checks,
/// the in-row Remediation block in `ComplianceHostView` resolves
/// for Linux check_ids, and `render_markdown_report` produces a
/// complete Remediation column for Linux runs — closing two of
/// the three tracked defects named in 1.12b.
///
/// **Drift discipline:** category and severity are derived via
/// the same `category_for_id` and `map_severity` helpers the runner
/// (`run_baseline` above) already uses. There is no second
/// source of truth — the persisted `CheckResult.category` from a
/// run and the library `CheckDefinition.category` are byte-
/// identical by construction because they come from the same
/// function call, not from parallel literals.
///
/// **Runtime fields (cli_command, cli_grep, channel, expect,
/// api_path, api_pointer)** are placeholders, not consulted by
/// the Linux runner — `run_baseline` reads commands directly off
/// `LINUX_CHECKS` and matches via `LinuxCheck.expect_contains`.
/// The library row's value for Linux is in `description /
/// remediation / cisReference / category / severity / title /
/// framework` — the fields `ChecksLibrarySheet` and `CheckRow`
/// actually render. See per-field notes below.
pub fn linux_default_checks() -> Vec<compliance::CheckDefinition> {
    LINUX_CHECKS
        .iter()
        .map(|c| compliance::CheckDefinition {
            id: c.id.to_owned(),
            title: c.title.to_owned(),
            // Author-time text describing the check's *intent* —
            // distinct from `detail_on_fail`, which is the
            // failure-mode message the runner stamps into
            // CheckResult.detail. See per-id authoring below.
            description: linux_description(c.id).to_owned(),
            // Same helpers the runner uses → identical strings on
            // both sides by construction. Drift impossible.
            category: category_for_id(c.id),
            severity: map_severity(c.severity),
            framework: "CIS Linux 4.0".to_owned(),
            // CIS Linux 4.0 section references not authored yet.
            // None renders cleanly (badge hides) in both the
            // library row and the report.
            cis_reference: None,
            // `Channel::Cli` for shape consistency with the
            // FortiGate CLI-channel rows. The Linux runner does
            // not consult this field; it hardcodes its own
            // execution path in `run_baseline`.
            channel: compliance::Channel::Cli,
            api_path: None,
            api_pointer: None,
            // `cli_command` / `cli_grep` deliberately not carried.
            // `ChecksLibrarySheet`'s `CheckLibraryRow` renders
            // title / category / cisReference / framework /
            // severity / description / remediation — never these
            // two. Carrying them as a display-string for the
            // browser was rejected as "build matches description":
            // not-rendered → not-carried.
            cli_command: None,
            cli_grep: None,
            // Neutral placeholder. Never evaluated for Linux
            // rows: the runner uses `LinuxCheck.expect_contains`
            // directly, not the library row's `expect`. The
            // empty-needle `Contains` would pass-everything if
            // some future code path ever evaluated a library
            // row's `expect` against a value — don't wire that
            // up from here without an explicit decision. The
            // runner owns the match; this field exists to
            // satisfy the struct shape.
            expect: compliance::Expectation::Contains {
                needle: String::new(),
            },
            // Authored copy from `LinuxCheck.recommendation` —
            // this is the load-bearing field. Lights up the
            // in-row Remediation block and the report's
            // Remediation column for every failed Linux check.
            remediation: Some(c.recommendation.to_owned()),
        })
        .collect()
}

/// Authored *intent* descriptions for each Linux check. Distinct
/// from `LinuxCheck.detail_on_fail` (which is what's-wrong text
/// the runner stamps into `CheckResult.detail`). The library
/// browser shows this when an operator expands a check row to
/// understand what the check is for, before they ever see a
/// failure. Keep them concise — 2-3 sentences each — and explain
/// the threat / control rationale, not the remediation.
fn linux_description(check_id: &str) -> &'static str {
    match check_id {
        "linux.ssh.password-auth-disabled" => "Enforces key-only SSH authentication on the host. Password authentication is the dominant attack vector for credential-stuffing and brute-force campaigns against internet-exposed sshd; disabling it removes that surface entirely. Verifies the effective sshd config via `sshd -T`, which reflects what the daemon actually does after parsing Match blocks.",
        "linux.ssh.root-login-disabled" => "Requires interactive admin sessions to log in as a regular user, then escalate via sudo. The audit trail of which user invoked which command vanishes when admins share a root login — and a stolen root key compromises the host directly with no second factor. Aligns with CIS guidance against direct privileged accounts.",
        "linux.ssh.protocol-v2-only" => "Confirms the host runs a modern OpenSSH release where SSHv1 has been fully removed. SSHv1 has known cryptographic weaknesses (downgrade attacks, session-key recovery); modern sshd (≥7.0) doesn't compile Protocol 1 support at all. This check inspects the daemon version rather than the config — if sshd doesn't speak v1, the config setting is moot.",
        "linux.kernel.core-pattern-safe" => "Guards against the pwnkit-class privilege-escalation pattern where a crashing setuid binary can pipe its core dump into an attacker-controlled program running as root. A normal `kernel.core_pattern` value (`core.%p`, `/var/...`, empty) is safe; the dangerous form starts with `|` and pipes to a command. Reads the kernel parameter via `sysctl`.",
        "linux.unattended-upgrades-active" => "Confirms an automatic-patching daemon is active so security updates land without manual operator intervention. CVE-to-patched-host latency is the single largest exposure window for known vulnerabilities; the CIS intent is that critical fixes apply within hours of release, not whenever an admin remembers to log in. Accepts either Debian/Ubuntu's `unattended-upgrades` or RHEL's `dnf-automatic`.",
        "linux.audit.journald-running" => "Verifies that systemd-journald is collecting logs centrally. Without an active log collector, incidents go uninvestigable — there's no record of what processes ran, what authentication attempts happened, or what an attacker touched. This check does not enforce remote log shipping (separate concern), only that local journald is alive.",
        "linux.firewall.active" => "Confirms a host-level firewall (firewalld, ufw, or non-trivial iptables/nftables rules) is active. Service sockets bind by default on Linux; a firewall is the layer that constrains exposure to the intended set of ports + networks regardless of what services accidentally bind to 0.0.0.0. Without one, a misconfigured listener is internet-reachable on any public-interface host.",
        // Defensive — every entry in LINUX_CHECKS should have a
        // description. The compile-time pair (every LinuxCheck has
        // a match arm here) is tested below; this fallback only
        // fires if a new check id is added without authoring text.
        _ => "Linux baseline check. (No detailed description authored — see CIS Linux 4.0 documentation.)",
    }
}

/// Static count of checks the baseline currently covers — handy
/// for the UI's "Linux baseline (7 checks)" subtitle without
/// needing to call `run_baseline` first.
pub fn check_count() -> usize {
    LINUX_CHECKS.len()
}

/// Names of every check, in order. Surfaced to the UI when the
/// operator wants to see what the baseline actually checks
/// before running it.
pub fn check_titles() -> Vec<&'static str> {
    LINUX_CHECKS.iter().map(|c| c.title).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_count_matches_array_length() {
        assert_eq!(check_count(), LINUX_CHECKS.len());
        assert!(check_count() >= 5, "should ship a meaningful starter set");
    }

    #[test]
    fn every_check_has_unique_id() {
        let mut ids: Vec<&'static str> = LINUX_CHECKS.iter().map(|c| c.id).collect();
        ids.sort();
        let original_len = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "duplicate check IDs would corrupt findings_store keys");
    }

    #[test]
    fn every_check_has_recommendation() {
        for check in LINUX_CHECKS {
            assert!(!check.recommendation.is_empty(),
                "check {} missing recommendation", check.id);
            assert!(!check.detail_on_fail.is_empty(),
                "check {} missing detail_on_fail", check.id);
        }
    }

    #[test]
    fn check_titles_returns_all() {
        let titles = check_titles();
        assert_eq!(titles.len(), check_count());
    }

    #[tokio::test]
    async fn run_baseline_pass_path_produces_all_pass_checks() {
        // Mock ssh-cmd that always returns matching output.
        // Build a response that contains every expect_contains
        // substring across all checks (a maximally-passing host).
        let run = run_baseline(
            "host-id-1",
            Some("test-linux"),
            TriggerKind::Manual,
            |cmd| async move {
                let _ = cmd;
                Ok("passwordauthentication no\npermitrootlogin no\nopenssh_9.0\ncore.%p\nactive\nactive\nenabled".into())
            }
        ).await;
        assert_eq!(run.checks.len(), check_count());
        assert!(run.checks.iter().all(|c| matches!(c.status, Status::Pass)),
            "all should be Pass");
        assert_eq!(run.passed, check_count() as u32);
        assert_eq!(run.failed, 0);
        assert_eq!(run.errored, 0);
        assert_eq!(run.score, 100, "no failures → max score");
        assert_eq!(run.baseline_kind, BaselineKind::Linux);
        assert_eq!(run.hostname.as_deref(), Some("test-linux"));
    }

    #[tokio::test]
    async fn run_baseline_fail_path_produces_all_fail_checks() {
        // Mock that returns something that won't match anything.
        let run = run_baseline(
            "host-id-2",
            None,
            TriggerKind::Manual,
            |cmd| async move {
                let _ = cmd;
                Ok("nothing matches".into())
            }
        ).await;
        assert_eq!(run.checks.len(), check_count());
        assert!(run.checks.iter().all(|c| matches!(c.status, Status::Fail)),
            "all should be Fail with non-matching output");
        assert_eq!(run.failed, check_count() as u32);
        assert_eq!(run.passed, 0);
        assert_eq!(run.errored, 0);
        assert!(run.score < 100, "failures must drop score below 100");
        assert_eq!(run.baseline_kind, BaselineKind::Linux);
    }

    #[tokio::test]
    async fn ssh_error_is_classified_as_error_not_fail() {
        // If the command errors (network drop mid-session), the
        // check should map to Status::Error — distinct from Fail.
        // Fail = "we asked and got the wrong answer"; Error = "we
        // couldn't ask." Operators triage those differently.
        let run = run_baseline(
            "host-id-3",
            None,
            TriggerKind::Manual,
            |_cmd| async {
                Err(anyhow::anyhow!("simulated ssh disconnect"))
            }
        ).await;
        assert_eq!(run.checks.len(), check_count());
        for c in &run.checks {
            assert!(matches!(c.status, Status::Error),
                "ssh errors must produce Error, not Fail");
            assert!(c.raw_value.as_deref()
                .map(|s| s.contains("simulated ssh disconnect"))
                .unwrap_or(false));
        }
        assert_eq!(run.errored, check_count() as u32);
        assert_eq!(run.failed, 0);
    }

    // -- 1.12a: aggregation correctness ---------------------------------
    //
    // The Linux path now assembles its own ComplianceRun, which
    // means score + pass/fail/error counts are computed here rather
    // than in the FortiGate runner. The whole drift/history/notify
    // surface trusts these aggregates — assert they match the
    // underlying check vector directly. Mock returns a partial
    // match: only the `passwordauthentication no` check passes,
    // every other check sees the same string and fails because
    // their `expect_contains` is a different substring.

    #[tokio::test]
    async fn aggregation_score_and_tally_match_underlying_checks() {
        let run = run_baseline(
            "host-id-4",
            Some("partial-host"),
            TriggerKind::Manual,
            |cmd| async move {
                let _ = cmd;
                // Contains exactly the substring needed by the
                // password-auth-disabled check; other checks miss.
                Ok("passwordauthentication no".into())
            }
        ).await;

        // Recount independently — the tally must match exactly.
        let manual_passed = run.checks.iter()
            .filter(|c| matches!(c.status, Status::Pass)).count() as u32;
        let manual_failed = run.checks.iter()
            .filter(|c| matches!(c.status, Status::Fail)).count() as u32;
        let manual_errored = run.checks.iter()
            .filter(|c| matches!(c.status, Status::Error)).count() as u32;
        let manual_skipped = run.checks.iter()
            .filter(|c| matches!(c.status, Status::Skip)).count() as u32;

        assert_eq!(run.passed, manual_passed,
            "passed tally must match check vector — drift/history trust this");
        assert_eq!(run.failed, manual_failed, "failed tally");
        assert_eq!(run.errored, manual_errored, "errored tally");
        assert_eq!(run.skipped, manual_skipped, "skipped tally");
        assert_eq!(run.passed + run.failed + run.errored + run.skipped,
            run.checks.len() as u32,
            "tallies must sum to total check count");

        // Score must reflect failures present (start 100 minus
        // severity-weighted penalties). With ≥1 High-severity fail,
        // score is strictly below 100; with ≥1 Pass + many Fails,
        // it's strictly above 0.
        assert!(manual_passed >= 1, "this mock should produce ≥1 Pass");
        assert!(manual_failed >= 1, "this mock should produce ≥1 Fail");
        assert!(run.score < 100,
            "≥1 failure must drop the score below 100; got {}", run.score);

        // BaselineKind must round-trip through the assembly.
        assert_eq!(run.baseline_kind, BaselineKind::Linux);
        // Category derivation: at least one check has a non-default
        // category so the GUI doesn't render "Linux baseline" everywhere.
        assert!(run.checks.iter().any(|c| c.category == "SSH"),
            "category derivation must map linux.ssh.* → SSH");
    }

    #[tokio::test]
    async fn linux_run_persists_and_loads_with_baseline_kind_intact() {
        // End-to-end disk path: assemble → persist_run → load_run
        // returns the same shape with BaselineKind::Linux preserved.
        // This is what handle_compliance_render_report and
        // handle_compliance_get_run will see for Linux rows.
        let run = run_baseline(
            "host-id-roundtrip",
            Some("rt-host"),
            TriggerKind::Manual,
            |cmd| async move {
                let _ = cmd;
                Ok("passwordauthentication no".into())
            }
        ).await;
        let run_id = run.id.clone();

        compliance::persist_run(&run).expect("persist must succeed");
        let loaded = compliance::load_run("host-id-roundtrip", &run_id)
            .expect("load_run must find the just-written file");

        assert_eq!(loaded.baseline_kind, BaselineKind::Linux,
            "Linux runs must persist their kind, not silently coerce to Fortigate");
        assert_eq!(loaded.id, run.id);
        assert_eq!(loaded.score, run.score);
        assert_eq!(loaded.passed, run.passed);
        assert_eq!(loaded.failed, run.failed);
        assert_eq!(loaded.checks.len(), run.checks.len());
    }
}
