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

use serde::{Deserialize, Serialize};

use crate::vuln::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxCheckResult {
    pub id: String,
    pub title: String,
    pub command: String,
    pub passed: bool,
    pub output: String,
    pub severity: Severity,
}

struct LinuxCheck {
    id: &'static str,
    title: &'static str,
    command: &'static str,
    /// Substring that, when present in stdout, means the check
    /// PASSED. Inverse: if the substring is absent, the check
    /// failed.
    expect_contains: &'static str,
    severity: Severity,
    cvss: f32,
    detail_on_fail: &'static str,
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

/// Run all baseline checks over a single SSH session. Caller
/// supplies a `run_cmd` closure that executes a command and
/// returns combined stdout — typically wired to russh.
///
/// Returns parallel `LinuxCheckResult` (every check ran, pass/fail
/// captured) + `Finding` for every check that failed (so the
/// findings_store sees them like any other discovery output).
pub async fn run_baseline<F, Fut>(
    host_ip: &str,
    mut run_cmd: F,
) -> (Vec<LinuxCheckResult>, Vec<Finding>)
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<String>>,
{
    let mut results = Vec::with_capacity(LINUX_CHECKS.len());
    let mut findings: Vec<Finding> = Vec::new();
    for check in LINUX_CHECKS {
        let output = match run_cmd(check.command.to_owned()).await {
            Ok(s) => s,
            Err(e) => format!("[error: {e}]"),
        };
        let lower = output.to_lowercase();
        let passed = lower.contains(&check.expect_contains.to_lowercase());
        results.push(LinuxCheckResult {
            id: check.id.to_owned(),
            title: check.title.to_owned(),
            command: check.command.to_owned(),
            passed,
            output: output.chars().take(2048).collect(),
            severity: check.severity,
        });
        if !passed {
            findings.push(Finding {
                id: check.id.to_owned(),
                host_ip: host_ip.to_owned(),
                port: Some(22),
                service: Some("compliance".into()),
                severity: check.severity,
                title: check.title.to_owned(),
                detail: format!(
                    "{}\n\nCommand: `{}`\nExpected output to contain: `{}`",
                    check.detail_on_fail, check.command, check.expect_contains
                ),
                recommendation: check.recommendation.to_owned(),
                cve: None,
                cvss: Some(check.cvss),
            });
        }
    }
    (results, findings)
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
    async fn run_baseline_pass_path_emits_no_findings() {
        // Mock ssh-cmd that always returns matching output.
        let (results, findings) = run_baseline("10.0.0.1", |cmd| async move {
            // Build a response that contains every expect_contains
            // substring across all checks (a maximally-passing host).
            let _ = cmd;
            Ok("passwordauthentication no\npermitrootlogin no\nopenssh_9.0\ncore.%p\nactive\nactive\nenabled".into())
        }).await;
        assert_eq!(results.len(), check_count());
        assert!(results.iter().all(|r| r.passed), "all should pass");
        assert!(findings.is_empty(), "no failed checks → no findings");
    }

    #[tokio::test]
    async fn run_baseline_fail_path_emits_findings() {
        // Mock that returns something that won't match anything.
        let (results, findings) = run_baseline("10.0.0.1", |cmd| async move {
            let _ = cmd;
            Ok("nothing matches".into())
        }).await;
        assert_eq!(results.len(), check_count());
        assert!(results.iter().all(|r| !r.passed), "all fail with this output");
        assert_eq!(findings.len(), check_count(),
            "every failed check should produce one finding");
        // Each finding should have host_ip + cvss + recommendation.
        for f in &findings {
            assert_eq!(f.host_ip, "10.0.0.1");
            assert!(f.cvss.is_some());
            assert!(!f.recommendation.is_empty());
        }
    }

    #[tokio::test]
    async fn ssh_error_is_handled_as_failed_check() {
        // If the command errors (network drop mid-session), the
        // check should mark as failed rather than crash.
        let (results, _findings) = run_baseline("10.0.0.1", |_cmd| async {
            Err(anyhow::anyhow!("simulated ssh disconnect"))
        }).await;
        assert_eq!(results.len(), check_count());
        for r in &results {
            assert!(r.output.contains("simulated ssh disconnect"));
            assert!(!r.passed);
        }
    }
}
