//! Linux compliance baseline run over SSH.
//!
//! The existing `compliance.rs` module targets `FortiGate` via the
//! REST API. Linux servers (which an MSP fleet has *plenty* of)
//! got nothing — operators couldn't answer "is this server's
//! sshd configured per CIS?" from the GUI.
//!
//! # Approach
//!
//! Each check is a small `LinuxCheck` declaring:
//!   - A POSIX shell script to run (`grep`, `sysctl`, `systemctl`, etc.)
//!   - An [`Expect`] describing what output means "pass"
//!   - Severity + recommendation if it fails
//!
//! We run the scripts over an existing SSH connection (the same
//! `connection_pool` the SSH section uses). No agent install
//! required — vanilla coreutils is enough for the starter set.
//!
//! # Two invariants this module got wrong once, and now tests
//!
//! **The login shell does not parse our scripts.** Every script goes over the
//! wire inside [`posix_wrap`]'s `sh -c '…'`. The firewall check used to rely on
//! the account's shell being bash; against a `fish` account its `(…) && … || …`
//! was a syntax error, and because fish echoes the offending line back — and
//! that line contains the literal `echo enabled` — a substring match found its
//! needle in the *error message* and reported PASS.
//!
//! **A script's exit status is its verdict about whether it knows.** Exit 0
//! means "the answer is in my output"; non-zero means "I could not determine
//! this". Scripts are written to honour that (`systemctl is-active` returns 3
//! for a stopped unit, so those scripts normalise it away and report the state
//! in their output instead). The runner maps non-zero to [`Status::Error`],
//! because "we could not ask" and "we asked and the answer was wrong" are
//! different things to whoever triages the row. Both callers used to discard
//! the exit status, which is how an unprivileged `sshd -T` became a report
//! that root login was enabled.
//!
//! # Coverage (v1)
//!
//! Hand-picked from the CIS Distribution Independent Linux Benchmark — the
//! checks an attacker exploits most reliably. Note that "hand-picked from"
//! is doing real work in that sentence: several are the CIS *intent* rather
//! than a CIS control, and only two map to a section. See `cis_reference`.
//!
//! Attacker-reliability order:
//!   - SSH password auth disabled (vs key-only)
//!   - SSH root login disabled
//!   - SSH protocol v2 only (rule out v1 fallback)
//!   - Kernel `core_pattern` is sane (no pipe to an unrecognised program)
//!   - Automatic security updates applying
//!   - journald running (audit trail exists)
//!   - Host firewall active
//!
//! That is the whole set — seven, matching `LINUX_CHECKS`. This list previously
//! also named world-writable files, listening services and rsyslog, none of
//! which were ever implemented; a coverage list that overstates coverage is the
//! same kind of false claim as a wrong benchmark reference.
//!
//! Future: kernel hardening sysctls, AIDE/auditd presence, world-writable file
//! sweep. Each new check is ~10 lines.

use chrono::Utc;

use crate::compliance::{self, BaselineKind, ComplianceRun, Status, TriggerKind};
use crate::severity::Severity;

/// How much of a command's output is kept as the row's `raw_value`.
const RAW_LIMIT: usize = 2048;

/// What a check's script produced.
///
/// The exit status is the load-bearing addition. Both callers already had it
/// from their SSH transport and threw it away, which left the runner unable to
/// tell "the setting is wrong" from "the command failed" — so an unprivileged
/// `sshd -T`, which exits 1 and prints nothing to stdout, was scored as a
/// security finding. Carrying it costs one field.
pub struct CmdOutput {
    /// stdout and stderr combined — checks read stdout, diagnostics land on
    /// stderr and are worth keeping in `raw_value` either way.
    pub output: String,
    /// Exit status of the script, or `None` if the transport cannot report one.
    /// `None` is treated as "no reason to doubt it", so a transport that
    /// genuinely cannot observe status degrades to the old behaviour instead of
    /// erroring on every check.
    pub code: Option<i32>,
}

impl CmdOutput {
    /// Output from a command that exited successfully.
    #[must_use]
    pub fn ok(output: impl Into<String>) -> Self {
        Self {
            output: output.into(),
            code: Some(0),
        }
    }

    /// Output plus an observed exit status.
    #[must_use]
    pub fn new(output: impl Into<String>, code: i32) -> Self {
        Self {
            output: output.into(),
            code: Some(code),
        }
    }
}

/// What a check's output has to look like to pass.
///
/// This replaced a bare `expect_contains: &str`, which was substring-only and
/// silently defeated two checks in opposite directions:
///
/// - `"active"` is a substring of `"inactive"`, so `systemctl is-active`
///   reporting a *stopped* auto-update service passed the patching check.
/// - `"core"` is a substring of `"systemd-coredump"`, so a `kernel.core_pattern`
///   piped to a program — the precise attack the check exists to detect —
///   passed it. That is the default on every systemd distribution, so the check
///   passed essentially everywhere while verifying nothing.
///
/// Both were PASSes, which is the direction that never gets investigated.
///
/// Two variants, not a richer set: every check the baseline has is served by an
/// exact line match, and the one genuine substring case is the OpenSSH version
/// banner. Anything a check cannot express exactly belongs in the check's own
/// script, where the reasoning ends up visible in `raw_value` — which is how the
/// core-dump check now allowlists distribution handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Some line of the output, trimmed, equals this. The right mode for a
    /// setting's value: `permitrootlogin no` must not be satisfied by
    /// `permitrootlogin no-such-value`.
    LineIs(&'static str),
    /// The output contains this substring anywhere. Correct only where the
    /// needle cannot hide inside a longer word that means the opposite — see
    /// `no_check_still_uses_bare_substring_matching_for_a_state_word`.
    Contains(&'static str),
}

impl Expect {
    /// Whether `output` satisfies this expectation.
    ///
    /// Matching is case-insensitive, done by lowercasing here rather than in
    /// each script, so a config file's `PermitRootLogin` and `sshd -T`'s
    /// `permitrootlogin` compare equal without shell gymnastics. Needles are
    /// therefore required to be lowercase, which `needles_are_lowercase` tests.
    fn satisfied_by(self, output: &str) -> bool {
        let lower = output.to_lowercase();
        match self {
            Self::LineIs(want) => lower.lines().any(|l| l.trim() == want),
            Self::Contains(want) => lower.contains(want),
        }
    }

    /// The needle, for tests that need to inspect it without matching.
    #[cfg(test)]
    fn needle(self) -> &'static str {
        match self {
            Self::LineIs(n) | Self::Contains(n) => n,
        }
    }
}

/// What a check's script actually told us.
///
/// The distinction this type exists to force: only `Answered` may become a Pass
/// or a Fail. Everything else is [`Status::Error`], because a compliance row
/// that says "fail" is a claim about the host, and a permission error is not
/// evidence about the host.
enum Reading {
    /// The script ran, claimed success, and produced output.
    Answered(String),
    /// No answer was obtained, with the reason to show the operator.
    Inconclusive {
        /// Operator-facing explanation, stamped into `CheckResult.detail`.
        reason: String,
        /// Whatever came back, kept as `raw_value` so the underlying message
        /// (`sshd: no hostkeys available -- exiting`) stays visible.
        raw: String,
    },
}

/// Wrap a check's script so the account's *login* shell never parses it.
///
/// SSH hands a command to the login shell, and that shell is not ours to
/// choose — the host that exposed this was a `fish` account. The login shell
/// now only ever sees one simple command with one single-quoted argument, which
/// every shell agrees how to parse, and the script itself is interpreted by
/// `sh`.
///
/// Embedded single quotes are escaped the portable way (close, escaped quote,
/// reopen) rather than with a backslash, which single quotes do not honour.
fn posix_wrap(script: &str) -> String {
    format!("/bin/sh -c '{}'", script.replace('\'', r"'\''"))
}

/// Read one effective sshd setting, most authoritative source first, and print
/// `source=<how>` then `<key> <value>`.
///
/// `$k` is the setting name; `$d` is the value OpenSSH compiles in when no
/// config file mentions it. Exits 3 when nothing could answer, which the runner
/// turns into [`Status::Error`].
///
/// The fallback chain exists because `sshd -T` loads host keys and therefore
/// needs root, while a fleet scan runs as an ordinary user. Without it these
/// two checks — the two most valuable in the baseline — are unanswerable on
/// every normal scan. `sudo -n` never prompts, so an account without sudo just
/// falls through. The config-file branch is what the CIS controls are written
/// against; it does not resolve `Match` blocks, which is why `source=` is
/// reported alongside the value instead of being hidden.
macro_rules! sshd_value {
    ($key:literal, $default:literal) => {
        concat!(
            "k=", $key, "\n",
            "d=", $default, "\n",
            r#"v=$(sshd -T 2>/dev/null | grep -i "^$k "); s=sshd-T"#, "\n",
            r#"if [ -z "$v" ]; then v=$(sudo -n sshd -T 2>/dev/null | grep -i "^$k "); s=sudo-sshd-T; fi"#, "\n",
            r#"if [ -z "$v" ]; then v=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | sed "s/#.*//" | grep -iE "^[[:space:]]*$k[[:space:]]" | tail -1); s=config-file; fi"#, "\n",
            r#"if [ -z "$v" ] && [ -r /etc/ssh/sshd_config ]; then v="$k $d"; s=openssh-default; fi"#, "\n",
            r#"[ -z "$v" ] && exit 3"#, "\n",
            r#"printf "source=%s\n" "$s""#, "\n",
            r#"set -- $v"#, "\n",
            r#"printf "%s %s\n" "$1" "$2""#, "\n",
        )
    };
}

struct LinuxCheck {
    id: &'static str,
    title: &'static str,
    /// POSIX shell script. Runs under `sh` via [`posix_wrap`], so bourne
    /// syntax is safe regardless of the account's login shell. Must exit 0
    /// only when its output actually answers the question — see the module
    /// docs.
    command: &'static str,
    /// What the output has to look like to pass.
    expect: Expect,
    severity: Severity,
    /// CVSS score, currently unused by both the runner and the
    /// library (the library uses `severity` as the operator-facing
    /// magnitude; CVSS is preserved here for a future risk-score
    /// integration). Marked `allow(dead_code)` until consumed.
    #[allow(dead_code)]
    cvss: f32,
    detail_on_fail: &'static str,
    /// Optional refinement of `detail_on_fail`, given the observed output in
    /// lowercase. Exists because a substring match can be right about pass/fail
    /// and still leave the message wrong: `PermitRootLogin prohibit-password`
    /// fails the same control as `yes` and means something materially different
    /// to whoever reads the row. Return `None` to keep `detail_on_fail`.
    ///
    /// A function pointer rather than a closure so `LINUX_CHECKS` stays a
    /// `const`.
    refine_detail: Option<fn(&str) -> Option<&'static str>>,
    /// Authored remediation text. Read by `linux_default_checks()`
    /// into `CheckDefinition.remediation` since 1.12c — drives the
    /// in-row Remediation block and the report's Remediation column.
    recommendation: &'static str,
}

const LINUX_CHECKS: &[LinuxCheck] = &[
    LinuxCheck {
        id: "linux.ssh.password-auth-disabled",
        title: "sshd PasswordAuthentication disabled",
        // `yes` is OpenSSH's compiled-in default, so a config file that says
        // nothing fails this control — the old command's `||` fallback to
        // `sshd -T -f` was dead weight, since that form loads host keys too and
        // fails for exactly the same reason the first one does.
        command: sshd_value!("passwordauthentication", "yes"),
        expect: Expect::LineIs("passwordauthentication no"),
        severity: Severity::High,
        cvss: 7.0,
        detail_on_fail: "SSH password auth is enabled — exposes the host to credential-stuffing and brute-force attacks. Key-based auth is the modern best practice.",
        refine_detail: None,
        recommendation: "Set `PasswordAuthentication no` in /etc/ssh/sshd_config. Verify all admins have keys deployed before applying. Reload sshd: `systemctl reload sshd`.",
    },
    LinuxCheck {
        id: "linux.ssh.root-login-disabled",
        title: "sshd PermitRootLogin disabled",
        command: sshd_value!("permitrootlogin", "prohibit-password"),
        expect: Expect::LineIs("permitrootlogin no"),
        severity: Severity::High,
        cvss: 7.0,
        // Reached only if sshd reports something this does not recognise.
        // The two values that actually occur are handled below, precisely.
        detail_on_fail: "Root SSH login is not disabled. CIS 5.2.10 requires `PermitRootLogin no`; check the observed value for what sshd is currently allowing.",
        // `prohibit-password` and `yes` both fail 5.2.10, and calling both
        // "direct root login is allowed" cost an operator the difference
        // between an open door and untidy housekeeping. Observed on a real
        // host: the row said root login was allowed when only key-based root
        // login was, which reads as far more urgent than it is.
        //
        // Severity stays High for both. It drives the score penalty, and CIS
        // grades the control not the value — but the text no longer implies
        // they are the same problem.
        refine_detail: Some(|observed| {
            if observed.contains("prohibit-password") {
                Some(
                    "Root can log in over SSH with a key, but not with a password, \
                     so this is housekeeping rather than an open door. It still \
                     fails CIS 5.2.10, which requires `no`: a shared root key \
                     leaves no record of which admin used it, and sudo does.",
                )
            } else if observed.contains("permitrootlogin yes") {
                Some(
                    "Root can log in over SSH with a password. This is the urgent \
                     form of the finding: directly brute-forceable from anywhere \
                     the port is reachable, and it leaves no audit trail of who \
                     acted.",
                )
            } else {
                // `forced-commands-only` and anything future. Better to fall
                // back to the general message than to guess at what a value we
                // have not seen implies.
                None
            }
        }),
        recommendation: "Set `PermitRootLogin no` in /etc/ssh/sshd_config, make sure a non-root account with sudo works first, then `systemctl reload sshd`.",
    },
    LinuxCheck {
        id: "linux.ssh.protocol-v2-only",
        title: "sshd Protocol 2 only",
        // Modern OpenSSH does not compile Protocol 1 at all, so the version is
        // the evidence. `ssh -V` writes to stderr and is the form present on
        // every release (`sshd -V` is not), which is why the version read is the
        // installed OpenSSH build rather than a running-daemon banner.
        command: "v=$(ssh -V 2>&1 | head -1)\n[ -z \"$v\" ] && exit 3\nprintf \"%s\\n\" \"$v\"\n",
        expect: Expect::Contains("openssh"),
        severity: Severity::Medium,
        cvss: 4.0,
        detail_on_fail: "Could not detect OpenSSH version. SSHv1 is broken and shouldn't be on PATH.",
        refine_detail: None,
        recommendation: "Install OpenSSH ≥7.0 (SSHv1 was removed in 7.0). Verify with `ssh -V`.",
    },
    LinuxCheck {
        id: "linux.kernel.core-pattern-safe",
        title: "kernel.core_pattern not piped to attacker",
        // The verdict is computed where the value is, so `raw_value` shows both
        // the pattern and the reasoning. `expect_contains: "core"` used to stand
        // here, and `|/usr/lib/systemd/systemd-coredump` contains `core` —
        // meaning the check passed on precisely the piped form it exists to
        // catch, on every systemd host, which is nearly all of them.
        //
        // The threat is a pipe to an *attacker-controlled* program, not a pipe
        // as such: systemd-coredump and apport are root-owned distribution
        // defaults. Allowlisting them by absolute path keeps the check from
        // firing High on a stock install (which is how a check gets ignored)
        // while still failing anything else piped.
        command: "v=$(sysctl -n kernel.core_pattern 2>/dev/null)\n\
                  [ -z \"$v\" ] && v=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)\n\
                  [ -z \"$v\" ] && exit 3\n\
                  printf \"value=%s\\n\" \"$v\"\n\
                  case \"$v\" in\n\
                  \x20 \"|\"/usr/lib/systemd/systemd-coredump*|\"|\"/lib/systemd/systemd-coredump*|\"|\"/usr/share/apport/apport*)\n\
                  \x20   printf \"handler=distro-default\\ncore-pattern=safe\\n\" ;;\n\
                  \x20 \"|\"*)\n\
                  \x20   printf \"handler=unrecognised-pipe\\ncore-pattern=piped\\n\" ;;\n\
                  \x20 *)\n\
                  \x20   printf \"handler=file\\ncore-pattern=safe\\n\" ;;\n\
                  esac\n",
        expect: Expect::LineIs("core-pattern=safe"),
        severity: Severity::High,
        cvss: 7.5,
        detail_on_fail: "kernel.core_pattern pipes core dumps to a program that is not a known distribution handler. An unprivileged process can crash on demand, so whatever is on the other side of that pipe runs as root (pwnkit-class escalation).",
        refine_detail: None,
        recommendation: "Set `kernel.core_pattern = core.%p` (or empty) in /etc/sysctl.conf. Apply with `sysctl -p`.",
    },
    LinuxCheck {
        id: "linux.unattended-upgrades-active",
        title: "unattended-upgrades running",
        // Ubuntu/Debian: unattended-upgrades. RHEL: dnf-automatic. Either is
        // enough — auto-patching is the whole CIS intent.
        //
        // The comparison is `= active` in the script and `LineIs` in Rust, both
        // exact, because `expect_contains: "active"` matched `inactive` and so
        // reported PASS on hosts with no automatic patching at all. `systemctl
        // is-active` exits 3 for a stopped unit, so the loop normalises the
        // status away and states the finding in its output instead; a missing
        // `systemctl` is the one case we genuinely cannot answer.
        command: "for u in unattended-upgrades.service dnf-automatic.timer apt-daily-upgrade.timer; do\n\
                  \x20 if [ \"$(systemctl is-active \"$u\" 2>/dev/null)\" = active ]; then\n\
                  \x20   printf \"unit=%s\\nauto-updates=active\\n\" \"$u\"; exit 0\n\
                  \x20 fi\n\
                  done\n\
                  command -v systemctl >/dev/null 2>&1 || exit 3\n\
                  printf \"auto-updates=inactive\\n\"\n",
        expect: Expect::LineIs("auto-updates=active"),
        severity: Severity::Medium,
        cvss: 5.0,
        detail_on_fail: "No automatic security-update service is active. CVE patches reach the host only when an admin manually intervenes.",
        refine_detail: None,
        recommendation: "Install + enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL/Fedora). Configure to auto-apply security updates daily.",
    },
    LinuxCheck {
        id: "linux.audit.journald-running",
        title: "journald collecting logs",
        // Same `inactive`-contains-`active` trap as the patching check: the
        // prefix makes the two states impossible to confuse under any matcher.
        command: "command -v systemctl >/dev/null 2>&1 || exit 3\n\
                  printf \"journald=%s\\n\" \"$(systemctl is-active systemd-journald 2>/dev/null)\"\n",
        expect: Expect::LineIs("journald=active"),
        severity: Severity::Medium,
        cvss: 4.0,
        detail_on_fail: "systemd-journald is not running — no centralized log collection means an intrusion goes uninvestigated.",
        refine_detail: None,
        recommendation: "`systemctl enable --now systemd-journald`. Check storage isn't volatile: `journalctl --disk-usage`.",
    },
    LinuxCheck {
        id: "linux.firewall.active",
        title: "Host firewall enabled",
        // This is the script that made the shell assumption load-bearing: the
        // old one-liner was bash, and under a `fish` account it was a syntax
        // error whose message echoed the command back — including the literal
        // `echo enabled` the old `expect_contains: "enabled"` was looking for.
        // A PASS produced entirely by a parse failure.
        //
        // `iptables -L` normally needs root, so an unreadable ruleset with no
        // active firewall unit exits 3: "we could not tell" rather than a
        // confident "no firewall", which would be a fabricated finding on any
        // host whose firewall we simply lack the privilege to see.
        command: "for u in firewalld ufw nftables; do\n\
                  \x20 if [ \"$(systemctl is-active \"$u\" 2>/dev/null)\" = active ]; then\n\
                  \x20   printf \"via=%s\\nfirewall=active\\n\" \"$u\"; exit 0\n\
                  \x20 fi\n\
                  done\n\
                  ipt=$(iptables -L INPUT -n 2>/dev/null)\n\
                  [ -z \"$ipt\" ] && ipt=$(sudo -n iptables -L INPUT -n 2>/dev/null)\n\
                  if [ -z \"$ipt\" ]; then\n\
                  \x20 printf \"firewall=unknown\\nreason=no-active-firewall-unit-and-iptables-unreadable\\n\"; exit 3\n\
                  fi\n\
                  if printf \"%s\\n\" \"$ipt\" | head -1 | grep -qE \"policy (DROP|REJECT)\"; then\n\
                  \x20 printf \"via=iptables-default-deny\\nfirewall=active\\n\"; exit 0\n\
                  fi\n\
                  if printf \"%s\\n\" \"$ipt\" | grep -qE \"^(DROP|REJECT)\"; then\n\
                  \x20 printf \"via=iptables-rules\\nfirewall=active\\n\"; exit 0\n\
                  fi\n\
                  printf \"via=iptables-no-deny-rules\\nfirewall=inactive\\n\"\n",
        expect: Expect::LineIs("firewall=active"),
        severity: Severity::Medium,
        cvss: 5.5,
        detail_on_fail: "No host firewall (firewalld/ufw/nftables/iptables) detected. Anything listening on a non-localhost port is internet-reachable if the host has a public interface.",
        refine_detail: None,
        recommendation: "Enable a host firewall: `ufw enable` (Debian/Ubuntu) or `systemctl enable --now firewalld` (RHEL).",
    },
];

/// Run all baseline checks over a single SSH session and assemble
/// a `ComplianceRun` in the same shape the `FortiGate` path produces.
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
/// which is what the `FortiGate` path has always done. Pushing to
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
    Fut: std::future::Future<Output = anyhow::Result<CmdOutput>>,
{
    let started_at = Utc::now();
    let mut check_results = Vec::with_capacity(LINUX_CHECKS.len());

    for check in LINUX_CHECKS {
        // Three outcomes, not two. Fail means "we asked and the answer was
        // wrong"; Error means "we could not ask", which an operator retries
        // instead of remediating. Collapsing the second into the first is what
        // turned a permission error on `sshd -T` into a report that root login
        // was enabled.
        let reading = match run_cmd(posix_wrap(check.command)).await {
            // The message goes into `raw` as well as the reason: `raw_value` is
            // what the GUI shows as the row's evidence, and "connection reset"
            // is exactly the evidence an operator needs to decide whether to
            // retry the scan or investigate the host.
            Err(e) => Reading::Inconclusive {
                reason: format!("the command could not be run: {e}"),
                raw: format!("[transport error: {e}]"),
            },
            Ok(out) => {
                let raw = out.output.chars().take(RAW_LIMIT).collect::<String>();
                match out.code {
                    // Every script's contract: exit 0 only when its output
                    // answers the question. See the module docs.
                    Some(code) if code != 0 => Reading::Inconclusive {
                        reason: format!(
                            "the check script exited {code}, meaning it could not \
                             determine this setting — commonly because reading the \
                             effective sshd config needs root, or because the tool \
                             it queries is not installed"
                        ),
                        raw,
                    },
                    _ if raw.trim().is_empty() => Reading::Inconclusive {
                        reason: "the command produced no output, so nothing was \
                                 verified"
                            .to_owned(),
                        raw,
                    },
                    _ => Reading::Answered(raw),
                }
            }
        };

        let (status, detail, raw) = match reading {
            Reading::Inconclusive { reason, raw } => (
                Status::Error,
                format!("Not determined: {reason}"),
                raw,
            ),
            Reading::Answered(raw) if check.expect.satisfied_by(&raw) => (
                Status::Pass,
                "Configuration matches baseline.".to_owned(),
                raw,
            ),
            Reading::Answered(raw) => {
                // The refinement sees the same lowercased output the pass/fail
                // decision was made on, so a message can never describe a value
                // the check did not actually read.
                let lower = raw.to_lowercase();
                let detail = check
                    .refine_detail
                    .and_then(|refine| refine(&lower))
                    .unwrap_or(check.detail_on_fail)
                    .to_owned();
                (Status::Fail, detail, raw)
            }
        };

        check_results.push(compliance::CheckResult {
            check_id: check.id.to_owned(),
            status,
            detail,
            raw_value: Some(raw),
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
/// out of scope here and would ripple through `notify/findings_store`/
/// `report/cve_feed/risk`. See compliance.rs for that future cleanup.
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
/// `FortiGate` path's `CheckDefinition.category` (which has values
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
#[must_use]
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
/// for Linux `check_ids`, and `render_markdown_report` produces a
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
/// **Runtime fields (`cli_command`, `cli_grep`, channel, expect,
/// `api_path`, `api_pointer`)** are placeholders, not consulted by
/// the Linux runner — `run_baseline` reads commands directly off
/// `LINUX_CHECKS` and matches via `LinuxCheck.expect_contains`.
/// The library row's value for Linux is in `description /
/// remediation / cisReference / category / severity / title /
/// framework` — the fields `ChecksLibrarySheet` and `CheckRow`
/// actually render. See per-field notes below.
#[must_use]
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
            framework: LINUX_FRAMEWORK.to_owned(),
            cis_reference: cis_reference(c.id).map(str::to_owned),
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

/// The benchmark these checks are drawn from, named exactly.
///
/// Previously "CIS Linux 4.0", which is not a benchmark CIS publishes. Their
/// Linux benchmarks are per-distribution (Ubuntu 22.04, RHEL 9, …) plus this
/// distribution-independent one, and versions are `x.y.z`. A framework string
/// naming a document nobody can look up is worse than useless in a report an
/// auditor reads — it makes every reference beside it unverifiable too.
pub const LINUX_FRAMEWORK: &str = "CIS Distribution Independent Linux v2.0.0";

/// The benchmark section a check corresponds to, where one genuinely does.
///
/// **Two of seven.** This was checked against the control list rather than
/// filled in by pattern, and most of the baseline turns out to have no
/// counterpart in the distribution-independent benchmark:
///
/// - `password-auth-disabled` — CIS DIL has **no** `PasswordAuthentication`
///   control. 5.2.11 is `PermitEmptyPasswords`, which is a different setting.
///   Key-only SSH is a defensible control; it is not this benchmark's.
/// - `core-pattern-safe` — 1.5.1 "Ensure core dumps are restricted" is the
///   neighbourhood, but it checks `fs.suid_dumpable` and a limits entry, not
///   `kernel.core_pattern`. Piping a core dump to a program is a different
///   failure, and citing 1.5.1 would claim we verified something we did not.
/// - `unattended-upgrades-active` — 1.8 is "updates, patches and additional
///   security software are installed", i.e. that patching happened, not that
///   it is automated. 1.2.x is repositories and GPG keys.
/// - `journald-running` — 4.2.2.x configure journald (forward to rsyslog,
///   compress, persist) and 4.2.1.2 is *rsyslog* enabled-and-running. None of
///   them says "journald is up", which is what we check.
/// - `firewall.active` — 3.5.2.1 "Ensure default deny firewall policy" is the
///   closest, and deliberately not cited: it verifies INPUT/OUTPUT/FORWARD are
///   DROP, while this check only verifies a firewall is *active*. A PASS
///   labelled 3.5.2.1 would tell an auditor default-deny was confirmed. It
///   was not. Tightening the check to match the control is the way to earn
///   that reference.
///
/// Leaving those five `None` is the honest outcome, and the reasoning is here
/// so the next person reads "checked, no counterpart" rather than "not done
/// yet" and fills the gap with something plausible.
///
/// Sources: the control ids and titles were read from the `dev-sec/cis-dil-benchmark`
/// `InSpec` profile, which encodes the benchmark's own numbering.
fn cis_reference(check_id: &str) -> Option<&'static str> {
    match check_id {
        // "Ensure SSH Protocol is set to 2"
        "linux.ssh.protocol-v2-only" => Some("5.2.4"),
        // "Ensure SSH root login is disabled"
        "linux.ssh.root-login-disabled" => Some("5.2.10"),
        _ => None,
    }
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
        _ => "Linux baseline check. (No detailed description authored — see the CIS Distribution Independent Linux Benchmark.)",
    }
}

/// Static count of checks the baseline currently covers — handy
/// for the UI's "Linux baseline (7 checks)" subtitle without
/// needing to call `run_baseline` first.
#[must_use]
pub fn check_count() -> usize {
    LINUX_CHECKS.len()
}

/// Names of every check, in order. Surfaced to the UI when the
/// operator wants to see what the baseline actually checks
/// before running it.
#[must_use]
pub fn check_titles() -> Vec<&'static str> {
    LINUX_CHECKS.iter().map(|c| c.title).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_checks_with_a_real_cis_control_carry_a_reference() {
        // The point of this test is to stop the gap being "helpfully" filled.
        // Five of these checks have no counterpart in the CIS Distribution
        // Independent Linux Benchmark — that was established by reading its
        // control list, not assumed — and a plausible-looking section number
        // beside a PASS tells an auditor we verified something we did not.
        //
        // If a future version of the benchmark grows one of these controls,
        // update `cis_reference` and this list together.
        let with_ref: Vec<(&str, &str)> = LINUX_CHECKS
            .iter()
            .filter_map(|c| cis_reference(c.id).map(|r| (c.id, r)))
            .collect();
        assert_eq!(
            with_ref,
            [
                ("linux.ssh.root-login-disabled", "5.2.10"),
                ("linux.ssh.protocol-v2-only", "5.2.4"),
            ],
            "the set of checks claiming a CIS section changed"
        );
    }

    #[test]
    fn the_firewall_check_does_not_claim_the_default_deny_control() {
        // 3.5.2.1 verifies INPUT/OUTPUT/FORWARD are DROP. This check only
        // verifies that some firewall is active, which is weaker. Citing it
        // would be the most tempting of the five and the most misleading.
        assert_eq!(cis_reference("linux.firewall.active"), None);
    }

    #[test]
    fn the_framework_names_a_benchmark_that_exists() {
        // "CIS Linux 4.0" was not a document anyone could look up, which made
        // every reference beside it unverifiable too. Version included
        // because section numbers move between benchmark versions.
        assert!(LINUX_FRAMEWORK.contains("Distribution Independent"));
        assert!(
            LINUX_FRAMEWORK.contains("v2.0.0"),
            "the version must be named — 5.2.10 is only meaningful against one"
        );
    }

    #[test]
    fn every_reference_is_a_section_number_and_nothing_else() {
        // A reference is rendered raw into a badge and a report column. Prose
        // or a URL there would look like a citation without being one.
        for check in LINUX_CHECKS {
            if let Some(r) = cis_reference(check.id) {
                assert!(
                    r.chars().all(|c| c.is_ascii_digit() || c == '.'),
                    "{}: {r:?} is not a bare section number",
                    check.id
                );
            }
        }
    }

    /// One check by id, so a test can assert about it without running a scan.
    fn find(check_id: &str) -> &'static LinuxCheck {
        LINUX_CHECKS
            .iter()
            .find(|c| c.id == check_id)
            .unwrap_or_else(|| panic!("no check with id {check_id}"))
    }

    /// Pull the refinement for one check id, so the messages can be checked
    /// without running a baseline.
    fn refine(check_id: &str, observed: &str) -> Option<&'static str> {
        find(check_id).refine_detail.and_then(|f| f(observed))
    }

    #[test]
    fn prohibit_password_is_not_described_as_an_open_door() {
        // The bug this fixes, observed on a real host: sshd reported
        // `PermitRootLogin prohibit-password` and the row said "Direct root SSH
        // login is allowed". True of `yes`, misleading here — root cannot use a
        // password, so an operator reading it would escalate something that is
        // housekeeping.
        let msg = refine(
            "linux.ssh.root-login-disabled",
            "permitrootlogin prohibit-password",
        )
        .expect("prohibit-password has its own message");
        assert!(
            msg.contains("not with a password"),
            "must say passwords are already refused: {msg}"
        );
        assert!(
            msg.contains("5.2.10"),
            "must still cite the control it fails: {msg}"
        );
    }

    #[test]
    fn permitrootlogin_yes_is_described_as_urgent() {
        let msg = refine("linux.ssh.root-login-disabled", "permitrootlogin yes")
            .expect("yes has its own message");
        assert!(
            msg.contains("password"),
            "must name password login as the risk: {msg}"
        );
        assert!(
            msg.contains("brute-forceable"),
            "must say why it is the urgent form: {msg}"
        );
    }

    #[test]
    fn the_two_root_login_messages_are_not_interchangeable() {
        // The whole point. If these ever converge, the distinction that cost an
        // operator a wrong priority call is gone again.
        let lenient = refine(
            "linux.ssh.root-login-disabled",
            "permitrootlogin prohibit-password",
        );
        let open = refine("linux.ssh.root-login-disabled", "permitrootlogin yes");
        assert_ne!(lenient, open);
    }

    #[test]
    fn an_unrecognised_value_falls_back_rather_than_guessing() {
        // `forced-commands-only` exists and neither branch describes it. A
        // general message beats inventing an implication for a value we have
        // never seen.
        assert_eq!(
            refine(
                "linux.ssh.root-login-disabled",
                "permitrootlogin forced-commands-only"
            ),
            None
        );
    }

    #[test]
    fn only_the_root_login_check_refines_its_message() {
        // Not a style rule: every other check's failure means exactly one
        // thing, and a refinement there would be a second place for the text
        // to drift from the control.
        let refining: Vec<&str> = LINUX_CHECKS
            .iter()
            .filter(|c| c.refine_detail.is_some())
            .map(|c| c.id)
            .collect();
        assert_eq!(refining, ["linux.ssh.root-login-disabled"]);
    }

    // -- the four defects a live scan exposed, each with its own regression ---
    //
    // All four were found by running the baseline against a real host and
    // disbelieving the result, not by reading the code. Three of them produced
    // PASS, which is the direction nobody audits.

    #[test]
    fn inactive_does_not_satisfy_active() {
        // Defect 1. `expect_contains: "active"` matched `systemctl is-active`'s
        // output `inactive`, so a host with no automatic patching at all passed
        // the patching check. Verified against the real command: on the host
        // that exposed this, `systemctl is-active unattended-upgrades
        // dnf-automatic` prints exactly `inactive`.
        assert!(
            !Expect::LineIs("auto-updates=active").satisfied_by("auto-updates=inactive\n"),
            "the stopped state must not satisfy the running expectation"
        );
        assert!(Expect::LineIs("auto-updates=active").satisfied_by("unit=x\nauto-updates=active\n"));

        // The trap itself, so the reason this matcher exists stays legible.
        assert!(
            Expect::Contains("active").satisfied_by("inactive"),
            "substring matching really does accept the opposite state"
        );
    }

    #[test]
    fn the_journald_check_cannot_be_fooled_the_same_way() {
        // Same trap, same shape, second occurrence — it was two checks, not one.
        let check = find("linux.audit.journald-running");
        assert!(!check.expect.satisfied_by("journald=inactive\n"));
        assert!(check.expect.satisfied_by("journald=active\n"));
    }

    #[test]
    fn systemd_coredump_is_not_mistaken_for_a_safe_core_pattern() {
        // Defect 4, and the worst of them: `expect_contains: "core"` was
        // satisfied by `|/usr/lib/systemd/systemd-coredump` — the exact piped
        // form the check exists to detect — because `coredump` contains `core`.
        // systemd is the default init nearly everywhere, so this High/CVSS-7.5
        // check passed on nearly every host while verifying nothing.
        let piped = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h";
        assert!(
            Expect::Contains("core").satisfied_by(piped),
            "the old needle really did accept a piped pattern"
        );

        // What the check does now: the script classifies, and only its verdict
        // is matched. A pipe to an unrecognised program fails.
        let check = find("linux.kernel.core-pattern-safe");
        assert!(check.expect.satisfied_by("value=core.%p\nhandler=file\ncore-pattern=safe\n"));
        assert!(
            !check
                .expect
                .satisfied_by("value=|/tmp/evil\nhandler=unrecognised-pipe\ncore-pattern=piped\n"),
            "a pipe to an attacker's program must fail"
        );
        // And the distribution handler is allowlisted by absolute path in the
        // script, so a stock install does not produce a High finding.
        assert!(check.command.contains("/usr/lib/systemd/systemd-coredump"));
        assert!(check.command.contains("/usr/share/apport/apport"));
    }

    #[tokio::test]
    async fn a_script_that_could_not_answer_is_an_error_not_a_failure() {
        // Defect 3. `sshd -T` needs root; over SSH as an ordinary user it exits
        // non-zero and prints nothing to stdout. The old runner scored the empty
        // output as Fail, so an unprivileged scan reported that root login was
        // enabled and that passwords were accepted — findings invented from a
        // permission error. Both callers had the exit status and dropped it.
        let run = run_baseline("h", None, TriggerKind::Manual, |cmd| async move {
            let _ = cmd;
            Ok(CmdOutput::new("sshd: no hostkeys available -- exiting.", 1))
        })
        .await;

        assert_eq!(run.errored, check_count() as u32, "every check is inconclusive");
        assert_eq!(run.failed, 0, "a permission error is not a finding");
        assert_eq!(run.passed, 0);
        for c in &run.checks {
            assert!(matches!(c.status, Status::Error), "{}", c.check_id);
            assert!(
                c.detail.starts_with("Not determined:"),
                "the row must say we could not tell, not what is wrong: {}",
                c.detail
            );
            // The underlying reason stays visible for triage.
            assert!(c
                .raw_value
                .as_deref()
                .is_some_and(|r| r.contains("no hostkeys available")));
        }
    }

    #[tokio::test]
    async fn empty_output_with_a_zero_exit_is_still_not_an_answer() {
        // The other half of defect 3: a transport that cannot report status
        // (code: None) or a script that exits 0 having printed nothing has still
        // verified nothing, and must not be scored as a failed control.
        let run = run_baseline("h", None, TriggerKind::Manual, |cmd| async move {
            let _ = cmd;
            Ok(CmdOutput {
                output: "   \n".to_owned(),
                code: None,
            })
        })
        .await;
        assert_eq!(run.errored, check_count() as u32);
        assert_eq!(run.failed, 0);
    }

    #[tokio::test]
    async fn every_script_reaches_the_host_wrapped_for_a_posix_shell() {
        // Defect 2. SSH runs commands through the account's login shell. On the
        // host that exposed this the shell was fish, where the firewall check's
        // `(…) && … || …` is a syntax error — and fish's error message echoes the
        // offending line, which contained the literal `echo enabled` the old
        // needle was looking for. The check passed on its own error message.
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let tap = std::sync::Arc::clone(&seen);
        let _ = run_baseline("h", None, TriggerKind::Manual, move |cmd| {
            let tap = std::sync::Arc::clone(&tap);
            async move {
                tap.lock().unwrap().push(cmd);
                Ok(CmdOutput::ok(ALL_PASS))
            }
        })
        .await;

        let sent = seen.lock().unwrap();
        assert_eq!(sent.len(), check_count());
        for cmd in sent.iter() {
            assert!(
                cmd.starts_with("/bin/sh -c '") && cmd.ends_with('\''),
                "the login shell must only ever see one quoted argument: {cmd}"
            );
        }
    }

    #[test]
    fn wrapping_survives_a_script_containing_single_quotes() {
        // Backslash does not escape a quote inside single quotes; the portable
        // form is close-quote, quoted-quote, reopen. A script with an `awk '…'`
        // in it would otherwise break out of the wrapper.
        let wrapped = posix_wrap("echo 'hi there'");
        assert_eq!(wrapped, r"/bin/sh -c 'echo '\''hi there'\'''");

        // And it really parses: the wrapper is only correct if a shell agrees.
        #[cfg(unix)]
        {
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&wrapped)
                .output()
                .expect("run /bin/sh");
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi there");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_non_posix_login_shell_can_parse_every_wrapped_command() {
        // The defect-2 regression against the actual shell that exposed it.
        // `fish -n` parses without executing, and it rejects the *unwrapped*
        // firewall script outright — so this asserts the wrapper is what makes
        // the difference, not that fish happens to be lenient.
        //
        // Skipped where fish is absent (CI runners), because the invariant is
        // already covered structurally by
        // `every_script_reaches_the_host_wrapped_for_a_posix_shell`.
        let parses = |shell: &str, args: &[&str]| -> Option<bool> {
            std::process::Command::new(shell)
                .args(args)
                .output()
                .ok()
                .map(|o| o.status.success())
        };
        if parses("fish", &["-n", "-c", "true"]) != Some(true) {
            return;
        }

        for check in LINUX_CHECKS {
            let wrapped = posix_wrap(check.command);
            assert_eq!(
                parses("fish", &["-n", "-c", &wrapped]),
                Some(true),
                "{}: a fish login shell cannot parse the wrapped command",
                check.id
            );
        }

        // And the control: bourne syntax really is rejected unwrapped, which is
        // what silently turned into a PASS on a customer's host.
        let bourne = "(systemctl is-active ufw) && echo enabled || echo disabled";
        assert_eq!(
            parses("fish", &["-n", "-c", bourne]),
            Some(false),
            "fish should reject this — if it does not, the test proves nothing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn every_check_script_is_valid_posix_shell() {
        // The defect-2 backstop that does not depend on anyone remembering. `sh
        // -n` parses without executing, so this is cheap and catches the class
        // of mistake — bashisms, unbalanced quotes, a stray `(` — at test time
        // rather than as a false PASS on a customer's host.
        for check in LINUX_CHECKS {
            let out = std::process::Command::new("/bin/sh")
                .arg("-n")
                .arg("-c")
                .arg(check.command)
                .output()
                .expect("run /bin/sh -n");
            assert!(
                out.status.success(),
                "{} is not valid POSIX shell:\n{}\n--- script ---\n{}",
                check.id,
                String::from_utf8_lossy(&out.stderr),
                check.command
            );
        }
    }

    #[test]
    fn no_operator_facing_string_has_ragged_whitespace() {
        // A multi-line Rust string literal keeps every leading space of each
        // continuation line unless the line ends in `\`. The refined root-login
        // message shipped with a twenty-space gap in the middle of a sentence,
        // and it took reading a live scan's output to notice — these strings go
        // straight into a GUI row and a Markdown report an auditor reads.
        let mut authored: Vec<(&str, &str)> = Vec::new();
        for check in LINUX_CHECKS {
            authored.push((check.id, check.detail_on_fail));
            authored.push((check.id, check.recommendation));
            authored.push((check.id, linux_description(check.id)));
            if let Some(refine) = check.refine_detail {
                for probe in [
                    "permitrootlogin prohibit-password",
                    "permitrootlogin yes",
                ] {
                    if let Some(msg) = refine(probe) {
                        authored.push((check.id, msg));
                    }
                }
            }
        }

        for (id, s) in authored {
            assert!(
                !s.contains("  "),
                "{id}: authored text has a run of spaces, which renders as a gap \
                 mid-sentence: {s:?}"
            );
            assert!(
                !s.contains('\n') && !s.contains('\t'),
                "{id}: authored text has a hard line break: {s:?}"
            );
            assert_eq!(s.trim(), s, "{id}: authored text has edge whitespace: {s:?}");
        }
    }

    #[test]
    fn needles_are_lowercase() {
        // `satisfied_by` lowercases the output rather than making every script
        // normalise its own casing. An uppercase needle would therefore never
        // match, and the check would fail on a perfectly compliant host.
        for check in LINUX_CHECKS {
            let n = check.expect.needle();
            assert_eq!(
                n,
                n.to_lowercase(),
                "{}: needle {n:?} can never match a lowercased output",
                check.id
            );
        }
    }

    #[test]
    fn no_check_still_uses_bare_substring_matching_for_a_state_word() {
        // `Contains` is still the right mode for a genuine substring — the
        // OpenSSH version banner — but it is the mode both false PASSes came
        // from. Anything asserting a state or a setting value must be exact, so
        // adding a `Contains("active")`-shaped check fails here rather than on a
        // customer's host.
        for check in LINUX_CHECKS {
            if let Expect::Contains(n) = check.expect {
                assert_eq!(
                    check.id, "linux.ssh.protocol-v2-only",
                    "{}: substring matching on {n:?} — use LineIs or HasToken",
                    check.id
                );
            }
        }
    }

    #[test]
    fn the_sshd_checks_can_answer_without_root() {
        // Reporting Error on the two most valuable checks for every scan run as
        // an ordinary user would be honest but useless, so the reader falls back
        // through sudo, then the config file, then OpenSSH's compiled-in
        // default — reporting which source answered rather than hiding it.
        for id in [
            "linux.ssh.password-auth-disabled",
            "linux.ssh.root-login-disabled",
        ] {
            let cmd = find(id).command;
            assert!(cmd.contains("sudo -n sshd -T"), "{id}: no sudo fallback");
            assert!(cmd.contains("/etc/ssh/sshd_config.d"), "{id}: no drop-in dir");
            assert!(cmd.contains("s=openssh-default"), "{id}: no default branch");
            assert!(cmd.contains("exit 3"), "{id}: must be able to give up");
        }

        // The defaults named have to be OpenSSH's actual defaults, or the
        // fallback reports a value the host does not have. Both of these fail
        // their control, which is why a silent config file is a Fail and not a
        // Pass.
        assert!(find("linux.ssh.root-login-disabled")
            .command
            .contains("d=prohibit-password"));
        assert!(find("linux.ssh.password-auth-disabled")
            .command
            .contains("d=yes"));
    }

    #[tokio::test]
    async fn a_config_file_answer_is_matched_despite_the_source_line() {
        // The reader prints `source=<how>` on its own line so the operator can
        // see whether Match blocks were resolved. That line must not stop the
        // value from matching — which is why the source is a separate line
        // rather than a prefix.
        let check = find("linux.ssh.root-login-disabled");
        assert!(check
            .expect
            .satisfied_by("source=config-file\nPermitRootLogin no\n"));
        assert!(check
            .expect
            .satisfied_by("source=openssh-default\npermitrootlogin no\n"));
        assert!(!check
            .expect
            .satisfied_by("source=sshd-T\npermitrootlogin prohibit-password\n"));
    }

    #[test]
    fn check_count_matches_array_length() {
        assert_eq!(check_count(), LINUX_CHECKS.len());
        assert!(check_count() >= 5, "should ship a meaningful starter set");
    }

    #[test]
    fn every_check_has_unique_id() {
        let mut ids: Vec<&'static str> = LINUX_CHECKS.iter().map(|c| c.id).collect();
        ids.sort_unstable();
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

    /// Output of a maximally-compliant host: every check's expectation is
    /// satisfied by some line of this.
    const ALL_PASS: &str = "source=sshd-T\n\
                            passwordauthentication no\n\
                            permitrootlogin no\n\
                            openssh_9.0\n\
                            value=core.%p\n\
                            core-pattern=safe\n\
                            auto-updates=active\n\
                            journald=active\n\
                            firewall=active\n";

    #[tokio::test]
    async fn run_baseline_pass_path_produces_all_pass_checks() {
        let run = run_baseline(
            "host-id-1",
            Some("test-linux"),
            TriggerKind::Manual,
            |cmd| async move {
                let _ = cmd;
                Ok(CmdOutput::ok(ALL_PASS))
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
                Ok(CmdOutput::ok("nothing matches"))
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
                .is_some_and(|s| s.contains("simulated ssh disconnect")));
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
                Ok(CmdOutput::ok("passwordauthentication no"))
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
                Ok(CmdOutput::ok("passwordauthentication no"))
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
