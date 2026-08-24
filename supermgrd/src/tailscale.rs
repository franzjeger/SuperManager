//! Tailscale node listing.
//!
//! Reads the local tailscaled state via `tailscale status --json`, which is
//! the official supported way to script Tailscale and ships in every release
//! of the tailscale CLI. No API token is needed — the daemon reads through
//! the Unix socket of the local tailscaled.
//!
//! # Why a subprocess and not the local API directly
//!
//! tailscaled exposes a localhost HTTP API on a Unix socket
//! (`/var/run/tailscale/tailscaled.sock`), but its schema is unstable across
//! minor versions. The `tailscale status --json` output is a stable,
//! human-curated subset that Tailscale guarantees backwards compatibility
//! for, so it's the recommended boundary for third-party tooling.

use tracing::{debug, warn};

// The node shape is shared with the GUI, which deserializes it straight off
// D-Bus — see `supermgr_core::tailscale`. Re-exported so existing
// `crate::tailscale::TailscaleNode` paths keep resolving.
pub use supermgr_core::tailscale::{TailscaleHealth, TailscaleNode};

/// Diagnose the local Tailscale stack: CLI present, daemon answering,
/// backend state, pending login URL.
///
/// Never returns `Err` — the whole point of this function is that every
/// failure mode of the stack is a *state* with a remedy, not an error. The
/// GUI renders the returned struct; `TailscaleRepair` and `TailscaleLogin`
/// consume it to decide what needs doing.
pub async fn health() -> TailscaleHealth {
    let out = match tokio::process::Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .await
    {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return TailscaleHealth {
                detail: "the tailscale CLI is not installed".to_owned(),
                ..TailscaleHealth::default()
            };
        }
        Err(e) => {
            return TailscaleHealth {
                cli_present: true,
                detail: format!("failed to spawn tailscale: {e}"),
                ..TailscaleHealth::default()
            };
        }
    };

    // `tailscale status --json` reports logged-out and stopped states as
    // JSON on stdout with exit 0 or 1 depending on version; a daemon that
    // is not running at all yields no JSON and a "failed to connect" on
    // stderr. Parseable JSON is therefore the discriminator, not the exit
    // code.
    let Ok(raw) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return TailscaleHealth {
            cli_present: true,
            detail: if stderr.is_empty() {
                format!("tailscale status produced no JSON (exit {})", out.status)
            } else {
                stderr
            },
            ..TailscaleHealth::default()
        };
    };

    health_from_status_json(&raw)
}

/// The pure part of [`health`], split out so the state mapping is testable
/// without a tailscaled.
fn health_from_status_json(raw: &serde_json::Value) -> TailscaleHealth {
    let backend_state = raw
        .get("BackendState")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    TailscaleHealth {
        cli_present: true,
        // The CLI got JSON out of the daemon, so the daemon is up — however
        // unhappy the backend state says it is.
        daemon_running: true,
        auth_url: raw
            .get("AuthURL")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        backend_state,
        detail: String::new(),
    }
}

/// Which package manager this host uses, by which binary exists.
///
/// Checked in order of specificity, not popularity — a host with both
/// `pacman` and `apt` (containers do this) is far more likely to be Arch
/// with a stray tool than Debian with pacman installed.
fn detect_package_manager() -> Option<(&'static str, &'static [&'static str])> {
    const CANDIDATES: &[(&str, &[&str])] = &[
        ("pacman", &["-S", "--noconfirm", "--needed", "tailscale"]),
        ("apt-get", &["install", "-y", "tailscale"]),
        ("dnf", &["install", "-y", "tailscale"]),
        ("zypper", &["--non-interactive", "install", "tailscale"]),
    ];
    CANDIDATES
        .iter()
        .find(|(pm, _)| which_exists(pm))
        .copied()
}

/// `command -v` without the shell: walk PATH for an executable file.
fn which_exists(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(name);
        candidate.is_file()
            && std::fs::metadata(&candidate)
                .map(|m| {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode() & 0o111 != 0
                })
                .unwrap_or(false)
    })
}

/// Bring the local Tailscale stack up as far as it can go without a human:
/// install the package if the CLI is missing, start and enable tailscaled,
/// and `tailscale up` if the backend was deliberately stopped. Login is the
/// one step this cannot do — that is [`login_start`]'s job, because it needs
/// a browser and a person.
///
/// Idempotent by construction: each step is skipped when its condition
/// already holds, so calling this on a healthy stack does nothing. Returns a
/// human-readable summary of the steps actually taken.
///
/// The package name is a constant and the package manager is detected, not
/// caller-supplied — nothing from the bus reaches these command lines.
pub async fn repair() -> Result<String, String> {
    let mut done: Vec<String> = Vec::new();
    let mut state = health().await;

    if !state.cli_present {
        let Some((pm, args)) = detect_package_manager() else {
            return Err(
                "the tailscale CLI is missing and no supported package manager \
                 (pacman, apt-get, dnf, zypper) was found — install it manually, \
                 see https://tailscale.com/install"
                    .to_owned(),
            );
        };
        debug!(pm, "tailscale::repair: installing tailscale");
        let out = tokio::process::Command::new(pm)
            .args(args)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .output()
            .await
            .map_err(|e| format!("failed to run {pm}: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            return Err(format!(
                "{pm} could not install tailscale ({}): {stderr}. If the package \
                 is not in this distribution's repositories, add Tailscale's own — \
                 see https://tailscale.com/install",
                out.status
            ));
        }
        done.push(format!("installed the tailscale package via {pm}"));
    }

    // Enable + start in one systemctl call. Also the remedy when the unit
    // exists but is stopped, and a no-op (exit 0) when already both.
    let out = tokio::process::Command::new("systemctl")
        .args(["enable", "--now", "tailscaled"])
        .output()
        .await
        .map_err(|e| format!("failed to run systemctl: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return Err(format!("could not start tailscaled: {stderr}"));
    }
    if !state.daemon_running {
        done.push("started and enabled the tailscaled service".to_owned());
    }

    // `tailscale down` leaves BackendState "Stopped"; the daemon runs but
    // carries no traffic. `up` with no arguments resumes with existing
    // prefs. The timeout matters: against a logged-out node `up` would
    // otherwise block on the interactive login this method deliberately
    // does not perform.
    state = health().await;
    if state.daemon_running && state.backend_state == "Stopped" {
        let out = tokio::process::Command::new("tailscale")
            .args(["up", "--timeout=15s"])
            .output()
            .await
            .map_err(|e| format!("failed to run tailscale up: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            return Err(format!("tailscale up failed: {stderr}"));
        }
        done.push("brought the tailscale backend up".to_owned());
    }

    if done.is_empty() {
        Ok("nothing to repair — the Tailscale stack is already as far up \
            as it can get without a login"
            .to_owned())
    } else {
        Ok(done.join("; "))
    }
}

/// Start an interactive login and return the URL a person must visit.
///
/// Spawns `tailscale login` detached — it blocks until the browser flow
/// completes, which can be minutes away — and then polls the daemon's
/// status for the `AuthURL` it registers. Control-plane round-trips can be
/// slow, so an empty string is a legitimate return: the URL was not there
/// yet, but it will appear in [`health`]'s `auth_url` shortly, and the GUI
/// polls that anyway. Distinguishing "not yet" from "failed" is exactly
/// what the health polling is for.
///
/// Calling this twice is safe: tailscaled hands every `login` the same
/// pending URL until it is used, and the detached child exits on its own
/// when the login completes or tailscaled drops the attempt.
pub async fn login_start() -> Result<String, String> {
    let state = health().await;
    if !state.cli_present || !state.daemon_running {
        return Err("tailscale is not installed or tailscaled is not running — \
                    repair first, then log in"
            .to_owned());
    }
    if state.is_running() {
        return Err("already logged in".to_owned());
    }
    if !state.auth_url.is_empty() {
        // A login is already pending; reuse its URL rather than spawning a
        // second child to be told the same thing.
        return Ok(state.auth_url);
    }

    let mut child = tokio::process::Command::new("tailscale")
        .arg("login")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start tailscale login: {e}"))?;
    // Reap the child whenever it finishes; its lifetime is the login flow's,
    // not this method's.
    tokio::spawn(async move {
        let _ = child.wait().await;
    });

    // The URL comes from a control-plane round-trip that is usually fast
    // and occasionally ~30s. Poll briefly here so the common case returns
    // the URL directly; past the deadline, hand the wait over to the GUI's
    // health polling instead of holding the bus call open.
    const ATTEMPTS: u32 = 8;
    for _ in 0..ATTEMPTS {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let state = health().await;
        if !state.auth_url.is_empty() {
            return Ok(state.auth_url);
        }
        if state.is_running() {
            // Logged in before we even saw the URL — some other flow (CLI,
            // another session) completed it. Nothing left to visit.
            return Ok(String::new());
        }
    }
    Ok(String::new())
}

/// Run `tailscale status --json` and parse the output into a normalized
/// node list. Returns an error string suitable for surfacing to the GUI on
/// any failure (CLI not installed, daemon not running, JSON parse error).
pub async fn list_nodes() -> Result<Vec<TailscaleNode>, String> {
    debug!("tailscale::list_nodes: spawning `tailscale status --json`");

    let out = tokio::process::Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "tailscale CLI not found — install the tailscale package".to_owned()
            } else {
                format!("failed to spawn tailscale: {e}")
            }
        })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "tailscale status --json exited {}: {}",
            out.status,
            stderr.trim()
        ));
    }

    let raw: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("parse tailscale JSON: {e}"))?;

    let mut nodes: Vec<TailscaleNode> = Vec::new();

    if let Some(self_node) = raw.get("Self") {
        nodes.push(parse_node(self_node, true));
    }

    if let Some(peer_map) = raw.get("Peer").and_then(|v| v.as_object()) {
        for (_key, peer) in peer_map {
            nodes.push(parse_node(peer, false));
        }
    } else if raw.get("Peer").is_none() {
        // Either tailscale isn't running on this machine or the schema
        // changed. Self alone is still useful so don't fail the whole call.
        warn!("tailscale status JSON has no Peer field — only Self returned");
    }

    Ok(nodes)
}

/// Pull the fields we care about out of one `Self` / `Peer.*` JSON object.
///
/// Missing fields fall back to sensible defaults rather than failing —
/// `tailscale status --json` has gradually grown fields over the years and
/// older versions on a node may omit some. A partial node entry is more
/// useful than a hard error.
fn parse_node(v: &serde_json::Value, is_self: bool) -> TailscaleNode {
    TailscaleNode {
        id: v.get("ID").and_then(|x| x.as_str()).unwrap_or("").to_owned(),
        hostname: v.get("HostName").and_then(|x| x.as_str()).unwrap_or("").to_owned(),
        dns_name: v
            .get("DNSName")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim_end_matches('.')
            .to_owned(),
        os: v.get("OS").and_then(|x| x.as_str()).unwrap_or("").to_owned(),
        tailscale_ips: v
            .get("TailscaleIPs")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        online: v.get("Online").and_then(|x| x.as_bool()).unwrap_or(false),
        is_self,
        exit_node: v.get("ExitNode").and_then(|x| x.as_bool()).unwrap_or(false),
        exit_node_option: v
            .get("ExitNodeOption")
            .and_then(|x| x.as_bool())
            .unwrap_or(false),
        last_seen: v
            .get("LastSeen")
            .and_then(|x| x.as_str())
            // Tailscale uses the Go zero-time literal for "never seen".
            // Treat it as empty for the GUI.
            .filter(|s| !s.starts_with("0001-01-01"))
            .unwrap_or("")
            .to_owned(),
        rx_bytes: v.get("RxBytes").and_then(|x| x.as_u64()).unwrap_or(0),
        tx_bytes: v.get("TxBytes").and_then(|x| x.as_u64()).unwrap_or(0),
    }
}

/// Select an exit node, or clear the selection with an empty `value`.
///
/// `value` is a Tailscale IP, a MagicDNS name, or `""` to route normally
/// again. Handed to `tailscale set --exit-node=<value>`, which is the
/// documented interface and — unlike macOS, where open-source tailscaled
/// leaves the split-default routes to the caller — installs the routing
/// itself on Linux. So this is the whole implementation, not the first half of
/// one; there is no route bookkeeping to keep in sync here.
///
/// Rejects anything that is not a plausible address or DNS label rather than
/// passing it through. The argument reaches a subprocess, and while the argv
/// form means a shell is never involved, `--exit-node=--flag` would let a
/// caller inject a tailscale option instead of a host. tailscaled would
/// reject most of that anyway; not relying on somebody else's parser for that
/// guarantee costs one function.
pub async fn set_exit_node(value: &str) -> Result<(), String> {
    let value = value.trim();
    if !value.is_empty() && !is_plausible_exit_node(value) {
        return Err(format!(
            "{value:?} is not a Tailscale address or MagicDNS name"
        ));
    }

    let out = tokio::process::Command::new("tailscale")
        .arg("set")
        .arg(format!("--exit-node={value}"))
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "the tailscale CLI is not installed".to_owned()
            } else {
                format!("could not run tailscale: {e}")
            }
        })?;

    if out.status.success() {
        if value.is_empty() {
            debug!("tailscale exit node cleared");
        } else {
            debug!(exit_node = %value, "tailscale exit node set");
        }
        return Ok(());
    }

    // tailscale writes the useful part to stderr — "exit node not found",
    // "not logged in". Pass it through: it is better than anything we would
    // write, and the failure modes are somebody else's state, not ours.
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    let message = if stderr.is_empty() {
        format!("tailscale set failed ({})", out.status)
    } else {
        stderr
    };
    warn!(exit_node = %value, "{message}");
    Err(message)
}

/// Whether `value` looks like a Tailscale IP or a MagicDNS name.
///
/// Deliberately a shape check, not a resolution: whether the peer exists is
/// tailscaled's business and it answers with a better error than we could.
/// This only ensures what we hand over is an address-or-name and not an
/// option — the leading-dash case is the one that matters.
fn is_plausible_exit_node(value: &str) -> bool {
    !value.starts_with('-')
        && !value.contains(char::is_whitespace)
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_node_minimal_object() {
        let v = serde_json::json!({});
        let n = parse_node(&v, false);
        assert_eq!(n.id, "");
        assert_eq!(n.hostname, "");
        assert!(n.tailscale_ips.is_empty());
        assert!(!n.online);
        assert_eq!(n.last_seen, "");
        assert_eq!(n.rx_bytes, 0);
    }

    #[test]
    fn parse_node_typical_self_payload() {
        // Payload shape pulled from `tailscale status --json` on
        // tailscale 1.96.4 (2026-04). See module docs for stability promise.
        let v = serde_json::json!({
            "ID": "nABC123",
            "HostName": "franzjeger",
            "DNSName": "franzjeger.tailb0b06a.ts.net.",
            "OS": "linux",
            "TailscaleIPs": ["100.92.199.54", "fd7a:115c:a1e0::232:c736"],
            "Online": true,
            "ExitNode": false,
            "LastSeen": "2026-04-28T05:00:00Z",
            "RxBytes": 1024,
            "TxBytes": 2048,
        });
        let n = parse_node(&v, true);
        assert_eq!(n.id, "nABC123");
        assert_eq!(n.hostname, "franzjeger");
        // Trailing `.` from MagicDNS canonical form must be stripped.
        assert_eq!(n.dns_name, "franzjeger.tailb0b06a.ts.net");
        assert_eq!(n.os, "linux");
        assert_eq!(n.tailscale_ips.len(), 2);
        assert!(n.online);
        assert!(n.is_self);
        assert!(!n.exit_node);
        assert_eq!(n.last_seen, "2026-04-28T05:00:00Z");
        assert_eq!(n.rx_bytes, 1024);
        assert_eq!(n.tx_bytes, 2048);
    }

    #[test]
    fn parse_node_treats_go_zero_time_as_never() {
        let v = serde_json::json!({ "LastSeen": "0001-01-01T00:00:00Z" });
        let n = parse_node(&v, false);
        assert_eq!(n.last_seen, "", "Go zero-time should map to empty string");
    }

    /// Live smoke test against the local tailscaled. Ignored by default;
    /// run with `cargo test -p supermgrd tailscale::tests::live_listing
    /// -- --ignored --nocapture` on a machine with `tailscale up`.
    #[tokio::test]
    #[ignore = "live: requires a running tailscaled on this host"]
    async fn live_listing() {
        let nodes = list_nodes().await.expect("tailscale status --json failed");
        assert!(!nodes.is_empty(), "tailnet should at least include Self");
        let me = nodes.iter().find(|n| n.is_self).expect("no Self in node list");
        eprintln!("Self: {me:?}");
        assert!(!me.hostname.is_empty());
    }

    #[test]
    fn exit_node_option_is_parsed_separately_from_exit_node() {
        // The two mean different things and a real tailnet has peers where
        // they differ: one advertising exit-node capability while none is in
        // use. Collapsing them mislabels every candidate as active.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"HostName":"gw","ExitNode":false,"ExitNodeOption":true}"#,
        )
        .unwrap();
        let n = parse_node(&v, false);
        assert!(!n.exit_node, "not the active exit node");
        assert!(n.exit_node_option, "but available as one");
    }

    #[test]
    fn plausible_exit_node_rejects_option_injection() {
        // The value reaches `--exit-node=<value>`. argv means no shell, but a
        // leading dash would still let a caller pass a tailscale flag.
        assert!(!is_plausible_exit_node("--advertise-exit-node"));
        assert!(!is_plausible_exit_node("-x"));
        assert!(!is_plausible_exit_node("100.64.0.1 --reset"));
        assert!(!is_plausible_exit_node("host;reboot"));
    }

    #[test]
    fn plausible_exit_node_accepts_what_tailscale_accepts() {
        assert!(is_plausible_exit_node("100.96.91.67"));
        assert!(is_plausible_exit_node("fd7a:115c:a1e0::4832:5b44"));
        assert!(is_plausible_exit_node("cachyos-x8664.tailb0b06a.ts.net"));
    }

    #[test]
    fn health_maps_needs_login_with_pending_url() {
        // The logged-out-with-pending-login shape, as tailscale 1.102
        // reports it. The URL must pass through verbatim — the GUI opens it.
        let raw = serde_json::json!({
            "BackendState": "NeedsLogin",
            "AuthURL": "https://login.tailscale.com/a/abc123",
        });
        let h = health_from_status_json(&raw);
        assert!(h.cli_present && h.daemon_running);
        assert!(h.needs_login());
        assert!(!h.is_running());
        assert_eq!(h.auth_url, "https://login.tailscale.com/a/abc123");
    }

    #[test]
    fn health_maps_running_and_stopped() {
        let running = health_from_status_json(&serde_json::json!({"BackendState": "Running"}));
        assert!(running.is_running());
        assert!(running.auth_url.is_empty());

        // `tailscale down`: daemon up, carrying nothing. Neither running
        // nor a login problem — the repair path's `tailscale up` case.
        let stopped = health_from_status_json(&serde_json::json!({"BackendState": "Stopped"}));
        assert!(!stopped.is_running());
        assert!(!stopped.needs_login());
        assert_eq!(stopped.backend_state, "Stopped");
    }

    #[test]
    fn health_tolerates_schema_without_backend_state() {
        // An unrecognisable JSON shape must not read as "Running" — an
        // empty backend_state fails both is_running and needs_login, which
        // the GUI renders as its generic broken state.
        let h = health_from_status_json(&serde_json::json!({}));
        assert!(!h.is_running());
        assert!(!h.needs_login());
    }
}
