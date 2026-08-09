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
pub use supermgr_core::tailscale::TailscaleNode;

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
}
