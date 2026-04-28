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

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// One node in the tailnet, normalized for GUI consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleNode {
    /// Stable Tailscale node ID.
    pub id: String,
    /// Short hostname (e.g. `franzjeger`).
    pub hostname: String,
    /// MagicDNS name (e.g. `franzjeger.tailb0b06a.ts.net`).
    pub dns_name: String,
    /// Operating system as reported by tailscaled (e.g. `linux`, `macOS`,
    /// `iOS`, `windows`).
    pub os: String,
    /// All Tailscale IPs (IPv4 + IPv6) for this node.
    pub tailscale_ips: Vec<String>,
    /// Whether tailscaled currently considers this node online.
    pub online: bool,
    /// Whether this is the local node (`Self` in the raw JSON).
    pub is_self: bool,
    /// Whether this node is enabled as an exit node.
    pub exit_node: bool,
    /// RFC 3339 timestamp of last activity, when known. Empty for nodes that
    /// have never been seen on the tailnet.
    pub last_seen: String,
    /// Bytes received from this peer since tailscaled started.
    pub rx_bytes: u64,
    /// Bytes sent to this peer since tailscaled started.
    pub tx_bytes: u64,
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
}
