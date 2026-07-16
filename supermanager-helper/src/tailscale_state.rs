//! Persisted "desired exit node" intent for the tailscale self-heal loop.
//!
//! The `0/1` + `128/1` split-defaults that route all traffic through a
//! tailscale exit node are a SuperManager artifact — open-source tailscaled
//! does NOT install them. They die when the tailscale utun is torn down on
//! sleep, and the connectivity watchdog's `panic_reset` removes them on a
//! blip; nothing re-installs them, so the machine silently falls back to the
//! local uplink (exit node bypassed) until a reboot.
//!
//! This file is the single source of truth for "the user wants exit node X".
//! It survives reboot, helper restart, and `panic_reset` (which clears
//! tailscaled's OWN exit-node pref). The reconciler in `auto_reconnect` reads
//! it every tick and re-establishes the routes — but ONLY after confirming the
//! peer is set + reachable, so it can never black-hole the machine.
//!
//! Mirrors the `STATE_PATH` / `persist` pattern in `auto_reconnect.rs`.

use serde::{Deserialize, Serialize};
use std::path::Path;

const DESIRED_PATH: &str = "/var/lib/supermanager/tailscale_desired.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesiredExitNode {
    /// True when the user has an exit node selected and routes were installed.
    /// The reconciler self-heals only while this is true.
    pub desired: bool,
    /// tailscaled `ExitNodeID` (stable peer id), best-effort. Empty if unknown.
    #[serde(default)]
    pub exit_node_id: String,
    /// The exit node's tailscale IP (100.x), best-effort. Empty if unknown.
    #[serde(default)]
    pub exit_node_ip: String,
    /// Unix seconds of the last update — telemetry/debug only.
    #[serde(default)]
    pub updated_unix: u64,
}

/// Read the persisted intent. A missing or corrupt file yields the default
/// (`desired = false`), so a fresh machine reconciles to "no exit node" — a
/// no-op, identical to today's behaviour.
pub fn load() -> DesiredExitNode {
    match std::fs::read_to_string(DESIRED_PATH) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => DesiredExitNode::default(),
    }
}

/// Record that the user wants exit node `id`/`ip` (routes were just installed).
/// `id`/`ip` may be empty when unknown — the reconciler falls back to
/// tailscaled's live pref in that case.
pub fn set_desired(id: &str, ip: &str) {
    write(&DesiredExitNode {
        desired: true,
        exit_node_id: id.to_string(),
        exit_node_ip: ip.to_string(),
        updated_unix: now_unix(),
    });
}

/// Record that the user intentionally cleared the exit node — stops self-heal.
pub fn clear_desired() {
    write(&DesiredExitNode {
        desired: false,
        updated_unix: now_unix(),
        ..Default::default()
    });
}

fn write(state: &DesiredExitNode) {
    if let Some(parent) = Path::new(DESIRED_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(state) {
        Ok(json) => {
            if let Err(e) = std::fs::write(DESIRED_PATH, json) {
                tracing::warn!("tailscale_state: write {DESIRED_PATH}: {e}");
            }
        }
        Err(e) => tracing::warn!("tailscale_state: encode: {e}"),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_not_desired() {
        let d = DesiredExitNode::default();
        assert!(!d.desired);
        assert!(d.exit_node_id.is_empty());
    }

    #[test]
    fn round_trip() {
        let s = DesiredExitNode {
            desired: true,
            exit_node_id: "nodeABC".into(),
            exit_node_ip: "100.64.1.2".into(),
            updated_unix: 123,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: DesiredExitNode = serde_json::from_str(&json).unwrap();
        assert!(back.desired);
        assert_eq!(back.exit_node_id, "nodeABC");
        assert_eq!(back.exit_node_ip, "100.64.1.2");
    }

    #[test]
    fn tolerates_missing_fields() {
        // An older/minimal file with only `desired` must still decode.
        let back: DesiredExitNode = serde_json::from_str(r#"{"desired":true}"#).unwrap();
        assert!(back.desired);
        assert!(back.exit_node_ip.is_empty());
    }
}
