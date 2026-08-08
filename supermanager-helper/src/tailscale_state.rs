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
    /// True when the user asked for `auto:any` rather than naming a peer —
    /// "any exit node will do", with tailscaled choosing and free to re-choose.
    ///
    /// The distinction is load-bearing for the reconciler. `exit_node_id` /
    /// `exit_node_ip` below still record whichever peer tailscaled had settled
    /// on at install time, because that is useful when reading the file by
    /// hand — but for an auto selection they are an observation, not the
    /// intent, and the reconciler must not treat them as a pin. Re-asserting a
    /// pinned IP for a user who asked for `auto:any` would quietly convert
    /// their selection into a fixed one, and would strand self-heal the moment
    /// that particular peer went offline even with other exit nodes available.
    ///
    /// Defaults to false, so a file written before this field existed reads as
    /// a pinned selection — which is what those files recorded.
    #[serde(default)]
    pub auto: bool,
    /// tailscaled `ExitNodeID` (stable peer id), best-effort. Empty if unknown.
    /// For `auto` selections this is the peer observed at install time, not a
    /// commitment — see `auto`.
    #[serde(default)]
    pub exit_node_id: String,
    /// The exit node's tailscale IP (100.x), best-effort. Empty if unknown.
    /// Same caveat as `exit_node_id` for `auto` selections.
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

/// Record that the user wants a specific exit node `id`/`ip` (routes were just
/// installed). `id`/`ip` may be empty when unknown — the reconciler falls back
/// to tailscaled's live pref in that case.
pub fn set_desired(id: &str, ip: &str) {
    write(&DesiredExitNode {
        desired: true,
        auto: false,
        exit_node_id: id.to_string(),
        exit_node_ip: ip.to_string(),
        updated_unix: now_unix(),
    });
}

/// Record that the user wants `auto:any` — tailscaled picks the exit node.
///
/// `observed_id`/`observed_ip` are whichever peer tailscaled had settled on
/// when the routes went up. They are recorded for debuggability only; the
/// reconciler re-asserts `auto:any` rather than either of them. See
/// [`DesiredExitNode::auto`].
pub fn set_desired_auto(observed_id: &str, observed_ip: &str) {
    write(&DesiredExitNode {
        desired: true,
        auto: true,
        exit_node_id: observed_id.to_string(),
        exit_node_ip: observed_ip.to_string(),
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
            auto: false,
            exit_node_id: "nodeABC".into(),
            exit_node_ip: "100.64.1.2".into(),
            updated_unix: 123,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: DesiredExitNode = serde_json::from_str(&json).unwrap();
        assert!(back.desired);
        assert!(!back.auto);
        assert_eq!(back.exit_node_id, "nodeABC");
        assert_eq!(back.exit_node_ip, "100.64.1.2");
    }

    #[test]
    fn auto_round_trips_and_keeps_the_observed_peer() {
        // The observed peer is recorded for debuggability, but `auto` is what
        // the reconciler branches on — it must survive the round trip, or a
        // helper restart turns an auto selection back into a pin.
        let s = DesiredExitNode {
            desired: true,
            auto: true,
            exit_node_id: "nodeABC".into(),
            exit_node_ip: "100.64.1.2".into(),
            updated_unix: 123,
        };
        let back: DesiredExitNode =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(back.auto, "auto must survive serialisation");
        assert_eq!(back.exit_node_id, "nodeABC");
    }

    #[test]
    fn a_file_written_before_auto_existed_reads_as_pinned() {
        // Forward-compat guard. Files on disk from the previous helper have no
        // `auto` key, and they recorded pinned selections. Defaulting to true
        // would silently convert every one of them to auto:any on upgrade.
        let back: DesiredExitNode = serde_json::from_str(
            r#"{"desired":true,"exit_node_id":"nodeABC","exit_node_ip":"100.64.1.2"}"#,
        )
        .unwrap();
        assert!(back.desired);
        assert!(!back.auto, "a legacy file must not be read as auto:any");
        assert_eq!(back.exit_node_id, "nodeABC");
    }

    #[test]
    fn setters_disagree_on_auto() {
        // The two setters exist precisely to record this one bit differently;
        // if they ever converge, the reconciler loses the distinction.
        let pinned = DesiredExitNode {
            desired: true,
            auto: false,
            ..Default::default()
        };
        let auto = DesiredExitNode {
            desired: true,
            auto: true,
            ..Default::default()
        };
        assert_ne!(pinned.auto, auto.auto);
    }

    #[test]
    fn tolerates_missing_fields() {
        // An older/minimal file with only `desired` must still decode.
        let back: DesiredExitNode = serde_json::from_str(r#"{"desired":true}"#).unwrap();
        assert!(back.desired);
        assert!(back.exit_node_ip.is_empty());
    }
}
