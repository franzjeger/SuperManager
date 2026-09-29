//! What the helper did on its own, for the app to tell the user about.
//!
//! The helper acts without being asked: auto-reconnect replays a tunnel that
//! went down, and the connectivity watchdog fails egress open after a
//! sustained outage. The app used to learn about these by reading
//! `/var/log/supermanager-helper.log` for known phrases. For reconnects that
//! never worked: tracing colours each field name, so `profile_id=` never
//! occurs as one run of text. And a log line is prose; rewording it breaks
//! whatever reads it, silently.
//!
//! So each such action is recorded here as data, numbered in order, and the
//! app asks for everything after the last number it has seen
//! (`events_since`). The list lives in memory and keeps the newest
//! `CAPACITY` events, which covers a GUI that was closed for a while. A
//! restarted helper starts a new list under a new `boot` id, and a position
//! from an older boot means nothing to it.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auto_reconnect::WatchMode;

/// Events kept for a GUI that is not asking. Each one is a reconnect, a run
/// of failed reconnects or a fail-open, so this is hours of history.
const CAPACITY: usize = 128;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// Auto-reconnect brought a watched profile back. `mode` is why it was
    /// watched: `always_on` resurrects a tunnel that went down, `route_guard`
    /// only puts back the routes of a manually connected full tunnel.
    VpnReconnected {
        profile_id: String,
        backend: String,
        mode: WatchMode,
    },
    /// An Always-on profile has failed to reconnect `attempts` times in a
    /// row. Recorded once per run of failures, as it reaches that count.
    VpnReconnectFailing {
        profile_id: String,
        backend: String,
        attempts: u32,
        error: String,
    },
    /// The connectivity watchdog ran `panic_reset` after a sustained outage.
    /// `exit_node` is whether a Tailscale exit node was wanted: then the
    /// reset moved egress off a dead exit peer onto the local network.
    ConnectivityFailedOpen { exit_node: bool },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Recorded {
    pub seq: u64,
    /// When it happened, in milliseconds since the Unix epoch.
    pub at_ms: u64,
    #[serde(flatten)]
    pub event: Event,
}

/// The answer to `events_since`.
#[derive(Debug, PartialEq, Serialize)]
pub struct Batch {
    pub boot: String,
    /// Number of the newest event this boot has recorded, 0 before the
    /// first. The caller's next position, even when `events` is empty.
    pub latest: u64,
    pub events: Vec<Recorded>,
}

struct Journal {
    boot: String,
    latest: u64,
    events: VecDeque<Recorded>,
    capacity: usize,
}

impl Journal {
    fn new(boot: String, capacity: usize) -> Self {
        Self {
            boot,
            latest: 0,
            events: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn record(&mut self, event: Event, at_ms: u64) {
        self.latest += 1;
        if self.events.len() == self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(Recorded {
            seq: self.latest,
            at_ms,
            event,
        });
    }

    fn since(&self, boot: Option<&str>, after: u64) -> Batch {
        let after = if boot == Some(self.boot.as_str()) {
            after
        } else {
            0
        };
        Batch {
            boot: self.boot.clone(),
            latest: self.latest,
            events: self
                .events
                .iter()
                .filter(|e| e.seq > after)
                .cloned()
                .collect(),
        }
    }
}

static JOURNAL: LazyLock<Mutex<Journal>> =
    LazyLock::new(|| Mutex::new(Journal::new(uuid::Uuid::new_v4().to_string(), CAPACITY)));

/// Record `event` as happening now.
///
/// Called from the connectivity watchdog's own thread, which also carries the
/// no-brick route reaper, so a poisoned lock is recovered rather than
/// propagated: losing that thread over a notification would be absurd.
pub fn record(event: Event) {
    let at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    JOURNAL
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .record(event, at_ms);
}

/// Everything kept after position `after` of boot `boot`. A caller with no
/// position, or one from an earlier boot, gets everything kept.
#[must_use]
pub fn since(boot: Option<&str>, after: u64) -> Batch {
    JOURNAL
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .since(boot, after)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed_open(exit_node: bool) -> Event {
        Event::ConnectivityFailedOpen { exit_node }
    }

    #[test]
    fn hands_out_only_what_came_after_the_callers_position() {
        let mut j = Journal::new("boot-a".into(), 8);
        for n in 0..3 {
            j.record(failed_open(false), 1000 + n);
        }

        let batch = j.since(Some("boot-a"), 1);

        assert_eq!(batch.latest, 3);
        assert_eq!(
            batch
                .events
                .iter()
                .map(|e| (e.seq, e.at_ms))
                .collect::<Vec<_>>(),
            [(2, 1001), (3, 1002)]
        );
        assert!(j.since(Some("boot-a"), 3).events.is_empty());
    }

    #[test]
    fn a_position_from_another_boot_or_none_gets_everything_kept() {
        let mut j = Journal::new("boot-b".into(), 8);
        j.record(failed_open(false), 1);
        j.record(failed_open(true), 2);

        // A restarted helper numbers from 1 again; "after 2" from the old
        // boot would hide this boot's first two events.
        assert_eq!(j.since(Some("boot-a"), 2).events.len(), 2);
        assert_eq!(j.since(None, 2).events.len(), 2);
    }

    #[test]
    fn keeps_the_newest_events_and_keeps_counting() {
        let mut j = Journal::new("boot-a".into(), 2);
        for n in 0..3 {
            j.record(failed_open(false), n);
        }

        let batch = j.since(None, 0);

        assert_eq!(batch.latest, 3);
        assert_eq!(
            batch.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [2, 3]
        );
    }

    #[test]
    fn nothing_recorded_yet_still_names_the_boot() {
        let j = Journal::new("boot-a".into(), 8);
        assert_eq!(
            j.since(None, 0),
            Batch {
                boot: "boot-a".into(),
                latest: 0,
                events: vec![],
            }
        );
    }

    /// The app parses exactly this; `HelperEventTests` in the Mac tests holds
    /// the same JSON. Change one, change both.
    #[test]
    fn wire_form_is_what_the_app_reads() {
        let mut j = Journal::new("0c6e6d4a".into(), 8);
        j.record(
            Event::VpnReconnected {
                profile_id: "p1".into(),
                backend: "ikev2".into(),
                mode: WatchMode::AlwaysOn,
            },
            1_790_000_000_000,
        );
        j.record(
            Event::VpnReconnected {
                profile_id: "p2".into(),
                backend: "wireguard".into(),
                mode: WatchMode::RouteGuard,
            },
            1_790_000_001_000,
        );
        j.record(
            Event::VpnReconnectFailing {
                profile_id: "p1".into(),
                backend: "ikev2".into(),
                attempts: 3,
                error: "charon refused".into(),
            },
            1_790_000_002_000,
        );
        j.record(failed_open(true), 1_790_000_003_000);

        assert_eq!(
            serde_json::to_value(j.since(None, 0)).unwrap(),
            serde_json::json!({
                "boot": "0c6e6d4a",
                "latest": 4,
                "events": [
                    {"seq": 1, "at_ms": 1_790_000_000_000_u64, "kind": "vpn_reconnected",
                     "profile_id": "p1", "backend": "ikev2", "mode": "always_on"},
                    {"seq": 2, "at_ms": 1_790_000_001_000_u64, "kind": "vpn_reconnected",
                     "profile_id": "p2", "backend": "wireguard", "mode": "route_guard"},
                    {"seq": 3, "at_ms": 1_790_000_002_000_u64, "kind": "vpn_reconnect_failing",
                     "profile_id": "p1", "backend": "ikev2", "attempts": 3,
                     "error": "charon refused"},
                    {"seq": 4, "at_ms": 1_790_000_003_000_u64, "kind": "connectivity_failed_open",
                     "exit_node": true},
                ],
            })
        );
    }
}
