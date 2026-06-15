//! Connectivity dead-man switch.
//!
//! Probes the actual internet (TCP-connect to 1.1.1.1:443) every
//! 2 seconds. On consecutive failures, escalates recovery:
//!
//! - **1 miss (2s)**: noted, no action — could be transient.
//! - **2 misses (4s)**: trigger `route_guardian::force_restore()`
//!   in case tailscaled out-raced our 500ms poll.
//! - **3 misses (6s)**: full `tailscale::panic_reset` —
//!   clears exit-node pref, removes split-default routes,
//!   DHCP-renews. Always recoverable; only acts on tailscale
//!   state.
//!
//! ## Why not just rely on the route guardian?
//!
//! The guardian fixes routes but not their consequences:
//! tailscaled can rip the default 2-3 times during a single
//! prefs reconfig, each rip leaves DNS state stale and TCP
//! connections dead. Even after the route is back, "internet"
//! isn't usable for several seconds. The watchdog cuts that
//! ambiguity short — if internet is unreachable for 6 s
//! period, regardless of cause, we yank tailscale's
//! exit-node-related state out and let everything reconverge.
//!
//! ## False-positive concerns
//!
//! What if the user's ISP is genuinely out, or they're roaming
//! between WiFi APs, or DHCP is mid-renewal? The watchdog will
//! still fire panic_reset. That's acceptable because:
//!
//! 1. `panic_reset` only touches tailscale state — clears the
//!    exit-node pref (a no-op if none was set), removes split-
//!    default routes (no-op if not installed), and DHCP-renews
//!    (which is what the user wants if they're between APs
//!    anyway).
//! 2. The user does not lose data — TCP connections are
//!    already dead by then.
//! 3. The alternative (do nothing) leaves the user offline
//!    indefinitely, which we have empirically learned is
//!    worse.

use anyhow::Result;
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

static SPAWNED: Mutex<bool> = Mutex::new(false);

/// Suspend-until timestamp. While `Instant::now() < *PAUSE_UNTIL`,
/// the watchdog keeps probing for visibility but does NOT
/// escalate to force_restore or panic_reset. Used by AppState
/// to grant exit-node-set / clear transitions a quiet window
/// to settle without our defense kicking in mid-reconfig.
static PAUSE_UNTIL: Mutex<Option<Instant>> = Mutex::new(None);

/// Pause watchdog escalation for `secs` seconds. Probes still
/// run + log so the user can see what's happening, but no
/// force_restore or panic_reset fires until pause expires.
pub fn pause_for(secs: u64) {
    let new_until = Instant::now() + Duration::from_secs(secs);
    let mut g = PAUSE_UNTIL.lock().unwrap();
    // Extend rather than shorten — multiple overlapping pauses
    // should result in the latest deadline winning.
    *g = Some(match *g {
        Some(prev) if prev > new_until => prev,
        _ => new_until,
    });
    tracing::info!(seconds = secs, "watchdog escalation paused");
}

/// Lift any active pause immediately. Called when user
/// explicitly cancels an operation that armed a pause.
pub fn resume_now() {
    *PAUSE_UNTIL.lock().unwrap() = None;
    tracing::info!("watchdog escalation resumed");
}

fn is_paused() -> bool {
    let g = PAUSE_UNTIL.lock().unwrap();
    matches!(*g, Some(t) if t > Instant::now())
}

/// Idempotent: spawns the watchdog thread if not running.
pub fn spawn_watchdog() -> Result<()> {
    let mut spawned = SPAWNED.lock().unwrap();
    if *spawned {
        return Ok(());
    }
    *spawned = true;
    drop(spawned);

    thread::Builder::new()
        .name("connectivity-watchdog".into())
        .spawn(watchdog_loop)
        .map_err(|e| anyhow::anyhow!("could not spawn watchdog: {e}"))?;

    tracing::info!("connectivity watchdog spawned");
    Ok(())
}

fn watchdog_loop() {
    let mut consecutive_failures: u32 = 0;
    // Track whether we've already escalated to panic_reset for
    // this outage — without this we'd fire panic_reset every
    // poll while internet is still out (e.g., genuine ISP
    // outage). Reset to false the first time a probe succeeds.
    let mut already_panic_reset = false;

    loop {
        thread::sleep(Duration::from_secs(2));

        if probe_internet() {
            if consecutive_failures > 0 {
                tracing::info!(
                    "connectivity restored after {} miss(es)",
                    consecutive_failures
                );
            }
            consecutive_failures = 0;
            already_panic_reset = false;
            continue;
        }

        consecutive_failures += 1;
        let paused = is_paused();
        tracing::warn!(
            paused = paused,
            "connectivity probe miss #{} (~{}s outage)",
            consecutive_failures,
            consecutive_failures * 2
        );

        // SUSPEND escalation when AppState has armed a pause —
        // this gives exit-node setup transitions ~30s to
        // settle without our protection panic-resetting them.
        // We still LOG the misses for visibility.
        if paused {
            continue;
        }

        match consecutive_failures {
            1 => {
                // 2s. Could be a single packet loss. Wait one more
                // cycle before doing anything.
            }
            2 => {
                // 4s. Trigger an immediate route restore in case
                // tailscaled out-paced our route guardian.
                tracing::warn!("4s no internet — forcing route restore");
                if let Err(e) = crate::route_guardian::force_restore_now() {
                    tracing::warn!("force_restore_now failed: {e}");
                }
            }
            _ if consecutive_failures >= 3 && !already_panic_reset => {
                // 6s+. FAIL OPEN: remove the exit-node split routes so egress
                // falls back to the local uplink, and DHCP-renew — but
                // clear_pref=false means we KEEP the tailscaled exit-node pref
                // and the persisted desired-state, so the reconciler can
                // re-establish the exit node once the network returns. Only the
                // user-initiated "Panic reset" menu hard-clears intent.
                // Fires once per outage.
                tracing::error!("6s no internet — escalating to panic_reset (fail-open)");
                match crate::tailscale::panic_reset(crate::tailscale::PanicResetArgs { clear_pref: false }) {
                    Ok(_) => {
                        tracing::info!("panic_reset complete");
                        already_panic_reset = true;
                    }
                    Err(e) => {
                        tracing::error!("panic_reset failed: {e}");
                    }
                }
            }
            _ => {
                // Probe still failing past panic_reset — likely
                // genuine network outage. Don't spam the log on
                // every poll.
                if consecutive_failures.is_multiple_of(15) {
                    tracing::warn!(
                        "{}s sustained outage; panic_reset already fired, waiting for network to come back",
                        consecutive_failures * 2
                    );
                }
            }
        }
    }
}

/// TCP-connect to 1.1.1.1:443 with a 1-second timeout. Pure
/// connectivity check — doesn't depend on DNS, doesn't rely on
/// a specific HTTPS response. If the SYN/ACK lands within 1s,
/// we have internet.
fn probe_internet() -> bool {
    let out = Command::new("/usr/bin/nc")
        .args(["-z", "-G", "1", "-w", "1", "1.1.1.1", "443"])
        .output();
    match out {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}
