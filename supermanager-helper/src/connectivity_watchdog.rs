//! Connectivity dead-man switch.
//!
//! Probes the actual internet (TCP-connect to 1.1.1.1:443) every
//! 2 seconds. On consecutive failures, escalates recovery:
//!
//! - **1 miss (2s)**: noted, no action — could be transient.
//! - **2 misses (4s)**: trigger `route_guardian::force_restore()`
//!   in case tailscaled out-raced our 500ms poll.
//! - **3 misses (6s)**: fail-open `tailscale::panic_reset`
//!   (clear_pref=false) — removes the exit-node split routes so
//!   egress drops to the local uplink, DHCP-renews, but KEEPS the
//!   exit-node pref + persisted intent so the reconciler can
//!   re-establish it. Always recoverable; only acts on tailscale
//!   state. **Suppressed when an exit node is desired AND the
//!   local uplink itself is down** (sleep/roam/hotspot blip) —
//!   that is the reconciler's to recover, not ours to tear down.
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
//! between WiFi APs, or DHCP is mid-renewal? When NO exit node is
//! active the watchdog still fires panic_reset, which is
//! acceptable because:
//!
//! 1. `panic_reset` (fail-open) only touches tailscale state —
//!    removes split-default routes (no-op if not installed) and
//!    DHCP-renews (which is what the user wants if they're between
//!    APs anyway); it keeps the exit-node pref + intent.
//! 2. The user does not lose data — TCP connections are
//!    already dead by then.
//! 3. The alternative (do nothing) leaves the user offline
//!    indefinitely, which we have empirically learned is
//!    worse.
//!
//! When an exit node IS active the calculus flips: a transient
//! local-uplink outage must NOT tear the exit node down, or every
//! sleep/blip rips a healthy node and the user has to reconnect
//! (the reported "exit node bugs on any idle"). So the escalation
//! is gated on `tailscale::local_uplink_up()` (carrier + IPv4 link
//! state, NOT an ICMP ping that a filtering gateway would fail): a
//! DOWN uplink means "wait" — tailscale and the reconciler recover
//! when the link returns; an UP uplink with no egress past a
//! sustained window (`EXIT_DEAD_PEER_MISSES`) means the exit peer
//! is the dead part, so we fail open to the local uplink.

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

/// When an exit node is active and the physical uplink is UP, this many
/// consecutive probe misses before we conclude the exit PEER is dead and fail
/// open. The probe budget is ~8s when an exit node is desired, plus a 2s sleep,
/// so each miss is ~10s of real outage — 6 misses ≈ 60s. Long enough to ride
/// out an upstream hotspot blip (WiFi association stays up, internet drops for a
/// few seconds) without flapping the exit node; short enough that a genuinely
/// dead peer recovers to the local uplink promptly. A DOWN uplink is never torn
/// down regardless of this count.
const EXIT_DEAD_PEER_MISSES: u32 = 6;

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
                // Sustained outage. With NO exit node active this is the simple
                // unconditional fail-open. With an exit node active the handling
                // splits on LINK STATE, because tearing the node down on a
                // transient local outage is exactly the flap the user reported
                // ("bugs on any idle"):
                //
                //   * uplink DOWN → our own link blipped (sleep/roam/WiFi drop).
                //     DO NOTHING. tailscale recovers when it returns; the
                //     reconciler reinstalls routes if the utun renumbered. A
                //     panic_reset here rips a perfectly healthy exit node on
                //     every sleep.
                //   * uplink UP but still no egress after a sustained window
                //     (>= EXIT_DEAD_PEER_MISSES) → the exit PEER is genuinely
                //     dead while our link is fine → fail open. Below that window
                //     we wait it out (an upstream hotspot blip with the WiFi
                //     association still up recovers on its own without a flap).
                //
                // Link state (carrier + IPv4), NOT an ICMP ping: a ping-filtering
                // gateway must never wedge a dead peer offline forever.
                let exit_desired = crate::tailscale_state::load().desired;
                if exit_desired {
                    if !crate::tailscale::local_uplink_up() {
                        tracing::warn!(
                            "{}s no internet, physical uplink down — link blip, NOT tearing down exit node",
                            consecutive_failures * 2
                        );
                    } else if consecutive_failures >= EXIT_DEAD_PEER_MISSES {
                        tracing::error!(
                            "{}s no internet with uplink UP — exit peer appears dead, failing open (panic_reset)",
                            consecutive_failures * 2
                        );
                        match crate::tailscale::panic_reset(crate::tailscale::PanicResetArgs { clear_pref: false }) {
                            Ok(_) => {
                                tracing::info!("panic_reset complete (exit peer dead, failed open to local uplink)");
                                already_panic_reset = true;
                            }
                            Err(e) => tracing::error!("panic_reset failed: {e}"),
                        }
                    } else {
                        tracing::warn!(
                            "{}s no internet, uplink up — riding out possible upstream blip before failing open",
                            consecutive_failures * 2
                        );
                    }
                } else {
                    // No exit node — fail open immediately. Removes split-default
                    // routes (no-op if none) and DHCP-renews; clear_pref=false
                    // keeps any intent. Fires once per outage.
                    tracing::error!("6s no internet — escalating to panic_reset (fail-open)");
                    match crate::tailscale::panic_reset(crate::tailscale::PanicResetArgs { clear_pref: false }) {
                        Ok(_) => {
                            tracing::info!("panic_reset complete");
                            already_panic_reset = true;
                        }
                        Err(e) => tracing::error!("panic_reset failed: {e}"),
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

/// TCP-connect to 1.1.1.1:443. Pure connectivity check — no DNS, no specific
/// HTTPS response needed. If the SYN/ACK lands within the budget, we have
/// internet.
///
/// The budget adapts to whether a tailscale exit node is active: when it is,
/// the probe routes THROUGH the exit peer, and a DERP-relayed peer adds 3-6s
/// of latency — a 1s budget false-negatives and the watchdog would tear down a
/// perfectly healthy node (the user's reported flap). Use a generous 8s budget
/// then (matching test_exit_reachability), and the snappy 1s otherwise. A
/// genuinely dead peer still fails at 8s and escalates, so this never hides a
/// real outage.
fn probe_internet() -> bool {
    let budget = if crate::tailscale_state::load().desired { "8" } else { "1" };
    let out = Command::new("/usr/bin/nc")
        .args(["-z", "-G", budget, "-w", budget, "1.1.1.1", "443"])
        .output();
    match out {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}
