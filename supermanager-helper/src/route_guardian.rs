//! Background sentinel that snapshots both the IPv4 AND IPv6
//! default routes and restores them within ~1 second if they
//! disappear.
//!
//! ## Why this exists
//!
//! Open-source `tailscaled` on macOS, when its `EditPrefs` clears
//! the exit-node, calls into `wgengine/router/osrouter/router_userspace_bsd.go`
//! which `route delete`s its old `0.0.0.0/0` entry. On this host
//! that observably ALSO takes out the en0-bound default route —
//! either macOS's `route` is loose about the `-iface` match, or
//! tailscaled does additional cleanup we can't see from outside.
//! Either way the user lands on a routing table with no default
//! and is offline until WiFi-cycles or panic-resets.
//!
//! Tailscale.app sidesteps this with NetworkExtension. We can't
//! (no Developer Program enrollment yet). Cheapest practical fix:
//! a watchdog thread.
//!
//! ## How it works
//!
//! 1. On startup, snapshot the current `default` route's gateway
//!    + interface (e.g. `192.0.2.1` via `en0`).
//! 2. Every 500 ms, re-read the route table.
//!    - Default present → update snapshot (network may have changed
//!      legitimately, e.g. WiFi roam; we want the freshest known-good).
//!    - Default missing → wait one more poll (debounce against
//!      transient reconfigs), then restore via
//!      `route -q add default <gw>`.
//! 3. The 1 s worst-case bricking window is shorter than the 7-15 s
//!    bricks we were seeing before — and recovery is automatic.
//!
//! ## Knowing when NOT to fight
//!
//! When the user has a working exit-node, tailscaled installs
//! `0.0.0.0/1` + `128.0.0.0/1` via utun. Those `/1` routes
//! shadow the default in *practice* but the kernel still keeps
//! the `default` entry. So the guardian sees default = present
//! and updates its snapshot to the (still en0) gateway. No
//! conflict.
//!
//! Cases where the guardian could in theory fight legitimate
//! reconfigs (e.g. DHCP lease change between two networks): we
//! debounce one poll and only restore if our snapshot's interface
//! is still `UP`. If the interface dropped, we let DHCP own it.

use anyhow::{anyhow, Result};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

/// Shared mutable snapshots of the most-recent observation of the
/// default route — separate for v4 and v6. Mutex is fine here —
/// touched only from the guardian thread + the read API; never
/// on a hot path.
static SNAPSHOT_V4: OnceLock<Mutex<Option<RouteSnapshot>>> = OnceLock::new();
static SNAPSHOT_V6: OnceLock<Mutex<Option<RouteSnapshot>>> = OnceLock::new();
/// Track whether the guardian is already running so multiple
/// `spawn` calls collapse to a no-op.
static SPAWNED: Mutex<bool> = Mutex::new(false);

#[derive(Clone, Debug, PartialEq)]
struct RouteSnapshot {
    gateway: String,
    interface: String,
}

/// Address family for diagnostics + scoping route(8) flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Af {
    V4,
    V6,
}
impl Af {
    fn label(self) -> &'static str {
        match self {
            Af::V4 => "v4",
            Af::V6 => "v6",
        }
    }
    fn is_v6(self) -> bool {
        self == Af::V6
    }
    fn route_add_args(self, gw: &str) -> Vec<String> {
        match self {
            Af::V4 => vec!["-q".into(), "add".into(), "default".into(), gw.into()],
            Af::V6 => vec![
                "-q".into(),
                "add".into(),
                "-inet6".into(),
                "default".into(),
                gw.into(),
            ],
        }
    }
}

/// Idempotent: spawns the guardian thread if it isn't already
/// running. Safe to call from helper startup AND from a future
/// "restart guardian" RPC.
pub fn spawn_guardian() -> Result<()> {
    let mut spawned = SPAWNED.lock().unwrap();
    if *spawned {
        return Ok(());
    }
    *spawned = true;
    drop(spawned);

    SNAPSHOT_V4.get_or_init(|| Mutex::new(None));
    SNAPSHOT_V6.get_or_init(|| Mutex::new(None));
    remove_stray_loopback_default(Af::V4);
    remove_stray_loopback_default(Af::V6);

    thread::Builder::new()
        .name("route-guardian".into())
        .spawn(move || guardian_loop())
        .map_err(|e| anyhow!("could not spawn guardian thread: {e}"))?;

    tracing::info!("route guardian spawned (v4 + v6)");
    Ok(())
}

/// Clear both v4 and v6 snapshots.
///
/// Call this on system wake. Before sleep the guardian snapshotted the
/// gateway for whatever network was active (e.g. `192.168.1.1 via en0`).
/// After wake the machine may be on a completely different network
/// (different gateway, different subnet). If we don't clear the snapshot
/// the guardian sees "default missing, restore from snapshot" and re-adds
/// the *old* gateway — which is now unreachable. The next tick after the
/// new network comes up will snapshot the correct gateway; clearing the
/// stale one bridges that gap cleanly.
pub fn reset_snapshot() {
    if let Some(m) = SNAPSHOT_V4.get() {
        if let Ok(mut s) = m.lock() {
            *s = None;
        }
    }
    if let Some(m) = SNAPSHOT_V6.get() {
        if let Ok(mut s) = m.lock() {
            *s = None;
        }
    }
    tracing::info!("route guardian: snapshots cleared on system wake");
}

/// Out-of-band restore — called by the connectivity watchdog
/// when the regular 500ms polling hasn't caught up yet but
/// internet is already failing. Synchronous; runs the route-add
/// for both v4 and v6 right now and returns.
///
/// Returns `Err` if there's no snapshot to restore from
/// (probably the helper just started and hasn't seen a default
/// route yet).
pub fn force_restore_now() -> Result<()> {
    let v4 = SNAPSHOT_V4
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|s| s.clone());
    let v6 = SNAPSHOT_V6
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|s| s.clone());

    let mut any_done = false;
    if let Some(snap) = v4 {
        if interface_is_up(&snap.interface) {
            if restore_default(&snap, Af::V4).is_ok() {
                tracing::warn!(
                    af = %Af::V4.label(),
                    gw = %snap.gateway,
                    iface = %snap.interface,
                    "force_restore_now: default asserted"
                );
                any_done = true;
            }
        }
    }
    if let Some(snap) = v6 {
        if interface_is_up(&snap.interface) {
            if restore_default(&snap, Af::V6).is_ok() {
                tracing::warn!(
                    af = %Af::V6.label(),
                    gw = %snap.gateway,
                    iface = %snap.interface,
                    "force_restore_now: default asserted"
                );
                any_done = true;
            }
        }
    }
    if any_done {
        Ok(())
    } else {
        Err(anyhow!("no snapshots available"))
    }
}

fn guardian_loop() {
    let mut missing_v4 = 0u32;
    let mut missing_v6 = 0u32;
    loop {
        thread::sleep(Duration::from_millis(500));
        tick_one(Af::V4, &mut missing_v4);
        tick_one(Af::V6, &mut missing_v6);
    }
}

fn tick_one(af: Af, missing: &mut u32) {
    let observed = read_default_route(af);
    let cell = match af {
        Af::V4 => SNAPSHOT_V4.get(),
        Af::V6 => SNAPSHOT_V6.get(),
    };
    let Some(cell) = cell else { return };

    match observed {
        Some(snap) => {
            *missing = 0;
            if let Ok(mut guard) = cell.lock() {
                if guard.as_ref() != Some(&snap) {
                    tracing::info!(
                        af = %af.label(),
                        gw = %snap.gateway,
                        iface = %snap.interface,
                        "default-route snapshot updated"
                    );
                }
                *guard = Some(snap);
            }
        }
        None => {
            // `read_default_route` filters out utun-bound defaults.
            // Before treating the route as "missing", check whether a
            // VPN tunnel has legitimately replaced the default via a
            // utun interface (strongSwan full tunnel, WireGuard, etc.).
            // If so, the route is not missing — the VPN owns it.
            // Restoring the physical-interface default would fight the
            // tunnel: charon reinstalls 0.0.0.0/0 via utun, the guardian
            // removes it again, repeat every 500 ms. Symptom: 90-second
            // connectivity outage in the helper log with ~100 "restored
            // from snapshot" messages, followed by the VPN silently dying.
            if read_default_route_raw(af).map_or(false, |s| s.interface.starts_with("utun")) {
                // VPN tunnel owns the default route. Reset the miss
                // counter so we don't act on accumulated misses when
                // the tunnel eventually tears down.
                *missing = 0;
                return;
            }

            *missing += 1;
            // Debounce: act on second consecutive miss (1 s gap).
            if *missing < 2 {
                return;
            }
            let snap = cell.lock().ok().and_then(|s| s.clone());
            let Some(snap) = snap else { return };
            if !interface_is_up(&snap.interface) {
                tracing::warn!(
                    af = %af.label(),
                    iface = %snap.interface,
                    "snapshot interface is down; not restoring"
                );
                return;
            }
            match restore_default(&snap, af) {
                Ok(()) => {
                    tracing::warn!(
                        af = %af.label(),
                        gw = %snap.gateway,
                        iface = %snap.interface,
                        "default route was missing — restored from snapshot"
                    );
                    *missing = 0;
                }
                Err(e) => {
                    tracing::warn!(af = %af.label(), "restore failed: {e}");
                }
            }
        }
    }
}

/// The primary default route, if it is the user's own way out: not a
/// tunnel's (utun), not through loopback, and through a gateway it can be
/// put back by.
///
/// The entry itself, from the routing table: `route -n get default` is a
/// lookup, and for IPv6 a lookup of `::`, which the IPv6 leak block of a
/// full tunnel answers (`::/1` via `::1` on lo0). Taking that for the
/// default route put a default through loopback back once the tunnel was
/// gone.
fn read_default_route(af: Af) -> Option<RouteSnapshot> {
    snapshot_of(crate::route_table::primary_default(af.is_v6()))
}

fn snapshot_of(route: Option<crate::route_table::DefaultRoute>) -> Option<RouteSnapshot> {
    let route = route?;
    if route.interface.starts_with("utun")
        || route.interface.starts_with("lo")
        || route.gateway.starts_with("link#")
    {
        return None;
    }
    Some(RouteSnapshot {
        gateway: route.gateway,
        interface: route.interface,
    })
}

/// The primary default route, whoever's it is: `tick_one` uses it to see a
/// VPN's tunnel has taken the default route over. Never a snapshot, which
/// would put back a tunnel's route after the tunnel is gone.
fn read_default_route_raw(af: Af) -> Option<RouteSnapshot> {
    crate::route_table::primary_default(af.is_v6()).map(|route| RouteSnapshot {
        gateway: route.gateway,
        interface: route.interface,
    })
}

/// Remove a default route through loopback, which no network needs and
/// which sends everything of its family nowhere. The guardian put one back
/// after an IKEv2 full tunnel, while it read the default route by lookup
/// (see `read_default_route`); a helper since then clears it once, here.
fn remove_stray_loopback_default(af: Af) {
    let Some(route) = crate::route_table::primary_default(af.is_v6()) else {
        return;
    };
    if !route.is_stray_loopback() {
        return;
    }
    let mut args = vec!["-n", "delete"];
    if af.is_v6() {
        args.push("-inet6");
    }
    args.extend(["default", route.gateway.as_str()]);
    match crate::proc::bounded(Command::new("/sbin/route").args(&args), crate::proc::MUTATE) {
        Ok(out) if out.status.success() => tracing::warn!(
            af = %af.label(),
            gw = %route.gateway,
            iface = %route.interface,
            "removed a default route through loopback"
        ),
        Ok(out) => tracing::warn!(
            af = %af.label(),
            "could not remove the default route through loopback: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => tracing::warn!(
            af = %af.label(),
            "could not remove the default route through loopback: {e}"
        ),
    }
}

/// Re-add the default route via `route -q add [-inet6] default <gw>`.
/// `-q` keeps stderr silent on the duplicate-add path.
fn restore_default(snap: &RouteSnapshot, af: Af) -> Result<()> {
    let args: Vec<String> = af.route_add_args(&snap.gateway);
    let out = crate::proc::bounded(Command::new("/sbin/route").args(&args), crate::proc::MUTATE)?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("File exists") || stderr.contains("file exists") {
        return Ok(());
    }
    Err(anyhow!(
        "route add ({}) failed: {}",
        af.label(),
        stderr.trim()
    ))
}

/// Returns true if the given interface (e.g. `en0`) is `UP`.
/// Avoids restoring through an interface that lost its link.
fn interface_is_up(iface: &str) -> bool {
    let Ok(out) = crate::proc::bounded(
        Command::new("/sbin/ifconfig").arg(iface),
        crate::proc::PROBE,
    ) else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // First line carries flags=NNNN<UP,...>
    s.lines()
        .next()
        .map(|l| l.contains("<UP,") || l.contains(",UP,") || l.contains(",UP>"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_table::DefaultRoute;

    fn route(gateway: &str, interface: &str) -> Option<DefaultRoute> {
        Some(DefaultRoute {
            gateway: gateway.into(),
            interface: interface.into(),
            flags: "UGScg".into(),
        })
    }

    #[test]
    fn only_the_users_own_way_out_is_kept() {
        assert_eq!(
            snapshot_of(route("192.168.2.55", "en0")),
            Some(RouteSnapshot {
                gateway: "192.168.2.55".into(),
                interface: "en0".into(),
            })
        );
        assert_eq!(
            snapshot_of(route("fe80::1%en0", "en0")).map(|s| s.gateway),
            Some("fe80::1%en0".into())
        );
        // A tunnel's, one through loopback, and one with no gateway to put
        // it back by.
        assert_eq!(snapshot_of(route("link#23", "utun7")), None);
        assert_eq!(snapshot_of(route("::1", "lo0")), None);
        assert_eq!(snapshot_of(route("link#6", "en0")), None);
        assert_eq!(snapshot_of(None), None);
    }
}
