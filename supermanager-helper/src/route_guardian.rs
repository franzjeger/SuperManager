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
//!
//! ## IPv6
//!
//! An IPv6 default route goes through a link-local address, and the kernel
//! takes any of those, on any network. Restoring a remembered one after a
//! move left a static route to a router that was not there. macOS never
//! clears a static route, and while it stood the kernel could not install
//! the router it had learned, so the guardian read the dead gateway back as
//! known-good. One Mac carried a router's address over six networks in two
//! days, with no IPv6 on any of them.
//!
//! So IPv6 is put back only through a router the kernel knows on the link
//! now (`ndp -r`), and a default through any other is replaced by one.

use anyhow::{anyhow, Result};
use std::process::Command;
use std::sync::{Mutex, OnceLock, PoisonError};
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

/// How many 500 ms ticks pass between checks that the IPv6 default goes
/// through a router on the link. Each costs an `ndp` run.
const IPV6_ROUTER_CHECK_TICKS: u32 = 20;

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
    let mut spawned = SPAWNED.lock().unwrap_or_else(PoisonError::into_inner);
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
        *m.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
    if let Some(m) = SNAPSHOT_V6.get() {
        *m.lock().unwrap_or_else(PoisonError::into_inner) = None;
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
        .and_then(|m| m.lock().unwrap_or_else(PoisonError::into_inner).clone());
    let v6 = SNAPSHOT_V6
        .get()
        .and_then(|m| m.lock().unwrap_or_else(PoisonError::into_inner).clone());

    let mut any_done = false;
    for (snap, af) in [(v4, Af::V4), (v6, Af::V6)] {
        let Some(snap) = snap.filter(|snap| interface_is_up(&snap.interface)) else {
            continue;
        };
        let Some(gateway) = restore_gateway(&snap, af) else {
            continue;
        };
        if restore_default(&gateway, af).is_ok() {
            tracing::warn!(
                af = %af.label(),
                gw = %gateway,
                iface = %snap.interface,
                "force_restore_now: default asserted"
            );
            any_done = true;
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
    let mut ticks = 0u32;
    loop {
        thread::sleep(Duration::from_millis(500));
        tick_one(Af::V4, &mut missing_v4);
        tick_one(Af::V6, &mut missing_v6);
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(IPV6_ROUTER_CHECK_TICKS) {
            repair_ipv6_default();
        }
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
            let mut guard = cell.lock().unwrap_or_else(PoisonError::into_inner);
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
            let snap = cell.lock().unwrap_or_else(PoisonError::into_inner).clone();
            let Some(snap) = snap else { return };
            if !interface_is_up(&snap.interface) {
                tracing::warn!(
                    af = %af.label(),
                    iface = %snap.interface,
                    "snapshot interface is down; not restoring"
                );
                return;
            }
            let Some(gateway) = restore_gateway(&snap, af) else {
                // No router on this link. The kernel installs the default
                // itself when one advertises.
                tracing::info!(
                    af = %af.label(),
                    iface = %snap.interface,
                    "default route is gone, and no router here to put it back through"
                );
                if let Ok(mut guard) = cell.lock() {
                    *guard = None;
                }
                *missing = 0;
                return;
            };
            match restore_default(&gateway, af) {
                Ok(()) => {
                    tracing::warn!(
                        af = %af.label(),
                        gw = %gateway,
                        iface = %snap.interface,
                        "default route was missing — restored"
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

/// The gateway to put a default route back through. For IPv4, the one in
/// use: the kernel refuses one that is not on this network. For IPv6, a
/// router the kernel knows on the link now: see the module docs. None
/// when there is none.
fn restore_gateway(snap: &RouteSnapshot, af: Af) -> Option<String> {
    match af {
        Af::V4 => Some(snap.gateway.clone()),
        Af::V6 => crate::route_table::ipv6_routers(&snap.interface)
            .into_iter()
            .next(),
    }
}

/// The router to replace an IPv6 default through `gateway` with: the
/// preferred of `routers` when `gateway` is not one of them. When the kernel
/// knows no router there is nothing better, and a router set by hand stands.
fn better_router<'a>(gateway: &str, routers: &'a [String]) -> Option<&'a str> {
    if routers.iter().any(|router| router == gateway) {
        return None;
    }
    routers.first().map(String::as_str)
}

/// Replace an IPv6 default route through a router that is not on the link.
/// Nothing else does: it is static, so macOS leaves it, and it keeps the
/// kernel from installing the router it learned.
fn repair_ipv6_default() {
    let Some(current) = read_default_route(Af::V6) else {
        return;
    };
    let routers = crate::route_table::ipv6_routers(&current.interface);
    let Some(router) = better_router(&current.gateway, &routers) else {
        return;
    };
    let args = [
        "-n",
        "delete",
        "-inet6",
        "default",
        current.gateway.as_str(),
    ];
    match crate::proc::bounded(Command::new("/sbin/route").args(args), crate::proc::MUTATE) {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::warn!(
                gw = %current.gateway,
                "could not remove an IPv6 default through a router not on the link: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                gw = %current.gateway,
                "could not remove an IPv6 default through a router not on the link: {e}"
            );
            return;
        }
    }
    match restore_default(router, Af::V6) {
        Ok(()) => tracing::warn!(
            old = %current.gateway,
            gw = %router,
            iface = %current.interface,
            "replaced an IPv6 default through a router not on the link"
        ),
        Err(e) => tracing::warn!(gw = %router, "could not set the IPv6 default: {e}"),
    }
}

/// Re-add the default route via `route -q add [-inet6] default <gw>`.
/// `-q` keeps stderr silent on the duplicate-add path.
fn restore_default(gateway: &str, af: Af) -> Result<()> {
    let args: Vec<String> = af.route_add_args(gateway);
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

    /// On 2026-11-05 the default on a Mac at home still went through a
    /// router from another network, with the home router known and unused.
    #[test]
    fn a_default_through_a_router_not_on_the_link_gets_a_better_one() {
        let dead = "fe80::683b:9ff:fe0f:ad64%en0";
        let home = "fe80::aa9c:6cff:fe8c:4bd%en0".to_owned();
        let other = "fe80::10d1:1e98:4933:5bf0%en0".to_owned();
        let routers = [home.clone(), other.clone()];

        assert_eq!(better_router(dead, &routers), Some(home.as_str()));
        // Any router the kernel knows will do, not only its first choice.
        assert_eq!(better_router(&other, &routers), None);
        // No router known, as with IPv6 set by hand: it stands.
        assert_eq!(better_router(dead, &[]), None);
    }

    /// Against this Mac's routing table and routers. Reads only:
    /// `cargo test -p supermanager-helper live_ipv6_default -- --ignored --nocapture`
    #[test]
    #[ignore = "reads the live routing table"]
    fn live_ipv6_default() {
        let current = read_default_route(Af::V6).expect("an IPv6 default");
        let routers = crate::route_table::ipv6_routers(&current.interface);
        println!("default: {} on {}", current.gateway, current.interface);
        println!("routers: {routers:?}");
        println!(
            "replace with: {:?}",
            better_router(&current.gateway, &routers)
        );
    }

    #[test]
    fn ipv4_is_put_back_through_the_gateway_in_use() {
        let snap = RouteSnapshot {
            gateway: "192.168.2.55".into(),
            interface: "en0".into(),
        };
        assert_eq!(
            restore_gateway(&snap, Af::V4).as_deref(),
            Some("192.168.2.55")
        );
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
