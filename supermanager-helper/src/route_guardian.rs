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
/// `spawn` calls collapse to a no-op (idempotent at helper
/// startup or after `deploy_self` respawns).
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
        match self { Af::V4 => "v4", Af::V6 => "v6" }
    }
    fn route_get_args(self) -> &'static [&'static str] {
        match self {
            Af::V4 => &["-n", "get", "default"],
            Af::V6 => &["-n", "get", "-inet6", "default"],
        }
    }
    fn route_add_args(self, gw: &str) -> Vec<String> {
        match self {
            Af::V4 => vec![
                "-q".into(), "add".into(), "default".into(), gw.into(),
            ],
            Af::V6 => vec![
                "-q".into(), "add".into(), "-inet6".into(),
                "default".into(), gw.into(),
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

    thread::Builder::new()
        .name("route-guardian".into())
        .spawn(move || guardian_loop())
        .map_err(|e| anyhow!("could not spawn guardian thread: {e}"))?;

    tracing::info!("route guardian spawned (v4 + v6)");
    Ok(())
}

/// Read the most recent v4 snapshot — useful for debug RPC.
pub fn current_snapshot() -> Option<(String, String)> {
    SNAPSHOT_V4
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|s| s.clone())
        .map(|s| (s.gateway, s.interface))
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

/// Parse `/sbin/route -n get [-inet6] default` for gateway + iface.
///
/// Path note: macOS keeps `route(8)` only at `/sbin/route`.
/// `/usr/sbin/route` doesn't exist; an early version of this
/// helper called the wrong path, ENOENT was swallowed, the
/// guardian became a no-op, and bricks went unrecovered. Always
/// hard-code `/sbin/route`.
///
/// Filtering: we want only the user-facing default route (en0
/// or similar physical iface), not utun-bound default routes
/// that tailscale or other VPNs install. `route -n get default`
/// without filters returns the highest-priority default — which
/// might be a utun. We post-filter to require non-utun iface.
fn read_default_route(af: Af) -> Option<RouteSnapshot> {
    let out = Command::new("/sbin/route")
        .args(af.route_get_args())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut gateway = None;
    let mut iface = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("gateway:") {
            gateway = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("interface:") {
            iface = Some(rest.trim().to_string());
        }
    }
    let snap = RouteSnapshot {
        gateway: gateway?,
        interface: iface?,
    };
    // Skip utun-bound defaults — those are tailscale's own
    // routes and aren't what we want to snapshot/restore as
    // "the user's gateway."
    if snap.interface.starts_with("utun") {
        return None;
    }
    Some(snap)
}

/// Re-add the default route via `route -q add [-inet6] default <gw>`.
/// `-q` keeps stderr silent on the duplicate-add path.
fn restore_default(snap: &RouteSnapshot, af: Af) -> Result<()> {
    let args: Vec<String> = af.route_add_args(&snap.gateway);
    let out = Command::new("/sbin/route")
        .args(&args)
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("File exists") || stderr.contains("file exists") {
        return Ok(());
    }
    Err(anyhow!("route add ({}) failed: {}", af.label(), stderr.trim()))
}

/// **TEST ONLY** — deletes the default route to simulate
/// tailscaled's prefs-reconfig strip. Guardian should detect +
/// restore within ~1 second. Used for isolation testing the
/// guardian without involving tailscaled. NOT exposed in
/// production paths — only an RPC handler we run from the
/// command line during verification.
pub fn debug_strip_default_route() -> Result<()> {
    let out = Command::new("/sbin/route")
        .args(["-q", "delete", "default"])
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "delete failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Returns true if the given interface (e.g. `en0`) is `UP`.
/// Avoids restoring through an interface that lost its link.
fn interface_is_up(iface: &str) -> bool {
    let Ok(out) = Command::new("/sbin/ifconfig").arg(iface).output() else {
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
