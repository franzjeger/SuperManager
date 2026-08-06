//! VPN DNS state management — macOS best-practice teardown.
//!
//! ## Why two stores?
//!
//! macOS System Configuration has two layers:
//!
//!   Setup:/Network/Service/<uuid>/DNS  — persistent, survives reboot.
//!                                        Written by `networksetup`.
//!   State:/Network/Service/<uuid>/DNS  — ephemeral, cleared on reboot.
//!                                        Written by scutil / VPN daemons.
//!
//! `networksetup -setdnsservers` writes to **Setup** — the user's saved
//! preference. If a VPN sets DNS there and the cleanup step is skipped
//! (fallback disconnect path, crash, SIGKILL), those servers stay set
//! permanently and survive VPN disconnection and reboots.
//!
//! ## Best practice
//!
//! `clear_vpn_dns()` uses a belt-and-braces approach:
//!   1. `networksetup -setdnsservers <service> Empty` — handles any DNS
//!      set via the Setup store (wg-quick, openvpn --up scripts, etc.)
//!   2. `scutil remove State:/Network/Service/<uuid>/DNS` — handles any
//!      DNS set via the State store (our own future scutil writes,
//!      tailscaled, configd overrides)
//!   3. Flush mDNSResponder so apps pick up the reverted config instantly.
//!
//! The function is deliberately infallible — all errors are logged but
//! never propagated, because DNS cleanup must always run to completion
//! even if individual steps fail. Callers treat it as fire-and-forget.
//!
//! ## Boot-time survival
//!
//! The companion LaunchDaemon (`no.sybr.supermanager.vpn-dns-cleanup`)
//! runs `clear_vpn_dns` equivalent shell commands at boot, so a
//! machine that was hard-powered-off mid-VPN session comes up with
//! clean DNS rather than pointing at a VPN gateway that no longer exists.

use std::io::Write as _;
use std::process::Command;

/// The one State-store key SuperManager ever writes DNS to.
///
/// Scoped to our own service name on purpose: the physical interface's
/// `State:/Network/Service/<uuid>/DNS` is where DHCP puts the router's
/// resolvers, and removing that is what broke name resolution after
/// every teardown.
const SUPERMGR_DNS_KEY: &str = "State:/Network/Service/com.sybr.supermanager.vpn/DNS";

/// Remove any VPN-pushed DNS from both the Setup and State stores.
///
/// Safe to call on every disconnect regardless of backend or whether
/// DNS was actually set — all operations are idempotent and best-effort.
pub fn clear_vpn_dns() {
    tracing::info!("clear_vpn_dns: starting cleanup");

    // ── Step 1: Setup store ──────────────────────────────────────────
    //
    // Deliberately does NOTHING now.
    //
    // This used to run `networksetup -setdnsservers <svc> Empty` across
    // Wi-Fi, Ethernet and USB LAN, to catch DNS a VPN had written to the
    // persistent Setup store. Nothing in SuperManager writes there any
    // more: the WireGuard renderer stopped emitting a `DNS =` line (it
    // hijacked the system resolver), and the only remaining writer is
    // the user-initiated `tailscale_set_dns_servers` RPC.
    //
    // So the blanket clear had exactly one effect left: wiping the
    // operator's own saved DNS on every disconnect, sleep and wake —
    // including the static resolver they had set to work around the
    // State-store bug fixed below, and any DNS set through the app's own
    // Tailscale settings.
    //
    // Trade-off, stated plainly: if a backend is ever taught to push
    // Setup DNS again, it must restore it itself. Teardown will not
    // guess on its behalf, because it cannot tell VPN DNS from the
    // user's.

    // ── Step 2: State store via scutil ───────────────────────────────
    //
    // ONLY our own key. The previous version removed
    // `State:/Network/Service/<primary-uuid>/DNS`, believing configd
    // would then "revert to whatever DHCP pushed". It does not — that
    // entry IS what DHCP pushed. Removing it left the Mac with no
    // resolver at all after every disconnect, sleep and wake, until the
    // lease renewed. On the reporting machine it produced 15 651
    // "DNS probe miss" warnings against the router at 10.10.110.1, and
    // the only way to browse was to set a static resolver by hand.
    //
    // A VPN that writes State DNS writes it under its OWN service key,
    // never the physical interface's, so scoping the removal to ours
    // loses nothing. `SUPERMGR_DNS_KEY` is also what the updown script
    // writes to when a gateway pushes INTERNAL_IP4_DNS.
    let script = format!("open\nremove {SUPERMGR_DNS_KEY}\nquit\n");
    match std::process::Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(script.as_bytes());
            }
            let _ = child.wait();
            tracing::info!("clear_vpn_dns: removed {SUPERMGR_DNS_KEY} (if present)");
        }
        Err(e) => tracing::warn!("clear_vpn_dns: spawn scutil: {e}"),
    }

    // ── Step 3: flush resolver caches ────────────────────────────────
    // Without this, apps keep using the old resolver for up to 60 s.
    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").output();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .output();

    tracing::info!("clear_vpn_dns: done");
}

/// Find the primary network service UUID from the Setup store.
///
/// Queries `scutil` for `Setup:/Network/Service/*/DNS` keys and
/// returns the first UUID (36-char hyphenated form). Used by
/// `clear_vpn_dns` to target the correct State-store key.
pub(crate) fn find_service_uuid() -> Option<String> {
    let mut child = std::process::Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        let _ = stdin.write_all(b"list Setup:/Network/Service/[^/]+/DNS\nquit\n");
    }
    let out = child.wait_with_output().ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        // Lines look like:
        //   subKey [0] = Setup:/Network/Service/67C7F8A5-...-727B82/DNS
        if let Some(idx) = line.find("Setup:/Network/Service/") {
            let rest = &line[idx + "Setup:/Network/Service/".len()..];
            if let Some(end) = rest.find('/') {
                let uuid = &rest[..end];
                if uuid.len() == 36 {
                    return Some(uuid.to_string());
                }
            }
        }
    }
    None
}

/// Detect the user-facing name of the primary active network service.
///
/// Returns `Some("Wi-Fi")` on most Mac laptops; `None` if we cannot
/// determine it (callers fall back to `"Wi-Fi"`).
pub(crate) fn detect_active_network_service() -> Option<String> {
    let out = Command::new("/usr/sbin/networksetup")
        .arg("-listallnetworkservices")
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let s = line.trim();
        if s.starts_with('*') || s.contains("informational") || s.is_empty() {
            continue;
        }
        if s == "Wi-Fi" {
            return Some(s.to_string());
        }
    }
    None
}
