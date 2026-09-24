//! VPN DNS state management — macOS best-practice teardown.
//!
//! ## Why two stores?
//!
//! macOS System Configuration has two layers:
//!
//!   <Setup:/Network/Service>/<uuid>/DNS  — persistent, survives reboot.
//!                                        Written by `networksetup`.
//!   <State:/Network/Service>/<uuid>/DNS  — ephemeral, cleared on reboot.
//!                                        Written by scutil / VPN daemons.
//!
//! `networksetup -setdnsservers` writes to **Setup** — the user's saved
//! preference. If a VPN sets DNS there and the cleanup step is skipped
//! (fallback disconnect path, crash, SIGKILL), those servers stay set
//! permanently and survive VPN disconnection and reboots.
//!
//! VPN resolvers live under our own ephemeral service key, as a
//! supplemental resolver for all domains. macOS chooses the route to the
//! nameserver instead of binding DNS queries to the physical interface.
//! Disconnect removes only our key and flushes the resolver cache. Neither
//! the user's saved DNS nor configd's derived Global/DNS is overwritten.

use std::io::Write as _;
use std::process::Command;

/// The one State-store key SuperManager ever writes DNS to.
///
/// Scoped to our own service name on purpose: the physical interface's
/// `State:/Network/Service/<uuid>/DNS` is where DHCP puts the router's
/// resolvers, and removing that is what broke name resolution after
/// every teardown.
const SUPERMGR_DNS_KEY: &str = "State:/Network/Service/com.sybr.supermanager.vpn/DNS";

/// Remove our ephemeral VPN resolver without changing saved DNS.
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
    // loses nothing. configd owns Global/DNS; do not remove its derived
    // state or another network service's resolver during teardown.
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
    let _ = Command::new("/usr/bin/dscacheutil")
        .arg("-flushcache")
        .output();
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

/// Write VPN DNS directly to the State store via `scutil`.
/// This avoids the persistent Setup store (`networksetup`), meaning
/// it never leaves "manual DNS" behind if the process crashes.
pub fn set_vpn_dns(servers: &[String]) {
    if servers.is_empty() {
        return;
    }
    tracing::info!("set_vpn_dns: setting State DNS to {:?}", servers);

    let script = vpn_dns_script(servers);

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
        }
        Err(e) => tracing::warn!("set_vpn_dns: spawn scutil: {e}"),
    }

    // Flush resolver caches so apps pick up the new resolver instantly
    let _ = Command::new("/usr/bin/dscacheutil")
        .arg("-flushcache")
        .output();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .output();
}

/// A supplemental default resolver is not bound to the physical service.
/// Merely changing Global/DNS leaves mDNSResponder using en0, even when
/// the IP route to the resolver belongs to an IPsec utun. configd owns
/// Global/DNS, so install and remove only our own service dictionary.
fn vpn_dns_script(servers: &[String]) -> String {
    let addresses = servers
        .iter()
        .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "open\nd.init\nd.add ServerAddresses * {addresses}\n\
         d.add SupplementalMatchDomains * \"\"\n\
         d.add SupplementalMatchOrders * # 100\n\
         set {SUPERMGR_DNS_KEY}\nquit\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_resolver_matches_all_domains_without_binding_to_wifi() {
        let script = vpn_dns_script(&["1.1.1.1".into(), "8.8.8.8".into()]);
        assert!(script.contains("ServerAddresses * 1.1.1.1 8.8.8.8\n"));
        assert!(script.contains("SupplementalMatchDomains * \"\"\n"));
        assert!(script.contains("SupplementalMatchOrders * # 100\n"));
        assert!(!script.contains("Global/DNS"));
        assert!(!script.contains("InterfaceName"));
    }

    #[test]
    fn dns_addresses_cannot_inject_scutil_commands() {
        let script = vpn_dns_script(&["1.1.1.1\nremove Setup:/Network/Global/DNS".into()]);
        assert!(!script.contains("remove"));
    }
}
