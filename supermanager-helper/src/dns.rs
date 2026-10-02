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
//! VPN resolvers live under our own ephemeral service key, as a
//! supplemental resolver for all domains. macOS chooses the route to the
//! nameserver instead of binding DNS queries to the physical interface.
//! Disconnect removes only our key and flushes the resolver cache. Neither
//! the user's saved DNS nor configd's derived Global/DNS is overwritten.

use std::io::Write as _;
// Every command here is bounded: see `proc::Bounded`.
use crate::proc::Bounded as Command;

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
            // Bounded: a wedged configd leaves scutil alive and mute, and this
            // runs on an RPC path.
            let _ = crate::proc::wait_bounded(child, crate::proc::MUTATE, "scutil (clear DNS)");
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
    let out =
        crate::proc::wait_bounded(child, crate::proc::PROBE, "scutil (list services)").ok()?;
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

/// The Mac's own resolvers: the primary network service's. Ones set by
/// hand in its Setup override what DHCP put in its State, which is where
/// strongSwan's osx-attr also puts an IKEv2 gateway's. Empty when it has
/// none, or they cannot be read.
///
/// Not `State:/Network/Global/DNS` or `scutil --dns`: those are what macOS
/// resolves with now, and with another VPN up that can be that VPN's
/// servers. A full tunnel cannot reach them. An IKEv2 full tunnel set up
/// while an OpenVPN 3 session held them published them as its own, and no
/// name resolved until it was disconnected.
pub fn system_resolvers() -> Vec<String> {
    let Some(service) = show("State:/Network/Global/IPv4")
        .as_deref()
        .and_then(primary_service)
        .map(str::to_owned)
    else {
        return Vec::new();
    };
    own_resolvers(
        show(&format!("Setup:/Network/Service/{service}/DNS")).as_deref(),
        show(&format!("State:/Network/Service/{service}/DNS")).as_deref(),
    )
}

/// A service's resolvers, from its Setup and State DNS dictionaries.
/// configd lets the ones set by hand override the rest.
fn own_resolvers(setup: Option<&str>, state: Option<&str>) -> Vec<String> {
    let manual = setup.map(server_addresses).unwrap_or_default();
    if manual.is_empty() {
        state.map(server_addresses).unwrap_or_default()
    } else {
        manual
    }
}

/// `PrimaryService` in `show State:/Network/Global/IPv4`. It goes into
/// other keys' paths, so it has to look like a service ID.
fn primary_service(ipv4: &str) -> Option<&str> {
    ipv4.lines()
        .find_map(|line| line.trim().strip_prefix("PrimaryService : "))
        .map(str::trim)
        .filter(|id| {
            !id.is_empty()
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        })
}

/// `scutil`'s `show` of `key`. None when scutil cannot be asked.
fn show(key: &str) -> Option<String> {
    let mut child = std::process::Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(format!("open\nshow {key}\nquit\n").as_bytes());
    }
    crate::proc::wait_bounded(child, crate::proc::PROBE, "scutil (show)")
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Keep the Mac's own resolvers answering through a tunnel that takes all
/// of IPv4 or IPv6, and return them. mDNSResponder binds its queries to
/// them to the primary interface, where the tunnel's two halves leave no
/// route, so every lookup hangs. As VPN DNS they are not bound to an
/// interface and follow the routes: through the tunnel, or straight onto
/// the local network for a resolver there.
pub fn follow_system_resolvers() -> Vec<String> {
    let servers = system_resolvers();
    set_vpn_dns(&servers);
    servers
}

/// `ServerAddresses` from `scutil`'s `show` of a DNS dictionary: the
/// entries of its array, each an address.
fn server_addresses(dictionary: &str) -> Vec<String> {
    dictionary
        .lines()
        .skip_while(|line| !line.trim_start().starts_with("ServerAddresses"))
        .skip(1)
        .take_while(|line| line.trim() != "}")
        .filter_map(|line| line.split_once(" : "))
        .map(|(_, address)| address.trim())
        .filter(|address| address.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_owned)
        .collect()
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
            let _ = crate::proc::wait_bounded(child, crate::proc::MUTATE, "scutil (set DNS)");
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
    fn the_system_resolvers_are_the_server_addresses() {
        let shown = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 8.8.8.8\n    \
                     1 : 2001:4860:4860::8888\n    2 : fe80::1%en0\n  }\n  \
                     __IF_INDEX__ : 14\n  __ORDER__ : 0\n}\n";
        // A scoped link-local address cannot leave unbound; it is left out.
        assert_eq!(
            server_addresses(shown),
            vec!["8.8.8.8".to_owned(), "2001:4860:4860::8888".to_owned()]
        );
        assert!(server_addresses("  No such key\n").is_empty());
    }

    /// This Mac on 2026-10-01: Wi-Fi is primary, and its DNS holds what DHCP
    /// handed out, with the Elteco gateway's resolver that osx-attr put first.
    #[test]
    fn the_own_resolvers_are_the_primary_services() {
        let ipv4 = "<dictionary> {\n  PrimaryInterface : en0\n  \
                    PrimaryService : 02C8522B-E796-4B29-AA2F-8322C955FF7C\n  \
                    Router : 192.168.2.55\n}\n";
        assert_eq!(
            primary_service(ipv4),
            Some("02C8522B-E796-4B29-AA2F-8322C955FF7C")
        );
        assert_eq!(primary_service("  No such key\n"), None);
        // Interpolated into a key path: nothing that leaves the service's own.
        assert_eq!(primary_service("  PrimaryService : x/../../Global\n"), None);
        assert_eq!(primary_service("  PrimaryService : a b\n"), None);

        let state = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 10.20.200.1\n    \
                     1 : 8.8.8.8\n  }\n}\n";
        let manual = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 9.9.9.9\n  }\n}\n";
        assert_eq!(
            own_resolvers(Some("<dictionary> {\n}\n"), Some(state)),
            vec!["10.20.200.1".to_owned(), "8.8.8.8".to_owned()]
        );
        assert_eq!(own_resolvers(Some("  No such key\n"), Some(state)).len(), 2);
        assert_eq!(
            own_resolvers(Some(manual), Some(state)),
            vec!["9.9.9.9".to_owned()]
        );
        assert!(own_resolvers(None, None).is_empty());
    }

    #[test]
    fn dns_addresses_cannot_inject_scutil_commands() {
        let script = vpn_dns_script(&["1.1.1.1\nremove Setup:/Network/Global/DNS".into()]);
        assert!(!script.contains("remove"));
    }
}
