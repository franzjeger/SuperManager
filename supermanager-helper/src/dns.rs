//! VPN DNS state management — macOS best-practice teardown.
//!
//! ## Why two stores?
//!
//! macOS System Configuration has two layers:
//!
//!   `Setup:/Network/Service/<uuid>/DNS` — persistent, survives reboot.
//!                                         Written by `networksetup`.
//!   `State:/Network/Service/<uuid>/DNS` — ephemeral, cleared on reboot.
//!                                         Written by scutil / VPN daemons.
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

use std::fmt::Write as _;
use std::io::Write as _;
// Every command here is bounded: see `proc::Bounded`.
use crate::proc::Bounded as Command;

/// Legacy shared State-store key (kept so boot-time / full sweeps remove it too)
/// and per-owner prefix (`State:/Network/Service/com.sybr.supermanager.vpn.<owner>/DNS`).
const LEGACY_SUPERMGR_DNS_KEY: &str = "State:/Network/Service/com.sybr.supermanager.vpn/DNS";
const SUPERMGR_DNS_SERVICE_PREFIX: &str = "com.sybr.supermanager.vpn.";

fn sanitize_owner(owner: &str) -> String {
    let mut s: String = owner
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_' | '.'))
        .take(128)
        .collect();
    if s.is_empty() {
        s.push_str("default");
    }
    s
}

pub(crate) fn dns_key_for(owner: &str) -> String {
    let safe = sanitize_owner(owner);
    format!("State:/Network/Service/{SUPERMGR_DNS_SERVICE_PREFIX}{safe}/DNS")
}

fn flush_resolver_caches() {
    let _ = Command::new("/usr/bin/dscacheutil")
        .arg("-flushcache")
        .output();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .output();
}

/// Remove ONLY `owner`'s ephemeral VPN resolver key without touching other
/// connected VPN profiles or the DNS health watchdog.
pub fn clear_vpn_dns_for(owner: &str) {
    let key = dns_key_for(owner);
    tracing::info!(owner, key = %key, "clear_vpn_dns_for: removing owner DNS key");
    let script = format!("open\nremove {key}\nquit\n");
    run_scutil_script(&script, "scutil (clear owner DNS)");
    flush_resolver_caches();
}

/// Remove all ephemeral VPN resolver keys whose owner begins with `owner_prefix`
/// (e.g. `"ikev2-"` or `"ovpn-"` during pre-sleep bulk teardown).
pub fn clear_vpn_dns_prefix(owner_prefix: &str) {
    let safe_prefix = sanitize_owner(owner_prefix);
    let wanted_service_prefix =
        format!("State:/Network/Service/{SUPERMGR_DNS_SERVICE_PREFIX}{safe_prefix}");
    let keys = list_supermgr_dns_keys()
        .into_iter()
        .filter(|k| k.starts_with(&wanted_service_prefix))
        .collect::<Vec<_>>();
    if keys.is_empty() {
        return;
    }
    let mut script = String::from("open\n");
    for key in &keys {
        let _ = writeln!(script, "remove {key}");
    }
    script.push_str("quit\n");
    run_scutil_script(&script, "scutil (clear prefix DNS)");
    flush_resolver_caches();
}

/// Remove ALL ephemeral SuperManager VPN DNS keys (boot-time `vpn-dns-cleanup`).
pub fn clear_vpn_dns() {
    tracing::info!("clear_vpn_dns: sweeping all SuperManager State DNS keys");
    let mut keys = list_supermgr_dns_keys();
    if !keys.iter().any(|k| k == LEGACY_SUPERMGR_DNS_KEY) {
        keys.push(LEGACY_SUPERMGR_DNS_KEY.to_owned());
    }
    let mut script = String::from("open\n");
    for key in &keys {
        let _ = writeln!(script, "remove {key}");
    }
    script.push_str("quit\n");
    run_scutil_script(&script, "scutil (clear all DNS)");
    flush_resolver_caches();
    tracing::info!("clear_vpn_dns: done");
}

fn list_supermgr_dns_keys() -> Vec<String> {
    let Ok(mut child) = std::process::Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return Vec::new();
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(
            b"open\nlist State:/Network/Service/com\\.sybr\\.supermanager\\.vpn[^/]*/DNS\nquit\n",
        );
    }
    let Ok(out) = crate::proc::wait_bounded(child, crate::proc::PROBE, "scutil (list VPN DNS)")
    else {
        return Vec::new();
    };
    parse_listed_supermgr_keys(&String::from_utf8_lossy(&out.stdout))
}

fn parse_listed_supermgr_keys(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.split_once('=').map(|(_, rhs)| rhs.trim()))
        .filter(|key| {
            *key == LEGACY_SUPERMGR_DNS_KEY
                || (key.starts_with("State:/Network/Service/com.sybr.supermanager.vpn.")
                    && key.ends_with("/DNS")
                    && key["State:/Network/Service/com.sybr.supermanager.vpn.".len()
                        ..key.len() - "/DNS".len()]
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        })
        .map(str::to_owned)
        .collect()
}

fn run_scutil_script(script: &str, label: &str) {
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
            let _ = crate::proc::wait_bounded(child, crate::proc::MUTATE, label);
        }
        Err(e) => tracing::warn!("{label}: spawn scutil: {e}"),
    }
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
pub fn follow_system_resolvers_for(owner: &str) -> Vec<String> {
    let servers = system_resolvers();
    set_vpn_dns_for(owner, &servers);
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

/// Write VPN DNS directly to the State store via `scutil` under `owner`'s own
/// service key, so disconnecting one profile never wipes another's DNS.
pub fn set_vpn_dns_for(owner: &str, servers: &[String]) {
    let Some(script) = vpn_dns_script_for(owner, servers) else {
        return;
    };
    tracing::info!(owner, "set_vpn_dns_for: setting State DNS to {:?}", servers);
    run_scutil_script(&script, "scutil (set DNS)");
    flush_resolver_caches();
}

/// A supplemental default resolver is not bound to the physical service.
/// Merely changing Global/DNS leaves mDNSResponder using en0, even when
/// the IP route to the resolver belongs to an IPsec utun. configd owns
/// Global/DNS, so install and remove only our per-owner service dictionary.
fn vpn_dns_script_for(owner: &str, servers: &[String]) -> Option<String> {
    let addresses = servers
        .iter()
        .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return None;
    }
    let key = dns_key_for(owner);
    Some(format!(
        "open\nd.init\nd.add ServerAddresses * {}\n\
         d.add SupplementalMatchDomains * \"\"\n\
         d.add SupplementalMatchOrders * # 100\n\
         set {key}\nquit\n",
        addresses.join(" ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_resolver_matches_all_domains_without_binding_to_wifi() {
        let script = vpn_dns_script_for("wg-smwg-a1", &["1.1.1.1".into(), "8.8.8.8".into()])
            .expect("script");
        assert!(script.contains("ServerAddresses * 1.1.1.1 8.8.8.8\n"));
        assert!(script.contains("SupplementalMatchDomains * \"\"\n"));
        assert!(script.contains("SupplementalMatchOrders * # 100\n"));
        assert!(script
            .contains("set State:/Network/Service/com.sybr.supermanager.vpn.wg-smwg-a1/DNS\n"));
        assert!(!script.contains("Global/DNS"));
        assert!(!script.contains("InterfaceName"));
    }

    #[test]
    fn distinct_owners_receive_isolated_scutil_keys() {
        let k1 = dns_key_for("ikev2-1111");
        let k2 = dns_key_for("wg-2222");
        let kw = dns_key_for("watchdog");
        assert_ne!(k1, k2);
        assert_ne!(k1, kw);
        assert_eq!(
            dns_key_for("bad/../../Global"),
            "State:/Network/Service/com.sybr.supermanager.vpn.bad....Global/DNS"
        );
        let listed = "\
  subKey [0] = State:/Network/Service/com.sybr.supermanager.vpn/DNS\n\
  subKey [1] = State:/Network/Service/com.sybr.supermanager.vpn.ikev2-1111/DNS\n\
  subKey [2] = State:/Network/Service/02C8522B-E796-4B29-AA2F-8322C955FF7C/DNS\n";
        assert_eq!(
            parse_listed_supermgr_keys(listed),
            vec![
                "State:/Network/Service/com.sybr.supermanager.vpn/DNS".to_owned(),
                "State:/Network/Service/com.sybr.supermanager.vpn.ikev2-1111/DNS".to_owned(),
            ]
        );
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
        assert_eq!(server_addresses("  No such key\n"), Vec::<String>::new());
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
        assert_eq!(own_resolvers(None, None), Vec::<String>::new());
    }

    #[test]
    fn dns_addresses_cannot_inject_scutil_commands() {
        assert!(vpn_dns_script_for(
            "wg-a",
            &["1.1.1.1\nremove Setup:/Network/Global/DNS".into()]
        )
        .is_none());
    }
}
