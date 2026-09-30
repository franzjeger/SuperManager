//! The routing table's default routes, as `netstat -nr` lists them.
//!
//! `route -n get default` answers with the route a packet to the default
//! destination would take, and for IPv6 it is a lookup of `::`. With a more
//! specific route in the way, a VPN's two /1 halves or the IPv6 leak block
//! for one, that answer is not the default route. These are the entries
//! themselves.

use std::process::Command;

/// A `default` entry in the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    /// An address, with its scope if it has one (`fe80::1%en0`), or
    /// `link#N` for a route straight out of an interface.
    pub gateway: String,
    pub interface: String,
    pub flags: String,
}

impl DefaultRoute {
    /// Out through loopback without dropping (`B`) or rejecting (`R`) what
    /// it carries: not a way out, and not a way to block one either.
    pub fn is_stray_loopback(&self) -> bool {
        self.interface.starts_with("lo") && !self.flags.contains(['B', 'R'])
    }
}

/// The primary default route: the first `default` entry not bound to one
/// interface (flag `I`). None without one, or when netstat fails.
pub fn primary_default(v6: bool) -> Option<DefaultRoute> {
    let family = if v6 { "inet6" } else { "inet" };
    let out = crate::proc::bounded(
        Command::new("/usr/sbin/netstat").args(["-nr", "-f", family]),
        crate::proc::PROBE,
    )
    .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_primary_default(&String::from_utf8_lossy(&out.stdout))
}

/// Columns are found by their heading: macOS once printed `Refs` and
/// `Use` before `Netif`, and no longer does.
fn parse_primary_default(table: &str) -> Option<DefaultRoute> {
    let mut columns = None;
    for line in table.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() == Some(&"Destination") {
            let find = |name: &str| fields.iter().position(|field| *field == name);
            columns = find("Gateway").zip(find("Flags")).zip(find("Netif"));
            continue;
        }
        let Some(((gateway, flags), netif)) = columns else {
            continue;
        };
        if fields.first() != Some(&"default") {
            continue;
        }
        let (Some(gateway), Some(flags), Some(netif)) =
            (fields.get(gateway), fields.get(flags), fields.get(netif))
        else {
            continue;
        };
        if flags.contains('I') {
            continue;
        }
        return Some(DefaultRoute {
            gateway: (*gateway).to_owned(),
            interface: (*netif).to_owned(),
            flags: (*flags).to_owned(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(gateway: &str, interface: &str, flags: &str) -> DefaultRoute {
        DefaultRoute {
            gateway: gateway.into(),
            interface: interface.into(),
            flags: flags.into(),
        }
    }

    #[test]
    fn the_primary_default_is_the_one_not_bound_to_an_interface() {
        let table = "Routing tables\n\nInternet:\n\
            Destination        Gateway            Flags               Netif Expire\n\
            default            link#23            UCSIg               utun7\n\
            default            192.168.2.55       UGScg                 en0\n\
            default            192.168.2.55       UGScIg                en1\n\
            0/1                utun7              USc                 utun7\n";
        assert_eq!(
            parse_primary_default(table),
            Some(route("192.168.2.55", "en0", "UGScg"))
        );
    }

    /// An IKEv2 full tunnel on an IPv4-only network: its leak block and the
    /// tunnels' own scoped defaults, and no default route of the Mac's.
    #[test]
    fn the_ipv6_leak_block_is_not_a_default_route() {
        let table = "Routing tables\n\nInternet6:\n\
            Destination                             Gateway                                 Flags               Netif Expire\n\
            default                                 fe80::%utun1                            UGcIg               utun1\n\
            default                                 fe80::%utun2                            UGcIg               utun2\n\
            ::/1                                    ::1                                     UGRSc                 lo0\n\
            ::1                                     ::1                                     UHL                   lo0\n\
            8000::/1                                ::1                                     UGRSc                 lo0\n";
        assert_eq!(parse_primary_default(table), None);
    }

    #[test]
    fn a_default_through_loopback_is_a_stray_unless_it_blocks() {
        let table = "Destination                             Gateway                                 Flags               Netif Expire\n\
            default                                 ::1                                     UGScg                 lo0\n\
            default                                 fe80::%utun1                            UGcIg               utun1\n";
        let stray = parse_primary_default(table).unwrap();
        assert_eq!(stray, route("::1", "lo0", "UGScg"));
        assert!(stray.is_stray_loopback());
        assert!(!route("::1", "lo0", "UGSBc").is_stray_loopback());
        assert!(!route("::1", "lo0", "UGRSc").is_stray_loopback());
        assert!(!route("fe80::1%en0", "en0", "UGcg").is_stray_loopback());
    }

    #[test]
    fn columns_are_found_by_their_heading() {
        let table =
            "Destination        Gateway            Flags        Refs      Use   Netif Expire\n\
            default            10.0.0.1           UGSc           47        0     en0\n";
        assert_eq!(
            parse_primary_default(table),
            Some(route("10.0.0.1", "en0", "UGSc"))
        );
        assert_eq!(parse_primary_default("no table here"), None);
    }
}
