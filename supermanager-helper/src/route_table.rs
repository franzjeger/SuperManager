//! The routing table's default routes, as `netstat -nr` lists them.
//!
//! `route -n get default` answers with the route a packet to the default
//! destination would take, and for IPv6 it is a lookup of `::`. With a more
//! specific route in the way, a VPN's two /1 halves or the IPv6 leak block
//! for one, that answer is not the default route. These are the entries
//! themselves.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

use ipnet::IpNet;

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

/// The interface of the route for exactly `net`, if the table has one.
///
/// Not `route -n get <prefix>`: macOS answers that with any route that
/// shares the prefix's key (asked for 128.0.0.0/1 with only 0/1 in the
/// table, it returns 0/1), and without `-host` route(8) reads an address
/// ending in zeros as a network (128.0.0.0 as 128.0/16, 0.0.0.0 as the
/// default route). A `-host` lookup of the prefix's first address finds
/// the route that covers that address, `net`'s own when there is one.
/// `RTM_GET` can hang on a route through a torn-down utun; the dump answers
/// then.
pub fn exact_route(net: &IpNet) -> Option<String> {
    let family = if net.addr().is_ipv4() {
        "-inet"
    } else {
        "-inet6"
    };
    let first = net.network().to_string();
    match crate::proc::bounded(
        Command::new("/sbin/route").args(["-n", "get", family, "-host", &first]),
        crate::proc::PROBE,
    ) {
        Ok(out) if out.status.success() => route_for(&String::from_utf8_lossy(&out.stdout), net),
        Ok(_) => None,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => exact_route_in_dump(net),
        Err(_) => None,
    }
}

/// The interface in a `route -n get` answer, if the route it found is for
/// exactly `net`.
fn route_for(out: &str, net: &IpNet) -> Option<String> {
    let (found, interface) = parse_route_get(out, net.addr().is_ipv4())?;
    (found == net.trunc()).then_some(interface)
}

/// `route -n get` output: `destination:` (`default` for all zeros),
/// `mask:` (`default` for none; no line for a host route) and
/// `interface:`.
fn parse_route_get(out: &str, v4: bool) -> Option<(IpNet, String)> {
    let (mut destination, mut mask, mut interface) = (None, None, None);
    for line in out.lines() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key {
            "destination" => destination = Some(value),
            "mask" => mask = Some(value),
            "interface" => interface = Some(value),
            _ => {}
        }
    }
    let unspecified = if v4 {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let address = match destination? {
        "default" => unspecified,
        address => address.parse().ok()?,
    };
    let prefix = match mask {
        None => {
            if v4 {
                32
            } else {
                128
            }
        }
        Some("default") => 0,
        Some(mask) => ipnet::ip_mask_to_prefix(mask.parse().ok()?).ok()?,
    };
    Some((IpNet::new(address, prefix).ok()?, interface?.to_owned()))
}

/// [`exact_route`] from the kernel routing-table dump. `netstat -rn` gets
/// that via sysctl, which never waits for a per-route reply — unlike
/// `route -n get`, whose `RTM_GET` blocks when the route points at a
/// torn-down utun.
pub fn exact_route_in_dump(want: &IpNet) -> Option<String> {
    let want = want.trunc();
    let af = if want.addr().is_ipv4() {
        "inet"
    } else {
        "inet6"
    };
    let out = crate::proc::bounded(
        std::process::Command::new("/usr/sbin/netstat").args(["-rn", "-f", af]),
        crate::proc::PROBE,
    )
    .ok()?;
    if !out.status.success() {
        return None;
    }
    iface_for_net(&String::from_utf8_lossy(&out.stdout), want)
}

/// Find `want` in `netstat -rn` output (Destination Gateway Flags Netif …).
fn iface_for_net(table: &str, want: IpNet) -> Option<String> {
    table.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            return None;
        }
        (parse_netstat_net(fields[0])? == want).then(|| fields[3].to_owned())
    })
}

/// Parse a destination as `netstat -rn` prints it: IPv4 networks drop
/// trailing zero octets (`0/1`, `128.0/1`, `10.8/16`), IPv6 may carry a
/// `%scope`. Host routes and `default` have no prefix and yield `None`.
fn parse_netstat_net(dest: &str) -> Option<IpNet> {
    let (addr, len) = dest.split_once('/')?;
    let addr = addr.split('%').next()?;
    let full = if addr.contains(':') {
        addr.to_owned()
    } else {
        let mut octets: Vec<&str> = addr.split('.').collect();
        if octets.is_empty() || octets.len() > 4 {
            return None;
        }
        octets.resize(4, "0");
        octets.join(".")
    };
    format!("{full}/{len}").parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `route -n get -host` printed on a Mac with a WireGuard full
    /// tunnel half set up: 0/1 through utun9, and no 128.0/1.
    const HALF: &str = "   route to: 128.0.0.0\ndestination: default\n       mask: 128.0.0.0\n\
                        \x20 interface: utun9\n      flags: <UP,DONE,STATIC,PRCLONING,GLOBAL>\n";

    #[test]
    fn only_a_route_for_exactly_the_prefix_answers() {
        let net = |s: &str| s.parse::<IpNet>().unwrap();
        assert_eq!(route_for(HALF, &net("0.0.0.0/1")).as_deref(), Some("utun9"));
        // Asked for the other half, route(8) finds 0/1: not a route for it.
        assert_eq!(route_for(HALF, &net("128.0.0.0/1")), None);
        let host = "   route to: 51.174.175.4\ndestination: 51.174.175.4\n\
                    \x20   gateway: 192.168.2.55\n  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE,STATIC>\n";
        assert_eq!(
            route_for(host, &net("51.174.175.4/32")).as_deref(),
            Some("en0")
        );
        let v6 = "   route to: fd7a:115c:a1e0::1\ndestination: fd7a:115c:a1e0::\n\
                  \x20      mask: ffff:ffff:ffff::\n  interface: utun0\n";
        assert_eq!(
            route_for(v6, &net("fd7a:115c:a1e0::/48")).as_deref(),
            Some("utun0")
        );
        assert_eq!(
            route_for(
                "route: writing to routing socket: not in table\n",
                &net("0.0.0.0/1")
            ),
            None
        );
    }

    #[test]
    fn netstat_destinations_match_their_cidrs() {
        let table = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.200.1      UGScg                 en0
0/1                10.8.0.1           UGSc                utun7
10.8/16            utun7              USc                 utun7
100.64/10          utun12             USc                utun12
128.0/1            10.8.0.1           UGSc                utun7
169.254            link#14            UCS                   en0      !
";
        let net = |s: &str| s.parse::<IpNet>().unwrap();
        assert_eq!(
            iface_for_net(table, net("0.0.0.0/1")).as_deref(),
            Some("utun7")
        );
        assert_eq!(
            iface_for_net(table, net("128.0.0.0/1")).as_deref(),
            Some("utun7")
        );
        assert_eq!(
            iface_for_net(table, net("10.8.0.0/16")).as_deref(),
            Some("utun7")
        );
        assert_eq!(
            iface_for_net(table, net("100.64.0.0/10")).as_deref(),
            Some("utun12")
        );
        // Exact prefix, like `route -n get <cidr>`: a covering route is not a match.
        assert_eq!(iface_for_net(table, net("100.64.0.0/12")), None);

        let table6 = "\
Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::aa9c:6cff:fe8c:4bd%en0            UGScg                 en0
::/1                                    ::1                                     UGRSc                 lo0
8000::/1                                fe80::%utun4                            UGcIg               utun4
fe80::%utun4/64                         fe80::1%utun4                           UcI                 utun4
";
        assert_eq!(iface_for_net(table6, net("::/1")).as_deref(), Some("lo0"));
        assert_eq!(
            iface_for_net(table6, net("8000::/1")).as_deref(),
            Some("utun4")
        );
        assert_eq!(
            iface_for_net(table6, net("fe80::/64")).as_deref(),
            Some("utun4")
        );
    }

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
