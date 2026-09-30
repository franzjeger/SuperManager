//! The tunnel's addresses, MTU and routes, set with `ifconfig` and `route`
//! as wg-quick set them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt as _;
use tokio::process::Command;

const IFCONFIG: &str = "/sbin/ifconfig";
const ROUTE: &str = "/sbin/route";

/// Run a command that changes something; its stderr is the error.
async fn change(program: &str, args: &[&str]) -> Result<()> {
    let output = crate::proc::bounded_async(Command::new(program).args(args), crate::proc::MUTATE)
        .await
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// What a command prints, or None when it fails.
async fn read(program: &str, args: &[&str]) -> Option<String> {
    let output = crate::proc::bounded_async(Command::new(program).args(args), crate::proc::PROBE)
        .await
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Whether an interface of that name exists. A lookup in the kernel, so
/// nothing to hang on the way `ifconfig` can on a half-removed utun.
pub fn exists(interface: &str) -> bool {
    let Ok(name) = std::ffi::CString::new(interface) else {
        return false;
    };
    // SAFETY: a NUL-terminated name the call only reads.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

pub async fn add_address(interface: &str, address: &IpNet) -> Result<()> {
    let net = address.to_string();
    match address {
        // A utun is point-to-point: its own address is the far end too.
        IpNet::V4(v4) => {
            let own = v4.addr().to_string();
            change(IFCONFIG, &[interface, "inet", &net, &own, "alias"]).await
        }
        IpNet::V6(_) => change(IFCONFIG, &[interface, "inet6", &net, "alias"]).await,
    }
}

pub async fn up(interface: &str) -> Result<()> {
    change(IFCONFIG, &[interface, "up"]).await
}

pub async fn set_mtu(interface: &str, mtu: u32) -> Result<()> {
    change(IFCONFIG, &[interface, "mtu", &mtu.to_string()]).await
}

pub async fn mtu(interface: &str) -> Option<u32> {
    parse_mtu(&read(IFCONFIG, &[interface]).await?)
}

/// `en0: flags=8863<UP,...> mtu 1500`
fn parse_mtu(ifconfig: &str) -> Option<u32> {
    let mut words = ifconfig.lines().next()?.split_whitespace();
    words.by_ref().find(|word| *word == "mtu")?;
    words.next()?.parse().ok()
}

fn family(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "-inet"
    } else {
        "-inet6"
    }
}

/// The route traffic to `ip` takes: the prefix it is for, and its
/// interface. `-host` makes it a lookup of the address. Without it,
/// route(8) reads an address ending in zeros as a network (128.0.0.0 as
/// 128.0/16, 0.0.0.0 as the default route), and macOS answers a network
/// with any route sharing its key: asked for 128.0.0.0/1, it finds 0/1.
async fn lookup(ip: IpAddr) -> Option<(IpNet, String)> {
    let address = ip.to_string();
    let out = read(ROUTE, &["-n", "get", family(ip), "-host", &address]).await?;
    parse_route_get(&out, ip.is_ipv4())
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

/// Whether `net` has a route of its own through `interface`.
pub async fn has_own_route(net: &IpNet, interface: &str) -> bool {
    lookup(net.network())
        .await
        .is_some_and(|(found, through)| found == net.trunc() && through == interface)
}

/// Route `net` through `interface`. A route for it already there is fine
/// if it is this one: the one for the interface's own address, say.
pub async fn add_route(net: &IpNet, interface: &str) -> Result<()> {
    let dest = net.to_string();
    let added = change(
        ROUTE,
        &[
            "-n",
            "add",
            family(net.addr()),
            &dest,
            "-interface",
            interface,
        ],
    )
    .await;
    match added {
        Err(_) if has_own_route(net, interface).await => Ok(()),
        added => added,
    }
}

/// The way out of the primary default route, which a peer's endpoint
/// keeps taking while the tunnel takes everything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Via {
    Gateway(String),
    /// A default route straight out of an interface, with no gateway.
    Interface(String),
    /// No default route: the endpoint's packets are dropped rather than
    /// sent into the tunnel they carry.
    Nowhere,
}

/// The primary default route (`route_table::primary_default`): its way
/// out, and its interface.
pub async fn default_route(v4: bool) -> (Via, Option<String>) {
    let route = tokio::task::spawn_blocking(move || crate::route_table::primary_default(!v4))
        .await
        .ok()
        .flatten();
    match route {
        Some(route) => (way_out(&route), Some(route.interface)),
        None => (Via::Nowhere, None),
    }
}

/// Its gateway, with the scope a link-local one has; its interface for a
/// route straight out of one; nowhere for one through loopback, which is
/// no way out.
fn way_out(route: &crate::route_table::DefaultRoute) -> Via {
    if route.interface.starts_with("lo") {
        return Via::Nowhere;
    }
    let address = route.gateway.split('%').next().unwrap_or_default();
    if address.parse::<IpAddr>().is_ok() {
        Via::Gateway(route.gateway.clone())
    } else {
        Via::Interface(route.interface.clone())
    }
}

/// A host route for a peer's endpoint.
pub async fn add_host_route(ip: IpAddr, via: &Via) -> Result<()> {
    let dest = ip.to_string();
    let mut args = vec!["-n", "add", family(ip), "-host", dest.as_str()];
    let blackhole = if ip.is_ipv4() { "127.0.0.1" } else { "::1" };
    match via {
        Via::Gateway(gateway) => args.extend(["-gateway", gateway.as_str()]),
        Via::Interface(interface) => args.extend(["-interface", interface.as_str()]),
        Via::Nowhere => args.extend([blackhole, "-blackhole"]),
    }
    change(ROUTE, &args).await
}

pub async fn delete_host_route(ip: IpAddr) {
    let dest = ip.to_string();
    if let Err(e) = change(ROUTE, &["-q", "-n", "delete", family(ip), "-host", &dest]).await {
        tracing::debug!("{e:#}");
    }
}

/// The messages that say a route or an interface changed. The others,
/// lookups and misses above all, come several times a second and change
/// nothing; wg-quick redid its endpoint routes on every one.
fn is_change(message: &str) -> bool {
    const CHANGES: [&str; 6] = [
        "RTM_ADD",
        "RTM_DELETE",
        "RTM_CHANGE",
        "RTM_IFINFO",
        "RTM_NEWADDR",
        "RTM_DELADDR",
    ];
    message
        .split(':')
        .next()
        .is_some_and(|kind| CHANGES.contains(&kind))
}

/// Changes to routes and interfaces, from `route -n monitor`.
#[derive(Default)]
pub struct RouteEvents {
    monitor: Option<(
        tokio::process::Child,
        tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    )>,
}

impl RouteEvents {
    /// Wait for a route or an interface to change, then for the burst one
    /// change comes as (a network switch, a tunnel coming up) to settle, for
    /// at most two seconds. Cancel-safe, for `select!`.
    pub async fn changed(&mut self) {
        loop {
            if self.monitor.is_none() {
                match Command::new(ROUTE)
                    .args(["-n", "monitor"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
                {
                    Ok(mut child) => {
                        let stdout = child.stdout.take().expect("piped");
                        let lines = tokio::io::BufReader::new(stdout).lines();
                        self.monitor = Some((child, lines));
                    }
                    Err(e) => {
                        tracing::warn!("route monitor: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                }
            }
            let (_, lines) = self.monitor.as_mut().expect("started above");
            match lines.next_line().await {
                Ok(Some(line)) if is_change(&line) => break,
                Ok(Some(_)) => {}
                _ => {
                    // It ended; start another after a pause.
                    self.monitor = None;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
        if let Some((_, lines)) = self.monitor.as_mut() {
            let quiet = std::time::Duration::from_millis(500);
            let settled = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
            let mut until = tokio::time::Instant::now() + quiet;
            while let Ok(Ok(Some(line))) =
                tokio::time::timeout_at(until.min(settled), lines.next_line()).await
            {
                if is_change(&line) {
                    until = tokio::time::Instant::now() + quiet;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(gateway: &str, interface: &str) -> crate::route_table::DefaultRoute {
        crate::route_table::DefaultRoute {
            gateway: gateway.into(),
            interface: interface.into(),
            flags: "UGScg".into(),
        }
    }

    #[test]
    fn endpoints_leave_the_way_the_default_route_does() {
        assert_eq!(
            way_out(&route("192.168.2.55", "en0")),
            Via::Gateway("192.168.2.55".into())
        );
        // A link-local gateway keeps its scope.
        assert_eq!(
            way_out(&route("fe80::1%en0", "en0")),
            Via::Gateway("fe80::1%en0".into())
        );
        // Straight out of an interface, with no gateway.
        assert_eq!(
            way_out(&route("link#20", "utun5")),
            Via::Interface("utun5".into())
        );
        // Through loopback is no way out.
        assert_eq!(way_out(&route("::1", "lo0")), Via::Nowhere);
    }

    /// What `route -n get -host` printed on a Mac with a WireGuard full
    /// tunnel half set up: 0/1 through utun9, and no 128.0/1.
    #[test]
    fn a_lookup_names_the_route_it_found() {
        let parse = |out: &str, v4| parse_route_get(out, v4).map(|(net, i)| (net.to_string(), i));
        let half = "   route to: default\ndestination: default\n       mask: 128.0.0.0\n\
                    \x20 interface: utun9\n      flags: <UP,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(
            parse(half, true),
            Some(("0.0.0.0/1".into(), "utun9".into()))
        );
        let default = "   route to: 128.0.0.0\ndestination: default\n       mask: default\n\
                       \x20   gateway: 192.168.2.55\n  interface: en0\n";
        assert_eq!(
            parse(default, true),
            Some(("0.0.0.0/0".into(), "en0".into()))
        );
        let host = "   route to: 51.174.175.4\ndestination: 51.174.175.4\n\
                    \x20   gateway: 192.168.2.55\n  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE,STATIC>\n";
        assert_eq!(
            parse(host, true),
            Some(("51.174.175.4/32".into(), "en0".into()))
        );
        let v6 = "   route to: fd7a:115c:a1e0::1\ndestination: fd7a:115c:a1e0::\n\
                  \x20      mask: ffff:ffff:ffff::\n  interface: utun0\n";
        assert_eq!(
            parse(v6, false),
            Some(("fd7a:115c:a1e0::/48".into(), "utun0".into()))
        );
        assert_eq!(
            parse("route: writing to routing socket: not in table\n", true),
            None
        );
    }

    #[test]
    fn the_mtu_is_read_from_the_first_line() {
        assert_eq!(
            parse_mtu(
                "en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500\n\toptions=6460<TSO4>\n"
            ),
            Some(1500)
        );
        assert_eq!(
            parse_mtu("utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>"),
            None
        );
    }

    #[test]
    fn only_changes_count_as_events() {
        for change in [
            "RTM_ADD: Add Route: len 144, pid: 0, seq 0, errno 0, flags:<UP,GATEWAY>",
            "RTM_DELETE: Delete Route: len 144, pid: 0, seq 0, errno 0",
            "RTM_IFINFO: iface status change: len 112, if# 18, flags:<UP,POINTOPOINT>",
            "RTM_NEWADDR: address being added to iface: len 64, metric 0",
        ] {
            assert!(is_change(change), "{change}");
        }
        for noise in [
            "RTM_GET: Report Metrics: len 164, pid: 9588, seq 1, errno 0",
            "RTM_MISS: Lookup failed on this address: len 92, pid: 0",
            "got message of size 164 on Tue Sep 30 07:40:12 2026",
            "",
        ] {
            assert!(!is_change(noise), "{noise}");
        }
    }

    #[test]
    fn interfaces_are_looked_up_in_the_kernel() {
        assert!(exists("lo0"));
        assert!(!exists("utun-not-there"));
        assert!(!exists("bad\0name"));
    }
}
