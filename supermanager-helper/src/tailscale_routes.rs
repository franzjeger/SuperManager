//! Puts back the subnet routes Tailscale accepted when something took them.
//!
//! tailscaled adds a route through its utun for each subnet a peer routes,
//! and it does that only when its configuration changes. macOS takes such a
//! route away when the Mac joins a network with the same prefix, because the
//! local network's own route wins. Leaving that network takes the local
//! route away as well, and nothing puts Tailscale's back. The subnet stays
//! unreachable until someone toggles "Accept routes". A Mac whose home LAN
//! (192.168.200.0/24) the tailnet also routes ran into this every morning it
//! left home.
//!
//! While "Accept routes" is on, this compares the subnets the peers route
//! with the routing table every [`INTERVAL`]. A subnet with no route at all
//! gets one through the Tailscale utun, as tailscaled would have added it. A
//! prefix that another route holds is left alone: the local network's route
//! at home, or a VPN's.

use std::time::Duration;

use ipnet::IpNet;
use serde_json::Value;

use crate::proc::Bounded as Command;

/// The longest a subnet goes without its route. Each check is two CLI calls
/// and one route lookup per subnet.
const INTERVAL: Duration = Duration::from_secs(20);

pub fn spawn() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("tailscale-routes".into())
        .spawn(|| loop {
            std::thread::sleep(INTERVAL);
            restore_missing();
        })?;
    Ok(())
}

fn restore_missing() {
    let Some((prefs, status)) = crate::tailscale::prefs_and_status() else {
        return;
    };
    let subnets = accepted_subnets(&prefs, &status);
    if subnets.is_empty() {
        return;
    }
    let Some(utun) = crate::tailscale::detect_tailscale_utun() else {
        return;
    };
    for net in missing(&subnets, crate::route_table::exact_route) {
        let family = if net.addr().is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        let added = Command::new("/sbin/route")
            .args([
                "-n",
                "add",
                family,
                "-net",
                &net.to_string(),
                "-interface",
                &utun,
            ])
            .output();
        match added {
            Ok(out) if out.status.success() => {
                tracing::info!(subnet = %net, %utun, "put back a Tailscale subnet route that was gone");
            }
            Ok(out) => tracing::warn!(
                subnet = %net,
                "could not put back a Tailscale subnet route: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => {
                tracing::warn!(subnet = %net, "could not put back a Tailscale subnet route: {e}");
            }
        }
    }
}

/// The subnets tailscaled routes while "Accept routes" is on: those the peers
/// are the primary routers for. A default route among them belongs to an exit
/// node, which this does not handle.
fn accepted_subnets(prefs: &Value, status: &Value) -> Vec<IpNet> {
    let accepting = prefs.get("RouteAll").and_then(Value::as_bool) == Some(true)
        && status.get("BackendState").and_then(Value::as_str) == Some("Running");
    if !accepting {
        return Vec::new();
    }
    let routes = status
        .get("Peer")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|peers| peers.values())
        .filter_map(|peer| peer.get("PrimaryRoutes").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str);
    let mut subnets: Vec<IpNet> = Vec::new();
    for net in routes.filter_map(|route| route.parse::<IpNet>().ok()) {
        if net.prefix_len() > 0 && !subnets.contains(&net) {
            subnets.push(net);
        }
    }
    subnets
}

/// The subnets no route holds. `route_for` names the interface of the route
/// for exactly a prefix (production: `route_table::exact_route`).
fn missing(subnets: &[IpNet], route_for: impl Fn(&IpNet) -> Option<String>) -> Vec<IpNet> {
    subnets
        .iter()
        .filter(|net| route_for(net).is_none())
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This Mac's tailnet on 2026-10-02: one subnet router at home, and a
    /// peer that routes nothing.
    fn status() -> Value {
        serde_json::json!({
            "BackendState": "Running",
            "Peer": {
                "nodekey:a": {
                    "HostName": "homelab",
                    "PrimaryRoutes": ["172.172.172.0/24", "192.168.200.0/24", "192.168.201.0/24"]
                },
                "nodekey:b": { "HostName": "laptop" },
                "nodekey:c": { "HostName": "exit", "PrimaryRoutes": ["0.0.0.0/0", "::/0", "192.168.200.0/24"] }
            }
        })
    }

    fn nets(list: &[&str]) -> Vec<IpNet> {
        list.iter().map(|net| net.parse().unwrap()).collect()
    }

    #[test]
    fn the_subnets_are_the_peers_primary_routes_while_accepting() {
        let accepting = serde_json::json!({ "RouteAll": true });
        let mut subnets = accepted_subnets(&accepting, &status());
        subnets.sort();
        assert_eq!(
            subnets,
            nets(&["172.172.172.0/24", "192.168.200.0/24", "192.168.201.0/24"])
        );

        assert!(accepted_subnets(&serde_json::json!({ "RouteAll": false }), &status()).is_empty());
        let mut stopped = status();
        stopped["BackendState"] = "Stopped".into();
        assert!(accepted_subnets(&accepting, &stopped).is_empty());
        assert!(accepted_subnets(&accepting, &serde_json::json!({})).is_empty());
    }

    /// Against this Mac's tailscaled and routing table. Reads only:
    /// `cargo test -p supermanager-helper live_subnets -- --ignored --nocapture`
    #[test]
    #[ignore = "reads the live tailscaled and routing table"]
    fn live_subnets() {
        let (prefs, status) = crate::tailscale::prefs_and_status().expect("tailscaled answers");
        let subnets = accepted_subnets(&prefs, &status);
        println!("accepted: {subnets:?}");
        println!(
            "missing: {:?}",
            missing(&subnets, crate::route_table::exact_route)
        );
    }

    /// At home the LAN's route holds the home subnet, and Tailscale's own
    /// routes hold the others. Away from home, the home subnet has none.
    #[test]
    fn only_a_subnet_no_route_holds_is_missing() {
        let subnets = nets(&["172.172.172.0/24", "192.168.200.0/24", "192.168.201.0/24"]);
        let at_home = |net: &IpNet| {
            Some(
                if net.to_string() == "192.168.200.0/24" {
                    "en0"
                } else {
                    "utun0"
                }
                .to_owned(),
            )
        };
        assert!(missing(&subnets, at_home).is_empty());

        let at_work =
            |net: &IpNet| (net.to_string() != "192.168.200.0/24").then(|| "utun0".to_owned());
        assert_eq!(missing(&subnets, at_work), nets(&["192.168.200.0/24"]));
    }
}
