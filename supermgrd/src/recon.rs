//! Bounded local-network TCP discovery.

use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::{bail, Context as _};
use futures_util::{stream::FuturesUnordered, StreamExt as _};
use ipnet::Ipv4Net;
use tokio::sync::Semaphore;

use supermgr_core::{
    host::Host,
    recon::{ReconHost, ReconScanResult},
};

/// Conservative ports for finding common managed infrastructure.
pub const DEFAULT_PORTS: &[u16] = &[22, 80, 443, 445, 3389, 5900, 8080, 8443];

/// Scan one private IPv4 range. Public ranges and ranges larger than /24 are
/// rejected before any socket is opened.
pub async fn scan(
    target: &str,
    ports: &[u16],
    managed: &[Host],
) -> anyhow::Result<ReconScanResult> {
    let network: Ipv4Net = target
        .trim()
        .parse()
        .with_context(|| format!("invalid IPv4 CIDR '{target}'"))?;
    if network.prefix_len() < 24 {
        bail!("scan range is too large; use /24 or a smaller range");
    }
    if !is_local(network.network()) || !is_local(network.broadcast()) {
        bail!("Recon only scans private or link-local IPv4 ranges");
    }
    if ports.is_empty() || ports.len() > 32 || ports.contains(&0) {
        bail!("select between 1 and 32 valid TCP ports");
    }

    let mut ports = ports.to_vec();
    ports.sort_unstable();
    ports.dedup();
    let known: HashMap<String, (String, String, String)> = managed
        .iter()
        .filter_map(|host| {
            host.hostname.parse::<Ipv4Addr>().ok().map(|ip| {
                (
                    ip.to_string(),
                    (
                        host.id.to_string(),
                        host.label.clone(),
                        host.customer.clone(),
                    ),
                )
            })
        })
        .collect();
    let started_at = chrono::Utc::now();
    let concurrency = Arc::new(Semaphore::new(32));
    let mut work = FuturesUnordered::new();

    for ip in network.hosts() {
        let permit = Arc::clone(&concurrency).acquire_owned().await?;
        let ports = ports.clone();
        let known = known.get(&ip.to_string()).cloned();
        work.push(tokio::spawn(async move {
            let _permit = permit;
            let probes = ports.into_iter().map(|port| async move {
                let address = std::net::SocketAddr::from((ip, port));
                let open = tokio::time::timeout(
                    Duration::from_millis(650),
                    tokio::net::TcpStream::connect(address),
                )
                .await
                .is_ok_and(|result| result.is_ok());
                open.then_some(port)
            });
            let mut open_ports: Vec<u16> = futures_util::future::join_all(probes)
                .await
                .into_iter()
                .flatten()
                .collect();
            open_ports.sort_unstable();
            if open_ports.is_empty() && known.is_none() {
                return None;
            }
            let (managed_host_id, managed_label, customer) = known
                .map(|(id, label, customer)| {
                    (
                        Some(id),
                        Some(label),
                        (!customer.is_empty()).then_some(customer),
                    )
                })
                .unwrap_or_default();
            Some(ReconHost {
                ip: ip.to_string(),
                open_ports,
                managed_host_id,
                managed_label,
                customer,
            })
        }));
    }

    let mut hosts = Vec::new();
    while let Some(result) = work.next().await {
        if let Ok(Some(host)) = result {
            hosts.push(host);
        }
    }
    hosts.sort_by_key(|host| {
        host.ip
            .parse::<Ipv4Addr>()
            .map(u32::from)
            .unwrap_or_default()
    });
    Ok(ReconScanResult {
        target: network.to_string(),
        ports,
        started_at,
        finished_at: chrono::Utc::now(),
        hosts,
    })
}

fn is_local(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn public_ranges_are_rejected_before_scanning() {
        let error = scan("8.8.8.0/24", &[443], &[]).await.unwrap_err();
        assert!(error.to_string().contains("private"));
    }

    #[tokio::test]
    async fn broad_ranges_are_rejected_before_scanning() {
        let error = scan("10.0.0.0/8", &[22], &[]).await.unwrap_err();
        assert!(error.to_string().contains("too large"));
    }
}
