//! Bounded local-network TCP discovery.

use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::{bail, Context as _};
use futures_util::{
    stream::{self, FuturesUnordered},
    StreamExt as _,
};
use ipnet::Ipv4Net;
use tokio::sync::Semaphore;

use supermgr_core::{
    host::Host,
    recon::{service_hint, ReconHost, ReconScanResult, ReconService},
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
    let started_at = chrono::Utc::now();
    let (known, warnings) = resolve_inventory(network, managed.to_vec()).await;
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
                probe(address, port == 22).await.map(|banner| ReconService {
                    port,
                    name: if banner.is_some() {
                        "SSH"
                    } else {
                        service_hint(port)
                    }
                    .into(),
                    source: if banner.is_some() {
                        "ssh_banner"
                    } else {
                        "port"
                    }
                    .into(),
                    banner,
                })
            });
            let services: Vec<_> = futures_util::future::join_all(probes)
                .await
                .into_iter()
                .flatten()
                .collect();
            let open_ports: Vec<u16> = services.iter().map(|s| s.port).collect();
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
                services,
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
        warnings,
    })
}

type InventoryMap = HashMap<String, (String, String, String)>;

async fn resolve_inventory(network: Ipv4Net, managed: Vec<Host>) -> (InventoryMap, Vec<String>) {
    let resolved = stream::iter(managed.into_iter().map(|host| async move {
        let addresses = if let Ok(ip) = host.hostname.parse::<Ipv4Addr>() {
            Ok(vec![ip])
        } else {
            match tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::lookup_host((host.hostname.as_str(), host.port)),
            )
            .await
            {
                Ok(Ok(addresses)) => Ok(addresses
                    .filter_map(|a| match a.ip() {
                        std::net::IpAddr::V4(ip) => Some(ip),
                        _ => None,
                    })
                    .collect()),
                _ => Err(format!("Inventory DNS lookup failed: {}", host.hostname)),
            }
        };
        (host, addresses)
    }))
    .buffer_unordered(16)
    .collect::<Vec<_>>()
    .await;
    let mut known = HashMap::new();
    let mut warnings = Vec::new();
    for (host, addresses) in resolved {
        match addresses {
            Ok(addresses) => {
                for ip in addresses.into_iter().filter(|ip| network.contains(ip)) {
                    known.entry(ip.to_string()).or_insert_with(|| {
                        (
                            host.id.to_string(),
                            host.label.clone(),
                            host.customer.clone(),
                        )
                    });
                }
            }
            Err(error) => warnings.push(error),
        }
    }
    warnings.sort();
    (known, warnings)
}

/// No application payload or authentication is sent. SSH servers volunteer a greeting.
async fn probe(address: std::net::SocketAddr, read_ssh_banner: bool) -> Option<Option<String>> {
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};
    let stream = tokio::time::timeout(
        Duration::from_millis(650),
        tokio::net::TcpStream::connect(address),
    )
    .await
    .ok()?
    .ok()?;
    if !read_ssh_banner {
        return Some(None);
    }
    let mut reader = tokio::io::BufReader::new(stream).take(512);
    let mut line = Vec::new();
    let banner = match tokio::time::timeout(
        Duration::from_millis(400),
        reader.read_until(b'\n', &mut line),
    )
    .await
    {
        Ok(Ok(_)) => ssh_banner(&line),
        _ => None,
    };
    Some(banner)
}

fn ssh_banner(bytes: &[u8]) -> Option<String> {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control())
        .take(255)
        .collect();
    (text.starts_with("SSH-2.0-") || text.starts_with("SSH-1.99-")).then_some(text)
}

fn is_local(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dns_inventory_matches_addresses_in_scope() {
        let host: Host = serde_json::from_value(serde_json::json!({
            "label":"Local fixture","hostname":"localhost","username":"test","auth_method":"password"
        })).unwrap();
        let (known, warnings) = resolve_inventory("127.0.0.0/24".parse().unwrap(), vec![host]).await;
        assert!(warnings.is_empty());
        assert!(known.contains_key("127.0.0.1"));
        assert!(!known.contains_key("192.0.2.1"));
    }

    #[tokio::test]
    async fn ssh_greeting_is_observed_without_sending_any_payload() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-TestFixture\r\n").await.unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        });
        assert_eq!(
            probe(address, true).await,
            Some(Some("SSH-2.0-TestFixture".into()))
        );
        server.await.unwrap();
        assert!(ssh_banner(b"HTTP/1.1 200 OK\r\n").is_none());
    }

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
