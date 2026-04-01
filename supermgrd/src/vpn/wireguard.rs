//! WireGuard backend — drives the Linux kernel directly via the WireGuard
//! netlink API using the `wireguard-control` crate.
//!
//! No subprocesses (`wg`, `ip`) are used for tunnel configuration.  All kernel
//! interactions go through the [`wireguard_control`] crate which speaks the
//! netlink `WG_*` family.
//!
//! # Responsibilities
//!
//! 1. Retrieve the private key from the system keyring.
//! 2. Create the WireGuard kernel interface with `DeviceUpdate`.
//! 3. Assign IP addresses and bring the interface up via rtnetlink.
//! 4. Add peer routes and push DNS servers to `systemd-resolved` over D-Bus.
//! 5. On disconnect, delete the interface via rtnetlink (which removes
//!    interface routes) and restore any displaced default routes.
//!
//! Route management (step 4) still uses subprocess calls (`ip route`).
//! DNS push (step 4) remains a subprocess call via `resolvectl`.
//!
//! # Full-tunnel routing sequence
//!
//! When a peer's `AllowedIPs` includes `0.0.0.0/0` or `::/0`, `add_routes`
//! follows this order to avoid a routing black-hole:
//!
//! 1. Capture the current default route (e.g. `default via 192.168.1.1 dev eth0`).
//! 2. Parse the gateway IP and physical interface from that line.
//! 3. Add a `/32` (or `/128`) host route for **every peer's endpoint** via the
//!    original gateway — this keeps WireGuard UDP traffic flowing through the
//!    physical NIC after the default is replaced.
//! 4. Delete the original default route.
//! 5. Add the tunnel default route: `ip route add 0.0.0.0/0 dev <wg> metric 100`.
//!
//! On disconnect the order is reversed:
//! 1. Delete the WireGuard interface (kernel removes all `dev <wg>` routes).
//! 2. Delete the endpoint host routes (they live on the physical NIC).
//! 3. Restore the original default route.
//!
//! # wireguard-control API notes (v1.7)
//!
//! - `Device::get(name: &InterfaceName, backend: Backend)` → `Result<Device, _>` (backend by value)
//! - `DeviceUpdate::new()…apply(&InterfaceName, Backend)` → `Result<(), _>`
//! - `PeerConfigBuilder::add_allowed_ip(IpAddr, u8)` — addr + prefix-length separately
//! - `PeerConfigBuilder::set_persistent_keepalive_interval(u16)` — renamed from v0.6
//! - `PeerInfo` has two fields: `config: PeerConfig` and `stats: PeerStats`
//! - `PeerStats` has `tx_bytes: u64`, `rx_bytes: u64`, `last_handshake_time: Option<SystemTime>`
//! - Interface deletion is NOT in the crate API; we use rtnetlink directly.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::TryStreamExt as _;
use netlink_packet_route::route::{RouteAttribute, RouteMessage};
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, warn};
use wireguard_control::{Backend, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use supermgr_core::{
    vpn::backend::{BackendStatus, Capabilities, VpnBackend},
    error::BackendError,
    vpn::profile::{Profile, ProfileConfig, SecretRef, WireGuardConfig},
    vpn::state::TunnelStats,
};

use crate::secrets;

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Tracks whether a WireGuard interface is currently owned by this backend,
/// and saves state that must be restored at disconnect time.
#[derive(Debug, Default)]
struct WgState {
    /// The kernel interface name if a tunnel is up.
    interface: Option<String>,

    /// The full default IPv4 route message captured before we displaced it.
    /// `None` if AllowedIPs did not include `0.0.0.0/0` or no pre-existing
    /// default was found.
    saved_default_v4: Option<RouteMessage>,

    /// The full default IPv6 route message captured before we displaced it.
    saved_default_v6: Option<RouteMessage>,

    /// Host routes (`<ip>/32` or `<ip>/128`) added for peer endpoints before
    /// displacing the default route.  These are installed on the *physical*
    /// interface so they survive `ip link delete <wg>` and must be removed
    /// explicitly during disconnect.
    endpoint_host_routes: Vec<String>,

    /// Linux interface index stored after a successful `SetLinkDNS` call to
    /// `systemd-resolved`.  Used to call `RevertLink` on disconnect.
    /// `None` if DNS was not configured (no DNS servers in profile, or the
    /// D-Bus call failed).
    dns_configured_ifindex: Option<i32>,

    /// The client VPN addresses configured on this interface (from `Address =`
    /// in the WireGuard config).  Cached at connect time so `status()` can
    /// return a virtual IP without re-parsing the profile.
    addresses: Vec<ipnet::IpNet>,

    /// Instant at which the tunnel was connected.  Used to give the WireGuard
    /// handshake time to complete before reporting the peer as dead.
    connected_at: Option<std::time::Instant>,
}

// ---------------------------------------------------------------------------
// Module-level route helpers (no &self needed)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// rtnetlink route helpers
// ---------------------------------------------------------------------------

/// Extract gateway IP and output interface index from a RouteMessage.
fn route_gateway_and_oif(msg: &RouteMessage) -> Option<(IpAddr, u32)> {
    let mut gw: Option<IpAddr> = None;
    let mut oif: Option<u32> = None;
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Gateway(addr) => {
                gw = match addr {
                    netlink_packet_route::route::RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
                    netlink_packet_route::route::RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
                    _ => None,
                };
            }
            RouteAttribute::Oif(idx) => oif = Some(*idx),
            _ => {}
        }
    }
    match (gw, oif) {
        (Some(g), Some(o)) => Some((g, o)),
        _ => None,
    }
}

/// Resolve an interface name to its index via rtnetlink.
async fn ifname_to_index(name: &str) -> Result<u32, BackendError> {
    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
    tokio::spawn(conn);

    let mut links = handle.link().get().match_name(name.to_owned()).execute();
    let link = links
        .try_next()
        .await
        .map_err(|e| BackendError::Interface(format!("rtnetlink link get '{name}': {e}")))?
        .ok_or_else(|| BackendError::Interface(format!("interface '{name}' not found")))?;
    Ok(link.header.index)
}

/// Resolve an interface index to its name via rtnetlink.
async fn ifindex_to_name(idx: u32) -> Option<String> {
    let (conn, handle, _) = rtnetlink::new_connection().ok()?;
    tokio::spawn(conn);
    let mut links = handle.link().get().match_index(idx).execute();
    let link = links.try_next().await.ok()??;
    use netlink_packet_route::link::LinkAttribute;
    link.attributes.iter().find_map(|a| {
        if let LinkAttribute::IfName(name) = a { Some(name.clone()) } else { None }
    })
}

/// Capture the current default route for the given address family.
///
/// Returns `None` if no default route exists. Only the first (lowest metric)
/// default is captured; ECMP setups will have the primary restored.
async fn capture_default_route(ipv6: bool) -> Result<Option<RouteMessage>, BackendError> {
    let family = if ipv6 { rtnetlink::IpVersion::V6 } else { rtnetlink::IpVersion::V4 };
    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
    tokio::spawn(conn);

    let mut routes = handle.route().get(family).execute();
    let mut best: Option<RouteMessage> = None;

    while let Some(route) = routes
        .try_next()
        .await
        .map_err(|e| BackendError::Interface(format!("rtnetlink route get: {e}")))?
    {
        // Default route has destination prefix length 0.
        if route.header.destination_prefix_length != 0 {
            continue;
        }
        // Only consider unicast routes in the main table.
        use netlink_packet_route::route::{RouteType, RouteHeader};
        if route.header.kind != RouteType::Unicast {
            continue;
        }
        if route.header.table != RouteHeader::RT_TABLE_MAIN
            && !route.attributes.iter().any(|a| matches!(a, RouteAttribute::Table(254)))
        {
            continue;
        }
        // Take the first (lowest metric) match.
        if best.is_none() {
            let gw_info = route_gateway_and_oif(&route);
            if let Some((gw, oif)) = gw_info {
                let dev_name = ifindex_to_name(oif).await.unwrap_or_else(|| format!("ifindex:{oif}"));
                info!("captured {} default route: via {} dev {}", if ipv6 { "IPv6" } else { "IPv4" }, gw, dev_name);
            }
            best = Some(route);
        }
    }
    Ok(best)
}

/// Delete a default route captured by `capture_default_route`.
///
/// Logged as a warning if deletion fails — the route may not exist.
async fn delete_default_route(saved: &RouteMessage) -> Result<(), BackendError> {
    let ipv6 = saved.header.address_family == netlink_packet_route::AddressFamily::Inet6;
    info!("deleting {} default route via rtnetlink", if ipv6 { "IPv6" } else { "IPv4" });

    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
    tokio::spawn(conn);

    match handle.route().del(saved.clone()).execute().await {
        Ok(()) => {
            info!("deleted {} default route — ok", if ipv6 { "IPv6" } else { "IPv4" });
        }
        Err(e) => {
            warn!("delete {} default route failed: {e} (may be harmless)", if ipv6 { "IPv6" } else { "IPv4" });
        }
    }
    Ok(())
}

/// Restore a previously captured default route.
///
/// A failure is logged as a warning; we do not fail `disconnect` over a
/// restore error since the tunnel itself is already torn down.
async fn restore_default_route(saved: &RouteMessage) -> Result<(), BackendError> {
    let ipv6 = saved.header.address_family == netlink_packet_route::AddressFamily::Inet6;
    info!("restoring {} default route via rtnetlink", if ipv6 { "IPv6" } else { "IPv4" });

    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
    tokio::spawn(conn);

    // Rebuild the route via the add API using the saved message.
    let mut req = handle.route().add();
    *req.message_mut() = saved.clone();
    // Ensure NLM_F_CREATE is set.
    match req.execute().await {
        Ok(()) => {
            info!("restored {} default route — ok", if ipv6 { "IPv6" } else { "IPv4" });
        }
        Err(e) => {
            warn!("restore {} default route failed: {e}", if ipv6 { "IPv6" } else { "IPv4" });
        }
    }
    Ok(())
}

/// Add a host route for a specific IP via a gateway and output interface.
async fn add_host_route(ip: IpAddr, gateway: IpAddr, oif: u32) -> Result<(), BackendError> {
    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
    tokio::spawn(conn);

    let result = match (ip, gateway) {
        (IpAddr::V4(dst), IpAddr::V4(gw)) => {
            handle.route().add()
                .v4()
                .destination_prefix(dst, 32)
                .gateway(gw)
                .output_interface(oif)
                .execute()
                .await
        }
        (IpAddr::V6(dst), IpAddr::V6(gw)) => {
            handle.route().add()
                .v6()
                .destination_prefix(dst, 128)
                .gateway(gw)
                .output_interface(oif)
                .execute()
                .await
        }
        _ => return Err(BackendError::Interface("mixed IPv4/IPv6 gateway mismatch".into())),
    };

    result.map_err(|e| BackendError::Interface(format!("add host route for {ip}: {e}")))
}

/// Delete a host route (endpoint route added during connect).
async fn delete_host_route(cidr: &str) -> Result<(), BackendError> {
    let (ip, prefix) = parse_cidr(cidr)?;

    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
    tokio::spawn(conn);

    // Find the matching route.
    let family = if ip.is_ipv4() { rtnetlink::IpVersion::V4 } else { rtnetlink::IpVersion::V6 };
    let mut routes = handle.route().get(family).execute();
    while let Some(route) = routes.try_next().await
        .map_err(|e| BackendError::Interface(format!("rtnetlink route get: {e}")))?
    {
        if route.header.destination_prefix_length != prefix {
            continue;
        }
        let matches_dst = route.attributes.iter().any(|a| match a {
            RouteAttribute::Destination(addr) => match (addr, ip) {
                (netlink_packet_route::route::RouteAddress::Inet(v4), IpAddr::V4(want)) => *v4 == want,
                (netlink_packet_route::route::RouteAddress::Inet6(v6), IpAddr::V6(want)) => *v6 == want,
                _ => false,
            },
            _ => false,
        });
        if matches_dst {
            let (conn2, handle2, _) = rtnetlink::new_connection()
                .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
            tokio::spawn(conn2);
            match handle2.route().del(route).execute().await {
                Ok(()) => info!("deleted host route {cidr} — ok"),
                Err(e) => warn!("delete host route {cidr} failed: {e} (may already be gone)"),
            }
            return Ok(());
        }
    }
    warn!("host route {cidr} not found for deletion (may already be gone)");
    Ok(())
}

/// Add a route for an AllowedIP CIDR via a WireGuard interface.
async fn add_allowed_ip_route(cidr: &str, iface_index: u32, metric: Option<u32>) -> Result<(), BackendError> {
    let (ip, prefix) = parse_cidr(cidr)?;

    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
    tokio::spawn(conn);

    let result = match ip {
        IpAddr::V4(v4) => {
            let mut req = handle.route().add()
                .v4()
                .destination_prefix(v4, prefix)
                .output_interface(iface_index);
            if let Some(m) = metric { req = req.priority(m); }
            req.execute().await
        }
        IpAddr::V6(v6) => {
            let mut req = handle.route().add()
                .v6()
                .destination_prefix(v6, prefix)
                .output_interface(iface_index);
            if let Some(m) = metric { req = req.priority(m); }
            req.execute().await
        }
    };

    result.map_err(|e| {
        let msg = e.to_string();
        let hint = if msg.contains("Permission denied") || msg.contains("Operation not permitted") {
            " — the daemon must run as root to manage routes"
        } else if msg.contains("File exists") {
            " — a conflicting route already exists; disconnect any other VPN first"
        } else if msg.contains("No such device") {
            " — the WireGuard interface disappeared unexpectedly"
        } else {
            ""
        };
        BackendError::Interface(format!("failed to add route {cidr}: {msg}{hint}"))
    })
}

/// Parse a CIDR string like "10.0.0.1/32" into (IpAddr, prefix_len).
fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), BackendError> {
    let net: ipnet::IpNet = cidr.parse()
        .map_err(|e| BackendError::Interface(format!("invalid CIDR '{cidr}': {e}")))?;
    Ok((net.addr(), net.prefix_len()))
}

// ---------------------------------------------------------------------------
// Backend struct
// ---------------------------------------------------------------------------

/// WireGuard backend — creates and manages a WireGuard kernel interface.
pub struct WireGuardBackend {
    state: Arc<Mutex<WgState>>,
}

impl WireGuardBackend {
    /// Create a new, idle WireGuard backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(WgState::default())),
        }
    }

    /// Retrieve the private key bytes from the system keyring and decode them
    /// as a WireGuard [`Key`].
    ///
    /// The key is stored in the keyring as a base64-encoded UTF-8 string
    /// (the same format used in WireGuard `.conf` files).
    ///
    /// # Errors
    ///
    /// - [`BackendError::Key`] if the secret is missing from the keyring,
    ///   not valid UTF-8, or not valid base64.
    async fn resolve_private_key(&self, secret_ref: &SecretRef) -> Result<Key, BackendError> {
        let raw_bytes = secrets::retrieve_secret(secret_ref.label())
            .await
            .map_err(|e| {
                error!(
                    "credential not found in keyring — please re-import the profile \
                     (label '{}': {e})",
                    secret_ref.label()
                );
                BackendError::Key(format!(
                    "credential not found in keyring — please re-import the profile \
                     (label '{}')",
                    secret_ref.label()
                ))
            })?;

        // The secret is normally stored as base64-encoded UTF-8 (WireGuard .conf
        // format).  However, older imports or TOML backup restores may have stored
        // the raw 32-byte key directly.  Handle both cases gracefully.
        match std::str::from_utf8(&raw_bytes) {
            Ok(raw_str) => Key::from_base64(raw_str.trim())
                .map_err(|e| BackendError::Key(format!("base64 decode failed: {e}"))),
            Err(_) if raw_bytes.len() == 32 => {
                // Raw 32-byte WireGuard key — use directly.
                let arr: [u8; 32] = raw_bytes.try_into().unwrap();
                Ok(Key(arr))
            }
            Err(_) => Err(BackendError::Key(format!(
                "private key bytes are neither valid UTF-8 base64 nor a raw 32-byte key \
                 (got {} bytes)",
                raw_bytes.len()
            ))),
        }
    }

    /// Apply WireGuard configuration to the kernel interface.
    ///
    /// Creates the interface if it does not yet exist.
    #[instrument(skip(self, wg_cfg, private_key), fields(iface = %iface_name))]
    async fn apply_wg_config(
        &self,
        iface_name: &str,
        wg_cfg: &WireGuardConfig,
        private_key: Key,
    ) -> Result<(), BackendError> {
        let iface: InterfaceName = iface_name
            .parse()
            .map_err(|e| BackendError::Interface(format!("invalid interface name '{iface_name}': {e}")))?;

        // Build the device update.
        let mut update = DeviceUpdate::new().set_private_key(private_key);

        if let Some(port) = wg_cfg.listen_port {
            update = update.set_listen_port(port);
        }

        // Add peers.
        for peer in &wg_cfg.peers {
            let peer_key = Key::from_base64(&peer.public_key)
                .map_err(|e| BackendError::Key(format!("peer public key: {e}")))?;

            let mut peer_builder = PeerConfigBuilder::new(&peer_key);

            if let Some(ref ep) = peer.endpoint {
                let addr = tokio::net::lookup_host(ep)
                    .await
                    .map_err(|e| BackendError::Interface(format!(
                        "cannot resolve peer endpoint '{ep}': {e} — \
                         check that the hostname is correct and DNS is working"
                    )))?
                    .next()
                    .ok_or_else(|| BackendError::Interface(format!(
                        "peer endpoint '{ep}' resolved to zero addresses — \
                         verify the hostname in your WireGuard configuration"
                    )))?;
                peer_builder = peer_builder.set_endpoint(addr);
            }

            for allowed_ip in &peer.allowed_ips {
                peer_builder = peer_builder.add_allowed_ip(
                    allowed_ip.addr(),
                    u8::try_from(allowed_ip.prefix_len())
                        .expect("prefix length fits in u8"),
                );
            }

            if let Some(ka) = peer.persistent_keepalive {
                // Renamed in wireguard-control 1.7 from set_persistent_keepalive.
                peer_builder = peer_builder.set_persistent_keepalive_interval(ka);
            }

            if let Some(ref psk_ref) = peer.preshared_key {
                match secrets::retrieve_secret(psk_ref.label()).await {
                    Ok(raw_bytes) => {
                        let psk_result = match std::str::from_utf8(&raw_bytes) {
                            Ok(raw_str) => Key::from_base64(raw_str.trim()),
                            Err(_) if raw_bytes.len() == 32 => {
                                let arr: [u8; 32] = raw_bytes.try_into().unwrap();
                                Ok(Key(arr))
                            }
                            Err(_) => {
                                warn!("PSK bytes not UTF-8 and not 32 bytes for peer {}", &peer.public_key[..8]);
                                Err(wireguard_control::InvalidKey)
                            }
                        };
                        match psk_result {
                            Ok(psk_key) => {
                                peer_builder = peer_builder.set_preshared_key(psk_key);
                                debug!("applied PSK for peer {}", &peer.public_key[..8]);
                            }
                            Err(e) => warn!("PSK decode failed for peer {}: {}", &peer.public_key[..8], e),
                        }
                    }
                    Err(e) => warn!("PSK not found in keyring for peer {}: {}", &peer.public_key[..8], e),
                }
            }

            update = update.add_peer(peer_builder);
        }

        // Apply to the kernel.
        debug!("applying WireGuard config to {}", iface_name);
        update
            .apply(&iface, Backend::Kernel)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("Permission denied") || msg.contains("EPERM") || msg.contains("Operation not permitted") {
                    BackendError::Interface(format!(
                        "permission denied creating WireGuard interface '{iface_name}': \
                         the daemon must run as root (or with CAP_NET_ADMIN) — {e}"
                    ))
                } else if msg.contains("not supported") || msg.contains("ENOTSUP") || msg.contains("No such device") {
                    BackendError::Interface(format!(
                        "WireGuard kernel module not loaded or not available: \
                         ensure CONFIG_WIREGUARD is enabled in your kernel — {e}"
                    ))
                } else {
                    BackendError::Interface(format!("WireGuard DeviceUpdate failed: {e}"))
                }
            })?;

        // Tell NetworkManager not to manage this interface so it does not
        // appear as a new network adapter in the system tray / network applet.
        // Non-fatal: if nmcli is unavailable or NM is not running, log and continue.
        match tokio::process::Command::new("nmcli")
            .args(["device", "set", iface_name, "managed", "no"])
            .output()
            .await
        {
            Ok(out) if out.status.success() => {
                debug!("nmcli: set {iface_name} unmanaged — ok");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                debug!("nmcli: set {iface_name} unmanaged — {} ({})", out.status, stderr.trim());
            }
            Err(e) => debug!("nmcli not available, skipping unmanaged flag: {e}"),
        }

        info!("WireGuard interface {} configured", iface_name);
        Ok(())
    }

    /// Assign IP addresses to the interface and bring it up via rtnetlink.
    #[instrument(skip(self, wg_cfg), fields(iface = %iface_name))]
    async fn assign_addresses(
        &self,
        iface_name: &str,
        wg_cfg: &WireGuardConfig,
    ) -> Result<(), BackendError> {
        let (conn, handle, _) = rtnetlink::new_connection()
            .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
        tokio::spawn(conn);

        // Look up the interface index by name.
        let mut links = handle.link().get().match_name(iface_name.to_owned()).execute();
        let link = links
            .try_next()
            .await
            .map_err(|e| BackendError::Interface(format!("rtnetlink link get '{iface_name}': {e}")))?
            .ok_or_else(|| BackendError::Interface(format!("interface '{iface_name}' not found")))?;
        let if_index = link.header.index;

        // Assign each address.
        for addr in &wg_cfg.addresses {
            debug!("assigning address {} to {} (rtnetlink)", addr, iface_name);
            handle
                .address()
                .add(if_index, addr.addr(), addr.prefix_len())
                .execute()
                .await
                .map_err(|e| {
                    BackendError::Interface(format!("rtnetlink addr add {addr} dev {iface_name}: {e}"))
                })?;
        }

        // Bring the interface up.
        handle
            .link()
            .set(if_index)
            .up()
            .execute()
            .await
            .map_err(|e| {
                BackendError::Interface(format!("rtnetlink link set up '{iface_name}': {e}"))
            })?;

        info!("interface {} brought up with {} address(es) (rtnetlink)", iface_name, wg_cfg.addresses.len());
        Ok(())
    }

    /// Install kernel routes for every `AllowedIPs` entry across all peers.
    ///
    /// For full-tunnel configs (`0.0.0.0/0` or `::/0` in AllowedIPs) the
    /// sequence is:
    /// 1. Capture the current default route via rtnetlink.
    /// 2. Add a `/32` (IPv4) or `/128` (IPv6) host route for **every** peer
    ///    endpoint via the original gateway, so WireGuard UDP traffic continues
    ///    to reach the server after the default is replaced.
    /// 3. Delete the original default route.
    /// 4. Add the AllowedIPs routes (including `0.0.0.0/0 dev <wg> metric 100`).
    ///
    /// Returns `(saved_v4, saved_v6, endpoint_host_routes)` for storage in
    /// `WgState` so `disconnect` can reverse the changes.
    #[instrument(skip(self, wg_cfg), fields(iface = %iface_name))]
    async fn add_routes(
        &self,
        iface_name: &str,
        wg_cfg: &WireGuardConfig,
    ) -> Result<(Option<RouteMessage>, Option<RouteMessage>, Vec<String>), BackendError> {
        let mut saved_v4: Option<RouteMessage> = None;
        let mut saved_v6: Option<RouteMessage> = None;
        let mut endpoint_host_routes: Vec<String> = Vec::new();

        // Determine whether full-tunnel routing is needed for each family.
        let needs_full_tunnel_v4 = wg_cfg.peers.iter().any(|p| {
            p.allowed_ips.iter().any(|ip| ip.to_string() == "0.0.0.0/0")
        });
        let needs_full_tunnel_v6 = wg_cfg.peers.iter().any(|p| {
            p.allowed_ips.iter().any(|ip| ip.to_string() == "::/0")
        });

        // ----------------------------------------------------------------
        // Phase 1: Capture default routes via rtnetlink.
        // ----------------------------------------------------------------
        if needs_full_tunnel_v4 {
            saved_v4 = capture_default_route(false).await?;
        }
        if needs_full_tunnel_v6 {
            saved_v6 = capture_default_route(true).await?;
        }

        // ----------------------------------------------------------------
        // Phase 2: Add endpoint host routes BEFORE displacing the default.
        // ----------------------------------------------------------------
        let gw_v4 = saved_v4.as_ref().and_then(route_gateway_and_oif);
        let gw_v6 = saved_v6.as_ref().and_then(route_gateway_and_oif);

        if needs_full_tunnel_v4 || needs_full_tunnel_v6 {
            for peer in &wg_cfg.peers {
                let Some(ref ep) = peer.endpoint else { continue };

                let ep_ip = match tokio::net::lookup_host(ep.as_str()).await {
                    Ok(mut addrs) => match addrs.next().map(|sa| sa.ip()) {
                        Some(ip) => ip,
                        None => {
                            warn!("endpoint {} resolved to zero addresses — skipping host route", ep);
                            continue;
                        }
                    },
                    Err(e) => {
                        warn!("could not resolve endpoint {} for host route: {e}", ep);
                        continue;
                    }
                };

                let (host_cidr, gw_info, family_active) = if ep_ip.is_ipv4() {
                    (format!("{}/32", ep_ip), gw_v4.as_ref(), needs_full_tunnel_v4)
                } else {
                    (format!("{}/128", ep_ip), gw_v6.as_ref(), needs_full_tunnel_v6)
                };

                if !family_active {
                    continue;
                }

                match gw_info {
                    Some((gw, oif)) => {
                        info!("adding endpoint host route: {} via {} oif {}", host_cidr, gw, oif);
                        match add_host_route(ep_ip, *gw, *oif).await {
                            Ok(()) => {
                                info!("endpoint host route {} — ok", host_cidr);
                                endpoint_host_routes.push(host_cidr);
                            }
                            Err(e) => {
                                warn!("failed to add endpoint host route for {}: {e}", ep);
                            }
                        }
                    }
                    None => {
                        warn!(
                            "full-tunnel active but could not extract gateway from default route \
                             — endpoint host route for {} not added; WireGuard UDP may be lost",
                            ep
                        );
                    }
                }
            }

            // ----------------------------------------------------------------
            // Phase 2b: Persist state BEFORE deleting defaults.
            // ----------------------------------------------------------------
            {
                let mut st = self.state.lock().await;
                st.interface = Some(iface_name.to_owned());
                st.saved_default_v4 = saved_v4.clone();
                st.saved_default_v6 = saved_v6.clone();
                st.endpoint_host_routes = endpoint_host_routes.clone();
            }

            // ----------------------------------------------------------------
            // Phase 3: Displace the original default routes.
            // ----------------------------------------------------------------
            if let Some(ref saved) = saved_v4 {
                delete_default_route(saved).await?;
            }
            if let Some(ref saved) = saved_v6 {
                delete_default_route(saved).await?;
            }
        }

        // ----------------------------------------------------------------
        // Phase 4: Add all AllowedIPs routes via rtnetlink.
        // ----------------------------------------------------------------
        let iface_index = ifname_to_index(iface_name).await?;

        for peer in &wg_cfg.peers {
            for allowed_ip in &peer.allowed_ips {
                let cidr = allowed_ip.to_string();
                let is_default_v4 = cidr == "0.0.0.0/0";
                let is_default_v6 = cidr == "::/0";

                let metric = if is_default_v4 || is_default_v6 { Some(100) } else { None };
                info!("adding route {} dev {}{}", cidr, iface_name,
                    metric.map(|m| format!(" metric {m}")).unwrap_or_default());

                add_allowed_ip_route(&cidr, iface_index, metric).await?;
                debug!("added route {} dev {}", cidr, iface_name);
            }
        }

        Ok((saved_v4, saved_v6, endpoint_host_routes))
    }

    /// Configure per-link DNS via `systemd-resolved` D-Bus (`org.freedesktop.resolve1`).
    ///
    /// Calls `SetLinkDNS(i, a(iay))` and `SetLinkDomains(i, a(sb))` on the
    /// `org.freedesktop.resolve1.Manager` interface.
    ///
    /// For full-tunnel profiles (`0.0.0.0/0` or `::/0` in any peer's
    /// `AllowedIPs`), the catch-all routing domain is added to the domain list.
    /// The D-Bus `a(sb)` array takes plain DNS domain names — the `~` notation
    /// is a display/config-file convention only.  The DNS root is passed as
    /// `"."` with `routing_only = true`; systemd-resolved then routes **all**
    /// DNS queries through the VPN's DNS server, and `resolvectl status`
    /// displays this as `~.`.
    ///
    /// Do NOT pass `"~."` as the domain string — systemd-resolved will not
    /// strip the leading `~` from the D-Bus argument and will instead escape
    /// it as the decimal ASCII code `\126`, causing `resolvectl status` to
    /// display `~\126` instead of `~.`.
    ///
    /// Failures are **non-fatal**: the error is logged and the method returns
    /// `None` so that a missing or unavailable `systemd-resolved` never blocks
    /// tunnel bring-up.
    ///
    /// Returns `Some(ifindex)` when `SetLinkDNS` succeeds (stored in
    /// [`WgState`] so [`disconnect`][Self::disconnect] can call `RevertLink`),
    /// or `None` when DNS was skipped or failed.
    #[instrument(skip(self, wg_cfg), fields(iface = %iface_name))]
    async fn configure_dns(&self, iface_name: &str, wg_cfg: &WireGuardConfig) -> Option<i32> {
        if wg_cfg.dns.is_empty() {
            debug!("no DNS servers in profile — skipping systemd-resolved configuration");
            return None;
        }

        // ----------------------------------------------------------------
        // Interface index (i32 — D-Bus `i` type).
        // ----------------------------------------------------------------
        let ifindex: i32 = match nix::net::if_::if_nametoindex(iface_name) {
            Ok(idx) => idx as i32,
            Err(e) => {
                error!("if_nametoindex({iface_name}): {e}");
                return None;
            }
        };

        // ----------------------------------------------------------------
        // Build DNS address list: D-Bus type `a(iay)`
        // Each tuple is (address_family: i32, address_bytes: Vec<u8>).
        // AF_INET = 2, AF_INET6 = 10 (POSIX / Linux constant).
        // ----------------------------------------------------------------
        let dns_addrs: Vec<(i32, Vec<u8>)> = wg_cfg
            .dns
            .iter()
            .map(|ip| match ip {
                std::net::IpAddr::V4(v4) => (2_i32, v4.octets().to_vec()),
                std::net::IpAddr::V6(v6) => (10_i32, v6.octets().to_vec()),
            })
            .collect();

        // ----------------------------------------------------------------
        // Build domain list: D-Bus type `a(sb)`
        // Each tuple is (domain: String, routing_only: bool).
        //
        //   routing_only = true  → routing domain only (no FQDN search suffix)
        //   routing_only = false → search domain (also used for routing)
        //
        // The D-Bus protocol uses plain DNS domain names.  The `~` prefix is
        // a display/config-file convention that resolvectl and systemd.network
        // strip before making the D-Bus call.  Passing `"~."` over D-Bus
        // causes systemd-resolved to escape the `~` as `\126` (its decimal
        // ASCII code) in the stored domain name, breaking `resolvectl status`.
        //
        // The catch-all routing domain must be passed as `(".", true)`:
        //   "."   — the DNS root domain, ancestor of every valid DNS name
        //   true  — routing-only; systemd-resolved displays this as `~.`
        // ----------------------------------------------------------------
        let is_full_tunnel = wg_cfg.peers.iter().any(|p| {
            p.allowed_ips.iter().any(|ip| {
                let s = ip.to_string();
                s == "0.0.0.0/0" || s == "::/0"
            })
        });

        let mut domains: Vec<(String, bool)> = Vec::new();
        if is_full_tunnel {
            // "." = DNS root, routing_only = true → resolvectl shows as "~."
            domains.push((".".to_owned(), true));
        }
        for search in &wg_cfg.dns_search {
            domains.push((search.clone(), false));
        }

        // ----------------------------------------------------------------
        // Open system bus and build a generic proxy for resolve1.
        // ----------------------------------------------------------------
        let conn = match zbus::Connection::system().await {
            Ok(c) => c,
            Err(e) => {
                error!("D-Bus system connection for DNS config failed: {e}");
                return None;
            }
        };

        let proxy = match zbus::Proxy::new(
            &conn,
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                error!("org.freedesktop.resolve1.Manager proxy failed: {e}");
                return None;
            }
        };

        // ----------------------------------------------------------------
        // SetLinkDNS(i ifindex, a(iay) addresses)
        // ----------------------------------------------------------------
        match proxy
            .call_method("SetLinkDNS", &(ifindex, &dns_addrs))
            .await
        {
            Ok(_) => {
                info!(
                    "SetLinkDNS({iface_name}, {} server(s): {:?}) — ok",
                    dns_addrs.len(),
                    wg_cfg.dns
                );
            }
            Err(e) => {
                error!("SetLinkDNS for {iface_name} failed: {e}");
                return None;
            }
        }

        // ----------------------------------------------------------------
        // Set per-link DNS search/routing domains via `resolvectl domain`.
        //
        // We intentionally avoid SetLinkDomains over D-Bus here.  Although
        // the D-Bus API takes plain domain names (the `~` prefix is a
        // display/config-file convention), zbus/zvariant may transmit the
        // string with unexpected encoding depending on the Rust type used
        // for the `a(sb)` array, causing systemd-resolved to escape the
        // tilde as `\126` in its stored domain name.
        //
        // `resolvectl domain` is the authoritative, stable interface:
        //   - routing-only domains are passed with a leading `~`
        //     (`resolvectl` strips the `~` before calling SetLinkDomains)
        //   - search domains are passed as plain names
        //
        // Non-fatal — a failure here leaves DNS servers active but without
        // domain routing.
        // ----------------------------------------------------------------
        if !domains.is_empty() {
            // Build the argument list: routing-only domains get "~" prefix.
            let domain_args: Vec<String> = domains
                .iter()
                .map(|(d, routing_only)| {
                    if *routing_only {
                        format!("~{d}")
                    } else {
                        d.clone()
                    }
                })
                .collect();

            info!(
                "running: resolvectl domain {} {}",
                iface_name,
                domain_args.join(" ")
            );

            let mut cmd = tokio::process::Command::new("resolvectl");
            cmd.arg("domain").arg(iface_name);
            for arg in &domain_args {
                cmd.arg(arg);
            }

            match cmd.output().await {
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if out.status.success() {
                        info!(
                            "resolvectl domain {iface_name} [{}] — ok",
                            domain_args.join(", ")
                        );
                    } else {
                        // Don't return None — SetLinkDNS succeeded.
                        error!(
                            "resolvectl domain {iface_name} failed: exit={} stderr={:?} \
                             (DNS servers active; domain routing not configured)",
                            out.status,
                            stderr.trim()
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "resolvectl domain {iface_name}: could not spawn process: {e} \
                         (DNS servers active; domain routing not configured)"
                    );
                }
            }
        }

        Some(ifindex)
    }

}

/// Remove a WireGuard kernel interface via rtnetlink.
///
/// Deleting the interface automatically removes all kernel routes whose
/// `dev` is that interface (including any AllowedIPs routes added by
/// `add_routes`).  Endpoint host routes on the physical NIC are NOT
/// removed here — the caller must do that separately.
///
/// Returns `Err(BackendError::Interface(...))` containing "not found" if
/// the interface does not exist (already gone — treat as warning, not error).
#[instrument(fields(iface = %iface_name))]
async fn delete_interface(iface_name: &str) -> Result<(), BackendError> {
    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
    tokio::spawn(conn);

    let mut links = handle.link().get().match_name(iface_name.to_owned()).execute();
    let link = links
        .try_next()
        .await
        .map_err(|e| BackendError::Interface(format!("rtnetlink link get '{iface_name}': {e}")))?
        .ok_or_else(|| {
            // Interface not found — treat as already gone (idempotent).
            BackendError::Interface(format!("interface '{iface_name}' not found for deletion"))
        })?;

    handle
        .link()
        .del(link.header.index)
        .execute()
        .await
        .map_err(|e| BackendError::Interface(format!("rtnetlink link del '{iface_name}': {e}")))?;

    info!("deleted WireGuard interface {} (rtnetlink)", iface_name);
    Ok(())
}

impl Default for WireGuardBackend {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// VpnBackend implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl VpnBackend for WireGuardBackend {
    #[instrument(skip(self, profile), fields(profile_id = %profile.id, profile_name = %profile.name))]
    async fn connect(&self, profile: &Profile) -> Result<(), BackendError> {
        let wg_cfg = match &profile.config {
            ProfileConfig::WireGuard(cfg) => cfg,
            other => {
                return Err(BackendError::Config(format!(
                    "WireGuardBackend cannot handle '{}' profile",
                    other.backend_name()
                )));
            }
        };

        // Guard against double-connect.
        {
            let state = self.state.lock().await;
            if state.interface.is_some() {
                return Err(BackendError::AlreadyConnected);
            }
        }

        let iface_name = profile
            .wg_interface_name()
            .expect("wg_interface_name is always Some for WireGuard profiles");

        // 1. Retrieve the private key from the system keyring.
        let private_key = self.resolve_private_key(&wg_cfg.private_key).await?;

        // Build an effective config that reflects the full_tunnel toggle.
        // We clone so that the stored profile is never mutated.
        //   full_tunnel=true  → ensure 0.0.0.0/0 and ::/0 are in AllowedIPs
        //   full_tunnel=false → remove 0.0.0.0/0 and ::/0 (use explicit routes only)
        let effective_cfg: std::borrow::Cow<'_, WireGuardConfig> = if profile.full_tunnel {
            let has_v4 = wg_cfg.peers.iter().any(|p| {
                p.allowed_ips.iter().any(|ip| ip.to_string() == "0.0.0.0/0")
            });
            let has_v6 = wg_cfg.peers.iter().any(|p| {
                p.allowed_ips.iter().any(|ip| ip.to_string() == "::/0")
            });
            if has_v4 && has_v6 {
                std::borrow::Cow::Borrowed(wg_cfg)
            } else {
                let mut cfg = wg_cfg.clone();
                for peer in &mut cfg.peers {
                    if !has_v4 {
                        peer.allowed_ips.push("0.0.0.0/0".parse().expect("static"));
                    }
                    if !has_v6 {
                        peer.allowed_ips.push("::/0".parse().expect("static"));
                    }
                }
                std::borrow::Cow::Owned(cfg)
            }
        } else {
            // Split-tunnel: use explicit split_routes if configured, otherwise
            // strip catch-alls from AllowedIPs and keep specific prefixes.
            let mut cfg = wg_cfg.clone();
            if !wg_cfg.split_routes.is_empty() {
                // Replace every peer's AllowedIPs with the configured split routes.
                for peer in &mut cfg.peers {
                    peer.allowed_ips = wg_cfg.split_routes.clone();
                }
                std::borrow::Cow::Owned(cfg)
            } else {
                // Fall back: strip catch-alls, keep explicit prefixes.
                let has_catch_all = wg_cfg.peers.iter().any(|p| {
                    p.allowed_ips.iter().any(|ip| {
                        let s = ip.to_string();
                        s == "0.0.0.0/0" || s == "::/0"
                    })
                });
                if has_catch_all {
                    for peer in &mut cfg.peers {
                        peer.allowed_ips.retain(|ip| {
                            let s = ip.to_string();
                            s != "0.0.0.0/0" && s != "::/0"
                        });
                    }
                }
                // If no routes remain after stripping, refuse to connect.
                let has_routes = cfg.peers.iter().any(|p| !p.allowed_ips.is_empty());
                if !has_routes {
                    return Err(BackendError::Config(
                        "split-tunnel is enabled but no routes are configured — \
                         add subnets to 'split_routes' in the WireGuard profile, \
                         or disable split-tunnel".into(),
                    ));
                }
                std::borrow::Cow::Owned(cfg)
            }
        };
        let wg_cfg = effective_cfg.as_ref();

        // 2. Create / configure the WireGuard kernel interface.
        self.apply_wg_config(&iface_name, wg_cfg, private_key).await?;

        // 3. Assign addresses and bring the interface up.
        self.assign_addresses(&iface_name, wg_cfg).await?;

        // 4. Add routes for peer AllowedIPs.
        //    For full-tunnel configs this also captures the original default
        //    route, pins endpoint host routes on the physical NIC, and then
        //    displaces the default before adding the tunnel default route.
        let (saved_v4, saved_v6, endpoint_host_routes) =
            self.add_routes(&iface_name, wg_cfg).await?;

        // 5. Configure DNS (non-fatal — returns None on failure).
        let dns_ifindex = self.configure_dns(&iface_name, wg_cfg).await;

        // Record active interface and all state needed for clean disconnect.
        {
            let mut state = self.state.lock().await;
            state.interface = Some(iface_name.clone());
            state.saved_default_v4 = saved_v4;
            state.saved_default_v6 = saved_v6;
            state.endpoint_host_routes = endpoint_host_routes;
            state.dns_configured_ifindex = dns_ifindex;
            state.addresses = wg_cfg.addresses.clone();
            state.connected_at = Some(std::time::Instant::now());
        }

        info!("WireGuard tunnel {} is up", iface_name);
        Ok(())
    }

    #[instrument(skip(self))]
    async fn disconnect(&self) -> Result<(), BackendError> {
        let (iface_name, saved_v4, saved_v6, endpoint_host_routes, dns_ifindex) = {
            let state = self.state.lock().await;
            match state.interface.clone() {
                Some(name) => (
                    name,
                    state.saved_default_v4.clone(),
                    state.saved_default_v6.clone(),
                    state.endpoint_host_routes.clone(),
                    state.dns_configured_ifindex,
                ),
                None => {
                    debug!("disconnect called but no interface is active — no-op");
                    return Ok(());
                }
            }
        };

        // Step 0: Revert systemd-resolved DNS settings before the interface
        // disappears.  RevertLink removes all per-link DNS servers and domains
        // that were previously set with SetLinkDNS / SetLinkDomains.
        if let Some(ifindex) = dns_ifindex {
            match zbus::Connection::system().await {
                Ok(conn) => {
                    match zbus::Proxy::new(
                        &conn,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                    )
                    .await
                    {
                        Ok(proxy) => {
                            match proxy.call_method("RevertLink", &(ifindex,)).await {
                                Ok(_) => info!("RevertLink({iface_name}) — ok"),
                                Err(e) => warn!("RevertLink({iface_name}) failed: {e}"),
                            }
                        }
                        Err(e) => warn!("resolve1 proxy for RevertLink failed: {e}"),
                    }
                }
                Err(e) => warn!("D-Bus connection for RevertLink failed: {e}"),
            }
        }

        // Step 1: Delete the WireGuard interface.  The kernel automatically
        // removes all routes whose `dev` is that interface (AllowedIPs routes,
        // the tunnel default route, etc.).
        match delete_interface(&iface_name).await {
            Ok(()) => {}
            Err(BackendError::Interface(ref msg)) if msg.contains("not found") => {
                warn!("delete_interface: {msg} — interface already gone, continuing disconnect");
            }
            Err(e) => return Err(e),
        }

        // Step 2: Remove endpoint host routes via rtnetlink.  These were
        // installed on the physical interface and survive interface deletion.
        for cidr in &endpoint_host_routes {
            info!("removing endpoint host route: {}", cidr);
            if let Err(e) = delete_host_route(cidr).await {
                warn!("delete endpoint host route {}: {e}", cidr);
            }
        }

        // Step 3: Restore the original default routes via rtnetlink.
        if let Some(ref saved) = saved_v4 {
            restore_default_route(saved).await?;
        }
        if let Some(ref saved) = saved_v6 {
            restore_default_route(saved).await?;
        }

        {
            let mut state = self.state.lock().await;
            state.interface = None;
            state.saved_default_v4 = None;
            state.saved_default_v6 = None;
            state.endpoint_host_routes = Vec::new();
            state.dns_configured_ifindex = None;
        }

        info!("WireGuard tunnel {} torn down", iface_name);
        Ok(())
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let (iface_name, cached_addresses, connected_at): (String, Vec<ipnet::IpNet>, Option<std::time::Instant>) = {
            let state = self.state.lock().await;
            match state.interface.clone() {
                Some(name) => (name, state.addresses.clone(), state.connected_at),
                None => return Ok(BackendStatus::Inactive),
            }
        };

        let iface: InterfaceName = iface_name
            .parse()
            .map_err(|e| BackendError::Interface(format!("invalid name: {e}")))?;

        let device = wireguard_control::Device::get(&iface, Backend::Kernel)
            .map_err(|e| BackendError::Interface(format!("get device: {e}")))?;

        // Aggregate stats across all peers.
        // In wireguard-control 1.7, traffic counters and handshake time moved
        // from PeerConfig to PeerStats, accessed via peer.stats.
        let mut bytes_tx: u64 = 0;
        let mut bytes_rx: u64 = 0;
        let mut last_handshake: Option<chrono::DateTime<chrono::Utc>> = None;

        for peer in &device.peers {
            bytes_tx += peer.stats.tx_bytes;
            bytes_rx += peer.stats.rx_bytes;

            if let Some(lhs) = peer.stats.last_handshake_time {
                use std::time::UNIX_EPOCH;
                let secs: u64 = lhs
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                // chrono 0.4.27+: from_timestamp returns Option<DateTime<Utc>>.
                if let Some(dt) = chrono::DateTime::from_timestamp(secs as i64, 0) {
                    last_handshake =
                        Some(last_handshake.map_or(dt, |prev: chrono::DateTime<chrono::Utc>| {
                            prev.max(dt)
                        }));
                }
            }
        }

        // Collect AllowedIPs from all peers as the active routes.
        let active_routes: Vec<String> = device
            .peers
            .iter()
            .flat_map(|p| {
                p.config
                    .allowed_ips
                    .iter()
                    .map(|ai| format!("{}/{}", ai.address, ai.cidr))
            })
            .collect();

        // Dead-peer detection: if the tunnel has been up for more than 30 s
        // and no handshake has been seen in the last 180 s (WireGuard's
        // REJECT_AFTER_TIME), treat the peer as gone and report Inactive so
        // the monitor task can trigger kill-switch strict mode / reconnect.
        const HANDSHAKE_GRACE_SECS: u64 = 30;
        const DEAD_PEER_SECS: i64 = 180;
        let now = chrono::Utc::now();
        let been_up_long_enough = connected_at
            .map(|t| t.elapsed().as_secs() >= HANDSHAKE_GRACE_SECS)
            .unwrap_or(true);

        if been_up_long_enough {
            let peer_dead = match last_handshake {
                None => true,
                Some(hs) => (now - hs).num_seconds() > DEAD_PEER_SECS,
            };
            if peer_dead {
                warn!(
                    "WireGuard peer dead — no handshake in {}s, reporting Inactive",
                    match last_handshake {
                        None => DEAD_PEER_SECS + 1,
                        Some(hs) => (now - hs).num_seconds(),
                    }
                );
                return Ok(BackendStatus::Inactive);
            }
        }

        // Use the first configured address as the virtual IP.
        let virtual_ip = cached_addresses
            .first()
            .map(|a| a.to_string())
            .unwrap_or_default();

        Ok(BackendStatus::Active {
            interface: iface_name,
            stats: TunnelStats {
                bytes_sent: bytes_tx,
                bytes_received: bytes_rx,
                last_handshake,
                rtt_ms: None,
                ..TunnelStats::default()
            },
            virtual_ip,
            active_routes,
        })
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            split_tunnel: true,
            full_tunnel: true,
            dns_push: true,
            persistent_keepalive: true,
            config_import: true,
        }
    }

    fn name(&self) -> &'static str {
        "WireGuard"
    }
}
