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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt as _;
use rtnetlink::{LinkUnspec, RouteMessageBuilder};
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, warn};
use wireguard_control::{Backend, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use supermgr_core::{
    error::BackendError,
    vpn::backend::{BackendStatus, Capabilities, VpnBackend},
    vpn::profile::{Profile, ProfileConfig, SecretRef, WireGuardConfig},
    vpn::state::TunnelStats,
};

use crate::secrets;

/// Dedicated WireGuard `fwmark` and routing table ID (`0xca6c`, matching `wg-quick`).
pub const WG_FWMARK_TABLE: u32 = 51820;

/// Timeout for single-shot peer endpoint DNS resolution (`P2-35`).
const ENDPOINT_DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for `ip`, `modprobe`, `nmcli`, and `resolvectl` helper commands (`P3-12`).
const WG_CMD_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Tracks whether a WireGuard interface is currently owned by this backend,
/// and records resources that must be cleaned up on disconnect or error.
#[derive(Debug, Default)]
struct WgState {
    /// The kernel interface name if a tunnel is up (or mid-bring-up).
    interface: Option<String>,

    /// True if IPv4 policy routing rules (`table 51820`) were installed.
    policy_routing_v4: bool,

    /// True if IPv6 policy routing rules (`table 51820`) were installed.
    policy_routing_v6: bool,

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
// Endpoint resolution & policy-routing helpers
// ---------------------------------------------------------------------------

/// Resolve a single WireGuard peer endpoint (`host:port` or literal `ip:port`),
/// falling back to `cached` if live DNS fails (e.g. when a persisted kill
/// switch blocks outbound DNS during reconnect, `P2-35`).
async fn resolve_single_endpoint(
    ep: &str,
    cached: &HashMap<String, SocketAddr>,
) -> Result<SocketAddr, BackendError> {
    let trimmed = ep.trim();
    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Ok(sock);
    }

    match tokio::time::timeout(ENDPOINT_DNS_TIMEOUT, tokio::net::lookup_host(trimmed)).await {
        Ok(Ok(mut addrs)) => {
            if let Some(addr) = addrs.next() {
                return Ok(addr);
            }
            if let Some(&fallback) = cached.get(trimmed) {
                warn!(
                    "peer endpoint '{trimmed}' returned zero DNS records; \
                     using cached endpoint {fallback}"
                );
                return Ok(fallback);
            }
            Err(BackendError::Interface(format!(
                "peer endpoint '{trimmed}' resolved to zero addresses — \
                 verify the hostname in your WireGuard configuration"
            )))
        }
        Ok(Err(e)) => {
            if let Some(&fallback) = cached.get(trimmed) {
                warn!(
                    "DNS lookup failed for peer endpoint '{trimmed}' ({e}); \
                     using cached endpoint {fallback}"
                );
                return Ok(fallback);
            }
            Err(BackendError::Interface(format!(
                "cannot resolve peer endpoint '{trimmed}': {e} — \
                 check that the hostname is correct and DNS is working"
            )))
        }
        Err(_) => {
            if let Some(&fallback) = cached.get(trimmed) {
                warn!(
                    "DNS lookup timed out for peer endpoint '{trimmed}'; \
                     using cached endpoint {fallback}"
                );
                return Ok(fallback);
            }
            Err(BackendError::Interface(format!(
                "timed out resolving peer endpoint '{trimmed}' after {}s",
                ENDPOINT_DNS_TIMEOUT.as_secs()
            )))
        }
    }
}

/// Resolve all configured peer endpoints (`host:port` → [`SocketAddr`]) once
/// before kill-switch and interface setup (`P2-35`).
///
/// # Errors
///
/// Returns [`BackendError::Interface`] if any peer endpoint cannot be resolved
/// and has no entry in `cached`.
pub async fn resolve_wg_endpoints(
    wg_cfg: &WireGuardConfig,
    cached: &HashMap<String, SocketAddr>,
) -> Result<HashMap<String, SocketAddr>, BackendError> {
    let mut resolved = HashMap::new();
    for peer in &wg_cfg.peers {
        let Some(ref ep) = peer.endpoint else {
            continue;
        };
        let key = ep.trim().to_owned();
        if resolved.contains_key(&key) {
            continue;
        }
        let addr = resolve_single_endpoint(&key, cached).await?;
        resolved.insert(key, addr);
    }
    Ok(resolved)
}

/// Check whether `ip -4/-6 rule show` output already contains the `not fwmark`
/// lookup rule for [`WG_FWMARK_TABLE`].
fn has_fwmark_policy_rule(rule_output: &str) -> bool {
    let dec = WG_FWMARK_TABLE.to_string();
    let hex = format!("0x{WG_FWMARK_TABLE:x}");
    rule_output.lines().any(|line| {
        line.contains("not")
            && line.contains("fwmark")
            && (line.contains(&dec) || line.contains(&hex))
            && line.contains(&format!("lookup {dec}"))
    })
}

/// Check whether `ip -4/-6 rule show` output already contains
/// `lookup main suppress_prefixlength 0`.
fn has_suppress_prefix_rule(rule_output: &str) -> bool {
    rule_output
        .lines()
        .any(|line| line.contains("lookup main") && line.contains("suppress_prefixlength 0"))
}

/// Install `wg-quick`-equivalent policy routing for IPv4 or IPv6 (`P2-31`).
async fn install_policy_default_route(iface_name: &str, ipv6: bool) -> Result<(), BackendError> {
    let family_flag = if ipv6 { "-6" } else { "-4" };
    let default_cidr = if ipv6 { "::/0" } else { "0.0.0.0/0" };
    let table_str = WG_FWMARK_TABLE.to_string();

    let route_out = crate::subprocess::run_system_cmd(
        &["ip"],
        &[
            family_flag,
            "route",
            "replace",
            default_cidr,
            "dev",
            iface_name,
            "table",
            &table_str,
        ],
        WG_CMD_TIMEOUT,
    )
    .await
    .map_err(|e| {
        BackendError::Interface(format!(
            "ip {family_flag} route replace {default_cidr} table {table_str}: {e}"
        ))
    })?;
    if !route_out.status.success() {
        let stderr = String::from_utf8_lossy(&route_out.stderr);
        return Err(BackendError::Interface(format!(
            "ip {family_flag} route replace {default_cidr} dev {iface_name} table {table_str} failed: {}",
            stderr.trim()
        )));
    }

    let existing_rules =
        crate::subprocess::run_system_cmd(&["ip"], &[family_flag, "rule", "show"], WG_CMD_TIMEOUT)
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();

    // Order matters: adding `not fwmark 51820 table 51820` first and
    // `table main suppress_prefixlength 0` second assigns the lower rule
    // priority number to `suppress_prefixlength 0`, matching `wg-quick` so
    // non-/0 routes in `main` are evaluated before table 51820.
    if !has_fwmark_policy_rule(&existing_rules) {
        let out = crate::subprocess::run_system_cmd(
            &["ip"],
            &[
                family_flag,
                "rule",
                "add",
                "not",
                "fwmark",
                &table_str,
                "table",
                &table_str,
            ],
            WG_CMD_TIMEOUT,
        )
        .await
        .map_err(|e| {
            BackendError::Interface(format!(
                "ip {family_flag} rule add not fwmark {table_str} table {table_str}: {e}"
            ))
        })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(BackendError::Interface(format!(
                "ip {family_flag} rule add not fwmark {table_str} table {table_str} failed: {}",
                stderr.trim()
            )));
        }
    }

    if !has_suppress_prefix_rule(&existing_rules) {
        let out = crate::subprocess::run_system_cmd(
            &["ip"],
            &[
                family_flag,
                "rule",
                "add",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ],
            WG_CMD_TIMEOUT,
        )
        .await
        .map_err(|e| {
            BackendError::Interface(format!(
                "ip {family_flag} rule add table main suppress_prefixlength 0: {e}"
            ))
        })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(BackendError::Interface(format!(
                "ip {family_flag} rule add table main suppress_prefixlength 0 failed: {}",
                stderr.trim()
            )));
        }
    }

    info!(
        "installed WireGuard {} policy routing via table {} on {}",
        if ipv6 { "IPv6" } else { "IPv4" },
        table_str,
        iface_name
    );
    Ok(())
}

/// Remove WireGuard policy routing rules and flush routing table [`WG_FWMARK_TABLE`]
/// for the requested address families (`P2-31`, `P2-34`).
///
/// Safe and idempotent to call during disconnect, failed connect cleanup, or
/// daemon startup recovery.
pub async fn cleanup_policy_rules(ipv4: bool, ipv6: bool) {
    let table_str = WG_FWMARK_TABLE.to_string();
    for (enabled, family_flag) in [(ipv4, "-4"), (ipv6, "-6")] {
        if !enabled {
            continue;
        }
        // Loop up to 8 times to clear any duplicate rules without risking an infinite loop.
        for _ in 0..8 {
            match crate::subprocess::run_system_cmd(
                &["ip"],
                &[
                    family_flag,
                    "rule",
                    "del",
                    "not",
                    "fwmark",
                    &table_str,
                    "table",
                    &table_str,
                ],
                WG_CMD_TIMEOUT,
            )
            .await
            {
                Ok(out) if out.status.success() => {
                    debug!(
                        "removed ip {family_flag} rule not fwmark {table_str} table {table_str}"
                    );
                }
                _ => break,
            }
        }
        for _ in 0..8 {
            match crate::subprocess::run_system_cmd(
                &["ip"],
                &[
                    family_flag,
                    "rule",
                    "del",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ],
                WG_CMD_TIMEOUT,
            )
            .await
            {
                Ok(out) if out.status.success() => {
                    debug!("removed ip {family_flag} rule table main suppress_prefixlength 0");
                }
                _ => break,
            }
        }
        let _ = crate::subprocess::run_system_cmd(
            &["ip"],
            &[family_flag, "route", "flush", "table", &table_str],
            WG_CMD_TIMEOUT,
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// rtnetlink route helpers
// ---------------------------------------------------------------------------

/// True when rtnetlink returned the specified kernel errno.
///
/// Matching the numeric code avoids depending on the host locale or on the
/// wording chosen by rtnetlink's `Display` implementation.
fn rtnetlink_has_errno(error: &rtnetlink::Error, errno: nix::errno::Errno) -> bool {
    matches!(
        error,
        rtnetlink::Error::NetlinkError(message)
            if message.to_io().raw_os_error() == Some(errno as i32)
    )
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

/// Add a route for an AllowedIP CIDR via a WireGuard interface.
async fn add_allowed_ip_route(
    cidr: &str,
    iface_index: u32,
    metric: Option<u32>,
) -> Result<(), BackendError> {
    let (ip, prefix) = parse_cidr(cidr)?;

    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Interface(format!("rtnetlink: {e}")))?;
    tokio::spawn(conn);

    let route = match ip {
        IpAddr::V4(v4) => {
            let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(v4, prefix)
                .output_interface(iface_index);
            if let Some(m) = metric {
                builder = builder.priority(m);
            }
            builder.build()
        }
        IpAddr::V6(v6) => {
            let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(v6, prefix)
                .output_interface(iface_index);
            if let Some(m) = metric {
                builder = builder.priority(m);
            }
            builder.build()
        }
    };
    let result = handle.route().add(route).execute().await;

    result.map_err(|e| {
        let hint = if rtnetlink_has_errno(&e, nix::errno::Errno::EACCES)
            || rtnetlink_has_errno(&e, nix::errno::Errno::EPERM)
        {
            " — the daemon must run as root to manage routes"
        } else if rtnetlink_has_errno(&e, nix::errno::Errno::EEXIST) {
            " — a conflicting route already exists; disconnect any other VPN first"
        } else if rtnetlink_has_errno(&e, nix::errno::Errno::ENODEV) {
            " — the WireGuard interface disappeared unexpectedly"
        } else {
            ""
        };
        BackendError::Interface(format!("failed to add route {cidr}: {e}{hint}"))
    })
}

/// Parse a CIDR string like "10.0.0.1/32" into (IpAddr, prefix_len).
fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), BackendError> {
    let net: ipnet::IpNet = cidr
        .parse()
        .map_err(|e| BackendError::Interface(format!("invalid CIDR '{cidr}': {e}")))?;
    Ok((net.addr(), net.prefix_len()))
}

// ---------------------------------------------------------------------------
// Kernel module preflight
// ---------------------------------------------------------------------------

/// Load the WireGuard module if the kernel does not already have it.
///
/// Every mainstream distro ships WireGuard as `CONFIG_WIREGUARD=m` rather than
/// built in, so on a freshly booted machine that has never run a tunnel the
/// module is usually absent. Creating the interface through the generic-netlink
/// `wireguard` family does not autoload it the way creating a `wireguard`-type
/// link would — the family simply is not registered, and the netlink call comes
/// back `ENOTSUP`. Without this the daemon reported that as a kernel that
/// cannot do WireGuard at all.
///
/// Best-effort by design: a failure here is not returned. The module may be
/// built in (nothing to load), and if it genuinely is unavailable the apply
/// below fails anyway, with [`wireguard_unsupported_hint`] to explain it.
async fn ensure_module_loaded() {
    if std::path::Path::new("/sys/module/wireguard").exists() {
        debug!("WireGuard module already in the kernel");
        return;
    }

    match crate::subprocess::run_system_cmd(&["modprobe"], &["wireguard"], WG_CMD_TIMEOUT).await {
        Ok(out) if out.status.success() => info!("loaded the WireGuard kernel module"),
        Ok(out) => debug!(
            "modprobe wireguard: exit={} stderr={:?}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => debug!("modprobe not available: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Backend struct
// ---------------------------------------------------------------------------

/// WireGuard backend — creates and manages a WireGuard kernel interface.
/// Explain an `EOPNOTSUPP` from interface creation in terms of what to do
/// about it.
///
/// The kernel gives the same answer whether the module is missing from the
/// build or merely not inserted, and the old message picked the rarer one:
/// it told the operator to check `CONFIG_WIREGUARD`, which on a stock kernel
/// is already `=m` and sends them reading kernel configs when the fix is one
/// `modprobe`. Every kernel since 5.6 ships the module, so "not loaded" is
/// the overwhelmingly likely case and goes first.
///
/// `/sys/module/<name>` is the cheapest way to tell the two apart: present
/// means loaded, and if it is loaded then the failure is something else and
/// saying "modprobe it" would be actively misleading.
fn wireguard_unsupported_hint(err: &str) -> String {
    if std::path::Path::new("/sys/module/wireguard").exists() {
        return format!(
            "the kernel refused to create a WireGuard interface even though the \
             wireguard module is loaded — {err}"
        );
    }
    wireguard_unsupported_hint_for(kernel_module_tree_state(), err)
}

/// The wording for a given tree state, split out so each branch can be
/// exercised without arranging a matching `/lib/modules` on the test machine.
fn wireguard_unsupported_hint_for(state: ModuleTree, err: &str) -> String {
    match state {
        ModuleTree::Stale { running, newest } => format!(
            "the running kernel is {running}, but its modules are gone from \
             /lib/modules — {newest} is what is installed now. A kernel update \
             removed the tree the running one loads from, so nothing can be \
             modprobed until you reboot. Reboot and try again — {err}"
        ),
        ModuleTree::Missing { running } => format!(
            "there is no /lib/modules/{running} for the running kernel, so no \
             module can be loaded at all. This normally means the kernel was \
             updated or removed since boot; reboot into the installed kernel \
             and try again — {err}"
        ),
        ModuleTree::Present => format!(
            "the WireGuard kernel module is not loaded. Load it with \
             `sudo modprobe wireguard`, and install \
             contrib/modules-load.d/supermgr.conf to /etc/modules-load.d/ so it \
             comes back after a reboot — `scripts/install-linux.sh` does both. \
             If modprobe says the module does not exist, this kernel was built \
             without CONFIG_WIREGUARD, which is unusual since 5.6 — {err}"
        ),
    }
}

/// Whether the running kernel still has a module tree to load from.
#[derive(Debug, PartialEq, Eq)]
enum ModuleTree {
    /// `/lib/modules/<running>` is there; a missing module is a real absence.
    Present,
    /// It is not, and something newer is — a kernel update without a reboot.
    Stale { running: String, newest: String },
    /// It is not, and nothing else is either.
    Missing { running: String },
}

/// Classify `/lib/modules` against the running kernel release.
///
/// Worth doing because the three cases have completely different remedies and
/// the kernel reports the same `EOPNOTSUPP` for all of them. On a rolling
/// distribution the common one is the middle case: `pacman -Syu` replaces the
/// module tree, the running kernel's is deleted, and every `modprobe` fails
/// with "not found in directory /lib/modules/<running>" even though the
/// kernel was built with the module. Telling that operator to check
/// `CONFIG_WIREGUARD` wastes their evening; the answer is "reboot".
fn kernel_module_tree_state() -> ModuleTree {
    let running = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();

    if running.is_empty() {
        return ModuleTree::Present; // nothing to reason about; keep the generic advice
    }
    if std::path::Path::new(&format!("/lib/modules/{running}")).exists() {
        return ModuleTree::Present;
    }

    // Any other tree present means a different kernel is installed. Not sorted
    // by version — "newest" here just needs to name one for the operator, and
    // version-comparing distro kernel strings is its own swamp.
    let other = std::fs::read_dir("/lib/modules").ok().and_then(|entries| {
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| *n != running)
            .collect();
        names.sort();
        names.pop()
    });

    match other {
        Some(newest) => ModuleTree::Stale { running, newest },
        None => ModuleTree::Missing { running },
    }
}

/// WireGuard backend — creates and manages a WireGuard kernel interface.
pub struct WireGuardBackend {
    state: Arc<Mutex<WgState>>,
    /// Pre-resolved peer endpoints (`host:port` → [`SocketAddr`]) passed in by
    /// the daemon so connect/reconnect performs a single DNS lookup before
    /// kill-switch activation (`P2-35`).
    resolved_endpoints: HashMap<String, SocketAddr>,
}

impl WireGuardBackend {
    /// Create a new, idle WireGuard backend.
    #[must_use]
    pub fn new() -> Self {
        Self::with_resolved_endpoints(HashMap::new())
    }

    /// Create a new WireGuard backend seeded with pre-resolved peer endpoints (`P2-35`).
    #[must_use]
    pub fn with_resolved_endpoints(resolved_endpoints: HashMap<String, SocketAddr>) -> Self {
        Self {
            state: Arc::new(Mutex::new(WgState::default())),
            resolved_endpoints,
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
                BackendError::SecretMissing(format!(
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
        let iface: InterfaceName = iface_name.parse().map_err(|e| {
            BackendError::Interface(format!("invalid interface name '{iface_name}': {e}"))
        })?;

        // The netlink call below needs the wireguard family registered.
        ensure_module_loaded().await;

        // Build the device update.
        let mut update = DeviceUpdate::new().set_private_key(private_key);

        let uses_default_route = wg_cfg.peers.iter().any(|p| {
            p.allowed_ips.iter().any(|ip| {
                let s = ip.to_string();
                s == "0.0.0.0/0" || s == "::/0"
            })
        });
        if uses_default_route {
            update = update.set_fwmark(WG_FWMARK_TABLE);
        }

        if let Some(port) = wg_cfg.listen_port {
            update = update.set_listen_port(port);
        }

        // Add peers.
        for peer in &wg_cfg.peers {
            let peer_key = Key::from_base64(&peer.public_key)
                .map_err(|e| BackendError::Key(format!("peer public key: {e}")))?;

            let mut peer_builder = PeerConfigBuilder::new(&peer_key);

            if let Some(ref ep) = peer.endpoint {
                let trimmed = ep.trim();
                let addr = match self.resolved_endpoints.get(trimmed).copied() {
                    Some(pre) => pre,
                    None => resolve_single_endpoint(trimmed, &self.resolved_endpoints).await?,
                };
                peer_builder = peer_builder.set_endpoint(addr);
            }

            for allowed_ip in &peer.allowed_ips {
                peer_builder = peer_builder.add_allowed_ip(
                    allowed_ip.addr(),
                    u8::try_from(allowed_ip.prefix_len()).expect("prefix length fits in u8"),
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
                                warn!(
                                    "PSK bytes not UTF-8 and not 32 bytes for peer {}",
                                    &peer.public_key[..8]
                                );
                                Err(wireguard_control::InvalidKey)
                            }
                        };
                        match psk_result {
                            Ok(psk_key) => {
                                peer_builder = peer_builder.set_preshared_key(psk_key);
                                debug!("applied PSK for peer {}", &peer.public_key[..8]);
                            }
                            Err(e) => warn!(
                                "PSK decode failed for peer {}: {}",
                                &peer.public_key[..8],
                                e
                            ),
                        }
                    }
                    Err(e) => warn!(
                        "PSK not found in keyring for peer {}: {}",
                        &peer.public_key[..8],
                        e
                    ),
                }
            }

            update = update.add_peer(peer_builder);
        }

        // Apply to the kernel.
        debug!("applying WireGuard config to {}", iface_name);
        update.apply(&iface, Backend::Kernel).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("Permission denied")
                || msg.contains("EPERM")
                || msg.contains("Operation not permitted")
            {
                BackendError::Interface(format!(
                    "permission denied creating WireGuard interface '{iface_name}': \
                         the daemon must run as root (or with CAP_NET_ADMIN) — {e}"
                ))
            } else if msg.contains("not supported")
                || msg.contains("ENOTSUP")
                || msg.contains("No such device")
            {
                // Reached only after ensure_module_loaded() has already
                // tried, so the module really is unavailable — the
                // diagnosis says which of the reasons it is.
                BackendError::Prerequisite(wireguard_unsupported_hint(&e.to_string()))
            } else {
                BackendError::Interface(format!("WireGuard DeviceUpdate failed: {e}"))
            }
        })?;

        // Tell NetworkManager not to manage this interface so it does not
        // appear as a new network adapter in the system tray / network applet.
        // Non-fatal: if nmcli is unavailable or NM is not running, log and continue.
        match crate::subprocess::run_system_cmd(
            &["nmcli"],
            &["device", "set", iface_name, "managed", "no"],
            WG_CMD_TIMEOUT,
        )
        .await
        {
            Ok(out) if out.status.success() => {
                debug!("nmcli: set {iface_name} unmanaged — ok");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                debug!(
                    "nmcli: set {iface_name} unmanaged — {} ({})",
                    out.status,
                    stderr.trim()
                );
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
        let mut links = handle
            .link()
            .get()
            .match_name(iface_name.to_owned())
            .execute();
        let link = links
            .try_next()
            .await
            .map_err(|e| {
                BackendError::Interface(format!("rtnetlink link get '{iface_name}': {e}"))
            })?
            .ok_or_else(|| {
                BackendError::Interface(format!("interface '{iface_name}' not found"))
            })?;
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
                    BackendError::Interface(format!(
                        "rtnetlink addr add {addr} dev {iface_name}: {e}"
                    ))
                })?;
        }

        // Bring the interface up.
        handle
            .link()
            .set(LinkUnspec::new_with_index(if_index).up().build())
            .execute()
            .await
            .map_err(|e| {
                BackendError::Interface(format!("rtnetlink link set up '{iface_name}': {e}"))
            })?;

        info!(
            "interface {} brought up with {} address(es) (rtnetlink)",
            iface_name,
            wg_cfg.addresses.len()
        );
        Ok(())
    }

    /// Install kernel routes for every `AllowedIPs` entry across all peers.
    ///
    /// Full-tunnel prefixes (`0.0.0.0/0` and `::/0`) are installed into
    /// dedicated policy-routing table [`WG_FWMARK_TABLE`] (`51820`) with
    /// `ip rule` rules matching `wg-quick` (`P2-31`), leaving the host's
    /// default route in `main` intact. Specific prefixes are installed into
    /// `main` via rtnetlink.
    #[instrument(skip(self, wg_cfg), fields(iface = %iface_name))]
    async fn add_routes(
        &self,
        iface_name: &str,
        wg_cfg: &WireGuardConfig,
    ) -> Result<(bool, bool), BackendError> {
        let needs_full_tunnel_v4 = wg_cfg
            .peers
            .iter()
            .any(|p| p.allowed_ips.iter().any(|ip| ip.to_string() == "0.0.0.0/0"));
        let needs_full_tunnel_v6 = wg_cfg
            .peers
            .iter()
            .any(|p| p.allowed_ips.iter().any(|ip| ip.to_string() == "::/0"));

        // Record policy-routing intent BEFORE installing rules so deterministic
        // error cleanup (`P2-34`) removes partial `ip rule`s on any failure.
        {
            let mut st = self.state.lock().await;
            st.policy_routing_v4 = needs_full_tunnel_v4;
            st.policy_routing_v6 = needs_full_tunnel_v6;
        }

        if needs_full_tunnel_v4 {
            install_policy_default_route(iface_name, false).await?;
        }
        if needs_full_tunnel_v6 {
            install_policy_default_route(iface_name, true).await?;
        }

        // Install explicit (non-/0) AllowedIPs prefixes into the main table.
        let iface_index = ifname_to_index(iface_name).await?;

        for peer in &wg_cfg.peers {
            for allowed_ip in &peer.allowed_ips {
                let cidr = allowed_ip.to_string();
                if cidr == "0.0.0.0/0" || cidr == "::/0" {
                    continue;
                }
                info!("adding route {} dev {}", cidr, iface_name);
                add_allowed_ip_route(&cidr, iface_index, None).await?;
                debug!("added route {} dev {}", cidr, iface_name);
            }
        }

        Ok((needs_full_tunnel_v4, needs_full_tunnel_v6))
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

            let mut argv: Vec<&str> = Vec::with_capacity(2 + domain_args.len());
            argv.push("domain");
            argv.push(iface_name);
            for arg in &domain_args {
                argv.push(arg.as_str());
            }

            match crate::subprocess::run_system_cmd(&["resolvectl"], &argv, WG_CMD_TIMEOUT).await {
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

    /// Deterministically tear down any WireGuard interface, policy rules,
    /// table `51820` routes, and per-link DNS owned by this backend (`P2-31`, `P2-34`).
    async fn cleanup_tunnel(&self, ignore_missing_iface: bool) -> Result<(), BackendError> {
        let (iface_name, policy_v4, policy_v6, dns_ifindex) = {
            let state = self.state.lock().await;
            match state.interface.clone() {
                Some(name) => (
                    name,
                    state.policy_routing_v4,
                    state.policy_routing_v6,
                    state.dns_configured_ifindex,
                ),
                None => {
                    debug!("cleanup_tunnel called with no active interface — no-op");
                    return Ok(());
                }
            }
        };

        // Step 0: Revert systemd-resolved DNS settings before the interface disappears.
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
                        Ok(proxy) => match proxy.call_method("RevertLink", &(ifindex,)).await {
                            Ok(_) => info!("RevertLink({iface_name}) — ok"),
                            Err(e) => warn!("RevertLink({iface_name}) failed: {e}"),
                        },
                        Err(e) => warn!("resolve1 proxy for RevertLink failed: {e}"),
                    }
                }
                Err(e) => warn!("D-Bus connection for RevertLink failed: {e}"),
            }
        }

        // Step 1: Remove policy-routing rules and flush table 51820 BEFORE or
        // alongside interface deletion so traffic immediately reverts cleanly
        // to `main` (`P2-31`).
        if policy_v4 || policy_v6 {
            cleanup_policy_rules(policy_v4, policy_v6).await;
        }

        // Step 2: Delete the WireGuard interface via rtnetlink.
        let del_res = match delete_interface(&iface_name).await {
            Ok(()) => Ok(()),
            Err(BackendError::Interface(ref msg))
                if ignore_missing_iface || msg.contains("not found") =>
            {
                debug!("delete_interface({iface_name}): {msg} — already absent");
                Ok(())
            }
            Err(e) => Err(e),
        };

        {
            let mut state = self.state.lock().await;
            *state = WgState::default();
        }

        del_res?;
        info!("WireGuard tunnel {} torn down", iface_name);
        Ok(())
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

    let mut links = handle
        .link()
        .get()
        .match_name(iface_name.to_owned())
        .execute();
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
            let has_v4 = wg_cfg
                .peers
                .iter()
                .any(|p| p.allowed_ips.iter().any(|ip| ip.to_string() == "0.0.0.0/0"));
            let has_v6 = wg_cfg
                .peers
                .iter()
                .any(|p| p.allowed_ips.iter().any(|ip| ip.to_string() == "::/0"));
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
            // Split-tunnel: reconcile each peer's AllowedIPs through the
            // shared core function, exactly as the macOS engine does, so a
            // profile routes identically on both platforms. This branch used
            // to replace every peer's AllowedIPs with `split_routes` alone,
            // which silently dropped peer-specific prefixes (e.g. the
            // gateway's own LAN) that the engine keeps — a host reachable
            // from the macOS build was unreachable from this one on the same
            // profile. `effective_allowed_ips` also carries the "split tunnel
            // but no routes" refusal, so the manual check is gone with it.
            let mut cfg = wg_cfg.clone();
            let pid = profile.id.simple().to_string();
            for peer in &mut cfg.peers {
                peer.allowed_ips = supermgr_core::vpn::profile::effective_allowed_ips(
                    &peer.allowed_ips,
                    &wg_cfg.split_routes,
                    false,
                    &pid,
                )
                .map_err(BackendError::Config)?;
            }
            // Same class of failure as the IKEv2 backend's DNS selectors: a
            // split profile whose AllowedIPs don't cover its own DNS servers
            // configures a resolver the tunnel can't carry, and every lookup
            // stalls until timeout. Cryptokey routing allows a prefix in only
            // one peer, so the missing host prefixes go to the first peer —
            // split profiles overwhelmingly have exactly one.
            let all_allowed: Vec<ipnet::IpNet> = cfg
                .peers
                .iter()
                .flat_map(|p| p.allowed_ips.iter().copied())
                .collect();
            let missing = supermgr_core::vpn::profile::uncovered_dns_hosts(&all_allowed, &cfg.dns);
            if !missing.is_empty() {
                if let Some(first) = cfg.peers.first_mut() {
                    info!(
                        "split tunnel: adding host prefixes for DNS servers outside \
                         AllowedIPs: {missing:?}"
                    );
                    first.allowed_ips.extend(missing);
                }
            }
            std::borrow::Cow::Owned(cfg)
        };
        let wg_cfg = effective_cfg.as_ref();

        // Reserve the interface name in `WgState` BEFORE touching the kernel so
        // any error below triggers deterministic cleanup (`P2-34`).
        {
            let mut state = self.state.lock().await;
            if state.interface.is_some() {
                return Err(BackendError::AlreadyConnected);
            }
            state.interface = Some(iface_name.clone());
        }

        let bringup_res: Result<(), BackendError> = async {
            // 2. Create / configure the WireGuard kernel interface.
            self.apply_wg_config(&iface_name, wg_cfg, private_key)
                .await?;

            // 3. Assign addresses and bring the interface up.
            self.assign_addresses(&iface_name, wg_cfg).await?;

            // 4. Add routes (policy routing via table 51820 for full-tunnel,
            //    rtnetlink `main` routes for explicit prefixes).
            let (policy_v4, policy_v6) = self.add_routes(&iface_name, wg_cfg).await?;

            // 5. Configure DNS (non-fatal — returns None on failure).
            // Only configure if the profile explicitly opted in, mirroring macOS.
            let dns_ifindex = if profile.push_dns {
                self.configure_dns(&iface_name, wg_cfg).await
            } else {
                debug!("profile.push_dns is false — skipping systemd-resolved configuration");
                None
            };

            let mut state = self.state.lock().await;
            state.interface = Some(iface_name.clone());
            state.policy_routing_v4 = policy_v4;
            state.policy_routing_v6 = policy_v6;
            state.dns_configured_ifindex = dns_ifindex;
            state.addresses = wg_cfg.addresses.clone();
            state.connected_at = Some(std::time::Instant::now());
            Ok(())
        }
        .await;

        if let Err(err) = bringup_res {
            warn!(
                "WireGuard connect failed on {} ({}); running deterministic cleanup",
                iface_name, err
            );
            let _ = self.cleanup_tunnel(true).await;
            return Err(err);
        }

        info!("WireGuard tunnel {} is up", iface_name);
        Ok(())
    }

    #[instrument(skip(self))]
    async fn disconnect(&self) -> Result<(), BackendError> {
        self.cleanup_tunnel(false).await
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let (iface_name, cached_addresses, connected_at): (
            String,
            Vec<ipnet::IpNet>,
            Option<std::time::Instant>,
        ) = {
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
                let secs: u64 = lhs.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                // chrono 0.4.27+: from_timestamp returns Option<DateTime<Utc>>.
                if let Some(dt) = chrono::DateTime::from_timestamp(secs as i64, 0) {
                    last_handshake = Some(
                        last_handshake
                            .map_or(dt, |prev: chrono::DateTime<chrono::Utc>| prev.max(dt)),
                    );
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

#[cfg(test)]
mod module_hint_tests {
    use super::{kernel_module_tree_state, wireguard_unsupported_hint, ModuleTree};

    /// The case a real CachyOS desktop hit: CONFIG_WIREGUARD=m in the running
    /// kernel, and `modprobe` still reporting
    /// "Module wireguard not found in directory /lib/modules/7.1.5-1-cachyos".
    /// A kernel update had removed the running kernel's module tree. The
    /// remedy is a reboot, and no amount of checking kernel config finds that.
    #[test]
    fn a_stale_module_tree_is_reported_as_needing_a_reboot() {
        let msg = super::wireguard_unsupported_hint_for(
            ModuleTree::Stale {
                running: "7.1.5-1-cachyos".into(),
                newest: "7.2.0-1-cachyos".into(),
            },
            "Operation not supported (os error 95)",
        );

        assert!(msg.contains("reboot"), "no remedy given: {msg}");
        assert!(
            msg.contains("7.1.5-1-cachyos"),
            "does not name the running kernel: {msg}"
        );
        assert!(
            msg.contains("7.2.0-1-cachyos"),
            "does not name the installed one: {msg}"
        );
        assert!(
            !msg.contains("sudo modprobe"),
            "tells you to run modprobe when no tree exists to load from: {msg}"
        );
        assert!(
            !msg.contains("CONFIG_WIREGUARD"),
            "sends the reader to kernel config for a reboot problem: {msg}"
        );
    }

    #[test]
    fn a_missing_tree_with_no_alternative_says_so_without_blaming_the_config() {
        let msg = super::wireguard_unsupported_hint_for(
            ModuleTree::Missing {
                running: "9.9.9-custom".into(),
            },
            "os error 95",
        );
        assert!(msg.contains("9.9.9-custom"), "{msg}");
        assert!(msg.contains("reboot"), "{msg}");
        assert!(!msg.contains("CONFIG_WIREGUARD"), "{msg}");
    }

    #[test]
    fn a_present_tree_still_gets_the_modprobe_advice() {
        let msg = super::wireguard_unsupported_hint_for(ModuleTree::Present, "os error 95");
        assert!(msg.contains("modprobe wireguard"), "{msg}");
        let modprobe = msg.find("modprobe").unwrap();
        let config = msg.find("CONFIG_WIREGUARD").unwrap();
        assert!(modprobe < config, "rare cause stated first: {msg}");
    }

    #[test]
    fn this_machine_is_classified_without_panicking() {
        // Whatever the environment, the classifier must return something and
        // the running release must be named when it claims a problem.
        match kernel_module_tree_state() {
            ModuleTree::Present => {}
            ModuleTree::Stale { running, .. } | ModuleTree::Missing { running } => {
                assert!(
                    !running.is_empty(),
                    "claimed a bad tree without naming the kernel"
                );
            }
        }
    }

    #[test]
    fn a_loaded_module_is_not_told_to_load_it_again() {
        if !std::path::Path::new("/sys/module/wireguard").exists() {
            return;
        }
        let msg = wireguard_unsupported_hint("Operation not supported (os error 95)");
        assert!(
            !msg.contains("sudo modprobe"),
            "tells you to load a module that is already loaded: {msg}"
        );
    }
}

#[cfg(test)]
mod policy_routing_and_endpoint_tests {
    use super::*;

    #[test]
    fn policy_rule_matchers_detect_hex_and_decimal_fwmark() {
        let sample_hex = "0:\tfrom all lookup local\n\
                          32764:\tfrom all lookup main suppress_prefixlength 0\n\
                          32765:\tnot from all fwmark 0xca6c lookup 51820\n\
                          32766:\tfrom all lookup main\n";
        assert!(has_fwmark_policy_rule(sample_hex));
        assert!(has_suppress_prefix_rule(sample_hex));

        let sample_dec = "32765:\tnot from all fwmark 51820 lookup 51820\n";
        assert!(has_fwmark_policy_rule(sample_dec));
        assert!(!has_suppress_prefix_rule(sample_dec));
    }

    #[tokio::test]
    async fn resolve_single_endpoint_parses_literals_and_uses_cached_fallback() {
        let empty = HashMap::new();
        let v4 = resolve_single_endpoint("198.51.100.10:51820", &empty)
            .await
            .unwrap();
        assert_eq!(v4, "198.51.100.10:51820".parse().unwrap());

        let v6 = resolve_single_endpoint("[2001:db8::1]:51820", &empty)
            .await
            .unwrap();
        assert_eq!(v6, "[2001:db8::1]:51820".parse().unwrap());

        let mut cached = HashMap::new();
        let expected: SocketAddr = "203.0.113.42:51820".parse().unwrap();
        cached.insert("vpn.invalid:51820".to_owned(), expected);
        let resolved = resolve_single_endpoint("vpn.invalid:51820", &cached)
            .await
            .unwrap();
        assert_eq!(resolved, expected);
    }
}
