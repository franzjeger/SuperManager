//! FortiGate IPsec/IKEv2 backend — drives strongSwan via `swanctl` subprocess.
//!
//! # Architecture
//!
//! 1. Writes a per-connection `swanctl.conf` fragment to
//!    the system's swanctl `conf.d/` directory (auto-detected).
//! 2. Runs `swanctl --load-all` to reload strongSwan's connection + secrets tables.
//! 3. Adds a `/32` host route for the FortiGate endpoint IP via the original
//!    default gateway so IKE/ESP packets reach the peer on the physical NIC.
//! 4. Initiates the IKE SA via `swanctl --initiate --child <name> --timeout 30`.
//!    strongSwan/charon installs the XFRM policies and routes (including the
//!    tunnel default route) in the kernel automatically upon CHILD_SA establishment.
//! 5. Configures `systemd-resolved` per-link DNS via D-Bus.
//! 6. On disconnect: reverts DNS, terminates SA (charon removes its routes),
//!    deletes config, removes the endpoint host route.
//!
//! # Prerequisites
//!
//! - `strongswan` and `strongswan-swanctl` installed.
//! - `charon` IKE daemon running (managed by the `strongswan` systemd unit).
//! - `supermgrd` running as root (write access to the swanctl `conf.d/` directory).
//!
//! # Tunnel cipher suite
//!
//! IKE proposals (IKEv2):
//! `aes128-sha256-ecp384`, `aes256-sha256-ecp384`,
//! `aes128gcm16-prfsha256-ecp384`, `aes256gcm16-prfsha384-ecp521`,
//! `chacha20poly1305-prfsha256-ecp384`
//!
//! DH groups 20 (ECP-384) and 21 (ECP-521).
//! Authentication: EAP-MSCHAPv2 (local) + PSK (remote).
//! Virtual IP via IKEv2 config payload (`vips = 0.0.0.0`).

use std::{net::IpAddr, path::PathBuf};

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, warn};

use supermgr_core::{
    vpn::backend::{BackendStatus, Capabilities, VpnBackend},
    error::BackendError,
    vpn::profile::{FortiGateConfig, Profile, ProfileConfig},
    vpn::state::TunnelStats,
};

use crate::secrets;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Candidate directories where swanctl reads per-connection config fragments.
/// The first one that exists on the current system is used.
///
/// - `/etc/strongswan/swanctl/conf.d` — Fedora 40+, RHEL 9+, openSUSE
/// - `/etc/swanctl/conf.d`            — Debian, Ubuntu, Arch, older Fedora
///
/// The more specific path is checked first because on some distros (e.g. Fedora)
/// both directories exist but only the `/etc/strongswan/` prefixed one is used.
const SWANCTL_CONF_DIR_CANDIDATES: &[&str] = &[
    "/etc/strongswan/swanctl/conf.d",
    "/etc/swanctl/conf.d",
];

/// Returns the first swanctl conf.d directory that exists on the system,
/// or falls back to the first candidate if none exist.
fn swanctl_conf_dir() -> &'static str {
    use std::sync::OnceLock;
    static DIR: OnceLock<&str> = OnceLock::new();
    DIR.get_or_init(|| {
        for candidate in SWANCTL_CONF_DIR_CANDIDATES {
            if std::path::Path::new(candidate).is_dir() {
                info!("using swanctl config directory: {candidate}");
                return candidate;
            }
        }
        warn!(
            "no swanctl conf.d directory found; defaulting to {}",
            SWANCTL_CONF_DIR_CANDIDATES[0]
        );
        SWANCTL_CONF_DIR_CANDIDATES[0]
    })
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Mutable state owned by a running FortiGate connection.
#[derive(Debug, Default)]
struct FgState {
    /// swanctl connection / child name (used for terminate and list-sas).
    connection_name: Option<String>,

    /// Path to the conf fragment we wrote — deleted on disconnect.
    config_path: Option<PathBuf>,

    /// `/32` (or `/128`) host routes added for the FortiGate endpoint.
    /// Installed on the physical NIC before the IKE SA is initiated so that
    /// IKE/ESP packets continue to reach the peer via the physical interface.
    /// Must be removed explicitly on disconnect (charon does not manage these).
    endpoint_host_routes: Vec<String>,

    /// `org.freedesktop.resolve1` interface index stored after a successful
    /// `SetLinkDNS` call; used to call `RevertLink` on disconnect.
    dns_configured_ifindex: Option<i32>,

    /// Tunnel routes added after SA establishment.  For full-tunnel this
    /// includes the default route; for split-tunnel the individual remote TS
    /// CIDRs.  These are added with `src <VIP>` so the XFRM policy matches.
    /// Must be removed explicitly on disconnect.
    tunnel_routes: Vec<String>,

    /// The original default route line captured before installing a full-tunnel
    /// default, so it can be restored on disconnect.  `None` for split-tunnel.
    saved_default_route: Option<String>,
}

// ---------------------------------------------------------------------------
// Backend struct
// ---------------------------------------------------------------------------

/// FortiGate IPsec/IKEv2 backend.
pub struct FortiGateBackend {
    state: Mutex<FgState>,
}

impl FortiGateBackend {
    /// Create a new, idle FortiGate backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(FgState::default()),
        }
    }
}

impl Default for FortiGateBackend {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// swanctl subprocess helper
// ---------------------------------------------------------------------------

/// Run `swanctl <args>`, log every detail, and return the raw `Output`.
///
/// Never panics; propagates I/O errors as [`BackendError::Io`].
async fn run_swanctl(args: &[&str]) -> Result<std::process::Output, BackendError> {
    let cmd_str = format!("swanctl {}", args.join(" "));
    let is_stats = args.contains(&"--list-sas");

    if is_stats {
        debug!("running: {}", cmd_str);
    } else {
        info!("running: {}", cmd_str);
    }

    let out = tokio::process::Command::new("swanctl")
        .args(args)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BackendError::Interface(
                    "swanctl not found — install strongswan and strongswan-swanctl".into(),
                )
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                BackendError::Interface(
                    "permission denied running swanctl — the daemon must run as root".into(),
                )
            } else {
                BackendError::Io(e)
            }
        })?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if is_stats {
        debug!("{} → exit={}", cmd_str, out.status);
    } else {
        info!(
            "{} → exit={} stdout={:?} stderr={:?}",
            cmd_str,
            out.status,
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// swanctl config generation
// ---------------------------------------------------------------------------

/// Generate the swanctl config fragment text for a FortiGate
/// connection.
///
/// Uses:
/// - IKEv2 proposals: aes128/256-sha256-ecp384, aes128/256gcm16, chacha20poly1305
/// - DH groups 20 (ecp384) and 21 (ecp521)
/// - `local { auth = eap-mschapv2; eap_id = <username> }`
/// - `remote { auth = psk }`
/// - `vips = 0.0.0.0` for mode-config virtual IP assignment
/// - `remote_ts` set to `0.0.0.0/0,::/0` for full-tunnel or to the
///   profile's `routes` list for split-tunnel
fn generate_swanctl_config(
    conn_name: &str,
    profile_id_simple: &str,
    fg_cfg: &FortiGateConfig,
    password: &str,
    psk: &str,
    full_tunnel: bool,
) -> String {
    let remote_ts = if full_tunnel {
        "0.0.0.0/0,::/0".to_owned()
    } else {
        fg_cfg
            .routes
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };

    format!(
        r#"connections {{
  {conn} {{
    remote_addrs = {host}
    vips = 0.0.0.0
    proposals = aes128-sha256-ecp384,aes256-sha256-ecp384,aes128gcm16-prfsha256-ecp384,aes256gcm16-prfsha384-ecp521,chacha20poly1305-prfsha256-ecp384
    local {{
      auth = eap-mschapv2
      id = {user}
      eap_id = {user}
    }}
    remote {{
      auth = psk
    }}
    children {{
      {conn} {{
        remote_ts = {remote_ts}
        start_action = none
      }}
    }}
  }}
}}
secrets {{
  ike-supermgr-{pid} {{
    secret = "{psk}"
  }}
  eap-supermgr-{pid} {{
    id = {user}
    secret = "{pw}"
  }}
}}
"#,
        conn = conn_name,
        host = fg_cfg.host,
        user = fg_cfg.username,
        psk = psk,
        pw = password,
        pid = profile_id_simple,
    )
}

// ---------------------------------------------------------------------------
// Virtual-IP parser
// ---------------------------------------------------------------------------

/// Extract the virtual IP from `swanctl --list-sas` human-readable output.
///
/// strongSwan places the mode-config assigned IP in square brackets on the
/// `local` line of the IKE SA section, e.g.:
/// ```text
///   local  'user@vpn' @ 192.168.1.10[500] [172.16.0.5]
/// ```
/// This function returns the first IP found in the last bracket pair on any
/// `local` line.
fn parse_virtual_ip(output: &str) -> Option<IpAddr> {
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("local") {
            continue;
        }
        // Walk every [...] group; keep the last one that parses as an IP
        // (port numbers like [500] don't contain dots/colons).
        let mut last_ip: Option<IpAddr> = None;
        let mut rest = trimmed;
        while let Some(bstart) = rest.find('[') {
            let after = &rest[bstart + 1..];
            if let Some(bend) = after.find(']') {
                let inside = &after[..bend];
                if inside.contains('.') || inside.contains(':') {
                    if let Ok(ip) = inside.parse::<IpAddr>() {
                        last_ip = Some(ip);
                    }
                }
                rest = &after[bend + 1..];
            } else {
                break;
            }
        }
        if last_ip.is_some() {
            return last_ip;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Active-routes parser
// ---------------------------------------------------------------------------

/// Parse the negotiated remote traffic selectors (i.e., the routes pushed
/// through the tunnel) from `swanctl --list-sas` output.
///
/// Each installed child SA emits a line like:
/// ```text
///   remote  10.0.0.0/8
/// ```
/// or, for full-tunnel:
/// ```text
///   remote  0.0.0.0/0
/// ```
fn parse_active_routes(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            let rest = t.strip_prefix("remote")?;
            let cidr = rest.trim();
            // Exclude the port-placeholder lines like "remote '1.2.3.4' @ …"
            if cidr.starts_with('\'') || cidr.starts_with('"') {
                return None;
            }
            // Must look like a CIDR (contains '/')
            if cidr.contains('/') {
                Some(cidr.to_owned())
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Byte-count parser
// ---------------------------------------------------------------------------

/// Parse aggregate bytes sent/received from `swanctl --list-sas` output.
///
/// Each installed child SA emits two traffic lines:
/// ```text
///   in  c1234abcd, 1024 bytes, 10 packets
///   out d4321efab, 2048 bytes, 20 packets
/// ```
/// The function sums the byte counts across *all* child SAs found in the
/// output (there may be more than one if rekeying has produced overlapping
/// SAs).  `bytes_sent` corresponds to `out` lines; `bytes_received` to `in`.
fn parse_sa_bytes(output: &str) -> (u64, u64) {
    let mut bytes_in: u64 = 0;
    let mut bytes_out: u64 = 0;

    for line in output.lines() {
        let trimmed = line.trim();

        // Split on the first run of whitespace to isolate the direction token.
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let dir = match parts.next() {
            Some(d) if d == "in" || d == "out" => d,
            _ => continue,
        };
        let rest = parts.next().unwrap_or("").trim_start();
        // rest = "<hex_spi>, <N> bytes, <M> packets"
        // Skip the SPI (everything before the first comma).
        let after_spi = match rest.find(',') {
            Some(pos) => rest[pos + 1..].trim_start(),
            None => continue,
        };
        // after_spi = "<N> bytes, ..."
        let bytes_token = match after_spi.split_whitespace().next() {
            Some(t) => t,
            None => continue,
        };
        if let Ok(n) = bytes_token.parse::<u64>() {
            match dir {
                "in" => bytes_in += n,
                "out" => bytes_out += n,
                _ => {}
            }
        }
    }

    (bytes_in, bytes_out)
}

// ---------------------------------------------------------------------------
// Routing helpers
// ---------------------------------------------------------------------------

/// Parse the gateway IP and physical interface name from a captured default
/// route line (`ip route show exact 0.0.0.0/0` output).
fn parse_gateway(route_line: &str) -> Option<(String, String)> {
    let mut tokens = route_line.split_whitespace().peekable();
    let mut gw: Option<String> = None;
    let mut dev: Option<String> = None;
    while let Some(tok) = tokens.next() {
        match tok {
            "via" => gw = tokens.next().map(str::to_owned),
            "dev" => dev = tokens.next().map(str::to_owned),
            _ => {}
        }
    }
    match (gw, dev) {
        (Some(g), Some(d)) => Some((g, d)),
        _ => None,
    }
}

/// Capture the first line of the current IPv4 default route.
///
/// Returns `None` if no default route exists.  Used only to extract the
/// gateway IP and outbound interface — the route itself is never replaced by
/// this backend (strongSwan manages tunnel routing).
async fn capture_default_route_v4() -> Result<Option<String>, BackendError> {
    let argv = ["route", "show", "exact", "0.0.0.0/0"];
    info!("running: ip {}", argv.join(" "));
    let out = tokio::process::Command::new("ip")
        .args(argv)
        .output()
        .await
        .map_err(BackendError::Io)?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    info!(
        "ip {} → exit={} stdout={:?} stderr={:?}",
        argv.join(" "),
        out.status,
        stdout.trim(),
        stderr.trim()
    );
    Ok(stdout
        .lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned))
}

// ---------------------------------------------------------------------------
// DNS helper
// ---------------------------------------------------------------------------

/// Configure per-link DNS on `iface_name` via systemd-resolved D-Bus.
///
/// `iface_name` is the physical outbound interface (from the default route),
/// since IPsec/XFRM does not create a separate kernel interface.
/// Returns `Some(ifindex)` on success for later [`RevertLink`] call.
async fn configure_dns_for_link(iface_name: &str, dns_servers: &[IpAddr]) -> Option<i32> {
    if dns_servers.is_empty() {
        return None;
    }

    let ifindex: i32 = match nix::net::if_::if_nametoindex(iface_name) {
        Ok(idx) => idx as i32,
        Err(e) => {
            error!("if_nametoindex({iface_name}): {e}");
            return None;
        }
    };

    let dns_addrs: Vec<(i32, Vec<u8>)> = dns_servers
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v4) => (2_i32, v4.octets().to_vec()),
            IpAddr::V6(v6) => (10_i32, v6.octets().to_vec()),
        })
        .collect();

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
            error!("resolve1 proxy failed: {e}");
            return None;
        }
    };

    // Full-tunnel: route all DNS queries through VPN.
    let domains: Vec<(String, bool)> = vec![("~.".to_owned(), true)];

    match proxy.call_method("SetLinkDNS", &(ifindex, &dns_addrs)).await {
        Ok(_) => info!("SetLinkDNS({iface_name}, {} server(s)) — ok", dns_addrs.len()),
        Err(e) => {
            error!("SetLinkDNS for {iface_name} failed: {e}");
            return None;
        }
    }

    match proxy.call_method("SetLinkDomains", &(ifindex, &domains)).await {
        Ok(_) => info!("SetLinkDomains({iface_name}, {:?}) — ok", domains),
        Err(e) => error!(
            "SetLinkDomains for {iface_name} failed: {e} (DNS active; domain routing not set)"
        ),
    }

    Some(ifindex)
}

async fn revert_link_dns(ifindex: i32) {
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
                    Ok(_) => info!("RevertLink(ifindex={ifindex}) — ok"),
                    Err(e) => warn!("RevertLink(ifindex={ifindex}) failed: {e}"),
                },
                Err(e) => warn!("resolve1 proxy for RevertLink failed: {e}"),
            }
        }
        Err(e) => warn!("D-Bus connection for RevertLink failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// VpnBackend implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl VpnBackend for FortiGateBackend {
    #[instrument(skip(self, profile), fields(profile_id = %profile.id, profile_name = %profile.name))]
    async fn connect(&self, profile: &Profile) -> Result<(), BackendError> {
        let fg_cfg = match &profile.config {
            ProfileConfig::FortiGate(cfg) => cfg,
            other => {
                return Err(BackendError::Config(format!(
                    "FortiGateBackend cannot handle '{}' profile",
                    other.backend_name()
                )));
            }
        };

        {
            let state = self.state.lock().await;
            if state.connection_name.is_some() {
                return Err(BackendError::AlreadyConnected);
            }
        }

        // Derive a short, filesystem-safe connection name.
        let conn_name = format!("supermgr-{}", &profile.id.simple().to_string()[..12]);
        let profile_id_simple = profile.id.simple().to_string();

        info!(
            host = %fg_cfg.host,
            user = %fg_cfg.username,
            conn = %conn_name,
            "initiating FortiGate IPsec/IKEv2 connection"
        );

        // ── Step 0: Retrieve credentials from secrets file ───────────────────
        let password_bytes =
            secrets::retrieve_secret(fg_cfg.password.label()).await.map_err(|e| {
                error!(
                    "credential not found in keyring — please re-import the profile \
                     (label '{}': {e})",
                    fg_cfg.password.label()
                );
                BackendError::Key(format!(
                    "credential not found in keyring — please re-import the profile \
                     (label '{}')",
                    fg_cfg.password.label()
                ))
            })?;
        let psk_bytes = secrets::retrieve_secret(fg_cfg.psk.label()).await.map_err(|e| {
            error!(
                "credential not found in keyring — please re-import the profile \
                 (label '{}': {e})",
                fg_cfg.psk.label()
            );
            BackendError::Key(format!(
                "credential not found in keyring — please re-import the profile \
                 (label '{}')",
                fg_cfg.psk.label()
            ))
        })?;
        let password = std::str::from_utf8(&password_bytes)
            .map_err(|_| BackendError::Key("password bytes are not valid UTF-8".into()))?
            .to_owned();
        let psk = std::str::from_utf8(&psk_bytes)
            .map_err(|_| BackendError::Key("PSK bytes are not valid UTF-8".into()))?
            .to_owned();

        // ── Step 1: Write swanctl config fragment ───────────────────────────
        if !profile.full_tunnel && fg_cfg.routes.is_empty() {
            return Err(BackendError::Config(
                "split-tunnel is enabled but no routes are configured for this profile — \
                 add destination prefixes to the profile's 'routes' list, or re-enable \
                 'Route all traffic through VPN'"
                    .into(),
            ));
        }
        let config_text =
            generate_swanctl_config(&conn_name, &profile_id_simple, fg_cfg, &password, &psk, profile.full_tunnel);
        let config_path = PathBuf::from(swanctl_conf_dir()).join(format!("{conn_name}.conf"));

        info!("writing swanctl config to {}", config_path.display());
        tokio::fs::write(&config_path, &config_text).await.map_err(|e| {
            let dir = swanctl_conf_dir();
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                format!(" — the daemon must run as root to write to {dir}/")
            } else if e.kind() == std::io::ErrorKind::NotFound {
                format!(" — {dir}/ does not exist; install strongswan-swanctl")
            } else {
                String::new()
            };
            BackendError::Subprocess {
                command: "write swanctl config".into(),
                message: format!("{}: {e}{hint}", config_path.display()),
            }
        })?;

        // ── Step 2: Reload strongSwan (load-all picks up connections + secrets)
        let out = run_swanctl(&["--load-all"]).await?;
        if !out.status.success() {
            let _ = tokio::fs::remove_file(&config_path).await;
            return Err(BackendError::Subprocess {
                command: "swanctl --load-all".into(),
                message: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }

        // ── Step 3: Resolve FortiGate host to IP ────────────────────────────
        let host_ip: IpAddr = {
            let lookup_target = format!("{}:500", fg_cfg.host);
            let result = tokio::net::lookup_host(&lookup_target).await;
            match result {
                Ok(mut addrs) => match addrs.next().map(|sa| sa.ip()) {
                    Some(ip) => {
                        info!("resolved {} → {}", fg_cfg.host, ip);
                        ip
                    }
                    None => {
                        let _ = tokio::fs::remove_file(&config_path).await;
                        return Err(BackendError::Interface(format!(
                            "FortiGate hostname '{}' resolved to zero addresses — \
                             verify the hostname in the profile configuration",
                            fg_cfg.host
                        )));
                    }
                },
                Err(e) => {
                    let _ = tokio::fs::remove_file(&config_path).await;
                    let hint = if format!("{e}").contains("Name or service not known") {
                        " — check that the hostname is correct and DNS is working"
                    } else if format!("{e}").contains("Temporary failure") {
                        " — DNS server is unreachable; check your network connection"
                    } else {
                        ""
                    };
                    return Err(BackendError::Interface(format!(
                        "cannot resolve FortiGate host '{}': {e}{hint}",
                        fg_cfg.host
                    )));
                }
            }
        };

        // ── Step 4: Add endpoint host route ─────────────────────────────────
        // A specific /32 host route for the FortiGate IP via the physical
        // gateway keeps IKE/ESP packets on the physical NIC.  strongSwan
        // manages all tunnel routing (XFRM policies + default route) itself
        // once the CHILD_SA is established — we must not interfere with that.
        let default_route = capture_default_route_v4().await?;
        let gw_v4 = default_route.as_deref().and_then(parse_gateway);
        let mut outbound_iface: Option<String> = gw_v4.as_ref().map(|(_, dev)| dev.clone());

        let mut endpoint_host_routes: Vec<String> = Vec::new();
        if let Some((gw, dev)) = &gw_v4 {
            let host_cidr = if host_ip.is_ipv4() {
                format!("{}/32", host_ip)
            } else {
                format!("{}/128", host_ip)
            };
            info!(
                "adding endpoint host route: ip route add {} via {} dev {}",
                host_cidr, gw, dev
            );
            let out = tokio::process::Command::new("ip")
                .args(["route", "add", &host_cidr, "via", gw, "dev", dev])
                .output()
                .await
                .map_err(BackendError::Io)?;
            let stderr = String::from_utf8_lossy(&out.stderr);
            info!(
                "ip route add {} via {} dev {} → exit={} stderr={:?}",
                host_cidr,
                gw,
                dev,
                out.status,
                stderr.trim()
            );
            if out.status.success() {
                endpoint_host_routes.push(host_cidr);
            } else {
                warn!(
                    "endpoint host route for {} failed: {} (IKE packets may be misrouted)",
                    host_ip,
                    stderr.trim()
                );
            }
        } else {
            warn!(
                "could not parse gateway from default route — endpoint host route not added; \
                 IKE packets may be misrouted"
            );
        }

        // ── Step 5: Initiate IKE SA ──────────────────────────────────────────
        // Clean up any existing SA before connecting — prevents "duplicate
        // CHILD_SA" errors when strongSwan rekeys or a previous session was
        // not cleanly torn down.  Safe: if no SA exists, --terminate is a
        // no-op (returns an error which we ignore).
        let _ = run_swanctl(&["--terminate", "--ike", &conn_name]).await;

        // strongSwan installs XFRM policies and the tunnel default route upon
        // CHILD_SA establishment.  We do not touch the default route.
        let out = run_swanctl(&[
            "--initiate",
            "--child",
            &conn_name,
            "--timeout",
            "30",
        ])
        .await?;
        if !out.status.success() {
            // Clean up host routes and config on failure.
            for cidr in &endpoint_host_routes {
                let _ = tokio::process::Command::new("ip")
                    .args(["route", "del", cidr])
                    .output()
                    .await;
            }
            let _ = tokio::fs::remove_file(&config_path).await;
            let _ = run_swanctl(&["--load-all"]).await;
            // swanctl writes plugin load warnings to stderr before the real
            // error.  Extract only the lines that describe the actual failure
            // (those starting with "initiate failed" or "establishing").
            let stderr = String::from_utf8_lossy(&out.stderr);
            let meaningful: Vec<&str> = stderr
                .lines()
                .filter(|l| {
                    !l.contains("plugin")
                        && !l.contains("CAP_DAC_OVERRIDE")
                        && !l.trim().is_empty()
                })
                .collect();
            let message = if meaningful.is_empty() {
                stderr.trim().to_owned()
            } else {
                meaningful.join("\n")
            };
            let hint = if message.contains("EAP_FAILURE") || message.contains("AUTHENTICATION_FAILED") || message.contains("AUTH_FAILED") {
                "authentication failed — verify your username and password in the profile"
            } else if message.contains("TIMEOUT") || message.contains("timed out") || message.contains("establishing connection") {
                "connection timed out — the FortiGate gateway may be unreachable; \
                 check your network connection and verify the gateway hostname"
            } else if message.contains("NO_PROPOSAL_CHOSEN") || message.contains("no matching proposal") {
                "IKE negotiation failed (no matching proposal) — the FortiGate may not \
                 support the configured cipher suites; check VPN settings on the firewall"
            } else if message.contains("Permission denied") || message.contains("EPERM") {
                "permission denied — the daemon must run as root to initiate IPsec tunnels"
            } else if message.contains("connection not found") {
                "strongSwan configuration not loaded — ensure charon is running \
                 (systemctl start strongswan)"
            } else {
                "IKE/IPsec negotiation failed"
            };
            return Err(BackendError::ConnectionFailed(format!(
                "{hint}: {message}",
            )));
        }

        // ── Step 6: Log virtual IP from list-sas ─────────────────────────────
        let list_out = run_swanctl(&["--list-sas"]).await?;
        let list_stdout = String::from_utf8_lossy(&list_out.stdout);
        match parse_virtual_ip(&list_stdout) {
            Some(vip) => info!("mode-config assigned virtual IP: {}", vip),
            None => info!("no virtual IP in --list-sas output (split-tunnel or parse miss)"),
        }

        // ── Step 6b: Install tunnel routes ──────────────────────────────────
        // strongSwan's XFRM policies only match traffic with src=VIP.  The
        // kernel needs explicit routes that force traffic to use the VIP as
        // source address, otherwise packets leave with the physical IP and
        // bypass the tunnel entirely.
        let mut tunnel_routes: Vec<String> = Vec::new();
        let mut saved_default_route: Option<String> = None;

        // Parse VIP from the initiate output (already confirmed above).
        let stdout_str = String::from_utf8_lossy(&out.stdout);
        let vip: Option<std::net::IpAddr> = stdout_str
            .lines()
            .find(|l| l.contains("installing new virtual IP"))
            .and_then(|l| {
                l.split("installing new virtual IP")
                    .nth(1)
                    .and_then(|s| s.trim().parse().ok())
            });

        if let Some(vip) = vip {
            let outbound_dev = outbound_iface.as_deref().unwrap_or("enp129s0");

            if profile.full_tunnel {
                // Full-tunnel: capture old default, then add a new one with src=VIP.
                let cap = tokio::process::Command::new("ip")
                    .args(["route", "show", "exact", "0.0.0.0/0"])
                    .output()
                    .await
                    .map_err(BackendError::Io)?;
                let cap_out = String::from_utf8_lossy(&cap.stdout);
                saved_default_route = cap_out.lines().next().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());

                // Delete old default and add new one with src=VIP via the same gateway.
                if let Some(ref saved) = saved_default_route {
                    if let Some((gw, _dev)) = parse_gateway(saved) {
                        info!("installing full-tunnel default: via {gw} dev {outbound_dev} src {vip}");

                        // Delete existing defaults.
                        let _ = tokio::process::Command::new("ip")
                            .args(["route", "del", "default"])
                            .output()
                            .await;

                        // Add new default with src=VIP so XFRM policy matches.
                        let add_out = tokio::process::Command::new("ip")
                            .args([
                                "route", "add", "default",
                                "via", &gw,
                                "dev", outbound_dev,
                                "src", &vip.to_string(),
                                "metric", "50",
                            ])
                            .output()
                            .await
                            .map_err(BackendError::Io)?;

                        if add_out.status.success() {
                            tunnel_routes.push("default".to_owned());
                            info!("full-tunnel default route installed — ok");
                        } else {
                            let stderr = String::from_utf8_lossy(&add_out.stderr);
                            warn!("failed to install full-tunnel default: {}", stderr.trim());
                        }
                    }
                }
            } else {
                // Split-tunnel: add a route for each remote traffic selector with src=VIP.
                for route_cidr in &fg_cfg.routes {
                    let cidr = route_cidr.to_string();
                    info!("installing split-tunnel route: {cidr} dev {outbound_dev} src {vip}");

                    let add_out = tokio::process::Command::new("ip")
                        .args([
                            "route", "add", &cidr,
                            "dev", outbound_dev,
                            "src", &vip.to_string(),
                        ])
                        .output()
                        .await
                        .map_err(BackendError::Io)?;

                    if add_out.status.success() {
                        tunnel_routes.push(cidr.clone());
                        info!("split-tunnel route {cidr} — ok");
                    } else {
                        let stderr = String::from_utf8_lossy(&add_out.stderr);
                        warn!("failed to add split-tunnel route {cidr}: {}", stderr.trim());
                    }
                }
            }
        } else {
            warn!("could not parse virtual IP from swanctl output — tunnel routes not installed");
        }

        // ── Step 7: Configure DNS ────────────────────────────────────────────
        // Prefer DNS servers from the profile config.  If none are set,
        // parse the IKE negotiation output for servers pushed by the server
        // (lines like "[IKE] installing DNS server 1.2.3.4 via resolvconf").
        // strongSwan's own resolvconf integration fails on systemd-networkd
        // systems, so we handle DNS ourselves via systemd-resolved D-Bus.
        let effective_dns: Vec<std::net::IpAddr> = if !fg_cfg.dns_servers.is_empty() {
            fg_cfg.dns_servers.clone()
        } else {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut pushed: Vec<std::net::IpAddr> = Vec::new();
            for line in stdout.lines() {
                // Match: "[IKE] installing DNS server 1.2.3.4 via resolvconf"
                if line.contains("installing DNS server") {
                    if let Some(ip_str) = line
                        .split("installing DNS server")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                    {
                        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                            if !pushed.contains(&ip) {
                                info!("FortiGate pushed DNS server: {ip}");
                                pushed.push(ip);
                            }
                        }
                    }
                }
            }
            pushed
        };

        let dns_configured_ifindex = if !effective_dns.is_empty() {
            configure_dns_for_link(
                outbound_iface.get_or_insert_with(|| "eth0".to_owned()),
                &effective_dns,
            )
            .await
        } else {
            None
        };

        // ── Step 8: Persist state ────────────────────────────────────────────
        {
            let mut state = self.state.lock().await;
            state.connection_name = Some(conn_name.clone());
            state.config_path = Some(config_path);
            state.endpoint_host_routes = endpoint_host_routes;
            state.dns_configured_ifindex = dns_configured_ifindex;
            state.tunnel_routes = tunnel_routes;
            state.saved_default_route = saved_default_route;
        }

        info!("FortiGate SA '{}' established", conn_name);
        Ok(())
    }

    #[instrument(skip(self))]
    async fn disconnect(&self) -> Result<(), BackendError> {
        let (conn_name, config_path, endpoint_host_routes, dns_ifindex, tunnel_routes, saved_default_route) = {
            let state = self.state.lock().await;
            match state.connection_name.clone() {
                Some(name) => (
                    name,
                    state.config_path.clone(),
                    state.endpoint_host_routes.clone(),
                    state.dns_configured_ifindex,
                    state.tunnel_routes.clone(),
                    state.saved_default_route.clone(),
                ),
                None => {
                    debug!("disconnect called but no SA is active — no-op");
                    return Ok(());
                }
            }
        };

        // Step 0: Revert systemd-resolved DNS (non-fatal).
        if let Some(ifindex) = dns_ifindex {
            revert_link_dns(ifindex).await;
        }

        // Step 1: Terminate IKE SA.
        // charon removes the XFRM policies and any tunnel routes it installed
        // (including the tunnel default route), restoring the original routing
        // table automatically.
        let out = run_swanctl(&["--terminate", "--ike", &conn_name, "--timeout", "10"]).await?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            warn!(
                "swanctl --terminate --ike {} failed: {} (proceeding with cleanup)",
                conn_name,
                stderr.trim()
            );
        }

        // Step 2: Delete config fragment.
        if let Some(ref path) = config_path {
            if path.exists() {
                if let Err(e) = tokio::fs::remove_file(path).await {
                    warn!("failed to remove config fragment {:?}: {}", path, e);
                } else {
                    info!("deleted config fragment {}", path.display());
                }
            }
        }

        // Step 3: Reload strongSwan (removes the terminated connection from charon).
        let out = run_swanctl(&["--load-all"]).await?;
        if !out.status.success() {
            warn!(
                "swanctl --load-all after disconnect failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }

        // Step 3b: Remove tunnel routes we added and restore original default.
        for cidr in &tunnel_routes {
            info!("removing tunnel route: {cidr}");
            let out = tokio::process::Command::new("ip")
                .args(["route", "del", cidr])
                .output()
                .await
                .map_err(BackendError::Io)?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                warn!("ip route del {cidr} → {} (may already be gone)", stderr.trim());
            }
        }

        // Restore original default route if we displaced it for full-tunnel.
        if let Some(ref saved) = saved_default_route {
            info!("restoring original default route: {saved}");
            let mut cmd = tokio::process::Command::new("ip");
            cmd.arg("route").arg("add");
            for word in saved.split_whitespace() {
                cmd.arg(word);
            }
            match cmd.output().await {
                Ok(out) if !out.status.success() => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!("restore default route failed: {}", stderr.trim());
                }
                Err(e) => warn!("restore default route failed: {e}"),
                _ => info!("default route restored — ok"),
            }
        }

        // Step 4: Delete endpoint host routes.
        // These were added manually before the IKE SA and are not managed by
        // charon, so we must remove them explicitly.
        for cidr in &endpoint_host_routes {
            info!("removing endpoint host route: ip route del {}", cidr);
            let out = tokio::process::Command::new("ip")
                .args(["route", "del", cidr])
                .output()
                .await
                .map_err(BackendError::Io)?;
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !out.status.success() {
                warn!(
                    "ip route del {} → exit={} stderr={:?} (may already be gone)",
                    cidr,
                    out.status,
                    stderr.trim()
                );
            } else {
                info!("ip route del {} → ok", cidr);
            }
        }

        // Step 5: Clear state.
        {
            let mut state = self.state.lock().await;
            state.connection_name = None;
            state.config_path = None;
            state.endpoint_host_routes = Vec::new();
            state.dns_configured_ifindex = None;
            state.tunnel_routes = Vec::new();
            state.saved_default_route = None;
        }

        info!("FortiGate SA '{}' torn down", conn_name);
        Ok(())
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let conn_name = {
            let state = self.state.lock().await;
            match state.connection_name.clone() {
                Some(name) => name,
                None => return Ok(BackendStatus::Inactive),
            }
        };

        let out = run_swanctl(&["--list-sas"]).await?;
        let stdout = String::from_utf8_lossy(&out.stdout);

        // The IKE SA header looks like: `supermgr-abc123: #1, ESTABLISHED, IKEv2, ...`
        let established = stdout
            .lines()
            .any(|l| l.contains(&conn_name) && l.contains("ESTABLISHED"));

        if !established {
            return Ok(BackendStatus::Inactive);
        }

        let (bytes_received, bytes_sent) = parse_sa_bytes(&stdout);
        let virtual_ip = parse_virtual_ip(&stdout)
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let active_routes = parse_active_routes(&stdout);

        Ok(BackendStatus::Active {
            interface: conn_name,
            stats: TunnelStats {
                bytes_sent,
                bytes_received,
                // IPsec does not have a WireGuard-style handshake timestamp.
                last_handshake: None,
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
            persistent_keepalive: false,
            config_import: true,
        }
    }

    fn name(&self) -> &'static str {
        "FortiGate (IPsec/IKEv2)"
    }
}
