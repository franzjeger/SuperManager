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
//! `chacha20poly1305-prfsha256-ecp384`, and `aes256-sha256-modp2048`
//! (legacy fallback for FortiGates without ECP DH groups).
//!
//! DH groups: 20 (ECP-384), 21 (ECP-521), and 14 (modp2048).
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

/// True when swanctl's stderr says it could not reach charon over the vici
/// socket.
///
/// swanctl is a client: it is installed and runs fine with the IKE daemon
/// stopped, and then fails on every call with this. On a distro that ships
/// `strongswan.service` disabled by default — Arch, and Debian when installed
/// without the daemon enabled — that is the state a machine is in until
/// somebody starts the unit, so it is the first thing a FortiGate connect
/// hits.
pub(crate) fn charon_unreachable(stderr: &str) -> bool {
    stderr.contains("charon.vici") || stderr.contains("connecting to 'default' URI failed")
}

/// Strip swanctl's usage block from stderr.
///
/// On any argument or connection error swanctl prints its full ~20-line usage
/// text after the one line that says what actually went wrong. That block was
/// being handed to the GUI verbatim as the connection error, which buried the
/// real message under a wall of option documentation.
pub(crate) fn strip_usage_block(stderr: &str) -> String {
    stderr
        .lines()
        .take_while(|l| !l.starts_with("strongSwan ") && !l.starts_with("usage:"))
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Turn a failed swanctl invocation into the error the user should see.
///
/// Charon being down is a [`BackendError::Prerequisite`] naming the command
/// that fixes it; anything else keeps the (de-noised) stderr.
fn swanctl_failure(command: &str, stderr: &str) -> BackendError {
    if charon_unreachable(stderr) {
        return BackendError::Prerequisite(
            "strongSwan is installed but its IKE daemon (charon) is not running — \
             start it with: sudo systemctl enable --now strongswan.service"
                .into(),
        );
    }
    BackendError::Subprocess {
        command: command.into(),
        message: strip_usage_block(stderr),
    }
}

/// Convert strongSwan's initiate diagnostics into a stable, user-facing
/// category. The complete diagnostic stays in the journal; the GUI gets a
/// sentence that explains the likely remedy without exposing connection IDs
/// or raw CHILD_SA state-machine text.
fn classify_initiate_failure(message: &str) -> BackendError {
    let upper = message.to_ascii_uppercase();

    if ["EAP_FAILURE", "AUTHENTICATION_FAILED", "AUTH_FAILED"]
        .iter()
        .any(|marker| upper.contains(marker))
    {
        BackendError::AuthenticationFailed(
            "The FortiGate rejected the credentials. Check the username, password and PSK."
                .into(),
        )
    } else if upper.contains("TIMEOUT") || upper.contains("TIMED OUT") {
        BackendError::Timeout { seconds: 30 }
    } else if upper.contains("INVALID_ID_INFORMATION") || upper.contains("INVALID_ID") {
        // Distinct from a credential failure on purpose: nothing the operator
        // types in the password field fixes this. Either we sent an IDi the
        // gateway does not recognise, or the gateway sent an IDr that does not
        // match the address we dialled — which is what `remote.id = <host>`
        // pins. A FortiGate with `set localid` configured is the usual cause.
        BackendError::AuthenticationFailed(
            "The FortiGate rejected the IKE identity (INVALID_ID_INFORMATION). \
             If the gateway is configured with its own local ID, it sends that \
             instead of its address and will not match. Check Local ID on this \
             profile, and the peer ID configured on the FortiGate."
                .into(),
        )
    } else if upper.contains("NO_PROPOSAL_CHOSEN")
        || upper.contains("NO MATCHING PROPOSAL")
    {
        BackendError::NegotiationFailed(
            "The FortiGate and SuperManager could not agree on IKE/IPsec security settings."
                .into(),
        )
    } else if upper.contains("PERMISSION DENIED") || upper.contains("EPERM") {
        BackendError::Permission(
            "The daemon needs root privileges to initiate IPsec tunnels.".into(),
        )
    } else if upper.contains("CONNECTION NOT FOUND") {
        BackendError::Prerequisite(
            "The strongSwan connection was not loaded. Ensure charon is running and try again."
                .into(),
        )
    } else if upper.contains("NETWORK IS UNREACHABLE")
        || upper.contains("NO ROUTE TO HOST")
        || upper.contains("NAME OR SERVICE NOT KNOWN")
    {
        BackendError::ConnectionFailed(
            "The FortiGate gateway could not be reached. Check the network and gateway address."
                .into(),
        )
    } else {
        BackendError::NegotiationFailed(
            "The IPsec connection could not be established. Check the credentials, PSK and IKE settings on the FortiGate."
                .into(),
        )
    }
}

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

    // Filter benign plugin-not-found warnings from swanctl's stderr before
    // logging. strongSwan emits one of these on every invocation when an
    // optional plugin (sqlite, kernel-libipsec, etc.) is not built into the
    // installed binary. They have no operational meaning and otherwise
    // dominate the journal, making real errors hard to spot.
    let filtered_stderr: String = stderr
        .lines()
        .filter(|l| {
            !(l.contains("plugin '")
                && (l.contains("failed to load")
                    || l.contains("no plugin file available")))
        })
        .collect::<Vec<_>>()
        .join("\n");

    if is_stats {
        debug!("{} → exit={}", cmd_str, out.status);
    } else {
        info!(
            "{} → exit={} stdout={:?} stderr={:?}",
            cmd_str,
            out.status,
            stdout.trim(),
            filtered_stderr.trim()
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
/// - DH groups 20 (ecp384), 21 (ecp521), and 14 (modp2048) as a legacy fallback
///   for FortiGates whose phase1 crypto hasn't been updated to ECP groups —
///   without a modp group in our proposal list, FortiOS silently drops the
///   IKE_SA_INIT when it can't parse the KE payload's DH group.
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

    // Remote identity, and the secrets entry it pairs with.
    //
    // `remote.id` defaults to `%any`, and the `ike-` secret carried no `id` at
    // all — an unkeyed PSK matches every peer. That works with one profile and
    // gets ambiguous with several: charon has multiple candidate PSKs for any
    // peer and no basis to prefer one, so the wrong key can be offered and the
    // failure looks intermittent rather than like a configuration problem.
    //
    // These two move together or not at all. Pinning `remote.id` while leaving
    // the secret unkeyed adds a constraint with no lookup benefit; keying the
    // secret while leaving `remote.id` open is what the macOS helper shipped
    // broken twice, because a secret keyed only to `%any` does not match an
    // IP-form IDr. `id-1 = <host>` catches the IP or FQDN the gateway sends,
    // `%any` stays as the fallback for a gateway that sends an ID_ANY.
    //
    // The risk this takes on: a FortiGate with `set localid` configured sends
    // that instead of its address, and pinning `remote.id` to the dialled host
    // then rejects it. There is no override field yet, so `classify_initiate_failure`
    // learned to name INVALID_ID_INFORMATION specifically — the macOS helper has
    // had that message since it hit this, and Linux had no diagnostic for it at
    // all. A gateway that does not fit now says so instead of failing as a
    // generic auth error.

    // Dead Peer Detection. Without `dpd_delay` — which defaults to 0s, i.e.
    // off — charon never notices a peer that vanished without a clean IKE
    // DELETE. A firewall reboot mid-tunnel leaves the IKE_SA ESTABLISHED
    // forever, and on this daemon that is worse than it sounds: the full-tunnel
    // default route carries `src <virtual IP>`, so every packet keeps being
    // sourced from an address the dead tunnel no longer owns. The machine has
    // no working internet and `swanctl --list-sas` insists it is connected.
    //
    // `dpd_action = clear` is deliberately NOT the macOS helper's `restart`,
    // and the difference is architectural rather than taste.
    //
    // This daemon owns the routes. `spawn_monitor_task` polls the backend, and
    // when the SA is gone it runs `backend.disconnect()` to restore the saved
    // default route, revert DNS and drop the endpoint host routes. That whole
    // recovery path is already written and correct — it is keyed on the SA
    // *disappearing*, which is exactly what `clear` produces.
    //
    // `restart` would re-negotiate under a fresh IKE_SA behind the daemon's
    // back. Mode-config can hand out a different virtual IP, while the default
    // route still says `src <old vip>`; the monitor would see an Active SA,
    // reconcile would find nothing wrong, and the result is a black hole the
    // GUI reports as Connected. That is a worse failure than today's, because
    // today's is at least visible.
    //
    // macOS can afford `restart` because its tunnel is a utun device and its
    // routes pin to the device, not to a source address.
    //
    // `clear` is also strongSwan's default for `dpd_action`, but it is set
    // explicitly: the recovery design depends on it, and a line copied over
    // from the helper would silently break it.
    //
    // Detection takes ~100s — the delay plus charon's default retransmit
    // schedule. Do NOT try to shorten that with `retransmit_timeout`,
    // `retransmit_base` or `retransmit_tries`: those are not swanctl.conf
    // connection options at all (they live under `charon` in strongswan.conf,
    // daemon-wide), and strongSwan 6.x rejects an unknown option by discarding
    // the ENTIRE connection, so the tunnel would stop loading. A test below
    // guards against a well-meaning re-add.

    // IKE identity (IDi). A FortiGate with several dial-up tunnels behind one
    // public IP picks the tunnel by peer ID *before* authentication, so a
    // profile that needs a specific identity cannot connect without this.
    //
    // The field has existed on `FortiGateConfig` and in the macOS app since
    // that feature shipped; this backend ignored it and hardcoded IDi to the
    // EAP username, so a Linux client sent a different identity than a macOS
    // client reading the very same profile.
    //
    // Empty keeps `id = <username>` rather than omitting the line the way the
    // macOS helper does. That is a deliberate difference: omitting it makes
    // strongSwan default IDi to the local IP, which would change the identity
    // every existing Linux profile has been connecting with. Anyone who needs a
    // particular IDi now sets it explicitly, and nobody's working tunnel moves
    // underneath them. See `local_id_line` in the helper's `build_swanctl_conf`
    // for the other half of this.
    //
    // Quoted and escaped so an arbitrary identity (FQDN, user@domain, keyid)
    // parses. strongSwan auto-detects the ID type regardless of quoting.
    let local_id = fg_cfg.local_id.trim();
    let local_id_line = if local_id.is_empty() {
        format!("id = {}", fg_cfg.username)
    } else {
        format!("id = \"{}\"", escape_swanctl(local_id))
    };

    format!(
        r#"connections {{
  {conn} {{
    remote_addrs = {host}
    vips = 0.0.0.0
    dpd_delay = 10s
    proposals = aes128-sha256-ecp384,aes256-sha256-ecp384,aes128gcm16-prfsha256-ecp384,aes256gcm16-prfsha384-ecp521,chacha20poly1305-prfsha256-ecp384,aes256-sha256-modp2048
    local {{
      auth = eap-mschapv2
      {local_id_line}
      eap_id = {user}
    }}
    remote {{
      auth = psk
      id = {host}
    }}
    children {{
      {conn} {{
        remote_ts = {remote_ts}
        start_action = none
        dpd_action = clear
      }}
    }}
  }}
}}
secrets {{
  ike-supermgr-{pid} {{
    id-1 = {host}
    id-2 = %any
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
        local_id_line = local_id_line,
        // Escaped, not interpolated raw. swanctl values are double-quoted
        // strings, so a PSK or password containing `"` used to terminate the
        // string early and leave the remainder to be parsed as config —
        // whereupon strongSwan discards the whole connection and the tunnel
        // fails to load with nothing pointing at the password as the cause.
        // The macOS helper has escaped these since it was written.
        psk = escape_swanctl(psk),
        pw = escape_swanctl(password),
        pid = profile_id_simple,
    )
}

/// Escape a value for a double-quoted swanctl string.
///
/// Twin of `escape_swanctl` in `supermanager-helper::strongswan`. Duplicated
/// rather than shared because that crate is macOS-only and does not depend on
/// `supermgr-core`; if it ever does, this is the first thing to move.
///
/// Newlines are dropped rather than escaped: they are not valid inside a
/// swanctl value, and a secret containing one is already broken — silently
/// truncating at the newline would be worse than removing it.
fn escape_swanctl(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\n' && *c != '\r')
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '"' => vec!['\\', '"'],
            other => vec![other],
        })
        .collect()
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

/// Name of the dedicated dummy netdev that holds the FortiGate session's DNS
/// state in systemd-resolved.
///
/// IPsec/XFRM has no kernel netdev, so we used to attach DNS to the *physical*
/// outbound interface (e.g. `enp14s0`).  But systemd-resolved's `RevertLink`
/// is per-link and indiscriminate — calling it on the physical link on
/// disconnect wiped NetworkManager's LAN DNS too, leaving the system unable
/// to resolve anything until a manual `nmcli connection up`.
///
/// Putting DNS on a dummy interface that we own end-to-end means RevertLink
/// only clears state we set, never NM's.  The dummy carries no IP and no
/// route — systemd-resolved only needs a netdev to anchor DNS state to;
/// query packets still leave the box via the real default route (the VPN).
const DNS_DUMMY_IFACE: &str = "supermgr_dns";

/// Ensure the DNS dummy interface exists and is up.
///
/// Idempotent: if a stale dummy from a previous crash is present we delete it
/// and recreate so we know the link state is fresh.  Returns the interface
/// name on success so the caller can pass it to `configure_dns_for_link`.
async fn ensure_dns_dummy() -> Option<&'static str> {
    // Best-effort delete of any leftover from a previous run.
    let _ = tokio::process::Command::new("ip")
        .args(["link", "del", DNS_DUMMY_IFACE])
        .output()
        .await;

    let add = tokio::process::Command::new("ip")
        .args(["link", "add", DNS_DUMMY_IFACE, "type", "dummy"])
        .output()
        .await;
    match add {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            warn!(
                "ip link add {DNS_DUMMY_IFACE}: exit={} stderr={:?} (DNS will not be pushed)",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return None;
        }
        Err(e) => {
            warn!("ip link add {DNS_DUMMY_IFACE}: spawn error {e}");
            return None;
        }
    }

    let up = tokio::process::Command::new("ip")
        .args(["link", "set", DNS_DUMMY_IFACE, "up"])
        .output()
        .await;
    if let Ok(out) = up {
        if !out.status.success() {
            warn!(
                "ip link set {DNS_DUMMY_IFACE} up: exit={} stderr={:?}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }

    Some(DNS_DUMMY_IFACE)
}

/// Remove the DNS dummy interface.  Idempotent — ignores errors.
pub(crate) async fn remove_dns_dummy() {
    let _ = tokio::process::Command::new("ip")
        .args(["link", "del", DNS_DUMMY_IFACE])
        .output()
        .await;
}

/// Configure per-link DNS on `iface_name` via systemd-resolved D-Bus.
///
/// `iface_name` should be the dedicated dummy netdev returned by
/// [`ensure_dns_dummy`] — never the physical outbound interface, or
/// `RevertLink` on disconnect will wipe NetworkManager's DNS.
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
                BackendError::SecretMissing(format!(
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
            BackendError::SecretMissing(format!(
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
        // The fragment embeds the EAP password and the group PSK in clear.
        // It was written at the umask — 0644 — and kept private only by the
        // mode strongSwan's packaging happens to give conf.d, which is a
        // distribution decision rather than something this daemon controls.
        crate::secure_file::write_private(&config_path, config_text.as_bytes(), None).map_err(|e| {
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
            return Err(swanctl_failure(
                "swanctl --load-all",
                &String::from_utf8_lossy(&out.stderr),
            ));
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
        let outbound_iface: Option<String> = gw_v4.as_ref().map(|(_, dev)| dev.clone());

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
            warn!(details = %message, "strongSwan failed to establish the FortiGate CHILD_SA");
            return Err(classify_initiate_failure(&message));
        }

        // ── Steps 6–7 wrapped in a rollback-on-error scope ───────────────────
        //
        // Once `--initiate` succeeds the IKE SA is up in the kernel. Any
        // subsequent failure — list-sas not running, `ip route` subprocess
        // bombing on EBUSY, mode-config DNS push erroring out — would
        // previously leak the SA, the endpoint host route, and the swanctl
        // config fragment, leaving the user with a half-up tunnel and no
        // way to clean it up except restarting the daemon.
        //
        // All post-initiate fallible work runs inside the `post_initiate`
        // async block. On Err the rollback below tears the SA down via
        // `swanctl --terminate --ike` and removes the side-effects we
        // installed before propagating the original error.
        let mut tunnel_routes: Vec<String> = Vec::new();
        let mut saved_default_route: Option<String> = None;

        // Helper closure that tears down everything we've installed since the
        // SA came up. Used by every rollback path below so the cleanup logic
        // stays in one place. Each step is best-effort — if it fails we still
        // try the next so the system gets back as close to clean as possible.
        let rollback_after_initiate = |conn_name: &str,
                                       endpoint_host_routes: &[String],
                                       tunnel_routes: &[String],
                                       saved_default_route: &Option<String>,
                                       config_path: &PathBuf| {
            let conn_name = conn_name.to_owned();
            let endpoint_host_routes = endpoint_host_routes.to_vec();
            let tunnel_routes = tunnel_routes.to_vec();
            let saved_default_route = saved_default_route.clone();
            let config_path = config_path.clone();
            async move {
                let _ = run_swanctl(&["--terminate", "--ike", &conn_name, "--timeout", "5"]).await;
                for spec in &tunnel_routes {
                    let mut cmd = tokio::process::Command::new("ip");
                    cmd.arg("route").arg("del");
                    for word in spec.split_whitespace() {
                        cmd.arg(word);
                    }
                    let _ = cmd.output().await;
                }
                if let Some(saved) = saved_default_route {
                    let mut cmd = tokio::process::Command::new("ip");
                    cmd.arg("route").arg("add");
                    for word in saved.split_whitespace() {
                        cmd.arg(word);
                    }
                    let _ = cmd.output().await;
                }
                for cidr in &endpoint_host_routes {
                    let _ = tokio::process::Command::new("ip")
                        .args(["route", "del", cidr])
                        .output()
                        .await;
                }
                let _ = tokio::fs::remove_file(&config_path).await;
                let _ = run_swanctl(&["--load-all"]).await;
            }
        };

        // ── Step 6: Log virtual IP from list-sas ─────────────────────────────
        match run_swanctl(&["--list-sas"]).await {
            Ok(list_out) => {
                let list_stdout = String::from_utf8_lossy(&list_out.stdout);
                match parse_virtual_ip(&list_stdout) {
                    Some(vip) => info!("mode-config assigned virtual IP: {}", vip),
                    None => info!("no virtual IP in --list-sas output (split-tunnel or parse miss)"),
                }
            }
            Err(e) => {
                warn!("--list-sas failed after successful initiate; tearing down SA: {e}");
                rollback_after_initiate(
                    &conn_name,
                    &endpoint_host_routes,
                    &tunnel_routes,
                    &saved_default_route,
                    &config_path,
                )
                .await;
                return Err(e);
            }
        }

        // ── Step 6b: Install tunnel routes ──────────────────────────────────
        // strongSwan's XFRM policies only match traffic with src=VIP.  The
        // kernel needs explicit routes that force traffic to use the VIP as
        // source address, otherwise packets leave with the physical IP and
        // bypass the tunnel entirely.
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
            // The outbound interface comes from the captured default route's
            // dev field. If that capture failed we cannot install tunnel routes
            // safely — the previous hardcoded fallback ("enp129s0") silently
            // installed routes on a non-existent or unrelated NIC on every
            // machine that didn't happen to use that exact interface name.
            let outbound_dev = outbound_iface.as_deref().ok_or_else(|| {
                BackendError::Interface(
                    "could not determine outbound interface — no default route \
                     found in main table; install a default route or check \
                     'ip route show' before retrying"
                        .into(),
                )
            })?;

            if profile.full_tunnel {
                // Full-tunnel: capture old default, then atomically swap in a
                // new one with src=VIP via the same gateway.
                let cap = tokio::process::Command::new("ip")
                    .args(["route", "show", "exact", "0.0.0.0/0"])
                    .output()
                    .await
                    .map_err(BackendError::Io)?;
                let cap_out = String::from_utf8_lossy(&cap.stdout);
                saved_default_route = cap_out.lines().next().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());

                if let Some(ref saved) = saved_default_route {
                    if let Some((gw, _dev)) = parse_gateway(saved) {
                        info!("installing full-tunnel default: via {gw} dev {outbound_dev} src {vip}");

                        // `ip route replace` is a single atomic netlink op:
                        // RTM_NEWROUTE with NLM_F_REPLACE, evaluated under the
                        // RTNL lock. The kernel swaps the matching route in
                        // place rather than running a `del` + `add` sequence,
                        // closing the brief window during which the routing
                        // table had no default at all (~1ms but enough for
                        // background traffic to error out).
                        //
                        // If the subprocess itself fails to spawn (e.g. fork
                        // ENOMEM), we still have a live SA. Roll back the SA
                        // before propagating the error.
                        let replace_out = match tokio::process::Command::new("ip")
                            .args([
                                "route", "replace", "default",
                                "via", &gw,
                                "dev", outbound_dev,
                                "src", &vip.to_string(),
                                "metric", "50",
                            ])
                            .output()
                            .await
                        {
                            Ok(o) => o,
                            Err(io) => {
                                warn!(
                                    "ip route replace default failed to spawn ({io}); \
                                     tearing down SA and restoring original default"
                                );
                                rollback_after_initiate(
                                    &conn_name,
                                    &endpoint_host_routes,
                                    &tunnel_routes,
                                    &saved_default_route,
                                    &config_path,
                                )
                                .await;
                                return Err(BackendError::Io(io));
                            }
                        };

                        if replace_out.status.success() {
                            // Store the FULL route spec, not just "default", so disconnect
                            // can delete this exact route instead of `ip route del default`
                            // (which non-deterministically removes the first matching default
                            // and may delete a parallel NM-restored default — leaving only
                            // the now-stale VPN default with src=VIP after teardown, which
                            // makes the kernel try to send packets with an unreachable
                            // source address and the network appears dead).
                            tunnel_routes.push(format!(
                                "default via {gw} dev {outbound_dev} src {vip} metric 50"
                            ));
                            info!("full-tunnel default route installed — ok");
                        } else {
                            let stderr = String::from_utf8_lossy(&replace_out.stderr);
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
            // Attach DNS to a dedicated dummy netdev so RevertLink on disconnect
            // never wipes NetworkManager's DNS on the physical interface.
            match ensure_dns_dummy().await {
                Some(name) => configure_dns_for_link(name, &effective_dns).await,
                None => None,
            }
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

        // Step 0: Revert systemd-resolved DNS, then delete the dummy netdev
        // (non-fatal).  RevertLink only touches the dummy's per-link state, so
        // NetworkManager's DNS on the physical interface is preserved.
        if let Some(ifindex) = dns_ifindex {
            revert_link_dns(ifindex).await;
            remove_dns_dummy().await;
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
        // For full-tunnel, the entry is the FULL route spec (default via GW dev IF
        // src VIP metric 50) so the kernel deletes that exact route, not whichever
        // default route happens to be first in the table — see the comment in
        // connect() where this is pushed.  For split-tunnel, the entry is a plain
        // CIDR which becomes a one-token argument; whitespace-splitting handles
        // both cases uniformly.
        for spec in &tunnel_routes {
            info!("removing tunnel route: {spec}");
            let mut cmd = tokio::process::Command::new("ip");
            cmd.arg("route").arg("del");
            for word in spec.split_whitespace() {
                cmd.arg(word);
            }
            let out = cmd
                .output()
                .await
                .map_err(BackendError::Io)?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                warn!("ip route del {spec} → {} (may already be gone)", stderr.trim());
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

// ---------------------------------------------------------------------------
// Pure-function tests
// ---------------------------------------------------------------------------
//
// These cover the parsers that translate strongSwan / iproute2 output into
// the typed values the connect/disconnect flow relies on. A regression in
// any of these silently corrupts state (wrong VIP, wrong route count, wrong
// gateway) and only manifests as a runtime networking failure — exactly the
// bug class the recent FortiGate fixes traced.
#[cfg(test)]
mod tests {
    use super::*;



    // -- Remote identity and PSK lookup -----------------------------------

    #[test]
    fn the_remote_identity_is_pinned_to_the_gateway() {
        let conf = generate_swanctl_config("c", "p", &fg(""), "pw", "psk", true);
        let remote_at = conf.find("remote {").expect("remote block");
        let children_at = conf.find("children").expect("children block");
        let id_at = conf[remote_at..children_at]
            .find("id = fw.example.com")
            .expect("remote.id must carry the gateway address");
        // Nesting, not mere presence: mis-nested into `local {}` this would be
        // our IDi rather than the peer's expected identity — the opposite
        // meaning, and a substring-anywhere check would pass either way.
        assert!(id_at > 0, "id must sit inside the remote block");
    }

    #[test]
    fn the_psk_is_keyed_to_the_gateway_with_a_wildcard_fallback() {
        // The pair `remote.id` depends on. An unkeyed PSK matches every peer,
        // which is ambiguous once a second profile is loaded. `id-1` catches the
        // IP or FQDN a FortiGate sends as IDr; `%any` alone does not — a secret
        // keyed only to `%any` fails to match an IP-form IDr, which is the bug
        // the macOS helper shipped twice.
        let conf = generate_swanctl_config("c", "p", &fg(""), "pw", "psk", true);
        let secrets_at = conf.find("secrets {").expect("secrets block");
        let tail = &conf[secrets_at..];
        assert!(tail.contains("id-1 = fw.example.com"), "{conf}");
        assert!(tail.contains("id-2 = %any"), "{conf}");
    }

    #[test]
    fn the_local_identity_is_not_confused_with_the_remote_one() {
        // Both blocks carry an `id`, and they mean opposite things. Pinning the
        // guard here so a future edit cannot quietly move one into the other.
        let conf = generate_swanctl_config("c", "p", &fg("sybr-porsgrunn"), "pw", "psk", true);
        let local_at = conf.find("local {").expect("local block");
        let remote_at = conf.find("remote {").expect("remote block");
        let local_block = &conf[local_at..remote_at];
        assert!(
            local_block.contains(r#"id = "sybr-porsgrunn""#),
            "our IDi belongs in local:\n{conf}"
        );
        assert!(
            !local_block.contains("id = fw.example.com"),
            "the gateway's identity must not land in local:\n{conf}"
        );
    }

    #[test]
    fn an_identity_rejection_is_not_reported_as_a_bad_password() {
        // Nothing typed into the password field fixes an ID mismatch, so it
        // must not be described as a credential problem. Linux had no
        // diagnostic for this at all before remote.id was pinned.
        let e = classify_initiate_failure("received INVALID_ID_INFORMATION notify");
        match e {
            BackendError::AuthenticationFailed(msg) => {
                assert!(msg.contains("identity"), "must name the identity: {msg}");
                assert!(msg.contains("Local ID"), "must point at the field: {msg}");
                assert!(
                    !msg.contains("password and PSK"),
                    "must not read as a credential failure: {msg}"
                );
            }
            other => panic!("expected an auth-shaped error, got {other:?}"),
        }
    }

    #[test]
    fn a_credential_failure_still_reads_as_one() {
        // The new branch sits above the credential one; make sure it did not
        // swallow it.
        match classify_initiate_failure("received EAP_FAILURE") {
            BackendError::AuthenticationFailed(msg) => {
                assert!(msg.contains("password and PSK"), "{msg}");
            }
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    // -- Dead Peer Detection ---------------------------------------------

    #[test]
    fn dead_peer_detection_is_enabled() {
        // `dpd_delay` defaults to 0s, i.e. off. Without it charon never
        // notices a peer that vanished without a clean IKE DELETE: the IKE_SA
        // stays ESTABLISHED, the full-tunnel default keeps sourcing packets
        // from a virtual IP the dead tunnel no longer owns, and the machine has
        // no internet while list-sas insists it is connected.
        let conf = generate_swanctl_config("c", "p", &fg(""), "pw", "psk", true);
        assert!(
            conf.contains("dpd_delay"),
            "DPD off means a dead peer is never detected:\n{conf}"
        );
    }

    #[test]
    fn a_dead_peer_clears_the_sa_rather_than_rebuilding_it() {
        // The load-bearing choice, and the one place this backend deliberately
        // differs from the macOS helper.
        //
        // This daemon owns the routes: `spawn_monitor_task` sees the SA vanish
        // and runs `backend.disconnect()`, which restores the saved default
        // route, reverts DNS and drops the endpoint host routes. `clear` is
        // what produces that signal.
        //
        // `restart` re-negotiates under a fresh IKE_SA behind the daemon's
        // back. Mode-config can assign a different virtual IP while the default
        // route still carries `src <old vip>` — the monitor sees an Active SA,
        // finds nothing to reconcile, and the result is a black hole the GUI
        // reports as Connected. Worse than the bug being fixed, because it is
        // invisible.
        let conf = generate_swanctl_config("c", "p", &fg(""), "pw", "psk", true);
        assert!(
            conf.contains("dpd_action = clear"),
            "a detected-dead peer must close the SA so the daemon can clean up:\n{conf}"
        );
        assert!(
            !conf.contains("dpd_action = restart"),
            "restart rebuilds the tunnel behind the route manager's back:\n{conf}"
        );
    }

    #[test]
    fn no_retransmit_option_reaches_swanctl() {
        // `retransmit_timeout` / `_base` / `_tries` are not swanctl.conf
        // connection options — they live under `charon` in strongswan.conf,
        // daemon-wide. strongSwan 6.x rejects an unknown option by discarding
        // the ENTIRE connection, so one of these added to speed up DPD
        // detection stops the tunnel loading at all. Ported from the macOS
        // helper's guard, which exists because someone tried it.
        let conf = generate_swanctl_config("c", "p", &fg(""), "pw", "psk", true);
        assert!(
            !conf.contains("retransmit_"),
            "retransmit_* are invalid here and break the whole connection:\n{conf}"
        );
    }

    #[test]
    fn dpd_settings_sit_at_the_levels_swanctl_expects() {
        // `dpd_delay` is a connection option and `dpd_action` a child option.
        // Swapped, strongSwan discards the connection as unknown-option and the
        // tunnel silently stops loading — the same failure mode as the
        // retransmit guard above, which is why this is pinned rather than
        // trusted to review.
        let conf = generate_swanctl_config("c", "p", &fg(""), "pw", "psk", true);
        let children_at = conf.find("children").expect("children block");
        let delay_at = conf.find("dpd_delay").expect("dpd_delay");
        let action_at = conf.find("dpd_action").expect("dpd_action");
        assert!(delay_at < children_at, "dpd_delay belongs on the connection");
        assert!(action_at > children_at, "dpd_action belongs on the child");
    }

    // -- Local ID (IDi) and swanctl escaping -----------------------------

    fn fg(local_id: &str) -> FortiGateConfig {
        FortiGateConfig {
            host: "fw.example.com".to_owned(),
            username: "alice".to_owned(),
            password: supermgr_core::vpn::profile::SecretRef::new("pw".to_owned()),
            psk: supermgr_core::vpn::profile::SecretRef::new("psk".to_owned()),
            dns_servers: Vec::new(),
            routes: Vec::new(),
            local_id: local_id.to_owned(),
        }
    }

    #[test]
    fn a_local_id_reaches_the_swanctl_config() {
        // The bug this fixes: the field existed on the profile and in the macOS
        // app, and this backend never read it — so a gateway that routes by
        // peer ID before authentication could not be reached from Linux at all.
        let conf = generate_swanctl_config("c", "p", &fg("sybr-porsgrunn"), "pw", "psk", true);
        assert!(
            conf.contains(r#"id = "sybr-porsgrunn""#),
            "local_id must be emitted as the IKE identity:\n{conf}"
        );
        assert!(
            conf.contains("eap_id = alice"),
            "the EAP identity is separate and stays the username"
        );
    }

    #[test]
    fn an_empty_local_id_keeps_the_previous_identity() {
        // Deliberately NOT the macOS behaviour of omitting the line. Omitting
        // it makes strongSwan default IDi to the local IP, which would change
        // the identity every existing Linux profile connects with. Nobody's
        // working tunnel moves because we added a field.
        let conf = generate_swanctl_config("c", "p", &fg(""), "pw", "psk", true);
        assert!(conf.contains("id = alice"), "{conf}");
        assert!(!conf.contains(r#"id = """#), "must not emit an empty identity");
    }

    #[test]
    fn a_whitespace_only_local_id_counts_as_unset() {
        let conf = generate_swanctl_config("c", "p", &fg("   "), "pw", "psk", true);
        assert!(conf.contains("id = alice"), "{conf}");
    }

    #[test]
    fn a_quote_in_a_secret_cannot_escape_its_string() {
        // Found while adding local_id. swanctl values are double-quoted, and
        // these were interpolated raw — so a PSK containing `"` terminated the
        // string early and left the rest to be parsed as config, whereupon
        // strongSwan discards the whole connection and the tunnel fails to load
        // with nothing pointing at the password as the cause.
        let conf = generate_swanctl_config("c", "p", &fg(""), r#"pa"ss"#, r#"p"sk"#, true);
        assert!(conf.contains(r#"secret = "p\"sk""#), "PSK not escaped:\n{conf}");
        assert!(conf.contains(r#"secret = "pa\"ss""#), "password not escaped:\n{conf}");

        // Every quote in the rendered file is either a delimiter or escaped.
        for (i, line) in conf.lines().enumerate() {
            let unescaped = line
                .char_indices()
                .filter(|(j, c)| *c == '"' && (*j == 0 || line.as_bytes()[j - 1] != b'\\'))
                .count();
            assert!(
                unescaped % 2 == 0,
                "line {i} has an unbalanced quote: {line}"
            );
        }
    }

    #[test]
    fn a_backslash_in_a_secret_is_escaped() {
        // A domain-qualified password like `CORP\alice` is entirely ordinary.
        let conf = generate_swanctl_config("c", "p", &fg(""), r"CORP\alice", "psk", true);
        assert!(conf.contains(r#"secret = "CORP\\alice""#), "{conf}");
    }

    #[test]
    fn a_newline_in_a_secret_is_dropped_not_smuggled() {
        // A newline would end the value and let the remainder be read as
        // config directives. Dropping is defensive; the secret is already
        // broken if it contains one.
        let conf = generate_swanctl_config("c", "p", &fg(""), "a\nb", "psk", true);
        assert!(conf.contains(r#"secret = "ab""#), "{conf}");
    }

    #[test]
    fn a_local_id_with_a_quote_is_escaped_too() {
        let conf = generate_swanctl_config("c", "p", &fg(r#"we"ird"#), "pw", "psk", true);
        assert!(conf.contains(r#"id = "we\"ird""#), "{conf}");
    }

    /// Verbatim stderr from `swanctl --load-all` on a machine where
    /// strongswan.service is installed but not started — the state Arch
    /// leaves after `pacman -S strongswan`, since the unit ships disabled.
    const CHARON_DOWN_STDERR: &str = "\
connecting to 'unix:///var/run/charon.vici' failed: No such file or directory
strongSwan 6.0.7 swanctl (--load-all/-q)
load credentials, authorities, pools and connections
usage:
  swanctl --load-all [--raw|--pretty] [--clear] [--noprompt]
options:
  --help            (-h)  show usage information
  --clear           (-c)  clear previously loaded credentials
  --debug           (-v)  set debug level, default: 1
error: connecting to 'default' URI failed: No such file or directory
";

    #[test]
    fn stopped_charon_is_a_prerequisite_naming_the_fix() {
        let err = swanctl_failure("swanctl --load-all", CHARON_DOWN_STDERR);
        let msg = err.to_string();
        assert!(matches!(err, BackendError::Prerequisite(_)), "{msg}");
        assert!(msg.contains("systemctl enable --now strongswan.service"), "{msg}");
    }

    #[test]
    fn the_usage_block_never_reaches_the_user() {
        // This is what the GUI used to display as the connection error: one
        // useful line followed by swanctl's whole option list.
        let msg = swanctl_failure("swanctl --load-all", CHARON_DOWN_STDERR).to_string();
        assert!(!msg.contains("show usage information"), "{msg}");
        assert!(!msg.contains("--noprompt"), "{msg}");
        assert!(msg.lines().count() == 1, "expected one line, got: {msg}");
    }

    #[test]
    fn a_real_swanctl_error_keeps_its_message() {
        let stderr = "establishing CHILD_SA supermgr-abc failed\n";
        let err = swanctl_failure("swanctl --initiate", stderr);
        assert!(matches!(err, BackendError::Subprocess { .. }));
        assert!(err.to_string().contains("establishing CHILD_SA"), "{err}");
    }

    #[test]
    fn charon_unreachable_does_not_fire_on_unrelated_failures() {
        assert!(!charon_unreachable("establishing CHILD_SA supermgr-abc failed"));
        assert!(charon_unreachable(CHARON_DOWN_STDERR));
    }

    #[test]
    fn a_bare_child_sa_failure_is_not_called_unreachable() {
        let raw = "initiate failed: establishing CHILD_SA 'supermgr-a132dcaa7713' failed";
        let error = classify_initiate_failure(raw);
        assert!(matches!(error, BackendError::NegotiationFailed(_)), "{error}");
        assert!(!error.to_string().contains("supermgr-a132dcaa7713"), "{error}");
    }

    #[test]
    fn initiate_failures_keep_distinct_actionable_categories() {
        assert!(matches!(
            classify_initiate_failure("received EAP_FAILURE"),
            BackendError::AuthenticationFailed(_)
        ));
        assert!(matches!(
            classify_initiate_failure("NO_PROPOSAL_CHOSEN"),
            BackendError::NegotiationFailed(_)
        ));
        assert!(matches!(
            classify_initiate_failure("send failed: Network is unreachable"),
            BackendError::ConnectionFailed(_)
        ));
        assert!(matches!(
            classify_initiate_failure("initiate timed out"),
            BackendError::Timeout { seconds: 30 }
        ));
    }

    #[test]
    fn parse_gateway_extracts_via_and_dev() {
        let line = "default via 192.0.2.1 dev enp14s0 proto dhcp src 192.0.2.121 metric 100";
        assert_eq!(
            parse_gateway(line),
            Some(("192.0.2.1".into(), "enp14s0".into()))
        );
    }

    #[test]
    fn parse_gateway_handles_unordered_tokens() {
        // ip(8) does not always emit `via` before `dev`; the parser must not assume order.
        let line = "default dev wlp4s0 via 10.0.0.1 metric 600";
        assert_eq!(
            parse_gateway(line),
            Some(("10.0.0.1".into(), "wlp4s0".into()))
        );
    }

    #[test]
    fn parse_gateway_returns_none_when_either_missing() {
        assert_eq!(parse_gateway("default dev enp14s0"), None);
        assert_eq!(parse_gateway("default via 192.168.1.1"), None);
        assert_eq!(parse_gateway(""), None);
    }

    #[test]
    fn parse_virtual_ip_picks_last_bracket_pair_on_local_line() {
        let out = "\
            local  'admin' @ 192.0.2.121[4500] [192.168.251.1]\n\
            remote '203.0.113.10' @ 203.0.113.10[4500]\n";
        assert_eq!(
            parse_virtual_ip(out),
            Some("192.168.251.1".parse().unwrap())
        );
    }

    #[test]
    fn parse_virtual_ip_ignores_port_numbers_in_brackets() {
        // [4500] is a port, not an IP — must not be returned.
        let out = "local 'u' @ 192.168.1.10[4500]\n";
        assert_eq!(parse_virtual_ip(out), None);
    }

    #[test]
    fn parse_virtual_ip_returns_none_without_local_line() {
        let out = "remote '1.2.3.4' @ 1.2.3.4[500] [10.0.0.5]\n";
        assert_eq!(parse_virtual_ip(out), None);
    }

    #[test]
    fn parse_active_routes_collects_remote_cidrs() {
        let out = "\
            CHILD_SAs:\n\
              supermgr-abc{1}: ESPv2 ...\n\
                local  192.168.251.1/32\n\
                remote 0.0.0.0/0\n\
              supermgr-abc{2}: ESPv2 ...\n\
                remote 10.0.0.0/8\n\
                remote 172.16.0.0/12\n";
        assert_eq!(
            parse_active_routes(out),
            vec!["0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12"]
        );
    }

    #[test]
    fn parse_active_routes_skips_quoted_remote_id_lines() {
        // `remote '1.2.3.4' @ 1.2.3.4[500]` is the peer identity, not a route.
        let out = "remote '79.160.88.198' @ 79.160.88.198[500]\n  remote 10.0.0.0/8\n";
        assert_eq!(parse_active_routes(out), vec!["10.0.0.0/8"]);
    }

    #[test]
    fn parse_sa_bytes_sums_across_child_sas() {
        let out = "\
            in  c1234abcd, 1024 bytes, 10 packets\n\
            out d4321efab, 2048 bytes, 20 packets\n\
            in  cabcd9999, 100 bytes, 1 packets\n\
            out d9999abcd, 200 bytes, 2 packets\n";
        // (in_bytes, out_bytes)
        assert_eq!(parse_sa_bytes(out), (1124, 2248));
    }

    #[test]
    fn parse_sa_bytes_returns_zero_when_no_traffic_lines() {
        let out = "no SAs found\n";
        assert_eq!(parse_sa_bytes(out), (0, 0));
    }

    #[test]
    fn parse_sa_bytes_ignores_unrelated_lines() {
        // The parser must not misread direction tokens out of garbage like
        // "input gateway ..." or stat headers.
        let out = "\
            stats refresh interval: 10s\n\
            input gateway: 192.168.1.1\n\
            in  c0, 50 bytes, 1 packets\n";
        assert_eq!(parse_sa_bytes(out), (50, 0));
    }
}


