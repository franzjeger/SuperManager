//! Install / uninstall the bundled `tailscaled` binary as a
//! system-level LaunchDaemon.
//!
//! Why this lives in the privileged helper: macOS `tailscaled`
//! requires root because it manages the kernel TUN device, the
//! routing table, and DNS resolver overrides. The unprivileged GUI
//! has no business doing any of that — it hands the bundled binary
//! path over to us, we copy it to a stable system location, write a
//! launchd plist, and bootstrap the daemon.
//!
//! Lifecycle:
//!   • install: copy `tailscaled` to /usr/local/sbin/, write
//!     /Library/LaunchDaemons/com.sybr.tailscaled.plist, bootstrap.
//!   • status:  read-only check that the launchd job is bootstrapped
//!     and reports a process running.
//!   • uninstall: bootout, remove plist + binary + state.
//!
//! State directory: `/var/lib/tailscale` — same path the official
//! Tailscale.app uses, so users who later reinstall the App Store
//! version pick up their existing tailnet membership without
//! having to re-auth.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Stable on-disk path for the daemon binary. The helper copies the
/// bundled `tailscaled` here on install. We don't run it directly
/// from inside the .app bundle because that location moves whenever
/// the user moves SuperManager.app, drags it into Trash, etc., and
/// the LaunchDaemon plist would then point at a missing binary.
const DAEMON_INSTALL_PATH: &str = "/usr/local/sbin/supermanager-tailscaled";

/// Where launchd looks for system daemons. Anything in this directory
/// owned by root with the right permissions is auto-bootstrapped at
/// boot.
const LAUNCH_DAEMON_PLIST: &str = "/Library/LaunchDaemons/com.sybr.tailscaled.plist";

/// Tailscale's standard state directory. We follow the official
/// daemon's convention so the user's tailnet membership survives
/// switching between SuperManager and Tailscale.app.
const STATE_DIR: &str = "/var/lib/tailscale";

/// Launchd label for the job. Used in `launchctl print`,
/// `bootstrap`, `bootout`. Mirrors the bundle id pattern we use
/// for the SuperManager helper itself.
const LAUNCH_LABEL: &str = "com.sybr.tailscaled";

#[derive(Deserialize, Debug)]
pub struct InstallArgs {
    /// Absolute path to the bundled `tailscaled` binary inside the
    /// SuperManager app bundle. The Swift caller passes
    /// `Bundle.main.url(forResource: "tailscaled", ...)`.
    pub bundled_daemon_path: String,
}

#[derive(Deserialize, Debug)]
pub struct UninstallArgs {}

#[derive(Deserialize, Debug)]
pub struct DaemonStatusArgs {}

#[derive(Serialize, Debug)]
pub struct DaemonStatus {
    /// True iff the launchd job is registered AND the corresponding
    /// process is alive.
    pub running: bool,
    /// True iff the daemon binary exists at its installed path.
    pub installed: bool,
    /// Free-form diagnostic for the UI to show on errors.
    pub message: String,
}

#[derive(Serialize, Debug)]
pub struct InstallResult {
    pub success: bool,
    pub message: String,
}

/// Read launchd's view of the daemon job. Distinguishes:
///   • `installed && running` — happy path.
///   • `installed && !running` — plist registered but process down.
///     Could be a transient crash; UI shows "Start" button.
///   • `!installed` — plist not present. UI shows "Install" button.
pub fn status(_: DaemonStatusArgs) -> Result<DaemonStatus> {
    let installed = Path::new(LAUNCH_DAEMON_PLIST).exists()
        && Path::new(DAEMON_INSTALL_PATH).exists();

    if !installed {
        return Ok(DaemonStatus {
            running: false,
            installed: false,
            message: "tailscaled is not installed.".to_string(),
        });
    }

    // `launchctl print system/<label>` returns 0 if the job exists
    // and includes its current state. We grep for `state = running`.
    let out = Command::new("/bin/launchctl")
        .args(["print", &format!("system/{}", LAUNCH_LABEL)])
        .output()
        .context("running launchctl print")?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    let running = stdout.contains("state = running")
        || stdout.contains("state = waiting"); // waiting == launchd has it queued

    Ok(DaemonStatus {
        running,
        installed,
        message: if running {
            "tailscaled is running.".to_string()
        } else {
            "tailscaled is installed but not running.".to_string()
        },
    })
}

/// Install (and start) the bundled `tailscaled` as a system
/// LaunchDaemon. Idempotent — calling on an already-installed
/// daemon re-copies the binary (in case the version bundled with
/// SuperManager has changed) and re-bootstraps.
pub fn install(args: InstallArgs) -> Result<InstallResult> {
    let src = Path::new(&args.bundled_daemon_path);
    if !src.exists() {
        bail!("bundled daemon not found at {}", args.bundled_daemon_path);
    }
    if !src.is_file() {
        bail!("bundled daemon path is not a regular file");
    }

    // 1. Make sure the install directory + state directory exist.
    fs::create_dir_all(Path::new(DAEMON_INSTALL_PATH).parent().unwrap())
        .context("creating /usr/local/sbin")?;
    fs::create_dir_all(STATE_DIR).context("creating tailscale state dir")?;
    // tailscaled writes secrets to its state dir; lock it down to root.
    let _ = Command::new("/bin/chmod")
        .args(["0700", STATE_DIR])
        .status();
    let _ = Command::new("/usr/sbin/chown")
        .args(["root:wheel", STATE_DIR])
        .status();

    // 2. Bootout any prior incarnation of the daemon. Failures are
    // expected on first install (job doesn't exist) — ignored.
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{}", LAUNCH_LABEL)])
        .status();

    // 3. Copy the bundled binary to its stable location. We copy
    // (not symlink) so the daemon keeps working after the user
    // moves SuperManager.app or trashes it temporarily.
    fs::copy(src, DAEMON_INSTALL_PATH)
        .with_context(|| format!("copying daemon to {DAEMON_INSTALL_PATH}"))?;
    let _ = Command::new("/bin/chmod")
        .args(["0755", DAEMON_INSTALL_PATH])
        .status();
    let _ = Command::new("/usr/sbin/chown")
        .args(["root:wheel", DAEMON_INSTALL_PATH])
        .status();

    // 4. Write the LaunchDaemon plist. Pinning state-dir + socket
    // path matches Tailscale.app's defaults so the CLI we bundle
    // (which probes the standard socket location) talks to our
    // daemon without any --socket override.
    let plist = render_launchd_plist();
    fs::write(LAUNCH_DAEMON_PLIST, plist)
        .with_context(|| format!("writing {LAUNCH_DAEMON_PLIST}"))?;
    let _ = Command::new("/bin/chmod")
        .args(["0644", LAUNCH_DAEMON_PLIST])
        .status();
    let _ = Command::new("/usr/sbin/chown")
        .args(["root:wheel", LAUNCH_DAEMON_PLIST])
        .status();

    // 5. Bootstrap the job. `kickstart -k` then forces a restart in
    // case launchd cached an earlier instance.
    let bootstrap = Command::new("/bin/launchctl")
        .args(["bootstrap", "system", LAUNCH_DAEMON_PLIST])
        .output()
        .context("bootstrapping LaunchDaemon")?;
    if !bootstrap.status.success() {
        let stderr = String::from_utf8_lossy(&bootstrap.stderr);
        bail!("launchctl bootstrap failed: {}", stderr.trim());
    }

    let _ = Command::new("/bin/launchctl")
        .args(["kickstart", "-k", &format!("system/{}", LAUNCH_LABEL)])
        .status();

    Ok(InstallResult {
        success: true,
        message: format!("tailscaled installed at {DAEMON_INSTALL_PATH}"),
    })
}

/// Uninstall the daemon. Removes the LaunchDaemon, the binary, and
/// the launchd registration. Leaves the state directory intact —
/// the user's node key + tailnet identity is in there, and a future
/// reinstall (whether ours or Tailscale.app's) will pick it up.
pub fn uninstall(_: UninstallArgs) -> Result<InstallResult> {
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{}", LAUNCH_LABEL)])
        .status();
    if Path::new(LAUNCH_DAEMON_PLIST).exists() {
        let _ = fs::remove_file(LAUNCH_DAEMON_PLIST);
    }
    if Path::new(DAEMON_INSTALL_PATH).exists() {
        let _ = fs::remove_file(DAEMON_INSTALL_PATH);
    }
    Ok(InstallResult {
        success: true,
        message: "tailscaled uninstalled. State directory preserved.".to_string(),
    })
}

/// Find PID of the running tailscaled. Used by exit-node setup to
/// snapshot tailscaled's active underlay connections so we can
/// pin them to the LOCAL default before flipping the split-default
/// routes — without these pins the daemon's own WireGuard packets
/// would loop through utun, killing the tunnel and the user's
/// internet.
fn find_tailscaled_pid() -> Option<u32> {
    let out = Command::new("/bin/ps")
        .args(["-Ao", "pid,command"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if line.contains("tailscaled") && !line.contains("ps -Ao") {
            // First numeric token is the pid.
            if let Some(pid) = line.split_whitespace().next() {
                if let Ok(n) = pid.parse() {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Detect the LOCAL (pre-tailscale) default gateway. Reads `route
/// -n get default` and pulls out the gateway IP. Used as the
/// next-hop for tailscaled's underlay-endpoint pin routes.
fn detect_local_gateway() -> Option<String> {
    let out = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("gateway: ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Snapshot tailscaled's currently-connected external endpoints
/// from `lsof -p <pid> -i -P -n`. We pull IP addresses from
/// remote-side fields like `udp 1.2.3.4:41641` or
/// `tcp 5.6.7.8:443`. Filter to global-unicast IPv4 (skip
/// loopback, link-local, RFC1918, CGNAT — those don't need to
/// bypass split routes).
fn collect_tailscaled_underlay_ips(pid: u32) -> Vec<String> {
    let out = Command::new("/usr/sbin/lsof")
        .args(["-p", &pid.to_string(), "-i", "-P", "-n"])
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return vec![],
    };
    let mut ips = Vec::<String>::new();
    for line in stdout.lines() {
        // Format example:
        // tailscale 50956 root 12u IPv4 0x... 0t0 UDP 192.168.x.y:41641->88.93.37.13:443
        // We want the part after "->"
        if let Some(arrow) = line.find("->") {
            let rest = &line[arrow + 2..];
            // Strip trailing state tags, take up to space or end
            let endpoint = rest.split_whitespace().next().unwrap_or("");
            // endpoint is like "88.93.37.13:443" or "[::1]:53"
            if let Some(colon) = endpoint.rfind(':') {
                let ip = &endpoint[..colon];
                // Skip IPv6 (square brackets present) for now
                if ip.starts_with('[') { continue; }
                if !is_routeable_public_ipv4(ip) { continue; }
                if !ips.contains(&ip.to_string()) {
                    ips.push(ip.to_string());
                }
            }
        }
    }
    ips
}

/// Quick check: looks like a public IPv4 we should bypass-pin.
/// Skip loopback (127), link-local (169.254), RFC1918 (10/8,
/// 172.16/12, 192.168/16), CGNAT/tailnet (100.64/10), multicast.
fn is_routeable_public_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 { return false; }
    let nums: Option<Vec<u8>> = parts.iter().map(|s| s.parse::<u8>().ok()).collect();
    let n = match nums { Some(v) if v.len() == 4 => v, _ => return false };
    match n[0] {
        0 | 127 => false,                  // unspecified, loopback
        10 => false,                       // RFC1918
        100 if (64..=127).contains(&n[1]) => false, // CGNAT / tailnet
        169 if n[1] == 254 => false,       // link-local
        172 if (16..=31).contains(&n[1]) => false, // RFC1918
        192 if n[1] == 168 => false,       // RFC1918
        224..=239 => false,                // multicast
        _ => true,
    }
}

/// State file recording the exemption routes installed for the
/// current exit-node session. Lets `remove_exit_routes` clean up
/// without re-deriving the same set (tailscaled's connections may
/// have changed by then).
const EXEMPTION_STATE_FILE: &str = "/var/run/supermanager-tailscale-exemptions";

fn write_exemption_state(ips: &[String]) {
    let _ = fs::write(EXEMPTION_STATE_FILE, ips.join("\n"));
}

fn read_exemption_state() -> Vec<String> {
    fs::read_to_string(EXEMPTION_STATE_FILE)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect())
        .unwrap_or_default()
}

/// Install split-default IPv4 routes via the Tailscale `utun*`
/// interface so non-tailnet traffic is forwarded through the
/// currently-selected exit node.
///
/// Why this exists: open-source `tailscaled` on macOS does NOT
/// install a default-route override when an exit node is selected.
/// The official Tailscale.app does this via NetworkExtension —
/// not available to us. So `tailscale set --exit-node=<peer>`
/// silently completes (prefs updated, DNS reconfigured) but
/// internet traffic still leaves via the local default gateway.
/// User reports "exit-node doesn't work" — symptom is correct.
///
/// Strategy: add two `/1` routes (`0.0.0.0/1` and `128.0.0.0/1`)
/// pointing at Tailscale's utun. Together they cover the entire
/// IPv4 space and override the existing `0.0.0.0/0` default by
/// virtue of being more specific. Standard exit-node implementation
/// pattern.
///
/// **Safety**: the caller (AppState.setExitNodeWithSafety) MUST
/// follow installation with an internet probe. If the probe fails,
/// call `remove_exit_routes` plus `tailscale set --exit-node=`
/// before the user is stranded.
///
/// Returns the interface name if the IPv4 split-default `0.0.0.0/1` is currently
/// owned by a LIVE foreign full tunnel (Azure/OpenVPN, WireGuard, or strongSwan
/// IKEv2) on a utun OTHER than `ts_utun`. The exit-node machinery must never
/// delete/steal `0/1` from such a tunnel — it installs the exact same
/// `0/1`+`128/1` split-default pair, and stealing it black-holes that VPN's
/// entire traffic (and all DNS), freezing the Mac.
fn foreign_full_tunnel_owns_default(ts_utun: &str) -> Option<String> {
    let iface = crate::strongswan::route_iface_family("0.0.0.0/1", "-inet")?;
    if iface == ts_utun || !iface.starts_with("utun") {
        return None; // ours, or not a tunnel at all
    }
    // A non-tailscale utun holds 0/1. Confirm a live foreign backend owns it:
    // WG/OpenVPN already in the protected set, OR a live OpenVPN pid (catches
    // Azure/OpenVPN during its connect window before the CONNECTED log line),
    // OR a live strongSwan SA.
    let foreign = crate::strongswan::foreign_tunnel_ifaces();
    if foreign.contains(&iface)
        || crate::openvpn::has_live_tunnel()
        || crate::strongswan::has_established_strongswan_sa()
    {
        return Some(iface);
    }
    None
}

pub fn install_exit_routes(_: ExitRoutesArgs) -> Result<InstallResult> {
    tracing::info!("install_exit_routes: starting");
    let utun = detect_tailscale_utun()
        .context("could not find Tailscale utun interface — is tailscaled running?")?;
    tracing::info!(utun = %utun, "install_exit_routes: detected utun");
    let local_gateway = detect_local_gateway()
        .context("could not detect local default gateway")?;

    // 1. **Exemption snapshot** — read tailscaled's currently
    // active underlay endpoints (UDP/TCP to public IPs) BEFORE we
    // change routing. These are the IPs the daemon needs to reach
    // for WireGuard transport, DERP relay, and controlplane API
    // calls. With the /1 routes installed, those packets would
    // also get encapsulated through utun → infinite loop → dead
    // tunnel → dead internet.
    //
    // Tailscale.app dodges this with NetworkExtension: the
    // extension binds its outbound socket directly to the
    // physical interface, sidestepping the routing table for its
    // own packets. We can't do that without the entitlement, so
    // we pin each underlay IP to the local default explicitly.
    let exempt_ips = match find_tailscaled_pid() {
        Some(pid) => collect_tailscaled_underlay_ips(pid),
        None => return Err(anyhow::anyhow!("tailscaled not running")),
    };

    // Defensive: nuke any previously-installed exemption routes
    // (could be stale from a half-applied earlier run).
    for ip in &read_exemption_state() {
        let _ = Command::new("/sbin/route")
            .args(["delete", "-host", ip])
            .output();
    }

    // 2. Install exemption host routes (-host = /32) pointing at
    // the local default gateway. These are MORE SPECIFIC than the
    // /1 routes we'll add next, so they win in the routing
    // longest-prefix match.
    let mut installed_exemptions = Vec::new();
    for ip in &exempt_ips {
        // Pre-clean any stale entry.
        let _ = Command::new("/sbin/route")
            .args(["delete", "-host", ip])
            .output();
        let r = Command::new("/sbin/route")
            .args(["-q", "add", "-host", ip, &local_gateway])
            .output();
        match r {
            Ok(o) if o.status.success() => installed_exemptions.push(ip.clone()),
            Ok(o) => {
                tracing::warn!(
                    "exemption add {ip} via {local_gateway} failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => tracing::warn!("exemption add {ip} spawn error: {e}"),
        }
    }
    write_exemption_state(&installed_exemptions);

    // 2.5 OWNERSHIP GATE — never steal the shared split-default from a live
    // FOREIGN full tunnel. Azure VPN (rendered as an OpenVPN redirect-gateway
    // full tunnel), WireGuard, and strongSwan all install the EXACT same
    // 0/1+128/1 pair. If one currently owns 0/1 and we blindly `route delete` it
    // (step 3) to point the pair at the tailscale utun, that VPN's entire
    // traffic — and on macOS all DNS with it — black-holes, and the machine
    // appears frozen. The user explicitly brought that tunnel up; the exit node
    // must stand down. (This is the bug that bricked the Mac when connecting the
    // Azure VPN while a tailscale exit node was active: reconcile_exit_node kept
    // calling this every 30s and stealing 0/1 from Azure.)
    if let Some(owner) = foreign_full_tunnel_owns_default(&utun) {
        rollback_exemptions(&installed_exemptions);
        bail!(
            "refusing to install exit-node routes: 0.0.0.0/1 is owned by a live \
             foreign full tunnel ({owner}). Disconnect that VPN before using a \
             tailscale exit node."
        );
    }

    // 3. Idempotent: nuke any existing split routes before adding.
    let _ = Command::new("/sbin/route").args(["delete", "-net", "0.0.0.0/1"]).output();
    let _ = Command::new("/sbin/route").args(["delete", "-net", "128.0.0.0/1"]).output();
    let _ = Command::new("/sbin/route").args(["delete", "-inet6", "-net", "::/1"]).output();
    let _ = Command::new("/sbin/route").args(["delete", "-inet6", "-net", "8000::/1"]).output();

    // 4. Install IPv4 split.
    let r1 = Command::new("/sbin/route")
        .args(["-q", "add", "-net", "0.0.0.0/1", "-interface", &utun])
        .output()
        .context("route add 0.0.0.0/1")?;
    if !r1.status.success() {
        rollback_exemptions(&installed_exemptions);
        bail!("route add 0.0.0.0/1 failed: {}",
              String::from_utf8_lossy(&r1.stderr).trim());
    }
    let r2 = Command::new("/sbin/route")
        .args(["-q", "add", "-net", "128.0.0.0/1", "-interface", &utun])
        .output()
        .context("route add 128.0.0.0/1")?;
    if !r2.status.success() {
        let _ = Command::new("/sbin/route").args(["delete", "-net", "0.0.0.0/1"]).output();
        rollback_exemptions(&installed_exemptions);
        bail!("route add 128.0.0.0/1 failed: {}",
              String::from_utf8_lossy(&r2.stderr).trim());
    }
    // IPv6 best-effort. Ignore failures — many networks are v4-only.
    let _ = Command::new("/sbin/route")
        .args(["-q", "add", "-inet6", "-net", "::/1", "-interface", &utun]).output();
    let _ = Command::new("/sbin/route")
        .args(["-q", "add", "-inet6", "-net", "8000::/1", "-interface", &utun]).output();

    Ok(InstallResult {
        success: true,
        message: format!(
            "Exit routes installed via {utun} (with {} underlay exemptions via {local_gateway})",
            installed_exemptions.len()
        ),
    })
}

/// Roll back exemption host-routes when split-route install fails.
/// We don't return errors for individual deletions — best-effort.
fn rollback_exemptions(ips: &[String]) {
    for ip in ips {
        let _ = Command::new("/sbin/route")
            .args(["delete", "-host", ip])
            .output();
    }
    let _ = fs::remove_file(EXEMPTION_STATE_FILE);
}

/// Forcibly write the LIVE DNS state via `scutil`, bypassing
/// configd's normal merge logic. Used when `networksetup` writes
/// to Setup but configd refuses to apply it to State (which we
/// have observed when an IPv6 RA-derived nameserver gets stuck
/// in the live state and shadows our manual config).
///
/// We discover the service UUID dynamically from the State
/// store, so this works regardless of the user's specific
/// service ID.
pub fn force_dns_state(args: SetDnsArgs) -> Result<InstallResult> {
    if args.servers.is_empty() {
        bail!("force_dns_state requires at least one server");
    }
    // Find the active service UUID. We look in
    // Setup:/Network/Service/<UUID>/DNS keys and pick the one
    // that has IPv4 servers in its config.
    let uuid = scutil_find_service_uuid()
        .ok_or_else(|| anyhow::anyhow!("could not find Wi-Fi service UUID"))?;

    // Build the scutil script: replace State:/Network/Service/<UUID>/DNS
    // with our nameservers. The d.init+d.add+set sequence atomically
    // overwrites the dictionary at that key.
    let mut script = String::from("d.init\n");
    script.push_str("d.add ServerAddresses *");
    for s in &args.servers {
        script.push(' ');
        script.push_str(s);
    }
    script.push_str("\n");
    script.push_str(&format!("set State:/Network/Service/{uuid}/DNS\n"));
    script.push_str(&format!("set State:/Network/Global/DNS\n"));
    script.push_str("quit\n");

    let mut child = std::process::Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning scutil")?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().context("stdin")?;
        stdin.write_all(script.as_bytes())?;
    }
    let out = child.wait_with_output().context("waiting on scutil")?;
    if !out.status.success() {
        bail!(
            "scutil failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    // Flush macOS resolver caches so apps pick up immediately.
    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").status();
    let _ = Command::new("/usr/bin/killall").args(["-HUP", "mDNSResponder"]).status();

    Ok(InstallResult {
        success: true,
        message: format!(
            "Wrote State DNS for service {uuid}: {}",
            args.servers.join(", ")
        ),
    })
}

fn scutil_find_service_uuid() -> Option<String> {
    let mut child = std::process::Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take()?;
        let _ = stdin.write_all(b"list Setup:/Network/Service/[^/]+/DNS\nquit\n");
    }
    let out = child.wait_with_output().ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        // Lines look like:
        //   subKey [0] = Setup:/Network/Service/67C7F8A5-...-727B82/DNS
        if let Some(idx) = line.find("Setup:/Network/Service/") {
            let rest = &line[idx + "Setup:/Network/Service/".len()..];
            if let Some(end) = rest.find('/') {
                let uuid = &rest[..end];
                // Heuristic: UUID is 36 chars
                if uuid.len() == 36 {
                    return Some(uuid.to_string());
                }
            }
        }
    }
    None
}

/// Override the system DNS servers on the active network service
/// (Wi-Fi). Used to recover from situations where macOS's
/// resolver gets stuck on an unreachable IPv6 nameserver from
/// router advertisement, while ignoring the working IPv4 DNS
/// from DHCP. Pass `["empty"]` to clear and let DHCP own DNS
/// again. Pass `["1.1.1.1", "1.0.0.1"]` (or similar) for a
/// known-good fallback when DHCP-provided DNS is broken.
pub fn set_dns_servers(args: SetDnsArgs) -> Result<InstallResult> {
    let service = detect_active_network_service()
        .unwrap_or_else(|| "Wi-Fi".to_string());

    let mut cmd = Command::new("/usr/sbin/networksetup");
    cmd.arg("-setdnsservers").arg(&service);
    if args.servers.is_empty() || args.servers == vec!["empty".to_string()] {
        cmd.arg("empty");
    } else {
        for s in &args.servers {
            cmd.arg(s);
        }
    }
    let out = cmd.output().context("running networksetup")?;
    if !out.status.success() {
        bail!(
            "networksetup failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").status();
    let _ = Command::new("/usr/bin/killall").args(["-HUP", "mDNSResponder"]).status();

    Ok(InstallResult {
        success: true,
        message: format!(
            "Set DNS on '{}' to {}",
            service,
            if args.servers.is_empty() { "empty (DHCP)".to_string() } else { args.servers.join(", ") }
        ),
    })
}

#[derive(Deserialize, Debug)]
pub struct SetDnsArgs {
    pub servers: Vec<String>,
}

/// Find the user-facing network service name for the primary
/// interface. Returns `Some("Wi-Fi")` typically; falls back to
/// `None` if we can't tell so the caller can default.
fn detect_active_network_service() -> Option<String> {
    let out = Command::new("/usr/sbin/networksetup")
        .arg("-listallnetworkservices")
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let s = line.trim();
        if s.starts_with('*') || s.contains("informational") || s.is_empty() {
            continue;
        }
        if s == "Wi-Fi" {
            return Some(s.to_string());
        }
    }
    None
}

/// Pre-flight test: does the configured exit node actually forward
/// our internet traffic? Detects the case Tailscale.app handles
/// gracefully via NetworkExtension but open-source tailscaled on
/// macOS doesn't — picking a peer that's advertising as exit-node
/// but not actually NAT-forwarding silently bricks the user's
/// connection.
///
/// **The trick**: install a SINGLE /32 host route for a known
/// public IP via Tailscale's utun. tailscaled (with exit-node
/// pref already set) will forward those packets to the peer; if
/// the peer NATs and forwards, the public IP responds. The user's
/// other traffic is unaffected because only this one /32 was
/// redirected.
///
/// Caller flow:
///   1. `tailscale set --exit-node=<peer>`         (prefs only, no route change)
///   2. `tailscale_test_exit_reachability`         (this RPC, 2s budget)
///   3. If success → `tailscale_install_exit_routes`
///      If failure → `tailscale set --exit-node=`  (revert)
///
/// Always-cleans-up: even on early-return, we remove the /32
/// route. A leftover host route to 1.1.1.1 via utun would mean
/// pinging Cloudflare goes through Tailscale forever.
pub fn test_exit_reachability(_: TestExitArgs) -> Result<TestExitResult> {
    tracing::info!("test_exit_reachability: starting");
    let utun = detect_tailscale_utun()
        .context("tailscale utun not found — daemon not running?")?;
    tracing::info!(utun = %utun, "test_exit_reachability: utun detected");

    // Cloudflare's public DNS endpoint. Universal, fast, has HTTPS.
    let test_ip = "1.1.1.1";

    // Defensive cleanup of any leftover test route from a previous
    // failed run.
    let _ = Command::new("/sbin/route")
        .args(["delete", "-host", test_ip])
        .output();

    // Install the single /32 via tailscale's utun. From this
    // moment, packets to 1.1.1.1 specifically go through
    // tailscaled, which will encapsulate to the exit peer.
    let add = Command::new("/sbin/route")
        .args(["-q", "add", "-host", test_ip, "-interface", &utun])
        .output()
        .context("route add for test")?;
    if !add.status.success() {
        return Ok(TestExitResult {
            success: false,
            response_code: String::new(),
            message: format!(
                "Could not install test route for {test_ip} via {utun}: {}",
                String::from_utf8_lossy(&add.stderr).trim()
            ),
        });
    }

    // Probe with an 8-second timeout. We expect 1.1.1.1 to return
    // HTTP 301 (redirect to https://www.cloudflare.com/...) when
    // reachable. Any 2xx/3xx counts as success.
    //
    // 8 s rationale: peers on FreeBSD (OPNsense) or behind a DERP
    // relay add 3-6 s of TLS-handshake latency over a working path.
    // The original 2 s limit caused false-positives — probe timed out
    // (HTTP 000) while the exit-node was fully functional and approved
    // in the Tailscale admin console.  8 s is conservative enough to
    // let DERP settle without making the UX feel hung.
    let probe = Command::new("/usr/bin/curl")
        .args([
            "-sS",
            "--max-time", "8",
            "--connect-timeout", "8",
            "-o", "/dev/null",
            "-w", "%{http_code}",
            &format!("https://{test_ip}"),
        ])
        .output();

    // ALWAYS clean up the /32 route, regardless of probe outcome.
    let _ = Command::new("/sbin/route")
        .args(["delete", "-host", test_ip])
        .output();

    let probe = match probe {
        Ok(o) => o,
        Err(e) => {
            return Ok(TestExitResult {
                success: false,
                response_code: String::new(),
                message: format!("probe spawn failed: {e}"),
            });
        }
    };
    let code = String::from_utf8_lossy(&probe.stdout).trim().to_string();
    let success = code.starts_with('2') || code.starts_with('3');

    Ok(TestExitResult {
        success,
        response_code: code.clone(),
        message: if success {
            format!("Exit reachability OK — {test_ip} via {utun} responded {code}")
        } else {
            format!("Exit unreachable — {test_ip} via {utun} returned {code:?}")
        },
    })
}

#[derive(Deserialize, Debug)]
pub struct TestExitArgs {}

#[derive(Serialize, Debug)]
pub struct TestExitResult {
    pub success: bool,
    pub response_code: String,
    pub message: String,
}

/// Delete one split-default route unless a live WireGuard/OpenVPN full tunnel
/// currently owns it. `family` is `-inet` or `-inet6`; `net` is both the
/// `route get` target and the `route delete` prefix. Idempotent: a missing
/// route is a no-op.
fn delete_split_default_if_unowned(
    family: &str,
    net: &str,
    foreign: &std::collections::HashSet<String>,
) {
    if let Some(iface) = crate::strongswan::route_iface_family(net, family) {
        if foreign.contains(&iface) {
            tracing::info!("exit_routes: keeping {net} — owned by live tunnel {iface}");
            return;
        }
    }
    let mut args: Vec<&str> = vec!["delete"];
    if family == "-inet6" {
        args.push("-inet6");
    }
    args.push("-net");
    args.push(net);
    let _ = Command::new("/sbin/route").args(&args).output();
}

/// Remove the split-default exit-node routes. Always succeeds —
/// missing routes are a no-op. Called when the user clears the
/// exit node, when auto-revert kicks in, and from `panic_reset`.
pub fn remove_exit_routes(_: ExitRoutesArgs) -> Result<InstallResult> {
    // 1. Drop the /1 split routes — but ONLY the ones tailscale owns.
    //
    // This runs from panic_reset (fired by the connectivity watchdog on a
    // ~6s internet blip) and from auto-revert. The `0/1` + `128/1` (+ v6)
    // split-defaults are a SHARED kernel resource: WireGuard and OpenVPN
    // full tunnels install the exact same pair. A blind delete here would
    // rip a live WG/OpenVPN tunnel's default routes out from under it on any
    // transient outage, silently leaking all traffic in cleartext via en0.
    // So we skip any /1 route currently owned by a live foreign tunnel;
    // tailscale's own exit-node routes point at the tailscale utun (not a
    // WG/OpenVPN interface) and are still removed.
    let foreign = crate::strongswan::foreign_tunnel_ifaces();
    delete_split_default_if_unowned("-inet", "0.0.0.0/1", &foreign);
    delete_split_default_if_unowned("-inet", "128.0.0.0/1", &foreign);
    delete_split_default_if_unowned("-inet6", "::/1", &foreign);
    delete_split_default_if_unowned("-inet6", "8000::/1", &foreign);

    // 2. Drop the per-underlay-IP exemption host routes we
    // installed alongside. Without this, those /32 entries would
    // linger and pin specific hosts to the local gateway forever
    // (harmless but messy).
    let exempt = read_exemption_state();
    for ip in &exempt {
        let _ = Command::new("/sbin/route")
            .args(["delete", "-host", ip])
            .output();
    }
    let _ = fs::remove_file(EXEMPTION_STATE_FILE);

    Ok(InstallResult {
        success: true,
        message: format!(
            "Removed split-default + {} underlay exemptions (best-effort)",
            exempt.len()
        ),
    })
}

#[derive(Deserialize, Debug)]
pub struct ExitRoutesArgs {}

/// Find the `utunN` interface tailscaled installed for the tailnet.
/// We look for the route to the standard CGNAT range (100.64/10) —
/// that's always present when tailscaled is up and routing.
fn detect_tailscale_utun() -> Option<String> {
    let out = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[0] == "100.64/10" && fields[3].starts_with("utun") {
            return Some(fields[3].to_string());
        }
    }
    None
}

/// Install (or remove) the per-tailnet `/etc/resolver/<domain>`
/// file that macOS uses to route MagicDNS queries to
/// `100.100.100.100`.
///
/// Why this exists: open-source `tailscaled` on macOS doesn't have
/// the NetworkExtension privilege the official `Tailscale.app`
/// uses to install split DNS. It logs that it WANTS to set
/// `Nameservers:[100.100.100.100 ...] SearchDomains:[<tailnet>]`
/// but only writes the search file (`/etc/resolver/search.tailscale`)
/// — the per-domain nameserver file is silently missing. Result:
/// `mac.tailnet.ts.net` doesn't resolve through the system
/// resolver even though `dig @100.100.100.100` works fine.
///
/// We backstop the missing nameserver file from the helper. The
/// content is the canonical macOS resolver(5) format:
///
///     nameserver 100.100.100.100
///     nameserver fd7a:115c:a1e0::53
///     port 53
///     timeout 5
///
/// When the daemon goes back to BackendState=Stopped (user
/// disconnected), call with `install: false` so we leave a clean
/// system. The file is owned by root:wheel, mode 0644.
pub fn install_magicdns_resolver(args: MagicdnsResolverArgs) -> Result<InstallResult> {
    let domain = args.tailnet_suffix.trim_matches('.');
    if domain.is_empty() || !domain.contains('.') {
        bail!("invalid tailnet_suffix '{}'", args.tailnet_suffix);
    }
    // /etc/resolver/<domain> — macOS reads files in this dir and
    // routes any DNS query for matching suffix to the listed
    // nameservers.
    let path = format!("/etc/resolver/{domain}");
    if !args.install {
        if Path::new(&path).exists() {
            fs::remove_file(&path).with_context(|| format!("removing {path}"))?;
            return Ok(InstallResult {
                success: true,
                message: format!("Removed {path}"),
            });
        }
        return Ok(InstallResult {
            success: true,
            message: "no resolver file to remove".to_string(),
        });
    }
    // Make sure the dir exists. macOS creates it on demand for
    // some installs but not all.
    fs::create_dir_all("/etc/resolver").context("creating /etc/resolver")?;
    let content = "# Written by SuperManager helper — backstops macOS open-source\n\
                   # tailscaled which silently fails to install the per-domain\n\
                   # nameserver file. Removed automatically when the daemon stops.\n\
                   nameserver 100.100.100.100\n\
                   nameserver fd7a:115c:a1e0::53\n\
                   port 53\n\
                   timeout 5\n";
    fs::write(&path, content).with_context(|| format!("writing {path}"))?;
    let _ = Command::new("/bin/chmod").args(["0644", &path]).status();
    let _ = Command::new("/usr/sbin/chown").args(["root:wheel", &path]).status();
    // Force macOS to pick up the new resolver file. Without this,
    // queries for the tailnet domain still fall through to the
    // default DNS until the next configd reload.
    let _ = Command::new("/usr/bin/dscacheutil")
        .arg("-flushcache")
        .status();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .status();
    Ok(InstallResult {
        success: true,
        message: format!("Wrote {path} (MagicDNS for {domain})"),
    })
}

#[derive(Deserialize, Debug)]
pub struct MagicdnsResolverArgs {
    /// Tailnet domain suffix from `MagicDNSSuffix` (e.g.
    /// `tailb0b06a.ts.net`). Trailing dots tolerated.
    pub tailnet_suffix: String,
    /// True to write the resolver file, false to remove it.
    pub install: bool,
}

/// Argless panic-reset: clear any exit-node + accept-routes
/// preference, kick the routing table back to a sane state by
/// renewing DHCP on the active interface.
///
/// Why this exists: open-source `tailscaled` on macOS installs a
/// default route through the exit node's TUN. When that route is
/// removed (because the user cleared the exit node, or the peer
/// went unreachable), macOS doesn't always restore the original
/// DHCP-issued default route automatically. Result: no internet
/// until the user toggles WiFi off/on. This RPC handles both ends
/// of that recovery from inside the app.
///
/// We intentionally don't restart `tailscaled` here — that would
/// drop the user's authenticated session. Just clearing the
/// exit-node pref is enough on the daemon side; the route fix is
/// `ipconfig set en0 DHCP` which is fast (< 1 s) and idempotent.
pub fn panic_reset(args: PanicResetArgs) -> Result<InstallResult> {
    // 0. Wipe the split-default exit-node routes FIRST. If the
    // user got here by selecting an exit-node that broke
    // routing, those /1 routes are why their internet is dead.
    // Removing them lets the existing local default route work
    // again immediately — ipconfig DHCP renew below is belt-
    // and-braces. Removing routes is always FAIL OPEN (egress
    // falls back to the local uplink); it can never black-hole.
    let _ = remove_exit_routes(ExitRoutesArgs {});

    // 1. Optionally tell the daemon to drop exit-node + accept-routes.
    //
    // FAIL-OPEN vs HARD-CLEAR: the connectivity watchdog fires this
    // automatically on a transient blip (clear_pref = false). In that
    // case we must NOT clear the tailscaled pref or the persisted
    // desired-state — doing so destroys the only record of "the user
    // wants this exit node", which is exactly what left the machine
    // wedged (egress already failed open above; the reconciler will
    // re-establish the routes once the peer is reachable again). Only a
    // user-initiated hard reset (clear_pref = true, the in-app "Panic
    // reset" menu) actually clears intent.
    let mut last_err = String::new();
    if args.clear_pref {
        crate::tailscale_state::clear_desired();
        let mut cleared = false;
        if let Some(cli) = tailscale_cli() {
            let out = Command::new(cli)
                .args([
                    "--socket=/var/run/tailscaled.socket",
                    "set",
                    "--exit-node=",
                    "--accept-routes=false",
                ])
                .output();
            match out {
                Ok(o) if o.status.success() => cleared = true,
                Ok(o) => last_err = String::from_utf8_lossy(&o.stderr).to_string(),
                Err(e) => last_err = e.to_string(),
            }
        }
        if !cleared {
            // Don't bail — we still want to try the DHCP renew. The
            // exit-node clear is best-effort.
        }
    }

    // 2. Find the active network interface (usually en0 for WiFi
    // or en1 for ethernet) by parsing `route -n get default` —
    // wait, that's broken when default is missing, which is the
    // whole reason we're here. Use `networksetup -listallhardwareports`
    // and pick the first Wi-Fi or Ethernet device instead.
    let active_iface = detect_active_interface().unwrap_or_else(|| "en0".to_string());

    // 3. Renew DHCP on it. macOS treats `ipconfig set <iface> DHCP`
    // as an idempotent re-lease — no service restart, no socket
    // disruption beyond the 50-100 ms reconfig window.
    let renew = Command::new("/usr/sbin/ipconfig")
        .args(["set", &active_iface, "DHCP"])
        .output()
        .context("running ipconfig set DHCP")?;

    let stderr = String::from_utf8_lossy(&renew.stderr);
    if !renew.status.success() {
        return Ok(InstallResult {
            success: false,
            message: format!(
                "Cleared tailscale exit-node{}; DHCP renew on {active_iface} failed: {stderr}",
                if last_err.is_empty() { "" } else { " (with warnings)" }
            ),
        });
    }

    Ok(InstallResult {
        success: true,
        message: format!(
            "Reset complete on {active_iface}.{}",
            if last_err.is_empty() {
                String::new()
            } else {
                format!(" CLI warning: {}", last_err.trim())
            }
        ),
    })
}

#[derive(Deserialize, Debug, Default)]
pub struct PanicResetArgs {
    /// `true` (the user-initiated "Panic reset" menu) → hard reset: also clear
    /// the tailscaled exit-node pref and the persisted desired-state.
    /// `false` (the connectivity watchdog's automatic blip recovery, the serde
    /// default) → fail open only: remove routes + DHCP renew, but KEEP intent
    /// so the reconciler can re-establish the exit node when the peer returns.
    #[serde(default)]
    pub clear_pref: bool,
}

/// Locate the bundled/installed tailscale CLI (same candidates the panic path
/// uses). Returns the first existing path.
fn tailscale_cli() -> Option<&'static str> {
    const CANDIDATES: [&str; 3] = [
        "/Applications/SuperManagerMac.app/Contents/Resources/tailscale-bin/tailscale",
        "/opt/homebrew/bin/tailscale",
        "/usr/local/bin/tailscale",
    ];
    CANDIDATES.into_iter().find(|p| Path::new(p).exists())
}

/// Read the currently-selected exit node `(id, ip)` from tailscaled's prefs.
/// Best-effort: returns `("", "")` when there is no exit node or the CLI is
/// unavailable. Used only to record intent — never changes any state.
///
/// tailscaled's prefs frequently expose `ExitNodeID` (the stable node ID) with
/// an EMPTY `ExitNodeIP` (the IP is resolved from the netmap at runtime). The
/// reconciler can only re-assert the pref with an IP/hostname, not the stable
/// ID — so when the IP is blank we resolve it from `status --json`. Without this
/// the persisted intent carried an empty IP, the reconciler's re-assert never
/// fired, and a daemon that had lost its pref stayed wedged (the reported bug).
pub fn current_exit_node() -> (String, String) {
    let Some(cli) = tailscale_cli() else {
        return (String::new(), String::new());
    };
    let out = Command::new(cli)
        .args(["--socket=/var/run/tailscaled.socket", "debug", "prefs"])
        .output();
    let Ok(o) = out else {
        return (String::new(), String::new());
    };
    let v: serde_json::Value =
        serde_json::from_slice(&o.stdout).unwrap_or(serde_json::Value::Null);
    let id = v.get("ExitNodeID").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut ip = v.get("ExitNodeIP").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if ip.is_empty() && !id.is_empty() {
        ip = resolve_exit_node_ip(&id).unwrap_or_default();
    }
    (id, ip)
}

/// Resolve an exit node's current Tailscale IP from its stable node ID by
/// parsing `tailscale status --json` (the `Peer` map). Prefers the IPv4
/// (100.x) address. Returns `None` if the CLI is unavailable, the peer is not
/// in the current netmap, or it has no addresses. Read-only — never changes
/// any state.
fn resolve_exit_node_ip(id: &str) -> Option<String> {
    if id.is_empty() {
        return None;
    }
    let cli = tailscale_cli()?;
    let out = Command::new(cli)
        .args(["--socket=/var/run/tailscaled.socket", "status", "--json"])
        .output()
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let peers = v.get("Peer")?.as_object()?;
    for (_k, p) in peers {
        if p.get("ID").and_then(|x| x.as_str()) != Some(id) {
            continue;
        }
        let ips = p.get("TailscaleIPs")?.as_array()?;
        let mut v4 = None;
        let mut v6 = None;
        for ip in ips {
            if let Some(s) = ip.as_str() {
                if s.contains('.') {
                    v4.get_or_insert_with(|| s.to_string());
                } else {
                    v6.get_or_insert_with(|| s.to_string());
                }
            }
        }
        return v4.or(v6);
    }
    None
}

/// True if the PHYSICAL local uplink is up — carrier/association present AND an
/// assigned IPv4 on the hardware interface backing the default route. The
/// connectivity watchdog uses this to tell apart two outages that look identical
/// from a 1.1.1.1 probe but need OPPOSITE handling when a tailscale exit node is
/// active:
///
/// - **uplink DOWN** → OUR link blipped (sleep/roam/WiFi drop). Do NOTHING:
///   tearing the exit node down here is the flap the user reported ("bugs on any
///   idle"). tailscale recovers when the link returns; routes stay valid (or the
///   reconciler reinstalls if the utun renumbered across sleep).
/// - **uplink UP but egress still dead after a sustained window** → the exit
///   PEER is genuinely dead while our own link is fine → fail open (panic_reset
///   removes the routes, egress drops to the local uplink, reconciler
///   re-establishes when the peer returns).
///
/// CRITICAL: this is a LINK-STATE check, deliberately NOT an ICMP ping of the
/// gateway. An earlier ping-based version false-read "down" on any gateway that
/// filters ICMP (corporate / hardened / hotspot / CGN gateways) — which would
/// suppress the fail-open forever and leave a genuinely dead exit peer
/// black-holing the machine with no recovery. Carrier + IPv4 state has no such
/// blind spot. Biased toward "down" only when the link is genuinely unusable.
pub(crate) fn local_uplink_up() -> bool {
    let Some(iface) = physical_uplink_iface() else {
        return false; // no hardware uplink at all — treat as a blip, don't tear down
    };
    let Ok(out) = Command::new("/sbin/ifconfig").arg(&iface).output() else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let admin_up = s.lines().next().map(|l| l.contains("UP")).unwrap_or(false);
    // macOS prints `status: active` when a link/association is present,
    // `status: inactive` when not. Treat an explicit "inactive" as down; if the
    // field is absent (rare for hardware) fall back to admin-up + IPv4.
    let carrier_down = s.contains("status: inactive");
    // A routable IPv4 (skip APIPA link-local 169.254/16 and the v6-only case).
    let has_v4 = s.lines().any(|l| {
        let l = l.trim();
        l.starts_with("inet ") && !l.starts_with("inet 169.254")
    });
    admin_up && has_v4 && !carrier_down
}

/// The hardware interface backing the physical default route (`en0`, `en6`…).
/// The exit node installs more-specific `0/1`+`128/1`, so the `0/0` default
/// stays on the real uplink; we read its interface from there. If the `0/0`
/// default itself points at a utun (some tailscaled builds install one), fall
/// back to the OS's primary hardware service.
fn physical_uplink_iface() -> Option<String> {
    if let Ok(out) = Command::new("/sbin/route").args(["-n", "get", "default"]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if let Some(rest) = line.trim().strip_prefix("interface:") {
                let i = rest.trim();
                if i.starts_with("en") {
                    return Some(i.to_string());
                }
            }
        }
    }
    detect_active_interface()
}

/// Self-heal the tailscale exit node — the core of the no-brick design.
///
/// Called every `auto_reconnect` tick (always-on, GUI-closed-safe LaunchDaemon).
/// If the user wants an exit node (persisted intent in `tailscale_state`) but
/// its `0/1` split-default is NOT on the CURRENT tailscale utun — because sleep
/// renumbered the utun or a connectivity blip tore the route down — it
/// re-establishes the routes, but ONLY after a real reachability probe confirms
/// the peer forwards traffic. If the peer is not reachable, it does nothing
/// this tick and the machine stays on the local uplink (fail open).
///
/// NO-BRICK: `install_exit_routes` runs exclusively behind
/// `test_exit_reachability` (a self-cleaning /32 probe through the peer) — the
/// exact gate the safe user flow uses. It can never install `0/1` into a dead
/// tunnel, and it never removes a working local default.
pub fn reconcile_exit_node() {
    let desired = crate::tailscale_state::load();
    if !desired.desired {
        return; // no exit node wanted — nothing to heal
    }
    // Re-detect the tailscale utun (it is renumbered across sleep/wake).
    let Some(ts_utun) = detect_tailscale_utun() else {
        return; // tailscaled not up yet (mid-wake handshake) — retry next tick
    };
    // Healthy if 0/1 already points at the CURRENT tailscale utun.
    if crate::strongswan::route_iface_family("0.0.0.0/1", "-inet").as_deref()
        == Some(ts_utun.as_str())
    {
        return;
    }
    // STAND DOWN if a live FOREIGN full tunnel (Azure/OpenVPN, WireGuard,
    // strongSwan) currently owns 0/1. The user explicitly brought that tunnel
    // up; re-asserting the exit-node routes would `route delete` 0/1 out from
    // under it and black-hole the whole machine. (This is the Azure-VPN brick:
    // without this gate the reconciler stole 0/1 from Azure every 30s.)
    if let Some(owner) = foreign_full_tunnel_owns_default(&ts_utun) {
        tracing::warn!(
            iface = %owner,
            "reconcile: 0/1 owned by a live foreign full tunnel — standing down (not stealing exit-node routes)"
        );
        return;
    }
    tracing::info!(utun = %ts_utun, "reconcile: exit node desired but routes absent — checking reachability");

    // Belt-and-braces: re-assert the exit-node pref in tailscaled. panic_reset
    // with clear_pref=false keeps it, but a hard-cleared or freshly-restarted
    // daemon may have lost it; without it test_exit_reachability would probe a
    // tunnel with no exit and fail forever. We need the peer's IP to re-assert —
    // resolve it from the stable ID when intent recorded only the ID (the common
    // case: tailscaled prefs expose ExitNodeID with a blank ExitNodeIP).
    let eff_ip = if !desired.exit_node_ip.is_empty() {
        Some(desired.exit_node_ip.clone())
    } else {
        resolve_exit_node_ip(&desired.exit_node_id)
    };
    if let Some(ip) = eff_ip.as_deref() {
        if let Some(cli) = tailscale_cli() {
            let _ = Command::new(cli)
                .args([
                    "--socket=/var/run/tailscaled.socket",
                    "set",
                    &format!("--exit-node={ip}"),
                ])
                .output();
        }
        // Persist the resolved IP so subsequent ticks skip the status lookup
        // and so the intent file is self-describing.
        if desired.exit_node_ip.is_empty() {
            crate::tailscale_state::set_desired(&desired.exit_node_id, ip);
        }
    }

    // GATE: a real /32 probe through the peer (self-cleaning, never persists a
    // route). Only a 2xx/3xx response — i.e. the peer actually forwards — lets
    // us re-install the split-defaults.
    match test_exit_reachability(TestExitArgs {}) {
        Ok(r) if r.success => {
            // Pause the connectivity watchdog so the reinstall's brief
            // disruption can't itself trip panic_reset.
            crate::connectivity_watchdog::pause_for(20);
            match install_exit_routes(ExitRoutesArgs {}) {
                Ok(_) => tracing::info!(utun = %ts_utun, "reconcile: exit-node routes re-established"),
                Err(e) => tracing::warn!("reconcile: install_exit_routes failed: {e}"),
            }
        }
        Ok(r) => tracing::debug!(
            code = %r.response_code,
            "reconcile: exit node not reachable yet — staying on local uplink"
        ),
        Err(e) => tracing::debug!("reconcile: reachability test failed: {e} — staying on local uplink"),
    }
}

/// Best-effort detection of the active "primary" network interface.
/// Reads `networksetup -listnetworkserviceorder` which lists
/// services in priority order. We pick the first one that has a
/// device starting with `en`.
fn detect_active_interface() -> Option<String> {
    let out = Command::new("/usr/sbin/networksetup")
        .args(["-listnetworkserviceorder"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Output format: "(Hardware Port: Wi-Fi, Device: en0)"
    for line in stdout.lines() {
        if let Some(start) = line.find("Device: ") {
            let rest = &line[start + "Device: ".len()..];
            if let Some(end) = rest.find(')') {
                let dev = rest[..end].trim();
                if dev.starts_with("en") {
                    return Some(dev.to_string());
                }
            }
        }
    }
    None
}

/// Render the LaunchDaemon plist. Inlined as a string template
/// because the plist is small and pulling in a plist crate just for
/// 30 lines of XML is overkill.
///
/// `--state` and `--socket` flags pin the on-disk locations so the
/// bundled `tailscale` CLI (which uses the default socket path)
/// finds our daemon without any environment-variable plumbing.
///
/// `KeepAlive=true` restarts the daemon on crash. `RunAtLoad=true`
/// starts it at boot.
fn render_launchd_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{daemon}</string>
        <string>--state={state}/tailscaled.state</string>
        <string>--statedir={state}</string>
        <string>--socket=/var/run/tailscaled.socket</string>
        <string>--port=41641</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>UserName</key><string>root</string>
    <key>GroupName</key><string>wheel</string>
    <key>StandardOutPath</key><string>/var/log/supermanager-tailscaled.log</string>
    <key>StandardErrorPath</key><string>/var/log/supermanager-tailscaled.log</string>
</dict>
</plist>
"#,
        label = LAUNCH_LABEL,
        daemon = DAEMON_INSTALL_PATH,
        state = STATE_DIR,
    )
}
