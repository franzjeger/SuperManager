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

/// Remove the split-default exit-node routes. Always succeeds —
/// missing routes are a no-op. Called when the user clears the
/// exit node, when auto-revert kicks in, and from `panic_reset`.
pub fn remove_exit_routes(_: ExitRoutesArgs) -> Result<InstallResult> {
    // 1. Drop the /1 split routes.
    let _ = Command::new("/sbin/route").args(["delete", "-net", "0.0.0.0/1"]).output();
    let _ = Command::new("/sbin/route").args(["delete", "-net", "128.0.0.0/1"]).output();
    let _ = Command::new("/sbin/route").args(["delete", "-inet6", "-net", "::/1"]).output();
    let _ = Command::new("/sbin/route").args(["delete", "-inet6", "-net", "8000::/1"]).output();

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
pub fn panic_reset(_: PanicResetArgs) -> Result<InstallResult> {
    // 0. Wipe the split-default exit-node routes FIRST. If the
    // user got here by selecting an exit-node that broke
    // routing, those /1 routes are why their internet is dead.
    // Removing them lets the existing local default route work
    // again immediately — ipconfig DHCP renew below is belt-
    // and-braces.
    let _ = remove_exit_routes(ExitRoutesArgs {});

    // 1. Tell the daemon to drop exit-node + accept-routes. We
    // shell out to the bundled tailscale CLI by looking it up
    // relative to our own binary path. Tailscaled lives at
    // /usr/local/sbin/supermanager-tailscaled and the CLI is
    // bundled in the .app — we find it by the user-supplied path
    // argument when it exists, but for the panic case we rely on
    // a fixed install location plus a fallback to homebrew.
    let cli_candidates = [
        "/Applications/SuperManagerMac.app/Contents/Resources/tailscale-bin/tailscale",
        "/opt/homebrew/bin/tailscale",
        "/usr/local/bin/tailscale",
    ];
    let mut last_err = String::new();
    let mut cleared = false;
    for cli in cli_candidates {
        if !Path::new(cli).exists() {
            continue;
        }
        let out = Command::new(cli)
            .args([
                "--socket=/var/run/tailscaled.socket",
                "set",
                "--exit-node=",
                "--accept-routes=false",
            ])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                cleared = true;
                break;
            }
            Ok(o) => {
                last_err = String::from_utf8_lossy(&o.stderr).to_string();
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
    }
    if !cleared {
        // Don't bail — we still want to try the DHCP renew. The
        // exit-node clear is best-effort.
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

#[derive(Deserialize, Debug)]
pub struct PanicResetArgs {}

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
