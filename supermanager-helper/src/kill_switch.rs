//! VPN kill-switch via macOS' packet filter (`pf`).
//!
//! When a user toggles `kill_switch=true` on a VPN profile, this
//! module installs a pf anchor that:
//!
//!   1. Allows local LAN traffic (RFC1918 + link-local)
//!   2. Allows traffic via the tunnel interface (utun*)
//!   3. Blocks everything else
//!
//! On disconnect, the anchor is flushed and pf returns to whatever
//! state it was in before. Idempotent — repeated installs replace
//! the existing rule set.
//!
//! ## Why pf and not `route` blackhole + DNS
//!
//! - `route add -net 0.0.0.0/0 -blackhole` only catches IPv4 and
//!   doesn't enforce that traffic must go through utun (it just
//!   stops it from going anywhere). Apps see "no route" and may
//!   bind to a specific interface as a workaround.
//! - pf's `block all out except via utun*` is the canonical leak
//!   prevention. Same approach Tailscale.app, Mullvad, etc use.
//!
//! ## Anchor name
//!
//! `com.sybr.supermanager.killswitch` — under
//! `/etc/pf.anchors/`, loaded into the main `pf.conf` ruleset
//! via `pfctl -a com.sybr.supermanager.killswitch`. Doesn't
//! interfere with any existing pf rules the user might have.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
// Every command here is bounded: see `proc::Bounded`.
use crate::proc::Bounded as Command;
use std::process::Output;

const ANCHOR_NAME: &str = "com.sybr.supermanager.killswitch";
const ANCHOR_FILE: &str = "/etc/pf.anchors/com.sybr.supermanager.killswitch";
const PF_CONF_PATH: &str = "/etc/pf.conf";
const PF_CONF_TMP_PATH: &str = "/etc/pf.conf.supermgr.tmp";

/// Serialize all mutations of `/etc/pf.conf` and `pfctl` reloads.
static PF_LOCK: Mutex<()> = Mutex::new(());

#[derive(Deserialize, Debug)]
pub struct EnableArgs {
    /// The tunnel interface to allow egress through, e.g.
    /// `utun7`. Caller must already know which utun the active
    /// tunnel uses; this RPC doesn't auto-detect because there
    /// might be several utuns up at once (Tailscale + WireGuard).
    pub tunnel_interface: String,
    /// Optional VPN gateway endpoint IPs that must be reachable on the
    /// physical interface so encrypted outer tunnel packets are not blocked.
    #[serde(default)]
    pub allow_ips: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct DisableArgs {}

#[derive(Serialize, Debug)]
pub struct Result_ {
    pub success: bool,
    pub message: String,
}

/// Install the kill-switch anchor and load it into pf. Enables
/// pf if it isn't already running. Idempotent.
pub fn enable(args: EnableArgs) -> Result<Result_> {
    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let iface = args.tunnel_interface;
    validate_interface(&iface)?;

    let mut endpoints = validate_endpoints(&args.allow_ips)?;
    for auto_ep in discover_physical_host_route_endpoints() {
        if !endpoints.contains(&auto_ep) {
            endpoints.push(auto_ep);
        }
    }

    let rules = build_anchor_rules(&iface, &endpoints);

    if let Some(parent) = Path::new(ANCHOR_FILE).parent() {
        fs::create_dir_all(parent).context("creating /etc/pf.anchors")?;
    }
    atomic_write_file(Path::new(ANCHOR_FILE), rules.as_bytes(), 0o644)
        .context("writing anchor file")?;

    // Make sure pf is enabled. `pfctl -E` is idempotent — returns
    // 0 with "pf enabled" or "pf already enabled".
    checked_pfctl_output(Command::new("/sbin/pfctl").arg("-E").output(), "enable pf")?;

    // Load our anchor's rules. `-a <anchor>` loads into the
    // anchor namespace without touching the main ruleset.
    let load = Command::new("/sbin/pfctl")
        .args(["-a", ANCHOR_NAME, "-f", ANCHOR_FILE])
        .output()
        .context("running pfctl -f")?;
    if !load.status.success() {
        bail!(
            "pfctl load failed: {}",
            String::from_utf8_lossy(&load.stderr).trim()
        );
    }

    // Hook the anchor into the main ruleset. Without this, the
    // rules are loaded but never evaluated — pf only walks
    // anchors that are explicitly referenced. We add a tiny
    // referrer rule to the main ruleset that enters our anchor.
    install_referrer_if_missing()?;

    Ok(Result_ {
        success: true,
        message: format!("Kill-switch active — only {iface} + LAN allowed"),
    })
}

/// Build the anchor's pf rules. Order matters in pf: explicit
/// pass before block, last-matching wins (without `quick`).
/// We use `quick` to short-circuit — first match wins, fewer
/// surprises.
fn build_anchor_rules(iface: &str, endpoints: &[IpAddr]) -> String {
    let mut endpoint_rules = String::new();
    for ip in endpoints {
        let _ = writeln!(endpoint_rules, "pass quick to {ip}");
        let _ = writeln!(endpoint_rules, "pass quick from {ip}");
    }
    format!(
        "# SuperManager kill-switch anchor
# Generated by helper. Do not edit by hand — toggle via the GUI.

# Allow loopback (mDNS, local services, app introspection).
pass quick on lo0

# Allow tunnel egress + ingress.
pass quick on {iface} all

# Allow encrypted VPN outer transport to pinned gateway endpoints + IKE/ESP.
{endpoint_rules}pass quick proto udp from any to any port {{ 500, 4500 }}
pass quick proto esp all

# Allow LAN traffic so printers / NAS / etc keep working.
pass quick to 10.0.0.0/8
pass quick to 172.16.0.0/12
pass quick to 192.168.0.0/16
pass quick to 169.254.0.0/16
pass quick to 224.0.0.0/4
pass quick to ff00::/8
pass quick to fe80::/10
pass quick to fd00::/8

# Allow DHCP, ARP, mDNS, IPv6 ND.
pass quick proto udp from any to any port 67:68
pass quick proto udp from any to any port 546:547
pass quick proto udp from any to any port 5353

# Allow Tailscale's underlay UDP (peer-to-peer over public IPs).
# Without this, kill-switch breaks tailnet itself when used with
# WireGuard kill-switch + Tailscale running side-by-side.
pass quick proto udp from any to any port 41641

# Block everything else.
block return out all
block return in all
"
    )
}

/// Tear down the kill-switch anchor. After this, pf returns to
/// the state before `enable()` was called.
pub fn disable(_: DisableArgs) -> Result<Result_> {
    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    // Flush our anchor's rules.
    let _ = Command::new("/sbin/pfctl")
        .args(["-a", ANCHOR_NAME, "-F", "all"])
        .output();
    // Remove the anchor file so it doesn't get re-loaded on a
    // subsequent system reboot.
    let _ = fs::remove_file(ANCHOR_FILE);
    // Pull the referrer line out of the main ruleset.
    remove_referrer_if_present()?;
    Ok(Result_ {
        success: true,
        message: "Kill-switch removed".to_string(),
    })
}

/// Make sure the main pf ruleset includes our anchor reference.
/// Idempotent — only adds if not present.
fn install_referrer_if_missing() -> Result<()> {
    // Read current main ruleset and check for our anchor.
    let current = Command::new("/sbin/pfctl")
        .args(["-sr"])
        .output()
        .context("pfctl -sr")?;
    let current = checked_pfctl_output(Ok(current), "read pf rules")?;
    let stdout = String::from_utf8_lossy(&current.stdout);
    if stdout.contains(&format!("anchor \"{ANCHOR_NAME}\"")) {
        return Ok(());
    }
    // pf's main ruleset comes from /etc/pf.conf. We append a
    // single line referring to our anchor.
    let body = fs::read_to_string(PF_CONF_PATH).context("reading /etc/pf.conf")?;
    let line = format!(
        "\nanchor \"{ANCHOR_NAME}\"\nload anchor \"{ANCHOR_NAME}\" from \"{ANCHOR_FILE}\"\n"
    );
    if !body.contains(&format!("anchor \"{ANCHOR_NAME}\"")) {
        let new_body = format!("{body}{line}");
        atomic_write_pf_conf(&new_body)?;
    }
    // Reload the full ruleset so the new anchor reference takes effect.
    checked_pfctl_output(
        Command::new("/sbin/pfctl").args(["-f", PF_CONF_PATH]).output(),
        "activate kill-switch anchor reference",
    )?;
    Ok(())
}

/// Strip our anchor reference from /etc/pf.conf if present.
fn remove_referrer_if_present() -> Result<()> {
    let body = fs::read_to_string(PF_CONF_PATH).unwrap_or_default();
    let needle_anchor = format!("\nanchor \"{ANCHOR_NAME}\"\n");
    let needle_load = format!("load anchor \"{ANCHOR_NAME}\" from \"{ANCHOR_FILE}\"\n");
    let mut new_body = body.replace(&needle_anchor, "\n");
    new_body = new_body.replace(&needle_load, "");
    if new_body != body {
        atomic_write_pf_conf(&new_body)?;
        checked_pfctl_output(
            Command::new("/sbin/pfctl").args(["-f", PF_CONF_PATH]).output(),
            "reload pf.conf after removing kill-switch anchor",
        )?;
    }
    Ok(())
}

/// Write `/etc/pf.conf` atomically via a temporary sibling file + `fsync` + `rename`
/// so a crash or power loss mid-write can never truncate or corrupt the system's
/// packet filter configuration.
fn atomic_write_pf_conf(contents: &str) -> Result<()> {
    atomic_write_file(Path::new(PF_CONF_PATH), contents.as_bytes(), 0o644)
        .context("atomic write /etc/pf.conf")
}

fn atomic_write_file(target: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = if target == Path::new(PF_CONF_PATH) {
        Path::new(PF_CONF_TMP_PATH).to_path_buf()
    } else {
        target.with_extension("supermgr.tmp")
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, target)
}

fn validate_endpoints(raw: &[String]) -> Result<Vec<IpAddr>> {
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let ip: IpAddr = entry
            .trim()
            .parse()
            .with_context(|| format!("invalid endpoint IP in allow_ips: {entry:?}"))?;
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    Ok(out)
}

/// Discover active VPN gateway host routes (`UGHS` / `UH` on physical interfaces)
/// from the routing table so that even when the caller only passes `tunnel_interface`,
/// the VPN daemon's encrypted outer packets to its gateway endpoint are not blocked.
fn discover_physical_host_route_endpoints() -> Vec<IpAddr> {
    let Ok(out) = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_physical_host_route_endpoints(&String::from_utf8_lossy(&out.stdout))
}

fn parse_physical_host_route_endpoints(table: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in table.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (dest, flags, netif) = (fields[0], fields[2], fields[3]);
        // Static host route (`H` and `S` flags, e.g. `UGHS`) on a physical interface.
        if !flags.contains('H') || !flags.contains('S') {
            continue;
        }
        if netif.starts_with("utun") || netif.starts_with("lo") {
            continue;
        }
        let token = dest.strip_suffix("/32").unwrap_or(dest);
        if let Ok(ip) = token.parse::<IpAddr>() {
            if !ip.is_loopback() && !ip.is_unspecified() && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Interface names are interpolated into pf rules: accept only a utun index.
fn validate_interface(iface: &str) -> Result<()> {
    let Some(index) = iface.strip_prefix("utun") else {
        bail!("invalid tunnel_interface — expected utun<N>");
    };
    if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid tunnel_interface — expected utun<N>");
    }
    Ok(())
}

/// A failed command must never turn into a successful kill-switch response.
fn checked_pfctl_output(output: std::io::Result<Output>, action: &str) -> Result<Output> {
    let output = output.with_context(|| format!("pfctl: {action}"))?;
    if !output.status.success() {
        bail!(
            "pfctl could not {action}; kill-switch protection is not confirmed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn interface_validation_rejects_rule_injection() {
        for valid in ["utun0", "utun12"] {
            assert!(validate_interface(valid).is_ok());
        }
        for invalid in [
            "utun",
            "en0",
            "utun1\npass quick all",
            "utun1 all",
            "utun１",
            "utun-1",
        ] {
            assert!(validate_interface(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn pf_activation_errors_are_reported() {
        let failure = Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"permission denied".to_vec(),
        };
        let error = checked_pfctl_output(Ok(failure), "enable pf").unwrap_err();
        assert!(error.to_string().contains("permission denied"));
        assert!(checked_pfctl_output(
            Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            "enable pf"
        )
        .is_err());
    }

    #[test]
    fn anchor_rules_allow_vpn_endpoints_and_ike_before_block() {
        let ep: IpAddr = "51.174.175.4".parse().unwrap();
        let rules = build_anchor_rules("utun7", &[ep]);
        let pass_ep = rules.find("pass quick to 51.174.175.4").expect("endpoint pass rule");
        let pass_ike = rules
            .find("pass quick proto udp from any to any port { 500, 4500 }")
            .expect("ike pass rule");
        let block = rules.find("block return out all").expect("block rule");
        assert!(pass_ep < block);
        assert!(pass_ike < block);
    }

    #[test]
    fn parses_static_physical_host_routes_as_vpn_endpoints() {
        let table = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.200.1      UGScg                 en0
51.174.175.4       192.168.200.1      UGHS                  en0
10.8.0.1           10.8.0.2           UH                  utun7
127.0.0.1          127.0.0.1          UH                    lo0
";
        let eps = parse_physical_host_route_endpoints(table);
        assert_eq!(eps, vec!["51.174.175.4".parse::<IpAddr>().unwrap()]);
    }
}
