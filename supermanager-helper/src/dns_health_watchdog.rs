//! DNS health monitor.
//!
//! Probes the system's effective resolver every 10 seconds. If
//! the resolver fails to answer a known query 3 times in a row
//! (~30 s), forces the DNS State via scutil to a known-good
//! fallback list. Automatic recovery from the macOS-configd-
//! stuck-on-unreachable-IPv6-RDNSS class of bugs.
//!
//! ## Why not just always force?
//!
//! 1. The user's preferred DNS (their own home server) is
//!    usually right when DHCP/RA is sane.
//! 2. We respect that and only intervene when actively broken.
//! 3. Forcing DNS at every poll would fight DHCP renewals.
//!
//! ## What's "broken"?
//!
//! `dig +time=2 +tries=1 google.com @<resolver_ip> +short`
//! returning empty or non-zero exit, for **every** nameserver
//! listed under `scutil --dns` resolver #1 — not just the first.
//! macOS falls through the list, so a dead primary alongside a
//! healthy secondary (a perfectly ordinary DHCP handout) is a
//! working configuration. Judging only `nameserver[0]` made us
//! tear down usable setups.
//!
//! ## Fallback list
//!
//! Configurable via `set_fallback_dns` RPC, persisted in
//! `/var/lib/supermanager/dns_fallbacks.json`.
//!
//! Every candidate is probed before it is installed, and only the
//! ones that answer *on this network* are used. The list outlives
//! the network it was written on: an operator who adds their home
//! resolver carries it to a customer site, where it is unreachable.
//! Installing it unchecked swapped a dead primary for a different
//! dead primary — reproducing the exact fault the watchdog exists
//! to repair. If nothing in the list answers, we log and leave DNS
//! alone; making it worse is not an improvement.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
// Every command here is bounded: see `proc::Bounded`.
use crate::proc::Bounded as Command;
use std::sync::{Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

const FALLBACK_PATH: &str = "/var/lib/supermanager/dns_fallbacks.json";
const PROBE_QUERY: &str = "google.com";

static SPAWNED: Mutex<bool> = Mutex::new(false);
static WAKE_SIGNAL: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
/// Opt-in fallback list (`P3-4`): empty by default so SuperManager never forces
/// third-party public DNS (`1.1.1.1`/`9.9.9.9`) unless the operator explicitly
/// configured fallback servers via `tailscale_set_dns_fallbacks`.
static FALLBACKS: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn notify_state_changed() {
    let (lock, cvar) = &WAKE_SIGNAL;
    *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
    cvar.notify_all();
}

fn parse_requested_fallbacks(list: &[String]) -> Result<Vec<String>> {
    let clear =
        list.is_empty() || (list.len() == 1 && list[0].trim().eq_ignore_ascii_case("empty"));
    if clear {
        return Ok(Vec::new());
    }
    Ok(crate::tailscale::dns_servers(list)?
        .iter()
        .map(ToString::to_string)
        .collect())
}

/// Spawn the watchdog. Idempotent.
pub fn spawn_watchdog() -> Result<()> {
    let mut spawned = SPAWNED.lock().unwrap_or_else(PoisonError::into_inner);
    if *spawned {
        return Ok(());
    }
    *spawned = true;
    drop(spawned);

    // Load persisted opt-in fallbacks (if any). Missing or empty file leaves
    // the watchdog disabled (`FALLBACKS = []`).
    if let Ok(s) = fs::read_to_string(FALLBACK_PATH) {
        *FALLBACKS.lock().unwrap_or_else(PoisonError::into_inner) = stored_fallbacks(&s);
    }

    thread::Builder::new()
        .name("dns-health-watchdog".into())
        .spawn(watchdog_loop)
        .context("spawning dns-health-watchdog thread")?;

    tracing::info!(
        enabled = !current_fallbacks().is_empty(),
        "DNS health watchdog spawned (opt-in)"
    );
    Ok(())
}

/// Replace (or clear) the fallback list. Passing an empty list or `["empty"]`
/// disables the DNS health watchdog and removes any active `"watchdog"` DNS key.
pub fn set_fallbacks(list: &[String]) -> Result<()> {
    let list = parse_requested_fallbacks(list)?;
    if let Some(parent) = Path::new(FALLBACK_PATH).parent() {
        fs::create_dir_all(parent).context("creating fallback dir")?;
    }
    let json = serde_json::to_string(&list).context("encoding json")?;
    crate::private_file::write(Path::new(FALLBACK_PATH), json.as_bytes())
        .context("writing fallback file")?;
    let disabled = list.is_empty();
    *FALLBACKS.lock().unwrap_or_else(PoisonError::into_inner) = list;
    if disabled {
        crate::dns::clear_vpn_dns_for("watchdog");
    }
    notify_state_changed();
    Ok(())
}

/// The addresses in a stored fallback file. A file written before servers
/// were validated may hold other entries; only addresses are kept.
fn stored_fallbacks(json: &str) -> Vec<String> {
    let Ok(list) = serde_json::from_str::<Vec<String>>(json) else {
        return Vec::new();
    };
    let kept: Vec<String> = list
        .iter()
        .filter_map(|server| crate::tailscale::dns_servers(std::slice::from_ref(server)).ok())
        .flatten()
        .map(|address| address.to_string())
        .collect();
    if kept.len() != list.len() {
        tracing::warn!(
            stored = list.len(),
            kept = kept.len(),
            "dropping DNS fallbacks that are not IP addresses"
        );
    }
    kept
}

pub fn current_fallbacks() -> Vec<String> {
    FALLBACKS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn watchdog_loop() {
    let mut consecutive_failures = 0u32;
    let mut already_forced = false;
    loop {
        let configured = current_fallbacks();
        if configured.is_empty() {
            if already_forced {
                crate::dns::clear_vpn_dns_for("watchdog");
                already_forced = false;
            }
            consecutive_failures = 0;
            let (lock, cvar) = &WAKE_SIGNAL;
            let changed = lock.lock().unwrap_or_else(PoisonError::into_inner);
            if *changed {
                let mut guard = changed;
                *guard = false;
            } else {
                let mut guard = cvar.wait(changed).unwrap_or_else(PoisonError::into_inner);
                *guard = false;
            }
            continue;
        }

        // Gate active DNS probing on SuperManager managing an active VPN or
        // Tailscale session (`P3-1`).
        if !crate::has_managed_network_state() {
            if already_forced {
                crate::dns::clear_vpn_dns_for("watchdog");
                already_forced = false;
            }
            consecutive_failures = 0;
            let (lock, cvar) = &WAKE_SIGNAL;
            let changed = lock.lock().unwrap_or_else(PoisonError::into_inner);
            if *changed {
                let mut guard = changed;
                *guard = false;
            } else {
                let (mut guard, _) = cvar
                    .wait_timeout(changed, Duration::from_secs(30))
                    .unwrap_or_else(PoisonError::into_inner);
                *guard = false;
            }
            continue;
        }

        thread::sleep(Duration::from_secs(10));

        let resolvers = read_active_resolvers();
        if resolvers.is_empty() {
            // No resolver at all — skip; the route/connectivity
            // watchdogs handle that case from another angle.
            continue;
        }
        let primary = resolvers.join(", ");

        // If we previously installed the supplemental fallback DNS, check
        // whether the primary service's own resolver (Setup/DHCP) is answering
        // again; if so, remove our supplemental override so split-horizon /
        // local LAN names return to the native resolver.
        if already_forced {
            let own = crate::dns::system_resolvers();
            if !own.is_empty() && own.iter().any(|ip| probe_resolver(ip)) {
                tracing::info!(
                    own_resolvers = ?own,
                    "primary network service DNS is healthy again — clearing supplemental fallback"
                );
                crate::dns::clear_vpn_dns_for("watchdog");
                already_forced = false;
                consecutive_failures = 0;
                continue;
            }
        }

        // Healthy if ANY configured resolver answers, not just the
        // first. macOS falls through the list, so a dead primary with
        // a live secondary is a working configuration — treating it
        // as broken made us replace a usable setup with our own.
        if resolvers.iter().any(|ip| probe_resolver(ip)) {
            if consecutive_failures > 0 {
                tracing::info!(
                    resolver = %primary,
                    "DNS resolver healthy after {} miss(es)",
                    consecutive_failures
                );
            }
            consecutive_failures = 0;
            continue;
        }

        consecutive_failures += 1;
        tracing::warn!(
            resolver = %primary,
            "DNS probe miss #{} (~{}s of resolver failure)",
            consecutive_failures,
            consecutive_failures * 10
        );

        if consecutive_failures >= 3 && !already_forced && try_install_fallbacks(&primary) {
            already_forced = true;
        }
    }
}

/// Probe configured fallback resolvers and install the reachable ones under the
/// `"watchdog"` State DNS key. Returns `true` when at least one fallback was
/// installed.
fn try_install_fallbacks(primary: &str) -> bool {
    let configured = FALLBACKS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();

    // Only install fallbacks that actually answer *here*. The list is persisted
    // across networks, so it happily contains a home-LAN resolver that is
    // unreachable from a customer site — installing that unchecked replaces a
    // dead primary with another dead primary.
    let fallbacks: Vec<String> = configured
        .iter()
        .filter(|ip| probe_resolver(ip))
        .cloned()
        .collect();

    if fallbacks.is_empty() {
        tracing::error!(
            resolver = %primary,
            configured = ?configured,
            "DNS unhealthy 30s but no configured fallback answers here — \
             leaving DNS alone rather than making it worse"
        );
        return false;
    }
    if fallbacks.len() != configured.len() {
        tracing::warn!(
            skipped = ?configured.iter().filter(|ip| !fallbacks.contains(ip)).collect::<Vec<_>>(),
            "some configured DNS fallbacks are unreachable here — skipping them"
        );
    }
    tracing::error!(
        resolver = %primary,
        fallbacks = ?fallbacks,
        "DNS unhealthy 30s — installing supplemental fallback DNS via scutil"
    );
    crate::dns::set_vpn_dns_for("watchdog", &fallbacks);
    true
}

/// Read every nameserver of `resolver #1` from `scutil --dns`, in
/// the order macOS will try them.
fn read_active_resolvers() -> Vec<String> {
    let Ok(out) = Command::new("/usr/sbin/scutil").arg("--dns").output() else {
        return vec![];
    };
    if !out.status.success() {
        return vec![];
    }
    parse_resolvers(&String::from_utf8_lossy(&out.stdout))
}

/// Pure parse half of [`read_active_resolvers`], split out so the
/// scutil format can be tested without running scutil.
///
/// Collects ALL `nameserver[n]` entries under `resolver #1` — reading
/// only `nameserver[0]` meant a dead primary with a healthy secondary
/// (a normal DHCP handout) looked like total DNS failure.
fn parse_resolvers(scutil_output: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut in_first = false;
    for line in scutil_output.lines() {
        let t = line.trim();
        if t == "resolver #1" {
            in_first = true;
            continue;
        }
        if in_first {
            // Next resolver block starts — resolver #1 is done.
            if t.starts_with("resolver #") {
                break;
            }
            if let Some(rest) = t.strip_prefix("nameserver[") {
                if let Some(idx) = rest.find(": ") {
                    let ip = rest[idx + 2..].trim();
                    if !ip.is_empty() && !found.iter().any(|s: &String| s == ip) {
                        found.push(ip.to_string());
                    }
                }
            }
        }
    }
    found
}

/// Returns true iff `dig @<ip> +time=2 +tries=1 google.com +short`
/// produces a non-empty answer.
fn probe_resolver(ip: &str) -> bool {
    let out = Command::new("/usr/bin/dig")
        .args([
            "+time=2",
            "+tries=1",
            "+short",
            PROBE_QUERY,
            &format!("@{ip}"),
        ])
        .output();
    match out {
        Ok(o) => o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file written before servers were validated keeps only its
    /// addresses.
    #[test]
    fn a_stored_fallback_that_is_not_an_address_is_dropped() {
        assert_eq!(
            stored_fallbacks(r#"["1.1.1.1", "resolver.example", "x", " 9.9.9.9 "]"#),
            ["1.1.1.1", "9.9.9.9"]
        );
        assert_eq!(stored_fallbacks("not json"), Vec::<String>::new());
    }

    #[test]
    fn empty_or_clear_fallbacks_disable_watchdog() {
        assert_eq!(stored_fallbacks("[]"), Vec::<String>::new());
        assert_eq!(
            parse_requested_fallbacks(&[]).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_requested_fallbacks(&["empty".to_owned()]).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_requested_fallbacks(&["1.1.1.1".to_owned()]).unwrap(),
            vec!["1.1.1.1".to_owned()]
        );
    }

    /// The exact shape scutil emits on a machine whose DHCP server
    /// hands out a dead primary and a working secondary — the case
    /// that made the watchdog replace a usable config with its own.
    const SCUTIL_TWO: &str = "\
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 10.10.110.1
  nameserver[1] : 8.8.8.8
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  nameserver[0] : 224.0.0.251
";

    #[test]
    fn reads_every_nameserver_not_just_the_first() {
        assert_eq!(parse_resolvers(SCUTIL_TWO), ["10.10.110.1", "8.8.8.8"]);
    }

    /// Must not bleed into resolver #2 — mDNS's 224.0.0.251 is not a
    /// resolver we should ever probe or count as healthy.
    #[test]
    fn stops_at_the_next_resolver_block() {
        assert!(!parse_resolvers(SCUTIL_TWO).contains(&"224.0.0.251".to_string()));
    }

    #[test]
    fn handles_no_resolvers() {
        assert_eq!(
            parse_resolvers("DNS configuration\n\n"),
            Vec::<String>::new()
        );
        assert_eq!(parse_resolvers(""), Vec::<String>::new());
    }

    #[test]
    fn deduplicates_repeated_nameservers() {
        let dup = "resolver #1\n  nameserver[0] : 1.1.1.1\n  nameserver[1] : 1.1.1.1\n";
        assert_eq!(parse_resolvers(dup), ["1.1.1.1"]);
    }
}
