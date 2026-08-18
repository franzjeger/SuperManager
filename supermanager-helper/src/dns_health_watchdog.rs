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
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

const FALLBACK_PATH: &str = "/var/lib/supermanager/dns_fallbacks.json";
const PROBE_QUERY: &str = "google.com";

static SPAWNED: Mutex<bool> = Mutex::new(false);
/// User-configurable fallback list. Held in memory; persisted to
/// disk via `set_fallbacks()` so it survives helper restart.
static FALLBACKS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Spawn the watchdog. Idempotent.
pub fn spawn_watchdog() -> Result<()> {
    let mut spawned = SPAWNED.lock().unwrap();
    if *spawned { return Ok(()); }
    *spawned = true;
    drop(spawned);

    // Load persisted fallbacks (if any).
    if let Ok(s) = fs::read_to_string(FALLBACK_PATH) {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(&s) {
            *FALLBACKS.lock().unwrap() = list;
        }
    }
    if FALLBACKS.lock().unwrap().is_empty() {
        // Sensible default — two well-known public resolvers.
        // The user can override at runtime via `set_fallbacks`
        // (e.g. to prepend an internal DNS for split-horizon
        // domains). Defaults must be reachable everywhere so
        // the watchdog works out of the box on any network.
        *FALLBACKS.lock().unwrap() = vec![
            "1.1.1.1".to_string(),   // Cloudflare
            "9.9.9.9".to_string(),   // Quad9
        ];
    }

    thread::Builder::new()
        .name("dns-health-watchdog".into())
        .spawn(watchdog_loop)
        .context("spawning dns-health-watchdog thread")?;

    tracing::info!("DNS health watchdog spawned");
    Ok(())
}

/// Replace the fallback list. Persisted to disk so a helper
/// restart preserves the user's preference.
pub fn set_fallbacks(list: Vec<String>) -> Result<()> {
    if list.is_empty() {
        anyhow::bail!("fallback list cannot be empty");
    }
    let parent = Path::new(FALLBACK_PATH).parent().unwrap();
    fs::create_dir_all(parent).context("creating fallback dir")?;
    let json = serde_json::to_string(&list).context("encoding json")?;
    fs::write(FALLBACK_PATH, json).context("writing fallback file")?;
    *FALLBACKS.lock().unwrap() = list;
    Ok(())
}

pub fn current_fallbacks() -> Vec<String> {
    FALLBACKS.lock().unwrap().clone()
}

fn watchdog_loop() {
    let mut consecutive_failures = 0u32;
    let mut already_forced = false;
    loop {
        thread::sleep(Duration::from_secs(10));

        let resolvers = read_active_resolvers();
        if resolvers.is_empty() {
            // No resolver at all — skip; the route/connectivity
            // watchdogs handle that case from another angle.
            continue;
        }
        let primary = resolvers.join(", ");

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
            already_forced = false;
            continue;
        }

        consecutive_failures += 1;
        tracing::warn!(
            resolver = %primary,
            "DNS probe miss #{} (~{}s of resolver failure)",
            consecutive_failures,
            consecutive_failures * 10
        );

        if consecutive_failures >= 3 && !already_forced {
            let configured = FALLBACKS.lock().unwrap().clone();

            // Only install fallbacks that actually answer *here*.
            // The list is persisted across networks, so it happily
            // contains a home-LAN resolver that is unreachable from a
            // customer site — installing that unchecked replaces a
            // dead primary with another dead primary, which is the
            // exact failure we were called to repair.
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
                // Don't set already_forced: if a fallback becomes
                // reachable later (VPN comes up, network changes) we
                // should still step in.
                continue;
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
                "DNS unhealthy 30s — forcing State to fallback list"
            );
            match crate::tailscale::force_dns_state(&crate::tailscale::SetDnsArgs {
                servers: fallbacks,
            }) {
                Ok(_) => {
                    already_forced = true;
                }
                Err(e) => tracing::error!("force_dns_state failed: {e}"),
            }
        }
    }
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
        Ok(o) => {
            o.status.success()
                && !String::from_utf8_lossy(&o.stdout).trim().is_empty()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(parse_resolvers("DNS configuration\n\n").is_empty());
        assert!(parse_resolvers("").is_empty());
    }

    #[test]
    fn deduplicates_repeated_nameservers() {
        let dup = "resolver #1\n  nameserver[0] : 1.1.1.1\n  nameserver[1] : 1.1.1.1\n";
        assert_eq!(parse_resolvers(dup), ["1.1.1.1"]);
    }
}
