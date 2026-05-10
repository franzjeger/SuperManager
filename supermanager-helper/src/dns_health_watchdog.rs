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
//! returning empty or non-zero exit. The resolver's IP is read
//! live from `scutil --dns` resolver #1.
//!
//! ## Fallback list
//!
//! Configurable via `set_fallback_dns` RPC — defaults to
//! `["192.168.200.23", "9.9.9.9"]` based on the current user's
//! preferences. Persisted in
//! `/var/lib/supermanager/dns_fallbacks.json`.

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
        // Sensible default — user's home DNS first, Quad9 as
        // public-DNS fallback (Cloudflare 1.1.1.1 is also fine
        // but Quad9 is what the user told us to use).
        *FALLBACKS.lock().unwrap() = vec![
            "192.168.200.23".to_string(),
            "9.9.9.9".to_string(),
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

        let primary = match read_active_resolver() {
            Some(ip) => ip,
            None => {
                // No resolver at all — skip; the route/connectivity
                // watchdogs handle that case from another angle.
                continue;
            }
        };

        if probe_resolver(&primary) {
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
            let fallbacks = FALLBACKS.lock().unwrap().clone();
            tracing::error!(
                resolver = %primary,
                fallbacks = ?fallbacks,
                "DNS unhealthy 30s — forcing State to fallback list"
            );
            match crate::tailscale::force_dns_state(crate::tailscale::SetDnsArgs {
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

/// Read the IP of `resolver #1` from `scutil --dns`.
fn read_active_resolver() -> Option<String> {
    let out = Command::new("/usr/sbin/scutil").arg("--dns").output().ok()?;
    if !out.status.success() { return None; }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut in_first = false;
    for line in stdout.lines() {
        let t = line.trim();
        if t == "resolver #1" {
            in_first = true;
            continue;
        }
        if in_first {
            // We hit the next resolver before finding a
            // nameserver — give up.
            if t.starts_with("resolver #") { return None; }
            if let Some(rest) = t.strip_prefix("nameserver[") {
                if let Some(idx) = rest.find(": ") {
                    return Some(rest[idx + 2..].trim().to_string());
                }
            }
        }
    }
    None
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
