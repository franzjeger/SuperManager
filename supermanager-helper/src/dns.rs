//! VPN DNS state management — macOS best-practice teardown.
//!
//! ## Why two stores?
//!
//! macOS System Configuration has two layers:
//!
//!   Setup:/Network/Service/<uuid>/DNS  — persistent, survives reboot.
//!                                        Written by `networksetup`.
//!   State:/Network/Service/<uuid>/DNS  — ephemeral, cleared on reboot.
//!                                        Written by scutil / VPN daemons.
//!
//! `networksetup -setdnsservers` writes to **Setup** — the user's saved
//! preference. If a VPN sets DNS there and the cleanup step is skipped
//! (fallback disconnect path, crash, SIGKILL), those servers stay set
//! permanently and survive VPN disconnection and reboots.
//!
//! ## Best practice
//!
//! `clear_vpn_dns()` uses a belt-and-braces approach:
//!   1. `networksetup -setdnsservers <service> Empty` — handles any DNS
//!      set via the Setup store (wg-quick, openvpn --up scripts, etc.)
//!   2. `scutil remove State:/Network/Service/<uuid>/DNS` — handles any
//!      DNS set via the State store (our own future scutil writes,
//!      tailscaled, configd overrides)
//!   3. Flush mDNSResponder so apps pick up the reverted config instantly.
//!
//! The function is deliberately infallible — all errors are logged but
//! never propagated, because DNS cleanup must always run to completion
//! even if individual steps fail. Callers treat it as fire-and-forget.
//!
//! ## Boot-time survival
//!
//! The companion LaunchDaemon (`no.sybr.supermanager.vpn-dns-cleanup`)
//! runs `clear_vpn_dns` equivalent shell commands at boot, so a
//! machine that was hard-powered-off mid-VPN session comes up with
//! clean DNS rather than pointing at a VPN gateway that no longer exists.

use std::io::Write as _;
use std::process::Command;

/// Remove any VPN-pushed DNS from both the Setup and State stores.
///
/// Safe to call on every disconnect regardless of backend or whether
/// DNS was actually set — all operations are idempotent and best-effort.
pub fn clear_vpn_dns() {
    let service = detect_active_network_service().unwrap_or_else(|| "Wi-Fi".to_string());
    tracing::info!(service = %service, "clear_vpn_dns: starting cleanup");

    // ── Step 1: Setup store via networksetup ─────────────────────────
    // Covers DNS set by wg-quick and openvpn --up scripts.
    // Try the active service first, then the most common fallbacks so
    // we catch whichever interface was in use at connect time.
    let candidates = {
        let mut v = vec![service.clone()];
        for fallback in &["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"] {
            if !v.iter().any(|s| s == fallback) {
                v.push((*fallback).to_string());
            }
        }
        v
    };
    for svc in &candidates {
        let out = Command::new("/usr/sbin/networksetup")
            .args(["-setdnsservers", svc, "Empty"])
            .output();
        match out {
            Ok(o) if o.status.success() =>
                tracing::info!("clear_vpn_dns: cleared Setup DNS on '{svc}'"),
            Ok(o) => {
                // Service may not exist on this machine — not an error.
                let msg = String::from_utf8_lossy(&o.stderr);
                tracing::debug!("clear_vpn_dns: networksetup '{svc}' -> {msg}");
            }
            Err(e) => tracing::warn!("clear_vpn_dns: networksetup '{svc}' failed: {e}"),
        }
    }

    // ── Step 2: State store via scutil ───────────────────────────────
    // Covers DNS set via scutil (our own future writes, tailscaled, etc.)
    // We remove the State entry for the primary service UUID so configd
    // immediately reverts to whatever DHCP pushed.
    if let Some(uuid) = find_service_uuid() {
        let script = format!(
            "open\nremove State:/Network/Service/{uuid}/DNS\nquit\n"
        );
        match std::process::Command::new("/usr/sbin/scutil")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(script.as_bytes());
                }
                match child.wait() {
                    Ok(_) => tracing::info!(
                        "clear_vpn_dns: removed State DNS for service {uuid}"
                    ),
                    Err(e) => tracing::warn!("clear_vpn_dns: scutil wait: {e}"),
                }
            }
            Err(e) => tracing::warn!("clear_vpn_dns: spawn scutil: {e}"),
        }
    } else {
        tracing::debug!("clear_vpn_dns: no service UUID found, skipping State removal");
    }

    // ── Step 3: flush resolver caches ────────────────────────────────
    // Without this, apps keep using the old resolver for up to 60 s.
    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").output();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .output();

    tracing::info!("clear_vpn_dns: done");
}

/// Find the primary network service UUID from the Setup store.
///
/// Queries `scutil` for `Setup:/Network/Service/*/DNS` keys and
/// returns the first UUID (36-char hyphenated form). Used by
/// `clear_vpn_dns` to target the correct State-store key.
pub(crate) fn find_service_uuid() -> Option<String> {
    let mut child = std::process::Command::new("/usr/sbin/scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    {
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
                if uuid.len() == 36 {
                    return Some(uuid.to_string());
                }
            }
        }
    }
    None
}

/// Detect the user-facing name of the primary active network service.
///
/// Returns `Some("Wi-Fi")` on most Mac laptops; `None` if we cannot
/// determine it (callers fall back to `"Wi-Fi"`).
pub(crate) fn detect_active_network_service() -> Option<String> {
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
