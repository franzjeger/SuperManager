//! Always-on VPN watchdog.
//!
//! For each registered profile, polls the backend's status every
//! 30 seconds. If the tunnel is down, replays the last successful
//! connect args to bring it back up. Works even when the GUI is
//! closed because the helper is a system-level LaunchDaemon.
//!
//! ## State persistence
//!
//! The watch list is persisted at
//! `/var/lib/supermanager/auto_reconnect.json` so a helper
//! restart (deploy_self, system reboot, crash) preserves the
//! user's always-on selections. The connect args are stored
//! alongside — they're the same bytes the GUI passed to
//! `wg_connect` / `ovpn_connect` / `vpn_connect` last time the
//! user manually connected.
//!
//! ## Backends
//!
//! Three: `wireguard`, `openvpn`, `ikev2`. Tailscale isn't here
//! because tailscaled is itself a LaunchDaemon and handles its
//! own reconnect lifecycle (the daemon pref `WantRunning=true`
//! plus tailscaled's own reconnect-on-network-change).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::openvpn::OpenVpn;
use crate::strongswan::Strongswan;
use crate::wireguard::WireGuard;

const STATE_PATH: &str = "/var/lib/supermanager/auto_reconnect.json";
const POLL_INTERVAL_SECS: u64 = 30;

/// How aggressively the watchdog keeps a profile alive.
#[derive(Clone, Copy, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchMode {
    /// The user's explicit "Always on" toggle: keep the tunnel UP no matter
    /// what — reconnect even if the SA itself dies. This is the default so
    /// entries persisted before `mode` existed (all of which were always-on)
    /// deserialize unchanged.
    #[default]
    AlwaysOn,
    /// Set implicitly by a successful manual full-tunnel connect. Heals ONLY
    /// the route-less case: if the SA is still ESTABLISHED but its 0/1+128/1
    /// split-defaults were lost (e.g. a wake sweep mis-read the SA as down and
    /// ripped them), re-install them via replay. If the SA itself is DOWN, do
    /// nothing — a manually-connected profile stays down until the user
    /// reconnects; we never resurrect it the way Always-on does.
    RouteGuard,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchedProfile {
    pub profile_id: String,
    pub backend: String, // "wireguard" | "openvpn" | "ikev2"
    pub last_connect_args: serde_json::Value,
    #[serde(default)]
    pub mode: WatchMode,
}

/// Process-wide state. Built up at startup by `spawn_watchdog`,
/// then mutated via the public `enable` / `disable` APIs.
#[derive(Default)]
struct State {
    watched: HashMap<String, WatchedProfile>,
}

static STATE: tokio::sync::OnceCell<Arc<Mutex<State>>> = tokio::sync::OnceCell::const_new();

/// Spawn the watchdog. Idempotent. Pass in the helper's existing
/// Arc<Mutex<>> backend handles so we don't fight the main RPC
/// dispatch over them.
pub async fn spawn_watchdog(
    wg: Arc<Mutex<WireGuard>>,
    ov: Arc<Mutex<OpenVpn>>,
    sw: Arc<Mutex<Strongswan>>,
) -> Result<()> {
    let state = STATE
        .get_or_init(|| async {
            let map = match fs::read_to_string(STATE_PATH) {
                Ok(s) => serde_json::from_str::<HashMap<String, WatchedProfile>>(&s)
                    .unwrap_or_default(),
                Err(_) => HashMap::new(),
            };
            Arc::new(Mutex::new(State { watched: map }))
        })
        .await
        .clone();

    // Avoid double-spawn — guard via a separate Once flag.
    static SPAWNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SPAWNED.get().is_some() {
        return Ok(());
    }
    let _ = SPAWNED.set(());

    let count = state.lock().await.watched.len();
    tracing::info!(profiles = count, "auto-reconnect watchdog spawning");

    tokio::spawn(async move {
        watchdog_loop(state, wg, ov, sw).await;
    });
    Ok(())
}

pub async fn enable(
    profile_id: String,
    backend: String,
    args: serde_json::Value,
) -> Result<()> {
    let state = STATE.get().context("watchdog not initialised")?.clone();
    let mut g = state.lock().await;
    g.watched.insert(
        profile_id.clone(),
        WatchedProfile {
            profile_id: profile_id.clone(),
            backend,
            last_connect_args: args,
            mode: WatchMode::AlwaysOn,
        },
    );
    persist(&g.watched)?;
    tracing::info!(profile_id = %profile_id, "auto-reconnect enabled");
    Ok(())
}

pub async fn disable(profile_id: &str) -> Result<()> {
    let state = STATE.get().context("watchdog not initialised")?.clone();
    let mut g = state.lock().await;
    g.watched.remove(profile_id);
    persist(&g.watched)?;
    tracing::info!(profile_id = %profile_id, "auto-reconnect disabled");
    Ok(())
}

pub async fn list_watched() -> Vec<String> {
    let Some(state) = STATE.get() else { return Vec::new() };
    state.lock().await.watched.keys().cloned().collect()
}

/// Refresh stored args for a watched profile. Called from connect
/// RPC handlers after success — captures the latest args so
/// auto-reconnect uses fresh credentials.
pub async fn refresh_args(
    profile_id: &str,
    backend: String,
    args: serde_json::Value,
) -> Result<()> {
    let Some(state) = STATE.get() else { return Ok(()) };
    let mut g = state.lock().await;
    // Preserve the existing watch mode — this only refreshes credentials for a
    // profile that's already watched, and must not silently downgrade an
    // Always-on entry to RouteGuard (or vice versa).
    let Some(existing_mode) = g.watched.get(profile_id).map(|w| w.mode) else {
        return Ok(());
    };
    g.watched.insert(
        profile_id.to_string(),
        WatchedProfile {
            profile_id: profile_id.to_string(),
            backend,
            last_connect_args: args,
            mode: existing_mode,
        },
    );
    persist(&g.watched)?;
    Ok(())
}

/// Register a manually-connected full-tunnel profile for route-only healing.
/// No-op if the profile is already watched — an explicit Always-on entry has
/// strictly stronger semantics and must win. Called from `vpn_connect` on a
/// successful full-tunnel connect. The stored args are the same bytes the GUI
/// passed, so the route-less healer can replay the exact connection.
pub async fn guard_routes(
    profile_id: String,
    backend: String,
    args: serde_json::Value,
) -> Result<()> {
    let state = STATE.get().context("watchdog not initialised")?.clone();
    let mut g = state.lock().await;
    if g.watched.contains_key(&profile_id) {
        return Ok(()); // already Always-on or already guarded — leave it
    }
    g.watched.insert(
        profile_id.clone(),
        WatchedProfile {
            profile_id: profile_id.clone(),
            backend,
            last_connect_args: args,
            mode: WatchMode::RouteGuard,
        },
    );
    persist(&g.watched)?;
    tracing::info!(profile_id = %profile_id, "route-guard enabled (manual full-tunnel connect)");
    Ok(())
}

/// Drop a RouteGuard registration on manual disconnect. Leaves an Always-on
/// entry intact — that's the user's standing intent, not something a single
/// disconnect revokes (matching the pre-existing Always-on contract).
pub async fn unguard_routes(profile_id: &str) -> Result<()> {
    let Some(state) = STATE.get() else { return Ok(()) };
    let mut g = state.lock().await;
    if matches!(
        g.watched.get(profile_id).map(|w| w.mode),
        Some(WatchMode::RouteGuard)
    ) {
        g.watched.remove(profile_id);
        persist(&g.watched)?;
        tracing::info!(profile_id = %profile_id, "route-guard removed (manual disconnect)");
    }
    Ok(())
}

fn persist(map: &HashMap<String, WatchedProfile>) -> Result<()> {
    let parent = Path::new(STATE_PATH).parent().unwrap();
    fs::create_dir_all(parent).context("creating state dir")?;
    let json = serde_json::to_string_pretty(map).context("encoding json")?;
    fs::write(STATE_PATH, json).context("writing state file")?;
    Ok(())
}

async fn watchdog_loop(
    state: Arc<Mutex<State>>,
    wg: Arc<Mutex<WireGuard>>,
    ov: Arc<Mutex<OpenVpn>>,
    sw: Arc<Mutex<Strongswan>>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
    // First tick fires immediately — skip it so we don't probe
    // before the helper has fully started.
    ticker.tick().await;
    loop {
        ticker.tick().await;

        // Tailscale exit-node self-heal. Runs EVERY tick, independent of any
        // enrolled always-on VPN profile (so it must come before the
        // empty-snapshot `continue` below). spawn_blocking because the
        // reconcile does synchronous route/CLI/curl work (up to an ~8s
        // reachability probe) and must not block the async runtime. It is
        // no-brick: it only (re)installs the exit-node split routes behind a
        // live reachability gate, and stays on the local uplink otherwise.
        tokio::task::spawn_blocking(crate::tailscale::reconcile_exit_node);

        let snapshot: Vec<WatchedProfile> = {
            let g = state.lock().await;
            g.watched.values().cloned().collect()
        };
        if snapshot.is_empty() {
            continue;
        }
        for p in snapshot {
            let wg = wg.clone();
            let ov = ov.clone();
            let sw = sw.clone();
            tokio::spawn(async move {
                check_and_reconnect(&p, wg, ov, sw).await;
            });
        }
    }
}

async fn check_and_reconnect(
    p: &WatchedProfile,
    wg: Arc<Mutex<WireGuard>>,
    ov: Arc<Mutex<OpenVpn>>,
    sw: Arc<Mutex<Strongswan>>,
) {
    let connected = match p.backend.as_str() {
        "wireguard" => wg_connected(p, wg.clone()).await,
        "openvpn" => ov_connected(p, ov.clone()).await,
        "ikev2" => sw_connected(p, sw.clone()).await,
        other => {
            tracing::warn!(backend = %other, "unknown backend in watch list");
            return;
        }
    };
    if connected {
        return;
    }

    // RouteGuard (a manually-connected full tunnel) heals ONLY the route-less
    // case: the SA is still ESTABLISHED but its 0/1+128/1 routes vanished.
    // `sw_connected` already returned false above (it counts a route-less full
    // tunnel as not-connected); for RouteGuard we additionally require the SA
    // itself to still be up before replaying. If the SA is genuinely down we do
    // NOTHING — a manually-connected profile stays down until the user
    // reconnects, unlike Always-on which resurrects it here.
    if p.mode == WatchMode::RouteGuard {
        let sa_up = p.backend == "ikev2" && sw_sa_established(p, sw.clone()).await;
        if !sa_up {
            return;
        }
        tracing::warn!(
            profile_id = %p.profile_id,
            "route-guard: full-tunnel SA up but routes missing — reinstalling via replay"
        );
    } else {
        tracing::warn!(
            profile_id = %p.profile_id,
            backend = %p.backend,
            "tunnel down — auto-reconnecting"
        );
    }
    let result = match p.backend.as_str() {
        "wireguard" => replay_wg(p, wg).await,
        "openvpn" => replay_ov(p, ov).await,
        "ikev2" => replay_sw(p, sw).await,
        _ => unreachable!(),
    };
    match result {
        Ok(_) => tracing::info!(
            profile_id = %p.profile_id,
            backend = %p.backend,
            "auto-reconnect succeeded"
        ),
        Err(e) => tracing::warn!(
            profile_id = %p.profile_id,
            backend = %p.backend,
            error = %e,
            "auto-reconnect failed; will retry next cycle"
        ),
    }
}

// ---------- per-backend status + replay ----------

async fn wg_connected(p: &WatchedProfile, wg: Arc<Mutex<WireGuard>>) -> bool {
    let args = crate::wireguard::WgStatusArgs {
        profile_id: p.profile_id.clone(),
    };
    let mut g = wg.lock().await;
    matches!(
        g.status(&args).await,
        Ok(s) if matches!(s.state, crate::wireguard::WgState::Connected)
    )
}

async fn replay_wg(p: &WatchedProfile, wg: Arc<Mutex<WireGuard>>) -> Result<()> {
    let args: crate::wireguard::WgConnectArgs =
        serde_json::from_value(p.last_connect_args.clone())
            .context("decode wg args")?;
    let mut g = wg.lock().await;
    g.connect(&args).await.map(|_| ())
}

async fn ov_connected(p: &WatchedProfile, ov: Arc<Mutex<OpenVpn>>) -> bool {
    let args = crate::openvpn::OvpnStatusArgs {
        profile_id: p.profile_id.clone(),
    };
    let mut g = ov.lock().await;
    matches!(
        g.status(&args).await,
        Ok(s) if matches!(s.state, crate::openvpn::OvpnState::Connected)
    )
}

async fn replay_ov(p: &WatchedProfile, ov: Arc<Mutex<OpenVpn>>) -> Result<()> {
    let args: crate::openvpn::OvpnConnectArgs =
        serde_json::from_value(p.last_connect_args.clone())
            .context("decode ovpn args")?;
    let mut g = ov.lock().await;
    g.connect(&args).await.map(|_| ())
}

async fn sw_connected(p: &WatchedProfile, sw: Arc<Mutex<Strongswan>>) -> bool {
    let args = crate::strongswan::StatusArgs {
        profile_id: p.profile_id.clone(),
    };
    let connected = {
        let mut g = sw.lock().await;
        matches!(g.status(&args).await, Ok(s) if s.state == "connected")
    };
    if !connected {
        return false;
    }
    // Route-aware health: a full-tunnel SA can be ESTABLISHED while its
    // 0/1+128/1 split-defaults were externally flushed, leaving a live-but-
    // routeless tunnel that leaks traffic in cleartext while status reads
    // "connected". Treat that as not-connected so the watchdog replays the
    // connect and re-installs the routes. Split-tunnel profiles install no
    // 0/1, so only apply this when the profile asked for a full tunnel.
    let full_tunnel = serde_json::from_value::<crate::strongswan::ConnectArgs>(
        p.last_connect_args.clone(),
    )
    .map(|a| a.full_tunnel)
    .unwrap_or(false);
    if full_tunnel && !crate::strongswan::full_tunnel_routes_present() {
        tracing::warn!(
            profile = %p.profile_id,
            "auto_reconnect: SA established but full-tunnel routes missing — forcing replay"
        );
        return false;
    }
    true
}

/// True if THIS profile's IKEv2 SA is ESTABLISHED, regardless of whether its
/// full-tunnel routes are present. The RouteGuard branch uses this to tell the
/// route-less case (SA up + routes gone → heal) apart from a genuinely dead SA
/// (leave a manually-connected profile down). It is deliberately the
/// route-UNaware half of `sw_connected`.
async fn sw_sa_established(p: &WatchedProfile, sw: Arc<Mutex<Strongswan>>) -> bool {
    let args = crate::strongswan::StatusArgs {
        profile_id: p.profile_id.clone(),
    };
    let mut g = sw.lock().await;
    matches!(g.status(&args).await, Ok(s) if s.state == "connected")
}

async fn replay_sw(p: &WatchedProfile, sw: Arc<Mutex<Strongswan>>) -> Result<()> {
    let args: crate::strongswan::ConnectArgs =
        serde_json::from_value(p.last_connect_args.clone())
            .context("decode ikev2 args")?;
    let mut g = sw.lock().await;
    g.connect(&args).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watched_profile_without_mode_defaults_to_always_on() {
        // Migration guard: auto_reconnect.json predates the `mode` field, and
        // every entry in an existing file is an Always-on enrolment. A missing
        // `mode` MUST deserialize as AlwaysOn — never RouteGuard, which would
        // silently downgrade a user's Always-on profile the first time the new
        // helper reloads the persisted state.
        let json = r#"{
            "profile_id": "abc",
            "backend": "ikev2",
            "last_connect_args": { "profile_id": "abc" }
        }"#;
        let wp: WatchedProfile = serde_json::from_str(json).unwrap();
        assert_eq!(wp.mode, WatchMode::AlwaysOn);
    }

    #[test]
    fn watch_mode_wire_form_is_stable() {
        // Pin the serialized form: renaming a variant would silently orphan
        // every RouteGuard entry already written to disk.
        assert_eq!(
            serde_json::to_string(&WatchMode::AlwaysOn).unwrap(),
            "\"always_on\""
        );
        assert_eq!(
            serde_json::to_string(&WatchMode::RouteGuard).unwrap(),
            "\"route_guard\""
        );
        for m in [WatchMode::AlwaysOn, WatchMode::RouteGuard] {
            let s = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<WatchMode>(&s).unwrap(), m);
        }
    }
}
