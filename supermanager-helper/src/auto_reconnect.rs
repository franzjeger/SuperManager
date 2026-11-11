//! Always-on VPN watchdog.
//!
//! For each registered profile, polls the backend's status every
//! 30 seconds. If the tunnel is down, replays the last successful
//! connect args to bring it back up. Works even when the GUI is
//! closed because the helper is a system-level LaunchDaemon.
//!
//! ## State persistence
//!
//! The watch list is persisted, readable by root only, at
//! `/var/lib/supermanager/auto_reconnect.json` so a helper
//! restart (update, system reboot, crash) preserves the
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
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::events::{self, Event};
use crate::openvpn::OpenVpn;
use crate::strongswan::Strongswan;
use crate::wireguard::WireGuard;

const STATE_PATH: &str = "/var/lib/supermanager/auto_reconnect.json";
const POLL_INTERVAL_SECS: u64 = 30;

/// Failed replays in a row after which an Always-on profile is reported as
/// failing: 90 s at the 30 s tick. Long enough to ride out a network change,
/// short enough that the user hears about stale credentials from us rather
/// than from a connection that quietly stayed down.
const FAILING_AFTER: u32 = 3;

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
    /// Held in RAM only — never serialized to `auto_reconnect.json`. After a
    /// helper restart or reboot, the Mac app re-arms Always-on profiles from
    /// the user's Data Protection Keychain.
    #[serde(skip, default = "empty_connect_args")]
    pub last_connect_args: serde_json::Value,
    #[serde(default)]
    pub mode: WatchMode,
}

fn empty_connect_args() -> serde_json::Value {
    serde_json::Value::Null
}

impl WatchedProfile {
    /// Can a replay actually run, or is this entry enrolled but toothless?
    ///
    /// The GUI enrols an IKEv2 profile with empty args, because the rich
    /// connect args are only captured by `refresh_args` after a successful
    /// manual connect. Until that happens `replay_sw`'s decode fails every
    /// tick while the Always-on toggle sits there showing ON — the toggle
    /// claims protection the helper cannot deliver. Reported so the GUI can
    /// say "arms after the next connect" instead of lying.
    ///
    /// Deliberately the same decode + validation the replay path performs, so
    /// the answer cannot drift from the behaviour it describes.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        let a = self.last_connect_args.clone();
        match self.backend.as_str() {
            "wireguard" => {
                serde_json::from_value::<crate::wireguard::WgConnectArgs>(a).is_ok_and(|args| {
                    args.profile_id == self.profile_id
                        && crate::wireguard::validate_connect_args(&args).is_ok()
                })
            }
            "openvpn" => {
                serde_json::from_value::<crate::openvpn::OvpnConnectArgs>(a).is_ok_and(|args| {
                    args.profile_id == self.profile_id
                        && args.has_configuration()
                        && crate::openvpn::validate_connect_args(&args).is_ok()
                })
            }
            "ikev2" => {
                serde_json::from_value::<crate::strongswan::ConnectArgs>(a).is_ok_and(|args| {
                    args.profile_id == self.profile_id
                        && crate::strongswan::validate_connect_args(&args).is_ok()
                })
            }
            _ => false,
        }
    }
}

fn validate_profile_key(profile_id: &str) -> Result<()> {
    if profile_id.is_empty()
        || profile_id.len() > 128
        || !profile_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        anyhow::bail!("invalid profile_id");
    }
    Ok(())
}

/// True when `args` is the GUI's pre-connect placeholder (`null`, `{}`, or
/// `{"profile_id": "<same id>"}`), which enrols a profile in the unarmed state
/// until the first successful manual connect populates full connect arguments.
fn is_unarmed_placeholder(profile_id: &str, args: &serde_json::Value) -> bool {
    match args {
        serde_json::Value::Null => true,
        serde_json::Value::Object(map) if map.is_empty() => true,
        serde_json::Value::Object(map) if map.len() == 1 => {
            map.get("profile_id").and_then(|v| v.as_str()) == Some(profile_id)
        }
        _ => false,
    }
}

/// Validate auto-reconnect registration inputs with the same validators used by
/// the corresponding connect RPCs before storing anything in memory or on disk.
pub(crate) fn validate_enrollment(
    profile_id: &str,
    backend: &str,
    args: &serde_json::Value,
) -> Result<()> {
    validate_profile_key(profile_id)?;
    if !matches!(backend, "wireguard" | "openvpn" | "ikev2") {
        anyhow::bail!("unsupported auto-reconnect backend '{backend}'");
    }
    if args.get("config_file").is_some() {
        anyhow::bail!("config_file is not supported; pass inline configuration");
    }
    if is_unarmed_placeholder(profile_id, args) {
        return Ok(());
    }
    match backend {
        "wireguard" => {
            let parsed: crate::wireguard::WgConnectArgs =
                serde_json::from_value(args.clone()).context("invalid wireguard connect_args")?;
            if parsed.profile_id != profile_id {
                anyhow::bail!("connect_args.profile_id does not match profile_id");
            }
            crate::wireguard::validate_connect_args(&parsed)?;
        }
        "openvpn" => {
            let parsed: crate::openvpn::OvpnConnectArgs =
                serde_json::from_value(args.clone()).context("invalid openvpn connect_args")?;
            if parsed.profile_id != profile_id {
                anyhow::bail!("connect_args.profile_id does not match profile_id");
            }
            if parsed.has_configuration() {
                crate::openvpn::validate_connect_args(&parsed)?;
            }
        }
        "ikev2" => {
            let parsed: crate::strongswan::ConnectArgs =
                serde_json::from_value(args.clone()).context("invalid ikev2 connect_args")?;
            if parsed.profile_id != profile_id {
                anyhow::bail!("connect_args.profile_id does not match profile_id");
            }
            crate::strongswan::validate_connect_args(&parsed)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

const MAX_BACKOFF_SECS: u64 = 300;

/// Exponential backoff after `attempts` consecutive failures:
/// `30s -> 60s -> 120s -> 240s -> 300s (cap)`.
fn backoff_duration(attempts: u32) -> Duration {
    let shift = attempts.saturating_sub(1).min(4);
    let secs = POLL_INTERVAL_SECS
        .saturating_mul(1u64 << shift)
        .min(MAX_BACKOFF_SECS);
    Duration::from_secs(secs)
}

/// True when `error` indicates a definitive authentication/credential rejection
/// (where retrying every tick would only risk locking the operator's account).
fn is_auth_failure(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    [
        "authentication failed",
        "auth_failed",
        "eap_failure",
        "eap authentication failed",
        "received eap_failure",
        "invalid credentials",
        "bad username or password",
        "logon failure",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[derive(Clone, Debug, Default)]
struct FailureRecord {
    attempts: u32,
    next_retry_at: Option<std::time::Instant>,
    auth_failed: bool,
}

/// Process-wide state. Built up at startup by `spawn_watchdog`,
/// then mutated via the public `enable` / `disable` APIs.
#[derive(Default)]
struct State {
    watched: HashMap<String, WatchedProfile>,
    /// Failed replays in a row + backoff/auth-halt state, per profile.
    /// In memory only: a restarted helper counts from zero again.
    failures: HashMap<String, FailureRecord>,
}

impl State {
    fn should_skip_for_backoff(&self, profile_id: &str, now: std::time::Instant) -> bool {
        let Some(rec) = self.failures.get(profile_id) else {
            return false;
        };
        if rec.auth_failed {
            return true;
        }
        rec.next_retry_at.is_some_and(|due| now < due)
    }

    /// Count a failed replay of `p`. Returns the event to record when this
    /// failure completes a run of `FAILING_AFTER` (or immediately on a
    /// definitive authentication failure, which also halts further retries
    /// until fresh credentials arrive).
    fn replay_failed(&mut self, p: &WatchedProfile, error: &str) -> Option<Event> {
        self.replay_failed_at(p, error, std::time::Instant::now())
    }

    fn replay_failed_at(
        &mut self,
        p: &WatchedProfile,
        error: &str,
        now: std::time::Instant,
    ) -> Option<Event> {
        if p.mode != WatchMode::AlwaysOn || !p.is_armed() {
            return None;
        }
        let rec = self.failures.entry(p.profile_id.clone()).or_default();
        let was_auth_failed = rec.auth_failed;
        rec.attempts = rec.attempts.saturating_add(1);
        let attempts = rec.attempts;
        if is_auth_failure(error) {
            rec.auth_failed = true;
            rec.next_retry_at = None;
            if !was_auth_failed && attempts < FAILING_AFTER {
                return Some(Event::VpnReconnectFailing {
                    profile_id: p.profile_id.clone(),
                    backend: p.backend.clone(),
                    attempts,
                    error: error.to_owned(),
                });
            }
        } else {
            rec.next_retry_at = Some(now + backoff_duration(attempts));
        }
        (attempts == FAILING_AFTER).then(|| Event::VpnReconnectFailing {
            profile_id: p.profile_id.clone(),
            backend: p.backend.clone(),
            attempts,
            error: error.to_owned(),
        })
    }
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
            let (mut map, had_legacy_secrets) = match fs::read_to_string(STATE_PATH) {
                Ok(s) => {
                    let had_legacy = s.contains("last_connect_args");
                    let parsed = serde_json::from_str::<HashMap<String, WatchedProfile>>(&s)
                        .unwrap_or_default();
                    (parsed, had_legacy)
                }
                Err(_) => (HashMap::new(), false),
            };
            // Purge any legacy RouteGuard or invalid entries that an older
            // helper persisted to disk, and initialise in-memory connect args
            // to an unarmed placeholder until the GUI re-supplies credentials.
            let before = map.len();
            map.retain(|k, w| {
                w.last_connect_args = serde_json::json!({ "profile_id": w.profile_id });
                w.mode == WatchMode::AlwaysOn
                    && k == &w.profile_id
                    && validate_enrollment(&w.profile_id, &w.backend, &w.last_connect_args).is_ok()
            });
            if had_legacy_secrets || map.len() != before {
                let _ = persist(&map);
            }
            // A file an earlier helper wrote gets the same mode.
            if let Err(e) = fs::set_permissions(STATE_PATH, fs::Permissions::from_mode(0o600)) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("auto_reconnect: could not restrict {STATE_PATH}: {e}");
                }
            }
            Arc::new(Mutex::new(State {
                watched: map,
                ..State::default()
            }))
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

pub async fn enable(profile_id: String, backend: String, args: serde_json::Value) -> Result<()> {
    validate_enrollment(&profile_id, &backend, &args)?;
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
    // New args are a new promise: a run of failures with the old ones must not
    // keep a later run from being reported.
    g.failures.remove(&profile_id);
    persist(&g.watched)?;
    tracing::info!(profile_id = %profile_id, "auto-reconnect enabled");
    Ok(())
}

pub async fn disable(profile_id: &str) -> Result<()> {
    let state = STATE.get().context("watchdog not initialised")?.clone();
    let mut g = state.lock().await;
    g.watched.remove(profile_id);
    g.failures.remove(profile_id);
    persist(&g.watched)?;
    tracing::info!(profile_id = %profile_id, "auto-reconnect disabled");
    Ok(())
}

pub async fn list_watched() -> Vec<String> {
    let Some(state) = STATE.get() else {
        return Vec::new();
    };
    state
        .lock()
        .await
        .watched
        .values()
        .filter(|w| w.mode == WatchMode::AlwaysOn)
        .map(|w| w.profile_id.clone())
        .collect()
}

/// Watched profiles whose stored args cannot be replayed — enrolled but not
/// yet armed. See `WatchedProfile::is_armed`.
pub async fn list_unarmed() -> Vec<String> {
    let Some(state) = STATE.get() else {
        return Vec::new();
    };
    state
        .lock()
        .await
        .watched
        .values()
        .filter(|w| w.mode == WatchMode::AlwaysOn && !w.is_armed())
        .map(|w| w.profile_id.clone())
        .collect()
}

/// Refresh stored args for a watched profile. Called from connect
/// RPC handlers after success — captures the latest args so
/// auto-reconnect uses fresh credentials.
pub async fn refresh_args(
    profile_id: &str,
    backend: String,
    args: serde_json::Value,
) -> Result<()> {
    validate_enrollment(profile_id, &backend, &args)?;
    let Some(state) = STATE.get() else {
        return Ok(());
    };
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
    // Fresh credentials re-arm any halted auth-failure or backoff window.
    g.failures.remove(profile_id);
    persist(&g.watched)?;
    Ok(())
}

/// Register a manually-connected full-tunnel profile for route-only healing.
/// No-op if the profile is already watched — an explicit Always-on entry has
/// strictly stronger semantics and must win. Called from `vpn_connect` on a
/// successful full-tunnel connect. Held in memory only: manual connections do
/// not outlive the daemon or reboot, and their credentials must never be
/// written to `/var/lib/supermanager/auto_reconnect.json`.
pub async fn guard_routes(
    profile_id: String,
    backend: String,
    args: serde_json::Value,
) -> Result<()> {
    validate_enrollment(&profile_id, &backend, &args)?;
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
    tracing::info!(profile_id = %profile_id, "route-guard enabled in memory (manual full-tunnel connect)");
    Ok(())
}

/// Drop a RouteGuard registration on manual disconnect. Leaves an Always-on
/// entry intact — that's the user's standing intent, not something a single
/// disconnect revokes (matching the pre-existing Always-on contract).
pub async fn unguard_routes(profile_id: &str) -> Result<()> {
    let Some(state) = STATE.get() else {
        return Ok(());
    };
    let mut g = state.lock().await;
    if matches!(
        g.watched.get(profile_id).map(|w| w.mode),
        Some(WatchMode::RouteGuard)
    ) {
        g.watched.remove(profile_id);
        tracing::info!(profile_id = %profile_id, "route-guard removed (manual disconnect)");
    }
    Ok(())
}

/// Only `WatchMode::AlwaysOn` entries are persisted to disk. `RouteGuard`
/// entries belong to transient manual sessions and are never written out.
fn persistable_entries(map: &HashMap<String, WatchedProfile>) -> HashMap<&String, &WatchedProfile> {
    map.iter()
        .filter(|(_, w)| w.mode == WatchMode::AlwaysOn)
        .collect()
}

/// The connect arguments hold the profiles' credentials, so the file is
/// root's alone.
fn persist(map: &HashMap<String, WatchedProfile>) -> Result<()> {
    if let Some(parent) = Path::new(STATE_PATH).parent() {
        fs::create_dir_all(parent).context("creating state dir")?;
    }
    let filtered = persistable_entries(map);
    let json = serde_json::to_string_pretty(&filtered).context("encoding json")?;
    crate::private_file::write(Path::new(STATE_PATH), json.as_bytes())
        .context("writing state file")?;
    Ok(())
}

async fn watchdog_loop(
    state: Arc<Mutex<State>>,
    wg: Arc<Mutex<WireGuard>>,
    ov: Arc<Mutex<OpenVpn>>,
    sw: Arc<Mutex<Strongswan>>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // First tick fires immediately — skip it so we don't probe
    // before the helper has fully started.
    ticker.tick().await;
    loop {
        ticker.tick().await;

        // Tailscale exit-node self-heal. Runs EVERY tick, independent of any
        // enrolled always-on VPN profile (so it must come before the
        // empty-snapshot `continue` below). spawn_blocking because the
        // reconcile does synchronous route/CLI/curl work (up to an ~8s
        // reachability probe) and must not block the async runtime.
        let _ = tokio::task::spawn_blocking(crate::tailscale::reconcile_exit_node).await;

        let snapshot: Vec<WatchedProfile> = {
            let g = state.lock().await;
            g.watched.values().cloned().collect()
        };
        if snapshot.is_empty() {
            continue;
        }
        // Run sequentially so a slow reconnect (>30s) never overlaps with the
        // next tick and tears down a tunnel that just finished connecting.
        for p in snapshot {
            check_and_reconnect(&p, &state, wg.clone(), ov.clone(), sw.clone()).await;
        }
    }
}

async fn check_and_reconnect(
    p: &WatchedProfile,
    state: &Mutex<State>,
    wg: Arc<Mutex<WireGuard>>,
    ov: Arc<Mutex<OpenVpn>>,
    sw: Arc<Mutex<Strongswan>>,
) {
    if !p.is_armed() {
        return;
    }
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
        state.lock().await.failures.remove(&p.profile_id);
        return;
    }

    // RouteGuard (a manually-connected full tunnel) heals ONLY the route-less
    // case: the SA is still ESTABLISHED but its 0/1+128/1 routes vanished.
    // `sw_connected` already returned false above (it counts a route-less full
    // tunnel as not-connected); for RouteGuard we additionally require the SA
    // itself to still be up before replaying. If the SA is genuinely down we do
    // NOTHING — a manually-connected profile stays down until the user
    // reconnects, unlike Always-on which resurrects it here.
    // Re-verify membership, armed state, and backoff/auth-halt under the lock
    // right before replay so disabling a profile while an earlier entry in the
    // tick was connecting never replays a disenrolled profile (`P2-17`).
    let p = {
        let g = state.lock().await;
        let Some(current) = g.watched.get(&p.profile_id).cloned() else {
            return;
        };
        if !current.is_armed()
            || g.should_skip_for_backoff(&current.profile_id, std::time::Instant::now())
        {
            return;
        }
        current
    };

    if p.mode == WatchMode::RouteGuard {
        let sa_up = p.backend == "ikev2" && sw_sa_established(&p, sw.clone()).await;
        if !sa_up {
            // SA is gone: prune the transient RouteGuard entry from memory so
            // its credentials do not linger after the tunnel has closed.
            let mut g = state.lock().await;
            if matches!(
                g.watched.get(&p.profile_id).map(|w| w.mode),
                Some(WatchMode::RouteGuard)
            ) {
                g.watched.remove(&p.profile_id);
                tracing::info!(
                    profile_id = %p.profile_id,
                    "route-guard: SA down — pruned in-memory guard entry"
                );
            }
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
        "wireguard" => replay_wg(&p, wg).await,
        "openvpn" => replay_ov(&p, ov).await,
        "ikev2" => replay_sw(&p, sw).await,
        other => {
            tracing::warn!(backend = %other, "unknown backend in watch list");
            return;
        }
    };
    match result {
        Ok(()) => {
            tracing::info!(
                profile_id = %p.profile_id,
                backend = %p.backend,
                "auto-reconnect succeeded"
            );
            state.lock().await.failures.remove(&p.profile_id);
            events::record(Event::VpnReconnected {
                profile_id: p.profile_id.clone(),
                backend: p.backend.clone(),
                mode: p.mode,
            });
        }
        Err(e) => {
            let err_str = format!("{e:#}");
            let mut g = state.lock().await;
            if !g.watched.contains_key(&p.profile_id) {
                return;
            }
            let failing = g.replay_failed(&p, &err_str);
            let halted = g
                .failures
                .get(&p.profile_id)
                .is_some_and(|rec| rec.auth_failed);
            drop(g);
            if halted {
                tracing::error!(
                    profile_id = %p.profile_id,
                    backend = %p.backend,
                    error = %e,
                    "auto-reconnect halted after authentication failure to prevent account lockout"
                );
            } else {
                tracing::warn!(
                    profile_id = %p.profile_id,
                    backend = %p.backend,
                    error = %e,
                    "auto-reconnect failed; backing off before next retry"
                );
            }
            if let Some(event) = failing {
                events::record(event);
            }
        }
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
        serde_json::from_value(p.last_connect_args.clone()).context("decode wg args")?;
    let mut g = wg.lock().await;
    let res = g.connect(&args).await?;
    if !res.success {
        anyhow::bail!("{}", res.message);
    }
    Ok(())
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
        serde_json::from_value(p.last_connect_args.clone()).context("decode ovpn args")?;
    let mut g = ov.lock().await;
    let res = g.connect(&args).await?;
    if !res.success {
        anyhow::bail!("{}", res.message);
    }
    Ok(())
}

async fn sw_connected(p: &WatchedProfile, sw: Arc<Mutex<Strongswan>>) -> bool {
    let args = crate::strongswan::StatusArgs {
        profile_id: p.profile_id.clone(),
    };
    let status = {
        let mut g = sw.lock().await;
        g.status(&args).await
    };
    let Ok(status) = status else {
        return false;
    };
    if status.state != "connected" {
        return false;
    }
    // Route-aware health: a full-tunnel SA can be ESTABLISHED while its
    // 0/1+128/1 split-defaults were externally flushed, leaving a live-but-
    // routeless tunnel that leaks traffic in cleartext while status reads
    // "connected". Treat that as not-connected so the watchdog replays the
    // connect and re-installs the routes. Only a tunnel the gateway granted
    // everything has those routes: a split tunnel has none, and neither has
    // a full tunnel the gateway narrowed to its own networks, which would
    // otherwise be replayed, and cut, every 30 s.
    if carries_everything(&status.active_routes) && !crate::strongswan::full_tunnel_routes_present()
    {
        tracing::warn!(
            profile = %p.profile_id,
            "auto_reconnect: SA established but full-tunnel routes missing — forcing replay"
        );
        return false;
    }
    true
}

/// Whether the negotiated selectors take all of IPv4 through the tunnel.
fn carries_everything(selectors: &[String]) -> bool {
    selectors.iter().any(|ts| ts == "0.0.0.0/0")
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
        serde_json::from_value(p.last_connect_args.clone()).context("decode ikev2 args")?;
    let mut g = sw.lock().await;
    let res = g.connect(&args).await?;
    if !res.ok {
        anyhow::bail!("{}", res.message);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The route guard wants the 0/1 halves only where the gateway granted
    /// everything: Elteco's gateway, asked for a full tunnel, granted two
    /// networks, and the guard reconnected it every 30 s.
    #[test]
    fn only_a_tunnel_granted_everything_needs_the_halves() {
        assert!(carries_everything(&["0.0.0.0/0".to_owned()]));
        assert!(!carries_everything(&[
            "10.20.3.0/24".to_owned(),
            "10.20.21.0/24".to_owned()
        ]));
        assert!(!carries_everything(&[]));
    }

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

    fn watched(mode: WatchMode, args: serde_json::Value) -> WatchedProfile {
        WatchedProfile {
            profile_id: "p1".into(),
            backend: "wireguard".into(),
            last_connect_args: args,
            mode,
        }
    }

    fn armed_args() -> serde_json::Value {
        serde_json::json!({ "profile_id": "p1", "conf_content": "[Interface]\n" })
    }

    fn attempts(event: Option<Event>) -> Option<u32> {
        event.and_then(|e| match e {
            Event::VpnReconnectFailing { attempts, .. } => Some(attempts),
            _ => None,
        })
    }

    #[test]
    fn a_run_of_failed_replays_is_reported_once_as_it_reaches_the_threshold() {
        let mut state = State::default();
        let p = watched(WatchMode::AlwaysOn, armed_args());

        let reported: Vec<_> = (0..5)
            .map(|_| attempts(state.replay_failed(&p, "handshake timed out")))
            .collect();
        assert_eq!(reported, [None, None, Some(FAILING_AFTER), None, None]);

        // A success (or finding the tunnel up) ends the run; the next run is
        // reported again.
        state.failures.remove(&p.profile_id);
        let reported: Vec<_> = (0..3)
            .map(|_| attempts(state.replay_failed(&p, "handshake timed out")))
            .collect();
        assert_eq!(reported, [None, None, Some(FAILING_AFTER)]);
    }

    #[test]
    fn the_failing_report_carries_the_last_error() {
        let mut state = State::default();
        let p = watched(WatchMode::AlwaysOn, armed_args());
        state.replay_failed(&p, "first");
        state.replay_failed(&p, "second");
        assert_eq!(
            state.replay_failed(&p, "third"),
            Some(Event::VpnReconnectFailing {
                profile_id: "p1".into(),
                backend: "wireguard".into(),
                attempts: FAILING_AFTER,
                error: "third".into(),
            })
        );
    }

    #[test]
    fn only_armed_always_on_profiles_can_be_failing() {
        let mut state = State::default();
        let unarmed = watched(
            WatchMode::AlwaysOn,
            serde_json::json!({ "profile_id": "p1" }),
        );
        let route_guard = watched(WatchMode::RouteGuard, armed_args());
        for _ in 0..FAILING_AFTER * 2 {
            assert_eq!(state.replay_failed(&unarmed, "decode wg args"), None);
            assert_eq!(
                state.replay_failed(&route_guard, "handshake timed out"),
                None
            );
        }
        assert!(state.failures.is_empty());
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

    #[test]
    fn route_guard_entries_are_never_persisted_to_disk() {
        let mut map = HashMap::new();
        map.insert(
            "manual-1".to_owned(),
            WatchedProfile {
                profile_id: "manual-1".into(),
                backend: "ikev2".into(),
                last_connect_args: serde_json::json!({ "password": "secret" }),
                mode: WatchMode::RouteGuard,
            },
        );
        map.insert(
            "always-1".to_owned(),
            WatchedProfile {
                profile_id: "always-1".into(),
                backend: "wireguard".into(),
                last_connect_args: armed_args(),
                mode: WatchMode::AlwaysOn,
            },
        );
        let filtered = persistable_entries(&map);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key(&"always-1".to_owned()));
        assert!(!filtered.contains_key(&"manual-1".to_owned()));
    }

    #[test]
    fn enrollment_validation_enforces_backend_rules_and_rejects_config_file() {
        let uuid = "26b4fcc6-097a-41e7-932e-9a6d2a4663e5";

        // Unarmed placeholders from the GUI before first manual connect are allowed.
        assert!(
            validate_enrollment(uuid, "ikev2", &serde_json::json!({ "profile_id": uuid })).is_ok()
        );
        assert!(validate_enrollment(uuid, "ikev2", &serde_json::json!({})).is_ok());
        assert!(validate_enrollment(uuid, "openvpn", &serde_json::Value::Null).is_ok());

        // Valid inline WireGuard and OpenVPN configs succeed.
        assert!(validate_enrollment(
            uuid,
            "wireguard",
            &serde_json::json!({ "profile_id": uuid, "conf_content": "[Interface]\nAddress = 10.0.0.2/32\n" }),
        )
        .is_ok());
        assert!(validate_enrollment(
            uuid,
            "openvpn",
            &serde_json::json!({ "profile_id": uuid, "config": "client\nremote vpn.example.com 1194\n" }),
        )
        .is_ok());

        // Legacy/file-reading `config_file`, hook-bearing WireGuard configs,
        // script-bearing OpenVPN configs, mismatched profile_ids, and unknown
        // backends are rejected before storage.
        assert!(validate_enrollment(
            uuid,
            "openvpn",
            &serde_json::json!({ "profile_id": uuid, "config_file": "/etc/hosts" }),
        )
        .is_err());
        assert!(validate_enrollment(
            uuid,
            "openvpn",
            &serde_json::json!({ "profile_id": uuid, "config": "client\nup /tmp/evil.sh\n" }),
        )
        .is_err());
        assert!(validate_enrollment(
            uuid,
            "wireguard",
            &serde_json::json!({ "profile_id": uuid, "conf_content": "[Interface]\nPostUp = id\n" }),
        )
        .is_err());
        assert!(validate_enrollment(
            uuid,
            "wireguard",
            &serde_json::json!({ "profile_id": "other", "conf_content": "[Interface]\n" }),
        )
        .is_err());
        assert!(validate_enrollment("../etc/passwd", "ikev2", &serde_json::json!({})).is_err());
        assert!(validate_enrollment(uuid, "tailscale", &serde_json::json!({})).is_err());
    }

    #[test]
    fn persisted_state_never_serializes_connect_args_or_secrets() {
        let mut map = HashMap::new();
        map.insert(
            "p1".to_owned(),
            WatchedProfile {
                profile_id: "p1".into(),
                backend: "ikev2".into(),
                last_connect_args: serde_json::json!({
                    "profile_id": "p1",
                    "password": "super-secret-password",
                    "shared_secret": "top-secret-psk",
                }),
                mode: WatchMode::AlwaysOn,
            },
        );
        let serialized = serde_json::to_string_pretty(&persistable_entries(&map)).unwrap();
        assert!(serialized.contains("\"profile_id\": \"p1\""));
        assert!(!serialized.contains("last_connect_args"));
        assert!(!serialized.contains("super-secret-password"));
        assert!(!serialized.contains("top-secret-psk"));
    }

    #[test]
    fn legacy_json_with_secrets_deserializes_without_retaining_credentials() {
        let legacy = r#"{
            "profile_id": "p1",
            "backend": "wireguard",
            "last_connect_args": {
                "profile_id": "p1",
                "conf_content": "[Interface]\nPrivateKey = SECRETKEY\n"
            }
        }"#;
        let wp: WatchedProfile = serde_json::from_str(legacy).unwrap();
        assert_eq!(wp.mode, WatchMode::AlwaysOn);
        assert!(!wp.is_armed());
        assert_eq!(wp.last_connect_args, serde_json::Value::Null);
    }

    #[test]
    fn exponential_backoff_caps_at_five_minutes_and_auth_failure_halts_immediately() {
        assert_eq!(backoff_duration(1), Duration::from_secs(30));
        assert_eq!(backoff_duration(2), Duration::from_secs(60));
        assert_eq!(backoff_duration(3), Duration::from_secs(120));
        assert_eq!(backoff_duration(4), Duration::from_secs(240));
        assert_eq!(backoff_duration(5), Duration::from_secs(300));
        assert_eq!(backoff_duration(99), Duration::from_secs(300));

        let mut state = State::default();
        let p = watched(WatchMode::AlwaysOn, armed_args());
        let t0 = std::time::Instant::now();

        assert_eq!(state.replay_failed_at(&p, "network unreachable", t0), None);
        assert!(state.should_skip_for_backoff("p1", t0 + Duration::from_secs(29)));
        assert!(!state.should_skip_for_backoff("p1", t0 + Duration::from_secs(31)));

        let mut auth_state = State::default();
        let ev = auth_state.replay_failed_at(&p, "EAP authentication failed: AUTH_FAILED", t0);
        assert_eq!(attempts(ev), Some(1));
        assert!(auth_state.should_skip_for_backoff("p1", t0 + Duration::from_secs(3600)));
    }
}
