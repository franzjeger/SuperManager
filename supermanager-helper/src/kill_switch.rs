//! Per-profile VPN kill-switch via macOS' packet filter (`pf`).
//!
//! ## Ownership model
//!
//! The helper owns kill-switch state end-to-end:
//! 1. **Persisted intent (`intents`)**: which `profile_id`s have kill-switch
//!    enabled, saved atomically (`0600`, `O_NOFOLLOW`) in
//!    `/var/lib/supermanager/kill_switch.json`.
//! 2. **Active per-profile leases (`active`)**: each connected profile with
//!    kill-switch enabled registers `(tunnel_interface, endpoints, backend)`
//!    inside the backend's own `connect` path and releases ONLY its own lease
//!    on `disconnect`.
//! 3. **Fail-closed activation**: if `pfctl` cannot install or activate the
//!    anchor rules during `connect`, the backend immediately tears down the
//!    newly created tunnel and fails the connection rather than leaving an
//!    unprotected tunnel up.
//! 4. **Reference-counted `pfctl -E` / `pfctl -X <token>`**: the helper records
//!    the kernel pf reference token returned by `pfctl -E` and releases that
//!    exact token with `pfctl -X` when the last active lease is removed (or on
//!    startup reconciliation when no lease's tunnel interface survived).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::process::Output;
use std::sync::{Mutex, PoisonError};

// Every command here is bounded: see `proc::Bounded`.
use crate::proc::Bounded as Command;

const ANCHOR_NAME: &str = "com.sybr.supermanager.killswitch";
const ANCHOR_FILE: &str = "/etc/pf.anchors/com.sybr.supermanager.killswitch";
const PF_CONF_PATH: &str = "/etc/pf.conf";
const PF_CONF_TMP_PATH: &str = "/etc/pf.conf.supermgr.tmp";
const STATE_PATH: &str = "/var/lib/supermanager/kill_switch.json";
const LEGACY_PROFILE_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Serialize all mutations of persisted kill-switch state, `/etc/pf.conf`, and `pfctl`.
static PF_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchBackend {
    Wireguard,
    Openvpn,
    Ikev2,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveLease {
    pub tunnel_interface: String,
    pub endpoints: Vec<IpAddr>,
    pub backend: KillSwitchBackend,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    #[serde(default)]
    intents: BTreeSet<String>,
    #[serde(default)]
    active: BTreeMap<String, ActiveLease>,
    #[serde(default)]
    pf_token: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct SetIntentArgs {
    pub profile_id: String,
    pub enabled: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct StatusResponse {
    pub intents: Vec<String>,
    pub active: BTreeMap<String, ActiveLease>,
    pub pf_active: bool,
}

#[derive(Deserialize, Debug)]
pub struct EnableArgs {
    #[serde(default)]
    pub profile_id: Option<String>,
    pub tunnel_interface: String,
    #[serde(default)]
    pub allow_ips: Vec<String>,
    #[serde(default)]
    pub backend: Option<KillSwitchBackend>,
}

#[derive(Deserialize, Debug, Default)]
pub struct DisableArgs {
    #[serde(default)]
    pub profile_id: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct Result_ {
    pub success: bool,
    pub message: String,
}

/// Set or clear persisted kill-switch intent for a profile.
///
/// Clearing intent on a currently connected profile immediately removes ONLY
/// that profile's lease from `pf` while preserving any other connected
/// profile's kill-switch rules.
pub fn set_intent(args: SetIntentArgs) -> Result<StatusResponse> {
    let profile_id = validate_profile_id(&args.profile_id)?;
    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut state = load_state(Path::new(STATE_PATH));
    if args.enabled {
        state.intents.insert(profile_id);
        save_state(Path::new(STATE_PATH), &state)?;
    } else {
        state.intents.remove(&profile_id);
        let removed_active = state.active.remove(&profile_id).is_some();
        if removed_active {
            apply_active_leases(&mut state)?;
        }
        save_state(Path::new(STATE_PATH), &state)?;
    }
    Ok(status_from_state(&state))
}

/// Sync an optional `kill_switch` boolean passed alongside a backend `connect` RPC.
pub(crate) fn sync_intent_opt(profile_id: &str, kill_switch: Option<bool>) -> Result<()> {
    let Some(enabled) = kill_switch else {
        return Ok(());
    };
    let _ = set_intent(SetIntentArgs {
        profile_id: profile_id.to_owned(),
        enabled,
    })?;
    Ok(())
}

/// Whether `profile_id` currently has kill-switch intent enabled.
pub(crate) fn has_intent(profile_id: &str) -> bool {
    let Ok(canonical) = validate_profile_id(profile_id) else {
        return false;
    };
    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let state = load_state(Path::new(STATE_PATH));
    state.intents.contains(&canonical)
}

/// Read current kill-switch intents and active per-profile leases.
pub fn status() -> StatusResponse {
    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let state = load_state(Path::new(STATE_PATH));
    status_from_state(&state)
}

/// Activate or update `profile_id`'s kill-switch lease.
///
/// Called by `wireguard`, `openvpn`, and `strongswan` during `connect` whenever
/// `has_intent(profile_id)` is true. Fails closed if `tunnel_interface` is
/// invalid, no gateway outer endpoint could be determined, or `pfctl` fails.
pub(crate) fn activate_for_profile(
    profile_id: &str,
    tunnel_interface: &str,
    mut endpoints: Vec<IpAddr>,
    backend: KillSwitchBackend,
) -> Result<()> {
    let canonical = validate_profile_id(profile_id)?;
    validate_interface(tunnel_interface)?;

    dedup_ips(&mut endpoints);
    if endpoints.is_empty() {
        for auto_ep in discover_physical_host_route_endpoints() {
            if !endpoints.contains(&auto_ep) {
                endpoints.push(auto_ep);
            }
        }
    }
    if endpoints.is_empty() {
        bail!(
            "kill-switch requires at least one resolved gateway endpoint IP for profile {canonical}"
        );
    }

    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut state = load_state(Path::new(STATE_PATH));
    let previous = state.active.insert(
        canonical.clone(),
        ActiveLease {
            tunnel_interface: tunnel_interface.to_owned(),
            endpoints,
            backend,
        },
    );

    if let Err(err) = apply_active_leases(&mut state) {
        match previous {
            Some(old) => {
                state.active.insert(canonical, old);
            }
            None => {
                state.active.remove(&canonical);
            }
        }
        let _ = apply_active_leases(&mut state);
        let _ = save_state(Path::new(STATE_PATH), &state);
        return Err(err);
    }

    save_state(Path::new(STATE_PATH), &state)?;
    tracing::info!(
        profile = %canonical,
        iface = %tunnel_interface,
        ?backend,
        "kill-switch lease activated"
    );
    Ok(())
}

/// Remove ONLY `profile_id`'s active kill-switch lease while keeping its
/// persisted `intent` for future connects and preserving all other profiles'
/// active leases.
pub(crate) fn deactivate_for_profile(profile_id: &str) -> Result<()> {
    let canonical = validate_profile_id(profile_id)?;
    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut state = load_state(Path::new(STATE_PATH));
    if state.active.remove(&canonical).is_some() {
        apply_active_leases(&mut state)?;
        save_state(Path::new(STATE_PATH), &state)?;
        tracing::info!(profile = %canonical, "kill-switch lease released");
    }
    Ok(())
}

/// Release all active leases owned by `backend` (used by `system_sleep` bulk
/// backend teardowns such as `strongswan::terminate_and_sweep` and
/// `openvpn::terminate_all`).
pub(crate) fn deactivate_backend(backend: KillSwitchBackend) {
    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut state = load_state(Path::new(STATE_PATH));
    let before = state.active.len();
    state.active.retain(|_, lease| lease.backend != backend);
    if state.active.len() != before {
        if let Err(e) = apply_active_leases(&mut state) {
            tracing::warn!(?backend, "kill-switch backend teardown failed: {e:#}");
        }
        if let Err(e) = save_state(Path::new(STATE_PATH), &state) {
            tracing::warn!(?backend, "kill-switch state save failed: {e:#}");
        }
    }
}

/// Reconcile persisted kill-switch state on helper startup.
///
/// Prunes leases whose `utun` interface disappeared (e.g. across a reboot) and
/// either reloads the anchor for surviving live tunnels or tears down any
/// leftover `/etc/pf.conf` anchor reference and releases the stored `pfctl -E`
/// token.
pub fn reconcile_on_startup() {
    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut state = load_state(Path::new(STATE_PATH));
    state.active.retain(|profile_id, lease| {
        let alive = validate_interface(&lease.tunnel_interface).is_ok()
            && interface_is_up(&lease.tunnel_interface)
            && crate::tailscale::utun_has_live_owner(&lease.tunnel_interface);
        if !alive {
            tracing::info!(
                profile = %profile_id,
                iface = %lease.tunnel_interface,
                "kill-switch startup reconcile: dropping stale lease"
            );
        }
        alive
    });

    // Even when `state.active` was already empty on disk, clean up any orphaned
    // anchor file or /etc/pf.conf referrer left by an unclean shutdown.
    if let Err(e) = apply_active_leases(&mut state) {
        tracing::warn!("kill-switch startup reconcile failed: {e:#}");
    }
    if let Err(e) = save_state(Path::new(STATE_PATH), &state) {
        tracing::warn!("kill-switch startup state write failed: {e:#}");
    }
}

/// Backward-compatible direct enable RPC.
pub fn enable(args: EnableArgs) -> Result<Result_> {
    let pid = match args.profile_id.as_deref() {
        Some(raw) if !raw.trim().is_empty() => validate_profile_id(raw)?,
        _ => LEGACY_PROFILE_ID.to_owned(),
    };
    let endpoints = validate_endpoints(&args.allow_ips)?;
    let backend = args.backend.unwrap_or(KillSwitchBackend::Wireguard);
    activate_for_profile(&pid, &args.tunnel_interface, endpoints, backend)?;
    Ok(Result_ {
        success: true,
        message: format!("Kill-switch active on {}", args.tunnel_interface),
    })
}

/// Backward-compatible disable RPC (per-profile when `profile_id` is supplied,
/// or all active leases when omitted).
pub fn disable(args: DisableArgs) -> Result<Result_> {
    if let Some(raw) = args.profile_id.as_deref().filter(|s| !s.trim().is_empty()) {
        deactivate_for_profile(raw)?;
        return Ok(Result_ {
            success: true,
            message: "Kill-switch lease removed for profile".to_owned(),
        });
    }
    let _guard = PF_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let mut state = load_state(Path::new(STATE_PATH));
    state.active.clear();
    apply_active_leases(&mut state)?;
    save_state(Path::new(STATE_PATH), &state)?;
    Ok(Result_ {
        success: true,
        message: "Kill-switch removed".to_owned(),
    })
}

/// Resolve a `host` or `host:port` endpoint string into concrete IP addresses
/// before `pf` restricts DNS or physical egress.
pub(crate) fn resolve_endpoint_host(host_or_authority: &str, default_port: u16) -> Vec<IpAddr> {
    let trimmed = host_or_authority.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let host_only = extract_host_part(trimmed);
    if let Ok(ip) = host_only.parse::<IpAddr>() {
        return vec![ip];
    }
    let mut out = Vec::new();
    if let Ok(addrs) = (host_only, default_port).to_socket_addrs() {
        for sa in addrs {
            let ip = sa.ip();
            if !ip.is_loopback() && !ip.is_unspecified() && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Parse and resolve all `Endpoint = ...` lines in a WireGuard config.
pub(crate) fn resolve_wireguard_endpoints(conf: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in conf.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if !k.trim().eq_ignore_ascii_case("Endpoint") {
            continue;
        }
        for ip in resolve_endpoint_host(v.trim(), 51820) {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Parse and resolve all `remote <host> [port] [proto]` directives in an OpenVPN config.
pub(crate) fn resolve_openvpn_endpoints(conf: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in conf.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        if parts.next() != Some("remote") {
            continue;
        }
        let Some(host) = parts.next() else {
            continue;
        };
        let port = parts
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(1194);
        for ip in resolve_endpoint_host(host, port) {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

fn extract_host_part(input: &str) -> &str {
    if let Some(rest) = input.strip_prefix('[') {
        if let Some((v6, _)) = rest.split_once(']') {
            return v6;
        }
    }
    // Single colon = host:port; multiple colons = bare IPv6 literal.
    if input.bytes().filter(|&b| b == b':').count() == 1 {
        if let Some((host, _port)) = input.rsplit_once(':') {
            return host;
        }
    }
    input
}

fn status_from_state(state: &PersistedState) -> StatusResponse {
    StatusResponse {
        intents: state.intents.iter().cloned().collect(),
        active: state.active.clone(),
        pf_active: !state.active.is_empty(),
    }
}

fn apply_active_leases(state: &mut PersistedState) -> Result<()> {
    if state.active.is_empty() {
        let _ = Command::new("/sbin/pfctl")
            .args(["-a", ANCHOR_NAME, "-F", "all"])
            .output();
        let _ = fs::remove_file(ANCHOR_FILE);
        remove_referrer_if_present()?;
        if let Some(token) = state.pf_token.take() {
            if is_valid_pf_token(&token) {
                let _ = Command::new("/sbin/pfctl").args(["-X", &token]).output();
            }
        }
        return Ok(());
    }

    let tailscale_utun = crate::tailscale::detect_tailscale_utun()
        .filter(|u| validate_interface(u).is_ok());
    let rules = build_anchor_rules(&state.active, tailscale_utun.as_deref())?;

    if let Some(parent) = Path::new(ANCHOR_FILE).parent() {
        fs::create_dir_all(parent).context("creating /etc/pf.anchors")?;
    }
    atomic_write_file(Path::new(ANCHOR_FILE), rules.as_bytes(), 0o644)
        .context("writing anchor file")?;

    // Acquire a pf reference token once for our active lifetime; release it via
    // `pfctl -X <token>` when `state.active` drains back to empty.
    let need_enable = state.pf_token.is_none() || !pf_is_enabled();
    if need_enable {
        let out = checked_pfctl_output(Command::new("/sbin/pfctl").arg("-E").output(), "enable pf")?;
        if let Some(tok) = parse_pf_token(&out.stderr).or_else(|| parse_pf_token(&out.stdout)) {
            if let Some(old) = state.pf_token.replace(tok) {
                if is_valid_pf_token(&old) {
                    let _ = Command::new("/sbin/pfctl").args(["-X", &old]).output();
                }
            }
        }
    }

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

    install_referrer_if_missing()?;
    Ok(())
}

/// Build the pf anchor rules across all currently active profile leases.
///
/// Security invariants (`P2-4`):
/// - Never allows cleartext RFC1918 (`10/8`, `172.16/12`, `192.168/16`) on
///   physical interfaces: internal VPN subnets live in RFC1918 and must only
///   traverse their `utun<N>` interface.
/// - Never allows wildcard UDP `500/4500` or wildcard `esp` to `any`: IKE/ESP
///   is permitted strictly to/from the `Ikev2` lease's resolved gateway IP(s).
/// - Tailscale allowance (`utun` + root-owned UDP `41641`) is emitted only when
///   `tailscaled` is actively running with a verified `utun`.
fn build_anchor_rules(
    active: &BTreeMap<String, ActiveLease>,
    tailscale_utun: Option<&str>,
) -> Result<String> {
    let mut tunnel_rules = String::new();
    let mut endpoint_rules = String::new();
    let mut seen_ifaces = BTreeSet::new();

    for lease in active.values() {
        validate_interface(&lease.tunnel_interface)?;
        if seen_ifaces.insert(lease.tunnel_interface.as_str()) {
            let _ = writeln!(tunnel_rules, "pass quick on {} all", lease.tunnel_interface);
        }
        for &ip in &lease.endpoints {
            let af = match ip {
                IpAddr::V4(_) => "inet",
                IpAddr::V6(_) => "inet6",
            };
            match lease.backend {
                KillSwitchBackend::Ikev2 => {
                    let _ = writeln!(
                        endpoint_rules,
                        "pass out quick {af} proto udp from any to {ip} port {{ 500, 4500 }}"
                    );
                    let _ = writeln!(
                        endpoint_rules,
                        "pass in quick {af} proto udp from {ip} port {{ 500, 4500 }} to any"
                    );
                    let _ = writeln!(endpoint_rules, "pass quick {af} proto esp from any to {ip}");
                    let _ = writeln!(endpoint_rules, "pass quick {af} proto esp from {ip} to any");
                }
                KillSwitchBackend::Wireguard | KillSwitchBackend::Openvpn => {
                    let _ = writeln!(endpoint_rules, "pass out quick {af} from any to {ip}");
                    let _ = writeln!(endpoint_rules, "pass in quick {af} from {ip} to any");
                }
            }
        }
    }

    let mut tailscale_rules = String::new();
    if let Some(ts_iface) = tailscale_utun {
        validate_interface(ts_iface)?;
        if !seen_ifaces.contains(ts_iface) {
            let _ = writeln!(tailscale_rules, "pass quick on {ts_iface} all");
        }
        let _ = writeln!(
            tailscale_rules,
            "pass out quick proto udp from any to any port 41641 user = 0"
        );
    }

    Ok(format!(
        "# SuperManager kill-switch anchor
# Managed by supermanager-helper. Do not edit by hand.

# Loopback.
pass quick on lo0 all

# Active VPN tunnel interface(s).
{tunnel_rules}
# Outer encrypted transport strictly to/from pinned VPN gateway endpoint(s).
{endpoint_rules}
# Link-layer lease & neighbor maintenance (DHCPv4, DHCPv6, IPv6 ND).
pass out quick inet proto udp from any port 68 to any port 67
pass in quick inet proto udp from any port 67 to any port 68
pass quick inet6 proto ipv6-icmp from any to any icmp6-type {{ 133, 134, 135, 136 }}
pass quick inet6 proto udp from fe80::/10 port 546 to {{ fe80::/10, ff02::1:2 }} port 547
pass quick inet6 proto udp from fe80::/10 port 547 to fe80::/10 port 546
{tailscale_rules}
# Fail closed on everything else.
block return out all
block return in all
"
    ))
}

fn parse_pf_token(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    for line in text.lines() {
        if let Some((_, rhs)) = line.split_once("Token") {
            let tok = rhs.trim().trim_start_matches(':').trim();
            if is_valid_pf_token(tok) {
                return Some(tok.to_owned());
            }
        }
    }
    None
}

fn is_valid_pf_token(tok: &str) -> bool {
    !tok.is_empty() && tok.len() <= 64 && tok.bytes().all(|b| b.is_ascii_digit())
}

fn pf_is_enabled() -> bool {
    let Ok(out) = Command::new("/sbin/pfctl").args(["-s", "info"]).output() else {
        return false;
    };
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    text.lines()
        .any(|l| l.trim_start().starts_with("Status: Enabled"))
}

fn interface_is_up(iface: &str) -> bool {
    let Ok(out) = Command::new("/sbin/ifconfig").arg(iface).output() else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.contains("<UP,") || stdout.contains(",UP,") || stdout.contains(",UP>")
}

fn load_state(path: &Path) -> PersistedState {
    let Ok(bytes) = fs::read(path) else {
        return PersistedState::default();
    };
    match serde_json::from_slice::<PersistedState>(&bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("kill-switch state {} unreadable ({e}); starting empty", path.display());
            PersistedState::default()
        }
    }
}

fn save_state(path: &Path, state: &PersistedState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(state).context("serializing kill-switch state")?;
    atomic_write_file(path, &body, 0o600)
        .with_context(|| format!("writing {}", path.display()))
}

fn install_referrer_if_missing() -> Result<()> {
    let current = Command::new("/sbin/pfctl")
        .args(["-sr"])
        .output()
        .context("pfctl -sr")?;
    let current = checked_pfctl_output(Ok(current), "read pf rules")?;
    let stdout = String::from_utf8_lossy(&current.stdout);
    if stdout.contains(&format!("anchor \"{ANCHOR_NAME}\"")) {
        return Ok(());
    }
    let body = fs::read_to_string(PF_CONF_PATH).context("reading /etc/pf.conf")?;
    let line = format!(
        "\nanchor \"{ANCHOR_NAME}\"\nload anchor \"{ANCHOR_NAME}\" from \"{ANCHOR_FILE}\"\n"
    );
    if !body.contains(&format!("anchor \"{ANCHOR_NAME}\"")) {
        let new_body = format!("{body}{line}");
        atomic_write_pf_conf(&new_body)?;
    }
    checked_pfctl_output(
        Command::new("/sbin/pfctl").args(["-f", PF_CONF_PATH]).output(),
        "activate kill-switch anchor reference",
    )?;
    Ok(())
}

fn remove_referrer_if_present() -> Result<()> {
    let body = match fs::read_to_string(PF_CONF_PATH) {
        Ok(b) => b,
        Err(_) => return Ok(()),
    };
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

fn validate_profile_id(id: &str) -> Result<String> {
    let parsed = uuid::Uuid::try_parse(id.trim())
        .map_err(|_| anyhow::anyhow!("invalid profile_id: expected a canonical UUID"))?;
    Ok(parsed.hyphenated().to_string())
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

fn dedup_ips(ips: &mut Vec<IpAddr>) {
    let mut seen = Vec::with_capacity(ips.len());
    for ip in ips.drain(..) {
        if !ip.is_loopback() && !ip.is_unspecified() && !seen.contains(&ip) {
            seen.push(ip);
        }
    }
    *ips = seen;
}

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

fn validate_interface(iface: &str) -> Result<()> {
    let Some(index) = iface.strip_prefix("utun") else {
        bail!("invalid tunnel_interface — expected utun<N>");
    };
    if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid tunnel_interface — expected utun<N>");
    }
    Ok(())
}

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
    use std::process::Stdio;

    fn assert_pfctl_parses(rules: &str) {
        if !Path::new("/sbin/pfctl").exists() {
            return;
        }
        let mut child = std::process::Command::new("/sbin/pfctl")
            .args(["-nf", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn pfctl -nf -");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(rules.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait pfctl");
        assert!(
            out.status.success(),
            "pfctl rejected generated rules:\n{rules}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

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
    fn rules_scope_ike_and_esp_to_gateway_and_omit_rfc1918_and_tailscale_when_absent() {
        let mut active = BTreeMap::new();
        active.insert(
            "11111111-1111-1111-1111-111111111111".to_owned(),
            ActiveLease {
                tunnel_interface: "utun7".to_owned(),
                endpoints: vec!["51.174.175.4".parse().unwrap()],
                backend: KillSwitchBackend::Ikev2,
            },
        );
        active.insert(
            "22222222-2222-2222-2222-222222222222".to_owned(),
            ActiveLease {
                tunnel_interface: "utun9".to_owned(),
                endpoints: vec![
                    "198.51.100.10".parse().unwrap(),
                    "2001:db8::42".parse().unwrap(),
                ],
                backend: KillSwitchBackend::Wireguard,
            },
        );

        let rules = build_anchor_rules(&active, None).expect("rules");
        assert_pfctl_parses(&rules);

        assert!(rules.contains("pass quick on utun7 all"));
        assert!(rules.contains("pass quick on utun9 all"));
        assert!(rules.contains("pass out quick inet proto udp from any to 51.174.175.4 port { 500, 4500 }"));
        assert!(rules.contains("pass quick inet proto esp from any to 51.174.175.4"));
        assert!(rules.contains("pass out quick inet from any to 198.51.100.10"));
        assert!(rules.contains("pass out quick inet6 from any to 2001:db8::42"));

        // Must NEVER allow wildcard IKE, wildcard ESP, cleartext RFC1918, or Tailscale when absent.
        assert!(!rules.contains("to any port { 500, 4500 }"));
        assert!(!rules.contains("proto esp all"));
        assert!(!rules.contains("10.0.0.0/8"));
        assert!(!rules.contains("172.16.0.0/12"));
        assert!(!rules.contains("192.168.0.0/16"));
        assert!(!rules.contains("41641"));

        let with_ts = build_anchor_rules(&active, Some("utun4")).expect("rules with tailscale");
        assert_pfctl_parses(&with_ts);
        assert!(with_ts.contains("pass quick on utun4 all"));
        assert!(with_ts.contains("port 41641 user = 0"));
    }

    #[test]
    fn parses_pfctl_enable_token() {
        let stderr = b"No ALTQ support in kernel\nToken : 1384729384729384729\npf enabled\n";
        assert_eq!(
            parse_pf_token(stderr).as_deref(),
            Some("1384729384729384729")
        );
        assert_eq!(parse_pf_token(b"Token : not-a-number\n"), None);
    }

    #[test]
    fn state_persists_intents_and_leases_per_profile() {
        let dir = std::env::temp_dir().join(format!(
            "sm-ks-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kill_switch.json");
        let p1 = "11111111-1111-1111-1111-111111111111".to_owned();
        let p2 = "22222222-2222-2222-2222-222222222222".to_owned();

        let mut state = PersistedState::default();
        state.intents.insert(p1.clone());
        state.intents.insert(p2.clone());
        state.pf_token = Some("987654321".to_owned());
        state.active.insert(
            p1.clone(),
            ActiveLease {
                tunnel_interface: "utun5".to_owned(),
                endpoints: vec!["203.0.113.5".parse().unwrap()],
                backend: KillSwitchBackend::Openvpn,
            },
        );
        save_state(&path, &state).unwrap();

        let loaded = load_state(&path);
        assert!(loaded.intents.contains(&p1));
        assert!(loaded.intents.contains(&p2));
        assert_eq!(loaded.pf_token.as_deref(), Some("987654321"));
        assert_eq!(loaded.active.len(), 1);
        assert_eq!(loaded.active[&p1].tunnel_interface, "utun5");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn endpoint_parsers_extract_wireguard_and_openvpn_literals() {
        let wg = "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = 198.51.100.7:51820\nEndpoint = [2001:db8::9]:51820\n";
        assert_eq!(
            resolve_wireguard_endpoints(wg),
            vec![
                "198.51.100.7".parse::<IpAddr>().unwrap(),
                "2001:db8::9".parse::<IpAddr>().unwrap(),
            ]
        );

        let ovpn = "# comment\nremote 203.0.113.44 1194 udp\n;remote 192.0.2.1 443\n";
        assert_eq!(
            resolve_openvpn_endpoints(ovpn),
            vec!["203.0.113.44".parse::<IpAddr>().unwrap()]
        );
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
