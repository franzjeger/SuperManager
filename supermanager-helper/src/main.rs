//! SuperManager privileged helper daemon.
//!
//! ## What this is
//!
//! A small root-owned LaunchDaemon that brokers between the unprivileged
//! SuperManager.app GUI and the system-level VPN machinery (`strongSwan`).
//! macOS gates `NEVPNManager` behind the paid Personal VPN entitlement
//! (`com.apple.developer.networking.vpn.api`); going through Configuration
//! Profiles + the `nesessionmanager` stack means we can never call
//! `connection.startVPNTunnel()` from the app. So instead we follow the
//! Tunnelblick model: we ship our own VPN binary and our own privileged
//! helper that launches it on demand, with utun creation done by strongSwan
//! in kernel-cooperating userspace. No entitlements needed.
//!
//! ## How it's installed
//!
//! The Swift app calls `SMAppService.daemon(plistName:).register()` once.
//! macOS prompts the user to authorize the daemon, copies the plist into
//! the system LaunchDaemons store, and starts our binary as root. After
//! that the helper sticks around for the life of the install.
//!
//! ## Wire protocol
//!
//! Same length-prefixed JSON-RPC framing as the `supermgrd-mac` daemon
//! (`supermgr-engine::server`): 4-byte big-endian length prefix, then a JSON
//! `{ "jsonrpc": "2.0", "method": "...", "params": {...}, "id": <u64> }`
//! object. Responses use the same `Response::ok` / `Response::err` shape.
//! Sticking with this so the Swift `ServiceClient` we already have can talk
//! to either daemon with no protocol-level branching.
//!
//! ## Trust boundary
//!
//! The socket lives at `/var/run/com.sybr.supermanager.helper.sock`,
//! mode 0660, group `admin`. Any admin-group user on the machine can
//! send commands. We do NOT pass arbitrary shell strings into strongSwan
//! — every user-supplied value lands as a typed field in the swanctl
//! config we generate, and we use `tokio::process::Command` with explicit
//! argv (no shell). The credential bytes are written to a 0600 file under
//! `/etc/swanctl/secrets.d/` owned by root.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

mod auto_reconnect;
mod connectivity_watchdog;
mod dns_health_watchdog;
mod kill_switch;
mod openvpn;
// `power` (IOKit system-power monitor) is disabled in dev/ad-hoc builds: it
// links IOKit + CoreFoundation, and a cargo linker-signed ad-hoc signature on
// a framework-linking root daemon is rejected by AMFI (OS_REASON_CODESIGNING).
// Re-enable in the Developer-ID-signed release flow only. See build.rs.
// mod power;
mod route_guardian;
mod strongswan;
mod tailscale;
mod tailscale_state;
mod traffic_capture;
mod wireguard;

/// Bundle of per-backend controllers. Each is a long-lived
/// `tokio::sync::Mutex` so RPC handlers serialize on the same
/// controller without blocking the event loop. Cloning is one
/// `Arc::clone` per field.
#[derive(Clone)]
struct Controllers {
    strongswan: Arc<Mutex<strongswan::Strongswan>>,
    wireguard: Arc<Mutex<wireguard::WireGuard>>,
    openvpn: Arc<Mutex<openvpn::OpenVpn>>,
}

/// Path of the Unix socket we listen on.
const SOCKET_PATH: &str = "/var/run/com.sybr.supermanager.helper.sock";

/// Cap on individual JSON-RPC message size, mirroring `supermgr-engine`.
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct Request {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
    id: u64,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
    id: u64,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl Response {
    fn ok(id: u64, value: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0", result: Some(value), error: None, id }
    }
    fn err(id: u64, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(RpcError { code, message: message.into() }),
            id,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SM_HELPER_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("SuperManager helper starting");

    // Make sure we are root — refuse to start otherwise. Running unprivileged
    // would create a confusing partial-install state where the GUI thinks
    // the helper is up but `swanctl` calls fail with permission errors.
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        anyhow::bail!("supermanager-helper must run as root (got uid={uid})");
    }

    let socket_path = PathBuf::from(SOCKET_PATH);
    // Wipe any stale socket from a crashed previous instance — `bind` would
    // fail otherwise. This is safe: only root can write to /var/run.
    let _ = tokio::fs::remove_file(&socket_path).await;

    // Sweep transient strongSwan configs left behind by a previous helper
    // crash. We own the `supermanager-*` namespace under brew's swanctl
    // dirs, and any leftover file from before this start is a credential
    // we'd rather not have on disk. The next `vpn_connect` regenerates
    // them from scratch.
    strongswan::sweep_stale_configs().await;

    // Spawn the default-route guardian. It lives for the helper's
    // lifetime; on `deploy_self` the new helper instance spawns
    // its own. Idempotent on multiple calls.
    if let Err(e) = route_guardian::spawn_guardian() {
        tracing::warn!("could not spawn route guardian: {e:#}");
    }

    // Spawn the connectivity watchdog — the dead-man switch.
    // Probes internet every 2s, escalates recovery (force route
    // restore at 4s, panic_reset at 6s). Catches anything the
    // route guardian alone can't fix.
    if let Err(e) = connectivity_watchdog::spawn_watchdog() {
        tracing::warn!("could not spawn connectivity watchdog: {e:#}");
    }

    // DNS health watchdog: separate concern from connectivity.
    // Internet (TCP probe) can be fine while DNS is broken (e.g.
    // configd stuck on unreachable IPv6 RA RDNSS while default
    // route works). This watchdog catches that specifically.
    if let Err(e) = dns_health_watchdog::spawn_watchdog() {
        tracing::warn!("could not spawn dns health watchdog: {e:#}");
    }

    // (IOKit power monitor disabled in dev/ad-hoc builds — see `mod power`
    // note above. The wall-clock wake detector below covers the GUI-closed
    // POST-wake case without linking any framework.)

    // Helper-side wake detector — covers the GUI-CLOSED wake case (post-wake
    // cleanup even when the app is closed) without linking any framework.
    //
    // The Swift app fires system_sleep / system_wake from NSWorkspace, but
    // when the app is closed the helper (a LaunchDaemon) gets no such signal.
    // A tunnel left up across sleep then leaves stale full-tunnel routes
    // black-holing traffic on wake, with nothing to clean them.
    //
    // We can't observe *will-sleep* without IOKit, but we can detect that a
    // sleep HAPPENED: tokio's timer runs on the monotonic clock, which does
    // NOT advance while the machine is suspended, whereas the wall clock does.
    // So a `sleep(TICK)` that comes back with a wall-clock delta far exceeding
    // TICK means the machine was suspended in between. On detection we run the
    // same post-wake cleanup as the system_wake RPC — snapshot reset plus the
    // race-guarded stale-config/route sweep (which no-ops if a tunnel
    // auto-reconnected). Pre-sleep teardown for the GUI-closed case still
    // wants IOKit IORegisterForSystemPower; tracked as a follow-up.
    tokio::spawn(async {
        use std::time::{Duration, SystemTime};
        const TICK: Duration = Duration::from_secs(30);
        const SLEEP_THRESHOLD: Duration = Duration::from_secs(60);
        let mut last = SystemTime::now();
        loop {
            tokio::time::sleep(TICK).await;
            let now = SystemTime::now();
            let elapsed = now.duration_since(last).unwrap_or(TICK);
            if elapsed > TICK + SLEEP_THRESHOLD {
                info!(
                    "wake detector: {}s wall-clock jump across a {}s tick — \
                     machine slept; running post-wake cleanup",
                    elapsed.as_secs(),
                    TICK.as_secs()
                );
                // Suspend watchdog escalation for the fragile post-wake settle
                // window (interface reconfig + tailscaled re-handshake + the
                // reconciler's re-install) so accumulated probe misses can't
                // fire panic_reset before the exit node is re-established.
                connectivity_watchdog::pause_for(45);
                route_guardian::reset_snapshot();
                strongswan::sweep_stale_configs().await;
            }
            last = now;
        }
    });

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind {}", socket_path.display()))?;

    // 0660 + group `admin` lets any admin-group user talk to us.
    // chmod first so there is never a window where a non-admin process
    // could connect.
    set_socket_permissions(&socket_path).context("set socket perms")?;

    info!("listening on {}", socket_path.display());

    let controllers = Controllers {
        strongswan: Arc::new(Mutex::new(strongswan::Strongswan::new())),
        wireguard: Arc::new(Mutex::new(wireguard::WireGuard::new())),
        openvpn: Arc::new(Mutex::new(openvpn::OpenVpn::new())),
    };

    // Always-on auto-reconnect watchdog. Reads its persisted
    // watch list from /var/lib/supermanager/auto_reconnect.json
    // and re-establishes connections every 30s for any profile
    // that's down. Survives helper restart (deploy_self / boot)
    // because it's a LaunchDaemon, so this is true always-on
    // (not "always-on while GUI is running").
    if let Err(e) = auto_reconnect::spawn_watchdog(
        controllers.wireguard.clone(),
        controllers.openvpn.clone(),
        controllers.strongswan.clone(),
    )
    .await
    {
        tracing::warn!("could not spawn auto-reconnect watchdog: {e:#}");
    }

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let ctrls = controllers.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, ctrls).await {
                        warn!("client error: {e:#}");
                    }
                });
            }
            Err(e) => {
                error!("accept error: {e}");
            }
        }
    }
}

/// Read the last `want_bytes` of a file. If the file is shorter than that,
/// return the whole thing. Used to surface helper-side diagnostics in the
/// GUI without granting root read access to the log file directly.
async fn tail_file(path: &str, want_bytes: u64) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
    let mut f = tokio::fs::File::open(path).await?;
    let len = f.metadata().await?.len();
    let start = len.saturating_sub(want_bytes);
    f.seek(SeekFrom::Start(start)).await?;
    let mut buf = Vec::with_capacity(want_bytes as usize);
    f.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// `chown :admin` and `chmod 0660` on the socket so admin-group users can
/// connect but everyone else cannot. We deliberately leave it owned by
/// root:admin rather than something narrower because every admin user on
/// the Mac is already trusted to install software (which is what installing
/// SuperManager is).
fn set_socket_permissions(path: &PathBuf) -> anyhow::Result<()> {
    use std::ffi::CString;

    let cpath = CString::new(path.as_os_str().as_encoded_bytes())
        .context("path contains nul byte")?;
    // group "admin" is gid 80 on every Mac since forever, but look it up
    // properly anyway.
    let admin_gid = unsafe {
        let name = CString::new("admin").unwrap();
        let g = libc::getgrnam(name.as_ptr());
        if g.is_null() { 80 } else { (*g).gr_gid }
    };
    let rc = unsafe { libc::chown(cpath.as_ptr(), 0, admin_gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("chown socket");
    }
    let perms = std::fs::Permissions::from_mode(0o660);
    std::fs::set_permissions(path, perms).context("chmod socket")?;
    Ok(())
}

async fn handle_connection(
    mut stream: UnixStream,
    controllers: Controllers,
) -> anyhow::Result<()> {
    debug!("client connected");

    loop {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("client disconnected");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len > MAX_MESSAGE_SIZE {
            warn!("message too large: {msg_len} bytes — dropping connection");
            return Ok(());
        }

        let mut buf = vec![0u8; msg_len];
        stream.read_exact(&mut buf).await?;

        let response = match serde_json::from_slice::<Request>(&buf) {
            Ok(req) => dispatch(req, &controllers).await,
            Err(e) => Response::err(0, -32700, format!("parse error: {e}")),
        };

        let resp_bytes = serde_json::to_vec(&response)?;
        let len = (resp_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&resp_bytes).await?;
    }
}

async fn dispatch(req: Request, controllers: &Controllers) -> Response {
    let strongswan = &controllers.strongswan;
    let wireguard = &controllers.wireguard;
    let openvpn = &controllers.openvpn;
    let id = req.id;
    if req.jsonrpc != "2.0" {
        return Response::err(id, -32600, "expected jsonrpc=2.0");
    }
    debug!(method = %req.method, "dispatch");
    match req.method.as_str() {
        "ping" => Response::ok(id, serde_json::json!({"pong": true, "version": env!("CARGO_PKG_VERSION")})),

        // Dev convenience: exit non-zero so launchd's KeepAlive (Crashed=true)
        // respawns us from the bundle-managed BundleProgram path. This lets
        // us iterate on the helper binary without going through the
        // osascript-with-admin install dance every time. Production builds
        // can keep this — it's harmless and only the registering app can
        // Version + capability probe. Always available regardless
        // of feature flags — the GUI uses this to detect a stale
        // deployed helper (one missing RPCs the new code expects)
        // and auto-redeploy via `deploy_self` before any other
        // call site fails with "unknown method."
        //
        // `methods` is the canonical list this binary knows about.
        // The GUI checks the methods it intends to call against this
        // list rather than assuming a version-number monotonicity —
        // dev branches can ship out of order.
        "helper_version" => {
            let methods = vec![
                "helper_version",
                "restart",
                #[cfg(feature = "dev-rpc")]
                "deploy_self",
                "tail_log",
                "vpn_connect",
                "vpn_disconnect",
                "vpn_status",
                "wg_connect",
                "wg_disconnect",
                "wg_status",
                "ovpn_connect",
                "ovpn_disconnect",
                "ovpn_status",
                "tailscaled_install",
                "tailscaled_uninstall",
                "tailscaled_status",
                "tailscale_panic_reset",
                "tailscale_install_magicdns_resolver",
                "tailscale_install_exit_routes",
                "tailscale_remove_exit_routes",
                "tailscale_test_exit_reachability",
                "tailscale_set_dns_servers",
                "tailscale_force_dns_state",
                "tailscale_set_dns_fallbacks",
                "tailscale_get_dns_fallbacks",
                "tailscale_pause_watchdog",
                "tailscale_resume_watchdog",
                "auto_reconnect_enable",
                "auto_reconnect_disable",
                "auto_reconnect_list",
                "kill_switch_enable",
                "kill_switch_disable",
                "traffic_capture",
                "system_sleep",
                "system_wake",
            ];
            Response::ok(id, serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "build_timestamp": env!("HELPER_BUILD_TIMESTAMP"),
                "methods": methods,
                "dev_rpc": cfg!(feature = "dev-rpc"),
            }))
        }

        // talk to the socket.
        "restart" => {
            // Acknowledge the request before exiting so the client gets a
            // proper response, then schedule the abort.
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                tracing::info!("restart RPC received — exiting non-zero so launchd respawns");
                std::process::exit(1);
            });
            Response::ok(id, serde_json::json!({"restarting": true}))
        }

        // Self-update: copy a user-supplied binary into our system install
        // path and then exit non-zero so launchd's KeepAlive(Crashed=true)
        // respawns from the new binary. The helper runs as root, so the
        // copy works without an extra admin prompt.
        //
        // SECURITY: This is a privilege-escalation vector — any admin-group
        // process (not just SuperManager) that can connect to the socket
        // can swap the root-owned helper binary. We compile it in only
        // when the `dev-rpc` cargo feature is active. Production releases
        // build *without* the feature, so this method returns "unknown
        // method" and admin auth is required to swap the helper. Dev
        // iteration: `cargo build --release -p supermanager-helper --features dev-rpc`.
        #[cfg(feature = "dev-rpc")]
        "deploy_self" => {
            let src = match req.params.get("source").and_then(|v| v.as_str()) {
                Some(s) => s.to_owned(),
                None => return Response::err(id, -32602, "missing param: source"),
            };
            let target = "/Library/PrivilegedHelperTools/com.sybr.supermanager.helper";
            // Quick sanity: the source must exist and be a regular file
            // owned by the calling user (rough check — we trust the
            // socket-level gating above).
            let src_size = match std::fs::metadata(&src) {
                Ok(m) if m.is_file() => m.len(),
                Ok(_) => return Response::err(id, -32602, "source is not a regular file"),
                Err(e) => return Response::err(id, -32602, format!("source missing: {e}")),
            };
            if src_size == 0 {
                return Response::err(id, -32602, "source binary is 0 bytes — refusing");
            }
            // Atomic-rename pattern. The previous code did
            // `fs::copy(src, target)` directly, which opens
            // `target` with O_TRUNC and THEN copies bytes. If the
            // helper exited or crashed during the copy (which is
            // actually likely because we're overwriting the very
            // binary we're running from), the file was left at 0
            // bytes and launchd refused to spawn it (EX_CONFIG=78),
            // killing the entire helper subsystem.
            //
            // Fix: copy to a temp file in the same directory first,
            // verify size, then rename atomically. `rename(2)` is
            // atomic on the same filesystem — the target is either
            // the old binary or the new binary, never half-written.
            let tmp_target = format!("{target}.tmp-{}", std::process::id());
            if let Err(e) = std::fs::copy(&src, &tmp_target) {
                let _ = std::fs::remove_file(&tmp_target);
                return Response::err(id, -32000, format!("copy {src} -> {tmp_target}: {e}"));
            }
            // Sanity-check: the temp file should match src size.
            // Catches partial copies, full disk, etc. before we
            // commit to the rename.
            match std::fs::metadata(&tmp_target) {
                Ok(m) if m.len() == src_size => {}
                Ok(m) => {
                    let _ = std::fs::remove_file(&tmp_target);
                    return Response::err(id, -32000, format!(
                        "size mismatch after copy: src={src_size} tmp={}", m.len()));
                }
                Err(e) => {
                    return Response::err(id, -32000, format!("stat tmp: {e}"));
                }
            }
            // chmod 755 + chown root:wheel on the temp file BEFORE
            // the rename so the active binary always has correct
            // permissions.
            let _ = std::process::Command::new("/bin/chmod")
                .args(["755", &tmp_target])
                .status();
            let _ = std::process::Command::new("/usr/sbin/chown")
                .args(["root:wheel", &tmp_target])
                .status();
            // Atomic rename. If this fails, the existing target is
            // untouched.
            if let Err(e) = std::fs::rename(&tmp_target, target) {
                let _ = std::fs::remove_file(&tmp_target);
                return Response::err(id, -32000, format!("rename to {target}: {e}"));
            }
            tracing::info!("deploy_self: replaced {target} with {src_size} bytes from {src}");
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                tracing::info!("deploy_self complete — exiting so launchd respawns from new binary");
                std::process::exit(1);
            });
            Response::ok(id, serde_json::json!({"deployed": true, "size": src_size}))
        }

        "vpn_connect" => {
            // Capture the raw JSON before consuming `params` so we
            // can refresh auto-reconnect's stored args on success.
            let raw_args = req.params.clone();
            match serde_json::from_value::<strongswan::ConnectArgs>(req.params) {
                Ok(args) => {
                    let pid = args.profile_id.clone();
                    let mut sw = strongswan.lock().await;
                    match sw.connect(&args).await {
                        Ok(s) => {
                            let _ = auto_reconnect::refresh_args(
                                &pid, "ikev2".to_string(), raw_args).await;
                            Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                        }
                        Err(e) => Response::err(id, -32000, format!("connect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "vpn_disconnect" => match serde_json::from_value::<strongswan::DisconnectArgs>(req.params) {
            Ok(args) => {
                let mut sw = strongswan.lock().await;
                match sw.disconnect(&args).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("disconnect failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // Last N bytes of `/var/log/supermanager-helper.log` so the GUI can
        // surface "why did connect fail?" directly instead of telling the
        // user to open Console.app. The helper has open access; the client
        // would need root otherwise.
        //
        // Bounded to 64 KiB max — any single failure's diagnostic context
        // fits there comfortably and we don't want to ship megabytes
        // through the JSON-RPC pipe.
        "tail_log" => {
            const HELPER_LOG: &str = "/var/log/supermanager-helper.log";
            const DEFAULT_BYTES: u64 = 8 * 1024;
            const MAX_BYTES: u64 = 64 * 1024;
            let want = req
                .params
                .get("bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(DEFAULT_BYTES)
                .min(MAX_BYTES);
            match tail_file(HELPER_LOG, want).await {
                Ok(text) => Response::ok(id, serde_json::json!({"log": text})),
                Err(e) => Response::err(id, -32000, format!("tail_log: {e}")),
            }
        }

        "vpn_status" => match serde_json::from_value::<strongswan::StatusArgs>(req.params) {
            Ok(args) => {
                let mut sw = strongswan.lock().await;
                match sw.status(&args).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("status failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // -- WireGuard --

        "wg_connect" => {
            let raw_args = req.params.clone();
            match serde_json::from_value::<wireguard::WgConnectArgs>(req.params) {
                Ok(args) => {
                    let pid = args.profile_id.clone();
                    let mut wg = wireguard.lock().await;
                    match wg.connect(&args).await {
                        Ok(s) => {
                            let _ = auto_reconnect::refresh_args(
                                &pid, "wireguard".to_string(), raw_args).await;
                            Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                        }
                        Err(e) => Response::err(id, -32000, format!("wg_connect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "wg_disconnect" => match serde_json::from_value::<wireguard::WgDisconnectArgs>(req.params) {
            Ok(args) => {
                let mut wg = wireguard.lock().await;
                match wg.disconnect(&args).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("wg_disconnect failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        "wg_status" => match serde_json::from_value::<wireguard::WgStatusArgs>(req.params) {
            Ok(args) => {
                let mut wg = wireguard.lock().await;
                match wg.status(&args).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("wg_status failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // -- OpenVPN --

        "ovpn_connect" => {
            let raw_args = req.params.clone();
            match serde_json::from_value::<openvpn::OvpnConnectArgs>(req.params) {
                Ok(args) => {
                    let pid = args.profile_id.clone();
                    let mut ov = openvpn.lock().await;
                    match ov.connect(&args).await {
                        Ok(s) => {
                            let _ = auto_reconnect::refresh_args(
                                &pid, "openvpn".to_string(), raw_args).await;
                            Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                        }
                        Err(e) => Response::err(id, -32000, format!("ovpn_connect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "ovpn_disconnect" => match serde_json::from_value::<openvpn::OvpnDisconnectArgs>(req.params) {
            Ok(args) => {
                let mut ov = openvpn.lock().await;
                match ov.disconnect(&args).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("ovpn_disconnect failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        "ovpn_status" => match serde_json::from_value::<openvpn::OvpnStatusArgs>(req.params) {
            Ok(args) => {
                let mut ov = openvpn.lock().await;
                match ov.status(&args).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("ovpn_status failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // ----- Tailscale daemon management -----
        // Synchronous (not async) because they shell out to launchctl
        // + write small files; the Tokio runtime is overkill and the
        // calls finish in <100 ms.
        "tailscaled_install" => match serde_json::from_value::<tailscale::InstallArgs>(req.params) {
            Ok(args) => match tailscale::install(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("tailscaled_install failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        "tailscaled_uninstall" => match serde_json::from_value::<tailscale::UninstallArgs>(req.params) {
            Ok(args) => match tailscale::uninstall(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("tailscaled_uninstall failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        "tailscaled_status" => match serde_json::from_value::<tailscale::DaemonStatusArgs>(req.params) {
            Ok(args) => match tailscale::status(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("tailscaled_status failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // Panic-reset: clear exit-node + accept-routes, then renew
        // DHCP on the active interface. Used when an exit-node
        // selection has bricked routing and the user can't reach
        // the internet to even open a browser. Always available;
        // doesn't depend on tailscaled being responsive.
        "tailscale_panic_reset" => match serde_json::from_value::<tailscale::PanicResetArgs>(req.params) {
            Ok(args) => match tailscale::panic_reset(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("tailscale_panic_reset failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // MagicDNS resolver-file backstop. Open-source tailscaled
        // on macOS doesn't install the per-domain nameserver file
        // that NetworkExtension-backed Tailscale.app does. We
        // write it from the helper so MagicDNS names actually
        // resolve through the system resolver. See helper
        // `install_magicdns_resolver` for full reasoning.
        "tailscale_install_magicdns_resolver" => match serde_json::from_value::<tailscale::MagicdnsResolverArgs>(req.params) {
            Ok(args) => match tailscale::install_magicdns_resolver(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("magicdns_resolver failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // Exit-node split-default routes. tailscaled-on-macOS
        // doesn't install these itself — see tailscale.rs for
        // the rant. Caller (AppState.setExitNodeWithSafety)
        // pairs install with the existing internet probe so
        // we can auto-revert if traffic dies.
        "tailscale_install_exit_routes" => match serde_json::from_value::<tailscale::ExitRoutesArgs>(req.params) {
            Ok(args) => match tailscale::install_exit_routes(args) {
                Ok(s) => {
                    // Routes are up — record the user's intent so the reconciler
                    // can re-establish them after sleep/wake or a blip.
                    let (node_id, node_ip) = tailscale::current_exit_node();
                    tailscale_state::set_desired(&node_id, &node_ip);
                    Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                }
                Err(e) => Response::err(id, -32000, format!("install_exit_routes failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        "tailscale_remove_exit_routes" => match serde_json::from_value::<tailscale::ExitRoutesArgs>(req.params) {
            Ok(args) => match tailscale::remove_exit_routes(args) {
                Ok(s) => {
                    // This RPC is the INTENTIONAL clear (user cleared the exit
                    // node) — stop self-heal. The watchdog's blip recovery goes
                    // through panic_reset (clear_pref=false), which does NOT
                    // touch the desired-state, so a transient drop never wipes
                    // intent.
                    tailscale_state::clear_desired();
                    Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                }
                Err(e) => Response::err(id, -32000, format!("remove_exit_routes failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // Pre-flight test for exit-node selection. Installs a
        // single /32 route via tailscaled's utun, probes a known
        // public IP, cleans up. Used by AppState to decide
        // whether the chosen peer actually forwards before
        // committing to full split-default routes.
        "tailscale_test_exit_reachability" => match serde_json::from_value::<tailscale::TestExitArgs>(req.params) {
            Ok(args) => match tailscale::test_exit_reachability(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("test_exit_reachability failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // TEST-ONLY: strip the default route so we can verify
        // the route guardian's recovery in isolation. Available
        // because dev-rpc is on; production builds wouldn't have
        // the rest of dev-rpc either.
        // Set system DNS servers via networksetup. Used to
        // recover when macOS's resolver gets stuck on an
        // unreachable nameserver. Always available — DNS rescue
        // is a baseline capability.
        "tailscale_set_dns_servers" => match serde_json::from_value::<tailscale::SetDnsArgs>(req.params) {
            Ok(args) => match tailscale::set_dns_servers(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("set_dns_servers failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // Forcibly write live DNS state via scutil. Bypasses
        // configd merge logic — for situations where
        // `networksetup` writes to Setup but configd refuses to
        // propagate to State (e.g., a stale IPv6 RA RDNSS
        // nameserver shadowing the manual config).
        "tailscale_force_dns_state" => match serde_json::from_value::<tailscale::SetDnsArgs>(req.params) {
            Ok(args) => match tailscale::force_dns_state(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("force_dns_state failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        // Configure the DNS fallback list used by the DNS health
        // watchdog. Persisted to /var/lib/supermanager/dns_fallbacks.json
        // so a helper restart keeps the user's preference.
        "tailscale_set_dns_fallbacks" => match serde_json::from_value::<tailscale::SetDnsArgs>(req.params) {
            Ok(args) => match dns_health_watchdog::set_fallbacks(args.servers) {
                Ok(_) => Response::ok(id, serde_json::json!({
                    "fallbacks": dns_health_watchdog::current_fallbacks()
                })),
                Err(e) => Response::err(id, -32000, format!("set_dns_fallbacks failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        "tailscale_get_dns_fallbacks" => Response::ok(id, serde_json::json!({
            "fallbacks": dns_health_watchdog::current_fallbacks()
        })),

        // Pause connectivity-watchdog escalation. Critical for
        // exit-node transitions: setting/clearing the pref +
        // installing split-default routes always causes a few
        // seconds of disrupted internet (DNS reconfig, TCP
        // resets), and the watchdog would otherwise panic_reset
        // them mid-flight, undoing the user's selection.
        "tailscale_pause_watchdog" => {
            let secs = req.params.get("seconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(30);
            connectivity_watchdog::pause_for(secs);
            Response::ok(id, serde_json::json!({"paused_seconds": secs}))
        }

        "tailscale_resume_watchdog" => {
            connectivity_watchdog::resume_now();
            Response::ok(id, serde_json::json!({"resumed": true}))
        }

        // Always-on / auto-reconnect for VPN profiles. Helper-side
        // watchdog stores connect args + reconnects on tunnel
        // failure. Persists across helper restarts.
        //
        // Args: { profile_id, backend, connect_args }
        // - backend: "wireguard" | "openvpn" | "ikev2"
        // - connect_args: the same JSON the GUI sends to
        //   wg_connect / ovpn_connect / vpn_connect
        "auto_reconnect_enable" => {
            let profile_id = match req.params.get("profile_id").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => return Response::err(id, -32602, "missing profile_id"),
            };
            let backend = match req.params.get("backend").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => return Response::err(id, -32602, "missing backend"),
            };
            let args = req.params.get("connect_args").cloned()
                .unwrap_or(serde_json::Value::Null);
            match auto_reconnect::enable(profile_id.clone(), backend, args).await {
                Ok(_) => Response::ok(id, serde_json::json!({"enabled": profile_id})),
                Err(e) => Response::err(id, -32000, format!("enable failed: {e:#}")),
            }
        }

        "auto_reconnect_disable" => {
            let profile_id = match req.params.get("profile_id").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => return Response::err(id, -32602, "missing profile_id"),
            };
            match auto_reconnect::disable(&profile_id).await {
                Ok(_) => Response::ok(id, serde_json::json!({"disabled": profile_id})),
                Err(e) => Response::err(id, -32000, format!("disable failed: {e:#}")),
            }
        }

        "auto_reconnect_list" => {
            let watched = auto_reconnect::list_watched().await;
            Response::ok(id, serde_json::json!({"watched": watched}))
        }

        // Kill-switch: install pf rules that block all egress
        // except via the named tunnel interface + LAN. Idempotent.
        "kill_switch_enable" => match serde_json::from_value::<kill_switch::EnableArgs>(req.params) {
            Ok(args) => match kill_switch::enable(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("kill_switch_enable: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        "kill_switch_disable" => match serde_json::from_value::<kill_switch::DisableArgs>(req.params) {
            Ok(args) => match kill_switch::disable(args) {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("kill_switch_disable: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        #[cfg(feature = "dev-rpc")]
        "debug_strip_default_route" => {
            match route_guardian::debug_strip_default_route() {
                Ok(_) => Response::ok(id, serde_json::json!({"stripped": true})),
                Err(e) => Response::err(id, -32000, format!("strip failed: {e:#}")),
            }
        }

        // Passive traffic capture for cleartext-protocol audit.
        // Runs tcpdump as root (the helper's natural privilege)
        // to a caller-specified pcap path inside the user's
        // engagement directory. Tight argument validation: no
        // shell injection, BPF filter length-capped, output path
        // must be under the user's per-engagement captures dir.
        //
        // See `traffic_capture::run` for the full validation
        // logic; the helper just calls into it.
        "traffic_capture" => {
            match traffic_capture::run(req.params).await {
                Ok(report) => Response::ok(id, serde_json::to_value(report).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("traffic_capture: {e:#}")),
            }
        }

        // ── System sleep / wake ──────────────────────────────────────────
        //
        // The Swift app fires these when it receives NSWorkspace
        // willSleepNotification / didWakeNotification.  We use them to:
        //   sleep  — terminate all active IKEv2 SAs + kill ovpncli
        //   wake   — reset route guardian snapshot + sweep stale configs
        //
        // This handles the "lid close / open" failure modes where VPN
        // state becomes stale after sleep and the route guardian's
        // pre-sleep snapshot points at the wrong gateway.
        "system_sleep" => {
            info!("system_sleep: running pre-sleep VPN teardown");
            // Terminate all managed IKEv2 SAs and sweep leftover configs.
            // Belt-and-braces: the Swift layer has already disconnected
            // individual profiles, but this catches anything that slipped
            // through (GUI not open, connect happened from auto-reconnect,
            // etc.). terminate_and_sweep is idempotent — no-op if nothing
            // is active.
            strongswan::terminate_and_sweep().await;

            // SIGTERM any live OpenVPN tunnels we manage. If one outlived a
            // helper restart or the Swift disconnect path didn't fire, it
            // would hold the tunnel open across sleep, leaving macOS with no
            // useful VPN (the physical connection is gone but the process
            // thinks it's still alive). The old `pkill -f ovpncli` was dead
            // code — the spawned binary is `openvpn3`/`openvpn`, never named
            // "ovpncli" — so we kill by tracked pid instead.
            let killed = openvpn::terminate_all().await;
            if killed > 0 {
                info!("system_sleep: terminated {killed} OpenVPN process(es)");
            }

            info!("system_sleep: done");
            Response::ok(id, serde_json::json!({"ok": true}))
        }

        "system_wake" => {
            info!("system_wake: running post-wake cleanup");
            // Suspend watchdog escalation for the post-wake settle window so it
            // can't panic_reset a still-handshaking exit node before the
            // reconciler re-establishes it (same as the helper wake detector).
            connectivity_watchdog::pause_for(45);
            // Clear the route guardian's pre-sleep snapshot. After sleep
            // the machine may be on a completely different network; the
            // old gateway address is likely unreachable. Clearing lets the
            // guardian re-snapshot from the freshly-configured network
            // rather than flooding the routing table with restore attempts.
            route_guardian::reset_snapshot();

            // Sweep any configs charon left behind. This also deletes
            // stale kernel host routes, which prevents "unable to
            // determine source address" errors on the first post-wake
            // connect attempt.
            strongswan::sweep_stale_configs().await;

            info!("system_wake: done");
            Response::ok(id, serde_json::json!({"ok": true}))
        }

        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}
