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
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

mod auto_reconnect;
mod client_auth;
mod connectivity_watchdog;
mod dns;
mod dns_health_watchdog;
mod events;
mod kill_switch;
mod openvpn;
mod openvpn_config;
mod private_file;
mod proc;
// `power` (IOKit system-power monitor) is disabled in dev/ad-hoc builds: it
// links IOKit + CoreFoundation, and a cargo linker-signed ad-hoc signature on
// a framework-linking root daemon is rejected by AMFI (OS_REASON_CODESIGNING).
// Re-enable in the Developer-ID-signed release flow only. See build.rs.
// mod power;
mod route_guardian;
mod strongswan;
mod tailscale;
mod tailscale_state;
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
        Self {
            jsonrpc: "2.0",
            result: Some(value),
            error: None,
            id,
        }
    }
    fn err(id: u64, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
            id,
        }
    }
}

/// The CLI and RPC must describe the same build and capabilities so the
/// GUI can verify the running helper against the bundled executable.
fn helper_version_info() -> serde_json::Value {
    let methods = vec![
        "helper_version",
        "restart",
        "tail_log",
        "events_since",
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
        "system_sleep",
        "system_wake",
    ];
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build_timestamp": env!("HELPER_BUILD_TIMESTAMP"),
        "methods": methods,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SM_HELPER_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        // launchd writes stdout to /var/log/supermanager-helper.log, which
        // the app shows in its log viewer, after a failed connect and in
        // support bundles. Colour codes there are just `[2m…[0m` noise, so
        // colour only a terminal: the helper run by hand.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();

    // `--version` lets a binary that is NOT running answer for itself.
    //
    // The GUI needs the bundled helper's build timestamp to decide
    // whether deploying it over the live one is an upgrade or a
    // downgrade. It cannot ask over the socket — the bundled copy has
    // no socket; only the deployed one does. Reading the timestamp out
    // of the file with `strings` would work until the day it doesn't,
    // so the binary reports its own vintage instead.
    //
    // Deliberately before the root check and before any daemon setup:
    // this prints and exits, needs no privileges, and must stay cheap
    // enough to call on every launch.
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("{}", helper_version_info());
        return Ok(());
    }

    // Boot-time DNS cleanup subcommand.
    //
    // The LaunchDaemon `no.sybr.supermanager.vpn-dns-cleanup` runs this
    // binary at boot with `vpn-dns-cleanup` as the first argument. We
    // perform the cleanup and exit immediately — we do NOT start the
    // full daemon socket loop. This is intentional: the plist has
    // `KeepAlive false`, so launchd expects a short-lived process.
    if std::env::args().nth(1).as_deref() == Some("vpn-dns-cleanup") {
        info!("vpn-dns-cleanup: boot-time DNS teardown guard starting");
        let uid = unsafe { libc::geteuid() };
        if uid != 0 {
            anyhow::bail!("vpn-dns-cleanup must run as root (got uid={uid})");
        }
        dns::clear_vpn_dns();
        info!("vpn-dns-cleanup: done");
        return Ok(());
    }

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
    openvpn::sweep_legacy_logs();

    // Spawn the default-route guardian. It lives for the helper's
    // lifetime; a restarted helper spawns its own. Idempotent on
    // multiple calls.
    if let Err(e) = route_guardian::spawn_guardian() {
        tracing::warn!("could not spawn route guardian: {e:#}");
    }

    // Bring an already-installed tailscaled LaunchDaemon up to date
    // with our plist template. No-op unless the template changed (or
    // Tailscale isn't installed), so this costs one file read at
    // startup on the common path.
    tailscale::ensure_plist_current();

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
                // Don't wait up to 30s for the auto_reconnect tick to heal a
                // desired exit node — this is the GUI-closed wake case, so
                // there is no Swift-side system_wake RPC coming either.
                tailscale::schedule_wake_reconcile();
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

    // Who may connect depends on how this helper is signed; see client_auth.
    let client_policy = client_auth::own_policy();
    info!(?client_policy, "only SuperManager may use this helper");

    let controllers = Controllers {
        strongswan: Arc::new(Mutex::new(strongswan::Strongswan::new())),
        wireguard: Arc::new(Mutex::new(wireguard::WireGuard::new())),
        openvpn: Arc::new(Mutex::new(openvpn::OpenVpn::new())),
    };

    // Always-on auto-reconnect watchdog. Reads its persisted
    // watch list from /var/lib/supermanager/auto_reconnect.json
    // and re-establishes connections every 30s for any profile
    // that's down. Survives a helper restart or reboot
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
                    if let Err(refusal) = client_auth::authorize(&stream, client_policy).await {
                        warn!("refused a client: {refusal}");
                        refuse(stream, &refusal).await;
                        return;
                    }
                    if let Err(e) = handle_connection(stream, ctrls).await {
                        warn!("client error: {e:#}");
                    }
                });
            }
            Err(e) => {
                // EMFILE and friends return at once with the listener still
                // readable; without a pause this loop spins a core and floods
                // the log until a descriptor frees up.
                error!("accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
    }
}

/// Tell a refused client why, then hang up. Nothing it sent has been read.
async fn refuse(mut stream: UnixStream, refusal: &client_auth::Refusal) {
    let response = Response::err(0, -32001, format!("refused: {refusal}"));
    let Ok(body) = serde_json::to_vec(&response) else {
        return;
    };
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes();
    let _ = stream.write_all(&len).await;
    let _ = stream.write_all(&body).await;
}

/// Read the last `want_bytes` of a file. If the file is shorter than that,
/// return the whole thing. Used to surface helper-side diagnostics in the
/// GUI without granting root read access to the log file directly.
async fn tail_file(path: &std::path::Path, want_bytes: u64) -> anyhow::Result<String> {
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

    let cpath =
        CString::new(path.as_os_str().as_encoded_bytes()).context("path contains nul byte")?;
    // group "admin" is gid 80 on every Mac since forever, but look it up
    // properly anyway.
    let admin_gid = unsafe {
        let name = CString::new("admin").unwrap();
        let g = libc::getgrnam(name.as_ptr());
        if g.is_null() {
            80
        } else {
            (*g).gr_gid
        }
    };
    let rc = unsafe { libc::chown(cpath.as_ptr(), 0, admin_gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("chown socket");
    }
    let perms = std::fs::Permissions::from_mode(0o660);
    std::fs::set_permissions(path, perms).context("chmod socket")?;
    Ok(())
}

async fn handle_connection(mut stream: UnixStream, controllers: Controllers) -> anyhow::Result<()> {
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
            Ok(req) if is_read_only(&req.method) => {
                tokio::select! {
                    response = dispatch(req, &controllers) => response,
                    () = client_gone(&stream) => {
                        debug!("client hung up; dropping read-only request");
                        return Ok(());
                    }
                }
            }
            Ok(req) => dispatch(req, &controllers).await,
            Err(e) => Response::err(0, -32700, format!("parse error: {e}")),
        };

        let resp_bytes = serde_json::to_vec(&response)?;
        let len = (resp_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&resp_bytes).await?;
    }
}

/// Methods that only read state. The app gives up on an RPC at its deadline
/// and polls again; a read that is still queued (typically behind a backend
/// mutex held by a slow connect) then has nobody to answer, and it used to
/// hold its connection and file descriptor until the mutex freed — without
/// limit while charon was wedged, until `accept()` hit EMFILE. Anything that
/// changes state runs to completion regardless.
fn is_read_only(method: &str) -> bool {
    matches!(
        method,
        "ping"
            | "helper_version"
            | "tail_log"
            | "events_since"
            | "vpn_status"
            | "wg_status"
            | "ovpn_status"
            | "tailscaled_status"
            | "tailscale_get_dns_fallbacks"
            | "auto_reconnect_list"
    )
}

/// Resolves once the client has closed its end. HelperClient sends one
/// request per connection and then only reads, so EOF means the caller is
/// gone. Peeks, so a pipelined request stays in the socket for the next turn.
async fn client_gone(stream: &UnixStream) {
    let mut probe = [0u8; 1];
    loop {
        if stream.readable().await.is_err() {
            return;
        }
        let peeked = stream.try_io(tokio::io::Interest::READABLE, || {
            // SAFETY: `stream` owns a valid fd; the buffer is one byte long.
            let n = unsafe {
                libc::recv(
                    stream.as_raw_fd(),
                    probe.as_mut_ptr().cast(),
                    1,
                    libc::MSG_PEEK,
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n)
            }
        });
        match peeked {
            Ok(0) => return,
            // More bytes: the client is still there. Nothing to watch for.
            Ok(_) => std::future::pending::<()>().await,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return,
        }
    }
}

/// Run a synchronous handler on tokio's blocking pool. These handlers shell
/// out — bounded, but for up to a minute (`launchctl bootstrap`, a DHCP
/// renew) — and run inline they each pin an async worker. A few of them in
/// flight and nothing is left to answer even `ping`, which the app then
/// reads as a dead helper.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(value) => value,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
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
        "ping" => Response::ok(
            id,
            serde_json::json!({"pong": true, "version": env!("CARGO_PKG_VERSION")}),
        ),

        // Version + capability probe. The GUI compares it with the
        // helper bundled in the app and reinstalls a helper that
        // differs, before any other call site fails with "unknown
        // method."
        //
        // `methods` is the canonical list this binary knows about.
        // The GUI checks the methods it intends to call against this
        // list rather than assuming a version-number monotonicity —
        // dev branches can ship out of order.
        "helper_version" => Response::ok(id, helper_version_info()),

        // Exit non-zero so launchd's KeepAlive (Crashed=true) respawns us
        // from the installed binary.
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
                                &pid,
                                "ikev2".to_string(),
                                raw_args.clone(),
                            )
                            .await;
                            // A manual full-tunnel connect enrols the profile for
                            // route-only healing (no-op if it's already Always-on).
                            // Split tunnels install no 0/1, so nothing to guard,
                            // and neither does a full tunnel the gateway narrowed.
                            if args.full_tunnel && s.narrowed_to.is_empty() {
                                let _ = auto_reconnect::guard_routes(
                                    pid.clone(),
                                    "ikev2".to_string(),
                                    raw_args,
                                )
                                .await;
                            }
                            Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                        }
                        Err(e) => Response::err(id, -32000, format!("connect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "vpn_disconnect" => {
            match serde_json::from_value::<strongswan::DisconnectArgs>(req.params) {
                Ok(args) => {
                    let pid = args.profile_id.clone();
                    let mut sw = strongswan.lock().await;
                    match sw.disconnect(&args).await {
                        Ok(s) => {
                            // A deliberate disconnect ends any route-guard intent for
                            // this profile (leaves an explicit Always-on entry alone).
                            let _ = auto_reconnect::unguard_routes(&pid).await;
                            Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                        }
                        Err(e) => Response::err(id, -32000, format!("disconnect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        // Last N bytes of `/var/log/supermanager-helper.log` so the GUI can
        // surface "why did connect fail?" directly instead of telling the
        // user to open Console.app. The helper has open access; the client
        // would need root otherwise.
        //
        // Bounded to 64 KiB max — any single failure's diagnostic context
        // fits there comfortably and we don't want to ship megabytes
        // through the JSON-RPC pipe.
        // The helper's log, or with `profile_id` that OpenVPN tunnel's,
        // which only root can read.
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
            let path = match req.params.get("profile_id").and_then(|v| v.as_str()) {
                Some(profile) => openvpn::log_path(profile),
                None => PathBuf::from(HELPER_LOG),
            };
            match tail_file(&path, want).await {
                Ok(text) => Response::ok(id, serde_json::json!({"log": text})),
                Err(e) => Response::err(id, -32000, format!("tail_log: {e}")),
            }
        }

        // What the helper did on its own since the caller last asked:
        // reconnects, reconnects that keep failing, watchdog fail-opens. The
        // caller passes back `boot` and `latest` from its previous answer as
        // `boot` and `after`. See `events`.
        "events_since" => {
            let boot = req.params.get("boot").and_then(serde_json::Value::as_str);
            let after = req
                .params
                .get("after")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            Response::ok(
                id,
                serde_json::to_value(events::since(boot, after)).unwrap_or_default(),
            )
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
                                &pid,
                                "wireguard".to_string(),
                                raw_args,
                            )
                            .await;
                            Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                        }
                        Err(e) => Response::err(id, -32000, format!("wg_connect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "wg_disconnect" => {
            match serde_json::from_value::<wireguard::WgDisconnectArgs>(req.params) {
                Ok(args) => {
                    let mut wg = wireguard.lock().await;
                    match wg.disconnect(&args).await {
                        Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                        Err(e) => Response::err(id, -32000, format!("wg_disconnect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

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
                // The configuration comes in the request. Only a connect
                // stored by an older helper names a file instead.
                Ok(args) if args.config.is_none() => {
                    Response::err(id, -32602, "bad params: missing field `config`")
                }
                Ok(args) => {
                    let pid = args.profile_id.clone();
                    let mut ov = openvpn.lock().await;
                    match ov.connect(&args).await {
                        Ok(s) => {
                            let _ =
                                auto_reconnect::refresh_args(&pid, "openvpn".to_string(), raw_args)
                                    .await;
                            Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                        }
                        Err(e) => Response::err(id, -32000, format!("ovpn_connect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "ovpn_disconnect" => {
            match serde_json::from_value::<openvpn::OvpnDisconnectArgs>(req.params) {
                Ok(args) => {
                    let mut ov = openvpn.lock().await;
                    match ov.disconnect(&args).await {
                        Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                        Err(e) => {
                            Response::err(id, -32000, format!("ovpn_disconnect failed: {e:#}"))
                        }
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

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
        // Synchronous code (launchctl, route, scutil, small files), so it
        // runs through `blocking` rather than on an async worker.
        "tailscaled_install" => {
            match serde_json::from_value::<tailscale::InstallArgs>(req.params) {
                Ok(args) => match blocking(move || tailscale::install(args)).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => {
                        Response::err(id, -32000, format!("tailscaled_install failed: {e:#}"))
                    }
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "tailscaled_uninstall" => {
            match serde_json::from_value::<tailscale::UninstallArgs>(req.params) {
                Ok(args) => match blocking(move || tailscale::uninstall(args)).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => {
                        Response::err(id, -32000, format!("tailscaled_uninstall failed: {e:#}"))
                    }
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "tailscaled_status" => {
            match serde_json::from_value::<tailscale::DaemonStatusArgs>(req.params) {
                Ok(args) => match blocking(move || tailscale::status(args)).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("tailscaled_status failed: {e:#}")),
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        // Panic-reset: clear exit-node + accept-routes, then renew
        // DHCP on the active interface. Used when an exit-node
        // selection has bricked routing and the user can't reach
        // the internet to even open a browser. Always available;
        // doesn't depend on tailscaled being responsive.
        "tailscale_panic_reset" => {
            match serde_json::from_value::<tailscale::PanicResetArgs>(req.params) {
                Ok(args) => match blocking(move || tailscale::panic_reset(args)).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => {
                        Response::err(id, -32000, format!("tailscale_panic_reset failed: {e:#}"))
                    }
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        // MagicDNS resolver-file backstop. Open-source tailscaled
        // on macOS doesn't install the per-domain nameserver file
        // that NetworkExtension-backed Tailscale.app does. We
        // write it from the helper so MagicDNS names actually
        // resolve through the system resolver. See helper
        // `install_magicdns_resolver` for full reasoning.
        "tailscale_install_magicdns_resolver" => {
            match serde_json::from_value::<tailscale::MagicdnsResolverArgs>(req.params) {
                Ok(args) => {
                    match blocking(move || tailscale::install_magicdns_resolver(args)).await {
                        Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                        Err(e) => {
                            Response::err(id, -32000, format!("magicdns_resolver failed: {e:#}"))
                        }
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        // Exit-node split-default routes. tailscaled-on-macOS
        // doesn't install these itself — see tailscale.rs for
        // the rant. Caller (AppState.setExitNodeWithSafety)
        // pairs install with the existing internet probe so
        // we can auto-revert if traffic dies.
        "tailscale_install_exit_routes" => {
            match serde_json::from_value::<tailscale::ExitRoutesArgs>(req.params) {
                Ok(args) => {
                    // Read the caller's intent before `args` is consumed below.
                    let auto = args.auto_exit_node;
                    match blocking(move || tailscale::install_exit_routes(args)).await {
                        Ok(s) => {
                            // Routes are up — record the user's intent so the reconciler
                            // can re-establish them after sleep/wake or a blip.
                            //
                            // `current_exit_node` reports the peer tailscaled resolved
                            // to. For a pinned selection that IS the intent. For
                            // `auto:any` it is only an observation, so it gets recorded
                            // as such and the reconciler re-asserts `auto:any` rather
                            // than pinning this particular peer.
                            let (node_id, node_ip) = blocking(tailscale::current_exit_node).await;
                            if auto {
                                tailscale_state::set_desired_auto(&node_id, &node_ip);
                            } else {
                                tailscale_state::set_desired(&node_id, &node_ip);
                            }
                            Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                        }
                        Err(e) => {
                            Response::err(id, -32000, format!("install_exit_routes failed: {e:#}"))
                        }
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "tailscale_remove_exit_routes" => {
            match serde_json::from_value::<tailscale::ExitRoutesArgs>(req.params) {
                Ok(args) => match blocking(move || tailscale::remove_exit_routes(args)).await {
                    Ok(s) => {
                        // This RPC is the INTENTIONAL clear (user cleared the exit
                        // node) — stop self-heal. The watchdog's blip recovery goes
                        // through panic_reset (clear_pref=false), which does NOT
                        // touch the desired-state, so a transient drop never wipes
                        // intent.
                        tailscale_state::clear_desired();
                        Response::ok(id, serde_json::to_value(s).unwrap_or_default())
                    }
                    Err(e) => {
                        Response::err(id, -32000, format!("remove_exit_routes failed: {e:#}"))
                    }
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        // Pre-flight test for exit-node selection. Installs a
        // single /32 route via tailscaled's utun, probes a known
        // public IP, cleans up. Used by AppState to decide
        // whether the chosen peer actually forwards before
        // committing to full split-default routes.
        "tailscale_test_exit_reachability" => {
            match serde_json::from_value::<tailscale::TestExitArgs>(req.params) {
                Ok(args) => match blocking(move || tailscale::test_exit_reachability(args)).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => {
                        Response::err(id, -32000, format!("test_exit_reachability failed: {e:#}"))
                    }
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        // Set system DNS servers via networksetup. Used to
        // recover when macOS's resolver gets stuck on an
        // unreachable nameserver. Always available — DNS rescue
        // is a baseline capability.
        "tailscale_set_dns_servers" => {
            match serde_json::from_value::<tailscale::SetDnsArgs>(req.params) {
                Ok(args) => match blocking(move || tailscale::set_dns_servers(args)).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("set_dns_servers failed: {e:#}")),
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        // Forcibly write live DNS state via scutil. Bypasses
        // configd merge logic — for situations where
        // `networksetup` writes to Setup but configd refuses to
        // propagate to State (e.g., a stale IPv6 RA RDNSS
        // nameserver shadowing the manual config).
        "tailscale_force_dns_state" => {
            match serde_json::from_value::<tailscale::SetDnsArgs>(req.params) {
                Ok(args) => match blocking(move || tailscale::force_dns_state(args)).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("force_dns_state failed: {e:#}")),
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        // Configure the DNS fallback list used by the DNS health
        // watchdog. Persisted to /var/lib/supermanager/dns_fallbacks.json
        // so a helper restart keeps the user's preference.
        "tailscale_set_dns_fallbacks" => {
            match serde_json::from_value::<tailscale::SetDnsArgs>(req.params) {
                Ok(args) => {
                    match blocking(move || dns_health_watchdog::set_fallbacks(args.servers)).await {
                        Ok(_) => Response::ok(
                            id,
                            serde_json::json!({
                                "fallbacks": dns_health_watchdog::current_fallbacks()
                            }),
                        ),
                        Err(e) => {
                            Response::err(id, -32000, format!("set_dns_fallbacks failed: {e:#}"))
                        }
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }

        "tailscale_get_dns_fallbacks" => Response::ok(
            id,
            serde_json::json!({
                "fallbacks": dns_health_watchdog::current_fallbacks()
            }),
        ),

        // Pause connectivity-watchdog escalation. Critical for
        // exit-node transitions: setting/clearing the pref +
        // installing split-default routes always causes a few
        // seconds of disrupted internet (DNS reconfig, TCP
        // resets), and the watchdog would otherwise panic_reset
        // them mid-flight, undoing the user's selection.
        "tailscale_pause_watchdog" => {
            let secs = req
                .params
                .get("seconds")
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
            let args = req
                .params
                .get("connect_args")
                .cloned()
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
            // `unarmed` is additive — older GUIs read only `watched` and
            // keep working. A profile in both is enrolled but cannot be
            // replayed yet, which the GUI must not present as protected.
            let unarmed = auto_reconnect::list_unarmed().await;
            Response::ok(
                id,
                serde_json::json!({
                    "watched": watched,
                    "unarmed": unarmed,
                }),
            )
        }

        // Kill-switch: install pf rules that block all egress
        // except via the named tunnel interface + LAN. Idempotent.
        "kill_switch_enable" => match serde_json::from_value::<kill_switch::EnableArgs>(req.params)
        {
            Ok(args) => match blocking(move || kill_switch::enable(args)).await {
                Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                Err(e) => Response::err(id, -32000, format!("kill_switch_enable: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },

        "kill_switch_disable" => {
            match serde_json::from_value::<kill_switch::DisableArgs>(req.params) {
                Ok(args) => match blocking(move || kill_switch::disable(args)).await {
                    Ok(s) => Response::ok(id, serde_json::to_value(s).unwrap_or_default()),
                    Err(e) => Response::err(id, -32000, format!("kill_switch_disable: {e:#}")),
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
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

            // Accelerate exit-node recovery past the 30s reconcile tick. The
            // sweep above runs first on purpose: it is what may have removed
            // the stale /1 pair the reconciler is about to re-install.
            tailscale::schedule_wake_reconcile();

            info!("system_wake: done");
            Response::ok(id, serde_json::json!({"ok": true}))
        }

        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn client_gone_resolves_on_hangup() {
        let (server, client) = UnixStream::pair().expect("socketpair");
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), client_gone(&server))
            .await
            .expect("EOF from the client must resolve");
    }

    #[tokio::test]
    async fn client_gone_leaves_a_live_client_and_its_bytes_alone() {
        let (server, mut client) = UnixStream::pair().expect("socketpair");
        client.write_all(b"x").await.expect("write");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), client_gone(&server))
                .await
                .is_err(),
            "pending bytes mean the client is still there"
        );
        let mut byte = [0u8; 1];
        let mut server = server;
        server
            .read_exact(&mut byte)
            .await
            .expect("peeked byte is still readable");
        assert_eq!(&byte, b"x");
    }

    #[test]
    fn only_reads_are_cancellable() {
        for method in [
            "events_since",
            "vpn_status",
            "wg_status",
            "ovpn_status",
            "ping",
            "tailscaled_status",
        ] {
            assert!(is_read_only(method), "{method}");
        }
        for method in [
            "vpn_connect",
            "vpn_disconnect",
            "tailscaled_install",
            "system_sleep",
        ] {
            assert!(!is_read_only(method), "{method}");
        }
    }
}
