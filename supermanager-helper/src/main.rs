//! `SuperManager` privileged helper daemon.
//!
//! ## What this is
//!
//! A small root-owned `LaunchDaemon` that brokers between the unprivileged
//! `SuperManager.app` GUI and the system-level VPN machinery (`strongSwan`).
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
//! the system `LaunchDaemons` store, and starts our binary as root. After
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
use std::path::{Path, PathBuf};
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
mod route_guardian;
mod route_table;
mod signed_file;
mod strongswan;
mod tailscale;
mod tailscale_routes;
mod tailscale_state;
mod vpn_runtime;
mod wg_native;
mod wireguard;

/// Where launchd writes the helper's output (the plist's `StandardOutPath`),
/// and charon writes its own.
pub(crate) const HELPER_LOG: &str = "/var/log/supermanager-helper.log";

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

fn ok_json<T: Serialize>(id: u64, value: T) -> Response {
    match serde_json::to_value(value) {
        Ok(v) => Response::ok(id, v),
        Err(e) => Response::err(
            id,
            -32603,
            format!("internal error: serialize response: {e}"),
        ),
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
        "vpn_poll_all",
        "vpn_runtime_install",
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
        "kill_switch_set_intent",
        "kill_switch_status",
        "system_sleep",
        "system_wake",
    ];
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build_timestamp": env!("HELPER_BUILD_TIMESTAMP"),
        "methods": methods,
    })
}

fn spawn_background_supervisors(controllers: &Controllers) {
    if let Err(e) = route_guardian::spawn_guardian() {
        tracing::warn!("could not spawn route guardian: {e:#}");
    }
    tailscale::ensure_plist_current();
    if let Err(e) = connectivity_watchdog::spawn_watchdog() {
        tracing::warn!("could not spawn connectivity watchdog: {e:#}");
    }
    if let Err(e) = dns_health_watchdog::spawn_watchdog() {
        tracing::warn!("could not spawn dns health watchdog: {e:#}");
    }
    if let Err(e) = tailscale_routes::spawn() {
        tracing::warn!("could not spawn the Tailscale route keeper: {e:#}");
    }

    // Helper-side Mach wake detector — covers GUI-closed sleep/wake cleanup.
    let sw_for_wake = controllers.strongswan.clone();
    tokio::spawn(async move {
        use std::time::Duration;
        const TICK: Duration = Duration::from_secs(30);
        const SLEEP_THRESHOLD: Duration = Duration::from_secs(15);
        let mut last_slept = mach_sleep_duration();
        loop {
            tokio::time::sleep(TICK).await;
            let now_slept = mach_sleep_duration();
            let slept = now_slept.saturating_sub(last_slept);
            if slept >= SLEEP_THRESHOLD {
                info!(
                    "wake detector: {}s Mach sleep delta across a {}s tick — \
                     machine slept; running post-wake cleanup",
                    slept.as_secs(),
                    TICK.as_secs()
                );
                connectivity_watchdog::pause_for(45);
                route_guardian::reset_snapshot();
                sw_for_wake.lock().await.sweep_stale().await;
                tailscale::schedule_wake_reconcile();
            }
            last_slept = now_slept;
        }
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SM_HELPER_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();

    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("{}", helper_version_info());
        return Ok(());
    }

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
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        anyhow::bail!("supermanager-helper must run as root (got uid={uid})");
    }

    let client_policy = client_auth::own_policy();
    vpn_runtime::init_policy(client_policy);
    info!(?client_policy, "only SuperManager may use this helper");

    rotate_log_if_oversize(Path::new(HELPER_LOG), 5 * 1024 * 1024);
    rotate_log_if_oversize(
        Path::new("/var/log/supermanager-tailscaled.log"),
        5 * 1024 * 1024,
    );

    let socket_path = PathBuf::from(SOCKET_PATH);
    let _ = tokio::fs::remove_file(&socket_path).await;

    let controllers = Controllers {
        strongswan: Arc::new(Mutex::new(strongswan::Strongswan::new(client_policy))),
        wireguard: Arc::new(Mutex::new(wireguard::WireGuard::new(client_policy))),
        openvpn: Arc::new(Mutex::new(openvpn::OpenVpn::new(client_policy))),
    };

    controllers.strongswan.lock().await.sweep_stale().await;
    openvpn::sweep_legacy_logs();
    spawn_background_supervisors(&controllers);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind {}", socket_path.display()))?;
    set_socket_permissions(&socket_path).context("set socket perms")?;
    info!("listening on {}", socket_path.display());

    controllers.wireguard.lock().await.adopt_native().await;
    kill_switch::reconcile_on_startup();

    if let Err(e) = auto_reconnect::spawn_watchdog(
        controllers.wireguard.clone(),
        controllers.openvpn.clone(),
        controllers.strongswan.clone(),
    )
    .await
    {
        tracing::warn!("could not spawn auto-reconnect watchdog: {e:#}");
    }

    let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let Ok(permit) = conn_semaphore.clone().try_acquire_owned() else {
                    warn!("rejecting connection: max concurrent helper clients (64) reached");
                    continue;
                };
                let ctrls = controllers.clone();
                tokio::spawn(async move {
                    let _permit = permit;
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
    let to_read = len.saturating_sub(start).min(want_bytes);
    let mut buf = Vec::with_capacity(usize::try_from(to_read).unwrap_or(0));
    f.take(want_bytes).read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// `chown :admin` and `chmod 0660` on the socket so admin-group users can
/// connect but everyone else cannot. We deliberately leave it owned by
/// root:admin rather than something narrower because every admin user on
/// the Mac is already trusted to install software (which is what installing
/// `SuperManager` is).
fn set_socket_permissions(path: &PathBuf) -> anyhow::Result<()> {
    use std::ffi::CString;

    let cpath =
        CString::new(path.as_os_str().as_encoded_bytes()).context("path contains nul byte")?;
    // group "admin" is gid 80 on every Mac since forever, but look it up
    // properly anyway.
    let admin_gid = unsafe {
        let g = libc::getgrnam(c"admin".as_ptr());
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
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_exact(&mut len_buf),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("client disconnected");
                return Ok(());
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("client idle read timed out");
                return Ok(());
            }
        }
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len > MAX_MESSAGE_SIZE {
            warn!("message too large: {msg_len} bytes — dropping connection");
            return Ok(());
        }

        let mut buf = vec![0u8; msg_len];
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read_exact(&mut buf),
        )
        .await
        .context("client frame body read timed out")??;

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
        let len = u32::try_from(resp_bytes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes();
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
            | "kill_switch_status"
    )
}

/// Resolves once the client has closed its end. `HelperClient` sends one
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
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
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
    let id = req.id;
    if req.jsonrpc != "2.0" {
        return Response::err(id, -32600, "expected jsonrpc=2.0");
    }
    debug!(method = %req.method, "dispatch");
    match req.method.as_str() {
        "ping" | "helper_version" | "restart" | "tail_log" | "events_since" => {
            dispatch_meta(&req.method, id, req.params).await
        }
        "vpn_connect"
        | "vpn_disconnect"
        | "vpn_status"
        | "vpn_poll_all"
        | "vpn_runtime_install" => dispatch_ikev2(&req.method, id, req.params, controllers).await,
        "wg_connect" | "wg_disconnect" | "wg_status" | "ovpn_connect" | "ovpn_disconnect"
        | "ovpn_status" => dispatch_wg_and_ovpn(&req.method, id, req.params, controllers).await,
        "tailscaled_install"
        | "tailscaled_uninstall"
        | "tailscaled_status"
        | "tailscale_panic_reset"
        | "tailscale_install_magicdns_resolver"
        | "tailscale_install_exit_routes"
        | "tailscale_remove_exit_routes"
        | "tailscale_test_exit_reachability" => {
            dispatch_tailscale_daemon_and_routes(&req.method, id, req.params).await
        }
        "tailscale_set_dns_servers"
        | "tailscale_force_dns_state"
        | "tailscale_set_dns_fallbacks"
        | "tailscale_get_dns_fallbacks"
        | "tailscale_pause_watchdog"
        | "tailscale_resume_watchdog" => {
            dispatch_tailscale_dns_and_watchdog(&req.method, id, req.params).await
        }
        m if m.starts_with("auto_reconnect_") || m.starts_with("kill_switch_") => {
            dispatch_guards(&req.method, id, req.params).await
        }
        "system_sleep" | "system_wake" => dispatch_power(&req.method, id, controllers).await,
        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}

async fn dispatch_meta(method: &str, id: u64, params: serde_json::Value) -> Response {
    match method {
        "ping" => Response::ok(
            id,
            serde_json::json!({"pong": true, "version": env!("CARGO_PKG_VERSION")}),
        ),
        "helper_version" => Response::ok(id, helper_version_info()),
        "restart" => {
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                tracing::info!("restart RPC received — exiting non-zero so launchd respawns");
                std::process::exit(1);
            });
            Response::ok(id, serde_json::json!({"restarting": true}))
        }
        "tail_log" => {
            const DEFAULT_BYTES: u64 = 8 * 1024;
            const MAX_BYTES: u64 = 64 * 1024;
            let want = params
                .get("bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(DEFAULT_BYTES)
                .min(MAX_BYTES);
            let path = match params.get("profile_id").and_then(serde_json::Value::as_str) {
                Some(profile) => match openvpn::log_path(profile) {
                    Ok(p) => p,
                    Err(e) => return Response::err(id, -32602, format!("bad params: {e}")),
                },
                None => PathBuf::from(HELPER_LOG),
            };
            match tail_file(&path, want).await {
                Ok(text) => Response::ok(id, serde_json::json!({"log": text})),
                Err(e) => Response::err(id, -32000, format!("tail_log: {e}")),
            }
        }
        "events_since" => {
            let boot = params.get("boot").and_then(serde_json::Value::as_str);
            let after = params
                .get("after")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            ok_json(id, events::since(boot, after))
        }
        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}

#[derive(Deserialize)]
struct PollItem {
    profile_id: String,
    backend: String,
}

#[derive(Deserialize)]
struct PollAllArgs {
    #[serde(default)]
    profiles: Vec<PollItem>,
}

async fn handle_vpn_poll_all(
    id: u64,
    params: serde_json::Value,
    controllers: &Controllers,
) -> Response {
    let args = match serde_json::from_value::<PollAllArgs>(params) {
        Ok(a) => a,
        Err(e) => return Response::err(id, -32602, format!("bad params: {e}")),
    };
    let ks = blocking(kill_switch::status).await;
    let mut statuses = serde_json::Map::with_capacity(args.profiles.len());
    for item in args.profiles {
        let b = item.backend.to_ascii_lowercase();
        let entry = if b.contains("wireguard") || b.contains("wire_guard") {
            let q = wireguard::WgStatusArgs {
                profile_id: item.profile_id.clone(),
            };
            let mut wg = controllers.wireguard.lock().await;
            wg.status(&q)
                .await
                .and_then(|v| serde_json::to_value(v).map_err(Into::into))
        } else if b.contains("openvpn") || b.contains("open_vpn") || b.contains("azure") {
            let q = openvpn::OvpnStatusArgs {
                profile_id: item.profile_id.clone(),
            };
            let mut ov = controllers.openvpn.lock().await;
            ov.status(&q)
                .await
                .and_then(|v| serde_json::to_value(v).map_err(Into::into))
        } else if b.contains("fortigate")
            || b.contains("forti_gate")
            || b.contains("ikev2")
            || b.contains("ipsec")
        {
            let q = strongswan::StatusArgs {
                profile_id: item.profile_id.clone(),
            };
            let mut sw = controllers.strongswan.lock().await;
            sw.status(&q)
                .await
                .and_then(|v| serde_json::to_value(v).map_err(Into::into))
        } else {
            Ok(serde_json::json!({ "state": "disconnected" }))
        };
        match entry {
            Ok(v) => {
                statuses.insert(item.profile_id, v);
            }
            Err(e) => {
                statuses.insert(
                    item.profile_id,
                    serde_json::json!({
                        "state": "unknown",
                        "detail": format!("{e:#}"),
                    }),
                );
            }
        }
    }
    Response::ok(
        id,
        serde_json::json!({
            "kill_switch": ks,
            "profiles": statuses,
        }),
    )
}

async fn dispatch_ikev2(
    method: &str,
    id: u64,
    params: serde_json::Value,
    controllers: &Controllers,
) -> Response {
    let strongswan = &controllers.strongswan;
    match method {
        "vpn_connect" => {
            let raw_args = params.clone();
            match serde_json::from_value::<strongswan::ConnectArgs>(params) {
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
                            if args.full_tunnel && s.narrowed_to.is_empty() {
                                let _ = auto_reconnect::guard_routes(
                                    pid.clone(),
                                    "ikev2".to_string(),
                                    raw_args,
                                )
                                .await;
                            }
                            ok_json(id, s)
                        }
                        Err(e) => Response::err(id, -32000, format!("connect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "vpn_disconnect" => match serde_json::from_value::<strongswan::DisconnectArgs>(params) {
            Ok(args) => {
                let pid = args.profile_id.clone();
                let mut sw = strongswan.lock().await;
                match sw.disconnect(&args).await {
                    Ok(s) => {
                        let _ = auto_reconnect::unguard_routes(&pid).await;
                        ok_json(id, s)
                    }
                    Err(e) => Response::err(id, -32000, format!("disconnect failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        "vpn_status" => match serde_json::from_value::<strongswan::StatusArgs>(params) {
            Ok(args) => {
                let mut sw = strongswan.lock().await;
                match sw.status(&args).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => Response::err(id, -32000, format!("status failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        "vpn_poll_all" => handle_vpn_poll_all(id, params, controllers).await,
        "vpn_runtime_install" => match serde_json::from_value::<vpn_runtime::InstallArgs>(params) {
            Ok(args) => match blocking(move || vpn_runtime::install(&args)).await {
                Ok(s) => ok_json(id, s),
                Err(e) => Response::err(id, -32000, format!("vpn_runtime_install: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}

async fn dispatch_wg_and_ovpn(
    method: &str,
    id: u64,
    params: serde_json::Value,
    controllers: &Controllers,
) -> Response {
    let wireguard = &controllers.wireguard;
    let openvpn = &controllers.openvpn;
    match method {
        "wg_connect" => {
            let raw_args = params.clone();
            match serde_json::from_value::<wireguard::WgConnectArgs>(params) {
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
                            ok_json(id, s)
                        }
                        Err(e) => Response::err(id, -32000, format!("wg_connect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "wg_disconnect" => match serde_json::from_value::<wireguard::WgDisconnectArgs>(params) {
            Ok(args) => {
                let mut wg = wireguard.lock().await;
                match wg.disconnect(&args).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => Response::err(id, -32000, format!("wg_disconnect failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        "wg_status" => match serde_json::from_value::<wireguard::WgStatusArgs>(params) {
            Ok(args) => {
                let mut wg = wireguard.lock().await;
                match wg.status(&args).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => Response::err(id, -32000, format!("wg_status failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        "ovpn_connect" => {
            let raw_args = params.clone();
            match serde_json::from_value::<openvpn::OvpnConnectArgs>(params) {
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
                            ok_json(id, s)
                        }
                        Err(e) => Response::err(id, -32000, format!("ovpn_connect failed: {e:#}")),
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "ovpn_disconnect" => match serde_json::from_value::<openvpn::OvpnDisconnectArgs>(params) {
            Ok(args) => {
                let mut ov = openvpn.lock().await;
                match ov.disconnect(&args).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => Response::err(id, -32000, format!("ovpn_disconnect failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        "ovpn_status" => match serde_json::from_value::<openvpn::OvpnStatusArgs>(params) {
            Ok(args) => {
                let mut ov = openvpn.lock().await;
                match ov.status(&args).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => Response::err(id, -32000, format!("ovpn_status failed: {e:#}")),
                }
            }
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}

async fn dispatch_tailscale_daemon_and_routes(
    method: &str,
    id: u64,
    params: serde_json::Value,
) -> Response {
    match method {
        "tailscaled_install" => match serde_json::from_value::<tailscale::InstallArgs>(params) {
            Ok(args) => match blocking(move || tailscale::install(&args)).await {
                Ok(s) => ok_json(id, s),
                Err(e) => Response::err(id, -32000, format!("tailscaled_install failed: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        "tailscaled_uninstall" => {
            match serde_json::from_value::<tailscale::UninstallArgs>(params) {
                Ok(args) => ok_json(id, blocking(move || tailscale::uninstall(args)).await),
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "tailscaled_status" => {
            match serde_json::from_value::<tailscale::DaemonStatusArgs>(params) {
                Ok(args) => match blocking(move || tailscale::status(args)).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => Response::err(id, -32000, format!("tailscaled_status failed: {e:#}")),
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "tailscale_panic_reset" => {
            match serde_json::from_value::<tailscale::PanicResetArgs>(params) {
                Ok(args) => match blocking(move || tailscale::panic_reset(args)).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => {
                        Response::err(id, -32000, format!("tailscale_panic_reset failed: {e:#}"))
                    }
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "tailscale_install_magicdns_resolver" => {
            match serde_json::from_value::<tailscale::MagicdnsResolverArgs>(params) {
                Ok(args) => {
                    match blocking(move || tailscale::install_magicdns_resolver(&args)).await {
                        Ok(s) => ok_json(id, s),
                        Err(e) => {
                            Response::err(id, -32000, format!("magicdns_resolver failed: {e:#}"))
                        }
                    }
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "tailscale_install_exit_routes" => {
            match serde_json::from_value::<tailscale::ExitRoutesArgs>(params) {
                Ok(args) => {
                    let auto = args.auto_exit_node;
                    match blocking(move || tailscale::install_exit_routes(args)).await {
                        Ok(s) => {
                            let (exit_id, peer_addr) = blocking(tailscale::current_exit_node).await;
                            if auto {
                                tailscale_state::set_desired_auto(&exit_id, &peer_addr);
                            } else {
                                tailscale_state::set_desired(&exit_id, &peer_addr);
                            }
                            ok_json(id, s)
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
            match serde_json::from_value::<tailscale::ExitRoutesArgs>(params) {
                Ok(args) => {
                    let res = blocking(move || tailscale::remove_exit_routes(args)).await;
                    tailscale_state::clear_desired();
                    ok_json(id, res)
                }
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "tailscale_test_exit_reachability" => {
            match serde_json::from_value::<tailscale::TestExitArgs>(params) {
                Ok(args) => match blocking(move || tailscale::test_exit_reachability(args)).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => {
                        Response::err(id, -32000, format!("test_exit_reachability failed: {e:#}"))
                    }
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}

async fn dispatch_tailscale_dns_and_watchdog(
    method: &str,
    id: u64,
    params: serde_json::Value,
) -> Response {
    match method {
        "tailscale_set_dns_servers" => {
            match serde_json::from_value::<tailscale::SetDnsArgs>(params) {
                Ok(args) => match blocking(move || tailscale::set_dns_servers(&args)).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => Response::err(id, -32000, format!("set_dns_servers failed: {e:#}")),
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "tailscale_force_dns_state" => {
            match serde_json::from_value::<tailscale::SetDnsArgs>(params) {
                Ok(args) => match blocking(move || tailscale::force_dns_state(&args)).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => Response::err(id, -32000, format!("force_dns_state failed: {e:#}")),
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "tailscale_set_dns_fallbacks" => {
            match serde_json::from_value::<tailscale::SetDnsArgs>(params) {
                Ok(args) => {
                    match blocking(move || dns_health_watchdog::set_fallbacks(&args.servers)).await
                    {
                        Ok(()) => Response::ok(
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
        "tailscale_pause_watchdog" => {
            let secs = params
                .get("seconds")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(30);
            connectivity_watchdog::pause_for(secs);
            Response::ok(id, serde_json::json!({"paused_seconds": secs}))
        }
        "tailscale_resume_watchdog" => {
            connectivity_watchdog::resume_now();
            Response::ok(id, serde_json::json!({"resumed": true}))
        }
        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}

async fn dispatch_guards(method: &str, id: u64, params: serde_json::Value) -> Response {
    match method {
        "auto_reconnect_enable" => {
            let Some(profile_id) = params
                .get("profile_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            else {
                return Response::err(id, -32602, "missing profile_id");
            };
            let Some(backend) = params
                .get("backend")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            else {
                return Response::err(id, -32602, "missing backend");
            };
            let args = params
                .get("connect_args")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            match auto_reconnect::enable(profile_id.clone(), backend, args).await {
                Ok(()) => Response::ok(id, serde_json::json!({"enabled": profile_id})),
                Err(e) => Response::err(id, -32000, format!("enable failed: {e:#}")),
            }
        }
        "auto_reconnect_disable" => {
            let Some(profile_id) = params
                .get("profile_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            else {
                return Response::err(id, -32602, "missing profile_id");
            };
            match auto_reconnect::disable(&profile_id).await {
                Ok(()) => Response::ok(id, serde_json::json!({"disabled": profile_id})),
                Err(e) => Response::err(id, -32000, format!("disable failed: {e:#}")),
            }
        }
        "auto_reconnect_list" => {
            let watched = auto_reconnect::list_watched().await;
            let unarmed = auto_reconnect::list_unarmed().await;
            Response::ok(
                id,
                serde_json::json!({
                    "watched": watched,
                    "unarmed": unarmed,
                }),
            )
        }
        "kill_switch_enable" => match serde_json::from_value::<kill_switch::EnableArgs>(params) {
            Ok(args) => match blocking(move || kill_switch::enable(&args)).await {
                Ok(s) => ok_json(id, s),
                Err(e) => Response::err(id, -32000, format!("kill_switch_enable: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        "kill_switch_disable" => match serde_json::from_value::<kill_switch::DisableArgs>(params) {
            Ok(args) => match blocking(move || kill_switch::disable(&args)).await {
                Ok(s) => ok_json(id, s),
                Err(e) => Response::err(id, -32000, format!("kill_switch_disable: {e:#}")),
            },
            Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
        },
        "kill_switch_set_intent" => {
            match serde_json::from_value::<kill_switch::SetIntentArgs>(params) {
                Ok(args) => match blocking(move || kill_switch::set_intent(&args)).await {
                    Ok(s) => ok_json(id, s),
                    Err(e) => Response::err(id, -32000, format!("kill_switch_set_intent: {e:#}")),
                },
                Err(e) => Response::err(id, -32602, format!("bad params: {e}")),
            }
        }
        "kill_switch_status" => ok_json(id, blocking(kill_switch::status).await),
        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}

async fn dispatch_power(method: &str, id: u64, controllers: &Controllers) -> Response {
    match method {
        "system_sleep" => {
            info!("system_sleep: running pre-sleep VPN teardown");
            controllers
                .strongswan
                .lock()
                .await
                .terminate_all_and_sweep()
                .await;
            let killed = {
                let _ovpn_guard = controllers.openvpn.lock().await;
                openvpn::terminate_all().await
            };
            if killed > 0 {
                info!("system_sleep: terminated {killed} OpenVPN process(es)");
            }
            info!("system_sleep: done");
            Response::ok(id, serde_json::json!({"ok": true}))
        }
        "system_wake" => {
            info!("system_wake: running post-wake cleanup");
            connectivity_watchdog::pause_for(45);
            route_guardian::reset_snapshot();
            controllers.strongswan.lock().await.sweep_stale().await;
            tailscale::schedule_wake_reconcile();
            info!("system_wake: done");
            Response::ok(id, serde_json::json!({"ok": true}))
        }
        other => Response::err(id, -32601, format!("unknown method: {other}")),
    }
}

/// Cumulative time the machine has spent in system sleep since boot, computed
/// from Darwin's `mach_continuous_time() - mach_absolute_time()`.
///
/// Neither Mach clock is affected by NTP adjustments or manual wall-clock
/// changes: `mach_continuous_time` advances monotonically across sleep while
/// `mach_absolute_time` pauses during sleep. Sampling `mach_absolute_time`
/// again *after* `mach_continuous_time` ensures thread preemption between the
/// reads never masquerades as sleep time.
fn mach_sleep_duration() -> std::time::Duration {
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }
    extern "C" {
        fn mach_absolute_time() -> u64;
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::kern_return_t;
    }

    let (abs_before, cont, abs_after, tb) = unsafe {
        let mut tb = MachTimebaseInfo { numer: 1, denom: 1 };
        let _ = mach_timebase_info(&raw mut tb);
        let a1 = mach_absolute_time();
        let c = mach_continuous_time();
        let a2 = mach_absolute_time();
        (a1, c, a2, tb)
    };
    let sleep_ticks = cont.saturating_sub(abs_after.max(abs_before));
    if tb.denom == 0 {
        return std::time::Duration::ZERO;
    }
    let nanos = (u128::from(sleep_ticks) * u128::from(tb.numer)) / u128::from(tb.denom);
    std::time::Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

fn dir_has_matching_entry(dir: &Path, pred: impl Fn(&str) -> bool) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .any(|name| pred(&name))
}

fn has_ascii_ext(name: &str, ext: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// Zero-fork check whether `SuperManager` currently manages any active Tailscale
/// daemon, exit-node route intent, kill-switch lease, or WireGuard / OpenVPN /
/// IKEv2 tunnel state (`P3-1`).
pub(crate) fn has_managed_network_state() -> bool {
    if tailscale::has_managed_daemon()
        || tailscale_state::load().desired
        || Path::new("/var/run/supermanager-tailscale-exemptions").exists()
        || Path::new("/var/run/supermanager-charon.pid").exists()
        || Path::new("/var/run/charon.vici").exists()
        || kill_switch::has_active_leases()
    {
        return true;
    }
    dir_has_matching_entry(Path::new("/var/lib/supermanager/wg"), |n| {
        has_ascii_ext(n, "json")
    }) || dir_has_matching_entry(Path::new("/var/run/wireguard"), |n| {
        n.starts_with("smgr") && has_ascii_ext(n, "name")
    }) || dir_has_matching_entry(Path::new("/etc/wireguard"), |n| {
        n.starts_with("smgr") && has_ascii_ext(n, "conf")
    }) || dir_has_matching_entry(Path::new("/var/run/supermanager-vpn"), |n| {
        has_ascii_ext(n, "pid") || has_ascii_ext(n, "ovpn")
    })
}

/// Bounded log rotation (`P3-6`): when `path` exceeds `max_bytes`, atomically
/// move it to `<path>.1` (refusing symlinks) so the next open starts fresh.
pub(crate) fn rotate_log_if_oversize(path: &Path, max_bytes: u64) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() <= max_bytes {
        return;
    }
    let mut rotated = path.as_os_str().to_os_string();
    rotated.push(".1");
    let rotated_path = PathBuf::from(rotated);
    if std::fs::symlink_metadata(&rotated_path).is_ok_and(|m| m.file_type().is_symlink()) {
        return;
    }
    let _ = std::fs::rename(path, &rotated_path);
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
            "kill_switch_status",
        ] {
            assert!(is_read_only(method), "{method}");
        }
        for method in [
            "vpn_connect",
            "vpn_disconnect",
            "tailscaled_install",
            "system_sleep",
            "kill_switch_set_intent",
        ] {
            assert!(!is_read_only(method), "{method}");
        }
    }

    #[test]
    fn mach_sleep_duration_stays_stable_while_awake() {
        let d1 = mach_sleep_duration();
        std::thread::sleep(Duration::from_millis(20));
        let d2 = mach_sleep_duration();
        // While awake, `mach_continuous_time - mach_absolute_time` does not
        // advance (allow at most a small scheduling jitter margin, well below
        // the 15s wake threshold).
        assert!(
            d2.saturating_sub(d1) < Duration::from_secs(1),
            "unexpected sleep delta while awake: d1={d1:?}, d2={d2:?}"
        );
    }

    #[test]
    fn rotate_log_rotates_only_when_exceeding_cap() {
        let dir = std::env::temp_dir().join(format!("smgr-log-rot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("helper.log");
        std::fs::write(&log, vec![b'a'; 64]).unwrap();
        rotate_log_if_oversize(&log, 128);
        assert!(log.is_file());
        assert!(!dir.join("helper.log.1").exists());

        rotate_log_if_oversize(&log, 32);
        assert!(!log.exists());
        assert_eq!(
            std::fs::metadata(dir.join("helper.log.1")).unwrap().len(),
            64
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
