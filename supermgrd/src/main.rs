//! `supermgrd` — privileged VPN + SSH manager daemon.
//!
//! # Startup sequence
//!
//! 1. Initialise `tracing` subscriber (log to stdout / journald).
//! 2. Select the profile directory based on effective UID (root -> system path,
//!    non-root -> XDG user path for development).
//! 3. Load VPN profiles from the selected directory (TOML files).
//! 4. Load SSH keys and hosts from the SSH data directories.
//! 5. Clean up any stale WireGuard interfaces left by a previous crash.
//! 6. Acquire the D-Bus well-known name `org.supermgr.Daemon` on the **system** bus.
//! 7. Register the `DaemonService` object at `/org/supermgr/Daemon`.
//! 8. Spawn the background monitoring task.
//! 9. Block on the `zbus` connection loop until SIGTERM / SIGINT.
//!
//! # Privilege requirements
//!
//! The daemon must run as root (or a user with `CAP_NET_ADMIN`) to create and
//! configure WireGuard interfaces via netlink.  The provided systemd unit file
//! (in `contrib/systemd/`) restricts capabilities accordingly.
//!
//! When run as root the system bus is used and profiles are stored in
//! `/etc/supermgrd/profiles/`.  When run as a non-root user (development only)
//! the system bus is still used but profiles are stored under `$XDG_DATA_HOME`.

#![deny(missing_docs)]

mod audit;
mod vpn;
mod ssh;
mod daemon;
mod secrets;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use tokio::sync::{watch, Mutex};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _, EnvFilter, Layer as _};

use daemon::{DaemonService, DaemonState};
use supermgr_core::dbus::{DBUS_OBJECT_PATH, DBUS_SERVICE};

/// Profile directory used when the daemon runs as root (production / systemd).
const SYSTEM_PROFILE_DIR: &str = "/etc/supermgrd/profiles";

/// Stats polling interval.
const STATS_POLL_INTERVAL: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // -----------------------------------------------------------------------
    // 1. Logging — fmt layer (stdout) + ring-buffer layer (in-memory)
    // -----------------------------------------------------------------------
    let log_buffer: Arc<std::sync::Mutex<std::collections::VecDeque<String>>> =
        Arc::new(std::sync::Mutex::new(std::collections::VecDeque::with_capacity(500)));

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .with(RingLayer { buf: Arc::clone(&log_buffer), cap: 500 })
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "supermgrd starting"
    );

    // -----------------------------------------------------------------------
    // 2. Profile store
    // -----------------------------------------------------------------------
    // `SUPERMGRD_PROFILE_DIR` always wins; otherwise the directory is chosen
    // based on effective UID so the daemon works for both production (root,
    // system path) and development (non-root, XDG user path).
    let profile_dir = std::env::var("SUPERMGRD_PROFILE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if nix::unistd::getuid().is_root() {
                PathBuf::from(SYSTEM_PROFILE_DIR)
            } else {
                // Non-root development mode: use XDG data home so no
                // privileged filesystem access is required.
                let base = std::env::var("XDG_DATA_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        let home = std::env::var("HOME")
                            .unwrap_or_else(|_| "/tmp".to_owned());
                        PathBuf::from(home).join(".local/share")
                    });
                base.join("supermgrd/profiles")
            }
        });

    info!("profile directory: {}", profile_dir.display());

    let mut daemon_state = DaemonState::new(profile_dir);
    daemon_state
        .load_profiles()
        .context("failed to load profiles")?;

    let profile_count = daemon_state.profiles.len();
    info!("loaded {} VPN profile(s)", profile_count);

    // -----------------------------------------------------------------------
    // 2b. SSH data (keys and hosts)
    // -----------------------------------------------------------------------
    daemon_state.load_ssh_keys().context("failed to load SSH keys")?;
    daemon_state.load_ssh_hosts().context("failed to load SSH hosts")?;
    let ssh_key_count = daemon_state.ssh_keys.len();
    let ssh_host_count = daemon_state.ssh_hosts.len();
    info!("loaded {} SSH key(s), {} SSH host(s)", ssh_key_count, ssh_host_count);

    // -----------------------------------------------------------------------
    // 3. Stale interface cleanup + kill-switch teardown from any previous crash
    // -----------------------------------------------------------------------
    cleanup_stale_interfaces().await;
    cleanup_stale_strongswan().await;
    // If a previous daemon run was killed without a clean disconnect the
    // nftables supermgr_killswitch table will still be active in the kernel,
    // blocking all non-VPN traffic.  Remove it unconditionally on startup
    // (the call is a no-op if the table does not exist).
    daemon::remove_kill_switch().await;

    let state = Arc::new(Mutex::new(daemon_state));

    // -----------------------------------------------------------------------
    // 4. D-Bus connection — always the system bus
    // -----------------------------------------------------------------------
    // The daemon runs as root and must use the system bus.  Root has no session
    // bus; using the session bus here would cause the GUI (running as a normal
    // user on the system bus) to be unable to reach the daemon.
    let conn = zbus::Connection::system()
        .await
        .context("D-Bus system connection failed")?;

    // -----------------------------------------------------------------------
    // 5. Register D-Bus service
    // -----------------------------------------------------------------------
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let service = DaemonService {
        state: Arc::clone(&state),
        shutdown_tx,
        log_buffer,
    };

    conn.object_server()
        .at(DBUS_OBJECT_PATH, service)
        .await
        .context("failed to register D-Bus object")?;

    conn.request_name(DBUS_SERVICE)
        .await
        .context(format!("failed to acquire D-Bus name '{DBUS_SERVICE}'"))?;

    info!("D-Bus service '{}' registered at '{}'", DBUS_SERVICE, DBUS_OBJECT_PATH);

    // -----------------------------------------------------------------------
    // 6. Background monitoring task
    // -----------------------------------------------------------------------
    daemon::spawn_monitor_task(
        Arc::clone(&state),
        conn.clone(),
        shutdown_rx,
        STATS_POLL_INTERVAL,
    );

    // -----------------------------------------------------------------------
    // 6b. Auto-reconnect task (watches NetworkManager for network-up events)
    // -----------------------------------------------------------------------
    daemon::spawn_autoconnect_task(Arc::clone(&state), conn.clone());

    // -----------------------------------------------------------------------
    // 6c. SSH host health-check task (TCP-probes hosts every 60 s)
    // -----------------------------------------------------------------------
    daemon::spawn_health_check_task(Arc::clone(&state), conn.clone());

    // -----------------------------------------------------------------------
    // 6d. Scheduled FortiGate config backup task (daily)
    // -----------------------------------------------------------------------
    daemon::spawn_backup_scheduler(Arc::clone(&state), conn.clone());

    // -----------------------------------------------------------------------
    // 7. Run until SIGTERM / SIGINT
    // -----------------------------------------------------------------------
    wait_for_signal().await;
    info!("supermgrd shutting down");

    // -----------------------------------------------------------------------
    // 8. Shutdown cleanup — disconnect active backend and remove kill switch
    // -----------------------------------------------------------------------
    // This ensures that if the daemon is stopped via SIGTERM (e.g. by systemd
    // on reboot/restart) the kill-switch nftables table is removed and the VPN
    // tunnel is torn down gracefully, rather than leaving the system with all
    // traffic blocked and an orphaned tunnel.
    {
        let backend = {
            let mut s = state.lock().await;
            s.active_backend.take()
        };
        if let Some(b) = backend {
            info!("supermgrd shutdown: disconnecting active backend");
            // Disconnect first (while kill switch is still active) so there is
            // no window where traffic can bypass the VPN unprotected.  The kill
            // switch allows traffic to the VPN server IP, so the disconnect
            // subprocess can still reach the server to send a clean-close.
            if let Err(e) = b.disconnect().await {
                warn!("supermgrd shutdown: disconnect error: {e}");
            }
            daemon::remove_kill_switch().await;
        } else {
            // No active backend — still remove any stale kill-switch table in
            // case it was left over from a previous abnormal exit.
            daemon::remove_kill_switch().await;
        }
    }

    Ok(())
}

/// Scan `/sys/class/net/` for stale WireGuard interfaces left by a previous
/// crash and remove them.
///
/// Our interfaces follow the pattern `wg[0-9a-f]{8}` — exactly 10 characters,
/// the prefix `wg` followed by the first 8 hex digits of a profile UUID
/// (e.g. `wg7e59fe75`).
///
/// For each matching interface:
/// 1. `resolvectl revert <iface>` — remove any per-link DNS state from
///    systemd-resolved before the interface disappears.
/// 2. `ip link delete <iface>` — tear down the WireGuard interface; the kernel
///    automatically removes all routes whose `dev` is that interface.
/// 3. Check whether a default IPv4 route still exists; if not, log a warning
///    that manual route restoration may be needed (we cannot know the original
///    gateway after a crash).
///
/// All errors are logged but do not abort startup.
async fn cleanup_stale_strongswan() {
    // Terminate any strongSwan IKE SAs left by a previous daemon instance.
    // Our connections use the naming convention `supermgr-<hex>`.
    let out = tokio::process::Command::new("swanctl")
        .args(["--list-sas", "--raw"])
        .output()
        .await;

    let stdout = match out {
        Ok(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Ok(ref o) => {
            // swanctl may not be installed — that's fine.
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.contains("command not found") {
                warn!("swanctl --list-sas: exit={} stderr={:?}", o.status, stderr.trim());
            }
            return;
        }
        Err(e) => {
            // swanctl binary not found — no strongSwan SAs to clean.
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("swanctl --list-sas: {e}");
            }
            return;
        }
    };

    // Find our connection names (supermgr-*) and terminate them.
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("supermgr-") && trimmed.contains(':') {
            let name = trimmed.split(':').next().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            info!("terminating stale strongSwan SA: {name}");
            let term = tokio::process::Command::new("swanctl")
                .args(["--terminate", "--ike", name])
                .output()
                .await;
            match term {
                Ok(o) if o.status.success() => {
                    info!("terminated stale SA: {name}");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    warn!("failed to terminate SA {name}: {}", stderr.trim());
                }
                Err(e) => warn!("swanctl --terminate: {e}"),
            }
        }
    }
}

async fn cleanup_stale_interfaces() {
    let stale = match find_stale_interfaces() {
        Ok(v) => v,
        Err(e) => {
            error!("stale interface scan failed: {e}");
            return;
        }
    };

    if stale.is_empty() {
        return;
    }

    info!("{} stale WireGuard interface(s) found: {}", stale.len(), stale.join(", "));

    for iface in &stale {
        // ---- Step 1: revert systemd-resolved DNS state ---------------------
        let revert_out = tokio::process::Command::new("resolvectl")
            .args(["revert", iface])
            .output()
            .await;

        match revert_out {
            Ok(out) if out.status.success() => {
                info!("resolvectl revert {iface} — ok");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                warn!(
                    "resolvectl revert {iface} — exit={} stderr={:?} (continuing)",
                    out.status,
                    stderr.trim()
                );
            }
            Err(e) => warn!("resolvectl revert {iface}: spawn failed: {e} (continuing)"),
        }

        // ---- Step 2: delete the interface ----------------------------------
        let del_out = tokio::process::Command::new("ip")
            .args(["link", "delete", iface])
            .output()
            .await;

        match del_out {
            Ok(out) if out.status.success() => {
                info!("cleaned up stale WireGuard interface: {iface}");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                error!(
                    "ip link delete {iface} — exit={} stderr={:?}",
                    out.status,
                    stderr.trim()
                );
            }
            Err(e) => error!("ip link delete {iface}: spawn failed: {e}"),
        }
    }

    // ---- Step 3: check whether a default IPv4 route survived ---------------
    check_default_route_after_cleanup().await;
}

/// Return the list of network interface names under `/sys/class/net/` that
/// match the pattern `wg[0-9a-f]{8}` (exactly 10 characters).
fn find_stale_interfaces() -> std::io::Result<Vec<String>> {
    let mut found = Vec::new();

    for entry in std::fs::read_dir("/sys/class/net")? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();

        if is_our_wg_interface(&name) {
            found.push(name.into_owned());
        }
    }

    Ok(found)
}

/// Return `true` if `name` matches `wg[0-9a-f]{8}` (exactly 10 chars,
/// starts with `wg`, followed by exactly 8 lowercase hex digits).
fn is_our_wg_interface(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 10
        && bytes[0] == b'w'
        && bytes[1] == b'g'
        && bytes[2..].iter().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// After deleting stale interfaces, verify that an IPv4 default route still
/// exists.  If the machine was left without one (because supermgrd crashed while
/// a full-tunnel connection was active and had displaced the original default),
/// log a prominent warning — we cannot reconstruct the original gateway, so
/// the operator must restore routing manually or reboot / re-run DHCP.
async fn check_default_route_after_cleanup() {
    let out = tokio::process::Command::new("ip")
        .args(["route", "show", "exact", "0.0.0.0/0"])
        .output()
        .await;

    match out {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim().is_empty() {
                warn!(
                    "no default IPv4 route found after stale interface cleanup — \
                     the previous daemon may have crashed while a full-tunnel \
                     connection was active and the original default route was \
                     not restored. Manual intervention may be required: \
                     check `ip route` and restore the gateway, or run \
                     `systemctl restart systemd-networkd` to re-acquire \
                     the route via DHCP."
                );
            } else {
                info!("default IPv4 route present: {}", stdout.lines().next().unwrap_or("").trim());
            }
        }
        Err(e) => warn!("could not check default route after cleanup: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Ring-buffer tracing layer
// ---------------------------------------------------------------------------

/// A `tracing_subscriber` layer that captures formatted log lines into an
/// in-memory ring buffer so they can be retrieved via the `GetLogs` D-Bus
/// method.
struct RingLayer {
    buf: Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    cap: usize,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RingLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        use tracing::field::{Field, Visit};

        struct Visitor {
            message: String,
            extras: Vec<String>,
        }
        impl Visit for Visitor {
            fn record_str(&mut self, f: &Field, v: &str) {
                if f.name() == "message" {
                    self.message = v.to_owned();
                } else {
                    self.extras.push(format!("{}={:?}", f.name(), v));
                }
            }
            fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
                if f.name() == "message" {
                    // tracing formats &str message fields via Debug — strip outer quotes
                    let s = format!("{v:?}");
                    self.message = s.trim_matches('"').to_owned();
                } else {
                    self.extras.push(format!("{}={:?}", f.name(), v));
                }
            }
        }

        let mut v = Visitor { message: String::new(), extras: Vec::new() };
        event.record(&mut v);

        let meta = event.metadata();
        let mut line = format!(
            "[{}] {:<5} {}: {}",
            chrono::Local::now().format("%H:%M:%S"),
            meta.level().as_str(),
            meta.target(),
            v.message,
        );
        if !v.extras.is_empty() {
            line.push(' ');
            line.push_str(&v.extras.join(" "));
        }

        let mut buf = self.buf.lock().unwrap_or_else(|e| e.into_inner());
        if buf.len() >= self.cap {
            buf.pop_front();
        }
        buf.push_back(line);
    }
}

/// Block until SIGTERM or SIGINT is received.
async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM"),
        _ = sigint.recv()  => info!("received SIGINT"),
    }
}
