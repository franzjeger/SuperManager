//! `supermgrd` — privileged VPN + SSH manager daemon.
//!
//! # Startup sequence
//!
//! 1. Initialise `tracing` subscriber (log to stdout / journald).
//! 2. Connect to the system D-Bus and acquire `org.supermgr.Daemon` exclusively
//!    (`DoNotQueue`, without replacement) so duplicate instances exit immediately
//!    before touching any network interfaces, routes, or nftables (`P2-33`).
//! 3. Select the profile directory based on effective UID (root -> system path,
//!    non-root -> XDG user path for development) and load profiles, customers,
//!    SSH keys, and SSH hosts.
//! 4. Restore any persisted active kill-switch rules BEFORE cleaning stale
//!    interfaces or removing stale nftables tables (`P2-30`).
//! 5. Clean up any stale WireGuard interfaces, policy routing rules (`P2-31`),
//!    strongSwan SAs, and DNS dummy devices left by a previous crash.
//! 6. Register the `DaemonService` object at `/org/supermgr/Daemon`.
//! 7. Spawn background monitoring, auto-connect, sleep-resume (`P2-39`),
//!    health-check, and backup scheduler tasks.
//! 8. Block on the `zbus` connection loop until SIGTERM / SIGINT, preserving
//!    active persisted kill-switch rules across daemon shutdown (`P2-30`).
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
mod backup_retention;
mod daemon;
mod docs;
mod opnsense;
mod polkit;
mod recon;
mod secrets;
mod secure_file;
mod sophos;
mod ssh;
mod subprocess;
mod tailscale;
mod tailscale_accounts;
mod tailscale_diagnostics;
mod tailscale_exit;
mod tailscale_management;
mod vpn;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use tokio::sync::{watch, Mutex};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{
    fmt, layer::SubscriberExt as _, reload, util::SubscriberInitExt as _, EnvFilter,
};

use daemon::{DaemonService, DaemonState};
use supermgr_core::dbus::{DBUS_OBJECT_PATH, DBUS_SERVICE};

/// Profile directory used when the daemon runs as root (production / systemd).
const SYSTEM_PROFILE_DIR: &str = "/etc/supermgrd/profiles";

/// Stats polling interval.
const STATS_POLL_INTERVAL: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // -----------------------------------------------------------------------
    // 1. Logging — fmt layer (stdout) + file layer + ring-buffer layer
    // -----------------------------------------------------------------------
    let log_buffer: Arc<std::sync::Mutex<std::collections::VecDeque<String>>> = Arc::new(
        std::sync::Mutex::new(std::collections::VecDeque::with_capacity(500)),
    );

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter, filter_reload_handle) = reload::Layer::new(filter);

    // Persistent log file: /var/log/supermgrd/ when root, else $XDG_STATE_HOME/supermgrd/
    let log_dir = if nix::unistd::getuid().is_root() {
        PathBuf::from("/var/log/supermgrd")
    } else {
        let xdg_state = std::env::var("XDG_STATE_HOME").ok();
        let home = std::env::var("HOME").ok();
        supermgr_core::paths::try_xdg_state_base(xdg_state.as_deref(), home.as_deref())
            .map_err(anyhow::Error::msg)?
            .join("supermgrd")
    };

    let log_path = log_dir.join("supermgrd.log");
    let file_layer = match setup_file_layer(&log_dir, &log_path) {
        Ok(layer) => Some(layer),
        Err(e) => {
            eprintln!(
                "warning: could not set up log file at {}: {e}",
                log_path.display()
            );
            None
        }
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .with(file_layer)
        .with(RingLayer {
            buf: Arc::clone(&log_buffer),
            cap: 500,
        })
        .init();

    // Wrap the reload handle in a closure so DaemonService doesn't need the full generic type.
    let filter_reload_handle = Arc::new(filter_reload_handle);
    let set_log_level: daemon::LogLevelSetter = {
        let handle = Arc::clone(&filter_reload_handle);
        Arc::new(move |level: &str| {
            let new_filter = EnvFilter::try_new(level)
                .map_err(|e| format!("invalid log level '{level}': {e}"))?;
            handle
                .reload(new_filter)
                .map_err(|e| format!("reload failed: {e}"))
        })
    };

    info!(version = env!("CARGO_PKG_VERSION"), "supermgrd starting");

    // -----------------------------------------------------------------------
    // 2. Singleton D-Bus bus name acquisition FIRST (`P2-33`)
    // -----------------------------------------------------------------------
    // Acquire `org.supermgr.Daemon` on the system bus with queueing and
    // replacement disabled BEFORE touching any network interfaces, routing
    // rules, strongSwan SAs, or nftables tables.  If another `supermgrd`
    // instance is already running (e.g. a duplicate `pkexec supermgrd`
    // invocation), exit immediately without disrupting active tunnels.
    let conn = zbus::Connection::system()
        .await
        .context("D-Bus system connection failed")?;

    acquire_singleton_bus_name(&conn).await?;

    // -----------------------------------------------------------------------
    // 3. Profile & SSH data stores
    // -----------------------------------------------------------------------
    // `SUPERMGRD_PROFILE_DIR` always wins; otherwise the directory is chosen
    // based on effective UID so the daemon works for both production (root,
    // system path) and development (non-root, XDG user path).
    let profile_dir = match std::env::var("SUPERMGRD_PROFILE_DIR") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ if nix::unistd::getuid().is_root() => PathBuf::from(SYSTEM_PROFILE_DIR),
        _ => supermgr_core::paths::try_default_data_dir()
            .map_err(anyhow::Error::msg)?
            .join("profiles"),
    };

    info!("profile directory: {}", profile_dir.display());

    let mut daemon_state =
        DaemonState::new(profile_dir).context("failed to initialise daemon state")?;
    daemon_state
        .load_profiles()
        .context("failed to load profiles")?;
    daemon_state
        .load_customers()
        .context("failed to load customer catalog")?;

    let profile_count = daemon_state.profiles.len();
    info!("loaded {} VPN profile(s)", profile_count);
    info!("loaded {} customer(s)", daemon_state.customers.len());

    // -----------------------------------------------------------------------
    // 3b. SSH data (keys and hosts)
    // -----------------------------------------------------------------------
    daemon_state
        .load_ssh_keys()
        .context("failed to load SSH keys")?;
    daemon_state
        .load_hosts()
        .context("failed to load SSH hosts")?;
    let ssh_key_count = daemon_state.ssh_keys.len();
    let ssh_host_count = daemon_state.hosts.len();
    info!(
        "loaded {} SSH key(s), {} SSH host(s)",
        ssh_key_count, ssh_host_count
    );

    // Report credentials whose owning profile/host/key is gone. Deletes
    // before this release removed the record only, so an install of any age
    // is likely carrying some — and `export_all` puts them in the backup
    // archive. Advisory: it logs, it does not delete.
    daemon::audit_orphaned_secrets(&daemon_state).await;

    // -----------------------------------------------------------------------
    // 4. Persisted kill-switch recovery BEFORE stale interface cleanup (`P2-30`)
    // -----------------------------------------------------------------------
    // Re-apply persisted active kill-switch rules atomically before tearing
    // down stale interfaces or removing any orphan nftables table so crash
    // recovery never opens an unencrypted traffic window.
    daemon::restore_or_cleanup_kill_switch(&mut daemon_state).await;

    // -----------------------------------------------------------------------
    // 5. Stale interface, policy routing, and SA cleanup from previous crash
    // -----------------------------------------------------------------------
    cleanup_stale_interfaces().await;
    cleanup_stale_strongswan().await;
    // Remove any leftover FortiGate DNS dummy from a previous crash so
    // systemd-resolved doesn't keep stale state pinned to a dead link.
    crate::vpn::fortigate::remove_dns_dummy().await;

    if let Err(error) = tailscale_accounts::recover().await {
        tracing::warn!("Tailscale account recovery: {error}");
    }

    let state = Arc::new(Mutex::new(daemon_state));

    // -----------------------------------------------------------------------
    // 6. Register D-Bus object on the already-owned bus connection
    // -----------------------------------------------------------------------
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let sleep_shutdown_rx = shutdown_tx.subscribe();

    let service = DaemonService {
        state: Arc::clone(&state),
        shutdown_tx,
        log_buffer,
        set_log_level,
    };

    conn.object_server()
        .at(DBUS_OBJECT_PATH, service)
        .await
        .context("failed to register D-Bus object")?;

    info!(
        "D-Bus service '{}' registered at '{}'",
        DBUS_SERVICE, DBUS_OBJECT_PATH
    );

    // -----------------------------------------------------------------------
    // 7. Background tasks
    // -----------------------------------------------------------------------
    daemon::spawn_monitor_task(
        Arc::clone(&state),
        conn.clone(),
        shutdown_rx,
        STATS_POLL_INTERVAL,
    );

    // 7b. Auto-reconnect task (queries initial NM state + watches StateChanged, `P2-32`)
    daemon::spawn_autoconnect_task(Arc::clone(&state), conn.clone());

    // 7c. Suspend/resume recovery task (`org.freedesktop.login1.Manager.PrepareForSleep`, `P2-39`)
    daemon::spawn_sleep_monitor_task(Arc::clone(&state), conn.clone(), sleep_shutdown_rx);

    // 7d. SSH host health-check task (TCP-probes hosts every 60 s)
    daemon::spawn_health_check_task(Arc::clone(&state), conn.clone());

    // 7e. Scheduled FortiGate config backup task (daily)
    daemon::spawn_backup_scheduler(Arc::clone(&state), conn.clone());

    // -----------------------------------------------------------------------
    // 8. Run until SIGTERM / SIGINT
    // -----------------------------------------------------------------------
    wait_for_signal().await;
    info!("supermgrd shutting down");

    // -----------------------------------------------------------------------
    // 9. Shutdown cleanup — disconnect active backend & preserve persisted kill switch (`P2-30`)
    // -----------------------------------------------------------------------
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
        }
        daemon::shutdown_kill_switch(&state).await;
    }

    Ok(())
}

/// Acquire `org.supermgr.Daemon` on the system bus with queueing and owner
/// replacement disabled (`P2-33`).
async fn acquire_singleton_bus_name(conn: &zbus::Connection) -> anyhow::Result<()> {
    let reply = conn
        .request_name_with_flags(
            DBUS_SERVICE,
            zbus::fdo::RequestNameFlags::DoNotQueue.into(),
        )
        .await
        .with_context(|| {
            format!(
                "failed to acquire D-Bus name '{DBUS_SERVICE}' — another supermgrd instance may already be running"
            )
        })?;

    match reply {
        zbus::fdo::RequestNameReply::PrimaryOwner
        | zbus::fdo::RequestNameReply::AlreadyOwner => Ok(()),
        other => anyhow::bail!(
            "another supermgrd instance already owns '{DBUS_SERVICE}' ({other:?}); exiting without touching network state"
        ),
    }
}

/// Terminate any stale strongSwan IKE SAs (`supermgr-*`) left by a previous crash.
async fn cleanup_stale_strongswan() {
    let cmd_timeout = Duration::from_secs(10);
    let out =
        crate::subprocess::run_system_cmd(&["swanctl"], &["--list-sas", "--raw"], cmd_timeout)
            .await;

    let stdout = match out {
        Ok(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Ok(ref o) => {
            // swanctl may not be installed or charon may be stopped — that's fine.
            let stderr = String::from_utf8_lossy(&o.stderr);
            if crate::vpn::fortigate::charon_unreachable(&stderr) {
                debug!("startup cleanup: strongSwan/charon is not running");
            } else if !stderr.contains("command not found") {
                let message = crate::vpn::fortigate::strip_usage_block(&stderr);
                warn!("swanctl --list-sas: exit={} stderr={message:?}", o.status);
            }
            return;
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("swanctl --list-sas: {e}");
            }
            return;
        }
    };

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("supermgr-") && trimmed.contains(':') {
            let name = trimmed.split(':').next().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            info!("terminating stale strongSwan SA: {name}");
            let term = crate::subprocess::run_system_cmd(
                &["swanctl"],
                &["--terminate", "--ike", name],
                cmd_timeout,
            )
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

/// Scan `/sys/class/net/` for stale WireGuard interfaces (`wg[0-9a-f]{8}`) left
/// by a previous crash, remove them, and clean up policy-routing rules (`P2-31`).
async fn cleanup_stale_interfaces() {
    let cmd_timeout = Duration::from_secs(10);
    let stale = match find_stale_interfaces() {
        Ok(v) => v,
        Err(e) => {
            error!("stale interface scan failed: {e}");
            crate::vpn::wireguard::cleanup_policy_rules(true, true).await;
            return;
        }
    };

    if stale.is_empty() {
        crate::vpn::wireguard::cleanup_policy_rules(true, true).await;
        return;
    }

    info!(
        "{} stale WireGuard interface(s) found: {}",
        stale.len(),
        stale.join(", ")
    );

    for iface in &stale {
        // ---- Step 1: revert systemd-resolved DNS state ---------------------
        let revert_out =
            crate::subprocess::run_system_cmd(&["resolvectl"], &["revert", iface], cmd_timeout)
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
            Err(e) => warn!("resolvectl revert {iface}: failed: {e} (continuing)"),
        }

        // ---- Step 2: delete the interface ----------------------------------
        let del_out =
            crate::subprocess::run_system_cmd(&["ip"], &["link", "delete", iface], cmd_timeout)
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
            Err(e) => error!("ip link delete {iface}: failed: {e}"),
        }
    }

    // ---- Step 2b: clean up any leftover WireGuard policy-routing rules -----
    crate::vpn::wireguard::cleanup_policy_rules(true, true).await;

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
        && bytes[2..]
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// After deleting stale interfaces, verify that an IPv4 default route still
/// exists in the main table.
async fn check_default_route_after_cleanup() {
    let out = crate::subprocess::run_system_cmd(
        &["ip"],
        &["route", "show", "exact", "0.0.0.0/0"],
        Duration::from_secs(5),
    )
    .await;

    match out {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim().is_empty() {
                warn!(
                    "no default IPv4 route found after stale interface cleanup — \
                     check `ip route` and restore the gateway, or run \
                     `systemctl restart systemd-networkd` to re-acquire \
                     the route via DHCP."
                );
            } else {
                info!(
                    "default IPv4 route present: {}",
                    stdout.lines().next().unwrap_or("").trim()
                );
            }
        }
        Err(e) => warn!("could not check default route after cleanup: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Persistent file logging
// ---------------------------------------------------------------------------

/// Maximum log file size before rotation (10 MB).
const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum number of rotated log files to keep.
const LOG_ROTATE_KEEP: u32 = 3;

/// Rotate `supermgrd.log` → `.log.1` → `.log.2` → `.log.3`, removing the oldest.
fn rotate_log_file(log_path: &std::path::Path) {
    for i in (1..LOG_ROTATE_KEEP).rev() {
        let src = log_path.with_extension(format!("log.{i}"));
        let dst = log_path.with_extension(format!("log.{}", i + 1));
        let _ = std::fs::rename(&src, &dst);
    }
    let dst = log_path.with_extension("log.1");
    let _ = std::fs::rename(log_path, &dst);
}

/// Create the log directory, rotate if the file is too large, and return a
/// `tracing_subscriber` layer that writes to the file.
fn setup_file_layer<S>(
    log_dir: &std::path::Path,
    log_path: &std::path::Path,
) -> anyhow::Result<
    fmt::Layer<S, fmt::format::DefaultFields, fmt::format::Format, std::sync::Arc<std::fs::File>>,
>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    std::fs::create_dir_all(log_dir)
        .with_context(|| format!("create log dir {}", log_dir.display()))?;

    // Rotate on startup if the file exceeds the size limit.
    if let Ok(meta) = std::fs::metadata(log_path) {
        if meta.len() >= LOG_MAX_BYTES {
            rotate_log_file(log_path);
        }
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("open log file {}", log_path.display()))?;

    let file = std::sync::Arc::new(file);

    Ok(fmt::layer().with_writer(file).with_ansi(false))
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

        let mut v = Visitor {
            message: String::new(),
            extras: Vec::new(),
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wg_interface_name_matcher_is_strict() {
        assert!(is_our_wg_interface("wg7e59fe75"));
        assert!(is_our_wg_interface("wg00000000"));
        assert!(!is_our_wg_interface("wg0"));
        assert!(!is_our_wg_interface("wg7E59FE75"));
        assert!(!is_our_wg_interface("wg7e59fe750"));
        assert!(!is_our_wg_interface("eth0"));
    }

    #[test]
    fn startup_acquires_dbus_name_before_kill_switch_and_interface_cleanup() {
        let src = include_str!("main.rs");
        let fn_main = src
            .split("async fn main()")
            .nth(1)
            .and_then(|rest| rest.split("\nasync fn acquire_singleton_bus_name").next())
            .expect("main() body");

        let acquire_pos = fn_main
            .find("acquire_singleton_bus_name(&conn).await?")
            .expect("singleton D-Bus name acquisition in main()");
        let ks_restore_pos = fn_main
            .find("daemon::restore_or_cleanup_kill_switch(&mut daemon_state).await")
            .expect("persisted kill-switch recovery in main()");
        let stale_cleanup_pos = fn_main
            .find("cleanup_stale_interfaces().await")
            .expect("stale interface cleanup in main()");
        let sleep_monitor_pos = fn_main
            .find("daemon::spawn_sleep_monitor_task(")
            .expect("PrepareForSleep monitor spawn in main()");
        let shutdown_ks_pos = fn_main
            .find("daemon::shutdown_kill_switch(&state).await")
            .expect("shutdown kill-switch preservation in main()");

        assert!(
            acquire_pos < ks_restore_pos,
            "D-Bus singleton name MUST be acquired before touching kill-switch state"
        );
        assert!(
            ks_restore_pos < stale_cleanup_pos,
            "persisted kill-switch MUST be restored before tearing down stale interfaces"
        );
        assert!(stale_cleanup_pos < sleep_monitor_pos);
        assert!(sleep_monitor_pos < shutdown_ks_pos);
        assert!(
            !fn_main.contains("daemon::remove_kill_switch()"),
            "main() must not unconditionally wipe active persisted kill-switch rules"
        );
    }
}
