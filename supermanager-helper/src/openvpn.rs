//! OpenVPN tunnel control for SuperManager's privileged helper.
//!
//! ## Architecture
//!
//! `brew install openvpn` puts the canonical OpenVPN 2.x CLI at
//! `<brew>/sbin/openvpn`. We launch one OpenVPN process per active
//! profile, supervised by this helper. The child writes its PID to
//! `/var/run/supermgr-ovpn-<sanitized-id>.pid` (via the `--writepid`
//! flag), so disconnect / status look up the PID from there.
//!
//! ## What the GUI sends us
//!
//! - `profile_id` (UUID from the daemon)
//! - `config_file` — absolute path to the `.ovpn` already on disk
//!   under `<data_dir>/ovpn/<id>.ovpn` (placed there by the daemon's
//!   `vpn_import_openvpn` handler at import time, mode 0600)
//! - optionally `username` + `password` for `--auth-user-pass`
//!   profiles; we materialise the creds into a 0600 root-owned file
//!   under `/var/run/`, hand the path to `openvpn`, and `unlink()`
//!   immediately after — the kernel keeps the inode alive while the
//!   child holds the fd, but no other process can `open()` it
//!
//! ## Logging
//!
//! Each session logs to `/var/log/supermgr-ovpn-<sanitized-id>.log`.
//! The privileged helper reads / tails it for the GUI. We don't
//! currently rotate these — TODO once we ship to non-developer users.
//!
//! ## Why not openvpn3 / Tunnelblick / OpenVPN Connect?
//!
//! `openvpn3` brews cleanly but its session model is much heavier
//! and the project is moving towards a Cloud-Connect-only future.
//! Tunnelblick / OpenVPN Connect are full GUIs we'd have to drive
//! over AppleScript / mobileconfig — clunky and brittle. The plain
//! `openvpn` 2.x CLI is rock-solid, scriptable, and what every
//! integration tutorial assumes. Less work, fewer moving parts.

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;


/// Where we keep per-profile PID files.
const PID_DIR: &str = "/var/run";
/// Root-private logs; status RPCs expose bounded diagnostic output.
const LOG_DIR: &str = "/private/var/log/supermanager";

#[derive(Default)]
pub struct OpenVpn {}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OpenVpnEngine {
    #[default]
    Openvpn2,
    Openvpn3,
}

#[derive(Deserialize)]
pub struct OvpnConnectArgs {
    #[serde(default)]
    pub engine: OpenVpnEngine,
    pub profile_id: String,
    pub config_file: String,
    /// Optional credentials for `--auth-user-pass` profiles.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OvpnDisconnectArgs {
    pub profile_id: String,
}

#[derive(Debug, Deserialize)]
pub struct OvpnStatusArgs {
    pub profile_id: String,
}

#[derive(Debug, Serialize)]
pub struct OvpnConnectResult {
    pub success: bool,
    pub message: String,
    /// Path the GUI can read for failure diagnosis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OvpnDisconnectResult {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct OvpnStatusResult {
    pub state: OvpnState,
    /// PID of the running `openvpn` child, or None if the tunnel
    /// isn't up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Kernel interface the tunnel is bound to (e.g. `utun8`).
    /// Parsed from the `EVENT: CONNECTED` line ovpncli emits, or
    /// from `TUN/TAP device` for openvpn 2.x. Absent when status
    /// is anything but `connected`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Virtual IP the gateway assigned this client (e.g.
    /// `10.134.2.3`). Same parse-from-log story as `interface`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_ip: Option<String>,
    /// Gateway the gateway pushed (e.g. `10.134.2.1`). For
    /// full-tunnel profiles this is what 0.0.0.0/0 routes via.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_gateway: Option<String>,
    /// CIDRs the gateway pushed at connect time. Each entry is
    /// already in `network/prefix` form (e.g. `10.134.0.0/23`).
    /// Order is the order the routes appeared in the log, so the
    /// GUI can render them deterministically.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub active_routes: Vec<String>,
    /// Cumulative bytes received on the tunnel interface since
    /// it came up. Pulled from `netstat -ibn -I <iface>` — same
    /// counters the kernel exposes via the `if_data` struct.
    /// Absent when the tunnel isn't up. The GUI computes a
    /// per-second rate by diffing successive polls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bytes: Option<u64>,
    /// Last error extracted from the VPN log when state is
    /// `reconnecting` or `disconnected`. e.g.
    /// `"TRANSPORT_ERROR: NETWORK_EOF_ERROR"` or `"AUTH_FAILED"`.
    /// Absent when connected or no diagnostic is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OvpnState {
    /// Tunnel is up and the log confirms the VPN session is
    /// established (`EVENT: CONNECTED` or `Initialization Sequence
    /// Completed`). Safe to pass traffic.
    Connected,
    /// Process is alive but the tunnel has not negotiated yet —
    /// initial connect in progress (TLS handshake, auth, push
    /// directives). Different from `Reconnecting` because we have
    /// never been connected in this process lifetime.
    Connecting,
    /// Process is alive but the last log event was
    /// `TRANSPORT_ERROR` or `RECONNECTING`: a previously working
    /// session dropped and the client is retrying. The GUI should
    /// show a warning state (amber dot) rather than "Connected",
    /// and surface the last error so the user knows why.
    Reconnecting,
    Disconnected,
}

impl OpenVpn {
    pub fn new() -> Self {
        Self::default()
    }

    /// Spin up an `openvpn` child for this profile. Daemon mode
    /// (`--daemon`) detaches from us — the child keeps running on
    /// its own and writes its PID to the file we pass via
    /// `--writepid`.
    pub async fn connect(&mut self, args: &OvpnConnectArgs) -> anyhow::Result<OvpnConnectResult> {
        crate::vpn_input::profile_id(&args.profile_id)?;
        let content = crate::secure_files::read_config(Path::new(&args.config_file), 1024 * 1024)?;
        crate::vpn_input::openvpn(&content)?;
        for credential in [&args.username, &args.password].into_iter().flatten() {
            anyhow::ensure!(!credential.chars().any(char::is_control), "Credential contains control characters");
        }
        let openvpn = locate_openvpn(args.engine)?;
        let is_v3 = args.engine == OpenVpnEngine::Openvpn3;
        if is_v3 {
            anyhow::ensure!(args.password.as_ref().is_some_and(|p| !p.is_empty() && p.len() <= 65536), "OpenVPN 3 requires a nonempty credential of at most 65536 bytes");
        }
        // Run only the validated snapshot from a root-private directory.
        let directory = Path::new("/Library/PrivilegedHelperTools/SuperManagerVPNConfigs");
        crate::secure_files::ensure_root_directory(directory)?;
        let snapshot = directory.join(format!("{}.ovpn", uuid::Uuid::parse_str(&args.profile_id)?.simple()));
        crate::secure_files::write_private(&snapshot, content.as_bytes())?;
        let args = OvpnConnectArgs { profile_id: args.profile_id.clone(),
            config_file: snapshot.to_string_lossy().into_owned(),
            username: args.username.clone(), password: args.password.clone(), engine: args.engine };
        tracing::info!(
            "ovpn_connect: profile={} config={} openvpn={}",
            args.profile_id,
            args.config_file,
            openvpn.display()
        );

        // Suppress the connectivity watchdog during the connect/handshake window.
        // A full-tunnel OpenVPN/Azure profile installs 0/1+128/1 and briefly has
        // no working egress while TLS/auth/route-push complete; without this the
        // watchdog would count that as an outage and fire panic_reset, ripping
        // the just-installed split-defaults out from under the connecting tunnel.
        // The reconciler arms the same pause around its own route work.
        crate::connectivity_watchdog::pause_for(45);

        // Pre-flight: refuse to launch if the .ovpn doesn't exist.
        // Otherwise the failure surfaces only via the log file the
        // child never finished writing.
        if !Path::new(&args.config_file).exists() {
            tracing::error!("ovpn_connect: config file missing: {}", args.config_file);
            return Err(anyhow!(
                "config file does not exist: {}",
                args.config_file
            ));
        }
        // Stat the config so we know what we're dealing with —
        // size (sanity check the daemon actually wrote it),
        // permissions (root vs user), inline-key presence.
        if let Ok(meta) = std::fs::metadata(&args.config_file) {
            tracing::info!(
                "ovpn_connect: config size={} bytes, mode={:o}",
                meta.len(),
                std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777,
            );
        }
        if let Ok(body) = std::fs::read_to_string(&args.config_file) {
            tracing::info!(
                "ovpn_connect: config has_remote={} has_ca={} has_tls_auth={} has_tls_crypt={} has_auth_user_pass={}",
                body.contains("\nremote ") || body.starts_with("remote "),
                body.contains("<ca>"),
                body.contains("<tls-auth>"),
                body.contains("<tls-crypt>"),
                body.contains("auth-user-pass"),
            );
        }

        crate::vpn_input::profile_id(&args.profile_id)?;
        let safe = sanitize_id(&args.profile_id);
        let pid_path = pid_path_for(&safe);
        let log_path = log_path_for(&safe);

        anyhow::ensure!(find_openvpn_pid_for(&safe).await.is_none(), "This OpenVPN profile is already running");

        // Truncate the log before spawn. Otherwise our post-spawn
        // diagnostic check (`FATAL.iter().find(|m| log_body.contains(m))`)
        // sees stale errors from previous failed attempts that
        // haven't been GC'd — particularly when openvpn 2.x's
        // `--daemon` retry loop keeps appending its own failures
        // to the same path. Fresh log per spawn = unambiguous
        // diagnostics.
        crate::secure_files::write_private(&log_path, b"")?;
        // Same for the PID file — a stale PID from a previous
        // attempt causes the post-spawn `kill(pid, 0)` aliveness
        // check to spuriously claim a different process is "the
        // daemon."
        let _ = std::fs::remove_file(&pid_path);

        let auth_path = if !is_v3 && args.username.is_some() && args.password.is_some() {
            let u = args.username.as_deref().unwrap();
            let p = args.password.as_deref().unwrap();
            tracing::info!(
                "ovpn_connect: writing auth file (username={}, password={} chars)",
                u,
                p.len()
            );
            Some(write_auth_file(&safe, u, p)?)
        } else {
            tracing::info!("ovpn_connect: no auth-user-pass (no username/password)");
            None
        };

        // OpenVPN 3 reads its token from a bounded private stdin pipe. The
        // signed adapter refuses --password arguments; no token file is created.
        let output = if is_v3 {
            use tokio::io::AsyncWriteExt;
            let log_for_stdout = std::fs::OpenOptions::new()
                .write(true).truncate(true).custom_flags(libc::O_NOFOLLOW)
                .open(&log_path).context("open private OpenVPN log")?;
            let log_for_stderr = log_for_stdout.try_clone().context("dup log fd")?;
            let mut cmd = openvpn3_command(&openvpn, &args);
            cmd.stdout(log_for_stdout).stderr(log_for_stderr).kill_on_drop(true);
            let mut child = cmd.spawn().context("spawn managed OpenVPN 3")?;
            let pid = child.id().ok_or_else(|| anyhow!("OpenVPN 3 spawn returned no pid"))?;
            let mut input = child.stdin.take().context("OpenVPN 3 credential pipe missing")?;
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                input.write_all(args.password.as_deref().unwrap_or("").as_bytes()).await?;
                input.shutdown().await
            }).await.context("OpenVPN 3 credential delivery timed out")?
                .context("OpenVPN 3 credential delivery failed")?;
            drop(input);
            crate::secure_files::write_private(&pid_path, format!("{pid}\n").as_bytes())?;
            tokio::spawn(async move { let _ = child.wait().await; });
            std::process::Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: Vec::new(), stderr: Vec::new(),
            }
        } else {
            let mut argv: Vec<String> = vec![
                "--config".into(), args.config_file.clone(),
                "--daemon".into(), format!("supermgr-ovpn-{safe}"),
                "--writepid".into(), pid_path.display().to_string(),
                "--log".into(), log_path.display().to_string(),
                "--verb".into(), "3".into(),
            ];
            if let Some(ref auth) = auth_path {
                argv.push("--auth-user-pass".into());
                argv.push(auth.display().to_string());
            }
            tracing::info!("ovpn_connect: argv = {} {}", openvpn.display(), argv.join(" "));
            let mut cmd = Command::new(&openvpn);
            cmd.args(&argv);
            cmd.output().await.with_context(|| {
                format!("run {} --config {}", openvpn.display(), args.config_file)
            })?
        };
        tracing::info!(
            "ovpn_connect: child exited code={:?} stdout={} bytes stderr={} bytes",
            output.status.code(),
            output.stdout.len(),
            output.stderr.len()
        );
        if !output.stdout.is_empty() {
            tracing::info!(
                "ovpn_connect: stdout = {}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
        if !output.stderr.is_empty() {
            tracing::info!(
                "ovpn_connect: stderr = {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        // openvpn returns 0 on successful daemonisation. Any non-zero
        // exit means it bailed before going background — config
        // error, port conflict, no TUN module, etc.
        if !output.status.success() {
            // Auth file is a transient credential — wipe it on failure.
            if let Some(ref auth) = auth_path {
                let _ = std::fs::remove_file(auth);
            }
            // Diagnostics: stderr is usually empty for openvpn 2.x
            // because `--log <path>` redirects output to the log
            // file before the parser even starts. Read whatever
            // landed there so the GUI shows the real error
            // (config parse fail, "Cannot load CA certificate",
            // "Options error", etc.) instead of a bare "refused
            // to start".
            tracing::error!("ovpn_connect: NON-ZERO exit, reading {}", log_path.display());
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let log_tail = std::fs::read_to_string(&log_path)
                .ok()
                .map(|s| {
                    // Last ~20 non-empty lines is plenty — early
                    // openvpn errors fit comfortably and we don't
                    // want to flood the GUI alert.
                    let lines: Vec<&str> = s.lines()
                        .filter(|l| !l.trim().is_empty())
                        .collect();
                    let start = lines.len().saturating_sub(20);
                    lines[start..].join("\n")
                })
                .unwrap_or_default();
            let combined = match (stderr.is_empty(), log_tail.is_empty()) {
                (false, false) => format!("{stderr}\n--- log ---\n{log_tail}"),
                (true,  false) => log_tail,
                (false, true)  => stderr,
                (true,  true)  => format!("(no diagnostic output, see {})", log_path.display()),
            };
            tracing::error!("ovpn_connect: refused to start:\n{combined}");
            return Ok(OvpnConnectResult {
                success: false,
                message: format!("openvpn refused to start:\n{combined}"),
                log_path: Some(log_path.display().to_string()),
            });
        }
        tracing::info!("ovpn_connect: spawn succeeded for profile={}", args.profile_id);

        // Auth file was loaded by the now-running daemon. Unlink the
        // dirent — the running child still has the fd open, so it
        // can read further (auth-user-pass is single-shot) — the
        // file is gone from disk.
        if let Some(ref auth) = auth_path {
            let _ = std::fs::remove_file(auth);
        }

        // For openvpn 2.x in --daemon mode: the parent exits 0
        // the moment it forks, BEFORE the daemon child has done
        // any of the actual work (config parse, TLS handshake,
        // AAD token exchange). If anything fails after fork, we
        // see exit code 0 here but the tunnel never comes up.
        // Sleep briefly, then look at the log file — that's
        // where mid-handshake errors land — and at the PID file,
        // which the daemon writes once it's accepted the config.
        // If we see a fatal marker, treat it as a failure with
        // the log content even though the parent exited cleanly.
        if !is_v3 {
            // 5s settle window. We only abort when openvpn writes
            // a TRULY fatal marker (AUTH_FAILED, "Cannot load CA",
            // etc) or its PID disappears. Notably absent:
            // "Connection reset, restarting" — that's openvpn's
            // normal TCP-retry signal, NOT a fatal failure. The
            // gateway commonly resets the first connect attempt
            // and the daemon's retry succeeds; if we kill on the
            // first reset we sabotage our own retry loop. The
            // production Linux backend (`supermgrd/src/vpn/azure.rs`)
            // waits 60s for "Initialization Sequence Completed"
            // and only treats AUTH_FAILED as fatal — same idea.
            tracing::info!("ovpn_connect: waiting 5s for daemon child to settle…");
            tokio::time::sleep(std::time::Duration::from_millis(5000)).await;

            let log_body = std::fs::read_to_string(&log_path).unwrap_or_default();
            let pid_alive = read_pid_file(&pid_path)
                .map(|p| unsafe { libc::kill(p as i32, 0) } == 0)
                .unwrap_or(false);
            tracing::info!(
                "ovpn_connect: post-spawn check pid_alive={} log_size={}",
                pid_alive,
                log_body.len()
            );

            // Markers openvpn writes when it bails mid-handshake
            // *unrecoverably*. Recoverable signals (Connection
            // reset, soft restart) intentionally don't appear here
            // — the daemon retries those by design.
            const FATAL: &[&str] = &[
                "AUTH_FAILED",
                "auth-failure",
                "Cannot resolve host",
                "Fatal TLS error",
                "Options error",
                "Cannot load CA certificate",
                "Cannot load private key",
                "Cannot load inline certificate",
                "process exiting",
                "SIGTERM[soft,init_instance]",
            ];
            let fatal_hit = FATAL.iter().find(|m| log_body.contains(*m));

            if !pid_alive || fatal_hit.is_some() {
                let reason = fatal_hit
                    .map(|m| format!("openvpn died after fork — {m}"))
                    .unwrap_or_else(|| "openvpn died after fork (no PID, no fatal marker — see log)".to_owned());
                let log_tail = {
                    let lines: Vec<&str> = log_body.lines()
                        .filter(|l| !l.trim().is_empty())
                        .collect();
                    let start = lines.len().saturating_sub(25);
                    lines[start..].join("\n")
                };
                tracing::error!("ovpn_connect: post-fork failure: {reason}\n{log_tail}");
                return Ok(OvpnConnectResult {
                    success: false,
                    message: format!(
                        "{reason}\n\nLast 25 log lines from {}:\n{log_tail}",
                        log_path.display()
                    ),
                    log_path: Some(log_path.display().to_string()),
                });
            }
        }

        Ok(OvpnConnectResult {
            success: true,
            message: if is_v3 {
                format!("OpenVPN 3.x tunnel '{safe}' up — session managed by openvpn3 daemon")
            } else {
                format!("OpenVPN tunnel '{safe}' up")
            },
            // openvpn3 owns its own log; only the 2.x path has a
            // file we can hand back to the GUI's "View log" button.
            log_path: if is_v3 { None } else { Some(log_path.display().to_string()) },
        })
    }

    /// SIGTERM the running OpenVPN child(ren). First-pass uses the
    /// PID file; second-pass scans `ps` and kills anything else
    /// matching this profile's daemon-name fingerprint. The
    /// second pass catches tunnels whose PID file got out of sync
    /// (e.g. a previous app crash, a manually-cleared /var/run).
    pub async fn disconnect(
        &mut self,
        args: &OvpnDisconnectArgs,
    ) -> anyhow::Result<OvpnDisconnectResult> {
        crate::vpn_input::profile_id(&args.profile_id)?;
        let safe = sanitize_id(&args.profile_id);
        let pid_path = pid_path_for(&safe);
        let mut killed: Vec<u32> = Vec::new();

        // A PID file alone is insufficient: the PID may now belong to another
        // process or another profile. Resolve ownership before sending a signal.
        let stragglers = collect_openvpn_pids_for(&safe).await;
        for pid in stragglers {
            if killed.contains(&pid) { continue; }
            unsafe { libc::kill(pid as i32, libc::SIGTERM); }
            killed.push(pid);
        }

        // Cleanup files regardless of whether the kill landed —
        // sticking a stale PID file is worse than missing one
        // (next connect's read says "tunnel already up").
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(log_path_for(&safe));
        let snapshot = Path::new("/Library/PrivilegedHelperTools/SuperManagerVPNConfigs")
            .join(format!("{}.ovpn", uuid::Uuid::parse_str(&args.profile_id)?.simple()));
        let _ = std::fs::remove_file(snapshot);

        // Restore DNS. Both openvpn 2.x (via --up/--down scripts that
        // call networksetup) and ovpncli (via its platform DNS abstraction)
        // modify the system resolver on connect. SIGTERM should trigger
        // the --down script, but if openvpn exits uncleanly (SIGKILL,
        // crash, ovpncli receiving SIGTERM before its cleanup hook runs),
        // DNS changes are left behind. clear_vpn_dns is the guaranteed
        // cleanup that runs regardless of how the process exited.
        crate::dns::clear_vpn_dns();

        Ok(OvpnDisconnectResult {
            success: true,
            message: if killed.is_empty() {
                format!("OpenVPN tunnel '{safe}' was not running")
            } else {
                format!("OpenVPN tunnel '{safe}' down (killed {} process{})",
                    killed.len(), if killed.len() == 1 { "" } else { "es" })
            },
        })
    }

    /// Status check: try the PID file first (cheap, local), fall
    /// back to scanning `ps` for an `openvpn` process that has our
    /// per-profile config path in its argv. The fallback catches
    /// tunnels that survived a daemon restart or had their PID
    /// file deleted by hand — without it, `ovpn_status` returned
    /// "disconnected" while the user could see the actual tunnel
    /// in `ps aux`.
    ///
    /// **Connected vs Connecting**: a live PID alone is NOT enough
    /// to declare success. openvpn's `--daemon` mode forks before
    /// the TLS handshake even starts; for the first few seconds
    /// (or longer if the gateway resets the first attempt) the
    /// process is alive but no tunnel exists. We grep the log for
    /// `Initialization Sequence Completed` — openvpn writes that
    /// line exactly once, after IP / routes / DNS are all in place.
    /// Until it appears, status is `Connecting`. After it appears,
    /// `Connected`. This matches production Linux's contract where
    /// the connect path waits for the same marker before declaring
    /// the tunnel up.
    pub async fn status(&mut self, args: &OvpnStatusArgs) -> anyhow::Result<OvpnStatusResult> {
        crate::vpn_input::profile_id(&args.profile_id)?;
        let safe = sanitize_id(&args.profile_id);
        let pid_path = pid_path_for(&safe);
        let log_path = log_path_for(&safe);

        let live_pid = find_openvpn_pid_for(&safe).await;
        if live_pid.is_none() { let _ = std::fs::remove_file(&pid_path); }

        let Some(pid) = live_pid else {
            return Ok(OvpnStatusResult {
                state: OvpnState::Disconnected,
                pid: None,
                interface: None,
                virtual_ip: None,
                virtual_gateway: None,
                active_routes: Vec::new(),
                rx_bytes: None,
                tx_bytes: None,
                error_reason: None,
            });
        };

        // Process is alive. Determine the REAL tunnel state by
        // scanning the log for the LAST status event.
        //
        // Previous approach — body.contains("EVENT: CONNECTED") —
        // was wrong: it returned Connected even after the client
        // appended TRANSPORT_ERROR / RECONNECTING lines during
        // an automatic retry loop, so the UI showed green "Connected"
        // while the tunnel was stuck cycling through transport errors.
        //
        // last_event_from_log() scans every line and returns the
        // state implied by the FINAL status-bearing event plus a
        // short diagnostic string extracted from that line.
        let body = std::fs::read_to_string(&log_path).unwrap_or_default();
        let (tunnel_state, error_reason) = last_event_from_log(&body);
        let connected = tunnel_state == OvpnState::Connected;

        let (interface, virtual_ip, virtual_gateway) = parse_tunnel_metadata(&body);
        let active_routes = parse_active_routes(&body);

        // Byte counters and tunnel metadata are only meaningful when
        // the session is actually up. Clear them for reconnecting /
        // connecting states so the GUI never shows stale counters
        // from a previous session while the tunnel is broken.
        let (rx_bytes, tx_bytes) = match (connected, interface.as_deref()) {
            (true, Some(iface)) => read_iface_byte_counts(iface).await,
            _ => (None, None),
        };

        Ok(OvpnStatusResult {
            state: tunnel_state,
            pid: Some(pid),
            interface:        if connected { interface        } else { None },
            virtual_ip:       if connected { virtual_ip       } else { None },
            virtual_gateway:  if connected { virtual_gateway  } else { None },
            active_routes:    if connected { active_routes    } else { Vec::new() },
            rx_bytes,
            tx_bytes,
            error_reason,
        })
    }
}

// ── Log-state scanner ─────────────────────────────────────────────────────

/// Scan the VPN log from top to bottom and return the state
/// implied by the **last** status-bearing event, plus a short
/// diagnostic string taken from that line.
///
/// ## Why last-event matters
///
/// ovpncli appends to the log during automatic reconnect attempts.
/// A log that starts with `EVENT: CONNECTED` (initial session) but
/// then has `EVENT: TRANSPORT_ERROR` / `EVENT: RECONNECTING` lines
/// is **not** in a connected state — it's in a retry loop. Scanning
/// only for presence of `EVENT: CONNECTED` anywhere in the file
/// ("contains") was wrong; it returned Connected while the client
/// cycled through transport errors for hours.
///
/// ## State machine
///
/// ```text
/// initial (process alive, empty log) → Connecting
/// EVENT: CONNECTING / RESOLVE / WAIT  → Connecting  (or Reconnecting
///                                        if was_ever_connected)
/// EVENT: CONNECTED / "Initialization Sequence Completed"
///                                     → Connected
/// EVENT: TRANSPORT_ERROR              → Reconnecting
/// EVENT: RECONNECTING                 → Reconnecting
/// EVENT: AUTH_FAILED / "AUTH_FAILED"  → Disconnected  (permanent)
/// EVENT: DISCONNECTED                 → Disconnected
/// ```
///
/// `Reconnecting` is only possible when the process is alive;
/// callers already handle the dead-process → Disconnected path
/// before calling this function.
fn last_event_from_log(log: &str) -> (OvpnState, Option<String>) {
    let mut state = OvpnState::Connecting; // alive + no events = initial connect
    let mut reason: Option<String> = None;
    let mut was_ever_connected = false;

    for line in log.lines() {
        // ── ovpncli (OpenVPN 3.x) EVENT: lines ──────────────────
        if line.contains("EVENT: CONNECTED") {
            state = OvpnState::Connected;
            was_ever_connected = true;
            reason = None;
        } else if line.contains("EVENT: AUTH_FAILED") {
            state = OvpnState::Disconnected;
            reason = event_detail(line, "AUTH_FAILED");
        } else if line.contains("EVENT: DISCONNECTED") {
            state = OvpnState::Disconnected;
            reason = event_detail(line, "DISCONNECTED");
        } else if line.contains("EVENT: TRANSPORT_ERROR")
            || line.contains("EVENT: RECONNECTING")
        {
            state = OvpnState::Reconnecting;
            reason = event_detail(line, "EVENT:");
        } else if line.contains("EVENT: CONNECTING")
            || line.contains("EVENT: RESOLVE")
            || line.contains("EVENT: WAIT")
        {
            // Mid-sequence events: if we were previously connected
            // this is a reconnect attempt, not an initial connect.
            if was_ever_connected {
                state = OvpnState::Reconnecting;
                // Keep previous error reason — the TRANSPORT_ERROR
                // that caused the reconnect is still the relevant
                // diagnostic.
            } else {
                state = OvpnState::Connecting;
                reason = None;
            }
        }
        // ── openvpn 2.x ─────────────────────────────────────────
        else if line.contains("Initialization Sequence Completed") {
            state = OvpnState::Connected;
            was_ever_connected = true;
            reason = None;
        } else if line.contains("AUTH_FAILED") {
            // Matches "AUTH: Received control message: AUTH_FAILED"
            state = OvpnState::Disconnected;
            reason = Some("Authentication failed".to_string());
        }
    }
    (state, reason)
}

/// Extract a clean diagnostic string from a VPN log line.
///
/// Input (example):
/// `"Wed May 27 12:32:11.085 2026 EVENT: TRANSPORT_ERROR … NETWORK_EOF_ERROR [ERR]"`
///
/// Output: `Some("EVENT: TRANSPORT_ERROR … NETWORK_EOF_ERROR")`
///
/// We find `marker` in the line, take everything from there, strip
/// the trailing `[ERR]` tag (it's redundant noise), and cap at 120
/// characters so the GUI tooltip stays readable.
fn event_detail(line: &str, marker: &str) -> Option<String> {
    let idx = line.find(marker)?;
    let raw = line[idx..]
        .trim_end_matches("[ERR]")
        .trim_end_matches("[INFO]")
        .trim()
        .to_string();
    Some(if raw.len() > 120 {
        format!("{}…", &raw[..120])
    } else {
        raw
    })
}

// ── Byte-counter helper ────────────────────────────────────────────────────

/// Pull `(ibytes, obytes)` for `iface` out of `netstat -ibn -I
/// <iface>`. macOS's netstat outputs two rows per interface
/// (one for the link layer, one for each address family); both
/// rows carry the same byte counters in columns 7 (Ibytes) and
/// 10 (Obytes), so we read the first non-header row and skip
/// the rest. Returns `(None, None)` if netstat fails or the
/// columns can't be parsed — surfacing zero bytes here would
/// lie to the GUI's bandwidth-rate calculation.
async fn read_iface_byte_counts(iface: &str) -> (Option<u64>, Option<u64>) {
    let output = match tokio::process::Command::new("/usr/sbin/netstat")
        .args(["-ibn", "-I", iface])
        .output()
        .await
    {
        Ok(o) if o.status.success() => o,
        _ => return (None, None),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        if !line.starts_with(iface) { continue; }
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
        // Some address-family rows omit "Address" — column count drops by one.
        // The Ibytes column is always cols[6] when "Address" present, cols[5]
        // otherwise. We match by length to handle both.
        let (i_idx, o_idx) = match cols.len() {
            11 => (6, 9),    // header form: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
            10 => (5, 8),    // shorter form (no Address column)
            _  => continue,
        };
        let rx = cols.get(i_idx).and_then(|s| s.parse::<u64>().ok());
        let tx = cols.get(o_idx).and_then(|s| s.parse::<u64>().ok());
        if rx.is_some() || tx.is_some() {
            return (rx, tx);
        }
    }
    (None, None)
}

/// Pull `(interface, virtual_ip, virtual_gateway)` out of the
/// openvpn log. Format varies between binaries:
///
/// **ovpncli (openvpn3)**: `EVENT: CONNECTED <user>@<gw>:443 (...)
/// via /TCP on utun8/10.134.2.3/ gw=[10.134.2.1/] mtu=...`
///
/// **openvpn 2.x**: `TUN/TAP device <iface> opened` plus
/// `/sbin/ifconfig <iface> 10.134.2.3 10.134.2.1 netmask ...`.
///
/// We accept either shape and return the first match. Returns
/// `None` for any field that didn't appear in the log — the GUI
/// renders those as "—".
fn parse_tunnel_metadata(log: &str) -> (Option<String>, Option<String>, Option<String>) {
    // Try the openvpn3 format first — single line, three fields,
    // unambiguous.
    if let Some(idx) = log.find("EVENT: CONNECTED") {
        let line: &str = log[idx..]
            .split('\n')
            .next()
            .unwrap_or_default();
        // " on <iface>/<vip>/ gw=[<vgw>/]"
        let iface_vip = line
            .split(" on ")
            .nth(1)
            .and_then(|s| s.split(' ').next());
        let (iface, vip) = match iface_vip {
            Some(s) => {
                let mut it = s.split('/');
                (it.next().map(str::to_owned), it.next().map(str::to_owned))
            }
            None => (None, None),
        };
        let vgw = line
            .split("gw=[")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .map(str::to_owned);
        if iface.is_some() {
            return (iface, vip, vgw);
        }
    }
    // openvpn 2.x fallback. `TUN/TAP device tunN opened` for the
    // interface, `ifconfig tunN <vip> <vgw> netmask` for the IPs.
    let iface = log
        .lines()
        .find_map(|l| l.split("TUN/TAP device ").nth(1))
        .and_then(|s| s.split_whitespace().next())
        .map(str::to_owned);
    let (vip, vgw) = log
        .lines()
        .find_map(|l| l.split("/sbin/ifconfig ").nth(1))
        .map(|s| s.split_whitespace().collect::<Vec<_>>())
        .map(|toks| {
            // `<iface> <vip> <vgw> netmask ...`
            (
                toks.get(1).map(|s| s.to_string()),
                toks.get(2).map(|s| s.to_string()),
            )
        })
        .unwrap_or((None, None));
    (iface, vip, vgw)
}

/// Pull pushed-route CIDRs out of the openvpn log. Both binaries
/// shell out to `/sbin/route add -net X -netmask M GW` (macOS) when
/// installing routes, so we parse those lines and convert dotted
/// netmask → prefix length.
///
/// Skips the two halves of `redirect-gateway def1` (`0.0.0.0/1`
/// and `128.0.0.0/1`) — they're not actual destinations the
/// operator added, just openvpn's mechanism for stealing the
/// default route. Showing them would just be noise.
fn parse_active_routes(log: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in log.lines() {
        let Some(rest) = line.split("/sbin/route add -net ").nth(1) else {
            continue;
        };
        let toks: Vec<&str> = rest.split_whitespace().collect();
        if toks.len() < 3 || toks[1] != "-netmask" {
            continue;
        }
        let dest = toks[0];
        let mask = toks[2];
        let Some(prefix) = netmask_to_prefix_len(mask) else {
            continue;
        };
        // Drop the redirect-gateway halves — they're noise.
        if dest == "0.0.0.0" && prefix == 1 { continue; }
        if dest == "128.0.0.0" && prefix == 1 { continue; }
        let cidr = format!("{dest}/{prefix}");
        if !out.contains(&cidr) {
            out.push(cidr);
        }
    }
    out
}

/// `255.255.255.0` → `Some(24)`. Returns `None` for non-contiguous
/// masks (impossible from any real VPN gateway, but defensive).
fn netmask_to_prefix_len(mask: &str) -> Option<u8> {
    let octets: Vec<u8> = mask.split('.')
        .map(|s| s.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 4 { return None; }
    let bits = ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32);
    let leading = bits.leading_ones();
    let trailing = bits.trailing_zeros();
    if leading + trailing != 32 { return None; }
    Some(leading as u8)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Locate the OpenVPN binary.
///
/// **Order**: prefer OpenVPN 3 (`/opt/homebrew/bin/openvpn3`)
/// first. Microsoft's Azure VPN gateway *does* speak OpenVPN
/// protocol, but the gateway's TLS channel layer rejects 2.x
/// clients in the AAD/Entra ID flow — TLS handshake completes,
/// then the gateway RSTs immediately after our auth payload
/// without sending AUTH_FAILED. The same configuration on a 3.x
/// client connects cleanly. MSP-Toolkit-V2 (the production
/// reference) and Microsoft's own Azure VPN Client both use
/// OpenVPN 3 for this reason.
///
/// `openvpn3` is not in Homebrew's core formulae — install with
/// `contrib/build-openvpn3-mac.sh`, which clones upstream and
/// builds the `ovpncli` binary. Once installed, this function
/// picks it up automatically.
///
/// 2.x fallback paths exist for non-Azure profiles (regular
/// OpenVPN servers don't care about 2.x vs 3.x) but should not
/// be relied on for Azure VPN.
fn locate_openvpn(engine: OpenVpnEngine) -> anyhow::Result<PathBuf> {
    let root = Path::new("/Library/PrivilegedHelperTools/SuperManagerVPN");
    crate::secure_files::check_runtime_tree(root)?;
    let names: &[&str] = match engine {
        OpenVpnEngine::Openvpn2 => &["sbin/openvpn"],
        OpenVpnEngine::Openvpn3 => &["bin/openvpn3"],
    };
    for name in names {
        let path = root.join(name);
        if path.is_file() { return Ok(path); }
    }
    Err(anyhow!("A managed root-owned OpenVPN runtime is required; user-writable Homebrew executables are not permitted"))
}

/// Construct the sensitive process boundary separately so tests can inspect argv.
fn openvpn3_command(binary: &Path, args: &OvpnConnectArgs) -> Command {
    let mut command = Command::new(binary);
    command.arg("--no-cert")
        .arg("--username").arg(args.username.as_deref().unwrap_or("AzureAD"))
        .arg("--password-stdin")
        .arg(&args.config_file)
        .stdin(std::process::Stdio::piped());
    command
}

/// Sanitize a UUID into a filesystem-safe + length-bounded id that
/// matches the kernel's identifier rules without ambiguity.
fn sanitize_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(36)
        .collect()
}

fn pid_path_for(safe: &str) -> PathBuf {
    Path::new(PID_DIR).join(format!("supermgr-ovpn-{safe}.pid"))
}

/// SIGTERM every live OpenVPN tunnel the helper manages and clean up its
/// pidfiles. Used by the system-sleep teardown — a global, profile-agnostic
/// "kill all our tunnels" that doesn't need the per-profile id.
///
/// Replaces the old `pkill -f ovpncli`, which never matched anything: the
/// binary we actually spawn is `openvpn3` / `openvpn-patched` / `openvpn`
/// (the comments call it "ovpncli" after the upstream client name, but no
/// process is named that). We instead SIGTERM by tracked pid — exactly what
/// `disconnect()` does per profile.
///
/// Returns the number of processes signalled.
pub async fn terminate_all() -> usize {
    let mut killed = 0usize;
    let Ok(entries) = std::fs::read_dir(PID_DIR) else { return 0 };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else { continue };
        let Some(safe) = fname
            .strip_prefix("supermgr-ovpn-")
            .and_then(|s| s.strip_suffix(".pid"))
        else {
            continue;
        };
        if let Some(pid) = read_pid_file(&entry.path()) {
            if unsafe { libc::kill(pid as i32, 0) } == 0 {
                // SIGTERM lets openvpn flush its log and run its down script.
                unsafe { libc::kill(pid as i32, libc::SIGTERM); }
                killed += 1;
            }
        }
        // Belt-and-braces: ps-scan for stragglers carrying this profile's
        // daemon-name fingerprint (catches a tunnel whose pidfile was lost).
        for pid in collect_openvpn_pids_for(safe).await {
            if unsafe { libc::kill(pid as i32, 0) } == 0 {
                unsafe { libc::kill(pid as i32, libc::SIGTERM); }
                killed += 1;
            }
        }
        let _ = std::fs::remove_file(entry.path());
        let _ = std::fs::remove_file(log_path_for(safe));
    }
    killed
}

/// Kernel interfaces (`utunN`) of every OpenVPN tunnel that is currently
/// alive. Cheap, no `&mut self`: scans the helper's pidfiles in `/var/run`,
/// checks liveness with `kill(pid, 0)`, and parses the bound interface from
/// each session's log.
///
/// Used by the strongSwan teardown path so it never deletes the shared
/// full-tunnel split-default routes (`0/1` + `128.0/1`) out from under a
/// live OpenVPN session — those routes belong to whatever backend installed
/// them, and OpenVPN's `redirect-gateway def1` uses the exact same pair.
pub fn live_tunnel_interfaces() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(PID_DIR) else { return out };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else { continue };
        let Some(safe) = fname
            .strip_prefix("supermgr-ovpn-")
            .and_then(|s| s.strip_suffix(".pid"))
        else {
            continue;
        };
        let Some(pid) = read_pid_file(&entry.path()) else { continue };
        // Skip dead/stale pidfiles — a stale full-tunnel route from a dead
        // OpenVPN session SHOULD be swept, so we only protect live ones.
        if unsafe { libc::kill(pid as i32, 0) } != 0 {
            continue;
        }
        let body = std::fs::read_to_string(log_path_for(safe)).unwrap_or_default();
        if let (Some(iface), _, _) = parse_tunnel_metadata(&body) {
            out.push(iface);
        }
    }
    out
}

/// True if ANY supermgr OpenVPN tunnel process is alive, REGARDLESS of whether
/// it has reached `EVENT: CONNECTED` yet. `live_tunnel_interfaces()` only
/// reports a tunnel once its log shows CONNECTED (so it can name the utun); but
/// the exit-node ownership gate needs to recognize an Azure/OpenVPN full tunnel
/// during its entire connect/handshake window — the moment `redirect-gateway`
/// installs the shared `0/1`+`128/1` pair, before the CONNECTED line is
/// parseable. This is the cheap liveness-only scan: a live pidfile is enough to
/// say "a foreign full tunnel may own the split-default; do not steal it".
pub fn has_live_tunnel() -> bool {
    let Ok(entries) = std::fs::read_dir(PID_DIR) else { return false };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else { continue };
        if fname.strip_prefix("supermgr-ovpn-").and_then(|s| s.strip_suffix(".pid")).is_none() {
            continue;
        }
        if let Some(pid) = read_pid_file(&entry.path()) {
            if unsafe { libc::kill(pid as i32, 0) } == 0 {
                return true;
            }
        }
    }
    false
}

fn log_path_for(safe: &str) -> PathBuf {
    Path::new(LOG_DIR).join(format!("supermgr-ovpn-{safe}.log"))
}

/// Write user/password to a 0600 root:wheel file under `/var/run`.
/// Returns the path; caller deletes after openvpn has consumed it.
fn write_auth_file(safe: &str, user: &str, password: &str) -> anyhow::Result<PathBuf> {
    use std::io::Write;
    let path = Path::new(PID_DIR).join(format!("supermgr-ovpn-{safe}.auth"));
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("create {}", path.display()))?;
    writeln!(f, "{user}").context("write username")?;
    writeln!(f, "{password}").context("write password")?;
    Ok(path)
}

// `mode` requires the OpenOptionsExt trait in scope; bring it in
// here so the rest of the file doesn't have a stray import line.
use std::os::unix::fs::OpenOptionsExt;
// `ExitStatus::from_raw` for the synthetic Output we build on the
// openvpn3 spawn path (we don't actually wait on the foreground
// child — it runs as the persistent tunnel process).
use std::os::unix::process::ExitStatusExt;

/// Read a PID file if present, parse the integer.
fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Require both the managed executable and the exact session argument. A bare
/// UUID can occur in another client's argv and is never process ownership.
fn matches_openvpn_command(command: &str, safe: &str) -> bool {
    let words: Vec<_> = command.split_whitespace().collect();
    let Some(executable) = words.first().copied() else { return false; };
    if executable == "/Library/PrivilegedHelperTools/SuperManagerVPN/sbin/openvpn" {
        let name = format!("supermgr-ovpn-{safe}");
        return words.windows(2).any(|pair| pair == ["--daemon", name.as_str()]);
    }
    if executable == "/Library/PrivilegedHelperTools/SuperManagerVPN/bin/openvpn3" {
        let Ok(uuid) = uuid::Uuid::parse_str(safe) else { return false; };
        let config = format!("/Library/PrivilegedHelperTools/SuperManagerVPNConfigs/{}.ovpn", uuid.simple());
        return words.contains(&config.as_str());
    }
    false
}

fn has_managed_executable(pid: u32) -> bool {
    let mut path = [0u8; 4096];
    let length = unsafe { libc::proc_pidpath(pid as i32, path.as_mut_ptr().cast(), path.len() as u32) };
    if length <= 0 { return false; }
    let end = path.iter().position(|b| *b == 0).unwrap_or(path.len());
    matches!(std::str::from_utf8(&path[..end]),
        Ok("/Library/PrivilegedHelperTools/SuperManagerVPN/sbin/openvpn") |
        Ok("/Library/PrivilegedHelperTools/SuperManagerVPN/bin/openvpn3"))
}

async fn collect_openvpn_pids_for(safe: &str) -> Vec<u32> {
    let Ok(Ok(output)) = tokio::time::timeout(std::time::Duration::from_secs(3),
        Command::new("/bin/ps").args(["-Ao", "pid,command"]).output()).await
    else { return Vec::new(); };
    if !output.status.success() { return Vec::new(); }
    String::from_utf8_lossy(&output.stdout).lines().skip(1).filter_map(|line| {
        let line = line.trim_start();
        let boundary = line.find(char::is_whitespace)?;
        let pid: u32 = line[..boundary].parse().ok()?;
        (matches_openvpn_command(line[boundary..].trim_start(), safe) && has_managed_executable(pid)).then_some(pid)
    }).collect()
}

async fn find_openvpn_pid_for(safe: &str) -> Option<u32> {
    collect_openvpn_pids_for(safe).await.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openvpn3_credentials_never_enter_process_arguments() {
        let args = OvpnConnectArgs {
            profile_id: "26b4fcc6-097a-41e7-932e-9a6d2a4663e5".into(),
            config_file: "/managed/profile.ovpn".into(),
            username: Some("test-user".into()), password: Some("DO-NOT-LEAK-TOKEN".into()),
            engine: OpenVpnEngine::Openvpn3,
        };
        let cmd = openvpn3_command(Path::new("/managed/openvpn3"), &args);
        let argv: Vec<_> = cmd.as_std().get_args().collect();
        assert!(argv.contains(&std::ffi::OsStr::new("--password-stdin")));
        assert!(!argv.contains(&std::ffi::OsStr::new("--password")));
        assert!(argv.iter().all(|v| !v.to_string_lossy().contains("DO-NOT-LEAK-TOKEN")));
        assert_eq!(cmd.as_std().get_envs().count(), 0);
    }

    #[test]
    fn azure_rendered_directives_pass_the_privilege_boundary() {
        let config = "client\ndev tun\nproto tcp\nremote vpn.example.test 443\ndisable-dco\nauth SHA256\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM\nauth-user-pass\nremote-cert-tls server\n<ca>\ntest-certificate\n</ca>\n<tls-auth>\ntest-key\n</tls-auth>\nkey-direction 1\n";
        assert!(crate::vpn_input::openvpn(config).is_ok());
        assert!(crate::vpn_input::openvpn("disable-dco /tmp/untrusted").is_err());
    }

    #[test]
    fn engine_selection_is_explicit_and_validated() {
        let mut request = serde_json::json!({"profile_id":"id", "config_file":"path"});
        assert_eq!(serde_json::from_value::<OvpnConnectArgs>(request.clone()).unwrap().engine, OpenVpnEngine::Openvpn2);
        request["engine"] = "openvpn3".into();
        assert_eq!(serde_json::from_value::<OvpnConnectArgs>(request.clone()).unwrap().engine, OpenVpnEngine::Openvpn3);
        request["engine"] = "/tmp/untrusted-executable".into();
        assert!(serde_json::from_value::<OvpnConnectArgs>(request).is_err());
    }

    #[test]
    fn process_identity_requires_binary_and_exact_profile() {
        let id = "26b4fcc6-097a-41e7-932e-9a6d2a4663e5";
        let v2 = format!("/Library/PrivilegedHelperTools/SuperManagerVPN/sbin/openvpn --daemon supermgr-ovpn-{id}");
        let v3 = "/Library/PrivilegedHelperTools/SuperManagerVPN/bin/openvpn3 --password-stdin /Library/PrivilegedHelperTools/SuperManagerVPNConfigs/26b4fcc6097a41e7932e9a6d2a4663e5.ovpn";
        assert!(matches_openvpn_command(&v2, id));
        assert!(matches_openvpn_command(v3, id));
        assert!(!matches_openvpn_command(&format!("/usr/bin/echo {id}"), id));
        assert!(!matches_openvpn_command(&format!("{v2}-another-profile"), id));
        assert!(!matches_openvpn_command(&v2, "36b4fcc6-097a-41e7-932e-9a6d2a4663e5"));
        assert!(!matches_openvpn_command(v3, "36b4fcc6-097a-41e7-932e-9a6d2a4663e5"));
    }

    #[test]
    fn sanitize_strips_unsafe_chars() {
        assert_eq!(sanitize_id("abc/../etc/passwd"), "abcetcpasswd");
        assert_eq!(
            sanitize_id("26b4fcc6-097a-41e7-932e-9a6d2a4663e5"),
            "26b4fcc6-097a-41e7-932e-9a6d2a4663e5"
        );
    }
}
