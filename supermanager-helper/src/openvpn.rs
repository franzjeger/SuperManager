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
//! - `config` — the profile's configuration. OpenVPN runs as root, so
//!   the helper holds it to `openvpn_config::check` and runs OpenVPN on
//!   its own copy in `PRIVATE_DIR`, never on a file the user can change.
//! - optionally `username` + `password` for `--auth-user-pass`
//!   profiles; we materialise the creds into a root-only file in
//!   `PRIVATE_DIR`, hand the path to `openvpn`, and `unlink()`
//!   immediately after — the kernel keeps the inode alive while the
//!   child holds the fd, but no other process can `open()` it
//!
//! ## Logging
//!
//! Each session logs to `PRIVATE_DIR/<sanitized-id>.log`, which only
//! root can read. The GUI asks for it through `tail_log`.
//!
//! ## Why not openvpn3 / Tunnelblick / OpenVPN Connect?
//!
//! `openvpn3` brews cleanly but its session model is much heavier
//! and the project is moving towards a Cloud-Connect-only future.
//! Tunnelblick / OpenVPN Connect are full GUIs we'd have to drive
//! over AppleScript / mobileconfig — clunky and brittle. The plain
//! `openvpn` 2.x CLI is rock-solid, scriptable, and what every
//! integration tutorial assumes. Less work, fewer moving parts.

use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use crate::client_auth::Policy;
use crate::vpn_runtime::BREW_PREFIXES;

/// Known OpenVPN executable basenames, checked via `proc_pidpath` before
/// signalling any PID or counting a PID file / `ps` row as our tunnel.
const OPENVPN_BIN_NAMES: &[&str] = &["openvpn", "openvpn-patched", "openvpn3", "ovpncli"];

/// Where we keep per-profile PID files.
const PID_DIR: &str = "/var/run";
/// Each tunnel's checked configuration and its log. The one can hold
/// keys and the other usernames and addresses, so the directory is
/// root's alone; the GUI reads a log through `tail_log`.
const PRIVATE_DIR: &str = "/var/run/supermanager-ovpn";
/// Where helpers up to 1.8.14 wrote the logs.
const LEGACY_LOG_DIR: &str = "/tmp";
/// A profile's configuration is kilobytes; certificates included.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

pub struct OpenVpn {
    policy: Policy,
}

#[derive(Deserialize)]
pub struct OvpnConnectArgs {
    pub profile_id: String,
    /// The profile's inline configuration body.
    #[serde(default)]
    pub config: Option<String>,
    /// Azure Entra ID tokens require our OpenVPN 3 client path.
    /// Never silently fall back to OpenVPN 2 for these sessions.
    #[serde(default)]
    pub require_openvpn3: bool,
    /// Optional credentials for `--auth-user-pass` profiles.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Optional per-profile kill-switch intent synced atomically on connect.
    #[serde(default)]
    pub kill_switch: Option<bool>,
}

impl fmt::Debug for OvpnConnectArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OvpnConnectArgs")
            .field("profile_id", &self.profile_id)
            .field("has_config", &self.config.is_some())
            .field("require_openvpn3", &self.require_openvpn3)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("kill_switch", &self.kill_switch)
            .finish()
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl OvpnConnectArgs {
    /// Whether the request carries a configuration to run.
    #[must_use]
    pub fn has_configuration(&self) -> bool {
        self.config.is_some()
    }

    /// The inline configuration carried by the request, bounded to [`MAX_CONFIG_BYTES`].
    fn configuration(&self) -> anyhow::Result<String> {
        let Some(config) = &self.config else {
            return Err(anyhow!("the connect request carries no configuration"));
        };
        if config.len() as u64 > MAX_CONFIG_BYTES {
            return Err(anyhow!("the profile configuration exceeds the size limit"));
        }
        Ok(config.clone())
    }
}

/// Validate OpenVPN connect arguments before storing for auto-reconnect or spawning OpenVPN.
pub(crate) fn validate_connect_args(args: &OvpnConnectArgs) -> anyhow::Result<()> {
    validate_profile_id(&args.profile_id)?;
    let config_body = args.configuration()?;
    crate::openvpn_config::check(&config_body)
        .map_err(|refusal| anyhow!("the profile can't be used as it is: {refusal}"))?;
    if args.require_openvpn3 && (args.username.is_some() || args.password.is_some()) {
        let u = args.username.as_deref().unwrap_or("AzureAD");
        let p = args.password.as_deref().unwrap_or("");
        validate_v3_credentials(u, p)?;
    }
    for (field, val) in [("username", &args.username), ("password", &args.password)] {
        if let Some(s) = val {
            if s.contains('\n') || s.contains('\r') || s.contains('\0') {
                return Err(anyhow!(
                    "invalid {field}: newline or NUL characters are not permitted"
                ));
            }
        }
    }
    Ok(())
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
    /// The gateway pushed `redirect-gateway def1`, so the tunnel took the
    /// default route: everything not routed more specifically goes
    /// through it. Its two halves are not in `active_routes`.
    #[serde(default)]
    pub takes_all: bool,
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

struct OvpnFilesGuard {
    config_path: PathBuf,
    auth_path: Option<PathBuf>,
    keep_config: bool,
    keep_auth: bool,
}

impl Drop for OvpnFilesGuard {
    fn drop(&mut self) {
        if !self.keep_auth {
            if let Some(ref auth) = self.auth_path {
                let _ = std::fs::remove_file(auth);
            }
        }
        if !self.keep_config {
            let _ = std::fs::remove_file(&self.config_path);
        }
    }
}

/// Markers OpenVPN writes when it bails mid-handshake *unrecoverably*.
/// Recoverable signals (`Connection reset`, soft restart) intentionally don't
/// appear here — the daemon retries those by design.
const POST_FORK_FATAL_MARKERS: &[&str] = &[
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

fn prepare_auth_file(
    safe: &str,
    args: &OvpnConnectArgs,
    is_v3: bool,
) -> anyhow::Result<Option<PathBuf>> {
    if is_v3 {
        if args.username.is_some() || args.password.is_some() {
            let u = args.username.as_deref().unwrap_or("AzureAD");
            let p = args.password.as_deref().unwrap_or("");
            validate_v3_credentials(u, p)?;
            tracing::info!(
                "ovpn_connect: writing 0600 auth file for openvpn3 (username={}, password={} chars)",
                u,
                p.len()
            );
            Ok(Some(write_auth_file(safe, u, p)?))
        } else {
            Ok(None)
        }
    } else if let (Some(u), Some(p)) = (args.username.as_deref(), args.password.as_deref()) {
        tracing::info!(
            "ovpn_connect: writing auth file (username={}, password={} chars)",
            u,
            p.len()
        );
        Ok(Some(write_auth_file(safe, u, p)?))
    } else {
        tracing::info!("ovpn_connect: no auth-user-pass (no username/password)");
        Ok(None)
    }
}

fn spawn_openvpn3_process(
    openvpn: &Path,
    config_body: &str,
    config_path: &Path,
    pid_path: &Path,
    log_path: &Path,
    auth_path: Option<&Path>,
    files_guard: &mut OvpnFilesGuard,
) -> anyhow::Result<std::process::Output> {
    use std::os::unix::process::CommandExt as _;
    // Open the log file for stdout+stderr redirection.
    // ovpncli writes status to stderr; we merge both into one log.
    let log_for_stdout = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(log_path)
        .with_context(|| format!("open log {}", log_path.display()))?;
    let log_for_stderr = log_for_stdout.try_clone().context("dup log fd")?;

    let v3_args = build_v3_cli_args(config_body, config_path, auth_path);
    let mut cmd = Command::new(openvpn);
    cmd.args(&v3_args)
        .stdin(std::process::Stdio::null())
        .stdout(log_for_stdout)
        .stderr(log_for_stderr);
    unsafe {
        cmd.as_std_mut().pre_exec(|| {
            // New session — child won't get SIGHUP if the helper restarts.
            libc::setsid();
            Ok(())
        });
    }
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            if let Some(auth) = auth_path {
                let _ = std::fs::remove_file(auth);
            }
            let _ = std::fs::remove_file(config_path);
            return Err(e).with_context(|| format!("spawn {} (ovpncli)", openvpn.display()));
        }
    };
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("ovpncli spawn returned no pid"))?;
    tracing::info!(
        "ovpn_connect: ovpncli spawned pid={} log={}",
        pid,
        log_path.display()
    );
    if let Err(e) = crate::private_file::write(pid_path, format!("{pid}\n").as_bytes()) {
        tracing::warn!(
            "ovpn_connect: failed to write pid file {}: {e}",
            pid_path.display()
        );
    }
    // Reap the child asynchronously so it doesn't become a zombie,
    // and wipe its 0600 credentials file as soon as the process exits.
    files_guard.keep_auth = true;
    let auth_for_exit = auth_path.map(Path::to_path_buf);
    tokio::spawn(async move {
        let mut child = child;
        let _ = child.wait().await;
        if let Some(auth) = auth_for_exit {
            let _ = std::fs::remove_file(auth);
        }
    });
    // Synthesize a "spawn succeeded" Output so the post-spawn diagnostic
    // path covers the v3 case too.
    Ok(std::process::Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
    })
}

async fn spawn_openvpn2_daemon(
    openvpn: &Path,
    safe: &str,
    config_path: &Path,
    pid_path: &Path,
    log_path: &Path,
    status_path: &Path,
    auth_path: Option<&Path>,
) -> anyhow::Result<std::process::Output> {
    let mut cli_args: Vec<String> = vec![
        "--config".into(),
        config_path.display().to_string(),
        // After the configuration, so it wins: built-in commands only,
        // never a script. `openvpn_config::check` allows no directive that names one either.
        "--script-security".into(),
        "1".into(),
        "--daemon".into(),
        format!("supermgr-ovpn-{safe}"),
        "--writepid".into(),
        pid_path.display().to_string(),
        "--log".into(),
        log_path.display().to_string(),
        "--status".into(),
        status_path.display().to_string(),
        "5".into(),
        "--verb".into(),
        "3".into(),
    ];
    if let Some(auth) = auth_path {
        cli_args.push("--auth-user-pass".into());
        cli_args.push(auth.display().to_string());
    }
    tracing::info!(
        "ovpn_connect: argv = {} {}",
        openvpn.display(),
        cli_args.join(" ")
    );
    let mut cmd = Command::new(openvpn);
    cmd.args(&cli_args);
    // `--daemon` forks and the parent exits right after option parsing,
    // so this normally returns in well under a second.
    crate::proc::bounded_async(&mut cmd, crate::proc::MUTATE)
        .await
        .with_context(|| {
            format!(
                "run {} --config {}",
                openvpn.display(),
                config_path.display()
            )
        })
}

fn format_refused_to_start(output: &std::process::Output, log_path: &Path) -> String {
    tracing::error!(
        "ovpn_connect: NON-ZERO exit, reading {}",
        log_path.display()
    );
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let log_tail = {
        let s = read_openvpn_log(log_path);
        let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
        let start = lines.len().saturating_sub(20);
        lines[start..].join("\n")
    };
    let combined = match (stderr.is_empty(), log_tail.is_empty()) {
        (false, false) => format!("{stderr}\n--- log ---\n{log_tail}"),
        (true, false) => log_tail,
        (false, true) => stderr,
        (true, true) => "(no diagnostic output)".to_owned(),
    };
    tracing::error!("ovpn_connect: refused to start:\n{combined}");
    combined
}

async fn verify_openvpn2_post_fork(
    pid_path: &Path,
    log_path: &Path,
    config_path: &Path,
) -> Option<OvpnConnectResult> {
    // 5s settle window. For openvpn 2.x in `--daemon` mode, the parent exits 0
    // the moment it forks, before TLS/auth completes. Only abort when openvpn
    // writes an unrecoverable fatal marker or its PID disappears.
    tracing::info!("ovpn_connect: waiting 5s for daemon child to settle…");
    tokio::time::sleep(std::time::Duration::from_millis(5000)).await;

    let log_body = read_openvpn_log(log_path);
    let pid_alive = read_pid_file(pid_path).is_some_and(is_live_openvpn_pid);
    tracing::info!(
        "ovpn_connect: post-spawn check pid_alive={} log_size={}",
        pid_alive,
        log_body.len()
    );

    let fatal_hit = POST_FORK_FATAL_MARKERS
        .iter()
        .find(|m| log_body.contains(*m));
    if pid_alive && fatal_hit.is_none() {
        return None;
    }

    let reason = fatal_hit.map_or_else(
        || "openvpn died after fork (no PID, no fatal marker — see log)".to_owned(),
        |m| format!("openvpn died after fork — {m}"),
    );
    let log_tail = {
        let lines: Vec<&str> = log_body.lines().filter(|l| !l.trim().is_empty()).collect();
        let start = lines.len().saturating_sub(25);
        lines[start..].join("\n")
    };
    tracing::error!("ovpn_connect: post-fork failure: {reason}\n{log_tail}");
    let _ = std::fs::remove_file(config_path);
    Some(OvpnConnectResult {
        success: false,
        message: format!("{reason}\n\nLast 25 log lines:\n{log_tail}"),
        interface: None,
    })
}

impl OpenVpn {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    async fn await_and_activate_kill_switch(
        &mut self,
        safe: &str,
        endpoints: Vec<std::net::IpAddr>,
        bound_iface: &mut Option<String>,
    ) -> anyhow::Result<Option<OvpnConnectResult>> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
        while tokio::time::Instant::now() < deadline {
            let status = self
                .status(&OvpnStatusArgs {
                    profile_id: safe.to_owned(),
                })
                .await?;
            match status.state {
                OvpnState::Connected => {
                    *bound_iface = status.interface;
                    break;
                }
                OvpnState::Disconnected => {
                    let reason = status
                        .error_reason
                        .unwrap_or_else(|| "OpenVPN exited before establishing tunnel".into());
                    let _ = self
                        .disconnect(&OvpnDisconnectArgs {
                            profile_id: safe.to_owned(),
                        })
                        .await;
                    return Ok(Some(OvpnConnectResult {
                        success: false,
                        message: reason,
                        interface: None,
                    }));
                }
                OvpnState::Connecting | OvpnState::Reconnecting => {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        }

        let iface = bound_iface.clone().unwrap_or_default();
        let safe_for_ks = safe.to_owned();
        let ks_res = tokio::task::spawn_blocking(move || {
            crate::kill_switch::activate_for_profile(
                &safe_for_ks,
                &iface,
                endpoints,
                crate::kill_switch::KillSwitchBackend::Openvpn,
            )
        })
        .await
        .context("kill-switch blocking task")?;
        if let Err(e) = ks_res {
            tracing::error!(
                profile = %safe,
                "ovpn_connect: kill-switch activation failed; tearing down tunnel: {e:#}"
            );
            let _ = self
                .disconnect(&OvpnDisconnectArgs {
                    profile_id: safe.to_owned(),
                })
                .await;
            return Ok(Some(OvpnConnectResult {
                success: false,
                message: format!("Kill-switch activation failed (tunnel rolled back): {e:#}"),
                interface: None,
            }));
        }
        Ok(None)
    }

    async fn spawn_and_verify_openvpn(
        openvpn: &Path,
        is_v3: bool,
        safe: &str,
        config_body: &str,
        files_guard: &mut OvpnFilesGuard,
    ) -> anyhow::Result<Option<OvpnConnectResult>> {
        let pid_path = pid_path_for(safe);
        let log_path = log_path_for(safe);
        let status_path = status_path_for(safe);
        let config_path = files_guard.config_path.clone();
        let auth_path = files_guard.auth_path.clone();

        tracing::info!("ovpn_connect: spawning {} (v3={is_v3})", openvpn.display());
        let output = if is_v3 {
            spawn_openvpn3_process(
                openvpn,
                config_body,
                &config_path,
                &pid_path,
                &log_path,
                auth_path.as_deref(),
                files_guard,
            )?
        } else {
            spawn_openvpn2_daemon(
                openvpn,
                safe,
                &config_path,
                &pid_path,
                &log_path,
                &status_path,
                auth_path.as_deref(),
            )
            .await?
        };

        if !output.status.success() {
            if let Some(ref auth) = auth_path {
                let _ = std::fs::remove_file(auth);
            }
            let combined = format_refused_to_start(&output, &log_path);
            let _ = std::fs::remove_file(&config_path);
            return Ok(Some(OvpnConnectResult {
                success: false,
                message: format!("openvpn refused to start:\n{combined}"),
                interface: None,
            }));
        }
        if !is_v3 {
            if let Some(ref auth) = auth_path {
                let _ = std::fs::remove_file(auth);
            }
            if let Some(failed) =
                verify_openvpn2_post_fork(&pid_path, &log_path, &config_path).await
            {
                return Ok(Some(failed));
            }
        }
        Ok(None)
    }

    /// Spin up an `openvpn` child for this profile. Daemon mode
    /// (`--daemon`) detaches from us — the child keeps running on
    /// its own and writes its PID to the file we pass via
    /// `--writepid`.
    pub async fn connect(&mut self, args: &OvpnConnectArgs) -> anyhow::Result<OvpnConnectResult> {
        validate_connect_args(args)?;
        let safe = validate_profile_id(&args.profile_id)?;
        crate::kill_switch::sync_intent_opt(&safe, args.kill_switch)?;
        let want_kill_switch = crate::kill_switch::has_intent(&safe);
        let openvpn = locate_openvpn(self.policy, args.require_openvpn3)?;
        let config_body = args.configuration()?;
        let endpoints = if want_kill_switch {
            crate::kill_switch::resolve_openvpn_endpoints(&config_body)
        } else {
            Vec::new()
        };
        // Suppress the connectivity watchdog during the connect/handshake window.
        crate::connectivity_watchdog::pause_for(45);
        tracing::info!(
            "ovpn_connect: profile={safe} openvpn={} bytes={} has_remote={} has_ca={} has_auth_user_pass={} has_client_cert={}",
            openvpn.display(),
            config_body.len(),
            config_body.contains("\nremote ") || config_body.starts_with("remote "),
            config_body.contains("<ca>"),
            config_body.contains("auth-user-pass"),
            has_client_certificate(&config_body),
        );

        let pid_path = pid_path_for(&safe);
        let log_path = log_path_for(&safe);
        let config_path = config_path_for(&safe);
        let previous = stop_profile_processes(&safe).await;
        if !previous.is_empty() {
            tracing::info!(
                profile = %safe,
                killed = ?previous,
                "ovpn_connect: stopped existing OpenVPN instance before reconnect"
            );
        }

        ensure_private_dir()?;
        let mut files_guard = OvpnFilesGuard {
            config_path: config_path.clone(),
            auth_path: None,
            keep_config: false,
            keep_auth: false,
        };
        crate::private_file::write(&config_path, config_body.as_bytes())
            .with_context(|| format!("write {}", config_path.display()))?;
        crate::private_file::write(&log_path, b"")
            .with_context(|| format!("create {}", log_path.display()))?;
        let _ = std::fs::remove_file(&pid_path);

        let is_v3 = is_openvpn3(&openvpn);
        files_guard.auth_path = prepare_auth_file(&safe, args, is_v3)?;

        if let Some(failed) =
            Self::spawn_and_verify_openvpn(&openvpn, is_v3, &safe, &config_body, &mut files_guard)
                .await?
        {
            return Ok(failed);
        }

        files_guard.keep_config = true;
        files_guard.keep_auth = is_v3;
        let mut bound_iface: Option<String> = parse_tunnel_metadata(&read_openvpn_log(&log_path)).0;
        if want_kill_switch {
            if let Some(failed) = self
                .await_and_activate_kill_switch(&safe, endpoints, &mut bound_iface)
                .await?
            {
                return Ok(failed);
            }
        }
        crate::dns_health_watchdog::notify_state_changed();

        Ok(OvpnConnectResult {
            success: true,
            message: if is_v3 {
                format!("OpenVPN 3.x tunnel '{safe}' up — session managed by openvpn3 daemon")
            } else {
                format!("OpenVPN tunnel '{safe}' up")
            },
            interface: bound_iface,
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
        let safe = validate_profile_id(&args.profile_id)?;
        let safe_for_ks = safe.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = crate::kill_switch::deactivate_for_profile(&safe_for_ks);
        })
        .await;
        let killed = stop_profile_processes(&safe).await;

        let dns_owner = format!("ovpn-{safe}");
        let _ = tokio::task::spawn_blocking(move || {
            crate::dns::clear_vpn_dns_for(&dns_owner);
        })
        .await;

        Ok(OvpnDisconnectResult {
            success: true,
            message: if killed.is_empty() {
                format!("OpenVPN tunnel '{safe}' was not running")
            } else {
                format!(
                    "OpenVPN tunnel '{safe}' down (killed {} process{})",
                    killed.len(),
                    if killed.len() == 1 { "" } else { "es" }
                )
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
        let safe = validate_profile_id(&args.profile_id)?;
        let pid_path = pid_path_for(&safe);
        let log_path = log_path_for(&safe);

        let live_pid: Option<u32> = match read_pid_file(&pid_path) {
            Some(pid) if is_live_openvpn_pid(pid) => Some(pid),
            Some(_) => {
                // Stale or recycled PID file — clean up so subsequent polls
                // don't keep finding it.
                let _ = std::fs::remove_file(&pid_path);
                None
            }
            None => None,
        }
        .or(find_openvpn_pid_for(&safe).await);

        let Some(pid) = live_pid else {
            return Ok(OvpnStatusResult {
                state: OvpnState::Disconnected,
                pid: None,
                interface: None,
                virtual_ip: None,
                virtual_gateway: None,
                active_routes: Vec::new(),
                takes_all: false,
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
        let body = read_openvpn_log(&log_path);
        let (mut tunnel_state, mut error_reason) = last_event_from_log(&body);
        if tunnel_state == OvpnState::Connected
            && status_file_is_stale(&status_path_for(&safe), std::time::Duration::from_secs(30))
        {
            tunnel_state = OvpnState::Reconnecting;
            if error_reason.is_none() {
                error_reason = Some("OpenVPN status heartbeat stalled (>30s)".to_owned());
            }
        }
        let connected = tunnel_state == OvpnState::Connected;

        let (interface, virtual_ip, virtual_gateway) = parse_tunnel_metadata(&body);
        let (active_routes, takes_all) = parse_active_routes(&body);

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
            interface: if connected { interface } else { None },
            virtual_ip: if connected { virtual_ip } else { None },
            virtual_gateway: if connected { virtual_gateway } else { None },
            active_routes: if connected { active_routes } else { Vec::new() },
            takes_all: connected && takes_all,
            rx_bytes,
            tx_bytes,
            error_reason,
        })
    }
}

// ── Log-state scanner ─────────────────────────────────────────────────────

/// Bounded OpenVPN log reader (`P3-6`): preserves the initial setup header
/// (first `head_bytes`, containing `TUN/TAP device utunN` and `route add` lines)
/// and seeks directly to the latest `tail_bytes` of status transitions when the
/// log grows beyond `head_bytes + tail_bytes`.
fn read_openvpn_log_bounded(path: &Path, head_bytes: usize, tail_bytes: usize) -> String {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    let Ok(len) = file.metadata().map(|m| m.len()) else {
        return String::new();
    };
    let cap = (head_bytes.saturating_add(tail_bytes)) as u64;
    if len <= cap {
        let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        if file.take(cap).read_to_end(&mut buf).is_err() {
            return String::new();
        }
        return String::from_utf8_lossy(&buf).into_owned();
    }
    let mut head = Vec::with_capacity(head_bytes);
    if (&mut file)
        .take(head_bytes as u64)
        .read_to_end(&mut head)
        .is_err()
    {
        return String::new();
    }
    let tail_offset = len.saturating_sub(tail_bytes as u64);
    if file.seek(SeekFrom::Start(tail_offset)).is_err() {
        return String::from_utf8_lossy(&head).into_owned();
    }
    let mut tail = Vec::with_capacity(tail_bytes);
    if file.take(tail_bytes as u64).read_to_end(&mut tail).is_err() {
        return String::from_utf8_lossy(&head).into_owned();
    }
    // Advance `tail` past any partial line split by the seek offset.
    let tail_slice = match tail.iter().position(|&b| b == b'\n') {
        Some(pos) if pos + 1 < tail.len() => &tail[pos + 1..],
        _ => tail.as_slice(),
    };
    let mut out = String::from_utf8_lossy(&head).into_owned();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&String::from_utf8_lossy(tail_slice));
    out
}

fn read_openvpn_log(path: &Path) -> String {
    read_openvpn_log_bounded(path, 64 * 1024, 192 * 1024)
}

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
        } else if line.contains("EVENT: TRANSPORT_ERROR") || line.contains("EVENT: RECONNECTING") {
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
        } else if line.contains("SIGTERM[hard,") || line.contains("Exiting due to fatal error") {
            state = OvpnState::Disconnected;
            reason = Some(line.trim().chars().take(120).collect());
        } else if line.contains("Inactivity timeout (--ping-restart)")
            || line.contains("SIGUSR1[soft,")
            || line.contains("Connection reset, restarting")
            || line.contains("Restart pause,")
            || line.contains("TLS Error: TLS key negotiation failed")
            || line.contains("TLS Error: TLS handshake failed")
        {
            state = if was_ever_connected {
                OvpnState::Reconnecting
            } else {
                OvpnState::Connecting
            };
            reason = Some(line.trim().chars().take(120).collect());
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
        format!("{}…", &raw[..raw.floor_char_boundary(120)])
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
    let output = match crate::proc::bounded_async(
        tokio::process::Command::new("/usr/sbin/netstat").args(["-ibn", "-I", iface]),
        crate::proc::PROBE,
    )
    .await
    {
        Ok(o) if o.status.success() => o,
        _ => return (None, None),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        if !line.starts_with(iface) {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
        // Some address-family rows omit "Address" — column count drops by one.
        // The Ibytes column is always cols[6] when "Address" present, cols[5]
        // otherwise. We match by length to handle both.
        let (i_idx, o_idx) = match cols.len() {
            11 => (6, 9), // header form: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
            10 => (5, 8), // shorter form (no Address column)
            _ => continue,
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
        let line: &str = log[idx..].split('\n').next().unwrap_or_default();
        // " on <iface>/<vip>/ gw=[<vgw>/]"
        let iface_vip = line.split(" on ").nth(1).and_then(|s| s.split(' ').next());
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
        .find_map(|l| {
            l.split("TUN/TAP device ")
                .nth(1)
                .or_else(|| l.split("Opened utun device ").nth(1))
        })
        .and_then(|s| s.split_whitespace().next())
        .map(|s| s.trim_start_matches("/dev/").to_owned());
    let (vip, vgw) = log
        .lines()
        .find_map(|l| l.split("/sbin/ifconfig ").nth(1))
        .map_or((None, None), |s| {
            let toks: Vec<&str> = s.split_whitespace().collect();
            // `<iface> <vip> <vgw> netmask ...`
            (
                toks.get(1).copied().map(str::to_owned),
                toks.get(2).copied().map(str::to_owned),
            )
        });
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
/// default route. Showing them would just be noise. The second value
/// says whether both were added: the tunnel took the default route.
fn parse_active_routes(log: &str) -> (Vec<String>, bool) {
    let mut out: Vec<String> = Vec::new();
    let (mut low_half, mut high_half) = (false, false);
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
        if dest == "0.0.0.0" && prefix == 1 {
            low_half = true;
            continue;
        }
        if dest == "128.0.0.0" && prefix == 1 {
            high_half = true;
            continue;
        }
        let cidr = format!("{dest}/{prefix}");
        if !out.contains(&cidr) {
            out.push(cidr);
        }
    }
    (out, low_half && high_half)
}

/// `255.255.255.0` → `Some(24)`. Returns `None` for non-contiguous
/// masks (impossible from any real VPN gateway, but defensive).
fn netmask_to_prefix_len(mask: &str) -> Option<u8> {
    let octets: Vec<u8> = mask
        .split('.')
        .map(|s| s.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 4 {
        return None;
    }
    let bits = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let leading = bits.leading_ones();
    let trailing = bits.trailing_zeros();
    if leading + trailing != 32 {
        return None;
    }
    u8::try_from(leading).ok()
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
/// without sending `AUTH_FAILED`. The same configuration on a 3.x
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
fn locate_openvpn(policy: Policy, require_openvpn3: bool) -> anyhow::Result<PathBuf> {
    select_openvpn_for_policy(
        policy,
        require_openvpn3,
        Path::is_file,
        crate::vpn_runtime::ensure_root_owned,
    )
}

/// Which OpenVPN runs a profile. Azure VPN needs OpenVPN 3 and gets nothing
/// else. Every other profile gets OpenVPN 2 when it is installed and OpenVPN
/// 3 only as a last resort. Under `Policy::Release`, only root-owned binaries
/// that are not group- or world-writable may be executed.
fn select_openvpn_for_policy(
    policy: Policy,
    require_openvpn3: bool,
    is_available: impl Fn(&Path) -> bool,
    check_owner: impl Fn(&Path, &str) -> anyhow::Result<()>,
) -> anyhow::Result<PathBuf> {
    let runtime = Path::new(crate::vpn_runtime::RUNTIME_DIR);
    let mut v3_candidates = vec![runtime.join("openvpn3"), runtime.join("bin/openvpn3")];
    v3_candidates.extend(
        [
            "/opt/homebrew/bin/openvpn3",
            "/usr/local/bin/openvpn3",
            "/opt/local/bin/openvpn3",
        ]
        .into_iter()
        .map(PathBuf::from),
    );

    let mut v2_candidates = vec![
        runtime.join("openvpn"),
        runtime.join("sbin/openvpn"),
        runtime.join("bin/openvpn"),
        PathBuf::from("/opt/homebrew/bin/openvpn-patched"),
        PathBuf::from("/usr/local/bin/openvpn-patched"),
    ];
    for prefix in BREW_PREFIXES {
        v2_candidates.push(Path::new(prefix).join("sbin/openvpn"));
        v2_candidates.push(Path::new(prefix).join("bin/openvpn"));
    }

    let mut last_refusal: Option<anyhow::Error> = None;
    let mut first_usable = |candidates: &[PathBuf]| -> Option<PathBuf> {
        for candidate in candidates {
            if !is_available(candidate) {
                continue;
            }
            if policy == Policy::Release {
                if let Err(e) = check_owner(candidate, "OpenVPN binary") {
                    last_refusal = Some(e);
                    continue;
                }
            }
            return Some(candidate.clone());
        }
        None
    };

    if require_openvpn3 {
        if let Some(path) = first_usable(&v3_candidates) {
            return Ok(path);
        }
        if let Some(refusal) = last_refusal {
            return Err(refusal.context(format!(
                "refusing unprivileged OpenVPN 3 binary in Release mode; install a root-owned \
                 OpenVPN 3 in {} (`vpn_runtime_install` / `contrib/build-openvpn3-mac.sh`)",
                crate::vpn_runtime::RUNTIME_DIR
            )));
        }
        return Err(anyhow!(
            "Azure VPN requires OpenVPN 3, which is not installed. \
             OpenVPN 2 can fail to fit the Microsoft sign-in token in its TLS buffer. \
             Install OpenVPN 3 into {} (e.g. via `vpn_runtime_install` or \
             `contrib/build-openvpn3-mac.sh`), then try again.",
            crate::vpn_runtime::RUNTIME_DIR
        ));
    }

    if let Some(path) = first_usable(&v2_candidates) {
        return Ok(path);
    }
    if let Some(path) = first_usable(&v3_candidates) {
        return Ok(path);
    }

    if let Some(refusal) = last_refusal {
        return Err(refusal.context(format!(
            "refusing unprivileged OpenVPN binary in Release mode; install the root-owned \
             VPN runtime in {} (`vpn_runtime_install`)",
            crate::vpn_runtime::RUNTIME_DIR
        )));
    }
    match policy {
        Policy::Release => Err(anyhow!(
            "root-owned OpenVPN runtime not found in {}. Install the root-owned VPN runtime \
             via `vpn_runtime_install`.",
            crate::vpn_runtime::RUNTIME_DIR
        )),
        Policy::Development => Err(anyhow!(
            "openvpn not found. For Azure VPN profiles install \
             OpenVPN 3 by running `contrib/build-openvpn3-mac.sh` \
             (Microsoft's gateway rejects 2.x clients in the Entra \
             ID auth flow). For other profiles `brew install openvpn` \
             is sufficient."
        )),
    }
}

#[cfg(test)]
fn select_openvpn(
    require_openvpn3: bool,
    is_available: impl Fn(&Path) -> bool,
) -> anyhow::Result<PathBuf> {
    let runtime = Path::new(crate::vpn_runtime::RUNTIME_DIR);
    select_openvpn_for_policy(
        Policy::Development,
        require_openvpn3,
        |path| !path.starts_with(runtime) && is_available(path),
        |_, _| Ok(()),
    )
}

/// Build `openvpn3` (`ovpncli`) argv without exposing credentials on the
/// command line (`ps aux` / `KERN_PROCARGS2`). Credentials travel in `auth_path`
/// (mode 0600 in `PRIVATE_DIR`) through the bundled client's `--auth-user-pass`
/// adapter. Upstream's `-a` means `--auto-sess` and does not read credentials.
fn build_v3_cli_args(
    config_body: &str,
    config_path: &Path,
    auth_path: Option<&Path>,
) -> Vec<OsString> {
    let mut args = Vec::new();
    // A profile without a client certificate (Azure VPN signs in with a token
    // through auth-user-pass) needs `--no-cert`, or ovpncli aborts with
    // `Missing External PKI alias`. A profile that has one must not get it.
    if !has_client_certificate(config_body) {
        args.push(OsString::from("--no-cert"));
    }
    if let Some(auth) = auth_path {
        args.push(OsString::from("--auth-user-pass"));
        args.push(auth.as_os_str().to_owned());
    }
    args.push(config_path.as_os_str().to_owned());
    args
}

/// Whether an OpenVPN config carries a client certificate: an inline
/// `<cert>` or `<pkcs12>` block, or a `cert` or `pkcs12` directive.
fn has_client_certificate(config: &str) -> bool {
    config.lines().any(|line| {
        let line = line.trim_start();
        if line.starts_with('#') || line.starts_with(';') {
            return false;
        }
        matches!(
            line.split_whitespace().next(),
            Some("<cert>" | "<pkcs12>" | "cert" | "pkcs12")
        )
    })
}

/// True when the located binary is OpenVPN 3.x. Used to switch
/// to 3.x's foreground invocation syntax; 2.x is the default path.
fn is_openvpn3(bin: &Path) -> bool {
    matches!(
        bin.file_name().and_then(|s| s.to_str()),
        Some("openvpn3" | "ovpncli")
    )
}

/// Require a canonical UUID for profile operations so short or crafted IDs can
/// never collide on files or match unrelated processes in `ps`.
fn validate_profile_id(id: &str) -> anyhow::Result<String> {
    let parsed = uuid::Uuid::try_parse(id.trim())
        .map_err(|_| anyhow!("invalid profile_id: expected a canonical UUID"))?;
    Ok(parsed.hyphenated().to_string())
}

/// Sanitize a UUID into a filesystem-safe + length-bounded id that
/// matches the kernel's identifier rules without ambiguity.
#[cfg(test)]
fn sanitize_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(36)
        .collect()
}

fn is_live_openvpn_pid(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    pid > 1
        && crate::proc::process_file_name_in(pid, OPENVPN_BIN_NAMES)
        && unsafe { libc::kill(pid, 0) } == 0
}

fn pid_path_for(safe: &str) -> PathBuf {
    Path::new(PID_DIR).join(format!("supermgr-ovpn-{safe}.pid"))
}

fn status_path_for(safe: &str) -> PathBuf {
    Path::new(PRIVATE_DIR).join(format!("{safe}.status"))
}

/// True when OpenVPN 2 created `--status <path> 5` for this session and its
/// mtime is older than `max_age` (meaning the daemon's event loop stalled or
/// entered a blocking reconnect). Absent status file (e.g. OpenVPN 3) returns
/// `false`.
fn status_file_is_stale(path: &Path, max_age: std::time::Duration) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    std::time::SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age > max_age)
}

fn signal_openvpn_pid(pid: u32, sig: libc::c_int) {
    if let Ok(raw_pid) = i32::try_from(pid) {
        // SAFETY: callers first check `is_live_openvpn_pid`, which verifies `raw_pid > 1`
        // and matches the kernel executable name against `OPENVPN_BIN_NAMES`.
        unsafe {
            libc::kill(raw_pid, sig);
        }
    }
}

struct TrackedPidEntry {
    pid_path: PathBuf,
    safe_id: String,
    live_pid: Option<u32>,
}

/// Walk `PID_DIR` for valid `supermgr-ovpn-<uuid>.pid` files and check
/// whether each recorded PID is a live OpenVPN process.
fn tracked_pid_entries() -> impl Iterator<Item = TrackedPidEntry> {
    std::fs::read_dir(PID_DIR)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let fname = entry.file_name();
            let raw_id = fname
                .to_str()?
                .strip_prefix("supermgr-ovpn-")?
                .strip_suffix(".pid")?;
            let safe_id = validate_profile_id(raw_id).ok()?;
            let pid_path = entry.path();
            let live_pid = read_pid_file(&pid_path).filter(|&p| is_live_openvpn_pid(p));
            Some(TrackedPidEntry {
                pid_path,
                safe_id,
                live_pid,
            })
        })
}

/// Stop all live OpenVPN processes belonging to `safe` (`SIGTERM`, waiting up
/// to 1.5 s before escalating to `SIGKILL`) and remove transient state files.
async fn stop_profile_processes(safe: &str) -> Vec<u32> {
    let pid_path = pid_path_for(safe);
    let mut killed: Vec<u32> = Vec::new();

    if let Some(pid) = read_pid_file(&pid_path).filter(|&p| is_live_openvpn_pid(p)) {
        signal_openvpn_pid(pid, libc::SIGTERM);
        killed.push(pid);
    }

    for pid in collect_openvpn_pids_for(safe).await {
        if killed.contains(&pid) || !is_live_openvpn_pid(pid) {
            continue;
        }
        signal_openvpn_pid(pid, libc::SIGTERM);
        killed.push(pid);
    }

    if !killed.is_empty() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1500);
        while tokio::time::Instant::now() < deadline
            && killed.iter().any(|&pid| is_live_openvpn_pid(pid))
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        for &pid in &killed {
            if is_live_openvpn_pid(pid) {
                signal_openvpn_pid(pid, libc::SIGKILL);
            }
        }
    }

    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(log_path_for(safe));
    let _ = std::fs::remove_file(status_path_for(safe));
    let _ = std::fs::remove_file(config_path_for(safe));
    let _ = std::fs::remove_file(auth_path_for(safe));
    killed
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
    let entries: Vec<TrackedPidEntry> = tracked_pid_entries().collect();
    let mut killed = 0usize;
    for entry in entries {
        if let Some(pid) = entry.live_pid {
            // SIGTERM lets openvpn flush its log and run its down script.
            signal_openvpn_pid(pid, libc::SIGTERM);
            killed += 1;
        }
        // Belt-and-braces: ps-scan for stragglers carrying this profile's
        // exact config path or daemon-name fingerprint.
        for pid in collect_openvpn_pids_for(&entry.safe_id).await {
            if is_live_openvpn_pid(pid) {
                signal_openvpn_pid(pid, libc::SIGTERM);
                killed += 1;
            }
        }
        let _ = std::fs::remove_file(&entry.pid_path);
        let _ = std::fs::remove_file(log_path_for(&entry.safe_id));
        let _ = std::fs::remove_file(status_path_for(&entry.safe_id));
        let _ = std::fs::remove_file(config_path_for(&entry.safe_id));
        let _ = std::fs::remove_file(auth_path_for(&entry.safe_id));
    }
    crate::dns::clear_vpn_dns_prefix("ovpn-");
    crate::kill_switch::deactivate_backend(crate::kill_switch::KillSwitchBackend::Openvpn);
    killed
}

/// Kernel interfaces (`utunN`) of every OpenVPN tunnel that is currently
/// alive. Cheap, no `&mut self`: scans the helper's pidfiles in `/var/run`,
/// checks liveness + executable identity, and parses the bound interface from
/// each session's log.
///
/// Used by the strongSwan teardown path so it never deletes the shared
/// full-tunnel split-default routes (`0/1` + `128.0/1`) out from under a
/// live OpenVPN session — those routes belong to whatever backend installed
/// them, and OpenVPN's `redirect-gateway def1` uses the exact same pair.
pub fn live_tunnel_interfaces() -> Vec<String> {
    // Skip dead/recycled pidfiles — a stale full-tunnel route from a dead
    // OpenVPN session SHOULD be swept, so we only protect live ones.
    tracked_pid_entries()
        .filter(|entry| entry.live_pid.is_some())
        .filter_map(|entry| {
            let body = read_openvpn_log(&log_path_for(&entry.safe_id));
            parse_tunnel_metadata(&body).0
        })
        .collect()
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
    tracked_pid_entries().any(|entry| entry.live_pid.is_some())
}

fn log_path_for(safe: &str) -> PathBuf {
    Path::new(PRIVATE_DIR).join(format!("{safe}.log"))
}

/// The log of `profile_id`'s tunnel, for `tail_log`.
pub fn log_path(profile_id: &str) -> anyhow::Result<PathBuf> {
    let safe = validate_profile_id(profile_id)?;
    Ok(log_path_for(&safe))
}

fn config_path_for(safe: &str) -> PathBuf {
    Path::new(PRIVATE_DIR).join(format!("{safe}.ovpn"))
}

fn auth_path_for(safe: &str) -> PathBuf {
    Path::new(PRIVATE_DIR).join(format!("{safe}.auth"))
}

/// Create `PRIVATE_DIR` root-only if it is missing, and refuse it if it is
/// anything but a directory only root can use.
fn ensure_private_dir() -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    match std::fs::DirBuilder::new().mode(0o700).create(PRIVATE_DIR) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("create {PRIVATE_DIR}")),
    }
    let meta =
        std::fs::symlink_metadata(PRIVATE_DIR).with_context(|| format!("stat {PRIVATE_DIR}"))?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err(anyhow!(
            "{PRIVATE_DIR} is not a directory only root can use"
        ));
    }
    Ok(())
}

/// Remove the session logs helpers up to 1.8.14 kept in `/tmp`. Only
/// root's own regular files: a name there can belong to anyone.
pub fn sweep_legacy_logs() {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(entries) = std::fs::read_dir(LEGACY_LOG_DIR) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let is_log = name
            .to_str()
            .and_then(|name| name.strip_prefix("supermgr-ovpn-"))
            .is_some_and(|rest| rest.strip_suffix(".log").is_some());
        if !is_log {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if meta.is_file() && meta.uid() == 0 {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Validate the managed OpenVPN 3 client's private credential-file format.
fn validate_v3_credentials(user: &str, password: &str) -> anyhow::Result<()> {
    // Match the managed client's file parser before writing a file or
    // starting a child, so malformed input gets a direct RPC error.
    if user.is_empty() || password.is_empty() {
        bail!("invalid OpenVPN 3 credentials: username and password are required");
    }
    if user
        .bytes()
        .chain(password.bytes())
        .any(|byte| byte < 32 || byte == 127)
    {
        bail!("invalid OpenVPN 3 credentials: control characters are not permitted");
    }
    if user.len().saturating_add(password.len()).saturating_add(2) > 1024 * 1024 {
        bail!("invalid OpenVPN 3 credentials: authentication file exceeds 1 MiB");
    }
    Ok(())
}

/// Write user/password to a root-only file in `PRIVATE_DIR`.
/// Returns the path; caller deletes after openvpn has consumed it.
fn write_auth_file(safe: &str, user: &str, password: &str) -> anyhow::Result<PathBuf> {
    if user.contains('\n')
        || user.contains('\r')
        || password.contains('\n')
        || password.contains('\r')
    {
        bail!("invalid OpenVPN credentials: newline characters are not permitted");
    }
    let path = auth_path_for(safe);
    crate::private_file::write(&path, format!("{user}\n{password}\n").as_bytes())
        .with_context(|| format!("create {}", path.display()))?;
    Ok(path)
}

// `custom_flags` requires the OpenOptionsExt trait in scope; bring it in
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

/// Pure `ps -Ao pid,command` matcher: accepts ONLY an OpenVPN binary whose
/// argv contains the exact `/var/run/supermanager-ovpn/<uuid>.ovpn` config path
/// or `supermgr-ovpn-<uuid>` daemon token, never an arbitrary substring match.
fn matching_openvpn_pids(ps_output: &str, safe: &str) -> Vec<u32> {
    let Ok(safe) = validate_profile_id(safe) else {
        return Vec::new();
    };
    let expected_config = config_path_for(&safe).to_string_lossy().into_owned();
    let expected_daemon = format!("supermgr-ovpn-{safe}");
    let mut out = Vec::new();
    for line in ps_output.lines().skip(1) {
        let mut tokens = line.split_whitespace();
        let Some(pid) = tokens.next().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if i32::try_from(pid).is_err_and(|_| true) || pid <= 1 {
            continue;
        }
        let Some(exe) = tokens.next() else {
            continue;
        };
        let is_ovpn_exe = Path::new(exe)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| OPENVPN_BIN_NAMES.contains(&name));
        if !is_ovpn_exe {
            continue;
        }
        if tokens.any(|arg| arg == expected_config || arg == expected_daemon) {
            out.push(pid);
        }
    }
    out
}

/// `ps` scan for ALL `openvpn`/`openvpn3` processes running our per-profile
/// runtime config, additionally verified via `proc_pidpath`.
async fn collect_openvpn_pids_for(safe: &str) -> Vec<u32> {
    if validate_profile_id(safe).is_err() {
        return Vec::new();
    }
    let output = match crate::proc::bounded_async(
        tokio::process::Command::new("/bin/ps").args(["-Ao", "pid,command"]),
        crate::proc::PROBE,
    )
    .await
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    matching_openvpn_pids(&text, safe)
        .into_iter()
        .filter(|&pid| is_live_openvpn_pid(pid))
        .collect()
}

/// First live `openvpn`/`openvpn3` process running `safe`'s runtime config.
async fn find_openvpn_pid_for(safe: &str) -> Option<u32> {
    collect_openvpn_pids_for(safe).await.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_route_halves_say_the_tunnel_takes_all() {
        let split = "/sbin/route add -net 10.134.0.0 -netmask 255.255.254.0 10.134.2.1\n";
        assert_eq!(
            parse_active_routes(split),
            (vec!["10.134.0.0/23".to_owned()], false)
        );

        let full = format!(
            "{split}/sbin/route add -net 0.0.0.0 -netmask 128.0.0.0 10.134.2.1\n\
             /sbin/route add -net 128.0.0.0 -netmask 128.0.0.0 10.134.2.1\n"
        );
        assert_eq!(
            parse_active_routes(&full),
            (vec!["10.134.0.0/23".to_owned()], true)
        );

        // One half is not the default route.
        let half = "/sbin/route add -net 0.0.0.0 -netmask 128.0.0.0 10.134.2.1\n";
        assert_eq!(parse_active_routes(half), (Vec::new(), false));
    }

    #[test]
    fn azure_never_falls_back_to_openvpn2() {
        for installed in [
            "/opt/homebrew/sbin/openvpn",
            "/opt/homebrew/bin/openvpn-patched",
        ] {
            let err = select_openvpn(true, |path| path == Path::new(installed)).unwrap_err();
            assert!(err.to_string().contains("Azure VPN requires OpenVPN 3"));
        }
    }

    #[test]
    fn azure_selects_openvpn3_when_both_versions_are_installed() {
        let path = select_openvpn(true, |_| true).unwrap();
        assert_eq!(path, Path::new("/opt/homebrew/bin/openvpn3"));
    }

    /// Installing OpenVPN 3 for Azure must not move every other profile
    /// onto it.
    #[test]
    fn ordinary_profiles_prefer_openvpn2_when_both_are_installed() {
        let path = select_openvpn(false, |_| true).unwrap();
        assert_eq!(path, Path::new("/opt/homebrew/bin/openvpn-patched"));
        let path = select_openvpn(false, |path| {
            path != Path::new("/opt/homebrew/bin/openvpn-patched")
                && path != Path::new("/usr/local/bin/openvpn-patched")
        })
        .unwrap();
        assert_eq!(path, Path::new("/opt/homebrew/sbin/openvpn"));
    }

    #[test]
    fn ordinary_profiles_use_openvpn3_only_as_a_last_resort() {
        let path = select_openvpn(false, |path| {
            path == Path::new("/opt/homebrew/bin/openvpn3")
        })
        .unwrap();
        assert_eq!(path, Path::new("/opt/homebrew/bin/openvpn3"));
    }

    #[test]
    fn a_client_certificate_is_recognised_in_every_form() {
        for config in [
            "client\n<cert>\n-----BEGIN CERTIFICATE-----\n</cert>\n",
            "client\ncert client.crt\nkey client.key\n",
            "client\npkcs12 client.p12\n",
            "client\n<pkcs12>\nMIIK\n</pkcs12>\n",
        ] {
            assert!(has_client_certificate(config), "{config}");
        }
        for config in [
            // Azure VPN: a token through auth-user-pass, no certificate.
            "client\nauth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\n</ca>\n",
            "client\n# cert client.crt\n; pkcs12 old.p12\n",
            "client\nremote-cert-tls server\n",
        ] {
            assert!(!has_client_certificate(config), "{config}");
        }
    }

    #[test]
    fn ordinary_openvpn_keeps_v2_fallback() {
        let path = select_openvpn(false, |path| {
            path == Path::new("/opt/homebrew/sbin/openvpn")
        })
        .unwrap();
        assert_eq!(path, Path::new("/opt/homebrew/sbin/openvpn"));
    }

    #[test]
    fn connect_requests_carry_the_configuration() {
        let args: OvpnConnectArgs =
            serde_json::from_str(r#"{"profile_id":"test","config":"client\n"}"#).unwrap();
        assert!(!args.require_openvpn3);
        assert!(args.has_configuration());
        assert_eq!(args.configuration().unwrap(), "client\n");
        let args: OvpnConnectArgs = serde_json::from_str(
            r#"{"profile_id":"test","config":"client\n","require_openvpn3":true}"#,
        )
        .unwrap();
        assert!(args.require_openvpn3);
        // What the GUI enrols before a first connect: nothing to run yet.
        let args: OvpnConnectArgs = serde_json::from_str(r#"{"profile_id":"test"}"#).unwrap();
        assert!(!args.has_configuration());
        assert!(args.configuration().is_err());
    }

    /// Legacy `config_file` payloads are no longer read from disk; inline
    /// `config` is required.
    #[test]
    fn connect_requests_ignore_legacy_config_file_and_require_inline_config() {
        let legacy: OvpnConnectArgs = serde_json::from_str(
            r#"{"profile_id":"26b4fcc6-097a-41e7-932e-9a6d2a4663e5","config_file":"/etc/hosts"}"#,
        )
        .unwrap();
        assert!(!legacy.has_configuration());
        assert!(legacy.configuration().is_err());
        assert!(validate_connect_args(&legacy).is_err());
    }

    #[test]
    fn sanitize_strips_unsafe_chars() {
        assert_eq!(sanitize_id("abc/../etc/passwd"), "abcetcpasswd");
        assert_eq!(
            sanitize_id("26b4fcc6-097a-41e7-932e-9a6d2a4663e5"),
            "26b4fcc6-097a-41e7-932e-9a6d2a4663e5"
        );
    }

    #[test]
    fn profile_id_requires_canonical_uuid_and_ps_scan_never_matches_substrings() {
        for bad in ["", "1", "a", "abc/../etc/passwd", "not-a-uuid"] {
            assert!(validate_profile_id(bad).is_err(), "{bad:?}");
            assert_eq!(
                matching_openvpn_pids("  PID COMMAND\n    1 /sbin/launchd\n", bad),
                Vec::<u32>::new()
            );
        }

        let id = "26b4fcc6-097a-41e7-932e-9a6d2a4663e5";
        assert_eq!(validate_profile_id(id).unwrap(), id);

        let ps = format!(
            "  PID COMMAND\n\
                 1 /sbin/launchd\n\
               412 /usr/bin/vim /var/run/supermanager-ovpn/{id}.ovpn\n\
               513 /opt/homebrew/sbin/openvpn --config /tmp/{id}.ovpn\n\
               614 /Library/PrivilegedHelperTools/SuperManagerVPN/openvpn --config /var/run/supermanager-ovpn/{id}.ovpn --daemon supermgr-ovpn-{id}\n\
               715 /Library/PrivilegedHelperTools/SuperManagerVPN/openvpn3 --no-cert --auth-user-pass /var/run/supermanager-ovpn/{id}.auth /var/run/supermanager-ovpn/{id}.ovpn\n"
        );
        assert_eq!(matching_openvpn_pids(&ps, id), vec![614, 715]);
    }

    #[test]
    fn openvpn3_cli_args_use_the_credentials_file_adapter_not_auto_session() {
        let cfg_path = Path::new("/var/run/supermanager-ovpn/test.ovpn");
        let auth_path = Path::new("/var/run/supermanager-ovpn/test.auth");
        let args = build_v3_cli_args("client\nauth-user-pass\n", cfg_path, Some(auth_path));
        let rendered: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            rendered,
            vec![
                "--no-cert",
                "--auth-user-pass",
                "/var/run/supermanager-ovpn/test.auth",
                "/var/run/supermanager-ovpn/test.ovpn",
            ]
        );
        for forbidden in ["-a", "--auto-sess", "--password", "-p", "--username", "-u"] {
            assert!(!rendered.iter().any(|a| a == forbidden), "{rendered:?}");
        }
    }

    #[test]
    fn openvpn3_certificate_profiles_keep_certificate_authentication() {
        let cfg_path = Path::new("/var/run/supermanager-ovpn/client.ovpn");
        let config = "client\n<cert>\nclient certificate\n</cert>\n";
        assert_eq!(
            build_v3_cli_args(config, cfg_path, None),
            [cfg_path.as_os_str()]
        );

        // A certificate profile may also require a password. Paths are
        // individual argv entries, including when a development path has spaces.
        let auth_path = Path::new("/tmp/private vpn/client.auth");
        assert_eq!(
            build_v3_cli_args(config, cfg_path, Some(auth_path)),
            [
                OsString::from("--auth-user-pass"),
                auth_path.as_os_str().to_owned(),
                cfg_path.as_os_str().to_owned(),
            ]
        );
    }

    #[test]
    fn credential_lines_cannot_change_the_authentication_file_structure() {
        for (user, password) in [
            ("AzureAD\nother-user", "token"),
            ("AzureAD\r", "token"),
            ("AzureAD", "token\nextra-line"),
            ("AzureAD", "token\r"),
        ] {
            let err = write_auth_file("unused", user, password).unwrap_err();
            assert!(err.to_string().contains("newline characters"));
        }
    }

    #[test]
    fn openvpn3_credentials_match_the_managed_client_boundary() {
        for (user, password) in [
            ("", "token"),
            ("AzureAD", ""),
            ("AzureAD\t", "token"),
            ("AzureAD", "token\0tail"),
            ("AzureAD", "token\u{7f}"),
        ] {
            let error = validate_v3_credentials(user, password).unwrap_err();
            assert!(error
                .to_string()
                .starts_with("invalid OpenVPN 3 credentials:"));
            assert!(!error.to_string().contains("token"));
        }
        let maximum_password = "x".repeat(1024 * 1024 - "AzureAD".len() - 2);
        validate_v3_credentials("AzureAD", &maximum_password).unwrap();
        assert!(validate_v3_credentials("AzureAD", &(maximum_password + "x")).is_err());
        validate_v3_credentials("brüker", "valid-token").unwrap();
    }

    #[test]
    fn release_policy_refuses_unprivileged_openvpn_and_prefers_root_runtime() {
        let err = select_openvpn_for_policy(
            Policy::Release,
            false,
            |path| path == Path::new("/opt/homebrew/sbin/openvpn"),
            |path, _| Err(anyhow!("{} owned by uid 501", path.display())),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("vpn_runtime_install"),
            "{err:#}"
        );

        let root_bin = Path::new(crate::vpn_runtime::RUNTIME_DIR).join("openvpn3");
        let chosen = select_openvpn_for_policy(
            Policy::Release,
            true,
            |path| path == root_bin || path == Path::new("/opt/homebrew/bin/openvpn3"),
            |path, _| {
                if path == root_bin {
                    Ok(())
                } else {
                    Err(anyhow!("unprivileged"))
                }
            },
        )
        .unwrap();
        assert_eq!(chosen, root_bin);
    }

    #[test]
    fn event_detail_truncates_cleanly_at_multibyte_utf8_boundary() {
        // Place a 3-byte UTF-8 character ('…' = E2 80 A6) straddling byte 120.
        let line = format!("EVENT: {}…tail [ERR]", "a".repeat(112));
        let detail = event_detail(&line, "EVENT:").unwrap();
        assert!(detail.ends_with('…'), "{detail:?}");
    }

    #[test]
    fn openvpn2_log_transitions_out_of_connected_on_soft_restart_or_sigterm() {
        let reconnecting_log = "\
Initialization Sequence Completed\n\
[server] Inactivity timeout (--ping-restart), restarting\n\
SIGUSR1[soft,ping-restart] received, process restarting\n";
        let (st, reason) = last_event_from_log(reconnecting_log);
        assert_eq!(st, OvpnState::Reconnecting);
        assert!(reason.unwrap_or_default().contains("ping-restart"));

        let recovered_log = format!("{reconnecting_log}Initialization Sequence Completed\n");
        let (st2, reason2) = last_event_from_log(&recovered_log);
        assert_eq!(st2, OvpnState::Connected);
        assert!(reason2.is_none());

        let terminated_log = format!("{recovered_log}SIGTERM[hard,] received, process exiting\n");
        let (st3, _) = last_event_from_log(&terminated_log);
        assert_eq!(st3, OvpnState::Disconnected);
    }

    #[test]
    fn bounded_log_reader_preserves_setup_header_and_latest_tail_events() {
        use std::fmt::Write as _;

        let dir = std::env::temp_dir().join(format!("smgr-ovpn-log-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("test.log");
        let mut content = String::from(
            "TUN/TAP device /dev/utun9 opened\n\
             /sbin/ifconfig utun9 10.8.0.2 10.8.0.1 mtu 1500 netmask 255.255.255.255 up\n\
             Initialization Sequence Completed\n",
        );
        for i in 0..1000 {
            let _ = writeln!(content, "filler-line-{i:04}-xxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        }
        content.push_str("SIGUSR1[soft,ping-restart] received, process restarting\n");
        std::fs::write(&log, &content).unwrap();

        let sampled = read_openvpn_log_bounded(&log, 256, 256);
        assert!(sampled.len() <= 520, "sampled len={}", sampled.len());
        assert_eq!(parse_tunnel_metadata(&sampled).0.as_deref(), Some("utun9"));
        assert_eq!(last_event_from_log(&sampled).0, OvpnState::Reconnecting);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
