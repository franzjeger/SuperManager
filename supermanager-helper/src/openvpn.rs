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

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;

const BREW_PREFIXES: &[&str] = &["/opt/homebrew", "/usr/local"];

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

#[derive(Default)]
pub struct OpenVpn {}

#[derive(Debug, Deserialize)]
pub struct OvpnConnectArgs {
    pub profile_id: String,
    /// The profile's configuration.
    #[serde(default)]
    pub config: Option<String>,
    /// Where helpers up to 1.8.14 were told to read the configuration.
    /// Only a connect stored for auto-reconnect by one of them still
    /// names it; see `OvpnConnectArgs::configuration`.
    #[serde(default)]
    pub config_file: Option<String>,
    /// Azure Entra ID tokens require our OpenVPN 3 client path.
    /// Never silently fall back to OpenVPN 2 for these sessions.
    #[serde(default)]
    pub require_openvpn3: bool,
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
}

impl OvpnConnectArgs {
    /// Whether the request carries a configuration to run.
    #[must_use]
    pub fn has_configuration(&self) -> bool {
        self.config.is_some() || self.config_file.is_some()
    }

    /// The configuration to run: the one the request carries or, for a
    /// connect an older helper stored for auto-reconnect, the file it
    /// names. That file is read without following a symlink and must be
    /// a regular file of configuration size; it is checked like any other
    /// configuration.
    fn configuration(&self) -> anyhow::Result<String> {
        use std::io::Read as _;
        if let Some(config) = &self.config {
            return Ok(config.clone());
        }
        let Some(path) = &self.config_file else {
            return Err(anyhow!("the connect request carries no configuration"));
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open {path}"))?;
        let meta = file.metadata().with_context(|| format!("stat {path}"))?;
        if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
            return Err(anyhow!("{path} is not a profile configuration"));
        }
        let mut config = String::new();
        file.take(MAX_CONFIG_BYTES)
            .read_to_string(&mut config)
            .with_context(|| format!("read {path}"))?;
        Ok(config)
    }
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
        let openvpn = locate_openvpn(args.require_openvpn3)?;
        tracing::info!(
            "ovpn_connect: profile={} openvpn={}",
            args.profile_id,
            openvpn.display()
        );
        let config_body = args.configuration()?;
        crate::openvpn_config::check(&config_body)
            .map_err(|refusal| anyhow!("the profile can't be used as it is: {refusal}"))?;

        // Suppress the connectivity watchdog during the connect/handshake window.
        // A full-tunnel OpenVPN/Azure profile installs 0/1+128/1 and briefly has
        // no working egress while TLS/auth/route-push complete; without this the
        // watchdog would count that as an outage and fire panic_reset, ripping
        // the just-installed split-defaults out from under the connecting tunnel.
        // The reconciler arms the same pause around its own route work.
        crate::connectivity_watchdog::pause_for(45);

        tracing::info!(
            "ovpn_connect: config bytes={} has_remote={} has_ca={} has_tls_auth={} has_tls_crypt={} has_auth_user_pass={} has_client_cert={}",
            config_body.len(),
            config_body.contains("\nremote ") || config_body.starts_with("remote "),
            config_body.contains("<ca>"),
            config_body.contains("<tls-auth>"),
            config_body.contains("<tls-crypt>"),
            config_body.contains("auth-user-pass"),
            has_client_certificate(&config_body),
        );

        let safe = sanitize_id(&args.profile_id);
        let pid_path = pid_path_for(&safe);
        let log_path = log_path_for(&safe);
        let config_path = config_path_for(&safe);

        ensure_private_dir()?;
        crate::private_file::write(&config_path, config_body.as_bytes())
            .with_context(|| format!("write {}", config_path.display()))?;
        // Start the log empty. Otherwise our post-spawn diagnostic check
        // (`FATAL.iter().find(|m| log_body.contains(m))`) sees stale
        // errors from previous failed attempts — particularly when
        // openvpn 2.x's `--daemon` retry loop keeps appending its own
        // failures to the same path. Fresh log per spawn = unambiguous
        // diagnostics.
        crate::private_file::write(&log_path, b"")
            .with_context(|| format!("create {}", log_path.display()))?;
        // Same for the PID file — a stale PID from a previous
        // attempt causes the post-spawn `kill(pid, 0)` aliveness
        // check to spuriously claim a different process is "the
        // daemon."
        let _ = std::fs::remove_file(&pid_path);

        let auth_path = if args.username.is_some() && args.password.is_some() {
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

        // Build the argv. We dispatch on which binary we located:
        //
        //   2.x: `openvpn --config FILE --daemon NAME --writepid …`
        //        (forks itself; we wait for the parent's exit code
        //        and then poll the log for "Initialization Sequence
        //        Completed".)
        //
        //   3.x: `openvpn3 --username U --password P CONFIG`
        //        (the upstream `ovpncli` test client; runs in
        //        FOREGROUND, no `--daemon` mode. We spawn it,
        //        write our own PID file from the child's PID,
        //        redirect its stdout/stderr to our log file, and
        //        let it run as a child of this helper. On
        //        disconnect we SIGTERM the PID like 2.x.)
        let is_v3 = is_openvpn3(&openvpn);
        tracing::info!(
            "ovpn_connect: spawning {} (v3={})",
            openvpn.display(),
            is_v3
        );
        let output = if is_v3 {
            use std::os::unix::process::CommandExt as _;
            // Open the log file for stdout+stderr redirection.
            // ovpncli writes status to stderr; we merge both into
            // one log.
            let log_for_stdout = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&log_path)
                .with_context(|| format!("open log {}", log_path.display()))?;
            let log_for_stderr = log_for_stdout.try_clone().context("dup log fd")?;

            let user = args.username.as_deref().unwrap_or("AzureAD");
            let pass = args.password.as_deref().unwrap_or("");

            // KNOWN LIMITATION: the JWT shows up in `ps aux` /
            // `/proc/<pid>/cmdline` because ovpncli only takes
            // the password via `--password ARG`. We tried piping
            // it through a PTY (ovpncli's `get_password()` uses
            // `getpass(/dev/tty)`) but couldn't get the bytes
            // delivered reliably — the write to master succeeded
            // and `getpass()` returned an empty string. The
            // upstream-clean fix is `--password-fd N` in ovpncli
            // (see openvpn3 issue tracker); until then, the only
            // mitigations are (a) keep tokens short-lived (Azure
            // gives us 1h) and (b) trust the operator's machine.
            let mut cmd = Command::new(&openvpn);
            // A profile without a client certificate (Azure VPN signs in
            // with a token through auth-user-pass) needs `--no-cert`, or
            // ovpncli aborts with `Missing External PKI alias`. A profile
            // that has one must not get it: the certificate would be ignored
            // and the server would refuse the connection.
            if !has_client_certificate(&config_body) {
                cmd.arg("--no-cert");
            }
            cmd.arg("--username")
                .arg(user)
                .arg("--password")
                .arg(pass)
                .arg(&config_path)
                .stdin(std::process::Stdio::null())
                .stdout(log_for_stdout)
                .stderr(log_for_stderr);
            unsafe {
                cmd.as_std_mut().pre_exec(|| {
                    // New session — child won't get SIGHUP if the
                    // helper restarts.
                    libc::setsid();
                    Ok(())
                });
            }
            let child = cmd
                .spawn()
                .with_context(|| format!("spawn {} (ovpncli)", openvpn.display()))?;
            let pid = child
                .id()
                .ok_or_else(|| anyhow!("ovpncli spawn returned no pid"))?;
            tracing::info!(
                "ovpn_connect: ovpncli spawned pid={} log={}",
                pid,
                log_path.display()
            );
            let _ = std::fs::write(&pid_path, format!("{pid}\n"));
            // Reap the child asynchronously so it doesn't become
            // a zombie if the user never disconnects.
            tokio::spawn(async move {
                let mut child = child;
                let _ = child.wait().await;
            });
            // Auth file (if we created one) is unused by ovpncli
            // — wipe it.
            if let Some(ref auth) = auth_path {
                let _ = std::fs::remove_file(auth);
            }
            // Synthesize a "spawn succeeded" Output so the
            // post-spawn diagnostic path below (5s settle, fatal
            // marker scan) covers the v3 case too.
            std::process::Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        } else {
            let mut argv: Vec<String> = vec![
                "--config".into(),
                config_path.display().to_string(),
                // After the configuration, so it wins: built-in commands
                // only, never a script. `openvpn_config::check` allows no
                // directive that names one either.
                "--script-security".into(),
                "1".into(),
                "--daemon".into(),
                format!("supermgr-ovpn-{safe}"),
                "--writepid".into(),
                pid_path.display().to_string(),
                "--log".into(),
                log_path.display().to_string(),
                "--verb".into(),
                "3".into(),
            ];
            if let Some(ref auth) = auth_path {
                argv.push("--auth-user-pass".into());
                argv.push(auth.display().to_string());
            }
            tracing::info!(
                "ovpn_connect: argv = {} {}",
                openvpn.display(),
                argv.join(" ")
            );
            let mut cmd = Command::new(&openvpn);
            cmd.args(&argv);
            // `--daemon` forks and the parent exits right after option
            // parsing, so this normally returns in well under a second.
            crate::proc::bounded_async(&mut cmd, crate::proc::MUTATE)
                .await
                .with_context(|| {
                    format!(
                        "run {} --config {}",
                        openvpn.display(),
                        config_path.display()
                    )
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
            tracing::error!(
                "ovpn_connect: NON-ZERO exit, reading {}",
                log_path.display()
            );
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let log_tail = std::fs::read_to_string(&log_path)
                .ok()
                .map(|s| {
                    // Last ~20 non-empty lines is plenty — early
                    // openvpn errors fit comfortably and we don't
                    // want to flood the GUI alert.
                    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
                    let start = lines.len().saturating_sub(20);
                    lines[start..].join("\n")
                })
                .unwrap_or_default();
            let combined = match (stderr.is_empty(), log_tail.is_empty()) {
                (false, false) => format!("{stderr}\n--- log ---\n{log_tail}"),
                (true, false) => log_tail,
                (false, true) => stderr,
                (true, true) => "(no diagnostic output)".to_owned(),
            };
            tracing::error!("ovpn_connect: refused to start:\n{combined}");
            let _ = std::fs::remove_file(&config_path);
            return Ok(OvpnConnectResult {
                success: false,
                message: format!("openvpn refused to start:\n{combined}"),
            });
        }
        tracing::info!(
            "ovpn_connect: spawn succeeded for profile={}",
            args.profile_id
        );

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
                    .unwrap_or_else(|| {
                        "openvpn died after fork (no PID, no fatal marker — see log)".to_owned()
                    });
                let log_tail = {
                    let lines: Vec<&str> =
                        log_body.lines().filter(|l| !l.trim().is_empty()).collect();
                    let start = lines.len().saturating_sub(25);
                    lines[start..].join("\n")
                };
                tracing::error!("ovpn_connect: post-fork failure: {reason}\n{log_tail}");
                let _ = std::fs::remove_file(&config_path);
                return Ok(OvpnConnectResult {
                    success: false,
                    message: format!("{reason}\n\nLast 25 log lines:\n{log_tail}"),
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
        let safe = sanitize_id(&args.profile_id);
        let pid_path = pid_path_for(&safe);
        let mut killed: Vec<u32> = Vec::new();

        if let Some(pid) = read_pid_file(&pid_path) {
            // SIGTERM lets openvpn flush its log + run its
            // `down` script, which is what we want.
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            killed.push(pid);
        }

        // Belt-and-braces: scan ps for any openvpn process whose
        // argv carries this profile's daemon-name fingerprint and
        // SIGTERM each. Idempotent — sending SIGTERM to a process
        // that already exited (or doesn't exist) is a no-op for us.
        let stragglers = collect_openvpn_pids_for(&safe).await;
        for pid in stragglers {
            if killed.contains(&pid) {
                continue;
            }
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            killed.push(pid);
        }

        // Cleanup files regardless of whether the kill landed —
        // sticking a stale PID file is worse than missing one
        // (next connect's read says "tunnel already up").
        let _ = std::fs::remove_file(&pid_path);
        let _ = std::fs::remove_file(log_path_for(&safe));
        let _ = std::fs::remove_file(config_path_for(&safe));

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
        let safe = sanitize_id(&args.profile_id);
        let pid_path = pid_path_for(&safe);
        let log_path = log_path_for(&safe);

        let live_pid: Option<u32> = match read_pid_file(&pid_path) {
            Some(pid) if unsafe { libc::kill(pid as i32, 0) } == 0 => Some(pid),
            Some(_) => {
                // Stale file — clean up so subsequent polls don't
                // keep finding it.
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
            interface: if connected { interface } else { None },
            virtual_ip: if connected { virtual_ip } else { None },
            virtual_gateway: if connected { virtual_gateway } else { None },
            active_routes: if connected { active_routes } else { Vec::new() },
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
        if dest == "0.0.0.0" && prefix == 1 {
            continue;
        }
        if dest == "128.0.0.0" && prefix == 1 {
            continue;
        }
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
    let octets: Vec<u8> = mask
        .split('.')
        .map(|s| s.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 4 {
        return None;
    }
    let bits = ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32);
    let leading = bits.leading_ones();
    let trailing = bits.trailing_zeros();
    if leading + trailing != 32 {
        return None;
    }
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
fn locate_openvpn(require_openvpn3: bool) -> anyhow::Result<PathBuf> {
    select_openvpn(require_openvpn3, |path| path.is_file())
}

/// Which OpenVPN runs a profile. Azure VPN needs OpenVPN 3 and gets nothing
/// else. Every other profile gets OpenVPN 2 when it is installed and OpenVPN
/// 3 only as a last resort: OpenVPN 3 used to come first for everything, so
/// installing it for Azure moved every other profile onto it, where the
/// password travels on the command line.
fn select_openvpn(
    require_openvpn3: bool,
    is_available: impl Fn(&Path) -> bool,
) -> anyhow::Result<PathBuf> {
    const OVPN3_PATHS: &[&str] = &[
        "/opt/homebrew/bin/openvpn3",
        "/usr/local/bin/openvpn3",
        "/opt/local/bin/openvpn3",
    ];
    let openvpn3 = || {
        OVPN3_PATHS
            .iter()
            .map(Path::new)
            .find(|path| is_available(path))
            .map(Path::to_path_buf)
    };
    if require_openvpn3 {
        return openvpn3().ok_or_else(|| {
            anyhow!(
                "Azure VPN requires OpenVPN 3, which is not installed. \
             OpenVPN 2 can fail to fit the Microsoft sign-in token in its TLS buffer. \
             Install OpenVPN 3 using contrib/build-openvpn3-mac.sh, then try again."
            )
        });
    }
    // Locally-built openvpn 2.x with patched `TLS_CHANNEL_BUF_SIZE`.
    // Useful for non-Azure profiles where 2.x works fine — kept
    // for backwards compatibility but won't help with Azure VPN.
    const PATCHED_PATHS: &[&str] = &[
        "/opt/homebrew/bin/openvpn-patched",
        "/usr/local/bin/openvpn-patched",
    ];
    for path in PATCHED_PATHS {
        if is_available(Path::new(path)) {
            return Ok(PathBuf::from(path));
        }
    }
    for prefix in BREW_PREFIXES {
        let candidate = Path::new(prefix).join("sbin/openvpn");
        if is_available(&candidate) {
            return Ok(candidate);
        }
        let alt = Path::new(prefix).join("bin/openvpn");
        if is_available(&alt) {
            return Ok(alt);
        }
    }
    if let Some(path) = openvpn3() {
        return Ok(path);
    }
    Err(anyhow!(
        "openvpn not found. For Azure VPN profiles install \
         OpenVPN 3 by running `contrib/build-openvpn3-mac.sh` \
         (Microsoft's gateway rejects 2.x clients in the Entra \
         ID auth flow). For other profiles `brew install openvpn` \
         is sufficient."
    ))
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
/// to 3.x's session-start sub-command syntax when it's the only
/// thing installed; 2.x is the default and validated path.
fn is_openvpn3(bin: &Path) -> bool {
    bin.file_name().and_then(|s| s.to_str()) == Some("openvpn3")
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
    let Ok(entries) = std::fs::read_dir(PID_DIR) else {
        return 0;
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else {
            continue;
        };
        let Some(safe) = fname
            .strip_prefix("supermgr-ovpn-")
            .and_then(|s| s.strip_suffix(".pid"))
        else {
            continue;
        };
        if let Some(pid) = read_pid_file(&entry.path()) {
            if unsafe { libc::kill(pid as i32, 0) } == 0 {
                // SIGTERM lets openvpn flush its log and run its down script.
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                killed += 1;
            }
        }
        // Belt-and-braces: ps-scan for stragglers carrying this profile's
        // daemon-name fingerprint (catches a tunnel whose pidfile was lost).
        for pid in collect_openvpn_pids_for(safe).await {
            if unsafe { libc::kill(pid as i32, 0) } == 0 {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                killed += 1;
            }
        }
        let _ = std::fs::remove_file(entry.path());
        let _ = std::fs::remove_file(log_path_for(safe));
        let _ = std::fs::remove_file(config_path_for(safe));
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
    let Ok(entries) = std::fs::read_dir(PID_DIR) else {
        return out;
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else {
            continue;
        };
        let Some(safe) = fname
            .strip_prefix("supermgr-ovpn-")
            .and_then(|s| s.strip_suffix(".pid"))
        else {
            continue;
        };
        let Some(pid) = read_pid_file(&entry.path()) else {
            continue;
        };
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
    let Ok(entries) = std::fs::read_dir(PID_DIR) else {
        return false;
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else {
            continue;
        };
        if fname
            .strip_prefix("supermgr-ovpn-")
            .and_then(|s| s.strip_suffix(".pid"))
            .is_none()
        {
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
    Path::new(PRIVATE_DIR).join(format!("{safe}.log"))
}

/// The log of `profile_id`'s tunnel, for `tail_log`.
pub fn log_path(profile_id: &str) -> PathBuf {
    log_path_for(&sanitize_id(profile_id))
}

fn config_path_for(safe: &str) -> PathBuf {
    Path::new(PRIVATE_DIR).join(format!("{safe}.ovpn"))
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

/// Write user/password to a root-only file in `PRIVATE_DIR`.
/// Returns the path; caller deletes after openvpn has consumed it.
fn write_auth_file(safe: &str, user: &str, password: &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(PRIVATE_DIR).join(format!("{safe}.auth"));
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

/// `ps` scan for ALL `openvpn` processes whose argv contains our
/// per-profile daemon name. Used by disconnect to catch
/// stragglers; status takes the first.
async fn collect_openvpn_pids_for(safe: &str) -> Vec<u32> {
    // Match on the bare profile id rather than the
    // `supermgr-ovpn-` daemon-name prefix — that prefix only
    // appears for openvpn 2.x in `--daemon` mode. ovpncli has
    // no daemon-name argv, but the config-file path DOES carry
    // the profile id (`PRIVATE_DIR/<id>.ovpn`), so a bare-id
    // match catches both backends.
    let needle = safe.to_string();
    let mut out: Vec<u32> = Vec::new();
    let output = match crate::proc::bounded_async(
        tokio::process::Command::new("/bin/ps").args(["-Ao", "pid,command"]),
        crate::proc::PROBE,
    )
    .await
    {
        Ok(o) if o.status.success() => o,
        _ => return out,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        if !line.contains(&needle) {
            continue;
        }
        let mut parts = line.split_whitespace();
        if let Some(pid_str) = parts.next() {
            if let Ok(pid) = pid_str.parse::<u32>() {
                out.push(pid);
            }
        }
    }
    out
}

/// `ps` scan for an `openvpn` process whose argv contains our
/// per-profile daemon name (`supermgr-ovpn-<safe>`). Returns the
/// PID of the first match; None if no live process matches.
///
/// We look at argv rather than process name because openvpn calls
/// itself "openvpn" regardless of which profile it's running. The
/// daemon-name string is the per-profile fingerprint we wrote into
/// the `--daemon` flag in `connect`.
async fn find_openvpn_pid_for(safe: &str) -> Option<u32> {
    // Match on the bare profile id rather than the
    // `supermgr-ovpn-` daemon-name prefix — that prefix only
    // appears for openvpn 2.x in `--daemon` mode. ovpncli has
    // no daemon-name argv, but the config-file path DOES carry
    // the profile id (`PRIVATE_DIR/<id>.ovpn`), so a bare-id
    // match catches both backends.
    let needle = safe.to_string();
    let output = crate::proc::bounded_async(
        tokio::process::Command::new("/bin/ps").args(["-Ao", "pid,command"]),
        crate::proc::PROBE,
    )
    .await
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        if !line.contains(&needle) {
            continue;
        }
        let mut parts = line.split_whitespace();
        if let Some(pid_str) = parts.next() {
            if let Ok(pid) = pid_str.parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A connect an older helper stored for auto-reconnect names a file.
    /// It is read only as a regular file, never through a symlink.
    #[test]
    fn a_stored_connect_that_names_a_file_reads_only_a_regular_file() {
        let dir = std::env::temp_dir().join(format!("supermanager-ovpn-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("profile.ovpn");
        std::fs::write(&file, "client\n").unwrap();
        let link = dir.join("link.ovpn");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let stored = |path: &Path| OvpnConnectArgs {
            profile_id: "test".into(),
            config: None,
            config_file: Some(path.display().to_string()),
            require_openvpn3: false,
            username: None,
            password: None,
        };
        assert_eq!(stored(&file).configuration().unwrap(), "client\n");
        assert!(stored(&link).configuration().is_err());
        assert!(stored(&dir).configuration().is_err());
        std::fs::remove_dir_all(dir).unwrap();
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
