//! FortiGate SSL-VPN tunnel control via openfortivpn.
//!
//! ## Why this exists separately from strongswan.rs
//!
//! FortiGate offers two unrelated VPN services on the same
//! appliance:
//!
//!   - **IPsec / IKEv2** on UDP 500 + 4500.
//!     Handled by `strongswan.rs`.
//!   - **SSL-VPN** on TCP 443 (or a port the operator picked).
//!     Proprietary protocol that mostly looks like PPP over
//!     TLS. FortiClient is the official client; on Linux/macOS
//!     the open-source `openfortivpn` (Adrien Verge) speaks the
//!     same protocol.
//!
//! In practice almost every FortiGate end-user deployment uses
//! SSL-VPN, because it sails through corporate firewalls that
//! block UDP 500/4500. IPsec is reserved for site-to-site and
//! admin tunnels — meaning a user account configured for
//! "FortiClient" usually has SSL-VPN access ONLY, and our
//! strongSwan path fails at the auth phase even with correct
//! credentials. This module closes that gap.
//!
//! ## Architecture
//!
//! `brew install openfortivpn` puts the binary at
//! `<brew>/bin/openfortivpn`. We launch one openfortivpn
//! process per active profile, supervised by this helper. The
//! child writes its PID to
//! `/var/run/supermgr-forti-<sanitized-id>.pid`; disconnect /
//! status look up the PID from there.
//!
//! ## What the GUI sends us
//!
//! - `profile_id` (UUID from the daemon)
//! - `host`, `port` (port defaults to 443; FortiGate admins
//!   sometimes move SSL-VPN to a non-default port)
//! - `username`, `password` — passed via `-u` + a `--pppd-…`
//!   stdin pipe so the password never appears on the
//!   process listing
//! - `trusted_cert` (optional SHA-256 fingerprint) — for
//!   self-signed certs where the operator has verified the
//!   fingerprint out of band. Without one, openfortivpn falls
//!   back to the system trust store.
//!
//! ## Credential delivery
//!
//! openfortivpn reads the password either from `-p <pw>`
//! (visible in `ps`) or from stdin when invoked with no `-p`.
//! We use stdin so the password never lands in `/proc/*/cmdline`.
//!
//! ## Logging
//!
//! Each session logs to `/tmp/supermgr-forti-<sanitized-id>.log`.
//! Same world-readable rationale as openvpn.rs.

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const BREW_PREFIXES: &[&str] = &["/opt/homebrew", "/usr/local"];

const PID_DIR: &str = "/var/run";
const LOG_DIR: &str = "/tmp";

#[derive(Default)]
pub struct FortiVpn {}

#[derive(Debug, Deserialize)]
pub struct FortiConnectArgs {
    pub profile_id: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    /// Optional SHA-256 fingerprint of the server cert.
    /// Passed via `--trusted-cert`. Useful when the gateway
    /// presents a self-signed or non-public-CA cert and the
    /// operator has verified its fingerprint via FortiClient
    /// or the FortiGate UI.
    #[serde(default)]
    pub trusted_cert: Option<String>,
    /// When true, the helper passes `--no-routes` to
    /// openfortivpn — we don't replace the default route, the
    /// operator splits manually via the routing pane.
    #[serde(default)]
    pub no_default_route: bool,
}

fn default_port() -> u16 {
    443
}

#[derive(Debug, Deserialize)]
pub struct FortiDisconnectArgs {
    pub profile_id: String,
}

#[derive(Debug, Deserialize)]
pub struct FortiStatusArgs {
    pub profile_id: String,
}

#[derive(Debug, Serialize)]
pub struct FortiConnectResult {
    pub pid: u32,
    pub log_path: String,
}

#[derive(Debug, Serialize)]
pub struct FortiStatusResult {
    pub state: String, // "connected" | "connecting" | "disconnected"
    pub pid: Option<u32>,
    /// The last ~64 lines of the per-profile log so the GUI can
    /// surface AUTH_FAILED / cert-verify / timeout / etc.
    /// without making a second RPC.
    pub recent_log: Vec<String>,
}

impl FortiVpn {
    pub fn new() -> Self {
        Self::default()
    }

    /// Locate the `openfortivpn` binary in either Homebrew
    /// prefix. Returns an actionable error message if the
    /// operator hasn't installed it.
    fn binary_path() -> anyhow::Result<PathBuf> {
        for prefix in BREW_PREFIXES {
            let p = Path::new(prefix).join("bin/openfortivpn");
            if p.exists() {
                return Ok(p);
            }
        }
        Err(anyhow!(
            "openfortivpn isn't installed. Install via Homebrew: \
             `brew install openfortivpn`. We need it because \
             FortiClient's SSL-VPN protocol is proprietary; \
             openfortivpn is the open-source client that speaks it."
        ))
    }

    fn pid_path(profile_id: &str) -> PathBuf {
        PathBuf::from(format!(
            "{PID_DIR}/supermgr-forti-{}.pid",
            sanitize_id(profile_id)
        ))
    }

    fn log_path(profile_id: &str) -> PathBuf {
        PathBuf::from(format!(
            "{LOG_DIR}/supermgr-forti-{}.log",
            sanitize_id(profile_id)
        ))
    }

    /// Launch openfortivpn for a single profile. Returns the
    /// PID once the child is up. Note: openfortivpn does its
    /// TLS handshake + PPP negotiation asynchronously, so a
    /// successful return here means the process started — the
    /// caller should poll `status` (or read the log) to see
    /// whether the tunnel actually came up.
    pub async fn connect(&mut self, args: FortiConnectArgs) -> anyhow::Result<FortiConnectResult> {
        let bin = Self::binary_path()?;
        let pid_path = Self::pid_path(&args.profile_id);
        let log_path = Self::log_path(&args.profile_id);

        // Refuse to overwrite an active tunnel — operator must
        // disconnect first. Same semantics as openvpn.rs.
        if let Some(pid) = read_pid_if_alive(&pid_path) {
            return Err(anyhow!(
                "profile {} is already connected (pid {})",
                args.profile_id,
                pid
            ));
        }

        // Truncate the per-profile log so a fresh connect
        // attempt's diagnostics aren't mixed with prior runs.
        let _ = std::fs::write(&log_path, b"");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("open log {log_path:?}"))?;
        let log_for_stderr = log_file
            .try_clone()
            .with_context(|| "dup log fd for stderr")?;

        // Build the argv. Password comes via stdin to keep it
        // off the process listing.
        let host_arg = format!("{}:{}", args.host, args.port);
        let mut cmd = Command::new(&bin);
        cmd.arg(host_arg)
            .arg("-u")
            .arg(&args.username)
            // `--pppd-no-peerdns` is implied by our split
            // routing config; openfortivpn's default is to
            // hand DNS off to the kernel resolver, which we
            // don't want when split-tunneling.
            .arg("--pppd-log").arg(log_path.to_string_lossy().as_ref())
            // PID file location for our later disconnect/status
            // probes. openfortivpn supports `--pid-file` since
            // 1.20.
            .arg("--pid-file").arg(pid_path.to_string_lossy().as_ref())
            .stdin(Stdio::piped())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_for_stderr));

        if let Some(fp) = args.trusted_cert.as_deref() {
            if !fp.is_empty() {
                cmd.arg("--trusted-cert").arg(fp);
            }
        }
        if args.no_default_route {
            cmd.arg("--no-routes");
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn {}", bin.display()))?;

        // Pipe password into stdin so the kernel doesn't keep
        // it in the process arg vector.
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(args.password.as_bytes())
                .await
                .context("write password to openfortivpn stdin")?;
            stdin
                .write_all(b"\n")
                .await
                .context("terminate password line")?;
            stdin.shutdown().await.ok();
        }

        let pid = child
            .id()
            .ok_or_else(|| anyhow!("openfortivpn child has no PID"))?;

        // openfortivpn writes its own PID file via --pid-file,
        // but only after the SSL handshake completes. Drop our
        // own immediately so disconnect can find the child
        // even if it dies mid-handshake.
        let _ = std::fs::write(&pid_path, pid.to_string().as_bytes());

        // Detach — the helper doesn't reap this; openfortivpn
        // lives until disconnect tells it to stop.
        tokio::spawn(async move {
            // Surface child exit in the helper log; the GUI
            // already polls status.
            let _ = child.wait().await;
        });

        Ok(FortiConnectResult {
            pid,
            log_path: log_path.to_string_lossy().into_owned(),
        })
    }

    /// Stop the openfortivpn process for a profile. SIGTERM
    /// first; if it doesn't exit within 3s, SIGKILL.
    pub async fn disconnect(&mut self, args: FortiDisconnectArgs) -> anyhow::Result<()> {
        let pid_path = Self::pid_path(&args.profile_id);
        let pid = match std::fs::read_to_string(&pid_path) {
            Ok(s) => s.trim().parse::<u32>().ok(),
            Err(_) => None,
        };
        let pid = match pid {
            Some(p) => p,
            None => {
                let _ = std::fs::remove_file(&pid_path);
                return Ok(());
            }
        };
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if unsafe { libc::kill(pid as i32, 0) } != 0 {
                let _ = std::fs::remove_file(&pid_path);
                return Ok(());
            }
        }
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = std::fs::remove_file(&pid_path);
        Ok(())
    }

    pub async fn status(&self, args: FortiStatusArgs) -> anyhow::Result<FortiStatusResult> {
        let pid_path = Self::pid_path(&args.profile_id);
        let log_path = Self::log_path(&args.profile_id);
        let pid = read_pid_if_alive(&pid_path);
        let state = match pid {
            Some(_) => {
                // Look at the tail of the log to distinguish
                // "process alive, tunnel up" from "process
                // alive, still negotiating".
                let tail = tail_lines(&log_path, 16);
                let connected = tail.iter().any(|l| {
                    l.contains("Tunnel is up and running")
                        || l.contains("Got addresses:")
                });
                if connected { "connected" } else { "connecting" }
            }
            None => "disconnected",
        };
        let recent_log = tail_lines(&log_path, 64);
        Ok(FortiStatusResult {
            state: state.to_owned(),
            pid,
            recent_log,
        })
    }
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn read_pid_if_alive(pid_path: &Path) -> Option<u32> {
    let raw = std::fs::read_to_string(pid_path).ok()?;
    let pid: u32 = raw.trim().parse().ok()?;
    // `kill(pid, 0)` returns 0 if the process exists + we have
    // permission to signal it; -1 otherwise.
    if unsafe { libc::kill(pid as i32, 0) } == 0 {
        Some(pid)
    } else {
        None
    }
}

fn tail_lines(path: &Path, n: usize) -> Vec<String> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    // `str::Lines` isn't ExactSizeIterator + DoubleEndedIterator,
    // so we materialise into a Vec first, then take the last
    // `n` entries.
    let all: Vec<&str> = s.lines().collect();
    let start = all.len().saturating_sub(n);
    all[start..].iter().map(|s| (*s).to_owned()).collect()
}

// ---------------------------------------------------------------------------
// Diagnose openfortivpn log lines into one-line operator hints.
// Mirrors `strongswan::diagnose_strongswan_failure` so the GUI
// can show clean errors instead of raw daemon output.
// ---------------------------------------------------------------------------

/// Look at a recent log slice and return a one-line diagnosis
/// when a clear failure pattern is present. Returns None when
/// the log doesn't show a clear failure (tunnel might still be
/// negotiating, or has come up cleanly).
pub fn diagnose_fortivpn_failure(log_tail: &[String]) -> Option<String> {
    let joined = log_tail.join("\n").to_ascii_lowercase();

    if joined.contains("authentication failed") || joined.contains("invalid credentials") {
        return Some(
            "FortiGate rejected the username or password. \
             Verify them in FortiClient first; if those work, \
             your account may need its SSL-VPN portal access \
             enabled on the gateway side."
                .to_owned(),
        );
    }
    if joined.contains("could not authenticate") || joined.contains("login failed") {
        return Some("FortiGate login failed — bad credentials or account locked.".to_owned());
    }
    if joined.contains("certificate verify failed")
        || joined.contains("self-signed certificate")
    {
        return Some(
            "Server cert didn't verify against the system trust \
             store. If you've already accepted the cert in \
             FortiClient, copy its SHA-256 fingerprint into the \
             profile's 'Trusted cert' field."
                .to_owned(),
        );
    }
    if joined.contains("could not connect to") || joined.contains("connection refused") {
        return Some(
            "Couldn't reach the SSL-VPN listener. Check the host \
             + port (default is 443; admins sometimes move it). \
             Make sure TCP is open to the gateway."
                .to_owned(),
        );
    }
    if joined.contains("two-factor") || joined.contains("token") {
        return Some(
            "Server demands a second factor (TOTP / push). \
             openfortivpn supports this with `--otp <code>`; \
             we'll surface the prompt in a follow-up — for now, \
             ask your FortiGate admin to disable MFA for this \
             account or use FortiClient."
                .to_owned(),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnose_auth_failure() {
        let log = vec!["INFO:  Authentication failed.".to_owned()];
        let d = diagnose_fortivpn_failure(&log).unwrap();
        assert!(d.contains("rejected"));
    }

    #[test]
    fn diagnose_cert_failure() {
        let log = vec!["ERROR: certificate verify failed".to_owned()];
        let d = diagnose_fortivpn_failure(&log).unwrap();
        assert!(d.contains("Trusted cert"));
    }

    #[test]
    fn diagnose_unknown_returns_none() {
        let log = vec!["INFO: Connected as 10.0.60.100".to_owned()];
        assert!(diagnose_fortivpn_failure(&log).is_none());
    }
}
