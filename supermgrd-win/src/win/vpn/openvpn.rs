//! OpenVPN backend (Windows).
//!
//! Drives the OpenVPN Community Edition binary (`openvpn.exe`) as a
//! subprocess and monitors the tunnel via OpenVPN's
//! [management interface](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt) —
//! a plain-text TCP socket on `127.0.0.1` that emits state changes the
//! moment they happen, so we don't have to race the log file.
//!
//! # Flow
//!
//! 1. Resolve the password from Credential Manager (if the profile
//!    needs auth-user-pass) and write a temporary credentials file with
//!    restrictive permissions.
//! 2. Pick a free localhost port and spawn `openvpn.exe --config <path>
//!    --management 127.0.0.1 <port> stdin --management-query-passwords
//!    --management-hold`.
//! 3. Connect to the management port, send `hold off` to release the
//!    hold, then read `>STATE:` messages until we see `CONNECTED,SUCCESS`
//!    (tunnel up) or `>FATAL` / process exit (tunnel failed).
//! 4. Spawn a background watcher that keeps reading the management
//!    stream so OpenVPN never blocks writing further state messages.
//! 5. On disconnect: send `signal SIGTERM` over the management socket
//!    and wait for the process to exit; fall back to `Child::kill` if
//!    it doesn't terminate within 5 s.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    sync::Mutex,
    time::timeout,
};
use tracing::{info, warn};

use supermgr_core::keyring::SecretStore;
use supermgr_core::vpn::profile::{Profile, ProfileConfig};

use super::{VpnBackend, VpnError};

/// Soft cap on bring-up time. OpenVPN handshakes complete in under a
/// second for healthy gateways and trip TLS retries past 30 s.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);

/// Active OpenVPN tunnel state. Holds onto the child process and the
/// management-socket reader so disconnect can issue a graceful SIGTERM
/// over the management protocol before killing the process.
struct OvpnActive {
    profile_id: uuid::Uuid,
    child: Child,
    /// Writer half of the management TCP connection. Disconnect uses
    /// it to send `signal SIGTERM`.
    mgmt_writer: tokio::net::tcp::OwnedWriteHalf,
}

/// Windows OpenVPN backend.
pub struct OpenVpnBackend {
    secret_store: Option<Arc<dyn SecretStore>>,
    active: Mutex<Option<OvpnActive>>,
}

impl OpenVpnBackend {
    /// Construct a backend with a secret store. The store is optional so
    /// the existing `Default` path used in `DaemonState::load` still
    /// works for code paths that don't need auth-user-pass.
    pub fn with_store(secret_store: Arc<dyn SecretStore>) -> Self {
        Self {
            secret_store: Some(secret_store),
            active: Mutex::new(None),
        }
    }

    /// Whether a tunnel is currently up.
    pub async fn is_active(&self) -> bool {
        self.active.lock().await.is_some()
    }
}

impl Default for OpenVpnBackend {
    fn default() -> Self {
        Self {
            secret_store: None,
            active: Mutex::new(None),
        }
    }
}

/// Locate the `openvpn.exe` binary. Search order:
/// 1. SuperManager's own `bin\openvpn.exe` — bundled by the MSI alongside
///    the daemon. This is the expected location for normal installations.
/// 2. `OPENVPN_EXE` env var — lets advanced users override with a specific
///    binary (portable install, staging build, etc.).
/// 3. `%PATH%` lookup.
/// 4. Legacy `C:\Program Files\OpenVPN\bin\openvpn.exe` — fallback for
///    machines that happen to have a full OpenVPN Community install.
fn locate_openvpn() -> Result<PathBuf, VpnError> {
    // 1. Bundled in the same bin\ directory as the SuperManager daemon.
    let bundled = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("openvpn.exe")));
    if let Some(ref p) = bundled {
        if p.exists() {
            return Ok(p.clone());
        }
    }

    // 2. Env var override.
    if let Some(v) = std::env::var_os("OPENVPN_EXE") {
        let path = PathBuf::from(v);
        if path.exists() {
            return Ok(path);
        }
    }

    // 3. PATH.
    if let Ok(p) = which::which("openvpn.exe") {
        return Ok(p);
    }

    // 4. Legacy full-application install location.
    let legacy = PathBuf::from(r"C:\Program Files\OpenVPN\bin\openvpn.exe");
    if legacy.exists() {
        return Ok(legacy);
    }

    Err(VpnError::MissingDependency(
        "openvpn.exe not found. It should be bundled at \
         %ProgramFiles%\\SuperManager\\bin\\openvpn.exe. \
         Re-run the SuperManager installer to restore it."
            .into(),
    ))
}

/// Find a free TCP port on localhost.
async fn pick_free_port() -> Result<u16, VpnError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(VpnError::Io)?;
    let port = listener
        .local_addr()
        .map_err(VpnError::Io)?
        .port();
    // Drop the listener so OpenVPN can bind the port. There's a tiny
    // race window where another process could grab it; in practice
    // local management ports are quiet enough that this is acceptable.
    drop(listener);
    Ok(port)
}

impl OpenVpnBackend {
    /// Bring up a tunnel for `profile`. Tears down any prior tunnel first.
    async fn bring_up(&self, profile: &Profile) -> Result<(), VpnError> {
        if let Some(prev) = self.active.lock().await.take() {
            tear_down(prev).await;
        }

        let cfg = match &profile.config {
            ProfileConfig::OpenVpn(c) => c,
            _ => {
                return Err(VpnError::MissingDependency(
                    "profile is not an OpenVPN profile".into(),
                ));
            }
        };

        let openvpn_exe = locate_openvpn()?;
        let mgmt_port = pick_free_port().await?;

        // Credentials are supplied over the management interface's password
        // query (answered in `wait_for_connected`), never written to disk.
        // The previous implementation wrote them to
        // `C:\ProgramData\SuperManager\runtime\openvpn-<id>.auth`, and
        // ProgramData leaves that file readable by every authenticated local
        // user for as long as the tunnel is up.
        let auth_creds: Option<(String, String)> = if let (Some(username), Some(password_ref)) =
            (&cfg.username, &cfg.password)
        {
            let store = self.secret_store.as_ref().ok_or_else(|| {
                VpnError::MissingDependency(
                    "OpenVPN profile uses auth-user-pass but the backend has no secret store"
                        .into(),
                )
            })?;
            let password = store
                .retrieve(password_ref.label())
                .await
                .map_err(|e| VpnError::MissingDependency(format!(
                    "OpenVPN password lookup ({}): {e}", password_ref.label()
                )))?;
            let password_str = std::str::from_utf8(&password).map_err(|_| {
                VpnError::MissingDependency("stored OpenVPN password is not valid UTF-8".into())
            })?;
            Some((username.clone(), password_str.to_owned()))
        } else {
            None
        };

        let mut command = Command::new(&openvpn_exe);
        // Set the working directory to the directory containing openvpn.exe.
        // OpenVPN 2.6+ probes its CWD for wintun.dll, so this lets it pick
        // up the bundled wintun.dll without needing a separate --wintun flag.
        if let Some(bin_dir) = openvpn_exe.parent() {
            command.current_dir(bin_dir);
        }
        command
            .arg("--config")
            .arg(&cfg.config_file)
            .arg("--management")
            .arg("127.0.0.1")
            .arg(mgmt_port.to_string())
            .arg("stdin")
            .arg("--management-hold")
            .arg("--management-query-passwords");
        if auth_creds.is_some() {
            // No file argument: with --management-query-passwords this makes
            // OpenVPN request the credentials over the management interface,
            // which we answer in memory. A CLI --auth-user-pass overrides any
            // auth-user-pass directive in the config, preserving the previous
            // "we supply the credentials" behaviour without the file.
            command.arg("--auth-user-pass");
        }
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::piped());

        let mut child = command.spawn().map_err(VpnError::Io)?;
        info!(
            ?openvpn_exe,
            config = %cfg.config_file,
            mgmt_port,
            "spawned openvpn.exe"
        );

        // Send the management password on stdin. With `--management ...
        // stdin` openvpn reads the first line from stdin as the password.
        // Random token so the management protocol is authenticated even
        // though nobody outside localhost can reach it.
        let mgmt_password = uuid::Uuid::new_v4().to_string();
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(format!("{mgmt_password}\n").as_bytes())
                .await
                .map_err(VpnError::Io)?;
            drop(stdin);
        }

        let mgmt_addr: SocketAddr = format!("127.0.0.1:{mgmt_port}").parse().unwrap();
        let stream = match timeout(Duration::from_secs(5), connect_mgmt(mgmt_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let _ = child.kill().await;
                return Err(VpnError::Subprocess {
                    code: -1,
                    stderr: format!("connect to management socket: {e}"),
                });
            }
            Err(_) => {
                let _ = child.kill().await;
                return Err(VpnError::Subprocess {
                    code: -1,
                    stderr: "openvpn did not open management socket within 5 s".into(),
                });
            }
        };

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // Authenticate to the management interface, enable state events,
        // release the hold, then wait for `>STATE:.*,CONNECTED`.
        write_mgmt(&mut writer, &format!("password \"{mgmt_password}\"\n")).await?;
        write_mgmt(&mut writer, "state on\n").await?;
        write_mgmt(&mut writer, "hold release\n").await?;

        let success = timeout(HANDSHAKE_TIMEOUT, wait_for_connected(&mut reader, &mut writer, auth_creds.as_ref())).await;
        match success {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill().await;
                return Err(e);
            }
            Err(_) => {
                let _ = child.kill().await;
                return Err(VpnError::Subprocess {
                    code: -1,
                    stderr: format!("openvpn handshake exceeded {HANDSHAKE_TIMEOUT:?}"),
                });
            }
        }

        info!(profile_id = %profile.id, "openvpn tunnel up");

        // Drain the management stream in the background so OpenVPN
        // doesn't block writing further state messages once its socket
        // buffer fills.
        tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        });

        *self.active.lock().await = Some(OvpnActive {
            profile_id: profile.id,
            child,
            mgmt_writer: writer,
        });
        Ok(())
    }

    async fn bring_down(&self) -> Result<(), VpnError> {
        let active = self.active.lock().await.take();
        match active {
            Some(a) => {
                tear_down(a).await;
                Ok(())
            }
            None => Err(VpnError::NotImplemented("no active OpenVPN tunnel")),
        }
    }
}

#[async_trait]
impl VpnBackend for OpenVpnBackend {
    async fn connect(&self, profile_json: &str) -> Result<(), VpnError> {
        let profile: Profile = serde_json::from_str(profile_json).map_err(|e| {
            VpnError::MissingDependency(format!("parse OpenVPN profile JSON: {e}"))
        })?;
        self.bring_up(&profile).await
    }

    async fn disconnect(&self) -> Result<(), VpnError> {
        self.bring_down().await
    }

    async fn status(&self) -> Result<String, VpnError> {
        let guard = self.active.lock().await;
        if let Some(a) = guard.as_ref() {
            Ok(serde_json::json!({
                "state": "Connected",
                "backend": "openvpn",
                "profile_id": a.profile_id.to_string(),
            })
            .to_string())
        } else {
            Ok(r#"{"state":"Disconnected","backend":"openvpn"}"#.to_owned())
        }
    }
}

async fn connect_mgmt(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    // Brief retry loop — openvpn opens the management socket after a
    // few hundred milliseconds of startup, not instantly.
    let mut last_err = None;
    for _ in 0..20 {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "management socket did not open")
    }))
}

/// Escape a string for the OpenVPN management interface's quoted-string
/// form. Inside `"..."`, backslash and double-quote must be backslash-
/// escaped, backslashes first. A password containing `"` would otherwise
/// close the argument early and corrupt the credential — a hazard the
/// old file-based path never had, introduced by moving to the socket and
/// contained here.
fn mgmt_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

async fn write_mgmt(
    w: &mut tokio::net::tcp::OwnedWriteHalf,
    line: &str,
) -> Result<(), VpnError> {
    w.write_all(line.as_bytes()).await.map_err(VpnError::Io)
}

/// Read `>STATE:` and `>FATAL:` events until we see `CONNECTED,SUCCESS`
/// (success) or a fatal/auth-failure event (which we map to the typed
/// error variants).
async fn wait_for_connected(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    auth_creds: Option<&(String, String)>,
) -> Result<(), VpnError> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.map_err(VpnError::Io)?;
        if n == 0 {
            return Err(VpnError::Subprocess {
                code: -1,
                stderr: "management socket closed before CONNECTED event".into(),
            });
        }
        let trimmed = line.trim_end();
        if let Some(rest) = trimmed.strip_prefix(">STATE:") {
            // Format: timestamp,state,detail,...
            let parts: Vec<&str> = rest.splitn(4, ',').collect();
            let state = parts.get(1).copied().unwrap_or("");
            let detail = parts.get(2).copied().unwrap_or("");
            match state {
                "CONNECTED" if detail == "SUCCESS" => return Ok(()),
                "EXITING" => {
                    return Err(VpnError::Subprocess {
                        code: -1,
                        stderr: format!("openvpn exited during handshake: {detail}"),
                    });
                }
                _ => {} // RECONNECTING, WAIT, AUTH, GET_CONFIG, ASSIGN_IP …
            }
        } else if let Some(rest) = trimmed.strip_prefix(">FATAL:") {
            return Err(VpnError::Subprocess {
                code: -1,
                stderr: format!("openvpn fatal: {rest}"),
            });
        } else if trimmed.starts_with(">PASSWORD:Need 'Auth'") {
            // OpenVPN is requesting auth-user-pass credentials over the
            // management interface (we pass --auth-user-pass with no file).
            // Answer from memory. The quoted-string form needs backslash and
            // double-quote escaped, or a password containing `"` would
            // terminate the argument early.
            match auth_creds {
                Some((user, pass)) => {
                    write_mgmt(writer, &format!("username \"Auth\" \"{}\"\n", mgmt_escape(user))).await?;
                    write_mgmt(writer, &format!("password \"Auth\" \"{}\"\n", mgmt_escape(pass))).await?;
                }
                None => {
                    return Err(VpnError::Subprocess {
                        code: -1,
                        stderr: "server requires auth-user-pass but the profile has no stored credentials".into(),
                    });
                }
            }
        } else if trimmed.starts_with(">PASSWORD:Verification Failed") {
            return Err(VpnError::Subprocess {
                code: -1,
                stderr: "openvpn auth-user-pass verification failed".into(),
            });
        }
    }
}

async fn tear_down(mut active: OvpnActive) {
    info!(profile_id = %active.profile_id, "tearing down OpenVPN tunnel");
    let _ = active.mgmt_writer.write_all(b"signal SIGTERM\n").await;
    let _ = active.mgmt_writer.shutdown().await;
    match timeout(Duration::from_secs(5), active.child.wait()).await {
        Ok(Ok(status)) => info!(?status, "openvpn exited cleanly"),
        Ok(Err(e)) => warn!("waiting on openvpn child failed: {e}"),
        Err(_) => {
            warn!("openvpn did not exit within 5 s, killing");
            let _ = active.child.kill().await;
        }
    }
}


#[cfg(test)]
mod tests {
    use super::mgmt_escape;

    #[test]
    fn plain_credential_is_unchanged() {
        assert_eq!(mgmt_escape("hunter2"), "hunter2");
    }

    /// A password with a double-quote must not be able to terminate the
    /// management argument early — that would corrupt auth or, worse,
    /// let a crafted password inject a management command.
    #[test]
    fn double_quote_is_escaped() {
        assert_eq!(mgmt_escape(r#"pa"ss"#), r#"pa\"ss"#);
    }

    /// Backslashes are escaped first, so `\` followed by `"` does not
    /// collapse into an escaped quote by accident.
    #[test]
    fn backslash_is_escaped_before_quote() {
        assert_eq!(mgmt_escape(r#"a\b"#), r#"a\\b"#);
        assert_eq!(mgmt_escape(r#"\""#), r#"\\\""#);
    }
}
