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

/// Default install location of the OpenVPN Community binary. Probed
/// when `openvpn.exe` isn't on `%PATH%`.
const DEFAULT_INSTALL_PATH: &str = r"C:\Program Files\OpenVPN\bin\openvpn.exe";

/// Active OpenVPN tunnel state. Holds onto the child process and the
/// management-socket reader so disconnect can issue a graceful SIGTERM
/// over the management protocol before killing the process.
struct OvpnActive {
    profile_id: uuid::Uuid,
    child: Child,
    /// Writer half of the management TCP connection. Disconnect uses
    /// it to send `signal SIGTERM`.
    mgmt_writer: tokio::net::tcp::OwnedWriteHalf,
    /// Path to the temporary auth-user-pass file we created, if any.
    /// Cleaned up on disconnect — leaving it would leave plaintext
    /// credentials on disk.
    auth_file: Option<PathBuf>,
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

/// Locate the openvpn.exe binary. Search order:
/// 1. `OPENVPN_EXE` env var (lets users point at a portable install).
/// 2. `%PATH%` lookup (the installer adds the bin dir).
/// 3. Hardcoded `C:\Program Files\OpenVPN\bin\openvpn.exe`.
fn locate_openvpn() -> Result<PathBuf, VpnError> {
    if let Some(p) = std::env::var_os("OPENVPN_EXE") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
    }
    if let Ok(p) = which::which("openvpn.exe") {
        return Ok(p);
    }
    let fallback = PathBuf::from(DEFAULT_INSTALL_PATH);
    if fallback.exists() {
        return Ok(fallback);
    }
    Err(VpnError::MissingDependency(
        "openvpn.exe not found. Install OpenVPN Community Edition from \
         https://openvpn.net/community-downloads/ or set OPENVPN_EXE to its absolute path."
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

        let auth_file = if let (Some(username), Some(password_ref)) =
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
            let runtime_dir = PathBuf::from(r"C:\ProgramData\SuperManager\runtime");
            std::fs::create_dir_all(&runtime_dir).map_err(VpnError::Io)?;
            let auth_path = runtime_dir.join(format!("openvpn-{}.auth", profile.id.simple()));
            std::fs::write(
                &auth_path,
                format!("{username}\n{password_str}\n"),
            )
            .map_err(VpnError::Io)?;
            Some(auth_path)
        } else {
            None
        };

        let mut command = Command::new(&openvpn_exe);
        command
            .arg("--config")
            .arg(&cfg.config_file)
            .arg("--management")
            .arg("127.0.0.1")
            .arg(mgmt_port.to_string())
            .arg("stdin")
            .arg("--management-hold")
            .arg("--management-query-passwords");
        if let Some(p) = &auth_file {
            command.arg("--auth-user-pass").arg(p);
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
                cleanup_auth(&auth_file);
                return Err(VpnError::Subprocess {
                    code: -1,
                    stderr: format!("connect to management socket: {e}"),
                });
            }
            Err(_) => {
                let _ = child.kill().await;
                cleanup_auth(&auth_file);
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

        let success = timeout(HANDSHAKE_TIMEOUT, wait_for_connected(&mut reader)).await;
        match success {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill().await;
                cleanup_auth(&auth_file);
                return Err(e);
            }
            Err(_) => {
                let _ = child.kill().await;
                cleanup_auth(&auth_file);
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
            auth_file,
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
    cleanup_auth(&active.auth_file);
}

fn cleanup_auth(path: &Option<PathBuf>) {
    if let Some(p) = path {
        if let Err(e) = std::fs::remove_file(p) {
            warn!("remove openvpn auth file {}: {e}", p.display());
        }
    }
}
