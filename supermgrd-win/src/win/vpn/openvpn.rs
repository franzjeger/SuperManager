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
//!    needs auth-user-pass). It is given to OpenVPN over the management
//!    interface when OpenVPN asks for it, never written to disk.
//! 2. Pick a free localhost port and spawn `openvpn.exe --config <path>
//!    --management 127.0.0.1 <port> <password file>
//!    --management-query-passwords --management-hold`. The one-off
//!    management password is in a file only SYSTEM and Administrators can
//!    read, removed once OpenVPN has used it.
//! 3. Connect to the management port and log in: wait for OpenVPN's
//!    `ENTER PASSWORD:`, answer with the password, wait for it to be
//!    accepted. Switch on state events, release the hold when OpenVPN
//!    announces it (`>HOLD:`), then read `>STATE:` messages until we see
//!    `CONNECTED,SUCCESS` (tunnel up) or `>FATAL` / process exit (tunnel
//!    failed).
//! 4. Spawn a background watcher that keeps reading the management
//!    stream so OpenVPN never blocks writing further state messages.
//! 5. On disconnect: send `signal SIGTERM` over the management socket
//!    and wait for the process to exit; fall back to `Child::kill` if
//!    it doesn't terminate within 5 s.
//!
//! The client's stdout and stderr are read for its whole life by
//! [`super::output`] — unread, they fill and stall it — and what it last
//! complained about becomes the error when a connect fails. The child is
//! `kill_on_drop`, so a connect cancelled mid-handshake takes the process
//! with it instead of leaving an orphan holding the adapter.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

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

use super::{output, VpnBackend, VpnError};

/// Soft cap on bring-up time. OpenVPN handshakes complete in under a
/// second for healthy gateways and trip TLS retries past 30 s.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);

/// How long OpenVPN has to greet the management client and accept its
/// password. It is already listening by then, so this is only ever reached
/// when something is wrong.
const MGMT_LOGIN_TIMEOUT: Duration = Duration::from_secs(5);

/// How many management-interface lines to keep for the log when a connect
/// fails.
const HEARD_LINES: usize = 40;

/// Active OpenVPN tunnel state. Holds onto the child process and the
/// management-socket reader so disconnect can issue a graceful SIGTERM
/// over the management protocol before killing the process.
struct OvpnActive {
    profile_id: uuid::Uuid,
    child: Child,
    /// Writer half of the management TCP connection. Disconnect uses
    /// it to send `signal SIGTERM`.
    mgmt_writer: tokio::net::tcp::OwnedWriteHalf,
    /// What the client has been printing, for when it stops by itself.
    tail: output::Tail,
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

    /// Why the tunnel's client exited, if it has. `None` while it runs, and
    /// when there is no tunnel.
    pub async fn exited(&self) -> Option<String> {
        let mut guard = self.active.lock().await;
        let active = guard.as_mut()?;
        match active.child.try_wait() {
            Ok(Some(status)) => Some(output::exit_reason("OpenVPN", status, &active.tail)),
            _ => None,
        }
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

/// Whether `openvpn.exe` can be found, and what to tell the operator when
/// it cannot.
pub fn availability() -> Result<(), String> {
    locate_openvpn().map(|_| ()).map_err(|e| match e {
        VpnError::MissingDependency(message) => message,
        other => other.to_string(),
    })
}

/// Find a free TCP port on localhost.
async fn pick_free_port() -> Result<u16, VpnError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(VpnError::Io)?;
    let port = listener.local_addr().map_err(VpnError::Io)?.port();
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

        let ProfileConfig::OpenVpn(cfg) = &profile.config else {
            return Err(VpnError::MissingDependency(
                "profile is not an OpenVPN profile".into(),
            ));
        };

        let openvpn_exe = locate_openvpn()?;
        let mgmt_port = pick_free_port().await?;

        // The management interface's password, random per connect, in a
        // file only SYSTEM and Administrators can read, for as long as it
        // takes OpenVPN to read it. `--management … stdin` is meant for a
        // person at a console: OpenVPN on Linux refuses a pipe outright,
        // and on Windows a client was seen starting with no management
        // password at all, taking the password line for a command.
        let mgmt_password = uuid::Uuid::new_v4().to_string();
        let runtime = crate::win::paths::create_private_runtime_dir("openvpn", &profile.id)
            .map_err(VpnError::Io)?;
        let mgmt_password_file = runtime.path().join("management.pw");
        std::fs::write(&mgmt_password_file, format!("{mgmt_password}\n")).map_err(VpnError::Io)?;

        // Credentials are supplied over the management interface's password
        // query (answered in `wait_for_connected`), never written to disk.
        // The previous implementation wrote them to
        // `C:\ProgramData\SuperManager\runtime\openvpn-<id>.auth`, and
        // ProgramData leaves that file readable by every authenticated local
        // user for as long as the tunnel is up.
        let auth_creds: Option<(String, String)> =
            if let (Some(username), Some(password_ref)) = (&cfg.username, &cfg.password) {
                let store = self.secret_store.as_ref().ok_or_else(|| {
                    VpnError::MissingDependency(
                        "OpenVPN profile uses auth-user-pass but the backend has no secret store"
                            .into(),
                    )
                })?;
                let password = store.retrieve(password_ref.label()).await.map_err(|e| {
                    VpnError::MissingDependency(format!(
                        "OpenVPN password lookup ({}): {e}",
                        password_ref.label()
                    ))
                })?;
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
            .arg(&mgmt_password_file)
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
            // The log lines are only ever read here, so the date on each is
            // noise in front of the error message an operator is shown.
            .arg("--suppress-timestamps")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            VpnError::MissingDependency(format!("could not start {}: {e}", openvpn_exe.display()))
        })?;
        info!(
            ?openvpn_exe,
            config = %cfg.config_file,
            mgmt_port,
            "spawned openvpn.exe"
        );
        // The management interface reports progress; the log is for the
        // explanation when there is no progress to report.
        let (tail, _) = output::capture(&mut child);

        let mgmt_addr: SocketAddr = format!("127.0.0.1:{mgmt_port}").parse().unwrap();
        let stream = match timeout(Duration::from_secs(5), connect_mgmt(mgmt_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let _ = child.kill().await;
                // Almost always the client refusing the config and exiting
                // before it opened the socket. Its own words say why.
                return Err(explain(
                    VpnError::Subprocess {
                        code: -1,
                        stderr: format!("connect to management socket: {e}"),
                    },
                    &tail,
                ));
            }
            Err(_) => {
                let _ = child.kill().await;
                return Err(explain(
                    VpnError::Subprocess {
                        code: -1,
                        stderr: "openvpn did not open management socket within 5 s".into(),
                    },
                    &tail,
                ));
            }
        };

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut heard = Heard::default();

        // Log in before anything else is said: until the password is
        // accepted, OpenVPN takes every line it is sent as a password
        // attempt, and after three wrong ones it refuses the client.
        let login = timeout(
            MGMT_LOGIN_TIMEOUT,
            mgmt_login(&mut reader, &mut writer, &mgmt_password, &mut heard),
        )
        .await
        .unwrap_or_else(|_| {
            Err(VpnError::Subprocess {
                code: -1,
                stderr: format!(
                    "OpenVPN did not accept the management login within {} s",
                    MGMT_LOGIN_TIMEOUT.as_secs()
                ),
            })
        });
        if let Err(e) = login {
            let _ = child.kill().await;
            heard.log();
            return Err(explain(e, &tail));
        }
        // OpenVPN read the password file before it started listening.
        drop(runtime);

        // State events, then the hold: `wait_for_connected` releases it
        // when OpenVPN announces it.
        write_mgmt(&mut writer, "state on\n").await?;

        let mut last_state = String::new();
        let success = timeout(
            HANDSHAKE_TIMEOUT,
            wait_for_connected(
                &mut reader,
                &mut writer,
                auth_creds.as_ref(),
                &mut last_state,
                &mut heard,
            ),
        )
        .await;
        match success {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = child.kill().await;
                heard.log();
                return Err(explain(e, &tail));
            }
            Err(_) => {
                let _ = child.kill().await;
                heard.log();
                tail.log_failure("OpenVPN");
                let said = tail
                    .reason()
                    .map(|r| format!(" The client's last complaint: {r}"))
                    .unwrap_or_default();
                return Err(VpnError::Subprocess {
                    code: -1,
                    stderr: format!(
                        "OpenVPN did not connect within {} s — it was {}.{said}",
                        HANDSHAKE_TIMEOUT.as_secs(),
                        step(&last_state),
                    ),
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
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        });

        *self.active.lock().await = Some(OvpnActive {
            profile_id: profile.id,
            child,
            mgmt_writer: writer,
            tail,
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
        let profile: Profile = serde_json::from_str(profile_json)
            .map_err(|e| VpnError::MissingDependency(format!("parse OpenVPN profile JSON: {e}")))?;
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
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "management socket did not open",
        )
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

/// Log in to the management interface.
///
/// OpenVPN greets the client with `ENTER PASSWORD:` — no line end — and
/// compares the whole next line with the password: the bare password, not
/// a `password "…"` command, which is how credential queries are answered.
/// Nothing else is sent until OpenVPN says the password is correct.
async fn mgmt_login<R>(
    reader: &mut R,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    password: &str,
    heard: &mut Heard,
) -> Result<(), VpnError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let closed = || VpnError::Subprocess {
        code: -1,
        stderr: "OpenVPN closed the management connection during the login".into(),
    };
    // The greeting, read up to its colon since no line end follows it.
    let mut chunk = Vec::new();
    loop {
        chunk.clear();
        if reader
            .read_until(b':', &mut chunk)
            .await
            .map_err(VpnError::Io)?
            == 0
        {
            return Err(closed());
        }
        let text = String::from_utf8_lossy(&chunk);
        heard.push(text.trim());
        if text.trim_end().ends_with("ENTER PASSWORD:") {
            break;
        }
    }
    write_mgmt(writer, &format!("{password}\n")).await?;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await.map_err(VpnError::Io)? == 0 {
            return Err(closed());
        }
        let text = line.trim();
        heard.push(text);
        if text.starts_with("SUCCESS: password is correct") {
            return Ok(());
        }
        if text.starts_with("ERROR: bad password") {
            return Err(VpnError::Subprocess {
                code: -1,
                stderr: "OpenVPN refused the management password it was started with".into(),
            });
        }
    }
}

/// The last lines the management interface sent, for the log when a
/// connect fails: state changes, holds, the replies to our commands.
#[derive(Default)]
struct Heard(std::collections::VecDeque<String>);

impl Heard {
    fn push(&mut self, line: &str) {
        if line.is_empty() {
            return;
        }
        if self.0.len() == HEARD_LINES {
            self.0.pop_front();
        }
        self.0.push_back(line.to_owned());
    }

    fn log(&self) {
        if !self.0.is_empty() {
            let lines: Vec<&str> = self.0.iter().map(String::as_str).collect();
            warn!(
                "OpenVPN management interface, before the failure:\n{}",
                lines.join("\n")
            );
        }
    }
}

async fn write_mgmt(w: &mut tokio::net::tcp::OwnedWriteHalf, line: &str) -> Result<(), VpnError> {
    w.write_all(line.as_bytes()).await.map_err(VpnError::Io)
}

/// Read `>STATE:` and `>FATAL:` events until we see `CONNECTED,SUCCESS`
/// (success) or a fatal/auth-failure event (which we map to the typed
/// error variants).
async fn wait_for_connected(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    auth_creds: Option<&(String, String)>,
    last_state: &mut String,
    heard: &mut Heard,
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
        heard.push(trimmed);
        if trimmed.starts_with(">HOLD:") {
            // OpenVPN waits here at start and, while the hold flag
            // `--management-hold` set is on, after every restart. A release
            // sent before this announcement is not remembered, so this is
            // when to send it. `hold off` first: a reconnect later — a
            // ping-restart, a network change — must not wait for a release
            // nobody is there to send.
            write_mgmt(writer, "hold off\nhold release\n").await?;
        } else if let Some(rest) = trimmed.strip_prefix(">STATE:") {
            // Format: timestamp,state,detail,...
            let parts: Vec<&str> = rest.splitn(4, ',').collect();
            let state = parts.get(1).copied().unwrap_or("");
            let detail = parts.get(2).copied().unwrap_or("");
            state.clone_into(last_state);
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
                    write_mgmt(
                        writer,
                        &format!("username \"Auth\" \"{}\"\n", mgmt_escape(user)),
                    )
                    .await?;
                    write_mgmt(
                        writer,
                        &format!("password \"Auth\" \"{}\"\n", mgmt_escape(pass)),
                    )
                    .await?;
                }
                None => {
                    return Err(VpnError::MissingDependency(
                        "This server asks for a username and password, and the profile \
                         has none. Import the config again with the credentials."
                            .into(),
                    ));
                }
            }
        } else if trimmed.starts_with(">PASSWORD:Need 'Private Key'") {
            return Err(VpnError::MissingDependency(
                "The private key in this config is protected by a passphrase, which \
                 SuperManager cannot supply. Export the config without one."
                    .into(),
            ));
        } else if trimmed.starts_with(">PASSWORD:Verification Failed") {
            return Err(VpnError::PermissionDenied(
                "The server rejected the username or password",
            ));
        }
    }
}

/// Replace a bare transport error with what the client itself said, when
/// it said something. An authentication rejection is already the reason
/// and stays as it is.
fn explain(e: VpnError, tail: &output::Tail) -> VpnError {
    tail.log_failure("OpenVPN");
    match e {
        VpnError::PermissionDenied(_) | VpnError::MissingDependency(_) => e,
        other => match tail.reason() {
            Some(reason) => VpnError::Subprocess {
                code: -1,
                stderr: reason,
            },
            None => other,
        },
    }
}

/// The step a `>STATE:` name stands for, as the end of "it was …".
fn step(state: &str) -> String {
    match state {
        "" => "still starting up".into(),
        "RESOLVE" => "looking up the server's address".into(),
        "TCP_CONNECT" => "opening a TCP connection to the server".into(),
        "CONNECTING" => "connecting to the server".into(),
        "WAIT" => "waiting for the server to answer".into(),
        "AUTH" => "authenticating".into(),
        "GET_CONFIG" => "waiting for the server's settings".into(),
        "ASSIGN_IP" => "assigning the tunnel address".into(),
        "ADD_ROUTES" => "adding routes".into(),
        "RECONNECTING" => "retrying after a failed attempt".into(),
        other => format!("in state {other}"),
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
    use super::{mgmt_escape, mgmt_login, step, wait_for_connected, write_mgmt, Heard, VpnError};
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
        net::{TcpListener, TcpStream},
    };

    /// Connect to a stand-in for OpenVPN's end of the management interface.
    async fn talk_to(
        listener: &TcpListener,
    ) -> (
        BufReader<tokio::net::tcp::OwnedReadHalf>,
        tokio::net::tcp::OwnedWriteHalf,
    ) {
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (reader, writer) = stream.into_split();
        (BufReader::new(reader), writer)
    }

    #[tokio::test]
    async fn the_management_conversation_follows_openvpns_order() {
        // What OpenVPN 2.6 does, as seen from a real client: a greeting with
        // no line end, then every line is a password attempt until one is
        // right; the hold is announced after the login, and a release sent
        // before the announcement is lost.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut reader, mut writer) = talk_to(&listener).await;
        let openvpn = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (from_client, mut to_client) = socket.into_split();
            let mut from_client = BufReader::new(from_client);
            let mut line = String::new();
            to_client.write_all(b"ENTER PASSWORD:").await.unwrap();
            from_client.read_line(&mut line).await.unwrap();
            assert_eq!(line, "secret\n", "the first line is the bare password");
            to_client
                .write_all(
                    b"SUCCESS: password is correct\r\n\
                      >INFO:OpenVPN Management Interface Version 5\r\n\
                      >HOLD:Waiting for hold release:0\r\n",
                )
                .await
                .unwrap();
            let mut said = Vec::new();
            for _ in 0..3 {
                line.clear();
                from_client.read_line(&mut line).await.unwrap();
                said.push(line.trim_end().to_owned());
            }
            assert_eq!(said, ["state on", "hold off", "hold release"]);
            to_client
                .write_all(b">STATE:1,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1,1194,,\r\n")
                .await
                .unwrap();
        });

        let mut heard = Heard::default();
        mgmt_login(&mut reader, &mut writer, "secret", &mut heard)
            .await
            .unwrap();
        write_mgmt(&mut writer, "state on\n").await.unwrap();
        let mut last_state = String::new();
        wait_for_connected(&mut reader, &mut writer, None, &mut last_state, &mut heard)
            .await
            .unwrap();
        assert_eq!(last_state, "CONNECTED");
        openvpn.await.unwrap();
    }

    #[tokio::test]
    async fn a_refused_management_password_is_an_error_not_a_wait() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut reader, mut writer) = talk_to(&listener).await;
        let openvpn = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (from_client, mut to_client) = socket.into_split();
            let mut line = String::new();
            to_client.write_all(b"ENTER PASSWORD:").await.unwrap();
            BufReader::new(from_client)
                .read_line(&mut line)
                .await
                .unwrap();
            to_client
                .write_all(b"ERROR: bad password\r\n")
                .await
                .unwrap();
        });

        let err = mgmt_login(&mut reader, &mut writer, "secret", &mut Heard::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, VpnError::Subprocess { stderr, .. } if stderr.contains("refused the management password")),
            "{err:?}"
        );
        openvpn.await.unwrap();
    }

    #[test]
    fn a_stalled_handshake_names_the_step_it_stalled_on() {
        // "exceeded 45s" told an operator nothing. Where it stopped does:
        // WAIT is a server that never answered, AUTH one that did.
        assert_eq!(step("WAIT"), "waiting for the server to answer");
        assert_eq!(step("AUTH"), "authenticating");
        assert_eq!(step(""), "still starting up");
        assert_eq!(step("SOMETHING_NEW"), "in state SOMETHING_NEW");
    }

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
        assert_eq!(mgmt_escape(r"a\b"), r"a\\b");
        assert_eq!(mgmt_escape(r#"\""#), r#"\\\""#);
    }
}
