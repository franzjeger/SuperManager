//! Async SSH client wrapper using `russh`.
//!
//! Provides password, public-key and OpenSSH-certificate authentication,
//! command execution, and SFTP session creation over a single TCP
//! connection.

use std::sync::Arc;

use russh::client::{self, Handle};
use russh_keys::key::PublicKey;
use russh_keys::PublicKeyBase64;
use supermgr_core::error::SshError;

use super::known_hosts::{HostKeyCheck, KnownHostsStore};
use supermgr_core::ssh::remote::{RemoteFiles, RemoteShell};

// ---------------------------------------------------------------------------
// Client handler
// ---------------------------------------------------------------------------

/// russh client handler that verifies the server's host key against a
/// persistent `known_hosts` store.
///
/// First-sight policy is **TOFU + record**: an unrecorded host has its
/// key fingerprint silently saved, then accepted. Every subsequent
/// connection to the same `host:port` requires the recorded fingerprint
/// to match — a mismatch is rejected loudly. This is the same posture
/// OpenSSH gives you with `StrictHostKeyChecking=accept-new`.
///
/// Without this layer, every man-in-the-middle is invisible. Storing
/// the fingerprint on first sight is the minimum bar for a tool the
/// user is about to push private keys through.
struct SshClientHandler {
    known_hosts: Arc<KnownHostsStore>,
    host: String,
    port: u16,
}

#[async_trait::async_trait]
impl client::Handler for SshClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // We hash the SSH wire-format public key. Different from OpenSSH's
        // base64-truncated SHA256 representation, but stable across
        // restarts and we only need to compare it to ourselves.
        let key_bytes = server_public_key.public_key_bytes();
        let fingerprint = KnownHostsStore::fingerprint(&key_bytes);

        match self
            .known_hosts
            .check_and_enroll(&self.host, self.port, &fingerprint)?
        {
            HostKeyCheck::Match => Ok(true),
            HostKeyCheck::NewHost => {
                tracing::info!(
                    host = %self.host,
                    port = self.port,
                    fingerprint = %fingerprint,
                    "TOFU: recording new SSH host key"
                );
                Ok(true)
            }
            HostKeyCheck::Mismatch { stored, current } => {
                tracing::error!(
                    host = %self.host,
                    port = self.port,
                    stored = %stored,
                    current = %current,
                    "host key MISMATCH — rejecting connection"
                );
                // Returning Ok(false) makes russh treat it as a host-key
                // verification failure and tear down the connection. We
                // ALSO surface the detail via Err so the SshError reaches
                // the GUI with both fingerprints.
                Err(anyhow::anyhow!(
                    "host key mismatch for {}:{} — stored={}, server-presented={}; \
                     refusing to connect. If you trust this host, run `forget` to \
                     drop the saved fingerprint and reconnect.",
                    self.host,
                    self.port,
                    stored,
                    current
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session wrapper
// ---------------------------------------------------------------------------

/// An established SSH session wrapping a russh client handle.
pub struct SshSession {
    handle: Handle<SshClientHandler>,
}

/// Settings every session uses. The keepalive is what bounds a session
/// whose peer has gone: without one, a server that died or dropped off the
/// network after the handshake left every later await (an exec, an SFTP
/// transfer, a shell prompt) pending for good. A peer that answers nothing
/// for `KEEPALIVE_MAX` + 1 intervals is dropped; any traffic, its replies to
/// the keepalives included, keeps a quiet but live session going, such as
/// one running a long, silent command.
fn client_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        ..client::Config::default()
    })
}

const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
const KEEPALIVE_MAX: usize = 3;

/// Budget for each command run through `RemoteShell`.
const REMOTE_SHELL_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// `future`, or a `ConnectionFailed` naming `step` if it takes longer than
/// `secs`. Authentication needs one as much as the connect: a server that
/// completed the handshake and then went quiet used to hold it forever.
async fn within<T>(
    secs: u64,
    addr: &str,
    step: &str,
    future: impl std::future::Future<Output = T>,
) -> Result<T, SshError> {
    tokio::time::timeout(std::time::Duration::from_secs(secs), future)
        .await
        .map_err(|_| SshError::ConnectionFailed {
            host: addr.to_owned(),
            reason: format!("{step} timed out after {secs}s"),
        })
}

impl SshSession {
    // -- constructors -------------------------------------------------------

    /// Connect to a remote host using password authentication.
    ///
    /// `known_hosts` is consulted via the russh handler — see
    /// `SshClientHandler::check_server_key`. A previously-seen host whose
    /// fingerprint has changed will fail the connection here with a
    /// `ConnectionFailed` carrying both the stored and current fingerprint.
    pub async fn connect_password(
        hostname: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout_secs: u64,
        known_hosts: Arc<KnownHostsStore>,
    ) -> Result<Self, SshError> {
        let addr = format!("{hostname}:{port}");
        let handler = SshClientHandler {
            known_hosts,
            host: hostname.to_owned(),
            port,
        };

        let mut handle = within(
            timeout_secs,
            &addr,
            "connection",
            client::connect(client_config(), &addr as &str, handler),
        )
        .await?
        .map_err(|e| SshError::ConnectionFailed {
            host: addr.clone(),
            reason: e.to_string(),
        })?;

        let auth_ok = within(
            timeout_secs,
            &addr,
            "authentication",
            handle.authenticate_password(username, password),
        )
        .await?
        .map_err(|e| SshError::AuthFailed(e.to_string()))?;

        if !auth_ok {
            return Err(SshError::AuthFailed(
                "password authentication rejected by server".into(),
            ));
        }

        Ok(Self { handle })
    }

    /// Connect to a remote host using private-key authentication.
    ///
    /// See `connect_password` for the host-key verification semantics —
    /// it's the same handler.
    pub async fn connect_key(
        hostname: &str,
        port: u16,
        username: &str,
        private_key_pem: &str,
        timeout_secs: u64,
        known_hosts: Arc<KnownHostsStore>,
    ) -> Result<Self, SshError> {
        Self::connect_key_with_cert(
            hostname,
            port,
            username,
            private_key_pem,
            None,
            timeout_secs,
            known_hosts,
        )
        .await
    }

    /// Connect to a remote host using OpenSSH certificate authentication.
    ///
    /// `cert_pem` must be the CA-signed certificate matching
    /// `private_key_pem` (the `*-cert.pub` OpenSSH produces). If the
    /// certificate is unparseable or the server rejects it, this falls
    /// back to plain public-key auth with the same key rather than
    /// failing outright — a host that trusts the bare key still
    /// connects, and the server keeps the final say.
    ///
    /// See `connect_password` for the host-key verification semantics —
    /// it's the same handler.
    pub async fn connect_certificate(
        hostname: &str,
        port: u16,
        username: &str,
        private_key_pem: &str,
        cert_pem: &str,
        timeout_secs: u64,
        known_hosts: Arc<KnownHostsStore>,
    ) -> Result<Self, SshError> {
        Self::connect_key_with_cert(
            hostname,
            port,
            username,
            private_key_pem,
            Some(cert_pem),
            timeout_secs,
            known_hosts,
        )
        .await
    }

    /// Shared implementation behind `connect_key` / `connect_certificate`.
    ///
    /// Ported from the Linux daemon's `ssh::connection` so both platforms
    /// authenticate identically — including the cert-then-pubkey fallback
    /// order, which matters because a CA-signed cert that has expired
    /// should not lock an operator out of a host that also trusts the
    /// underlying key.
    async fn connect_key_with_cert(
        hostname: &str,
        port: u16,
        username: &str,
        private_key_pem: &str,
        cert_pem: Option<&str>,
        timeout_secs: u64,
        known_hosts: Arc<KnownHostsStore>,
    ) -> Result<Self, SshError> {
        let key_pair = russh_keys::decode_secret_key(private_key_pem, None)
            .map_err(|e| SshError::AuthFailed(format!("failed to decode private key: {e}")))?;

        let addr = format!("{hostname}:{port}");
        let handler = SshClientHandler {
            known_hosts,
            host: hostname.to_owned(),
            port,
        };

        let mut handle = within(
            timeout_secs,
            &addr,
            "connection",
            client::connect(client_config(), &addr as &str, handler),
        )
        .await?
        .map_err(|e| SshError::ConnectionFailed {
            host: addr.clone(),
            reason: e.to_string(),
        })?;

        let key_pair = Arc::new(key_pair);

        // Certificate auth first when we have one. Every failure mode
        // here is non-fatal on purpose — see `connect_certificate`.
        if let Some(cert_data) = cert_pem {
            // Trim before parsing. `validate_openssh_certificate` accepts a
            // cert with surrounding whitespace (it validates `cert.trim()`),
            // but the value is stored untrimmed and `ssh_key::from_openssh`
            // only trims the END — leading whitespace makes it fail to parse
            // here, and the non-fatal fallback below then silently drops to
            // plain pubkey auth despite a cert that validated fine on save.
            match ssh_key::Certificate::from_openssh(cert_data.trim()) {
                Ok(cert) => match within(
                    timeout_secs,
                    &addr,
                    "certificate authentication",
                    handle.authenticate_openssh_cert(username, Arc::clone(&key_pair), cert),
                )
                .await?
                {
                    Ok(true) => return Ok(Self { handle }),
                    Ok(false) => {
                        tracing::warn!(
                            host = %hostname,
                            "server rejected SSH certificate, trying plain pubkey"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            host = %hostname,
                            error = %e,
                            "certificate auth errored, trying plain pubkey"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        host = %hostname,
                        error = %e,
                        "could not parse SSH certificate, trying plain pubkey"
                    );
                }
            }
        }

        let auth_ok = within(
            timeout_secs,
            &addr,
            "authentication",
            handle.authenticate_publickey(username, key_pair),
        )
        .await?
        .map_err(|e| SshError::AuthFailed(e.to_string()))?;

        if !auth_ok {
            return Err(SshError::AuthFailed(
                "public-key authentication rejected by server".into(),
            ));
        }

        Ok(Self { handle })
    }

    // -- command execution --------------------------------------------------

    /// Execute a command on the remote host and return
    /// `(exit_status, stdout, stderr)`.
    ///
    /// `budget` bounds the whole call, from opening the channel to the exit
    /// status. `None` waits for as long as the command runs; the keepalive
    /// still drops a peer that has gone.
    pub async fn exec(
        &self,
        command: &str,
        budget: Option<std::time::Duration>,
    ) -> Result<(u32, String, String), SshError> {
        let Some(budget) = budget else {
            return self.run_command(command).await;
        };
        tokio::time::timeout(budget, self.run_command(command))
            .await
            .map_err(|_| SshError::ConnectionFailed {
                host: String::new(),
                reason: format!("command did not finish within {}s", budget.as_secs()),
            })?
    }

    async fn run_command(&self, command: &str) -> Result<(u32, String, String), SshError> {
        let mut channel =
            self.handle
                .channel_open_session()
                .await
                .map_err(|e| SshError::ConnectionFailed {
                    host: String::new(),
                    reason: format!("failed to open session channel: {e}"),
                })?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: String::new(),
                reason: format!("exec failed: {e}"),
            })?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status: Option<u32> = None;

        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::ExtendedData { data, ext }) if ext == 1 => {
                    // ext == 1 is stderr
                    stderr.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::ExitStatus { exit_status: code }) => {
                    exit_status = Some(code);
                }
                Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) => {
                    // Keep draining until the channel is fully closed.
                }
                None => break,
                _ => {}
            }
        }

        let exit_status = match exit_status {
            Some(code) => code,
            // The session died under the command: whatever it did, it didn't
            // exit 1, and callers read exit codes as answers (`grep -q`).
            None if self.handle.is_closed() => {
                return Err(SshError::ConnectionFailed {
                    host: String::new(),
                    reason: "connection lost before the command finished".into(),
                });
            }
            // A live server that closed the channel without an exit status.
            None => 1,
        };
        let stdout_str = String::from_utf8_lossy(&stdout).into_owned();
        let stderr_str = String::from_utf8_lossy(&stderr).into_owned();

        Ok((exit_status, stdout_str, stderr_str))
    }

    /// Run an interactive shell session, sending lines sequentially.
    ///
    /// Waits for a prompt (`# ` or `$ ` or `password:`) before sending each
    /// line.  Used for commands that prompt for input (e.g. `FortiGate`
    /// `generate-key` which asks for the admin password).
    pub async fn shell_interact(
        &self,
        lines: &[&str],
        _delay_ms: u64,
        timeout_secs: u64,
    ) -> Result<String, SshError> {
        let mut channel =
            self.handle
                .channel_open_session()
                .await
                .map_err(|e| SshError::ConnectionFailed {
                    host: String::new(),
                    reason: format!("failed to open session channel: {e}"),
                })?;

        // Request a PTY so FortiGate treats it as interactive.
        channel
            .request_pty(false, "xterm", 80, 24, 0, 0, &[])
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: String::new(),
                reason: format!("request_pty failed: {e}"),
            })?;

        channel
            .request_shell(true)
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: String::new(),
                reason: format!("request_shell failed: {e}"),
            })?;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let mut output = Vec::new();

        // Macro-like helper: drain channel data until a keyword appears
        // or a shell prompt is detected.
        macro_rules! wait_for {
            ($keywords:expr) => {
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() { break; }
                    match tokio::time::timeout(remaining, channel.wait()).await {
                        Ok(Some(russh::ChannelMsg::Data { data })) => {
                            output.extend_from_slice(&data);
                            let text = String::from_utf8_lossy(&output);
                            let found = $keywords.iter().any(|kw: &&str| text.contains(kw));
                            let trimmed = text.trim_end();
                            if found || trimmed.ends_with('#') || trimmed.ends_with('$') {
                                break;
                            }
                        }
                        Ok(Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close)) => break,
                        Ok(None) => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            };
        }

        // Wait for initial shell prompt.
        wait_for!(&["#", "$"]);

        // Send each line and wait for the next prompt or password request.
        // Clear the output buffer before each send so we only match NEW output.
        for line in lines {
            let prev_len = output.len();
            let data = format!("{line}\n");
            let _ = channel.data(data.as_bytes()).await;

            // Wait until new data arrives that contains a prompt or keyword.
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, channel.wait()).await {
                    Ok(Some(russh::ChannelMsg::Data { data })) => {
                        output.extend_from_slice(&data);
                        // Only check NEW data (after prev_len).
                        let new_text = String::from_utf8_lossy(&output[prev_len..]);
                        let keywords = [
                            "# ",
                            "$ ",
                            "password:",
                            "Password:",
                            "New API key:",
                            "API key:",
                        ];
                        let found = keywords.iter().any(|kw| new_text.contains(kw));
                        let trimmed = new_text.trim_end();
                        if found || trimmed.ends_with('#') || trimmed.ends_with('$') {
                            break;
                        }
                    }
                    Ok(Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close)) => break,
                    Ok(None) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }

        let _ = channel.close().await;
        Ok(String::from_utf8_lossy(&output).into_owned())
    }

    // -- SFTP ---------------------------------------------------------------

    /// Open an SFTP session over this SSH connection.
    ///
    /// The caller is responsible for dropping the `SftpSession` when done.
    pub async fn sftp(&self) -> Result<russh_sftp::client::SftpSession, SshError> {
        let channel =
            self.handle
                .channel_open_session()
                .await
                .map_err(|e| SshError::ConnectionFailed {
                    host: String::new(),
                    reason: format!("failed to open session channel for SFTP: {e}"),
                })?;

        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: String::new(),
                reason: format!("SFTP subsystem request failed: {e}"),
            })?;

        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: String::new(),
                reason: format!("SFTP session init failed: {e}"),
            })?;

        Ok(sftp)
    }

    // -- lifecycle ----------------------------------------------------------

    /// Gracefully disconnect from the remote host.
    pub async fn disconnect(&self) -> Result<(), SshError> {
        self.handle
            .disconnect(russh::Disconnect::ByApplication, "done", "")
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: String::new(),
                reason: format!("disconnect failed: {e}"),
            })
    }
}

// ---------------------------------------------------------------------------
// supermgr-core transport adapter
// ---------------------------------------------------------------------------
//
// `supermgr_core::ssh::authorized_keys` drives key push/revoke against the
// `RemoteShell` trait rather than this type, so the same logic serves the
// macOS engine's session too. This is the whole of what it needs from us.

/// Wraps an established SFTP session as [`RemoteFiles`].
struct SftpFiles(russh_sftp::client::SftpSession);

#[async_trait::async_trait]
impl RemoteFiles for SftpFiles {
    async fn read(&self, path: &str) -> Result<Vec<u8>, SshError> {
        self.0
            .read(path)
            .await
            .map_err(|e| sftp_err("read", path, &e))
    }

    async fn write(&self, path: &str, contents: &[u8]) -> Result<(), SshError> {
        self.0
            .write(path, contents)
            .await
            .map_err(|e| sftp_err("write", path, &e))
    }

    async fn create_dir(&self, path: &str) -> Result<(), SshError> {
        self.0
            .create_dir(path)
            .await
            .map_err(|e| sftp_err("create_dir", path, &e))
    }

    async fn exists(&self, path: &str) -> bool {
        self.0.metadata(path).await.is_ok()
    }
}

fn sftp_err(op: &str, path: &str, e: &impl std::fmt::Display) -> SshError {
    SshError::ConnectionFailed {
        host: String::new(),
        reason: format!("sftp {op} {path}: {e}"),
    }
}

#[async_trait::async_trait]
impl RemoteShell for SshSession {
    async fn exec(&self, command: &str) -> Result<(u32, String, String), SshError> {
        // Inherent method — the trait method is the one being defined here.
        // Core's callers run short housekeeping commands (`echo $HOME`,
        // `chmod`, `grep -q` on authorized_keys).
        SshSession::exec(self, command, Some(REMOTE_SHELL_BUDGET)).await
    }

    async fn files(&self) -> Result<Box<dyn RemoteFiles + Send + Sync + '_>, SshError> {
        Ok(Box::new(SftpFiles(self.sftp().await?)))
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use russh::server::{self, Auth, Msg, Session};
    use russh::{Channel, ChannelId};

    /// How the test server behaves once a client is in.
    #[derive(Clone, Copy)]
    enum Server {
        /// Never answers the password.
        StallAuth,
        /// Accepts every command and never finishes it.
        StallExec,
        /// Drops the whole connection when asked to run a command.
        DropOnExec,
        /// Answers every command with "ok" and exit status 0.
        Answer,
    }

    struct Handler(Server);

    #[async_trait::async_trait]
    impl server::Handler for Handler {
        type Error = russh::Error;

        async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
            if let Server::StallAuth = self.0 {
                std::future::pending::<()>().await;
            }
            Ok(Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _: Channel<Msg>,
            _: &mut Session,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            _: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            match self.0 {
                Server::Answer => {
                    session.data(channel, russh::CryptoVec::from_slice(b"ok\n"));
                    session.exit_status_request(channel, 0);
                    session.close(channel);
                }
                Server::DropOnExec => return Err(russh::Error::Disconnect),
                Server::StallExec | Server::StallAuth => {}
            }
            Ok(())
        }
    }

    /// Serve one connection on a loopback port, and log in to it.
    async fn login(behaviour: Server, timeout_secs: u64) -> Result<SshSession, SshError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = Arc::new(server::Config {
            keys: vec![russh_keys::key::KeyPair::generate_ed25519()],
            auth_rejection_time: std::time::Duration::ZERO,
            ..server::Config::default()
        });
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            if let Ok(session) = server::run_stream(config, socket, Handler(behaviour)).await {
                let _ = session.await;
            }
        });
        let known_hosts = tempfile::tempdir().unwrap();
        let known_hosts = Arc::new(KnownHostsStore::open(known_hosts.path()).unwrap());
        SshSession::connect_password(
            "127.0.0.1",
            port,
            "ops",
            "secret",
            timeout_secs,
            known_hosts,
        )
        .await
    }

    fn reason(error: &SshError) -> &str {
        match error {
            SshError::ConnectionFailed { reason, .. } => reason,
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    }

    /// A server that completed the handshake and then never answered the
    /// login used to hold the caller forever.
    #[tokio::test]
    async fn a_login_that_is_never_answered_times_out() {
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            login(Server::StallAuth, 1),
        )
        .await
        .expect("the login is still waiting")
        .err()
        .expect("login succeeded");
        assert!(
            reason(&error).contains("authentication timed out"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_command_that_never_finishes_ends_at_its_budget() {
        let session = login(Server::StallExec, 5).await.unwrap();
        let exec = session.exec("sleep forever", Some(std::time::Duration::from_millis(300)));
        let error = tokio::time::timeout(std::time::Duration::from_secs(5), exec)
            .await
            .expect("the command is still waiting")
            .expect_err("command finished");
        assert!(reason(&error).contains("did not finish"), "{error}");
    }

    /// Callers read exit codes as answers (`grep -q`), so a dropped session
    /// must not come back as the command's exit 1.
    #[tokio::test]
    async fn a_lost_connection_is_an_error_not_an_exit_status() {
        let session = login(Server::DropOnExec, 5).await.unwrap();
        let error = session
            .exec("true", Some(std::time::Duration::from_secs(5)))
            .await
            .expect_err("a dropped session returned an exit status");
        assert!(reason(&error).contains("connection lost"), "{error}");
    }

    #[tokio::test]
    async fn a_finished_command_returns_its_status_and_output() {
        let session = login(Server::Answer, 5).await.unwrap();
        let (status, stdout, _) = session
            .exec("true", Some(std::time::Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!((status, stdout.as_str()), (0, "ok\n"));
    }
}
