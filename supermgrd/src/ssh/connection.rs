//! Async SSH client wrapper using `russh`.
//!
//! Provides password and public-key authentication, command execution, and
//! SFTP session creation over a single TCP connection.

use std::sync::Arc;

use russh::client::{self, Handle, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::Channel;
use supermgr_core::error::SshError;
use supermgr_core::ssh::known_hosts::{HostKeyCheck, KnownHostsStore};
use supermgr_core::ssh::remote::{RemoteFiles, RemoteShell};
use tokio::io::{AsyncRead, AsyncWrite};

// ---------------------------------------------------------------------------
// Client handler
// ---------------------------------------------------------------------------

/// russh client handler that verifies the server's host key against the
/// persistent [`KnownHostsStore`].
///
/// First-sight policy is **TOFU + record**: an unrecorded host has its key
/// fingerprint saved, then accepted. Every subsequent connection to the same
/// `host:port` requires the recorded fingerprint to match — a mismatch is
/// rejected loudly. This is the same posture OpenSSH gives you with
/// `StrictHostKeyChecking=accept-new`.
///
/// Without this layer every man-in-the-middle is invisible, and this daemon
/// runs as root and pushes SSH private keys, runs remote commands and reads
/// device configuration over these sessions. macOS (`supermgr-engine`) and
/// Windows (`supermgrd-win`) already verified; Linux did not.
struct SshClientHandler {
    known_hosts: Arc<KnownHostsStore>,
    host: String,
    port: u16,
}

impl SshClientHandler {
    fn new(known_hosts: Arc<KnownHostsStore>, host: &str, port: u16) -> Self {
        Self {
            known_hosts,
            host: host.to_owned(),
            port,
        }
    }
}

impl client::Handler for SshClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = host_key_fingerprint(server_public_key)?;

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
                // An `Err` here aborts the handshake the same way `Ok(false)`
                // would, but it carries both fingerprints out to the GUI so
                // the operator can tell a rotation from an attack.
                Err(anyhow::anyhow!(
                    "host key mismatch for {}:{} — stored={stored}, server-presented={current}; \
                     refusing to connect. If this host was legitimately reinstalled or had its \
                     key rotated, forget the recorded key (host detail → Forget host key, or \
                     the SshForgetHostKey D-Bus method) and reconnect.",
                    self.host,
                    self.port,
                ))
            }
        }
    }
}

/// What `known_hosts` records for `key`: the SHA-256 of its SSH wire form, in
/// hex. Not OpenSSH's base64 `SHA256:` form, but stable, and we only ever
/// compare it with ourselves. It must never shift, or every recorded host
/// reads as a changed key.
fn host_key_fingerprint(key: &PublicKey) -> Result<String, russh::keys::ssh_key::Error> {
    Ok(KnownHostsStore::fingerprint(&key.to_bytes()?))
}

/// Parse a stored OpenSSH certificate, as russh's own `Certificate`: russh
/// uses a newer ssh-key than the rest of the workspace.
///
/// Trimmed first. The GUI stores whatever was pasted, surrounding whitespace
/// included, and `from_openssh` only trims the end: a leading space or
/// newline failed the parse, and login went ahead with the bare key, saying
/// so only in the daemon log.
fn parse_certificate(
    stored: &str,
) -> Result<russh::keys::Certificate, russh::keys::ssh_key::Error> {
    russh::keys::Certificate::from_openssh(stored.trim())
}

/// The signature hash for public-key authentication with `key`. For RSA it is
/// what the server says it accepts (RFC 8308 `server-sig-algs`), and
/// rsa-sha2-512 when it says nothing, which is what russh 0.46 always used
/// for OpenSSH-format keys. Other key types have no choice to make, and skip
/// waiting up to a second for the server's answer.
async fn signature_hash<H: client::Handler>(
    handle: &Handle<H>,
    key: &PrivateKey,
) -> Option<HashAlg> {
    if !key.algorithm().is_rsa() {
        return None;
    }
    match handle.best_supported_rsa_hash().await {
        Ok(Some(accepted)) => accepted,
        Ok(None) | Err(_) => Some(HashAlg::Sha512),
    }
}

// ---------------------------------------------------------------------------
// Session wrapper
// ---------------------------------------------------------------------------

/// An established SSH session wrapping a russh client handle.
pub struct SshSession {
    handle: Handle<SshClientHandler>,
}

impl SshSession {
    // -- constructors -------------------------------------------------------

    /// Try `password` auth first, then fall back to `keyboard-interactive`.
    ///
    /// macOS (and some other servers) only accept keyboard-interactive, not
    /// the plain SSH `password` method, so we must try both.
    async fn auth_password_or_keyboard(
        handle: &mut Handle<SshClientHandler>,
        username: &str,
        password: &str,
    ) -> Result<bool, SshError> {
        // 1. Try plain password auth.
        match handle.authenticate_password(username, password).await {
            Ok(result) if result.success() => return Ok(true),
            Ok(_) => {}  // server rejected – try keyboard-interactive
            Err(_) => {} // protocol error – try keyboard-interactive
        }

        // 2. Try keyboard-interactive (macOS, some Linux PAM setups).
        match handle
            .authenticate_keyboard_interactive_start(username, None::<String>)
            .await
        {
            Ok(KeyboardInteractiveAuthResponse::Success) => Ok(true),
            Ok(KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. }) => {
                // Respond with the password for every prompt (typically one
                // "Password:" prompt).
                let responses: Vec<String> = prompts.iter().map(|_| password.to_owned()).collect();
                match handle
                    .authenticate_keyboard_interactive_respond(responses)
                    .await
                {
                    Ok(KeyboardInteractiveAuthResponse::Success) => Ok(true),
                    Ok(_) => Ok(false),
                    Err(e) => Err(SshError::AuthFailed(e.to_string())),
                }
            }
            Ok(KeyboardInteractiveAuthResponse::Failure { .. }) => Ok(false),
            Err(e) => Err(SshError::AuthFailed(e.to_string())),
        }
    }

    /// Connect to a remote host using password authentication.
    ///
    /// `known_hosts` is consulted via the russh handler — see
    /// [`SshClientHandler::check_server_key`]. A previously-seen host whose
    /// fingerprint has changed fails the connection here with a
    /// `ConnectionFailed` carrying both the stored and current fingerprint.
    pub async fn connect_password(
        hostname: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout_secs: u64,
        known_hosts: Arc<KnownHostsStore>,
    ) -> Result<Self, SshError> {
        let config = Arc::new(client::Config::default());
        let addr = format!("{hostname}:{port}");
        let handler = SshClientHandler::new(known_hosts, hostname, port);

        let mut handle = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            client::connect(config, &addr as &str, handler),
        )
        .await
        .map_err(|_| SshError::ConnectionFailed {
            host: addr.clone(),
            reason: format!("connection timed out after {timeout_secs}s"),
        })?
        .map_err(|e| SshError::ConnectionFailed {
            host: addr.clone(),
            reason: e.to_string(),
        })?;

        let auth_ok = Self::auth_password_or_keyboard(&mut handle, username, password).await?;

        if !auth_ok {
            return Err(SshError::AuthFailed(
                "password authentication rejected by server".into(),
            ));
        }

        Ok(Self { handle })
    }

    /// Connect to a remote host using private-key authentication.
    ///
    /// If `cert_pem` is provided, attempts OpenSSH certificate authentication
    /// first, then falls back to plain public-key authentication.
    ///
    /// See [`Self::connect_password`] for the host-key verification
    /// semantics — it's the same handler.
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
    /// The certificate must correspond to the given private key.
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

    /// Internal: connect with optional certificate.
    async fn connect_key_with_cert(
        hostname: &str,
        port: u16,
        username: &str,
        private_key_pem: &str,
        cert_pem: Option<&str>,
        timeout_secs: u64,
        known_hosts: Arc<KnownHostsStore>,
    ) -> Result<Self, SshError> {
        let key_pair = russh::keys::decode_secret_key(private_key_pem, None)
            .map_err(|e| SshError::AuthFailed(format!("failed to decode private key: {e}")))?;

        let config = Arc::new(client::Config::default());
        let addr = format!("{hostname}:{port}");
        let handler = SshClientHandler::new(known_hosts, hostname, port);

        let mut handle = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            client::connect(config, &addr as &str, handler),
        )
        .await
        .map_err(|_| SshError::ConnectionFailed {
            host: addr.clone(),
            reason: format!("connection timed out after {timeout_secs}s"),
        })?
        .map_err(|e| SshError::ConnectionFailed {
            host: addr.clone(),
            reason: e.to_string(),
        })?;

        let key_pair = Arc::new(key_pair);

        // Try certificate auth first if a certificate is provided.
        if let Some(cert_data) = cert_pem {
            match parse_certificate(cert_data) {
                Ok(cert) => {
                    match handle
                        .authenticate_openssh_cert(username, key_pair.clone(), cert)
                        .await
                    {
                        Ok(result) if result.success() => return Ok(Self { handle }),
                        Ok(_) => {
                            // Certificate rejected — fall through to plain pubkey.
                        }
                        Err(e) => {
                            // Protocol error — fall through to plain pubkey.
                            tracing::warn!("certificate auth failed, trying plain pubkey: {e}");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to parse SSH certificate, trying plain pubkey: {e}");
                }
            }
        }

        // Plain public-key authentication.
        let hash = signature_hash(&handle, &key_pair).await;
        let auth_ok = handle
            .authenticate_publickey(username, PrivateKeyWithHashAlg::new(key_pair, hash))
            .await
            .map_err(|e| SshError::AuthFailed(e.to_string()))?;

        if !auth_ok.success() {
            return Err(SshError::AuthFailed(
                "public-key authentication rejected by server".into(),
            ));
        }

        Ok(Self { handle })
    }

    /// Connect to a remote host using password authentication over an
    /// existing stream (e.g. a tunnel from a jump host).
    ///
    /// The target's host key is verified exactly as it would be on a direct
    /// connection — a tunnelled hop is still a hop an attacker can sit on,
    /// and `hostname`/`port` name the *target*, not the jump host, so the
    /// fingerprint is recorded against the right identity.
    pub async fn connect_password_stream<S>(
        stream: S,
        hostname: &str,
        port: u16,
        username: &str,
        password: &str,
        known_hosts: Arc<KnownHostsStore>,
    ) -> Result<Self, SshError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let config = Arc::new(client::Config::default());
        let target_addr = format!("{hostname}:{port}");
        let handler = SshClientHandler::new(known_hosts, hostname, port);

        let mut handle = client::connect_stream(config, stream, handler)
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: target_addr.clone(),
                reason: format!("stream connect failed: {e}"),
            })?;

        let auth_ok = Self::auth_password_or_keyboard(&mut handle, username, password).await?;

        if !auth_ok {
            return Err(SshError::AuthFailed(
                "password authentication rejected by server (via tunnel)".into(),
            ));
        }

        Ok(Self { handle })
    }

    /// Connect to a remote host using private-key authentication over an
    /// existing stream (e.g. a tunnel from a jump host).
    ///
    /// See [`Self::connect_password_stream`] for the host-key verification
    /// semantics — it's the same handler.
    pub async fn connect_key_stream<S>(
        stream: S,
        hostname: &str,
        port: u16,
        username: &str,
        private_key_pem: &str,
        known_hosts: Arc<KnownHostsStore>,
    ) -> Result<Self, SshError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let key_pair = russh::keys::decode_secret_key(private_key_pem, None)
            .map_err(|e| SshError::AuthFailed(format!("failed to decode private key: {e}")))?;

        let config = Arc::new(client::Config::default());
        let target_addr = format!("{hostname}:{port}");
        let handler = SshClientHandler::new(known_hosts, hostname, port);

        let mut handle = client::connect_stream(config, stream, handler)
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: target_addr.clone(),
                reason: format!("stream connect failed: {e}"),
            })?;

        let key_pair = Arc::new(key_pair);
        let hash = signature_hash(&handle, &key_pair).await;
        let auth_ok = handle
            .authenticate_publickey(username, PrivateKeyWithHashAlg::new(key_pair, hash))
            .await
            .map_err(|e| SshError::AuthFailed(e.to_string()))?;

        if !auth_ok.success() {
            return Err(SshError::AuthFailed(
                "public-key authentication rejected by server (via tunnel)".into(),
            ));
        }

        Ok(Self { handle })
    }

    /// Open a direct-tcpip tunnel through this session to a target host:port.
    ///
    /// Returns a `ChannelStream` that implements `AsyncRead + AsyncWrite` and
    /// can be passed to `connect_password_stream` / `connect_key_stream`.
    pub async fn open_tunnel(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<russh::ChannelStream<Msg>, SshError> {
        let channel = self
            .handle
            .channel_open_direct_tcpip(target_host, target_port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: format!("{target_host}:{target_port}"),
                reason: format!("failed to open tunnel: {e}"),
            })?;

        Ok(channel.into_stream())
    }

    // -- command execution --------------------------------------------------

    /// Execute a command on the remote host.
    ///
    /// Returns `(exit_status, stdout, stderr)`.
    pub async fn exec(&self, command: &str) -> Result<(u32, String, String), SshError> {
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
        let mut exit_status: u32 = 1;

        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::ExtendedData { data, ext }) => {
                    if ext == 1 {
                        // ext == 1 is stderr
                        stderr.extend_from_slice(&data);
                    }
                }
                Some(russh::ChannelMsg::ExitStatus { exit_status: code }) => {
                    exit_status = code;
                }
                Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) => {
                    // Keep draining until the channel is fully closed.
                }
                None => break,
                _ => {}
            }
        }

        let stdout_str = String::from_utf8_lossy(&stdout).into_owned();
        let stderr_str = String::from_utf8_lossy(&stderr).into_owned();

        Ok((exit_status, stdout_str, stderr_str))
    }

    /// Run an interactive shell session, sending lines sequentially.
    ///
    /// Waits for a prompt (`# ` or `$ ` or `password:`) before sending each
    /// line.  Used for commands that prompt for input (e.g. FortiGate
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

    // -- port forwarding ----------------------------------------------------

    /// Open a direct-tcpip channel to `remote_host:remote_port`.
    ///
    /// Returns a russh `Channel` that can be used to shuttle data between a
    /// local TCP connection and the remote endpoint through the SSH tunnel.
    pub async fn channel_open_direct_tcpip(
        &self,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<Channel<Msg>, SshError> {
        self.handle
            .channel_open_direct_tcpip(remote_host, remote_port as u32, "127.0.0.1", 0u32)
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: String::new(),
                reason: format!("direct-tcpip channel open failed: {e}"),
            })
    }

    // -- lifecycle ----------------------------------------------------------

    /// Gracefully disconnect from the remote host.
    #[allow(dead_code)]
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
        SshSession::exec(self, command).await
    }

    async fn files(&self) -> Result<Box<dyn RemoteFiles + Send + Sync + '_>, SshError> {
        Ok(Box::new(SftpFiles(self.sftp().await?)))
    }
}

/// Host-key fingerprints are stored, so they must survive library upgrades.
/// The expected values were computed outside any SSH library, from keys made
/// by `ssh-keygen`: `shasum -a 256` over the base64-decoded key. The engine
/// pins the same keys, and also runs them through a real handshake.
#[cfg(test)]
mod host_key_tests {
    use super::*;

    #[test]
    fn fingerprints_match_what_known_hosts_already_holds() {
        let keys = [
            (
                "AAAAC3NzaC1lZDI1NTE5AAAAIO88gW2+ekico7P/wx3hnEskuq3Vu6VATCjUhEtMlYzD",
                "262c5a9e464b3ff6f888a4db6cd40fa1a5ca89aca000ff501a85307cbc964c53",
            ),
            (
                "AAAAB3NzaC1yc2EAAAADAQABAAABAQC2yvjxYsTv+XWbvV4aymsNDMSeL4a/FRxY33k0knq7/DGaFZpkppQChYDJ\
                 qYVUdYqdvGZ3V0uEjSKkEhlyJ+l7cMigD2JWkDPqqng4yEDy7e1+oX7Ggbrty+zqgWptst0e5LO+MLTNYujrU3GC\
                 ll5HI94qkI5tsrCsiajMFg/5Q0RUGtCqd4/E2q7bttlYGeH0nsbDlMG7JYcBQfEvvDS6M9p6OOde9ODGA2AhaoPQ\
                 oOzDNlgwf+1p4rJJlF7o0gd7pgdb725kSvPdUV2iLr0+m9awrIUVNzK0iLmvqhXSNcDP9x8QbKZetPjJAbptC/RM\
                 PcHAOMYuzHuNcMPJ3ofJ",
                "9a0e5f35e18f44da787e29a1adfdc913b362d99ada24d34ef4225c8ae647e344",
            ),
            (
                "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBJbjIi7BbSJRV0fZw6cbjrOxdv+BW12bAOR\
                 I7tQIKnqt4hh9mDPwCfwlcPXrgb6tQr7WdyS1lHcf2/uyO5Nvd0=",
                "7452945f1d26766d358217507f4321eaf76ad281732fa9fc7dda0e2d1079c7bb",
            ),
        ];
        for (blob, expected) in keys {
            let key = russh::keys::parse_public_key_base64(blob).unwrap();
            assert_eq!(host_key_fingerprint(&key).unwrap(), expected, "{blob}");
        }
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::*;

    /// The engine's test certificate, from `ssh-keygen -s ca -I testid -n
    /// root`. Only parsed, so its expiry can't rot the test.
    const CERT: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIJ9a/RUT34M6KpfmIHf+OOJMzRUEfVeqUOI02LzMhfNtAAAAIOUk18Uqim7mDZikSU6bmR7b9zjAFqL88V8dFZXWCen/AAAAAAAAAAAAAAABAAAABnRlc3RpZAAAAAgAAAAEcm9vdAAAAABqd03QAAAAAGxXMCUAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDzWHnfe5a0E+lvGZ9ye+4ItyAp57rjW9E01WbNw7fkoAAAAFMAAAALc3NoLWVkMjU1MTkAAABATEJm0QvR/7+XQ0ya/o9gNs+Ew6HvmNhR3hbiW0jwuVL2Fbpc/cMxapnKqUzZAzNkMvxPQGtpUWcXxx5Q4siCDg== testkey";

    #[test]
    fn a_stored_certificate_parses_despite_surrounding_whitespace() {
        let pasted = format!("\n  {CERT}\n\n");
        assert!(
            russh::keys::Certificate::from_openssh(&pasted).is_err(),
            "from_openssh now tolerates leading whitespace; the trim may be unnecessary"
        );
        let cert = parse_certificate(&pasted).unwrap();
        assert_eq!(cert.key_id(), "testid");
        assert_eq!(cert.valid_principals(), ["root"]);
    }
}
