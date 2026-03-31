//! Async SSH client wrapper using `russh`.
//!
//! Provides password and public-key authentication, command execution, and
//! SFTP session creation over a single TCP connection.

use std::sync::Arc;

use russh::client::{self, Handle, Msg};
use russh::Channel;
use russh_keys::key::PublicKey;
use supermgr_core::error::SshError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::ToSocketAddrs;

// ---------------------------------------------------------------------------
// Client handler
// ---------------------------------------------------------------------------

/// Minimal russh client handler.
///
/// Accepts all host keys (trust-on-first-use). In a production deployment the
/// handler should check known_hosts, but for a management tool that pushes
/// keys to many ephemeral hosts this is the pragmatic default.
struct SshClientHandler;

#[async_trait::async_trait]
impl client::Handler for SshClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all host keys (TOFU).
        Ok(true)
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

    /// Connect to a remote host using password authentication.
    pub async fn connect_password(
        hostname: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout_secs: u64,
    ) -> Result<Self, SshError> {
        let config = Arc::new(client::Config::default());
        let addr = format!("{hostname}:{port}");

        let mut handle = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            client::connect(config, &addr as &str, SshClientHandler),
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

        let auth_ok = handle
            .authenticate_password(username, password)
            .await
            .map_err(|e| SshError::AuthFailed(e.to_string()))?;

        if !auth_ok {
            return Err(SshError::AuthFailed(
                "password authentication rejected by server".into(),
            ));
        }

        Ok(Self { handle })
    }

    /// Connect to a remote host using private-key authentication.
    pub async fn connect_key(
        hostname: &str,
        port: u16,
        username: &str,
        private_key_pem: &str,
        timeout_secs: u64,
    ) -> Result<Self, SshError> {
        let key_pair = russh_keys::decode_secret_key(private_key_pem, None)
            .map_err(|e| SshError::AuthFailed(format!("failed to decode private key: {e}")))?;

        let config = Arc::new(client::Config::default());
        let addr = format!("{hostname}:{port}");

        let mut handle = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            client::connect(config, &addr as &str, SshClientHandler),
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

        let auth_ok = handle
            .authenticate_publickey(username, Arc::new(key_pair))
            .await
            .map_err(|e| SshError::AuthFailed(e.to_string()))?;

        if !auth_ok {
            return Err(SshError::AuthFailed(
                "public-key authentication rejected by server".into(),
            ));
        }

        Ok(Self { handle })
    }

    /// Connect to a remote host using password authentication over an
    /// existing stream (e.g. a tunnel from a jump host).
    pub async fn connect_password_stream<S>(
        stream: S,
        target_addr: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, SshError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let config = Arc::new(client::Config::default());

        let mut handle = client::connect_stream(config, stream, SshClientHandler)
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: target_addr.to_owned(),
                reason: format!("stream connect failed: {e}"),
            })?;

        let auth_ok = handle
            .authenticate_password(username, password)
            .await
            .map_err(|e| SshError::AuthFailed(e.to_string()))?;

        if !auth_ok {
            return Err(SshError::AuthFailed(
                "password authentication rejected by server (via tunnel)".into(),
            ));
        }

        Ok(Self { handle })
    }

    /// Connect to a remote host using private-key authentication over an
    /// existing stream (e.g. a tunnel from a jump host).
    pub async fn connect_key_stream<S>(
        stream: S,
        target_addr: &str,
        username: &str,
        private_key_pem: &str,
    ) -> Result<Self, SshError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let key_pair = russh_keys::decode_secret_key(private_key_pem, None)
            .map_err(|e| SshError::AuthFailed(format!("failed to decode private key: {e}")))?;

        let config = Arc::new(client::Config::default());

        let mut handle = client::connect_stream(config, stream, SshClientHandler)
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: target_addr.to_owned(),
                reason: format!("stream connect failed: {e}"),
            })?;

        let auth_ok = handle
            .authenticate_publickey(username, Arc::new(key_pair))
            .await
            .map_err(|e| SshError::AuthFailed(e.to_string()))?;

        if !auth_ok {
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
            .channel_open_direct_tcpip(
                target_host,
                target_port as u32,
                "127.0.0.1",
                0,
            )
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
        let mut channel = self
            .handle
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
        let mut channel = self
            .handle
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

        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(timeout_secs);
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
                if remaining.is_zero() { break; }
                match tokio::time::timeout(remaining, channel.wait()).await {
                    Ok(Some(russh::ChannelMsg::Data { data })) => {
                        output.extend_from_slice(&data);
                        // Only check NEW data (after prev_len).
                        let new_text = String::from_utf8_lossy(&output[prev_len..]);
                        let keywords = ["# ", "$ ", "password:", "Password:", "New API key:", "API key:"];
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
        let channel = self
            .handle
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
            .channel_open_direct_tcpip(
                remote_host,
                remote_port as u32,
                "127.0.0.1",
                0u32,
            )
            .await
            .map_err(|e| SshError::ConnectionFailed {
                host: String::new(),
                reason: format!("direct-tcpip channel open failed: {e}"),
            })
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
