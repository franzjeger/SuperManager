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
        let fingerprint = host_key_fingerprint(server_public_key);

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

/// What `known_hosts` records for `key`: the SHA-256 of its SSH wire form, in
/// hex. Not OpenSSH's base64 `SHA256:` form, but stable, and we only ever
/// compare it with ourselves. It must never shift, or every recorded host
/// reads as a changed key.
fn host_key_fingerprint(key: &PublicKey) -> String {
    KnownHostsStore::fingerprint(&key.public_key_bytes())
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

    /// Type `inputs` into an interactive shell, each only once the device
    /// has answered the one before it with a prompt.
    ///
    /// The whole session gets `timeout_secs`. If the device stops answering
    /// (the time runs out, the channel closes, or it asks something this
    /// doesn't recognise, like a y/n question), the session ends with
    /// `SshError::ShellInterrupted`, saying how many inputs it acknowledged.
    /// Nothing after that point is sent: a config push that went on typing
    /// into a silent device used to be reported as a success.
    pub async fn shell_interact(
        &self,
        inputs: &[ShellInput<'_>],
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
        let result = interact(&mut channel, inputs, deadline, timeout_secs).await;
        let _ = channel.close().await;
        result
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

// -- Interactive shell --------------------------------------------------------

/// One line to type into an interactive shell.
#[derive(Debug, Clone, Copy)]
pub enum ShellInput<'a> {
    /// A command, typed at the shell prompt.
    Command(&'a str),
    /// The answer to a password prompt, typed only if the command before it
    /// asked for one. At a shell prompt it would run as a command and land
    /// in the device's history, so there it is skipped.
    Secret(&'a str),
}

/// The prompt a device is waiting at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prompt {
    Shell,
    Password,
}

/// The prompt `output` ends in, if any. With `after_echo`, only what follows
/// the first line break counts: the device echoes the typed line first, and
/// a line that ends in `#` or `$` must not pass for the prompt after it.
fn trailing_prompt(output: &str, after_echo: bool) -> Option<Prompt> {
    let text = if after_echo {
        &output[output.find('\n')? + 1..]
    } else {
        output
    };
    let tail = text.trim_end();
    let ends_in_password = tail
        .get(tail.len().saturating_sub("password:".len())..)
        .is_some_and(|end| end.eq_ignore_ascii_case("password:"));
    if ends_in_password {
        Some(Prompt::Password)
    } else if tail.ends_with('#') || tail.ends_with('$') {
        Some(Prompt::Shell)
    } else {
        None
    }
}

/// What `interact` needs from a channel: send bytes, and wait until a
/// deadline for more output. The daemon passes a russh channel; the tests
/// pass a scripted device.
trait ShellChannel {
    async fn send(&mut self, data: &[u8]) -> Result<(), String>;
    async fn next_output(&mut self, deadline: tokio::time::Instant) -> ShellOutput;
}

enum ShellOutput {
    Data(Vec<u8>),
    Closed,
    TimedOut,
}

impl ShellChannel for russh::Channel<client::Msg> {
    async fn send(&mut self, data: &[u8]) -> Result<(), String> {
        self.data(data).await.map_err(|e| e.to_string())
    }

    async fn next_output(&mut self, deadline: tokio::time::Instant) -> ShellOutput {
        loop {
            match tokio::time::timeout_at(deadline, self.wait()).await {
                Err(_) => return ShellOutput::TimedOut,
                Ok(Some(russh::ChannelMsg::Data { data })) => {
                    return ShellOutput::Data(data.to_vec())
                }
                Ok(Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None) => {
                    return ShellOutput::Closed;
                }
                Ok(Some(_)) => {}
            }
        }
    }
}

/// `shell_interact`'s input loop, over any `ShellChannel`.
async fn interact<C: ShellChannel>(
    channel: &mut C,
    inputs: &[ShellInput<'_>],
    deadline: tokio::time::Instant,
    timeout_secs: u64,
) -> Result<String, SshError> {
    let total = inputs.len();
    let stop = |acknowledged: usize, reason: String, output: &[u8]| SshError::ShellInterrupted {
        acknowledged,
        total,
        reason,
        transcript: String::from_utf8_lossy(output).into_owned(),
    };
    let mut output = Vec::new();
    let mut acknowledged = 0;

    // The banner may say anything and echoes nothing, so its prompt is
    // simply whatever it ends in.
    let mut at = match wait_for_prompt(channel, &mut output, 0, false, deadline, timeout_secs).await
    {
        Ok(prompt) => prompt,
        Err(reason) => return Err(stop(0, format!("no shell prompt: {reason}"), &output)),
    };
    for input in inputs {
        let (text, secret) = match *input {
            ShellInput::Command(text) => (text, false),
            ShellInput::Secret(text) => (text, true),
        };
        match (at, secret) {
            (Prompt::Shell, true) => {
                // Nothing asked for it: typed now, it would run as a command.
                acknowledged += 1;
                continue;
            }
            (Prompt::Password, false) => {
                let reason = "the device asked for a password".to_owned();
                return Err(stop(acknowledged, reason, &output));
            }
            _ => {}
        }
        let start = output.len();
        if let Err(e) = channel.send(format!("{text}\n").as_bytes()).await {
            return Err(stop(acknowledged, format!("send failed: {e}"), &output));
        }
        at = match wait_for_prompt(channel, &mut output, start, true, deadline, timeout_secs).await
        {
            Ok(prompt) => prompt,
            Err(reason) => return Err(stop(acknowledged, reason, &output)),
        };
        acknowledged += 1;
    }
    Ok(String::from_utf8_lossy(&output).into_owned())
}

/// Read until the output since `start` ends in a prompt, and say which. The
/// error says why none came.
async fn wait_for_prompt<C: ShellChannel>(
    channel: &mut C,
    output: &mut Vec<u8>,
    start: usize,
    after_echo: bool,
    deadline: tokio::time::Instant,
    timeout_secs: u64,
) -> Result<Prompt, String> {
    loop {
        match channel.next_output(deadline).await {
            ShellOutput::Data(data) => {
                output.extend_from_slice(&data);
                let new = String::from_utf8_lossy(&output[start..]);
                if let Some(prompt) = trailing_prompt(&new, after_echo) {
                    return Ok(prompt);
                }
            }
            ShellOutput::Closed => return Err("the device closed the session".to_owned()),
            ShellOutput::TimedOut => {
                return Err(format!("no prompt within the session's {timeout_secs} s"))
            }
        }
    }
}

#[cfg(test)]
mod shell_tests {
    use super::*;
    use std::collections::VecDeque;

    /// A device that prints `outputs` in order, one per wait, and remembers
    /// what was typed into it.
    struct Device {
        outputs: VecDeque<ShellOutput>,
        typed: Vec<String>,
    }

    // The script answers at once, so its futures are ready ones.
    impl ShellChannel for Device {
        fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), String>> {
            self.typed
                .push(String::from_utf8_lossy(data).trim_end().to_owned());
            std::future::ready(Ok(()))
        }

        fn next_output(
            &mut self,
            _deadline: tokio::time::Instant,
        ) -> impl std::future::Future<Output = ShellOutput> {
            std::future::ready(self.outputs.pop_front().unwrap_or(ShellOutput::TimedOut))
        }
    }

    fn says(text: &str) -> ShellOutput {
        ShellOutput::Data(text.as_bytes().to_vec())
    }

    async fn run(
        outputs: Vec<ShellOutput>,
        inputs: &[ShellInput<'_>],
    ) -> (Result<String, SshError>, Vec<String>) {
        let mut device = Device {
            outputs: outputs.into(),
            typed: Vec::new(),
        };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let result = interact(&mut device, inputs, deadline, 5).await;
        (result, device.typed)
    }

    fn interrupted_after(result: &Result<String, SshError>) -> Option<usize> {
        match result {
            Err(SshError::ShellInterrupted { acknowledged, .. }) => Some(*acknowledged),
            _ => None,
        }
    }

    #[tokio::test]
    async fn a_device_that_answers_every_line_takes_them_all() {
        let (result, typed) = run(
            vec![
                says("FGT60F # "),
                says("config system global\r\nFGT60F (global) # "),
                says("end\r\nFGT60F # "),
            ],
            &[
                ShellInput::Command("config system global"),
                ShellInput::Command("end"),
            ],
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(typed, ["config system global", "end"]);
    }

    /// The bug: a device that went silent mid-push used to get the rest of
    /// the lines anyway, and the push was reported as a success.
    #[tokio::test]
    async fn a_device_that_goes_silent_gets_nothing_more() {
        let (result, typed) = run(
            vec![
                says("FGT60F # "),
                says("config system global\r\nFGT60F (global) # "),
            ],
            &[
                ShellInput::Command("config system global"),
                ShellInput::Command("set hostname edge"),
                ShellInput::Command("end"),
            ],
        )
        .await;
        assert_eq!(interrupted_after(&result), Some(1), "{result:?}");
        assert_eq!(typed, ["config system global", "set hostname edge"]);
    }

    #[tokio::test]
    async fn a_closed_session_ends_the_push() {
        let (result, typed) = run(
            vec![says("FGT60F # "), ShellOutput::Closed],
            &[
                ShellInput::Command("config system global"),
                ShellInput::Command("end"),
            ],
        )
        .await;
        assert_eq!(interrupted_after(&result), Some(0), "{result:?}");
        assert_eq!(typed, ["config system global"]);
    }

    #[tokio::test]
    async fn no_first_prompt_means_nothing_is_typed() {
        let (result, typed) = run(vec![says("Welcome")], &[ShellInput::Command("end")]).await;
        assert_eq!(interrupted_after(&result), Some(0), "{result:?}");
        assert!(typed.is_empty());
    }

    /// The device echoes what was typed; a line ending in `#` must not pass
    /// for the prompt that follows it.
    #[tokio::test]
    async fn the_echo_of_a_line_is_not_its_acknowledgement() {
        let (result, typed) = run(
            vec![says("FGT60F # "), says("set comments cost-center#")],
            &[
                ShellInput::Command("set comments cost-center#"),
                ShellInput::Command("end"),
            ],
        )
        .await;
        assert_eq!(interrupted_after(&result), Some(0), "{result:?}");
        assert_eq!(typed, ["set comments cost-center#"]);
    }

    #[tokio::test]
    async fn a_secret_answers_a_password_prompt() {
        let (result, typed) = run(
            vec![
                says("FGT60F # "),
                says("execute api-user generate-key ops\r\nPassword: "),
                says("\r\nNew API key: 0123abcd\r\nFGT60F # "),
            ],
            &[
                ShellInput::Command("execute api-user generate-key ops"),
                ShellInput::Secret("hunter2"),
            ],
        )
        .await;
        assert!(
            result
                .as_ref()
                .is_ok_and(|t| t.contains("New API key: 0123abcd")),
            "{result:?}"
        );
        assert_eq!(typed, ["execute api-user generate-key ops", "hunter2"]);
    }

    /// Unasked, a password typed at the shell prompt would run as a command
    /// and land in the device's history.
    #[tokio::test]
    async fn a_secret_is_never_typed_at_a_shell_prompt() {
        let (result, typed) = run(
            vec![
                says("FGT60F # "),
                says("execute api-user generate-key ops\r\nNew API key: 0123abcd\r\nFGT60F # "),
            ],
            &[
                ShellInput::Command("execute api-user generate-key ops"),
                ShellInput::Secret("hunter2"),
            ],
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(typed, ["execute api-user generate-key ops"]);
    }

    #[tokio::test]
    async fn a_command_is_never_typed_at_a_password_prompt() {
        let (result, typed) = run(
            vec![
                says("FGT60F # "),
                says("execute backup config\r\nPassword: "),
            ],
            &[
                ShellInput::Command("execute backup config"),
                ShellInput::Command("end"),
            ],
        )
        .await;
        assert_eq!(interrupted_after(&result), Some(1), "{result:?}");
        assert_eq!(typed, ["execute backup config"]);
    }

    #[test]
    fn prompts_are_recognised_by_how_the_output_ends() {
        assert_eq!(
            trailing_prompt("FGT60F (api-user) # ", false),
            Some(Prompt::Shell)
        );
        assert_eq!(
            trailing_prompt("admin@host:~$ ", false),
            Some(Prompt::Shell)
        );
        assert_eq!(
            trailing_prompt("Please enter admin PASSWORD: ", false),
            Some(Prompt::Password)
        );
        assert_eq!(
            trailing_prompt("Do you want to continue? (y/n)", false),
            None
        );
        assert_eq!(trailing_prompt("# comment\r\nstill running", false), None);
        // Past the echo, not in it.
        assert_eq!(trailing_prompt("echo a#", true), None);
        assert_eq!(
            trailing_prompt("echo a#\r\nFGT60F # ", true),
            Some(Prompt::Shell)
        );
    }
}

/// Host-key fingerprints are stored, so they must survive library upgrades.
/// The expected values below were computed outside any SSH library, from
/// keys made by `ssh-keygen`: `shasum -a 256` over the base64-decoded key.
#[cfg(test)]
mod host_key_tests {
    use super::*;

    const ED25519: (&str, &str) = (
        "AAAAC3NzaC1lZDI1NTE5AAAAIO88gW2+ekico7P/wx3hnEskuq3Vu6VATCjUhEtMlYzD",
        "262c5a9e464b3ff6f888a4db6cd40fa1a5ca89aca000ff501a85307cbc964c53",
    );
    const RSA: (&str, &str) = (
        "AAAAB3NzaC1yc2EAAAADAQABAAABAQC2yvjxYsTv+XWbvV4aymsNDMSeL4a/FRxY33k0knq7/DGaFZpkppQChYDJ\
         qYVUdYqdvGZ3V0uEjSKkEhlyJ+l7cMigD2JWkDPqqng4yEDy7e1+oX7Ggbrty+zqgWptst0e5LO+MLTNYujrU3GC\
         ll5HI94qkI5tsrCsiajMFg/5Q0RUGtCqd4/E2q7bttlYGeH0nsbDlMG7JYcBQfEvvDS6M9p6OOde9ODGA2AhaoPQ\
         oOzDNlgwf+1p4rJJlF7o0gd7pgdb725kSvPdUV2iLr0+m9awrIUVNzK0iLmvqhXSNcDP9x8QbKZetPjJAbptC/RM\
         PcHAOMYuzHuNcMPJ3ofJ",
        "9a0e5f35e18f44da787e29a1adfdc913b362d99ada24d34ef4225c8ae647e344",
    );
    const ECDSA_P256: (&str, &str) = (
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBJbjIi7BbSJRV0fZw6cbjrOxdv+BW12bAOR\
         I7tQIKnqt4hh9mDPwCfwlcPXrgb6tQr7WdyS1lHcf2/uyO5Nvd0=",
        "7452945f1d26766d358217507f4321eaf76ad281732fa9fc7dda0e2d1079c7bb",
    );

    #[test]
    fn fingerprints_match_what_known_hosts_already_holds() {
        for (blob, expected) in [ED25519, RSA, ECDSA_P256] {
            let key = russh_keys::parse_public_key_base64(blob).unwrap();
            assert_eq!(host_key_fingerprint(&key), expected, "{blob}");
        }
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

    /// Serve one connection on a loopback port with `host_key`; returns the port.
    async fn serve(behaviour: Server, host_key: russh_keys::key::KeyPair) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = Arc::new(server::Config {
            keys: vec![host_key],
            auth_rejection_time: std::time::Duration::ZERO,
            ..server::Config::default()
        });
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            if let Ok(session) = server::run_stream(config, socket, Handler(behaviour)).await {
                let _ = session.await;
            }
        });
        port
    }

    /// Serve one connection on a loopback port, and log in to it.
    async fn login(behaviour: Server, timeout_secs: u64) -> Result<SshSession, SshError> {
        let port = serve(behaviour, russh_keys::key::KeyPair::generate_ed25519()).await;
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

    /// The ed25519 host key anyone can rebuild from 32 bytes of 7. OpenSSL
    /// derived its public key, and `shasum` its fingerprint.
    fn seeded_host_key() -> russh_keys::key::KeyPair {
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]));
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        russh_keys::decode_secret_key(&pem, None).unwrap()
    }

    const SEEDED_HOST_KEY_FINGERPRINT: &str =
        "cff7d2bf46744594be2dc71b73a668396c2dfdf6e3d5514919204a41ba3889c1";

    /// The key a real handshake hands the host-key check must be recorded
    /// with the fingerprint of its standard wire form, the one `known_hosts`
    /// files already hold.
    #[tokio::test]
    async fn a_handshake_records_the_fingerprint_known_hosts_already_holds() {
        let port = serve(Server::Answer, seeded_host_key()).await;
        let dir = tempfile::tempdir().unwrap();
        let known_hosts = Arc::new(KnownHostsStore::open(dir.path()).unwrap());
        SshSession::connect_password(
            "127.0.0.1",
            port,
            "ops",
            "secret",
            5,
            Arc::clone(&known_hosts),
        )
        .await
        .unwrap();
        assert_eq!(
            known_hosts.entries(),
            [(
                format!("127.0.0.1:{port}"),
                SEEDED_HOST_KEY_FINGERPRINT.to_owned()
            )]
        );
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
