//! Remote shell-command execution over SSH (Windows).
//!
//! The portable parts of this — SSH transport, key parsing, command
//! channels — are handled by the cross-platform `russh` crate that the
//! Linux daemon already uses. The Windows-specific piece is the secret
//! resolution: passwords and private keys live in Credential Manager
//! rather than the on-disk keyring file the Linux daemon writes.
//!
//! # Flow
//!
//! 1. Load the host's JSON metadata from `%PROGRAMDATA%\SuperManager\hosts\`.
//! 2. Pick the auth method recorded on the host (`password`, `key`, or
//!    `api-token`).
//! 3. Pull the credential from Credential Manager (`supermgr/host/<id>/...`
//!    for passwords, `supermgr/ssh/<key_id>/privkey` for keys).
//! 4. Open a russh session, authenticate, run the command, capture stdout
//!    + stderr + exit code.
//! 5. Return them as a JSON blob — the same shape the D-Bus daemon emits.
//!
//! No data is persisted by this module; failures bubble up as
//! `RpcError::Backend`. The caller (the dispatcher) wraps the JSON in the
//! pipe response envelope.

use std::{sync::Arc, time::Duration};

use russh::{client, ChannelMsg};
use russh_keys::key::PublicKey;
use serde_json::{json, Value};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use supermgr_core::keyring::SecretStore;
use supermgr_core::protocol::RpcError;

use super::known_hosts::{HostKeyVerdict, KnownHostsStore};

/// Total session timeout. Long-running commands should use the streamed
/// progress channel rather than blocking the request/response pair.
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// How long we wait on the TCP `connect` itself before giving up. The
/// shorter cap stops the GUI from spinning when the host is offline.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve a host's JSON metadata to (hostname, port, username, auth).
fn read_host_meta(root: &std::path::Path, host_id: &str) -> Result<Value, RpcError> {
    let path = root.join("hosts").join(format!("{host_id}.json"));
    let bytes = std::fs::read(&path)
        .map_err(|_| RpcError::NotFound(format!("host {host_id}")))?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| RpcError::Other(format!("parse host json: {e}")))
}

/// Execute `command` on the SSH host identified by `host_id` and return a
/// JSON blob containing `stdout`, `stderr`, and `exit_code`.
///
/// Host-key verification consults the `known_hosts` store: first sight
/// records the fingerprint silently, subsequent connections require an
/// exact match. A mismatch surfaces as [`RpcError::PermissionDenied`] —
/// the caller (GUI or MCP tool) is expected to display a clear warning
/// rather than silently retry.
pub async fn execute(
    root: &std::path::Path,
    secret_store: Arc<dyn SecretStore>,
    known_hosts: KnownHostsStore,
    host_id: &str,
    command: &str,
) -> Result<Value, RpcError> {
    let meta = read_host_meta(root, host_id)?;
    let hostname = meta
        .get("hostname")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("host missing 'hostname' field".into()))?;
    let port = meta
        .get("port")
        .and_then(Value::as_u64)
        .unwrap_or(22) as u16;
    let username = meta
        .get("username")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("host missing 'username' field".into()))?;
    let auth_method = meta
        .get("auth_method")
        .and_then(Value::as_str)
        .unwrap_or("password");
    let auth_key_id = meta.get("auth_key_id").and_then(Value::as_str);

    debug!(host_id, hostname, port, username, auth_method, "ssh_exec start");

    // Resolve credentials from Credential Manager up front so the connect
    // path can stay linear.
    let auth: AuthMethod = match auth_method {
        "password" => {
            let secret = secret_store
                .retrieve(&format!("supermgr/host/{host_id}/password"))
                .await
                .map_err(|e| RpcError::Secret(format!("password for host {host_id}: {e}")))?;
            AuthMethod::Password(
                std::str::from_utf8(&secret)
                    .map_err(|_| RpcError::Other("stored password is not valid UTF-8".into()))?
                    .to_owned(),
            )
        }
        "key" => {
            let key_id = auth_key_id.ok_or_else(|| {
                RpcError::Other("host uses key auth but no auth_key_id is set".into())
            })?;
            let secret = secret_store
                .retrieve(&format!("supermgr/ssh/{key_id}/privkey"))
                .await
                .map_err(|e| RpcError::Secret(format!("private key {key_id}: {e}")))?;
            let pem = std::str::from_utf8(&secret)
                .map_err(|_| RpcError::Other("stored SSH key is not valid UTF-8".into()))?
                .to_owned();
            AuthMethod::Key(pem)
        }
        other => {
            return Err(RpcError::Other(format!(
                "auth_method {other:?} not supported by ssh_execute_command (use password or key)"
            )));
        }
    };

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(SESSION_TIMEOUT),
        ..<_>::default()
    });

    let addr = format!("{hostname}:{port}");

    // Hand the handler a clone of the known-hosts store so the host-key
    // check can record / verify fingerprints synchronously while russh
    // is mid-handshake.
    let handler = KnownHostsHandler::new(
        known_hosts.clone(),
        hostname.to_owned(),
        port,
    );
    let mut session = timeout(
        CONNECT_TIMEOUT,
        client::connect(config, addr.clone(), handler),
    )
    .await
    .map_err(|_| RpcError::Backend(format!("connect timeout after {CONNECT_TIMEOUT:?} to {addr}")))?
    .map_err(|e| {
        // Surface our own typed error when russh closed the connection
        // because we rejected the host key.
        let s = e.to_string();
        if s.contains("supermgr-host-key-mismatch") {
            RpcError::PermissionDenied(s)
        } else {
            RpcError::Backend(format!("ssh connect to {addr}: {e}"))
        }
    })?;

    match auth {
        AuthMethod::Password(pw) => {
            let ok = session
                .authenticate_password(username, pw)
                .await
                .map_err(|e| RpcError::Backend(format!("ssh password auth: {e}")))?;
            if !ok {
                return Err(RpcError::PermissionDenied(
                    "password authentication rejected".into(),
                ));
            }
        }
        AuthMethod::Key(pem) => {
            let keypair = russh_keys::decode_secret_key(&pem, None).map_err(|e| {
                RpcError::Other(format!("decode stored SSH key: {e}"))
            })?;
            let ok = session
                .authenticate_publickey(username, Arc::new(keypair))
                .await
                .map_err(|e| RpcError::Backend(format!("ssh pubkey auth: {e}")))?;
            if !ok {
                return Err(RpcError::PermissionDenied(
                    "public-key authentication rejected".into(),
                ));
            }
        }
    }

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| RpcError::Backend(format!("open ssh session channel: {e}")))?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| RpcError::Backend(format!("ssh exec: {e}")))?;

    let (stdout, stderr, exit_code) = collect_output(&mut channel)
        .await
        .map_err(|e| RpcError::Backend(format!("ssh output: {e}")))?;

    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;

    Ok(json!({
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
    }))
}

enum AuthMethod {
    Password(String),
    Key(String),
}

/// Drain the channel until the peer sends Eof + ExitStatus.
async fn collect_output(
    channel: &mut russh::Channel<client::Msg>,
) -> Result<(String, String, i32), russh::Error> {
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut exit = -1;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
            ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                // ext == 1 is the SSH constant for stderr.
                stderr.extend_from_slice(data);
            }
            ChannelMsg::ExtendedData { .. } => {}
            ChannelMsg::ExitStatus { exit_status } => {
                exit = exit_status as i32;
            }
            ChannelMsg::Eof => break,
            _ => {}
        }
    }
    Ok((
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
        exit,
    ))
}

/// russh client handler that consults the persistent `known_hosts`
/// store rather than auto-accepting every key.
struct KnownHostsHandler {
    store: KnownHostsStore,
    host: String,
    port: u16,
}

impl KnownHostsHandler {
    fn new(store: KnownHostsStore, host: String, port: u16) -> Self {
        Self { store, host, port }
    }
}

#[async_trait::async_trait]
impl client::Handler for KnownHostsHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let algo = server_public_key.name();
        let fingerprint = server_public_key.fingerprint();
        match self.store.check(&self.host, self.port, algo, &fingerprint).await {
            Ok(HostKeyVerdict::FirstSeen(_)) => {
                info!(host = %self.host, %algo, "recorded new SSH host key");
                Ok(true)
            }
            Ok(HostKeyVerdict::Match(_)) => Ok(true),
            Ok(HostKeyVerdict::Changed { stored, presented }) => {
                warn!(
                    host = %self.host,
                    stored = %stored.fingerprint,
                    presented = %presented.fingerprint,
                    "supermgr-host-key-mismatch: refusing connection"
                );
                Err(russh::Error::Disconnect)
            }
            Err(e) => {
                warn!("known_hosts I/O failed; refusing to connect: {e}");
                Err(russh::Error::Disconnect)
            }
        }
    }
}
