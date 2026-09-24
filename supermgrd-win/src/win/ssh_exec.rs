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
//! Nothing is persisted here except what the known-hosts store records.
//! Failures bubble up as [`RpcError`]s, and the caller (the dispatcher)
//! wraps the JSON in the pipe response envelope. A host whose key has
//! changed is the one failure kept apart ([`OpenError::HostKeyChanged`]):
//! the operator has to act on it, and needs both keys to decide how.

use std::{sync::Arc, time::Duration};

use russh::{client, ChannelMsg};
use russh_keys::key::PublicKey;
use serde_json::{json, Value};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use supermgr_core::keyring::SecretStore;
use supermgr_core::protocol::RpcError;

use super::known_hosts::{HostKeyVerdict, Known, KnownHostsStore};

/// Total session timeout. Long-running commands should use the streamed
/// progress channel rather than blocking the request/response pair.
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// How long we wait on the TCP `connect` itself before giving up. The
/// shorter cap stops the GUI from spinning when the host is offline.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve a host's JSON metadata to (hostname, port, username, auth).
fn read_host_meta(root: &std::path::Path, host_id: &str) -> Result<Value, RpcError> {
    let path = root.join("hosts").join(format!("{host_id}.json"));
    let bytes = std::fs::read(&path).map_err(|_| RpcError::NotFound(format!("host {host_id}")))?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| RpcError::Other(format!("parse host json: {e}")))
}

/// Execute `command` on the SSH host identified by `host_id` and return a
/// JSON blob containing `stdout`, `stderr`, and `exit_code`.
///
/// Host-key verification consults the `known_hosts` store: first sight
/// records the fingerprint silently, subsequent connections require an
/// exact match. A mismatch surfaces as [`RpcError::PermissionDenied`]
/// carrying both fingerprints and what to do about them — the caller (GUI
/// or MCP tool) shows it rather than retrying.
pub async fn execute(
    root: &std::path::Path,
    secret_store: Arc<dyn SecretStore>,
    known_hosts: KnownHostsStore,
    host_id: &str,
    command: &str,
) -> Result<Value, RpcError> {
    let session = open_session(root, secret_store, known_hosts, host_id).await?;

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

/// Whether the host answers and accepts its stored credentials, in the
/// Linux daemon's shape: `{"ssh": "ok" | "auth_failed" |
/// "connection_refused" | "timeout" | "error: …"}`.
///
/// A host whose key has changed reports `"host_key_changed"` with both
/// fingerprints — `stored`, and `presented` — so the operator can compare
/// them with the host's own before trusting the new one.
///
/// Signs in and out without running anything, so it is safe on appliances
/// whose shells have no `true` to run.
pub async fn test(
    root: &std::path::Path,
    secret_store: Arc<dyn SecretStore>,
    known_hosts: KnownHostsStore,
    host_id: &str,
) -> Value {
    match timeout(
        CONNECT_TIMEOUT * 2,
        open_session(root, secret_store, known_hosts, host_id),
    )
    .await
    {
        Err(_) => json!({ "ssh": "timeout" }),
        Ok(Ok(session)) => {
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
            json!({ "ssh": "ok" })
        }
        Ok(Err(OpenError::HostKeyChanged(change))) => change.to_json(),
        Ok(Err(OpenError::Rpc(RpcError::PermissionDenied(_)))) => json!({ "ssh": "auth_failed" }),
        Ok(Err(OpenError::Rpc(e))) => json!({ "ssh": classify_failure(&e.to_string()) }),
    }
}

/// Name the common ways a connection fails, as the Linux daemon does.
fn classify_failure(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if lower.contains("refused") {
        "connection_refused".to_owned()
    } else if lower.contains("timeout") || lower.contains("timed out") {
        "timeout".to_owned()
    } else {
        format!("error: {message}")
    }
}

/// Connect to the host and sign in with the credentials stored for it.
async fn open_session(
    root: &std::path::Path,
    secret_store: Arc<dyn SecretStore>,
    known_hosts: KnownHostsStore,
    host_id: &str,
) -> Result<client::Handle<KnownHostsHandler>, OpenError> {
    let meta = read_host_meta(root, host_id)?;
    let hostname = meta
        .get("hostname")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("host missing 'hostname' field".into()))?;
    let port = supermgr_core::port::field_or(&meta, "port", 22)
        .map_err(|e| RpcError::Other(format!("host {e}")))?;
    let username = meta
        .get("username")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Other("host missing 'username' field".into()))?;
    let auth_method = meta
        .get("auth_method")
        .and_then(Value::as_str)
        .unwrap_or("password");
    let auth_key_id = meta.get("auth_key_id").and_then(Value::as_str);

    debug!(
        host_id,
        hostname, port, username, auth_method, "ssh_exec start"
    );

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
                "this host signs in with {other:?}, which SSH cannot use — set a password or an SSH key for it"
            ))
            .into());
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
    let handler = KnownHostsHandler::new(known_hosts.clone(), hostname.to_owned(), port);
    let connect = timeout(
        CONNECT_TIMEOUT,
        client::connect(config, addr.clone(), handler),
    );
    let mut session = match connect.await {
        Ok(Ok(session)) => session,
        Err(_) => {
            return Err(RpcError::Backend(format!(
                "connect timeout after {CONNECT_TIMEOUT:?} to {addr}"
            ))
            .into())
        }
        Ok(Err(HandshakeError::HostKeyChanged { stored, presented })) => {
            return Err(OpenError::HostKeyChanged(KeyChange {
                address: addr,
                stored,
                presented,
            }))
        }
        Ok(Err(HandshakeError::TrustStore(e))) => {
            return Err(RpcError::Backend(format!(
                "the known-hosts file could not be read or written, so the key {addr} \
                 presented could not be checked: {e}"
            ))
            .into())
        }
        Ok(Err(HandshakeError::Ssh(e))) => {
            return Err(RpcError::Backend(format!("ssh connect to {addr}: {e}")).into())
        }
    };

    match auth {
        AuthMethod::Password(pw) => {
            let ok = session
                .authenticate_password(username, pw)
                .await
                .map_err(|e| RpcError::Backend(format!("ssh password auth: {e}")))?;
            if !ok {
                return Err(
                    RpcError::PermissionDenied("password authentication rejected".into()).into(),
                );
            }
        }
        AuthMethod::Key(pem) => {
            let keypair = russh_keys::decode_secret_key(&pem, None)
                .map_err(|e| RpcError::Other(format!("decode stored SSH key: {e}")))?;
            let ok = session
                .authenticate_publickey(username, Arc::new(keypair))
                .await
                .map_err(|e| RpcError::Backend(format!("ssh pubkey auth: {e}")))?;
            if !ok {
                return Err(RpcError::PermissionDenied(
                    "public-key authentication rejected".into(),
                )
                .into());
            }
        }
    }
    Ok(session)
}

enum AuthMethod {
    Password(String),
    Key(String),
}

/// Why a session could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// The host presented a different key from the one on file. Nothing
    /// was sent to it: the handshake stopped before any credential left
    /// this machine.
    HostKeyChanged(KeyChange),
    /// Every other failure, as the dispatcher reports it.
    Rpc(RpcError),
}

impl From<RpcError> for OpenError {
    fn from(e: RpcError) -> Self {
        Self::Rpc(e)
    }
}

impl From<OpenError> for RpcError {
    fn from(e: OpenError) -> Self {
        match e {
            OpenError::HostKeyChanged(change) => RpcError::PermissionDenied(change.message()),
            OpenError::Rpc(e) => e,
        }
    }
}

/// A host whose key is not the one recorded for it.
#[derive(Debug)]
pub struct KeyChange {
    /// `host:port`, as the key was recorded.
    pub address: String,
    /// The key on file, and since when.
    pub stored: Known,
    /// The key the host presented this time.
    pub presented: Known,
}

impl KeyChange {
    /// What a caller that cannot show both keys side by side tells the
    /// operator: what happened, what it can mean, and what to do.
    fn message(&self) -> String {
        let since = chrono::DateTime::parse_from_rfc3339(&self.stored.first_seen).map_or_else(
            |_| self.stored.first_seen.clone(),
            |t| t.format("%Y-%m-%d").to_string(),
        );
        format!(
            "the SSH host key of {address} has changed, so SuperManager did not connect. \
             Recorded since {since}: {stored_algorithm} SHA256:{stored}. \
             Presented now: {presented_algorithm} SHA256:{presented}. \
             Reinstalling a server or replacing an appliance changes its key; if neither \
             explains it, someone may be intercepting the connection. Compare the new key \
             with the one the host itself reports (ssh-keygen -lf on its host key), then \
             trust it on the host's page: Test connection, then Trust the new key.",
            address = self.address,
            stored_algorithm = self.stored.algorithm,
            stored = self.stored.fingerprint,
            presented_algorithm = self.presented.algorithm,
            presented = self.presented.fingerprint,
        )
    }

    /// The `test_host_connection` result for a changed key.
    fn to_json(&self) -> Value {
        json!({
            "ssh": "host_key_changed",
            "stored": self.stored.fingerprint,
            "stored_algorithm": self.stored.algorithm,
            "stored_since": self.stored.first_seen,
            "presented": self.presented.fingerprint,
            "presented_algorithm": self.presented.algorithm,
        })
    }
}

/// Drain the channel until the peer sends Eof + `ExitStatus`.
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

/// Why the handshake stopped.
///
/// russh hands the handler's own error back out of `client::connect`, so a
/// refused key arrives there with the keys still attached. A bare
/// `russh::Error::Disconnect` would say only that the connection closed.
#[derive(Debug)]
enum HandshakeError {
    /// The host presented a different key from the one on file.
    HostKeyChanged { stored: Known, presented: Known },
    /// The known-hosts file could not be read or written, so no key could
    /// be checked, and none is trusted.
    TrustStore(std::io::Error),
    /// Everything russh itself reports.
    Ssh(russh::Error),
}

impl From<russh::Error> for HandshakeError {
    fn from(e: russh::Error) -> Self {
        Self::Ssh(e)
    }
}

#[async_trait::async_trait]
impl client::Handler for KnownHostsHandler {
    type Error = HandshakeError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let algo = server_public_key.name();
        let fingerprint = server_public_key.fingerprint();
        match self
            .store
            .check(&self.host, self.port, algo, &fingerprint)
            .await
        {
            Ok(HostKeyVerdict::FirstSeen(_)) => {
                info!(host = %self.host, %algo, "recorded new SSH host key");
                Ok(true)
            }
            Ok(HostKeyVerdict::Match(_)) => Ok(true),
            Ok(HostKeyVerdict::Changed { stored, presented }) => {
                warn!(
                    host = %self.host,
                    port = self.port,
                    stored = %stored.fingerprint,
                    presented = %presented.fingerprint,
                    "SSH host key changed: refusing connection"
                );
                Err(HandshakeError::HostKeyChanged { stored, presented })
            }
            Err(e) => {
                warn!("known_hosts I/O failed; refusing to connect: {e}");
                Err(HandshakeError::TrustStore(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use russh::server;
    use russh_keys::key::KeyPair;
    use supermgr_core::{keyring::ZeroizingSecret, SecretError};

    use super::*;

    #[test]
    fn failures_are_named_as_the_linux_daemon_names_them() {
        assert_eq!(
            classify_failure("ssh connect to h:22: Connection refused (os error 10061)"),
            "connection_refused"
        );
        assert_eq!(
            classify_failure("connect timeout after 10s to h:22"),
            "timeout"
        );
        assert_eq!(classify_failure("no route"), "error: no route");
    }

    /// Every host's password is the same one.
    struct OnePassword;

    #[async_trait::async_trait]
    impl SecretStore for OnePassword {
        async fn store(&self, _: &str, _: &[u8]) -> Result<(), SecretError> {
            Ok(())
        }
        async fn retrieve(&self, _: &str) -> Result<ZeroizingSecret, SecretError> {
            Ok(ZeroizingSecret::from_vec(b"hunter2".to_vec()))
        }
        async fn delete(&self, _: &str) -> Result<(), SecretError> {
            Ok(())
        }
    }

    /// A server that lets anyone in with a password.
    struct AnyPassword;

    #[async_trait::async_trait]
    impl server::Handler for AnyPassword {
        type Error = russh::Error;

        async fn auth_password(&mut self, _: &str, _: &str) -> Result<server::Auth, Self::Error> {
            Ok(server::Auth::Accept)
        }
    }

    /// An SSH server on a loopback port whose host key can be swapped,
    /// the way a reinstalled machine's would be.
    struct Server {
        port: u16,
        keys: Vec<KeyPair>,
        current: Arc<AtomicUsize>,
    }

    impl Server {
        async fn start() -> Self {
            let keys = vec![KeyPair::generate_ed25519(), KeyPair::generate_ed25519()];
            let configs: Vec<Arc<server::Config>> = keys
                .iter()
                .map(|key| {
                    Arc::new(server::Config {
                        keys: vec![key.clone()],
                        auth_rejection_time: Duration::from_millis(1),
                        ..Default::default()
                    })
                })
                .collect();
            let current = Arc::new(AtomicUsize::new(0));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let serving = current.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let config = configs[serving.load(Ordering::SeqCst)].clone();
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, stream, AnyPassword).await {
                            let _ = session.await;
                        }
                    });
                }
            });
            Self {
                port,
                keys,
                current,
            }
        }

        fn fingerprint(&self, which: usize) -> String {
            self.keys[which].clone_public_key().unwrap().fingerprint()
        }

        fn present(&self, which: usize) {
            self.current.store(which, Ordering::SeqCst);
        }

        /// A data folder with this server saved as host `h1`.
        fn data_root(&self) -> tempfile::TempDir {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("hosts")).unwrap();
            std::fs::write(
                root.path().join("hosts").join("h1.json"),
                json!({
                    "hostname": "127.0.0.1",
                    "port": self.port,
                    "username": "admin",
                    "auth_method": "password",
                })
                .to_string(),
            )
            .unwrap();
            root
        }
    }

    #[tokio::test]
    async fn a_changed_host_key_is_reported_with_both_keys_and_can_be_trusted() {
        let server = Server::start().await;
        let root = server.data_root();
        let known_hosts = KnownHostsStore::load_from(root.path()).unwrap();
        let test = || {
            test(
                root.path(),
                Arc::new(OnePassword),
                known_hosts.clone(),
                "h1",
            )
        };

        // First sight: recorded and trusted.
        assert_eq!(test().await, json!({ "ssh": "ok" }));

        // The machine is reinstalled.
        server.present(1);
        let report = test().await;
        assert_eq!(report["ssh"], "host_key_changed", "{report}");
        assert_eq!(report["stored"], server.fingerprint(0).as_str());
        assert_eq!(report["presented"], server.fingerprint(1).as_str());
        assert_eq!(report["presented_algorithm"], "ssh-ed25519");

        // Running a command says the same, in words.
        let err = execute(
            root.path(),
            Arc::new(OnePassword),
            known_hosts.clone(),
            "h1",
            "uptime",
        )
        .await
        .unwrap_err();
        let RpcError::PermissionDenied(message) = err else {
            panic!("expected PermissionDenied, got {err:?}");
        };
        assert!(message.contains("has changed"), "{message}");
        assert!(message.contains(&server.fingerprint(0)), "{message}");
        assert!(message.contains(&server.fingerprint(1)), "{message}");

        // The new key stays refused until the operator trusts it…
        assert_eq!(test().await["ssh"], "host_key_changed");

        // …and once they trust the key they checked, that key gets in…
        known_hosts
            .trust(
                "127.0.0.1",
                server.port,
                "ssh-ed25519",
                &server.fingerprint(1),
            )
            .await
            .unwrap();
        assert_eq!(test().await, json!({ "ssh": "ok" }));

        // …and no other: the old key is now the stranger.
        server.present(0);
        assert_eq!(test().await["ssh"], "host_key_changed");

        // Forgetting instead trusts whichever key answers next.
        assert!(known_hosts.forget("127.0.0.1", server.port).await.unwrap());
        assert_eq!(test().await, json!({ "ssh": "ok" }));
        let recorded = known_hosts.entries().await;
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].1.fingerprint, server.fingerprint(0));
    }
}
