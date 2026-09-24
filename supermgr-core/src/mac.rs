//! Client for the macOS engine's length-prefixed JSON-RPC 2.0 socket.
//!
//! The typed methods adapt the shared daemon API to the engine's method names.
//! Operations owned by the privileged helper are explicitly unsupported here.
//! Available on Unix so integration tests can exercise the real client and
//! engine together on Linux as well as macOS.
//!
//! Clones serialize exchanges on one connection. A cancelled, timed-out or
//! malformed exchange invalidates that connection; reopen it before retrying.
//! A lost response does not establish whether a mutating operation completed.

use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    sync::Mutex,
    time::{timeout, Duration},
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
// Same request limit as EngineServer::handle_connection. Apply it to incoming
// frames too, before allocating memory for a response.
const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

/// Failures reported by the macOS engine client.
#[derive(Debug, thiserror::Error)]
pub enum MacError {
    /// The engine's Unix socket could not be opened.
    #[error("failed to connect to the macOS engine socket: {0}")]
    Connect(#[source] std::io::Error),
    /// An established connection failed during an exchange.
    #[error("engine socket I/O error: {0}")]
    Io(#[source] std::io::Error),
    /// The peer closed, or an earlier interrupted request invalidated the socket.
    #[error("engine connection closed; reopen before sending another request")]
    Disconnected,
    /// No complete response arrived before the deadline.
    #[error("engine did not respond within {0:?}; operation outcome may be unknown")]
    Timeout(Duration),
    /// A malformed frame, JSON-RPC version or response ID.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A JSON-RPC application error returned by the engine.
    #[error("engine error {code}: {message}")]
    Rpc {
        /// JSON-RPC error code.
        code: i32,
        /// Engine-provided explanation.
        message: String,
        /// Optional structured error category and context.
        data: Option<Value>,
    },
    /// The engine does not implement this shared daemon operation.
    #[error("not supported by the macOS engine: {0}")]
    Unsupported(&'static str),
}

#[derive(Serialize)]
struct Request<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Deserialize)]
struct Response {
    jsonrpc: String,
    id: u64,
    result: Option<Value>,
    error: Option<RemoteError>,
}

#[derive(Deserialize)]
struct RemoteError {
    code: i32,
    message: String,
    data: Option<Value>,
}

/// Async client for the macOS engine's Unix socket.
#[derive(Clone)]
pub struct MacClient {
    inner: Arc<Inner>,
}

struct Inner {
    // Take the stream while exchanging, and return it only after a complete,
    // validated response. Cancellation drops it instead of leaving half a frame
    // for the next caller to interpret.
    io: Mutex<Option<UnixStream>>,
    next_id: AtomicU64,
}

impl MacClient {
    /// Connect to the socket used by the installed macOS engine.
    pub async fn open() -> Result<Self, MacError> {
        Self::open_path(crate::paths::default_data_dir().join("supermgrd.sock")).await
    }

    /// Connect to an explicit engine socket, including isolated test instances.
    pub async fn open_path(path: impl AsRef<Path>) -> Result<Self, MacError> {
        let stream = UnixStream::connect(path).await.map_err(MacError::Connect)?;
        Ok(Self {
            inner: Arc::new(Inner {
                io: Mutex::new(Some(stream)),
                next_id: AtomicU64::new(1),
            }),
        })
    }

    /// Invoke an engine method using its JSON-RPC name and named parameters.
    pub async fn invoke(&self, method: &str, params: Value) -> Result<Value, MacError> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let request = Request {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let frame = serde_json::to_vec(&request)
            .map_err(|e| MacError::Protocol(format!("request serialise: {e}")))?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err(MacError::Protocol(format!(
                "request exceeds {MAX_FRAME_BYTES} bytes"
            )));
        }
        let response = timeout(DEFAULT_TIMEOUT, self.exchange(&frame, id))
            .await
            .map_err(|_| MacError::Timeout(DEFAULT_TIMEOUT))??;
        if let Some(error) = response.error {
            return Err(MacError::Rpc {
                code: error.code,
                message: error.message,
                data: error.data,
            });
        }
        Ok(response.result.unwrap_or(Value::Null))
    }

    /// Return a string result verbatim, or serialize a structured JSON result.
    pub async fn invoke_json_string(
        &self,
        method: &str,
        params: Value,
    ) -> Result<String, MacError> {
        let value = self.invoke(method, params).await?;
        match value {
            Value::String(text) => Ok(text),
            other => serde_json::to_string(&other)
                .map_err(|e| MacError::Protocol(format!("response serialise: {e}"))),
        }
    }

    /// Invoke an engine method whose successful response needs no result data.
    pub async fn invoke_unit(&self, method: &str, params: Value) -> Result<(), MacError> {
        self.invoke(method, params).await?;
        Ok(())
    }

    async fn exchange(&self, frame: &[u8], want_id: u64) -> Result<Response, MacError> {
        // Before the stream is taken: `invoke` keeps requests far below
        // this, and a request refused here leaves the connection usable.
        let length = u32::try_from(frame.len())
            .map_err(|_| MacError::Protocol(format!("request exceeds {MAX_FRAME_BYTES} bytes")))?;
        let mut guard = self.inner.io.lock().await;
        let mut stream = guard.take().ok_or(MacError::Disconnected)?;
        stream
            .write_all(&length.to_be_bytes())
            .await
            .map_err(MacError::Io)?;
        stream.write_all(frame).await.map_err(MacError::Io)?;
        let mut length = [0; 4];
        stream.read_exact(&mut length).await.map_err(read_error)?;
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_FRAME_BYTES {
            return Err(MacError::Protocol(format!(
                "response exceeds {MAX_FRAME_BYTES} bytes"
            )));
        }
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.map_err(read_error)?;
        let value: Value = serde_json::from_slice(&body)
            .map_err(|e| MacError::Protocol(format!("response parse: {e}")))?;
        if value.get("result").is_some() == value.get("error").is_some()
            || value.get("error").is_some_and(Value::is_null)
        {
            return Err(MacError::Protocol(
                "response must contain one result or error".into(),
            ));
        }
        let response: Response = serde_json::from_value(value)
            .map_err(|e| MacError::Protocol(format!("response parse: {e}")))?;
        if response.jsonrpc != "2.0" || response.id != want_id {
            return Err(MacError::Protocol(
                "unexpected JSON-RPC version or response ID".into(),
            ));
        }
        *guard = Some(stream);
        Ok(response)
    }
}

fn read_error(error: std::io::Error) -> MacError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        MacError::Disconnected
    } else {
        MacError::Io(error)
    }
}

// ---------------------------------------------------------------------------
// Typed method surface — mirrors `DaemonProxy` on Linux.
//
// Adapt method names, parameter keys and return values to the engine contract.
// The shared surface also includes operations the macOS engine cannot perform;
// those return Unsupported without sending a request.
// ---------------------------------------------------------------------------

// Callers reach this client through `client::DaemonClient`, which is the
// D-Bus proxy on Linux and the pipe client on Windows, and await every
// method alike. The methods the engine cannot serve here answer at once,
// but keep the shared signature.
#[expect(
    clippy::unused_async,
    reason = "one signature for the client on every platform"
)]
impl MacClient {
    // ----- VPN profile lifecycle -----

    /// List all VPN profiles as a JSON array.
    pub async fn list_profiles(&self) -> Result<String, MacError> {
        self.invoke_json_string("list_profiles", serde_json::json!({}))
            .await
    }

    /// Connect to the named profile.
    /// Requires the macOS app/helper; this engine client returns Unsupported.
    pub async fn connect(&self, _profile_id: &str) -> Result<(), MacError> {
        Err(MacError::Unsupported(
            "VPN connection is managed by the SuperManager app and privileged helper",
        ))
    }

    /// Disconnect the active profile.
    /// Requires the macOS app/helper; this engine client returns Unsupported.
    pub async fn disconnect(&self) -> Result<(), MacError> {
        Err(MacError::Unsupported(
            "VPN disconnection is managed by the SuperManager app and privileged helper",
        ))
    }

    /// Current VPN status JSON.
    /// Requires the macOS app/helper; this engine client returns Unsupported.
    pub async fn get_status(&self) -> Result<String, MacError> {
        Err(MacError::Unsupported(
            "live VPN status is managed by the SuperManager app and privileged helper",
        ))
    }

    /// Delete a profile by id.
    pub async fn delete_profile(&self, profile_id: &str) -> Result<(), MacError> {
        self.invoke_unit(
            "vpn_delete_profile",
            serde_json::json!({ "id": profile_id }),
        )
        .await
    }

    /// Import a WireGuard `wg-quick` config. Returns the new profile id.
    pub async fn import_wireguard(&self, conf_text: &str, name: &str) -> Result<String, MacError> {
        let profile = self
            .invoke(
                "vpn_import_wireguard",
                serde_json::json!({ "content": conf_text, "name": name }),
            )
            .await?;
        profile
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| MacError::Protocol("import response has no profile ID".into()))
    }

    /// IKEv2 credential import requires the macOS app's Keychain workflow.
    /// Returns an explicit unsupported error; no profile or secret is created.
    pub async fn import_fortigate(
        &self,
        _name: &str,
        _host: &str,
        _username: &str,
        _password: &str,
        _psk: &str,
    ) -> Result<String, MacError> {
        Err(MacError::Unsupported(
            "IKEv2 credentials must be imported through the SuperManager app",
        ))
    }

    /// FortiGate SSL VPN import is not implemented by the macOS engine.
    #[allow(clippy::too_many_arguments)]
    pub async fn import_forticlient_sslvpn(
        &self,
        _name: &str,
        _host: &str,
        _port: u16,
        _username: &str,
        _password: &str,
        _trusted_cert: Option<&str>,
        _dns_servers_json: &str,
        _routes_json: &str,
    ) -> Result<String, MacError> {
        Err(MacError::Unsupported("FortiGate SSL VPN import"))
    }

    // ----- SSH keys -----

    /// Generate a new SSH key. Returns its assigned ID.
    pub async fn ssh_generate_key(
        &self,
        key_type: &str,
        name: &str,
        description: &str,
        tags_json: &str,
    ) -> Result<String, MacError> {
        self.invoke_json_string(
            "ssh_generate_key",
            serde_json::json!({
                "key_type": key_type,
                "name": name,
                "description": description,
                "tags_json": tags_json,
            }),
        )
        .await
    }

    /// List all managed SSH keys as a JSON array.
    pub async fn ssh_list_keys(&self) -> Result<String, MacError> {
        self.invoke_json_string("ssh_list_keys", serde_json::json!({}))
            .await
    }

    /// Delete an SSH key by id.
    pub async fn ssh_delete_key(&self, key_id: &str) -> Result<(), MacError> {
        self.invoke_unit("ssh_delete_key", serde_json::json!({ "key_id": key_id }))
            .await
    }

    /// Export the public half of a key in OpenSSH `authorized_keys` format.
    pub async fn ssh_export_public_key(&self, key_id: &str) -> Result<String, MacError> {
        self.invoke_json_string(
            "ssh_export_public_key",
            serde_json::json!({ "key_id": key_id }),
        )
        .await
    }

    // ----- Hosts -----

    /// List all managed hosts as a JSON array.
    pub async fn list_hosts(&self) -> Result<String, MacError> {
        self.invoke_json_string("ssh_list_hosts", serde_json::json!({}))
            .await
    }

    /// Get a single host's JSON.
    pub async fn get_host(&self, host_id: &str) -> Result<String, MacError> {
        self.invoke_json_string("ssh_get_host", serde_json::json!({ "host_id": host_id }))
            .await
    }

    /// Add a new host from its JSON serialisation. Returns the assigned id.
    pub async fn add_host(&self, host_json: &str) -> Result<String, MacError> {
        self.invoke_json_string(
            "ssh_add_host",
            serde_json::json!({ "host_json": host_json }),
        )
        .await
    }

    /// Delete a host by id.
    pub async fn delete_host(&self, host_id: &str) -> Result<(), MacError> {
        self.invoke_unit("ssh_delete_host", serde_json::json!({ "host_id": host_id }))
            .await
    }

    /// Execute a shell command on a remote host via SSH. Returns JSON
    /// containing `stdout`, `stderr`, and `exit_code`.
    pub async fn ssh_execute_command(
        &self,
        host_id: &str,
        command: &str,
    ) -> Result<String, MacError> {
        self.invoke_json_string(
            "ssh_execute_command",
            serde_json::json!({ "host_id": host_id, "command": command }),
        )
        .await
    }

    /// Probe a host's reachability and credentials. Returns a JSON report.
    pub async fn test_host_connection(&self, host_id: &str) -> Result<String, MacError> {
        self.invoke_json_string(
            "ssh_test_connection",
            serde_json::json!({ "host_id": host_id }),
        )
        .await
    }

    /// Toggle the favourite/pin flag for a host. Returns the new state.
    pub async fn toggle_host_pin(&self, host_id: &str) -> Result<String, MacError> {
        let hosts = self
            .invoke("ssh_toggle_pin", serde_json::json!({ "host_id": host_id }))
            .await?;
        let host_uuid = uuid::Uuid::parse_str(host_id)
            .map_err(|_| MacError::Protocol("invalid host UUID".into()))?;
        let host = hosts
            .as_array()
            .and_then(|hosts| {
                hosts.iter().find(|host| {
                    host.get("id")
                        .and_then(Value::as_str)
                        .and_then(|id| uuid::Uuid::parse_str(id).ok())
                        == Some(host_uuid)
                })
            })
            .ok_or_else(|| {
                MacError::Protocol("toggle response does not contain the host".into())
            })?;
        let pinned = host
            .get("pinned")
            .and_then(Value::as_bool)
            .ok_or_else(|| MacError::Protocol("toggle response has no pinned state".into()))?;
        Ok(serde_json::json!({ "host_id": host_id, "pinned": pinned }).to_string())
    }

    /// Store a host's SSH password in the credential store.
    pub async fn ssh_set_password(&self, host_id: &str, password: &str) -> Result<(), MacError> {
        self.invoke_unit(
            "ssh_set_password",
            serde_json::json!({ "host_id": host_id, "password": password }),
        )
        .await
    }

    /// Store an API token for a host (FortiGate, UniFi, OPNsense, etc.),
    /// and the port its API listens on; 0 keeps the port the host has.
    pub async fn ssh_set_api_token(
        &self,
        host_id: &str,
        token: &str,
        port: u16,
    ) -> Result<(), MacError> {
        self.invoke_unit(
            "ssh_set_api_token",
            serde_json::json!({ "host_id": host_id, "token": token, "api_port": port }),
        )
        .await
    }

    /// Set the inform URL on a UniFi-managed device.
    pub async fn unifi_set_inform(
        &self,
        host_id: &str,
        inform_url: &str,
    ) -> Result<String, MacError> {
        self.invoke_json_string(
            "unifi_set_inform",
            serde_json::json!({ "host_id": host_id, "inform_url": inform_url }),
        )
        .await
    }

    /// Proxy an arbitrary UniFi controller API call through the daemon.
    pub async fn unifi_api(
        &self,
        host_id: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<String, MacError> {
        self.invoke_json_string(
            "unifi_api",
            serde_json::json!({
                "host_id": host_id,
                "method": method,
                "path": path,
                "body": body,
            }),
        )
        .await
    }

    /// Proxy an arbitrary FortiGate REST API call through the daemon.
    pub async fn fortigate_api(
        &self,
        host_id: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<String, MacError> {
        self.invoke_json_string(
            "fortigate_api",
            serde_json::json!({
                "host_id": host_id,
                "method": method,
                "path": path,
                "body": body,
            }),
        )
        .await
    }

    /// Push an SSH key to a FortiGate's admin user.
    /// This operation is not implemented by the macOS engine.
    pub async fn fortigate_push_ssh_key(
        &self,
        _host_id: &str,
        _key_id: &str,
        _admin_user: &str,
    ) -> Result<String, MacError> {
        Err(MacError::Unsupported(
            "FortiGate administrator key deployment",
        ))
    }

    /// Snapshot a FortiGate config. Returns the filename of the stored backup.
    /// This operation is not implemented by the macOS engine.
    pub async fn fortigate_backup_config(&self, _host_id: &str) -> Result<String, MacError> {
        Err(MacError::Unsupported("FortiGate configuration backup"))
    }

    /// Proxy an OPNsense REST API call.
    /// This operation is not implemented by the macOS engine.
    pub async fn opnsense_api(
        &self,
        _host_id: &str,
        _method: &str,
        _path: &str,
        _body: &str,
    ) -> Result<String, MacError> {
        Err(MacError::Unsupported("OPNsense API proxy"))
    }

    /// Snapshot an OPNsense config. Returns the saved filename.
    /// This operation is not implemented by the macOS engine.
    pub async fn opnsense_backup_config(&self, _host_id: &str) -> Result<String, MacError> {
        Err(MacError::Unsupported("OPNsense configuration backup"))
    }

    /// Send a Sophos WebAdmin XML Configuration API operation. `inner_xml`
    /// is the body fragment between `</Login>` and `</Request>`; the
    /// daemon wraps it in the envelope and attaches credentials.
    /// This operation is not implemented by the macOS engine.
    pub async fn sophos_xml_api(
        &self,
        _host_id: &str,
        _inner_xml: &str,
    ) -> Result<String, MacError> {
        Err(MacError::Unsupported("Sophos XML API proxy"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::UnixListener;

    async fn client_with_reply(
        reply: Vec<u8>,
    ) -> (tempfile::TempDir, MacClient, tokio::task::JoinHandle<()>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut body = vec![0; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut body).await.unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(request["jsonrpc"], "2.0");
            assert_eq!(request["params"], json!({}));
            assert!(request.get("args").is_none());
            stream.write_all(&reply).await.unwrap();
        });
        let client = MacClient::open_path(path).await.unwrap();
        (dir, client, peer)
    }

    fn frame(value: Value) -> Vec<u8> {
        let body = serde_json::to_vec(&value).unwrap();
        let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        frame.extend(body);
        frame
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_before_reading_a_body() {
        let (_dir, client, peer) = client_with_reply(u32::MAX.to_be_bytes().to_vec()).await;
        assert!(matches!(
            client.invoke("api_version", json!({})).await,
            Err(MacError::Protocol(_))
        ));
        assert!(matches!(
            client.list_hosts().await,
            Err(MacError::Disconnected)
        ));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_envelopes_and_wrong_ids_invalidate_the_connection() {
        for response in [
            json!({"jsonrpc": "2.0", "id": 99, "result": null}),
            json!({"jsonrpc": "1.0", "id": 1, "result": null}),
            json!({"jsonrpc": "2.0", "id": 1}),
            json!({"jsonrpc": "2.0", "id": 1, "result": null, "error": {"code": -1, "message": "bad"}}),
            json!({"jsonrpc": "2.0", "id": 1, "error": null}),
        ] {
            let (_dir, client, peer) = client_with_reply(frame(response)).await;
            assert!(matches!(
                client.invoke("api_version", json!({})).await,
                Err(MacError::Protocol(_))
            ));
            assert!(matches!(
                client.list_hosts().await,
                Err(MacError::Disconnected)
            ));
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn cancellation_during_partial_response_does_not_reuse_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (started, response_started) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).await.unwrap();
            let mut request = vec![0; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&100u32.to_be_bytes()).await.unwrap();
            stream.write_all(b"{").await.unwrap();
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let client = MacClient::open_path(path).await.unwrap();
        let caller = client.clone();
        let request = tokio::spawn(async move { caller.invoke("api_version", json!({})).await });
        response_started.await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(matches!(
            client.list_hosts().await,
            Err(MacError::Disconnected)
        ));
        peer.abort();
    }
}
