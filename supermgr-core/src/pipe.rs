//! Windows named-pipe client for the SuperManager daemon (`supermgrd-win`).
//!
//! This is the Windows counterpart to [`crate::dbus::DaemonProxy`]: the GUI
//! and the MCP server reach the daemon through this client. The wire format
//! is the JSON-RPC envelope defined in [`crate::protocol`].
//!
//! # Concurrency
//!
//! A [`PipeClient`] owns a single duplex pipe handle and serialises all
//! requests through an internal `Mutex` on the writer half. Concurrent
//! callers see ordered request submission and correctly correlated responses
//! via the per-request id. This mirrors how `zbus::Proxy` multiplexes calls
//! over its single D-Bus connection on Linux.
//!
//! # Failure recovery
//!
//! If the daemon restarts (Windows Service restart, crash, upgrade), the
//! pipe handle becomes invalid and subsequent calls return
//! [`PipeError::Disconnected`]. The caller decides whether to reconnect
//! ([`PipeClient::connect`] is cheap) or surface the failure to the user.

#![cfg(target_os = "windows")]

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    sync::Mutex,
    time::{timeout, Duration},
};

use crate::protocol::{
    PipeRequest, PipeResponse, RpcError, MAX_FRAME_BYTES, PIPE_NAME, PROTOCOL_VERSION,
};

/// Per-call timeout. The daemon is expected to either respond or return an
/// error inside this window — long-running operations (SSH key push, FortiGate
/// import) report progress via the event stream rather than blocking the
/// request. Sized to swallow ordinary disk I/O and TLS handshakes without
/// hanging the GUI indefinitely if the daemon wedges.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Errors raised by the named-pipe client. Server-side application errors
/// surface as [`PipeError::Rpc`], wire-level problems as the variants below.
#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    /// The named pipe could not be opened (daemon not running, ACL refusal,
    /// or all pipe instances busy).
    #[error("failed to connect to supermgrd named pipe: {0}")]
    Connect(#[source] std::io::Error),
    /// I/O error on an established pipe (write/read failure).
    #[error("pipe I/O error: {0}")]
    Io(#[source] std::io::Error),
    /// The pipe peer closed the handle before completing the response.
    #[error("daemon disconnected during request")]
    Disconnected,
    /// The daemon's response did not arrive within [`DEFAULT_TIMEOUT`].
    #[error("daemon did not respond within {0:?}")]
    Timeout(Duration),
    /// The response frame was malformed or the daemon reported an unknown
    /// protocol version.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The daemon completed the dispatch but returned a typed error.
    #[error(transparent)]
    Rpc(#[from] RpcError),
}

/// Async client for the daemon's named-pipe interface.
#[derive(Clone)]
pub struct PipeClient {
    inner: Arc<Inner>,
}

struct Inner {
    /// Write half + buffered read half share the same handle; the lock keeps
    /// request frames from interleaving on the wire.
    io: Mutex<BufReader<NamedPipeClient>>,
    next_id: AtomicU64,
}

impl PipeClient {
    /// Open a connection to the daemon's well-known pipe.
    ///
    /// Returns [`PipeError::Connect`] if the daemon is not running. On a
    /// fresh install the caller should surface a "Start SuperManager
    /// service" hint pointing at `services.msc` or `sc start supermgrd`.
    ///
    /// Named `open` (not `connect`) so the verb does not collide with the
    /// VPN `connect()` method below — that lets the GUI/MCP call
    /// `client.connect(profile_id)` with identical syntax on both Linux
    /// and Windows.
    pub async fn open() -> Result<Self, PipeError> {
        // ClientOptions::open performs the actual CreateFileW. We do not
        // retry on `PIPE_BUSY` here — the daemon configures a high
        // max_instances and a busy pipe almost always means the daemon is
        // overloaded or stuck, which the caller should see as an error.
        let pipe = ClientOptions::new()
            .open(PIPE_NAME)
            .map_err(PipeError::Connect)?;
        Ok(Self {
            inner: Arc::new(Inner {
                io: Mutex::new(BufReader::new(pipe)),
                next_id: AtomicU64::new(1),
            }),
        })
    }

    /// Send a request and await a single matching response.
    ///
    /// `args` should be a JSON object whose field names match the daemon's
    /// expected positional arguments for `method`. The named-pipe dispatcher
    /// rejects unknown methods with [`RpcError::Protocol`].
    pub async fn invoke(
        &self,
        method: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, PipeError> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let req = PipeRequest {
            v: PROTOCOL_VERSION,
            id,
            method: method.to_owned(),
            args,
        };
        let mut frame = serde_json::to_vec(&req)
            .map_err(|e| PipeError::Protocol(format!("request serialise: {e}")))?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err(PipeError::Protocol(format!(
                "request frame {} bytes exceeds limit {}",
                frame.len(),
                MAX_FRAME_BYTES
            )));
        }
        frame.push(b'\n');

        let resp = timeout(DEFAULT_TIMEOUT, self.exchange(&frame, id))
            .await
            .map_err(|_| PipeError::Timeout(DEFAULT_TIMEOUT))??;
        if let Some(err) = resp.error {
            return Err(PipeError::Rpc(err));
        }
        Ok(resp.result.unwrap_or(serde_json::Value::Null))
    }

    /// Convenience wrapper for methods that the D-Bus contract returns as
    /// a JSON-encoded string (`list_hosts`, `ssh_list_keys`, etc.). Strips
    /// the outer string wrapper if the daemon returned one, otherwise
    /// re-serialises the JSON value.
    pub async fn invoke_json_string(
        &self,
        method: &str,
        args: serde_json::Value,
    ) -> Result<String, PipeError> {
        let v = self.invoke(method, args).await?;
        match v {
            serde_json::Value::String(s) => Ok(s),
            other => serde_json::to_string(&other)
                .map_err(|e| PipeError::Protocol(format!("response reserialise: {e}"))),
        }
    }

    /// Convenience wrapper for void methods that return `null` on success.
    pub async fn invoke_unit(
        &self,
        method: &str,
        args: serde_json::Value,
    ) -> Result<(), PipeError> {
        let _ = self.invoke(method, args).await?;
        Ok(())
    }

    /// Write the framed request and read response frames until one matches
    /// the request id. Out-of-order responses (which the current daemon
    /// doesn't produce, but the protocol permits) are discarded — the
    /// per-request `Mutex` lock prevents the queue from being polluted by
    /// other in-flight callers.
    async fn exchange(&self, frame: &[u8], want_id: u64) -> Result<PipeResponse, PipeError> {
        let mut guard = self.inner.io.lock().await;
        guard
            .get_mut()
            .write_all(frame)
            .await
            .map_err(PipeError::Io)?;
        guard.get_mut().flush().await.map_err(PipeError::Io)?;

        let mut line = String::new();
        loop {
            line.clear();
            let n = guard.read_line(&mut line).await.map_err(PipeError::Io)?;
            if n == 0 {
                return Err(PipeError::Disconnected);
            }
            let resp: PipeResponse = serde_json::from_str(line.trim_end())
                .map_err(|e| PipeError::Protocol(format!("response parse: {e}")))?;
            if resp.v != PROTOCOL_VERSION {
                return Err(PipeError::Protocol(format!(
                    "daemon protocol version {} != client {}",
                    resp.v, PROTOCOL_VERSION
                )));
            }
            if resp.id == want_id {
                return Ok(resp);
            }
            // Different id — stale or out-of-order; keep reading.
        }
    }
}

// ---------------------------------------------------------------------------
// Typed method surface — mirrors `DaemonProxy` on Linux.
//
// Each method serialises its positional args as a JSON object and forwards
// to `invoke`. Adding a method here means: pick the same name as the D-Bus
// method, write the args object, choose `invoke_json_string` for JSON-typed
// returns or `invoke_unit` for void.
// ---------------------------------------------------------------------------

impl PipeClient {
    // ----- VPN profile lifecycle -----

    /// List all VPN profiles as a JSON array.
    pub async fn list_profiles(&self) -> Result<String, PipeError> {
        self.invoke_json_string("list_profiles", serde_json::json!({})).await
    }

    /// Connect to the named profile.
    pub async fn connect(&self, profile_id: &str) -> Result<(), PipeError> {
        self.invoke_unit("connect", serde_json::json!({ "profile_id": profile_id })).await
    }

    /// Disconnect the active profile.
    pub async fn disconnect(&self) -> Result<(), PipeError> {
        self.invoke_unit("disconnect", serde_json::json!({})).await
    }

    /// Current VPN status JSON.
    pub async fn get_status(&self) -> Result<String, PipeError> {
        self.invoke_json_string("get_status", serde_json::json!({})).await
    }

    /// Delete a profile by id.
    pub async fn delete_profile(&self, profile_id: &str) -> Result<(), PipeError> {
        self.invoke_unit("delete_profile", serde_json::json!({ "profile_id": profile_id })).await
    }

    /// Import a WireGuard `wg-quick` config. Returns the new profile id.
    pub async fn import_wireguard(
        &self,
        conf_text: &str,
        name: &str,
    ) -> Result<String, PipeError> {
        self.invoke_json_string(
            "import_wireguard",
            serde_json::json!({ "conf_text": conf_text, "name": name }),
        )
        .await
    }

    /// Import a FortiGate IKEv2 IPsec profile (Windows RAS / strongSwan).
    /// Returns the new profile id. Password + PSK are sent in cleartext
    /// over the local pipe; the daemon stores them in the platform
    /// secret store before responding.
    pub async fn import_fortigate(
        &self,
        name: &str,
        host: &str,
        username: &str,
        password: &str,
        psk: &str,
    ) -> Result<String, PipeError> {
        self.invoke_json_string(
            "import_fortigate",
            serde_json::json!({
                "name": name,
                "host": host,
                "username": username,
                "password": password,
                "psk": psk,
            }),
        )
        .await
    }

    /// Import a FortiGate SSL VPN profile. Returns the new profile id.
    ///
    /// `dns_servers_json` and `routes_json` are JSON-encoded arrays
    /// (`"[\"1.1.1.1\"]"`, `"[\"10.0.0.0/8\"]"`); the daemon parses them
    /// into typed `IpAddr`/`IpNet` values before persisting.
    #[allow(clippy::too_many_arguments)]
    pub async fn import_forticlient_sslvpn(
        &self,
        name: &str,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        trusted_cert: Option<&str>,
        dns_servers_json: &str,
        routes_json: &str,
    ) -> Result<String, PipeError> {
        self.invoke_json_string(
            "import_forticlient_sslvpn",
            serde_json::json!({
                "name": name,
                "host": host,
                "port": port,
                "username": username,
                "password": password,
                "trusted_cert": trusted_cert.unwrap_or(""),
                "dns_servers_json": dns_servers_json,
                "routes_json": routes_json,
            }),
        )
        .await
    }

    // ----- SSH keys -----

    /// Generate a new SSH key. Returns the key JSON.
    pub async fn ssh_generate_key(
        &self,
        key_type: &str,
        name: &str,
        description: &str,
        tags_json: &str,
    ) -> Result<String, PipeError> {
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
    pub async fn ssh_list_keys(&self) -> Result<String, PipeError> {
        self.invoke_json_string("ssh_list_keys", serde_json::json!({})).await
    }

    /// Delete an SSH key by id.
    pub async fn ssh_delete_key(&self, key_id: &str) -> Result<(), PipeError> {
        self.invoke_unit("ssh_delete_key", serde_json::json!({ "key_id": key_id })).await
    }

    /// Export the public half of a key in OpenSSH `authorized_keys` format.
    pub async fn ssh_export_public_key(&self, key_id: &str) -> Result<String, PipeError> {
        self.invoke_json_string(
            "ssh_export_public_key",
            serde_json::json!({ "key_id": key_id }),
        )
        .await
    }

    // ----- Hosts -----

    /// List all managed hosts as a JSON array.
    pub async fn list_hosts(&self) -> Result<String, PipeError> {
        self.invoke_json_string("list_hosts", serde_json::json!({})).await
    }

    /// Get a single host's JSON.
    pub async fn get_host(&self, host_id: &str) -> Result<String, PipeError> {
        self.invoke_json_string("get_host", serde_json::json!({ "host_id": host_id })).await
    }

    /// Add a new host from its JSON serialisation. Returns the assigned id.
    pub async fn add_host(&self, host_json: &str) -> Result<String, PipeError> {
        self.invoke_json_string("add_host", serde_json::json!({ "host_json": host_json })).await
    }

    /// Delete a host by id.
    pub async fn delete_host(&self, host_id: &str) -> Result<(), PipeError> {
        self.invoke_unit("delete_host", serde_json::json!({ "host_id": host_id })).await
    }

    /// Execute a shell command on a remote host via SSH. Returns JSON
    /// containing `stdout`, `stderr`, and `exit_code`.
    pub async fn ssh_execute_command(
        &self,
        host_id: &str,
        command: &str,
    ) -> Result<String, PipeError> {
        self.invoke_json_string(
            "ssh_execute_command",
            serde_json::json!({ "host_id": host_id, "command": command }),
        )
        .await
    }

    /// Probe a host's reachability and credentials. Returns a JSON report.
    pub async fn test_host_connection(&self, host_id: &str) -> Result<String, PipeError> {
        self.invoke_json_string(
            "test_host_connection",
            serde_json::json!({ "host_id": host_id }),
        )
        .await
    }

    /// Toggle the favourite/pin flag for a host. Returns the new state.
    pub async fn toggle_host_pin(&self, host_id: &str) -> Result<String, PipeError> {
        self.invoke_json_string(
            "toggle_host_pin",
            serde_json::json!({ "host_id": host_id }),
        )
        .await
    }

    /// Store a host's SSH password in the credential store.
    pub async fn ssh_set_password(
        &self,
        host_id: &str,
        password: &str,
    ) -> Result<(), PipeError> {
        self.invoke_unit(
            "ssh_set_password",
            serde_json::json!({ "host_id": host_id, "password": password }),
        )
        .await
    }

    /// Store an API token for a host (FortiGate, UniFi, OPNsense, etc.).
    pub async fn ssh_set_api_token(
        &self,
        host_id: &str,
        token: &str,
        port: u16,
    ) -> Result<(), PipeError> {
        self.invoke_unit(
            "ssh_set_api_token",
            serde_json::json!({ "host_id": host_id, "token": token, "port": port }),
        )
        .await
    }

    /// Set the inform URL on a UniFi-managed device.
    pub async fn unifi_set_inform(
        &self,
        host_id: &str,
        inform_url: &str,
    ) -> Result<String, PipeError> {
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
    ) -> Result<String, PipeError> {
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
    ) -> Result<String, PipeError> {
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
    pub async fn fortigate_push_ssh_key(
        &self,
        host_id: &str,
        key_id: &str,
        admin_user: &str,
    ) -> Result<String, PipeError> {
        self.invoke_json_string(
            "fortigate_push_ssh_key",
            serde_json::json!({
                "host_id": host_id,
                "key_id": key_id,
                "admin_user": admin_user,
            }),
        )
        .await
    }

    /// Snapshot a FortiGate config. Returns the filename of the stored backup.
    pub async fn fortigate_backup_config(&self, host_id: &str) -> Result<String, PipeError> {
        self.invoke_json_string(
            "fortigate_backup_config",
            serde_json::json!({ "host_id": host_id }),
        )
        .await
    }

    /// Proxy an OPNsense REST API call.
    pub async fn opnsense_api(
        &self,
        host_id: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<String, PipeError> {
        self.invoke_json_string(
            "opnsense_api",
            serde_json::json!({
                "host_id": host_id,
                "method": method,
                "path": path,
                "body": body,
            }),
        )
        .await
    }

    /// Snapshot an OPNsense config. Returns the saved filename.
    pub async fn opnsense_backup_config(&self, host_id: &str) -> Result<String, PipeError> {
        self.invoke_json_string(
            "opnsense_backup_config",
            serde_json::json!({ "host_id": host_id }),
        )
        .await
    }

    /// Send a Sophos WebAdmin XML Configuration API operation. `inner_xml`
    /// is the body fragment between `</Login>` and `</Request>`; the
    /// daemon wraps it in the envelope and attaches credentials.
    pub async fn sophos_xml_api(
        &self,
        host_id: &str,
        inner_xml: &str,
    ) -> Result<String, PipeError> {
        self.invoke_json_string(
            "sophos_xml_api",
            serde_json::json!({ "host_id": host_id, "inner_xml": inner_xml }),
        )
        .await
    }
}
