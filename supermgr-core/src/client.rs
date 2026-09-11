//! Platform-selected daemon client.
//!
//! Re-exports the right concrete client type as [`DaemonClient`] so that
//! cross-platform code — the MCP server, future cross-platform GUIs — can
//! be written against a single name and let `cfg` resolve the rest.
//!
//! - On Linux, [`DaemonClient`] is the zbus-generated `DaemonProxy`.
//! - On Windows, [`DaemonClient`] is the named-pipe [`crate::pipe::PipeClient`].
//! - On macOS the daemon side talks XPC; see `SuperManagerMac` for the
//!   Swift-native client. No Rust client is shipped for macOS today.
//!
//! Callers that need to construct a client typically want the
//! [`connect`] helper rather than touching the per-platform constructor.

/// On Linux the daemon client is the zbus-generated D-Bus proxy. We pin the
/// lifetime to `'static` here because [`connect`] leaks the underlying
/// `zbus::Connection` so the proxy can outlive any caller's scope without
/// dragging a lifetime parameter through every call site.
#[cfg(target_os = "linux")]
pub type DaemonClient = crate::dbus::DaemonProxy<'static>;

#[cfg(target_os = "windows")]
pub use crate::pipe::PipeClient as DaemonClient;

#[cfg(target_os = "macos")]
pub struct DaemonClient {}

#[cfg(target_os = "macos")]
pub async fn connect() -> Result<DaemonClient, String> {
    Err("supermgr-mcp is currently not supported natively on macOS via this client".into())
}

/// Connect to the local daemon.
///
/// On Linux this acquires a system-bus connection and creates a `DaemonProxy`.
/// On Windows this opens the named pipe `\\.\pipe\supermgrd`. Errors surface
/// in a string-typed wrapper to keep the API uniform across transports.
#[cfg(target_os = "linux")]
pub async fn connect() -> Result<DaemonClient, String> {
    let conn = zbus::Connection::system()
        .await
        .map_err(|e| format!("D-Bus system connection failed (is supermgrd running?): {e}"))?;
    // Leak the connection so the proxy can carry a `'static` lifetime.
    // Daemons are process-singletons; a single leaked connection per process
    // is the standard zbus pattern for "long-lived proxy".
    let conn_static: &'static zbus::Connection = Box::leak(Box::new(conn));
    let proxy = crate::dbus::DaemonProxy::new(conn_static)
        .await
        .map_err(|e| format!("failed to create DaemonProxy: {e}"))?;
    Ok(proxy)
}

/// See [`connect`] (Linux variant).
#[cfg(target_os = "windows")]
pub async fn connect() -> Result<DaemonClient, String> {
    crate::pipe::PipeClient::open()
        .await
        .map_err(|e| format!("named-pipe connect failed (is the SuperManager service running?): {e}"))
}
#[cfg(target_os = "macos")]
impl DaemonClient {
    pub async fn fortigate_api(&self, _host: &str, _method: &str, _path: &str, _body: &str) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn list_hosts(&self) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn ssh_list_keys(&self) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn ssh_execute_command(&self, _host: &str, _cmd: &str) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn get_status(&self) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn list_profiles(&self) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn connect(&self, _profile: &str) -> Result<(), String> { Err("macOS stub".into()) }
    pub async fn disconnect(&self) -> Result<(), String> { Err("macOS stub".into()) }
    pub async fn add_host(&self, _json: &str) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn test_host_connection(&self, _host: &str) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn toggle_host_pin(&self, _host: &str) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn ssh_set_password(&self, _host: &str, _pwd: &str) -> Result<(), String> { Err("macOS stub".into()) }
    pub async fn ssh_set_api_token(&self, _host: &str, _token: &str, _port: u16) -> Result<(), String> { Err("macOS stub".into()) }
    pub async fn unifi_set_inform(&self, _host: &str, _url: &str) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn unifi_api(&self, _host: &str, _method: &str, _path: &str, _body: &str) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn fortigate_push_ssh_key(&self, _host: &str, _key: &str, _user: &str) -> Result<String, String> { Err("macOS stub".into()) }
    pub async fn fortigate_backup_config(&self, _host: &str) -> Result<String, String> { Err("macOS stub".into()) }
}
