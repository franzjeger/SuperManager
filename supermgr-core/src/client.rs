//! Platform-selected daemon client.
//!
//! Re-exports the right concrete client type as [`DaemonClient`] so that
//! cross-platform code — the MCP server, future cross-platform GUIs — can
//! be written against a single name and let `cfg` resolve the rest.
//!
//! - On Linux, [`DaemonClient`] is the zbus-generated `DaemonProxy`.
//! - On Windows, [`DaemonClient`] is the named-pipe [`crate::pipe::PipeClient`].
//! - On macOS, [`DaemonClient`] is the unix-socket [`crate::mac::MacClient`].
//!
//! Callers that need to construct a client typically want the
//! [`connect`] helper rather than touching the per-platform constructor.

#[cfg(target_os = "linux")]
pub type DaemonClient = crate::dbus::DaemonProxy<'static>;

#[cfg(target_os = "windows")]
pub use crate::pipe::PipeClient as DaemonClient;

#[cfg(target_os = "macos")]
pub use crate::mac::MacClient as DaemonClient;

#[cfg(target_os = "linux")]
pub async fn connect() -> Result<DaemonClient, String> {
    let conn = zbus::Connection::system()
        .await
        .map_err(|e| format!("D-Bus system connection failed (is supermgrd running?): {e}"))?;
    let conn_static: &'static zbus::Connection = Box::leak(Box::new(conn));
    crate::dbus::DaemonProxy::new(conn_static)
        .await
        .map_err(|e| format!("failed to create DaemonProxy: {e}"))
}

#[cfg(target_os = "windows")]
pub async fn connect() -> Result<DaemonClient, String> {
    crate::pipe::PipeClient::open()
        .await
        .map_err(|e| format!("named-pipe connect failed (is the SuperManager service running?): {e}"))
}

#[cfg(target_os = "macos")]
pub async fn connect() -> Result<DaemonClient, String> {
    crate::mac::MacClient::open()
        .await
        .map_err(|e| format!("unix-socket connect failed (is the supermgrd-mac service running?): {e}"))
}
