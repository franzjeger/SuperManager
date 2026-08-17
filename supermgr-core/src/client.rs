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

/// A process-wide cached system-bus D-Bus connection.
///
/// `zbus::Connection::system()` opens a new Unix socket and performs the
/// D-Bus SASL (`EXTERNAL`) authentication handshake every time it is called.
/// The GTK app made that call once per D-Bus operation (87 call sites),
/// paying socket setup + auth latency on every button click and refresh.
/// This caches one live connection per process so a `DaemonProxy` can be
/// rebuilt cheaply from it without re-opening the bus.
///
/// `tokio::sync::OnceCell` is used rather than `std::sync::OnceLock` because
/// the connection is created asynchronously and the cell must be initialized
/// from within a tokio runtime (the GTK app drives all D-Bus calls from its
/// multi-thread runtime). Failed initializations are *not* cached by
/// `get_or_try_init`, so a daemon that is still starting up can be retried
/// on the next call — matching the previous per-call retry behaviour.
#[cfg(target_os = "linux")]
pub async fn system_connection() -> Result<&'static zbus::Connection, zbus::Error> {
    static CONN: tokio::sync::OnceCell<zbus::Connection> = tokio::sync::OnceCell::const_new();
    CONN.get_or_try_init(|| async { zbus::Connection::system().await }).await
}

/// Connect to the local daemon.
///
/// On Linux this acquires a system-bus connection and creates a `DaemonProxy`.
/// On Windows this opens the named pipe `\\.\pipe\supermgrd`. Errors surface
/// in a string-typed wrapper to keep the API uniform across transports.
#[cfg(target_os = "linux")]
pub async fn connect() -> Result<DaemonClient, String> {
    let conn = system_connection()
        .await
        .map_err(|e| e.to_string())?;
    let proxy = crate::dbus::DaemonProxy::new(conn)
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
