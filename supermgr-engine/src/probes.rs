//! Lightweight TCP reachability probe used by SSH host health checks.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

/// Test connectivity to `(host, port)` within a timeout. Returns `true`
/// if a TCP three-way handshake completes.
pub async fn tcp_check(host: &str, port: u16, timeout_ms: u64) -> bool {
    let target = format!("{host}:{port}");
    matches!(
        timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(&target)
        )
        .await,
        Ok(Ok(_))
    )
}
