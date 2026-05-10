//! Integration tests for the JSON-RPC server.
//!
//! These tests spawn a real `EngineServer` on a temp Unix socket
//! and exercise the wire protocol end-to-end. They catch:
//!   - Length-prefix framing regressions
//!   - JSON-RPC request/response shape drift
//!   - Method-name dispatch (e.g. `api_version` arm)
//!   - Concurrent connection handling under the new semaphore
//!
//! Each test gets its own temp socket via `tempfile::TempDir`
//! so they can run in parallel without colliding.
//!
//! Tests are deliberately minimal — they prove the wire works,
//! not that any specific handler returns correct data. Per-handler
//! correctness lives in the unit tests of each handler's module.
//!
//! Why not also unit-test EngineServer methods directly?
//! Because the bug class we're guarding against here is in the
//! *framing* + *dispatch*, not the handler bodies. A unit test
//! that calls `server.handle_X` skips the very layer we want to
//! catch regressions in.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use supermgr_engine::secrets::file::FileSecretStore;
use supermgr_engine::server::EngineServer;
use supermgr_engine::state::DaemonState;

/// Spawn a fresh server on a temp Unix socket. Returns the
/// socket path; the temp dir auto-cleans up when the returned
/// `TempDir` drops. Caller must keep it alive for the test.
async fn spawn_server() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket_path = dir.path().join("test.sock").to_string_lossy().into_owned();

    let state = DaemonState::new(dir.path().to_path_buf());
    let secrets: Arc<dyn supermgr_core::keyring::SecretStore> = Arc::new(
        FileSecretStore::new(dir.path().join("secrets.json")),
    );
    let server = Arc::new(EngineServer::new(state, secrets));

    let sock_for_task = socket_path.clone();
    tokio::spawn(async move {
        let _ = server.serve(&sock_for_task).await;
    });

    // Tiny sleep so the bind+chmod completes before the first
    // client tries to connect. 50 ms is plenty.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (dir, socket_path)
}

/// Send a JSON-RPC request and read the framed response. Mirrors
/// the Mac app's `ServiceClient` framing exactly.
async fn rpc_call(socket_path: &str, method: &str, params: Value, id: u64) -> Value {
    let mut stream = UnixStream::connect(socket_path).await.expect("connect");

    let req = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": id,
    });
    let body = serde_json::to_vec(&req).unwrap();
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await.expect("write len");
    stream.write_all(&body).await.expect("write body");

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.expect("read len");
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    assert!(resp_len < 10 * 1024 * 1024, "response should be under 10 MiB");

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.expect("read body");
    serde_json::from_slice(&resp_buf).expect("valid json")
}

#[tokio::test]
async fn api_version_returns_expected_major() {
    let (_dir, socket) = spawn_server().await;
    let resp = rpc_call(&socket, "api_version", json!({}), 1).await;

    // JSON-RPC envelope checks.
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert!(resp["result"].is_object(), "expected result object");
    let result = &resp["result"];
    assert!(result["major"].as_u64().is_some(), "major must be present");
    // We don't assert specific major value — that lets the constant
    // change without breaking the test. Just prove the field is there.
}

#[tokio::test]
async fn unknown_method_returns_error() {
    let (_dir, socket) = spawn_server().await;
    let resp = rpc_call(&socket, "this_method_does_not_exist", json!({}), 42).await;
    assert_eq!(resp["id"], 42);
    assert!(resp["error"].is_object(), "expected error object");
    let err = &resp["error"];
    let msg = err["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("unknown method") || msg.contains("not found"),
        "error message should mention unknown method, got: {msg}"
    );
}

#[tokio::test]
async fn malformed_json_returns_parse_error() {
    let (_dir, socket) = spawn_server().await;
    let mut stream = UnixStream::connect(&socket).await.unwrap();

    // Length-prefixed garbage (length is correct but body isn't JSON).
    let body = b"this is not json";
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(body).await.unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.unwrap();
    let resp: Value = serde_json::from_slice(&resp_buf).unwrap();

    assert!(resp["error"].is_object(), "parse error should populate error field");
}

#[tokio::test]
async fn list_profiles_on_empty_state_returns_array() {
    let (_dir, socket) = spawn_server().await;
    let resp = rpc_call(&socket, "list_profiles", json!({}), 1).await;
    assert!(resp["error"].is_null() || resp["error"] == json!(null));
    assert!(resp["result"].is_array(), "list_profiles should return an array");
}

#[tokio::test]
async fn parallel_connections_all_succeed() {
    let (_dir, socket) = spawn_server().await;

    // Spawn 16 concurrent api_version calls — well under the 256
    // semaphore but enough to hit any contention bug.
    let mut handles = Vec::new();
    for i in 0..16 {
        let s = socket.clone();
        handles.push(tokio::spawn(async move {
            rpc_call(&s, "api_version", json!({}), i).await
        }));
    }

    for (i, h) in handles.into_iter().enumerate() {
        let resp = h.await.expect("task");
        assert_eq!(resp["id"].as_u64().unwrap() as usize, i);
        assert!(resp["result"].is_object());
    }
}

#[tokio::test]
async fn socket_chmod_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, socket) = spawn_server().await;
    let meta = std::fs::metadata(&socket).expect("socket exists");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "socket must be 0o600 (owner-only) — security regression check"
    );
}

#[tokio::test]
async fn invalid_id_zero_still_responds() {
    // Some clients use id=0 for one-shot notifications.
    let (_dir, socket) = spawn_server().await;
    let resp = rpc_call(&socket, "api_version", json!({}), 0).await;
    assert_eq!(resp["id"], 0);
}
