//! Named-pipe server.
//!
//! Listens on `\\.\pipe\supermgrd`, accepts each instance, and dispatches
//! incoming JSON-RPC frames against [`crate::dispatch`].
//!
//! # Concurrency model
//!
//! `ServerOptions::create` creates the first pipe instance; we immediately
//! create a *replacement* instance before calling `connect()` on the
//! current one, so that the moment a client opens the pipe a fresh
//! instance is already in place for the next caller. This mirrors the
//! Win32 idiomatic "always have one listening" pattern and lets multiple
//! GUIs/MCP servers connect concurrently.
//!
//! # Security
//!
//! For the skeleton we rely on the default DACL (which permits the
//! creator's session). The production hardening step is to attach an
//! explicit security descriptor allowing only:
//!
//! - `NT AUTHORITY\SYSTEM`   — full control
//! - `BUILTIN\Administrators` — full control
//! - `NT AUTHORITY\Authenticated Users` — read + write (no change-pipe-mode)
//!
//! That requires constructing a SECURITY_ATTRIBUTES with a SDDL string —
//! tracked as a TODO in the issue tracker; the current default ACL is safe
//! on single-user workstations but should not ship to enterprise.

use std::sync::Arc;

use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    sync::Notify,
};
use tracing::{debug, warn};

use supermgr_core::protocol::{PipeRequest, PipeResponse, RpcError, MAX_FRAME_BYTES, PIPE_NAME, PROTOCOL_VERSION};

use super::{daemon::DaemonState, dispatch, pipe_acl::PipeSecurity};

/// Max number of concurrent pipe instances we will keep allocated. Each
/// connected client consumes one instance; idle instances are cheap.
/// `usize` because that's what `ServerOptions::max_instances` accepts.
const MAX_INSTANCES: usize = 32;

/// Create a fresh listening pipe instance with the restrictive ACL.
///
/// Tokio's safe `create()` uses the default DACL — which is too lax in
/// console mode and too strict in service mode. The SDDL-driven security
/// descriptor in [`PipeSecurity`] handles both correctly. The function
/// itself is unsafe because the underlying Win32 entry point dereferences
/// the SECURITY_ATTRIBUTES pointer; our `PipeSecurity` upholds its
/// validity-for-the-pointer-lifetime contract.
fn create_listener(first: bool) -> std::io::Result<(NamedPipeServer, PipeSecurity)> {
    let mut security = PipeSecurity::restrictive()?;
    let mut options = ServerOptions::new();
    options
        .max_instances(MAX_INSTANCES)
        .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte);
    if first {
        options.first_pipe_instance(true);
    }
    // SAFETY: `security` outlives the call; `attrs_ptr` returns a valid
    // SECURITY_ATTRIBUTES heap pointer for the duration of `security`.
    let server = unsafe {
        options.create_with_security_attributes_raw(PIPE_NAME, security.attrs_ptr())
    }?;
    Ok((server, security))
}

/// Listen on the well-known pipe path and dispatch requests until
/// `shutdown` fires.
pub async fn serve(state: Arc<DaemonState>, shutdown: Arc<Notify>) -> std::io::Result<()> {
    let (mut listener, _initial_sec) = create_listener(true)?;
    // Hold the SECURITY_ATTRIBUTES alive for the entire serve loop. We
    // re-create one per new listener and let the previous drop; the
    // tokio NamedPipeServer captures its own handle, so the security
    // descriptor is only consulted at creation time.

    loop {
        let connected = tokio::select! {
            res = listener.connect() => res,
            () = shutdown.notified() => {
                debug!("pipe server: shutdown received before connect");
                return Ok(());
            }
        };
        if let Err(e) = connected {
            warn!("pipe accept failed: {e}");
            let (new_listener, _sec) = create_listener(false)?;
            listener = new_listener;
            continue;
        }

        // Swap the listener out: hand off the connected instance to the
        // request handler, then build a fresh listener for the next caller.
        let (new_listener, _sec) = create_listener(false)?;
        let connection = std::mem::replace(&mut listener, new_listener);

        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(connection, state, shutdown).await {
                warn!("pipe connection ended with error: {e:#}");
            }
        });
    }
}

/// Per-connection loop: read a frame, dispatch, write the response, repeat.
async fn handle_connection(
    pipe: NamedPipeServer,
    state: Arc<DaemonState>,
    shutdown: Arc<Notify>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(pipe);
    let mut line = String::new();
    loop {
        line.clear();
        let read = tokio::select! {
            res = reader.read_line(&mut line) => res,
            () = shutdown.notified() => return Ok(()),
        };
        let n = match read {
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        if n == 0 {
            // Peer closed the pipe.
            return Ok(());
        }
        if n > MAX_FRAME_BYTES {
            // Defensive — the buffered reader has no hard ceiling on
            // line length on its own. Reject oversized frames.
            let _ = write_error(reader.get_mut(), 0, RpcError::Protocol(
                format!("frame exceeds {MAX_FRAME_BYTES} bytes"),
            )).await;
            return Ok(());
        }

        let trimmed = line.trim_end();
        let req: PipeRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let _ = write_error(reader.get_mut(), 0, RpcError::Protocol(
                    format!("malformed request: {e}"),
                )).await;
                continue;
            }
        };

        if req.v != PROTOCOL_VERSION {
            let _ = write_error(reader.get_mut(), req.id, RpcError::Protocol(
                format!("unsupported protocol version {}, daemon speaks {}", req.v, PROTOCOL_VERSION),
            )).await;
            continue;
        }

        let response = dispatch::dispatch(&state, &req).await;
        let frame = match serde_json::to_vec(&response) {
            Ok(mut v) => { v.push(b'\n'); v }
            Err(e) => {
                warn!("response serialise failed: {e}");
                continue;
            }
        };
        reader.get_mut().write_all(&frame).await?;
        reader.get_mut().flush().await?;
    }
}

/// Send a single error response with the given id. Used for early-stage
/// protocol failures where we couldn't even parse the request.
async fn write_error(
    pipe: &mut NamedPipeServer,
    id: u64,
    err: RpcError,
) -> std::io::Result<()> {
    let resp = PipeResponse {
        v: PROTOCOL_VERSION,
        id,
        result: None,
        error: Some(err),
    };
    let mut frame = serde_json::to_vec(&resp).map_err(std::io::Error::other)?;
    frame.push(b'\n');
    pipe.write_all(&frame).await?;
    pipe.flush().await
}
