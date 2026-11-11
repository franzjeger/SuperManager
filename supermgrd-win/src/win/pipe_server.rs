//! Named-pipe server.
//!
//! Listens on `\\.\pipe\supermgrd`, accepts each instance, verifies the
//! caller's security token, and dispatches incoming JSON-RPC frames against
//! [`crate::dispatch`].

use std::{os::windows::io::AsRawHandle as _, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncWriteExt as _, BufReader},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    sync::{Notify, Semaphore},
    time::{sleep, timeout},
};
use tracing::{debug, warn};

use supermgr_core::protocol::{
    PipeRequest, PipeResponse, RpcError, MAX_FRAME_BYTES, PIPE_NAME, PROTOCOL_VERSION,
};

use super::{
    daemon::DaemonState,
    dispatch,
    pipe_acl::{caller_auth_from_pipe, CallerAuth, PipeSecurity},
};
use crate::rpc_args::{read_bounded_line, BoundedLine};

/// Max number of pipe instances allocated simultaneously (1 listener + 31 active clients).
const MAX_INSTANCES: usize = 32;

/// Idle read timeout per client connection so stalled callers release their pipe slot.
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(300);

fn create_listener(first: bool) -> std::io::Result<(NamedPipeServer, PipeSecurity)> {
    let mut security = PipeSecurity::restrictive()?;
    let mut options = ServerOptions::new();
    options
        .max_instances(MAX_INSTANCES)
        .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte);
    if first {
        options.first_pipe_instance(true);
    }
    let server =
        unsafe { options.create_with_security_attributes_raw(PIPE_NAME, security.attrs_ptr()) }?;
    Ok((server, security))
}

async fn next_listener_or_shutdown(
    shutdown: &Notify,
) -> Option<(NamedPipeServer, PipeSecurity)> {
    let mut delay = Duration::from_millis(50);
    loop {
        match create_listener(false) {
            Ok(pair) => return Some(pair),
            Err(e) => {
                warn!("pipe listener replacement failed ({e}); retrying in {delay:?}");
                tokio::select! {
                    () = sleep(delay) => {}
                    () = shutdown.notified() => return None,
                }
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        }
    }
}

/// Listen on the well-known pipe path and dispatch requests until `shutdown` fires.
pub async fn serve(state: Arc<DaemonState>, shutdown: Arc<Notify>) -> std::io::Result<()> {
    let (mut listener, mut _active_sec) = create_listener(true)?;
    let slots = Arc::new(Semaphore::new(MAX_INSTANCES - 1));

    loop {
        let permit = tokio::select! {
            res = Arc::clone(&slots).acquire_owned() => match res {
                Ok(p) => p,
                Err(_) => return Ok(()),
            },
            () = shutdown.notified() => {
                debug!("pipe server: shutdown received while waiting for connection slot");
                return Ok(());
            }
        };

        let connected = tokio::select! {
            res = listener.connect() => res,
            () = shutdown.notified() => {
                debug!("pipe server: shutdown received before connect");
                return Ok(());
            }
        };
        if let Err(e) = connected {
            drop(permit);
            warn!("pipe accept failed: {e}");
            let Some((new_listener, new_sec)) = next_listener_or_shutdown(&shutdown).await else {
                return Ok(());
            };
            listener = new_listener;
            _active_sec = new_sec;
            continue;
        }

        let Some((new_listener, new_sec)) = next_listener_or_shutdown(&shutdown).await else {
            return Ok(());
        };
        let connection = std::mem::replace(&mut listener, new_listener);
        _active_sec = new_sec;

        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(connection, state, shutdown).await {
                warn!("pipe connection ended with error: {e:#}");
            }
        });
    }
}

/// Per-connection loop: read a frame with idle timeout, authenticate the client,
/// dispatch, write the response, repeat.
async fn handle_connection(
    pipe: NamedPipeServer,
    state: Arc<DaemonState>,
    shutdown: Arc<Notify>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(pipe);
    let mut line = String::new();
    let mut caller_auth: Option<CallerAuth> = None;

    loop {
        line.clear();
        let read = tokio::select! {
            res = timeout(IDLE_READ_TIMEOUT, read_bounded_line(&mut reader, &mut line, MAX_FRAME_BYTES)) => {
                match res {
                    Ok(inner) => inner,
                    Err(_) => {
                        debug!("closing idle named-pipe client after {IDLE_READ_TIMEOUT:?}");
                        return Ok(());
                    }
                }
            }
            () = shutdown.notified() => return Ok(()),
        };
        match read? {
            BoundedLine::Eof => return Ok(()),
            BoundedLine::Oversized => {
                let _ = write_error(
                    reader.get_mut(),
                    0,
                    RpcError::Protocol(format!("frame exceeds {MAX_FRAME_BYTES} bytes")),
                )
                .await;
                return Ok(());
            }
            BoundedLine::Frame => {}
        }

        if caller_auth.is_none() {
            let raw_handle = reader.get_ref().as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
            match caller_auth_from_pipe(raw_handle) {
                Ok(auth) => caller_auth = Some(auth),
                Err(e) => {
                    warn!("refusing named-pipe client whose token could not be inspected: {e}");
                    let _ = write_error(
                        reader.get_mut(),
                        0,
                        RpcError::PermissionDenied(format!(
                            "could not verify named-pipe caller identity: {e}"
                        )),
                    )
                    .await;
                    return Ok(());
                }
            }
        }
        let caller = caller_auth.as_ref().expect("populated above");

        let trimmed = line.trim_end();
        let req: PipeRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let _ = write_error(
                    reader.get_mut(),
                    0,
                    RpcError::Protocol(format!("malformed request: {e}")),
                )
                .await;
                continue;
            }
        };

        if req.v != PROTOCOL_VERSION {
            let _ = write_error(
                reader.get_mut(),
                req.id,
                RpcError::Protocol(format!(
                    "unsupported protocol version {}, daemon speaks {}",
                    req.v, PROTOCOL_VERSION
                )),
            )
            .await;
            continue;
        }

        let response = dispatch::dispatch(&state, &req, caller).await;
        let frame = match serde_json::to_vec(&response) {
            Ok(mut v) => {
                v.push(b'\n');
                v
            }
            Err(e) => {
                warn!("response serialise failed: {e}");
                continue;
            }
        };
        reader.get_mut().write_all(&frame).await?;
        reader.get_mut().flush().await?;
    }
}

async fn write_error(pipe: &mut NamedPipeServer, id: u64, err: RpcError) -> std::io::Result<()> {
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
