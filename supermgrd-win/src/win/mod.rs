//! Windows-only daemon body. Everything inside this module assumes Win32
//! APIs are available and is gated on `cfg(target_os = "windows")` by the
//! parent module declaration in `main.rs`.

#![deny(missing_docs)]

pub mod appliance;
pub mod daemon;
pub mod dispatch;
pub mod known_hosts;
pub mod paths;
pub mod pipe_acl;
pub mod pipe_server;
pub mod profile_store;
pub mod ssh_exec;
pub mod vpn;

use std::{ffi::OsString, sync::Arc, time::Duration};

use anyhow::Context as _;
use tokio::sync::{watch, Notify};
use tracing::{error, info};

use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

/// Windows Service display + service name. Must match what the installer
/// PowerShell script registers via `New-Service`.
const SERVICE_NAME: &str = "SuperManager";

define_windows_service!(ffi_service_main, service_main);

/// Entry point invoked from `main`.
pub fn run() -> anyhow::Result<()> {
    let console_mode = std::env::args().any(|a| a == "--console");
    if console_mode {
        init_console_tracing();
        info!("supermgrd-win starting in console mode");
        return run_async();
    }

    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("failed to start SCM dispatcher (use --console to run outside the SCM)")?;
    Ok(())
}

/// Console-mode tracing: log to stderr with `RUST_LOG` controlling the
/// filter. Mirrors the existing Linux daemon's developer ergonomics.
fn init_console_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let _ = fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .try_init();
}

/// Run the async daemon body. Used by both console mode and service mode.
fn run_async() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime build")?;
    rt.block_on(async {
        let shutdown = Arc::new(Notify::new());
        daemon::run(shutdown).await
    })
}

/// SCM-invoked entry point. Wires the Windows Service control handler to a
/// `watch` channel that the async daemon listens to for shutdown.
fn service_main(_args: Vec<OsString>) {
    // Tracing → Application event log when running under the SCM. The
    // `eventlog` crate registers the source on first init; we ignore the
    // result so an already-registered source doesn't crash startup.
    let _ = eventlog::register("SuperManager");
    let _ = eventlog::init("SuperManager", log::Level::Info);

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = match service_control_handler::register(SERVICE_NAME, handler) {
        Ok(h) => h,
        Err(e) => {
            error!("register service control handler: {e}");
            return;
        }
    };

    let set_status = |state: ServiceState, exit: ServiceExitCode| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: match state {
                ServiceState::Running => {
                    ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
                }
                _ => ServiceControlAccept::empty(),
            },
            exit_code: exit,
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        });
    };

    set_status(ServiceState::StartPending, ServiceExitCode::Win32(0));

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("tokio runtime: {e}");
            set_status(ServiceState::Stopped, ServiceExitCode::ServiceSpecific(1));
            return;
        }
    };

    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_notify_for_watch = shutdown_notify.clone();

    rt.spawn(async move {
        loop {
            if *shutdown_rx.borrow_and_update() {
                shutdown_notify_for_watch.notify_waiters();
                return;
            }
            if shutdown_rx.changed().await.is_err() {
                return;
            }
        }
    });

    set_status(ServiceState::Running, ServiceExitCode::Win32(0));

    let result = rt.block_on(async { daemon::run(shutdown_notify).await });
    match result {
        Ok(()) => set_status(ServiceState::Stopped, ServiceExitCode::Win32(0)),
        Err(e) => {
            error!("daemon exited with error: {e:#}");
            set_status(ServiceState::Stopped, ServiceExitCode::ServiceSpecific(2));
        }
    }
}
