//! `supermgr` — GTK4/Adwaita VPN + SSH manager GUI.
//!
//! Thin D-Bus client for the `supermgrd` daemon.  All VPN and SSH state is
//! owned by the daemon; the GUI renders it and issues commands.
//!
//! # Window structure
//!
//! ```text
//! AdwApplicationWindow
//! └── AdwToolbarView
//!     ├── [top bar] AdwHeaderBar   ← one header bar, OS window controls here
//!     └── [content] AdwToastOverlay
//!         └── GtkBox (vertical)
//!             ├── AdwBanner        ← "daemon not running" warning
//!             └── AdwNavigationSplitView
//!                 ├── sidebar: AdwNavigationPage
//!                 │   └── GtkScrolledWindow → GtkListBox (profiles)
//!                 └── content: AdwNavigationPage
//!                     └── GtkScrolledWindow → GtkStack
//!                         ├── "empty": AdwStatusPage
//!                         └── "detail": GtkBox (status + button + stats)
//! ```
//!
//! # Threading model
//!
//! ```text
//! GTK main thread                    tokio thread pool
//! ──────────────────────────         ──────────────────────────────────
//! button handler ──rt.spawn()──►     file I/O + D-Bus call (zbus/tokio)
//!                                            │ tx.send(AppMsg)
//! glib::timeout_add_local polls rx ◄─────────┘
//! updates widgets (GTK thread only)
//!
//! ksni tray task (StatusNotifierItem D-Bus)
//! reads VpnTray fields whenever the tray needs to re-render;
//! tray.update() is called from the drain loop after every state change.
//! ```
//!
//! # State updates
//!
//! A background tokio task subscribes to the `StateChanged` and `StatsUpdated`
//! D-Bus signals emitted by the daemon and forwards them to the GTK drain loop
//! as `AppMsg::StateUpdated` and `AppMsg::StatsUpdated` respectively.  If the
//! daemon disappears, the task detects the closed signal stream, shows the
//! "daemon unavailable" banner, and automatically reconnects when the daemon
//! comes back.

#![deny(missing_docs)]

mod app;
mod dbus_client;
mod master_password;
mod settings;
mod tray;
mod ui;

use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use gtk4::prelude::{ApplicationExt, ApplicationExtManual};
use libadwaita as adw;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

use app::AppState;
use dbus_client::{fetch_initial_state, fetch_initial_ssh_state};
use settings::AppSettings;
use ui::build_ui;

fn main() -> anyhow::Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stdout)
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "supermgr starting");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    let app_state: Arc<Mutex<AppState>> = Arc::new(Mutex::new(AppState::default()));
    let app_settings: Arc<Mutex<AppSettings>> = Arc::new(Mutex::new(AppSettings::load()));

    // Fetch initial daemon state (auto-starting supermgrd via pkexec if needed)
    // before showing the window so the first paint reflects reality.
    {
        let app_state = Arc::clone(&app_state);
        rt.block_on(async move {
            match fetch_initial_state(&app_state).await {
                Ok(()) => info!("connected to supermgrd daemon"),
                Err(e) => error!("could not reach supermgrd: {:#}", e),
            }
            match fetch_initial_ssh_state(&app_state).await {
                Ok(()) => info!("loaded SSH keys and hosts"),
                Err(e) => error!("could not load SSH state: {:#}", e),
            }
        });
    }

    let rt_handle = rt.handle().clone();
    let app = adw::Application::builder()
        .application_id("org.supermgr.SuperManager")
        .build();

    let app_state_for_activate = Arc::clone(&app_state);
    let app_settings_for_activate = Arc::clone(&app_settings);
    app.connect_activate(move |app| {
        build_ui(
            app,
            Arc::clone(&app_state_for_activate),
            Arc::clone(&app_settings_for_activate),
            rt_handle.clone(),
        );
    });

    let exit = app.run();
    if exit != gtk4::glib::ExitCode::SUCCESS {
        anyhow::bail!("GTK application exited with non-zero exit code");
    }
    Ok(())
}
