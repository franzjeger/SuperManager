//! Windows system tray integration.
//!
//! Uses the cross-platform [`tray_icon`] crate, which on Windows wraps
//! `Shell_NotifyIconW`. Two menu items in addition to Show/Hide/Quit:
//! "Quick disconnect" triggers a daemon `disconnect()` without opening
//! the window, and "Dashboard" opens the window directly on the
//! Dashboard tab.
//!
//! The MenuEvent receiver is a crossbeam channel that's polled by a
//! dedicated thread; events are bridged into the Slint event loop via
//! `slint::Weak::upgrade_in_event_loop`. The quick-disconnect path
//! reaches the daemon through the shared `ConnectionSlot`.

use std::sync::Arc;

use slint::{ComponentHandle as _, Weak};
use tokio::sync::Mutex;
use tracing::warn;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIcon, TrayIconBuilder,
};

use super::AppWindow;
use supermgr_core::client;

type ConnectionSlot = Arc<Mutex<Option<Arc<client::DaemonClient>>>>;

pub fn spawn(
    weak: Weak<AppWindow>,
    conn: ConnectionSlot,
    rt: tokio::runtime::Handle,
) -> Option<TrayIcon> {
    let menu = Menu::new();
    let dashboard = MenuItem::new("Dashboard", true, None);
    let show = MenuItem::new("Show window", true, None);
    let hide = MenuItem::new("Hide window", true, None);
    let disconnect = MenuItem::new("Quick disconnect VPN", true, None);
    let quit = MenuItem::new("Quit", true, None);

    let dashboard_id = dashboard.id().clone();
    let show_id = show.id().clone();
    let hide_id = hide.id().clone();
    let disconnect_id = disconnect.id().clone();
    let quit_id = quit.id().clone();

    if let Err(e) = menu.append_items(&[
        &dashboard,
        &show,
        &PredefinedMenuItem::separator(),
        &disconnect,
        &PredefinedMenuItem::separator(),
        &hide,
        &PredefinedMenuItem::separator(),
        &quit,
    ]) {
        warn!("tray menu append: {e}");
        return None;
    }

    let icon = match Icon::from_rgba(default_icon_rgba(), 32, 32) {
        Ok(i) => i,
        Err(e) => {
            warn!("tray icon decode: {e}");
            return None;
        }
    };

    let tray = match TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("SuperManager")
        .with_icon(icon)
        .build()
    {
        Ok(t) => t,
        Err(e) => {
            warn!("tray build: {e}");
            return None;
        }
    };

    // Dedicated thread polling the MenuEvent channel. `recv()` blocks
    // until a menu item is clicked or the sender drops (process
    // teardown).
    std::thread::spawn(move || {
        let rx = MenuEvent::receiver();
        while let Ok(event) = rx.recv() {
            let id = event.id;
            let weak = weak.clone();
            if id == dashboard_id {
                let _ = weak.upgrade_in_event_loop(|w| {
                    let _ = w.show();
                    w.window().set_minimized(false);
                    w.set_current_view(0);
                });
            } else if id == show_id {
                let _ = weak.upgrade_in_event_loop(|w| {
                    let _ = w.show();
                    w.window().set_minimized(false);
                });
            } else if id == hide_id {
                let _ = weak.upgrade_in_event_loop(|w| {
                    let _ = w.hide();
                });
            } else if id == disconnect_id {
                let conn = conn.clone();
                rt.spawn(async move {
                    let client = {
                        let guard = conn.lock().await;
                        guard.clone()
                    };
                    if let Some(c) = client {
                        match c.disconnect().await {
                            Ok(()) => {
                                let _ = weak.upgrade_in_event_loop(|w| {
                                    w.set_last_status_message("VPN disconnected.".into());
                                });
                            }
                            Err(e) => {
                                warn!("tray disconnect: {e}");
                                let _ = weak.upgrade_in_event_loop(move |w| {
                                    w.set_last_error(
                                        slint::SharedString::from(format!("Disconnect: {e}")),
                                    );
                                });
                            }
                        }
                    }
                });
            } else if id == quit_id {
                let _ = weak.upgrade_in_event_loop(|w| {
                    let _ = w.hide();
                    slint::quit_event_loop().ok();
                });
                return;
            }
        }
    });

    Some(tray)
}

/// Synthetic placeholder icon — 32×32 SuperManager-blue disc. The MSI
/// can later overwrite this with a real product icon by placing a
/// `tray.ico` next to the binary; not load-bearing for the MVP.
fn default_icon_rgba() -> Vec<u8> {
    let size = 32usize;
    let mut buf = Vec::with_capacity(size * size * 4);
    for y in 0..size {
        for x in 0..size {
            let dx = (x as i32 - 16).abs();
            let dy = (y as i32 - 16).abs();
            let in_circle = dx * dx + dy * dy < 14 * 14;
            if in_circle {
                buf.extend_from_slice(&[0x6e, 0xc1, 0xff, 0xff]);
            } else {
                buf.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    buf
}
