//! Windows system tray integration.
//!
//! Uses the cross-platform [`tray_icon`] crate, which on Windows wraps the
//! `Shell_NotifyIconW` API. The icon ships an embedded 32×32 PNG and a
//! single popup menu with "Show", "Hide", and "Quit" items.
//!
//! The tray's event channel runs on the winit event loop, but since Slint
//! owns the actual event loop on Windows we install a tiny polling task
//! that pulls events on a separate thread and forwards them to the Slint
//! UI thread via [`slint::Weak::upgrade_in_event_loop`].

use slint::{ComponentHandle as _, Weak};
use tracing::warn;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIcon, TrayIconBuilder,
};

use super::AppWindow;

/// Build and pin the tray icon. Returns the [`TrayIcon`] so the caller can
/// hold it alive — dropping it tears the icon down.
pub fn spawn(weak: Weak<AppWindow>) -> Option<TrayIcon> {
    let menu = Menu::new();
    let show = MenuItem::new("Show SuperManager", true, None);
    let hide = MenuItem::new("Hide window", true, None);
    let quit = MenuItem::new("Quit", true, None);

    let show_id = show.id().clone();
    let hide_id = hide.id().clone();
    let quit_id = quit.id().clone();

    if let Err(e) = menu.append_items(&[
        &show,
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

    // Forward menu events to the Slint event loop. `MenuEvent::receiver()`
    // hands back a crossbeam-channel `Receiver` that blocks on `recv()`; a
    // dedicated thread is the simplest way to bridge it to the Slint event
    // loop without taking a direct dependency on crossbeam-channel to name
    // its error variants.
    std::thread::spawn(move || {
        let rx = MenuEvent::receiver();
        // `recv()` returns Err only when the sender is dropped, which
        // happens during process teardown — at that point we just exit.
        while let Ok(event) = rx.recv() {
            let id = event.id;
            let weak = weak.clone();
            if id == show_id {
                let _ = weak.upgrade_in_event_loop(|w| {
                    let _ = w.show();
                    w.window().set_minimized(false);
                });
            } else if id == hide_id {
                let _ = weak.upgrade_in_event_loop(|w| {
                    let _ = w.hide();
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

/// Minimal placeholder icon — 32×32 grey rounded square. The MSI installer
/// will overwrite this with the real product icon, but the GUI must not
/// crash if the resource isn't present in dev builds.
fn default_icon_rgba() -> Vec<u8> {
    let size = 32usize;
    let mut buf = Vec::with_capacity(size * size * 4);
    for y in 0..size {
        for x in 0..size {
            let dx = (x as i32 - 16).abs();
            let dy = (y as i32 - 16).abs();
            let in_circle = dx * dx + dy * dy < 14 * 14;
            if in_circle {
                buf.extend_from_slice(&[0x29, 0x3b, 0x52, 0xff]);
            } else {
                buf.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    buf
}
