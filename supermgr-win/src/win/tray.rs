//! The notification-area icon.
//!
//! [`tray_icon`] wraps `Shell_NotifyIconW`. The icon is the app's own (the
//! same artwork as the Linux tray and the macOS menu bar); its tooltip says
//! where the tunnel stands, and its menu opens the window, disconnects, or
//! quits. A left click opens the window.
//!
//! Menu and click events arrive on channels polled by one thread each and
//! are handed to the Slint event loop. The icon itself is not `Send`, so it
//! lives in a thread-local on the UI thread, where the tooltip is updated.

use std::cell::RefCell;

use slint::ComponentHandle as _;
use tracing::warn;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
};

use super::{App, Ctx, Page, Updates};

thread_local! {
    static TRAY: RefCell<Option<TrayIcon>> = const { RefCell::new(None) };
}

/// The app icon at 64×64, ARGB32 in network byte order — the format the
/// Linux tray takes, shared so both trays show the same pixels.
const ICON_ARGB: &[u8] = include_bytes!("../../../contrib/icons/tray-icon-64.argb32");
const ICON_SIZE: u32 = 64;

/// Create the icon. Call on the UI thread; a failure costs the tray, not
/// the app.
pub(super) fn install(ctx: &Ctx) {
    let menu = Menu::new();
    let open = MenuItem::new("Open SuperManager", true, None);
    let disconnect = MenuItem::new("Disconnect VPN", true, None);
    let updates = MenuItem::new("Check for updates\u{2026}", true, None);
    let quit = MenuItem::new("Quit SuperManager", true, None);

    if let Err(e) = menu.append_items(&[
        &open,
        &PredefinedMenuItem::separator(),
        &disconnect,
        &PredefinedMenuItem::separator(),
        &updates,
        &quit,
    ]) {
        warn!("tray menu: {e}");
        return;
    }

    let icon = match Icon::from_rgba(rgba(ICON_ARGB), ICON_SIZE, ICON_SIZE) {
        Ok(i) => i,
        Err(e) => {
            warn!("tray icon: {e}");
            return;
        }
    };

    let tray = match TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip("SuperManager")
        .with_icon(icon)
        .build()
    {
        Ok(t) => t,
        Err(e) => {
            warn!("tray: {e}");
            return;
        }
    };
    TRAY.with(|slot| *slot.borrow_mut() = Some(tray));

    let (open_id, disconnect_id, updates_id, quit_id) = (
        open.id().clone(),
        disconnect.id().clone(),
        updates.id().clone(),
        quit.id().clone(),
    );
    let menu_ctx = ctx.clone();
    std::thread::spawn(move || {
        while let Ok(event) = MenuEvent::receiver().recv() {
            let ctx = &menu_ctx;
            if event.id == open_id {
                show(ctx, Some(Page::Vpn));
            } else if event.id == disconnect_id {
                let ctx2 = ctx.clone();
                ctx.spawn(async move {
                    match ctx2.call(|c| async move { c.disconnect().await }).await {
                        Ok(()) => ctx2.refresh_status(),
                        Err(e) => ctx2.toast_err(format!("Couldn't disconnect: {e}")),
                    }
                });
            } else if event.id == updates_id {
                show(ctx, Some(Page::Settings));
                ctx.ui(|w| w.global::<Updates>().invoke_check());
            } else if event.id == quit_id {
                let _ = slint::invoke_from_event_loop(|| {
                    slint::quit_event_loop().ok();
                });
                return;
            }
        }
    });

    let click_ctx = ctx.clone();
    std::thread::spawn(move || {
        while let Ok(event) = TrayIconEvent::receiver().recv() {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show(&click_ctx, None);
            }
        }
    });
}

/// Bring the window up, on `page` if given.
fn show(ctx: &Ctx, page: Option<Page>) {
    ctx.ui(move |w| {
        let _ = w.show();
        w.window().set_minimized(false);
        if let Some(page) = page {
            w.global::<App>().set_page(page);
        }
    });
}

/// Say where the tunnel stands. Call on the UI thread.
pub(super) fn set_tooltip(text: &str) {
    TRAY.with(|slot| {
        if let Some(tray) = slot.borrow().as_ref() {
            if let Err(e) = tray.set_tooltip(Some(text)) {
                warn!("tray tooltip: {e}");
            }
        }
    });
}

/// ARGB32 (network order) to the RGBA `tray_icon` takes.
fn rgba(argb: &[u8]) -> Vec<u8> {
    argb.chunks_exact(4)
        .flat_map(|px| [px[1], px[2], px[3], px[0]])
        .collect()
}
