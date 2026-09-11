//! Shared split panes and persisted window geometry.
use crate::settings::AppSettings;
use gtk4::prelude::*;
use libadwaita::{self as adw, prelude::*};
use std::sync::{Arc, Mutex};

pub fn split(
    sidebar: &impl IsA<gtk4::Widget>,
    content: &impl IsA<gtk4::Widget>,
    width: i32,
) -> gtk4::Paned {
    sidebar.set_size_request(240, -1);
    sidebar.add_css_class("supermgr-list-pane");
    let pane = gtk4::Paned::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .start_child(sidebar)
        .end_child(content)
        .resize_start_child(false)
        .resize_end_child(true)
        .shrink_start_child(false)
        .shrink_end_child(false)
        .wide_handle(true)
        .position(width)
        .vexpand(true)
        .hexpand(true)
        .css_classes(["supermgr-split"])
        .build();
    pane
}

pub fn remember_split(
    pane: &gtk4::Paned,
    settings: &Arc<Mutex<AppSettings>>,
    section: &'static str,
) {
    let initial = settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .layout
        .sidebar_widths
        .get(section)
        .copied()
        .unwrap_or(320)
        .clamp(240, 560);
    pane.set_position(initial);
    let settings = Arc::clone(settings);
    pane.connect_position_notify(move |pane| {
        if pane.is_mapped() && pane.position() >= 240 && pane.position() <= 560 {
            settings
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .layout
                .sidebar_widths
                .insert(section.into(), pane.position());
        }
    });
}

pub fn adapt_shell(window: &adw::ApplicationWindow, shell: &adw::OverlaySplitView) {
    let breakpoint =
        adw::Breakpoint::new(adw::BreakpointCondition::parse("max-width: 1050sp").unwrap());
    breakpoint.add_setter(shell, "collapsed", Some(&true.to_value()));
    breakpoint.add_setter(shell, "show-sidebar", Some(&false.to_value()));
    window.add_breakpoint(breakpoint);
}

pub fn remember_window(
    window: &adw::ApplicationWindow,
    app: &adw::Application,
    settings: &Arc<Mutex<AppSettings>>,
) {
    let saved = settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .layout
        .clone();
    window.set_default_size(
        saved.window_width.clamp(760, 3840),
        saved.window_height.clamp(540, 2160),
    );
    if saved.maximized {
        window.maximize();
    }
    let window = window.clone();
    let settings = Arc::clone(settings);
    app.connect_shutdown(move |_| {
        let mut settings = settings.lock().unwrap_or_else(|e| e.into_inner());
        settings.layout.maximized = window.is_maximized();
        // GTK maintains the most recent normal size across maximize/fullscreen.
        let (width, height) = window.default_size();
        settings.layout.window_width = width.clamp(760, 3840);
        settings.layout.window_height = height.clamp(540, 2160);
        settings.save();
    });
}
