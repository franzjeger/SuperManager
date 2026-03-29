//! UI construction — builds the unified VPN + SSH window and drain loop.
//!
//! # Widget hierarchy
//!
//! ```text
//! AdwApplicationWindow
//! └── AdwToolbarView
//!     ├── [top] AdwHeaderBar
//!     │   ├── [title] AdwViewSwitcher
//!     │   └── [end] settings button, add button
//!     └── [content] AdwToastOverlay
//!         └── GtkBox (vertical)
//!             ├── AdwBanner ("daemon unavailable")
//!             └── AdwViewStack
//!                 ├── "vpn": vpn_page (AdwNavigationSplitView)
//!                 │   ├── sidebar: VPN profile list
//!                 │   └── content: VPN detail/empty
//!                 └── "ssh": ssh_page (AdwNavigationSplitView)
//!                     ├── sidebar: GtkStack (keys/hosts tabs)
//!                     └── content: SSH detail/empty
//! ```
#![allow(missing_docs)]

pub mod console;
pub mod navigation;
pub mod provisioning;
pub mod ssh;
pub mod vpn;

use std::sync::{mpsc, Arc, Mutex};

use gtk4::{gio, glib, prelude::*};
use ksni::TrayMethods as _;
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use supermgr_core::vpn::{profile::ProfileSummary, state::VpnState};
use supermgr_core::ssh::key::SshKeySummary;
use supermgr_core::ssh::host::SshHostSummary;

use crate::app::{AppMsg, AppState};
use crate::dbus_client::{
    dbus_connect, dbus_disconnect, dbus_export_profile, dbus_get_state,
    dbus_list_profiles, dbus_set_auto_connect, dbus_set_full_tunnel,
    dbus_set_kill_switch, dbus_set_split_routes,
    fetch_initial_state, fetch_initial_ssh_state, run_signal_listener,
};
use crate::settings::{AppSettings, ColorScheme};
use crate::tray::VpnTray;

use self::vpn::detail::{apply_vpn_state, VpnDetail};
use self::vpn::sidebar::populate_vpn_sidebar;
use self::ssh::key_list::populate_ssh_key_list;
use self::ssh::host_tree::populate_ssh_host_list;
use self::ssh::host_detail::launch_ssh_terminal;

// ---------------------------------------------------------------------------
// Formatting helpers (shared by sidebar/detail)
// ---------------------------------------------------------------------------

/// Format a byte count as a human-readable string.
pub fn format_bytes(n: u64) -> String {
    const KIB: u64 = 1_024;
    const MIB: u64 = 1_024 * KIB;
    const GIB: u64 = 1_024 * MIB;
    if n >= GIB {
        format!("{:.1} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

/// Format elapsed seconds as "X ago".
pub fn format_ago(elapsed_secs: u64) -> String {
    if elapsed_secs < 60 {
        let s = elapsed_secs;
        format!("{s} second{} ago", if s == 1 { "" } else { "s" })
    } else if elapsed_secs < 3_600 {
        let m = elapsed_secs / 60;
        format!("{m} minute{} ago", if m == 1 { "" } else { "s" })
    } else {
        let h = elapsed_secs / 3_600;
        format!("{h} hour{} ago", if h == 1 { "" } else { "s" })
    }
}

// ---------------------------------------------------------------------------
// Tray update helper
// ---------------------------------------------------------------------------

/// Push updated state and profile list to the system tray.
fn push_tray_update(
    tray_handle: &Arc<Mutex<Option<ksni::Handle<VpnTray>>>>,
    new_state: VpnState,
    new_profiles: Vec<ProfileSummary>,
    rt: &tokio::runtime::Handle,
) {
    let handle = match tray_handle.lock().expect("tray_handle poisoned").as_ref() {
        Some(h) => h.clone(),
        None => return,
    };
    rt.spawn(async move {
        handle
            .update(|tray| {
                tray.vpn_state = new_state;
                tray.profiles = new_profiles;
            })
            .await;
    });
}

// ---------------------------------------------------------------------------
// Lock screen page
// ---------------------------------------------------------------------------

/// Widgets composing the lock / set-password page.
#[derive(Clone)]
struct LockPage {
    container: gtk4::Box,
    password_row: adw::PasswordEntryRow,
    confirm_row: adw::PasswordEntryRow,
    unlock_btn: gtk4::Button,
    set_btn: gtk4::Button,
    status_label: gtk4::Label,
}

/// Build the lock screen page (password entry + unlock / set-password buttons).
fn build_lock_page() -> LockPage {
    let container = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .halign(gtk4::Align::Center)
        .valign(gtk4::Align::Center)
        .spacing(24)
        .margin_start(48)
        .margin_end(48)
        .build();

    let icon = gtk4::Image::builder()
        .icon_name("system-lock-screen-symbolic")
        .pixel_size(64)
        .build();
    container.append(&icon);

    let title = gtk4::Label::builder()
        .label("SuperManager")
        .css_classes(["title-1"])
        .build();
    container.append(&title);

    let status_label = gtk4::Label::builder()
        .label("")
        .css_classes(["dim-label"])
        .wrap(true)
        .build();
    container.append(&status_label);

    let prefs_group = adw::PreferencesGroup::new();

    let password_row = adw::PasswordEntryRow::builder()
        .title("Master Password")
        .build();
    prefs_group.add(&password_row);

    let confirm_row = adw::PasswordEntryRow::builder()
        .title("Confirm Password")
        .build();
    prefs_group.add(&confirm_row);
    container.append(&prefs_group);

    let btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .halign(gtk4::Align::Center)
        .spacing(12)
        .build();

    let unlock_btn = gtk4::Button::builder()
        .label("Unlock")
        .css_classes(["suggested-action", "pill"])
        .build();
    btn_box.append(&unlock_btn);

    let set_btn = gtk4::Button::builder()
        .label("Set Password")
        .css_classes(["suggested-action", "pill"])
        .build();
    btn_box.append(&set_btn);
    container.append(&btn_box);

    LockPage {
        container,
        password_row,
        confirm_row,
        unlock_btn,
        set_btn,
        status_label,
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Build and present the main application window.
pub fn build_ui(
    app: &adw::Application,
    app_state: Arc<Mutex<AppState>>,
    app_settings: Arc<Mutex<AppSettings>>,
    rt: tokio::runtime::Handle,
) {
    // Apply persisted colour scheme.
    {
        let s = app_settings.lock().expect("lock");
        adw::StyleManager::default().set_color_scheme(s.adw_color_scheme());
    }

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("SuperManager")
        .default_width(1200)
        .default_height(750)
        .build();

    // Apply persisted opacity.
    {
        let s = app_settings.lock().expect("lock");
        window.set_opacity(s.opacity);
    }

    // Channel: tokio tasks -> GTK main thread, drained every 50 ms.
    let (tx, rx) = mpsc::channel::<AppMsg>();

    // =========================================================================
    // System tray
    // =========================================================================
    let tray_handle: Arc<Mutex<Option<ksni::Handle<VpnTray>>>> = Arc::new(Mutex::new(None));
    {
        let (initial_state, initial_profiles) = {
            let s = app_state.lock().expect("lock");
            (s.vpn_state.clone(), s.profiles.clone())
        };
        let vpn_tray = VpnTray {
            vpn_state: initial_state,
            profiles: initial_profiles,
            rt: rt.clone(),
            tx: tx.clone(),
        };
        let tray_handle_slot = Arc::clone(&tray_handle);
        rt.spawn(async move {
            match vpn_tray.spawn().await {
                Ok(handle) => {
                    *tray_handle_slot.lock().expect("tray_handle poisoned") = Some(handle);
                    info!("system tray registered");
                }
                Err(e) => {
                    error!("system tray unavailable: {e}");
                }
            }
        });
    }

    // =========================================================================
    // Header bar
    // =========================================================================

    // -- "Add" popover with VPN + SSH actions --------------------------------
    let popover = gtk4::Popover::new();
    let pop_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .spacing(2)
        .build();

    // VPN import buttons.
    let import_wg_btn = gtk4::Button::builder()
        .label("Import WireGuard .conf")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    let add_fg_btn = gtk4::Button::builder()
        .label("Add FortiGate connection")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    let import_ov_btn = gtk4::Button::builder()
        .label("Import OpenVPN .ovpn")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    let import_az_btn = gtk4::Button::builder()
        .label("Import Azure VPN config")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    let import_toml_btn = gtk4::Button::builder()
        .label("Import TOML config\u{2026}")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();

    // Separator.
    let sep = gtk4::Separator::new(gtk4::Orientation::Horizontal);

    // SSH action buttons.
    let ssh_gen_key_btn = gtk4::Button::builder()
        .label("Generate SSH Key")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    let ssh_add_host_btn = gtk4::Button::builder()
        .label("Add SSH Host")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    let ssh_import_keys_btn = gtk4::Button::builder()
        .label("Import SSH Keys\u{2026}")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();

    pop_box.append(&import_wg_btn);
    pop_box.append(&add_fg_btn);
    pop_box.append(&import_ov_btn);
    pop_box.append(&import_az_btn);
    pop_box.append(&import_toml_btn);
    pop_box.append(&sep);
    let ssh_audit_btn = gtk4::Button::builder()
        .label("SSH Audit Log\u{2026}")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    pop_box.append(&ssh_gen_key_btn);
    pop_box.append(&ssh_add_host_btn);
    pop_box.append(&ssh_import_keys_btn);
    pop_box.append(&ssh_audit_btn);
    popover.set_child(Some(&pop_box));

    let add_menu_btn = gtk4::MenuButton::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Add profile / key / host")
        .popover(&popover)
        .build();

    let logs_btn = gtk4::Button::builder()
        .icon_name("utilities-terminal-symbolic")
        .tooltip_text("View daemon logs")
        .build();

    let settings_btn = gtk4::Button::builder()
        .icon_name("preferences-system-symbolic")
        .tooltip_text("Settings")
        .build();

    // --- Primary (hamburger) menu with About action --------------------------
    let primary_menu = gio::Menu::new();
    primary_menu.append(Some("About SuperManager"), Some("win.about"));

    let hamburger_btn = gtk4::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .tooltip_text("Main menu")
        .menu_model(&primary_menu)
        .primary(true)
        .build();

    // =========================================================================
    // View stack: VPN + SSH pages
    // =========================================================================
    let view_stack = navigation::build_view_stack();
    let view_switcher = navigation::build_view_switcher(&view_stack);

    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&view_switcher));
    header.pack_end(&hamburger_btn);
    header.pack_end(&add_menu_btn);
    header.pack_end(&logs_btn);
    header.pack_end(&settings_btn);

    // -- Daemon-unavailable banner -------------------------------------------
    let banner = adw::Banner::new("Daemon not running");
    banner.set_button_label(Some("Retry"));
    {
        let available = app_state.lock().expect("lock").daemon_available;
        banner.set_revealed(!available);
    }

    // =========================================================================
    // VPN page
    // =========================================================================
    let (vpn_profile_list, vpn_sidebar_page) =
        vpn::sidebar::build_vpn_sidebar(&app_state, &tx, &rt, &window);
    let (vpn_detail, vpn_content_page) = vpn::detail::build_vpn_detail();

    let vpn_split = adw::NavigationSplitView::builder().vexpand(true).build();
    vpn_split.set_min_sidebar_width(280.0);
    vpn_split.set_max_sidebar_width(400.0);
    vpn_split.set_sidebar(Some(&vpn_sidebar_page));
    vpn_split.set_content(Some(&vpn_content_page));

    view_stack.add_titled(&vpn_split, Some("vpn"), "VPN");
    let vpn_page = view_stack.page(&vpn_split);
    vpn_page.set_icon_name(Some("network-vpn-symbolic"));

    // =========================================================================
    // SSH page
    // =========================================================================

    // SSH sidebar: a GtkStack with "keys" and "hosts" tabs, switched by a
    // linked toggle-button pair.
    let ssh_key_list = ssh::key_list::build_ssh_key_list();
    let ssh_host_list = ssh::host_tree::build_ssh_host_list();

    let ssh_sidebar_stack = gtk4::Stack::new();
    let ssh_key_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&ssh_key_list)
        .build();
    let ssh_host_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&ssh_host_list)
        .build();
    ssh_sidebar_stack.add_named(&ssh_key_scroll, Some("keys"));
    ssh_sidebar_stack.add_named(&ssh_host_scroll, Some("hosts"));

    let ssh_toggle_keys = gtk4::ToggleButton::builder()
        .label("Keys")
        .active(true)
        .build();
    let ssh_toggle_hosts = gtk4::ToggleButton::builder()
        .label("Hosts")
        .group(&ssh_toggle_keys)
        .build();
    let ssh_toggle_dashboard = gtk4::ToggleButton::builder()
        .label("Dashboard")
        .group(&ssh_toggle_keys)
        .build();
    let ssh_toggle_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 0);
    ssh_toggle_box.add_css_class("linked");
    ssh_toggle_box.append(&ssh_toggle_keys);
    ssh_toggle_box.append(&ssh_toggle_hosts);
    ssh_toggle_box.append(&ssh_toggle_dashboard);
    ssh_toggle_box.set_halign(gtk4::Align::Center);
    ssh_toggle_box.set_margin_top(8);
    ssh_toggle_box.set_margin_bottom(4);

    {
        let ssh_sidebar_stack = ssh_sidebar_stack.clone();
        ssh_toggle_keys.connect_toggled(move |btn| {
            if btn.is_active() {
                ssh_sidebar_stack.set_visible_child_name("keys");
            }
        });
    }
    {
        let ssh_sidebar_stack = ssh_sidebar_stack.clone();
        ssh_toggle_hosts.connect_toggled(move |btn| {
            if btn.is_active() {
                ssh_sidebar_stack.set_visible_child_name("hosts");
            }
        });
    }

    // Build the multi-device dashboard widget.
    let (dashboard_flow_box, dashboard_widget) =
        ssh::dashboard::build_ssh_dashboard(&app_state, &rt, &tx);

    // SSH sidebar search entry — filters both key and host lists.
    let ssh_search_entry = gtk4::SearchEntry::builder()
        .placeholder_text("Filter keys / hosts\u{2026}")
        .margin_start(8)
        .margin_end(8)
        .margin_top(8)
        .build();
    {
        let ssh_key_list = ssh_key_list.clone();
        let ssh_host_list = ssh_host_list.clone();
        let app_state = app_state.clone();
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_search_entry.connect_search_changed(move |entry| {
            let text = entry.text().to_string();
            let s = app_state.lock().expect("lock");
            populate_ssh_key_list(
                &ssh_key_list,
                &s.ssh_keys,
                s.selected_ssh_key.as_deref(),
                &window,
                &rt,
                &tx,
                &text,
            );
            let health = s.host_health.clone();
            populate_ssh_host_list(
                &ssh_host_list,
                &s.ssh_hosts,
                s.selected_ssh_host.as_deref(),
                &window,
                &rt,
                &tx,
                &text,
                &health,
            );
            drop(s);
            app_state.lock().expect("lock").ssh_filter = text;
        });
    }

    let ssh_sidebar_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    ssh_sidebar_box.append(&ssh_search_entry);
    ssh_sidebar_box.append(&ssh_toggle_box);
    ssh_sidebar_box.append(&ssh_sidebar_stack);

    let ssh_sidebar_page = adw::NavigationPage::builder()
        .title("SSH")
        .child(&ssh_sidebar_box)
        .build();

    // SSH content: stack that shows either key detail or host detail.
    let (ssh_key_detail, ssh_key_detail_widget) = ssh::key_detail::build_ssh_key_detail();
    let (ssh_host_detail, ssh_host_detail_widget) = ssh::host_detail::build_ssh_host_detail();

    let ssh_content_stack = gtk4::Stack::new();
    let ssh_empty_status = adw::StatusPage::builder()
        .title("SSH Manager")
        .description("Select a key or host from the sidebar to view details.")
        .icon_name("dialog-password-symbolic")
        .build();
    ssh_content_stack.add_named(&ssh_empty_status, Some("empty"));
    ssh_content_stack.add_named(&ssh_key_detail_widget, Some("key-detail"));
    ssh_content_stack.add_named(&ssh_host_detail_widget, Some("host-detail"));
    ssh_content_stack.add_named(&dashboard_widget, Some("dashboard"));
    ssh_content_stack.set_visible_child_name("empty");

    let ssh_content_page = adw::NavigationPage::builder()
        .title("Details")
        .child(&ssh_content_stack)
        .build();

    // Wire the "Dashboard" toggle to show the dashboard content.
    {
        let ssh_content_stack = ssh_content_stack.clone();
        ssh_toggle_dashboard.connect_toggled(move |btn| {
            if btn.is_active() {
                ssh_content_stack.set_visible_child_name("dashboard");
            }
        });
    }

    let ssh_split = adw::NavigationSplitView::builder().vexpand(true).build();
    ssh_split.set_min_sidebar_width(280.0);
    ssh_split.set_max_sidebar_width(400.0);
    ssh_split.set_sidebar(Some(&ssh_sidebar_page));
    ssh_split.set_content(Some(&ssh_content_page));

    view_stack.add_titled(&ssh_split, Some("ssh"), "SSH");
    let ssh_page_ref = view_stack.page(&ssh_split);
    ssh_page_ref.set_icon_name(Some("dialog-password-symbolic"));

    // Populate SSH lists with initial state.
    {
        let s = app_state.lock().expect("lock");
        populate_ssh_key_list(
            &ssh_key_list,
            &s.ssh_keys,
            s.selected_ssh_key.as_deref(),
            &window,
            &rt,
            &tx,
            "",
        );
        let health = s.host_health.clone();
        populate_ssh_host_list(
            &ssh_host_list,
            &s.ssh_hosts,
            s.selected_ssh_host.as_deref(),
            &window,
            &rt,
            &tx,
            "",
            &health,
        );
    }

    // =========================================================================
    // Console tab — built-in Claude AI chat
    // =========================================================================
    let (console_panel, console_widget) =
        console::panel::build_console_page(&app_state, &tx, &rt);

    view_stack.add_titled(&console_widget, Some("console"), "Console");
    let console_page_ref = view_stack.page(&console_widget);
    console_page_ref.set_icon_name(Some("utilities-terminal-symbolic"));

    // Console setup page is already handled internally by the stack.

    // =========================================================================
    // Provisioning tab — automated FortiGate/UniFi device setup wizard
    // =========================================================================
    let provisioning_widget =
        provisioning::wizard::build_provisioning_page(&app_state, &tx, &rt);

    view_stack.add_titled(&provisioning_widget, Some("provisioning"), "Provisioning");
    let provisioning_page_ref = view_stack.page(&provisioning_widget);
    provisioning_page_ref.set_icon_name(Some("emblem-system-symbolic"));

    // =========================================================================
    // Assemble the window
    // =========================================================================
    let root_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    root_box.append(&banner);
    root_box.append(&view_stack);

    let toast_overlay = adw::ToastOverlay::new();
    toast_overlay.set_child(Some(&root_box));

    let main_toolbar = adw::ToolbarView::new();
    main_toolbar.add_top_bar(&header);
    main_toolbar.set_content(Some(&toast_overlay));

    // =========================================================================
    // Lock screen (overlays entire app content via a GtkStack)
    // =========================================================================
    let lock_page = build_lock_page();
    let outer_stack = gtk4::Stack::builder()
        .transition_type(gtk4::StackTransitionType::Crossfade)
        .transition_duration(200)
        .build();
    outer_stack.add_named(&lock_page.container, Some("lock"));
    outer_stack.add_named(&main_toolbar, Some("app"));

    // Determine initial page: locked if password is set, otherwise app.
    {
        let s = app_settings.lock().expect("lock");
        if s.has_password() {
            outer_stack.set_visible_child_name("lock");
            lock_page.status_label.set_text("Enter your master password to unlock.");
            lock_page.set_btn.set_visible(false);
            lock_page.confirm_row.set_visible(false);
        } else {
            // No password yet — go straight to the app.
            outer_stack.set_visible_child_name("app");
        }
    }

    window.set_content(Some(&outer_stack));

    // =========================================================================
    // Inactivity timer — auto-lock after N minutes
    // =========================================================================
    // `inactivity_counter` counts elapsed seconds.  A 1-second tick
    // increments it; any user input resets it to 0.  When it reaches
    // `auto_lock_minutes * 60` and a password is set, we lock.
    let inactivity_counter: std::rc::Rc<std::cell::Cell<u64>> =
        std::rc::Rc::new(std::cell::Cell::new(0));

    // Reset inactivity on any key press or mouse click/motion.
    {
        let ctr = inactivity_counter.clone();
        let motion_ctrl = gtk4::EventControllerMotion::new();
        motion_ctrl.connect_motion(move |_, _, _| {
            ctr.set(0);
        });
        window.add_controller(motion_ctrl);
    }
    {
        let ctr = inactivity_counter.clone();
        let click_ctrl = gtk4::GestureClick::new();
        click_ctrl.connect_pressed(move |_, _, _, _| {
            ctr.set(0);
        });
        window.add_controller(click_ctrl);
    }
    {
        let ctr = inactivity_counter.clone();
        let key_inactivity_ctrl = gtk4::EventControllerKey::new();
        key_inactivity_ctrl.connect_key_pressed(move |_, _, _, _| {
            ctr.set(0);
            glib::Propagation::Proceed
        });
        window.add_controller(key_inactivity_ctrl);
    }

    // 1-second tick.
    {
        let ctr = inactivity_counter.clone();
        let outer_stack = outer_stack.clone();
        let lock_page = lock_page.clone();
        let app_settings = Arc::clone(&app_settings);
        glib::timeout_add_local(std::time::Duration::from_secs(1), move || {
            // Only tick when the app page is visible (not already locked).
            if outer_stack.visible_child_name().as_deref() == Some("app") {
                let cur = ctr.get() + 1;
                ctr.set(cur);
                let s = app_settings.lock().expect("lock");
                if s.has_password() && s.auto_lock_minutes > 0 {
                    let limit = s.auto_lock_minutes * 60;
                    if cur >= limit {
                        drop(s);
                        lock_session(&outer_stack, &lock_page);
                        ctr.set(0);
                    }
                }
            }
            glib::ControlFlow::Continue
        });
    }

    // Paint initial VPN state.
    {
        let s = app_state.lock().expect("lock");
        if s.selected_profile.is_some() {
            vpn_detail.detail_stack.set_visible_child_name("detail");
        }
        apply_vpn_state(
            &vpn_detail.connect_btn,
            &vpn_detail.rename_btn,
            &vpn_detail.status_label,
            &vpn_detail.stats_box,
            &s,
        );
    }

    // =========================================================================
    // Signal handlers
    // =========================================================================

    // --- Settings button ----------------------------------------------------
    {
        let window = window.clone();
        let app_settings = Arc::clone(&app_settings);
        let tx = tx.clone();
        let rt = rt.clone();
        settings_btn.connect_clicked(move |_| {
            vpn::dialogs::show_settings_dialog(
                &window,
                Arc::clone(&app_settings),
                &tx,
                &rt,
            );
        });
    }

    // --- About action (hamburger menu) ----------------------------------------
    {
        let window_for_about = window.clone();
        let about_action = gio::SimpleAction::new("about", None);
        about_action.connect_activate(move |_, _| {
            show_about_dialog(&window_for_about);
        });
        window.add_action(&about_action);
    }

    // --- Logs button --------------------------------------------------------
    {
        let window = window.clone();
        let rt = rt.clone();
        let app_settings = Arc::clone(&app_settings);
        logs_btn.connect_clicked(move |_| {
            vpn::dialogs::show_logs_dialog(&window, &rt, Arc::clone(&app_settings));
        });
    }

    // --- VPN import/add buttons ---------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let toast_overlay = toast_overlay.clone();
        let popover = popover.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        import_wg_btn.connect_clicked(move |_| {
            popover.popdown();
            vpn::dialogs::import_wireguard(
                &window,
                &app_state,
                &toast_overlay,
                &tx,
                &rt,
            );
        });
    }
    {
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        let popover = popover.clone();
        add_fg_btn.connect_clicked(move |_| {
            popover.popdown();
            vpn::dialogs::show_fortigate_dialog(&window, &rt, &tx);
        });
    }
    {
        let app_state = Arc::clone(&app_state);
        let toast_overlay = toast_overlay.clone();
        let popover = popover.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        import_ov_btn.connect_clicked(move |_| {
            popover.popdown();
            vpn::dialogs::import_openvpn(
                &window,
                &app_state,
                &toast_overlay,
                &tx,
                &rt,
            );
        });
    }
    {
        let popover = popover.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        import_az_btn.connect_clicked(move |_| {
            popover.popdown();
            vpn::dialogs::show_azure_import_dialog(&window, &rt, &tx);
        });
    }

    {
        let app_state = Arc::clone(&app_state);
        let toast_overlay = toast_overlay.clone();
        let popover = popover.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        import_toml_btn.connect_clicked(move |_| {
            popover.popdown();
            vpn::dialogs::import_toml_config(
                &window,
                &app_state,
                &toast_overlay,
                &tx,
                &rt,
            );
        });
    }

    // --- SSH add buttons ----------------------------------------------------
    {
        let popover = popover.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        ssh_gen_key_btn.connect_clicked(move |_| {
            popover.popdown();
            ssh::dialogs::show_generate_key_dialog(&window, &rt, &tx);
        });
    }
    {
        let popover = popover.clone();
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        ssh_add_host_btn.connect_clicked(move |_| {
            popover.popdown();
            let s = app_state.lock().expect("lock");
            ssh::dialogs::show_add_host_dialog(&window, &s.ssh_keys, &rt, &tx);
        });
    }
    {
        let popover = popover.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        ssh_import_keys_btn.connect_clicked(move |_| {
            popover.popdown();
            ssh::dialogs::show_import_keys_dialog(&window, &rt, &tx);
        });
    }
    {
        let popover = popover.clone();
        let rt = rt.clone();
        let window = window.clone();
        ssh_audit_btn.connect_clicked(move |_| {
            popover.popdown();
            ssh::dialogs::show_audit_log_dialog(&window, &rt);
        });
    }

    // --- VPN profile row activated (sidebar selection) -----------------------
    {
        let app_state = Arc::clone(&app_state);
        let connect_btn = vpn_detail.connect_btn.clone();
        let rename_btn = vpn_detail.rename_btn.clone();
        let edit_creds_btn = vpn_detail.edit_creds_btn.clone();
        let status_label = vpn_detail.status_label.clone();
        let stats_box = vpn_detail.stats_box.clone();
        let detail_stack = vpn_detail.detail_stack.clone();
        let vpn_content_page = vpn_content_page.clone();
        let profile_name_label = vpn_detail.profile_name_label.clone();
        let auto_connect_switch = vpn_detail.auto_connect_switch.clone();
        let full_tunnel_switch = vpn_detail.full_tunnel_switch.clone();
        let kill_switch_switch = vpn_detail.kill_switch_switch.clone();
        let rotate_key_btn = vpn_detail.rotate_key_btn.clone();
        let export_btn = vpn_detail.export_btn.clone();
        let split_routes_row = vpn_detail.split_routes_row.clone();
        let split_routes_value = vpn_detail.split_routes_value.clone();
        vpn_profile_list.connect_row_activated(move |list, row| {
            let idx = row.index() as usize;
            let (profile_name, profile_exists, ac, ft, ks, supports_split, split_routes, is_editable, is_wg) = {
                let mut s = app_state.lock().expect("lock");
                let mut sorted: Vec<&ProfileSummary> = s.profiles.iter().collect();
                sorted.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
                let entry = sorted.get(idx).copied();
                let name = entry.map(|p| p.name.clone());
                let exists = entry.is_some();
                let ac = entry.map_or(false, |p| p.auto_connect);
                let ft = entry.map_or(true, |p| p.full_tunnel);
                let ks = entry.map_or(false, |p| p.kill_switch);
                let supports = entry.map_or(false, |p| {
                    p.backend == "WireGuard" || p.backend.starts_with("FortiGate")
                });
                let routes = entry.map(|p| p.split_routes.clone()).unwrap_or_default();
                let editable = entry.map_or(false, |p| {
                    p.backend == "OpenVPN3" || p.backend.starts_with("FortiGate")
                });
                let wg = entry.map_or(false, |p| p.backend == "WireGuard");
                s.selected_profile = entry.map(|p| p.id.to_string());
                if matches!(s.vpn_state, VpnState::Error { .. }) {
                    s.vpn_state = VpnState::Disconnected;
                }
                (name, exists, ac, ft, ks, supports, routes, editable, wg)
            };

            if profile_exists {
                if let Some(ref name) = profile_name {
                    vpn_content_page.set_title(name);
                    profile_name_label.set_label(name.as_str());
                }
                auto_connect_switch.set_active(ac);
                auto_connect_switch.set_sensitive(true);
                full_tunnel_switch.set_active(ft);
                full_tunnel_switch.set_sensitive(true);
                kill_switch_switch.set_active(ks);
                kill_switch_switch.set_sensitive(true);
                edit_creds_btn.set_visible(is_editable);
                rotate_key_btn.set_visible(is_wg);
                export_btn.set_sensitive(true);
                let show_split = supports_split && !ft;
                split_routes_row.set_visible(show_split);
                if show_split {
                    if split_routes.is_empty() {
                        split_routes_value.set_label("None configured \u{2014} add CIDRs via Edit");
                    } else {
                        split_routes_value.set_label(&split_routes.join(", "));
                    }
                }
                detail_stack.set_visible_child_name("detail");
            }

            if let Some(r) = list.row_at_index(idx as i32) {
                list.select_row(Some(&r));
            }

            let s = app_state.lock().expect("lock");
            rename_btn.set_sensitive(s.selected_profile.is_some());
            apply_vpn_state(&connect_btn, &rename_btn, &status_label, &stats_box, &s);
        });
    }

    // --- SSH key list selection ----------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let ssh_content_stack = ssh_content_stack.clone();
        let ssh_key_detail = &ssh_key_detail;
        let key_name_label = ssh_key_detail.key_name_label.clone();
        let key_type_badge = ssh_key_detail.key_type_badge.clone();
        let fingerprint_label = ssh_key_detail.fingerprint_label.clone();
        let public_key_view = ssh_key_detail.public_key_view.clone();
        let tags_label = ssh_key_detail.tags_label.clone();
        let deployed_list = ssh_key_detail.deployed_list.clone();
        let key_detail_stack = ssh_key_detail.detail_stack.clone();
        let rt_for_key = rt.clone();
        let tx_for_key = tx.clone();
        ssh_key_list.connect_row_activated(move |_list, row| {
            let idx = row.index() as usize;
            let mut s = app_state.lock().expect("lock");
            let mut sorted: Vec<SshKeySummary> = s.ssh_keys.clone();
            sorted.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
            if let Some(key) = sorted.get(idx) {
                key_name_label.set_label(&key.name);
                key_type_badge.set_label(&format!("{:?}", key.key_type));
                fingerprint_label.set_label(&key.fingerprint);
                if key.tags.is_empty() {
                    tags_label.set_visible(false);
                } else {
                    tags_label.set_label(&format!("Tags: {}", key.tags.join(", ")));
                    tags_label.set_visible(true);
                }

                // Clear deployed-to list
                while let Some(child) = deployed_list.first_child() {
                    deployed_list.remove(&child);
                }
                let deployed_row = adw::ActionRow::builder()
                    .title(&format!("Deployed to {} host(s)", key.deployed_count))
                    .activatable(false)
                    .build();
                deployed_list.append(&deployed_row);

                key_detail_stack.set_visible_child_name("detail");
                ssh_content_stack.set_visible_child_name("key-detail");
                s.selected_ssh_key = Some(key.id.to_string());
                s.selected_ssh_host = None;

                // Fetch public key text asynchronously via the message channel
                let key_id = key.id.to_string();
                let tx2 = tx_for_key.clone();
                rt_for_key.spawn(async move {
                    match crate::dbus_client::dbus_ssh_export_public_key(key_id).await {
                        Ok(pubkey) => {
                            let _ = tx2.send(AppMsg::SshPublicKeyFetched(pubkey));
                        }
                        Err(e) => {
                            tracing::error!("fetch public key: {e}");
                        }
                    }
                });
            }
        });
    }

    // --- SSH host list selection ---------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let ssh_content_stack = ssh_content_stack.clone();
        let host_detail = ssh_host_detail.clone();
        let host_label_lbl = host_detail.host_label_lbl.clone();
        let group_badge = host_detail.group_badge.clone();
        let hostname_row = host_detail.hostname_row.clone();
        let port_row = host_detail.port_row.clone();
        let username_row = host_detail.username_row.clone();
        let device_type_row = host_detail.device_type_row.clone();
        let auth_method_row = host_detail.auth_method_row.clone();
        let host_detail_stack = host_detail.detail_stack.clone();
        let ssh_host_detail_for_closure = ssh_host_detail.clone();
        let rt_sel = rt.clone();
        let tx_sel = tx.clone();
        ssh_host_list.connect_row_activated(move |_list, row| {
            // Skip non-selectable group header rows.
            if !row.is_selectable() {
                return;
            }
            let idx = row.index();
            let mut s = app_state.lock().expect("lock");
            // Reconstruct the grouped order to find which host this row maps to.
            let mut groups: std::collections::BTreeMap<String, Vec<SshHostSummary>> =
                std::collections::BTreeMap::new();
            for host in &s.ssh_hosts {
                let group_name = if host.group.is_empty() {
                    "Ungrouped".to_owned()
                } else {
                    host.group.clone()
                };
                groups.entry(group_name).or_default().push(host.clone());
            }
            for hosts in groups.values_mut() {
                hosts.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));
            }
            // Flatten with group headers as None.
            let mut flat: Vec<Option<SshHostSummary>> = Vec::new();
            for (_group_name, hosts_in_group) in &groups {
                flat.push(None); // group header
                for h in hosts_in_group {
                    flat.push(Some(h.clone()));
                }
            }

            if let Some(Some(host)) = flat.get(idx as usize) {
                ssh::host_detail::update_ssh_host_detail(&ssh_host_detail_for_closure, host);
                ssh_content_stack.set_visible_child_name("host-detail");
                s.selected_ssh_host = Some(host.id.to_string());
                s.selected_ssh_key = None;

                // Auto-refresh FortiGate dashboard if applicable.
                if host.device_type == supermgr_core::ssh::DeviceType::Fortigate && host.has_api {
                    ssh::host_detail::refresh_fortigate_dashboard(
                        host.id.to_string(),
                        host.hostname.clone(),
                        host.api_port.unwrap_or(443),
                        &rt_sel,
                        &tx_sel,
                    );
                }
            }
        });
    }

    // --- FortiGate dashboard refresh button -----------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_detail.fg_refresh_btn.connect_clicked(move |_| {
            let s = app_state.lock().expect("lock");
            if let Some(host_id) = &s.selected_ssh_host {
                if let Some(host) = s.ssh_hosts.iter().find(|h| h.id.to_string() == *host_id) {
                    ssh::host_detail::refresh_fortigate_dashboard(
                        host_id.clone(),
                        host.hostname.clone(),
                        host.api_port.unwrap_or(443),
                        &rt,
                        &tx,
                    );
                }
            }
        });
    }

    // --- FortiGate backup config button -----------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_detail.fg_backup_btn.connect_clicked(move |_| {
            let s = app_state.lock().expect("lock");
            if let Some(host_id) = &s.selected_ssh_host {
                let host_id = host_id.clone();
                let tx = tx.clone();
                rt.spawn(async move {
                    let result = async {
                        let conn = zbus::Connection::system().await?;
                        let proxy = supermgr_core::dbus::DaemonProxy::new(&conn).await?;
                        let filename = proxy.fortigate_backup_config(&host_id).await
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        Ok::<String, anyhow::Error>(filename)
                    }
                    .await;
                    let msg = match result {
                        Ok(filename) => AppMsg::FortigateBackupDone {
                            host_id,
                            result: Ok(filename),
                        },
                        Err(e) => AppMsg::FortigateBackupDone {
                            host_id,
                            result: Err(e.to_string()),
                        },
                    };
                    let _ = tx.send(msg);
                });
            }
        });
    }

    // --- FortiGate compliance check button -----------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_detail.fg_compliance_btn.connect_clicked(move |_| {
            let s = app_state.lock().expect("lock");
            if let Some(host_id) = &s.selected_ssh_host {
                ssh::host_detail::run_fortigate_compliance(
                    host_id.clone(),
                    &rt,
                    &tx,
                );
            }
        });
    }

    // --- FortiGate Generate API Token button ----------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let toast_overlay = toast_overlay.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_detail.fg_gen_token_btn.connect_clicked(move |_| {
            let host_id = {
                let s = app_state.lock().expect("lock");
                s.selected_ssh_host.clone()
            };
            if let Some(host_id) = host_id {
                let tx = tx.clone();
                toast_overlay.add_toast(adw::Toast::new("Generating API token via SSH..."));
                rt.spawn(async move {
                    let conn = zbus::Connection::system().await.ok();
                    let proxy = if let Some(c) = &conn {
                        supermgr_core::dbus::DaemonProxy::new(c).await.ok()
                    } else { None };
                    if let Some(proxy) = proxy {
                        match proxy.fortigate_generate_api_token(&host_id, "SuperManager", 443).await {
                            Ok(token) => {
                                let _ = tx.send(AppMsg::ShowToast(
                                    format!("API token generated: {}...{}", &token[..6.min(token.len())], &token[token.len().saturating_sub(4)..])
                                ));
                            }
                            Err(e) => {
                                let _ = tx.send(AppMsg::OperationFailed(format!("Generate token: {e}")));
                            }
                        }
                    }
                });
            }
        });
    }

    // --- FortiGate Copy API Token button ------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_detail.fg_copy_token_btn.connect_clicked(move |_| {
            let host_id = {
                let s = app_state.lock().expect("lock");
                s.selected_ssh_host.clone()
            };
            if let Some(host_id) = host_id {
                let tx = tx.clone();
                rt.spawn(async move {
                    let conn = zbus::Connection::system().await.ok();
                    let proxy = if let Some(c) = &conn {
                        supermgr_core::dbus::DaemonProxy::new(c).await.ok()
                    } else { None };
                    if let Some(proxy) = proxy {
                        match proxy.fortigate_get_api_token(&host_id).await {
                            Ok(token) => {
                                let _ = tx.send(AppMsg::CopyToClipboard(token));
                            }
                            Err(e) => {
                                let _ = tx.send(AppMsg::OperationFailed(format!("No token: {e}")));
                            }
                        }
                    }
                });
            }
        });
    }

    // --- VPN Connect / Disconnect button ------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        vpn_detail.connect_btn.connect_clicked(move |_| {
            let (should_disconnect, selected) = {
                let s = app_state.lock().expect("lock");
                (!s.vpn_state.is_idle(), s.selected_profile.clone())
            };
            let tx = tx.clone();
            if should_disconnect {
                rt.spawn(async move {
                    let msg = match dbus_disconnect().await {
                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                        Ok(()) => match dbus_get_state().await {
                            Ok(s) => AppMsg::StateUpdated(s),
                            Err(e) => AppMsg::OperationFailed(e.to_string()),
                        },
                    };
                    tx.send(msg).ok();
                });
            } else if let Some(id) = selected {
                rt.spawn(async move {
                    let msg = match dbus_connect(id).await {
                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                        Ok(()) => match dbus_get_state().await {
                            Ok(s) => AppMsg::StateUpdated(s),
                            Err(e) => AppMsg::OperationFailed(e.to_string()),
                        },
                    };
                    tx.send(msg).ok();
                });
            }
        });
    }

    // --- Rename button ------------------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        let window = window.clone();
        vpn_detail.rename_btn.connect_clicked(move |_| {
            let profile_id = {
                app_state.lock().expect("lock").selected_profile.clone()
            };
            let Some(profile_id) = profile_id else { return };
            vpn::dialogs::show_rename_dialog(&window, profile_id, &rt, &tx);
        });
    }

    // --- Edit credentials button --------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        vpn_detail.edit_creds_btn.connect_clicked(move |_| {
            let (profile_id, backend, name, host, username) = {
                let s = app_state.lock().expect("lock");
                let pid = s.selected_profile.clone();
                let idx = pid.as_deref().and_then(|id| {
                    s.profiles.iter().position(|p| p.id.to_string() == id)
                });
                match idx {
                    Some(i) => {
                        let p = &s.profiles[i];
                        (
                            p.id.to_string(),
                            p.backend.clone(),
                            p.name.clone(),
                            p.host.clone().unwrap_or_default(),
                            p.username.clone().unwrap_or_default(),
                        )
                    }
                    None => return,
                }
            };
            if backend.starts_with("FortiGate") {
                vpn::dialogs::show_edit_fortigate_dialog(
                    &window, profile_id, name, host, username, &rt, &tx,
                );
            } else if backend == "OpenVPN3" {
                vpn::dialogs::show_edit_openvpn_dialog(&window, profile_id, username, &rt, &tx);
            }
        });
    }

    // --- Auto-connect switch ------------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        vpn_detail.auto_connect_switch.connect_state_set(move |_sw, new_state| {
            let profile_id = {
                app_state.lock().expect("lock").selected_profile.clone()
            };
            let Some(profile_id) = profile_id else {
                return glib::Propagation::Proceed;
            };
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match dbus_set_auto_connect(profile_id, new_state).await {
                    Ok(()) => match dbus_list_profiles().await {
                        Ok(profiles) => AppMsg::ImportSucceeded { profiles, toast: None },
                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                    },
                    Err(e) => AppMsg::OperationFailed(format!("set auto-connect: {e}")),
                };
                let _ = tx.send(msg);
            });
            glib::Propagation::Proceed
        });
    }

    // --- Full-tunnel switch -------------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let split_routes_row = vpn_detail.split_routes_row.clone();
        let split_routes_value = vpn_detail.split_routes_value.clone();
        vpn_detail.full_tunnel_switch.connect_state_set(move |_sw, new_state| {
            let (profile_id, supports_split, split_routes) = {
                let s = app_state.lock().expect("lock");
                let pid = s.selected_profile.clone();
                let idx = s.profiles.iter().position(|p| Some(p.id.to_string()) == pid);
                let supports = idx.map_or(false, |i| {
                    let b = &s.profiles[i].backend;
                    b == "WireGuard" || b.starts_with("FortiGate")
                });
                let routes = idx.map(|i| s.profiles[i].split_routes.clone()).unwrap_or_default();
                (pid, supports, routes)
            };
            let Some(profile_id) = profile_id else {
                return glib::Propagation::Proceed;
            };
            let show_split = supports_split && !new_state;
            split_routes_row.set_visible(show_split);
            if show_split {
                if split_routes.is_empty() {
                    split_routes_value.set_label("None configured \u{2014} add CIDRs via Edit");
                } else {
                    split_routes_value.set_label(&split_routes.join(", "));
                }
            }
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match dbus_set_full_tunnel(profile_id, new_state).await {
                    Ok(()) => match dbus_list_profiles().await {
                        Ok(profiles) => AppMsg::ImportSucceeded { profiles, toast: None },
                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                    },
                    Err(e) => AppMsg::OperationFailed(format!("set full tunnel: {e}")),
                };
                let _ = tx.send(msg);
            });
            glib::Propagation::Proceed
        });
    }

    // --- Kill-switch switch -------------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        vpn_detail.kill_switch_switch.connect_state_set(move |_sw, new_state| {
            let profile_id = {
                app_state.lock().expect("lock").selected_profile.clone()
            };
            let Some(profile_id) = profile_id else {
                return glib::Propagation::Proceed;
            };
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match dbus_set_kill_switch(profile_id, new_state).await {
                    Ok(()) => match dbus_list_profiles().await {
                        Ok(profiles) => AppMsg::ImportSucceeded { profiles, toast: None },
                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                    },
                    Err(e) => AppMsg::OperationFailed(format!("set kill switch: {e}")),
                };
                let _ = tx.send(msg);
            });
            glib::Propagation::Proceed
        });
    }

    // --- Rotate WireGuard key button ----------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        let window = window.clone();
        vpn_detail.rotate_key_btn.connect_clicked(move |_| {
            let profile_id = {
                app_state.lock().expect("lock").selected_profile.clone()
            };
            let Some(profile_id) = profile_id else { return };
            vpn::dialogs::rotate_wireguard_key(&window, profile_id, &rt, &tx);
        });
    }

    // --- Export profile button ----------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        let window = window.clone();
        vpn_detail.export_btn.connect_clicked(move |_| {
            let (profile_id, profile_name) = {
                let s = app_state.lock().expect("lock");
                let pid = s.selected_profile.clone();
                let name = pid.as_deref()
                    .and_then(|id| s.profiles.iter().find(|p| p.id.to_string() == id))
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "profile".to_owned());
                (pid, name)
            };
            let Some(profile_id) = profile_id else { return };
            let default_name = format!("{}.toml", profile_name.replace('/', "_"));

            let filter = gtk4::FileFilter::new();
            filter.set_name(Some("TOML files (*.toml)"));
            filter.add_pattern("*.toml");

            let fd = gtk4::FileDialog::builder()
                .title("Export Profile")
                .initial_name(&default_name)
                .default_filter(&filter)
                .modal(true)
                .build();

            let tx = tx.clone();
            let rt_clone = rt.clone();
            fd.save(Some(&window), gio::Cancellable::NONE, move |result| {
                let Ok(file) = result else { return };
                let Some(path) = file.path() else { return };
                let profile_id = profile_id.clone();
                let tx = tx.clone();
                rt_clone.spawn(async move {
                    match dbus_export_profile(profile_id).await {
                        Ok(toml_text) => {
                            match tokio::fs::write(&path, toml_text.as_bytes()).await {
                                Ok(()) => {
                                    let _ = tx.send(AppMsg::ShowToast(
                                        "Profile exported".to_string(),
                                    ));
                                }
                                Err(e) => {
                                    let _ = tx.send(AppMsg::OperationFailed(
                                        format!("write export: {e}"),
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(
                                format!("export profile: {e}"),
                            ));
                        }
                    }
                });
            });
        });
    }

    // --- Split-routes "Edit" button -----------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let split_routes_value = vpn_detail.split_routes_value.clone();
        let window = window.clone();
        vpn_detail.split_routes_edit_btn.connect_clicked(move |_| {
            let (profile_id, current_routes) = {
                let s = app_state.lock().expect("lock");
                let pid = s.selected_profile.clone().unwrap_or_default();
                let idx = s.profiles.iter().position(|p| p.id.to_string() == pid);
                let routes = idx
                    .map(|i| s.profiles[i].split_routes.join("\n"))
                    .unwrap_or_default();
                (pid, routes)
            };
            if profile_id.is_empty() {
                return;
            }

            let dialog = adw::AlertDialog::builder()
                .heading("Edit split-tunnel routes")
                .body(
                    "Enter one CIDR per line (e.g. 10.0.0.0/8)\n\
                     Leave empty to use default AllowedIPs.",
                )
                .build();
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("save", "Save");
            dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

            let entry = gtk4::TextView::builder()
                .monospace(true)
                .wrap_mode(gtk4::WrapMode::None)
                .build();
            entry.buffer().set_text(&current_routes);
            let scroll = gtk4::ScrolledWindow::builder()
                .min_content_height(120)
                .child(&entry)
                .build();
            dialog.set_extra_child(Some(&scroll));

            let tx = tx.clone();
            let rt = rt.clone();
            let split_routes_value = split_routes_value.clone();
            dialog.connect_response(None, move |_dlg, resp| {
                if resp != "save" {
                    return;
                }
                let buf = entry.buffer();
                let text = buf.text(&buf.start_iter(), &buf.end_iter(), false);
                let routes: Vec<String> = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
                    .collect();
                let label = if routes.is_empty() {
                    "None configured \u{2014} add CIDRs via Edit".to_owned()
                } else {
                    routes.join(", ")
                };
                split_routes_value.set_label(&label);
                let pid = profile_id.clone();
                let tx = tx.clone();
                rt.spawn(async move {
                    let msg = match dbus_set_split_routes(pid, routes).await {
                        Ok(()) => match dbus_list_profiles().await {
                            Ok(profiles) => AppMsg::ImportSucceeded { profiles, toast: None },
                            Err(e) => AppMsg::OperationFailed(e.to_string()),
                        },
                        Err(e) => AppMsg::OperationFailed(format!("set split routes: {e}")),
                    };
                    let _ = tx.send(msg);
                });
            });
            dialog.present(Some(&window));
        });
    }

    // --- SSH Connect button (launch terminal) -------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let toast_overlay = toast_overlay.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_detail.connect_btn.connect_clicked(move |_| {
            let host_id = {
                let s = app_state.lock().expect("lock");
                s.selected_ssh_host.clone()
            };
            if let Some(host_id) = host_id {
                let tx = tx.clone();
                rt.spawn(async move {
                    match crate::dbus_client::dbus_ssh_connect_command(host_id).await {
                        Ok(ssh_cmd) => {
                            glib::idle_add_once(move || {
                                launch_ssh_terminal(&ssh_cmd);
                            });
                        }
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(
                                format!("Failed to build SSH command: {e}"),
                            ));
                        }
                    }
                });
            } else {
                toast_overlay.add_toast(adw::Toast::new("No host selected"));
            }
        });
    }

    // --- SSH Test Connection button -------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let toast_overlay = toast_overlay.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_detail.test_btn.connect_clicked(move |_| {
            let host_id = {
                let s = app_state.lock().expect("lock");
                s.selected_ssh_host.clone()
            };
            if let Some(host_id) = host_id {
                let tx = tx.clone();
                tx.send(AppMsg::ShowToast("Testing connection\u{2026}".to_string())).ok();
                rt.spawn(async move {
                    let msg = match crate::dbus_client::dbus_ssh_test_connection(host_id).await {
                        Ok(json) => {
                            // Parse result JSON and build a human-readable summary.
                            let v: serde_json::Value = serde_json::from_str(&json)
                                .unwrap_or_else(|_| serde_json::json!({"raw": json}));
                            let ssh_status = v.get("ssh")
                                .and_then(|s| s.as_str())
                                .unwrap_or("unknown");
                            let mut parts = vec![format!("SSH: {ssh_status}")];
                            if let Some(api) = v.get("api").and_then(|s| s.as_str()) {
                                parts.push(format!("API: {api}"));
                            }
                            let summary = parts.join(", ");
                            if ssh_status == "ok" {
                                AppMsg::ShowToast(format!("Connection test passed ({summary})"))
                            } else {
                                AppMsg::OperationFailed(
                                    format!("Connection test: {summary}"),
                                )
                            }
                        }
                        Err(e) => AppMsg::OperationFailed(
                            format!("Connection test failed: {e}"),
                        ),
                    };
                    let _ = tx.send(msg);
                });
            } else {
                toast_overlay.add_toast(adw::Toast::new("No host selected"));
            }
        });
    }

    // --- SSH Edit Host button -----------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_detail.edit_btn.connect_clicked(move |_| {
            let s = app_state.lock().expect("lock");
            if let Some(host_id) = &s.selected_ssh_host {
                if let Some(host) = s.ssh_hosts.iter().find(|h| h.id.to_string() == *host_id) {
                    ssh::dialogs::show_edit_host_dialog(
                        &window, host, &s.ssh_keys, &s.profiles, &rt, &tx,
                    );
                }
            }
        });
    }

    // --- SSH Push Key button ------------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        ssh_key_detail.push_btn.connect_clicked(move |_| {
            let s = app_state.lock().expect("lock");
            ssh::dialogs::show_push_key_dialog(
                &window,
                &s.ssh_keys,
                &s.ssh_hosts,
                s.selected_ssh_key.as_deref(),
                &rt,
                &tx,
            );
        });
    }

    // --- SSH Delete Key button (from detail panel) --------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        let ssh_content_stack = ssh_content_stack.clone();
        ssh_key_detail.delete_btn.connect_clicked(move |_| {
            let key_id = {
                app_state.lock().expect("lock").selected_ssh_key.clone()
            };
            let Some(key_id) = key_id else { return };
            let dialog = adw::AlertDialog::new(
                Some("Delete this key?"),
                Some("The private key will be removed from the keyring. This cannot be undone."),
            );
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("delete", "Delete");
            dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);

            let tx = tx.clone();
            let rt = rt.clone();
            let ssh_content_stack = ssh_content_stack.clone();
            dialog.connect_response(Some("delete"), move |_dlg, _resp| {
                let key_id = key_id.clone();
                let tx = tx.clone();
                let ssh_content_stack = ssh_content_stack.clone();
                rt.spawn(async move {
                    let msg = match crate::dbus_client::dbus_ssh_delete_key(key_id).await {
                        Ok(()) => {
                            let keys = crate::dbus_client::dbus_ssh_list_keys().await.unwrap_or_default();
                            AppMsg::SshKeysRefreshed(keys)
                        }
                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                    };
                    tx.send(msg).ok();
                });
                // Optimistically return to empty.
                ssh_content_stack.set_visible_child_name("empty");
            });
            dialog.present(Some(&window));
        });
    }

    // --- SSH Host Push Key button -------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        ssh_host_detail.push_key_btn.connect_clicked(move |_| {
            let s = app_state.lock().expect("lock");
            ssh::dialogs::show_push_key_dialog(
                &window,
                &s.ssh_keys,
                &s.ssh_hosts,
                None,
                &rt,
                &tx,
            );
        });
    }

    // --- SSH Host Push Key via API button (FortiGate) -------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        let toast_overlay = toast_overlay.clone();
        ssh_host_detail.push_key_api_btn.connect_clicked(move |_| {
            let s = app_state.lock().expect("lock");
            let host_id = match s.selected_ssh_host.clone() {
                Some(id) => id,
                None => return,
            };
            let keys = s.ssh_keys.clone();
            drop(s);

            if keys.is_empty() {
                toast_overlay.add_toast(adw::Toast::new("No SSH keys available"));
                return;
            }

            // Build a dialog that asks for admin user + which key to push.
            let dialog = adw::AlertDialog::new(
                Some("Push Key via FortiGate API"),
                Some("Push an SSH public key to a FortiGate admin user."),
            );
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("push", "Push Key");
            dialog.set_response_appearance("push", adw::ResponseAppearance::Suggested);

            let content = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Vertical)
                .spacing(8)
                .build();

            let admin_entry = adw::EntryRow::builder()
                .title("Admin Username")
                .text("admin")
                .build();
            let admin_group = adw::PreferencesGroup::new();
            admin_group.add(&admin_entry);
            content.append(&admin_group);

            let key_combo = gtk4::DropDown::from_strings(
                &keys.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(),
            );
            let key_group = adw::PreferencesGroup::builder()
                .title("SSH Key")
                .build();
            let key_row = adw::ActionRow::builder()
                .title("Key")
                .activatable(false)
                .build();
            key_row.add_suffix(&key_combo);
            key_group.add(&key_row);
            content.append(&key_group);

            dialog.set_extra_child(Some(&content));

            let tx = tx.clone();
            let rt = rt.clone();
            let toast_overlay = toast_overlay.clone();
            dialog.connect_response(Some("push"), move |_dlg, _resp| {
                let admin_user = admin_entry.text().to_string();
                if admin_user.is_empty() {
                    toast_overlay.add_toast(adw::Toast::new("Admin username is required"));
                    return;
                }
                let selected_idx = key_combo.selected() as usize;
                let key_id = match keys.get(selected_idx) {
                    Some(k) => k.id.to_string(),
                    None => return,
                };
                let host_id = host_id.clone();
                let tx = tx.clone();
                let toast_overlay = toast_overlay.clone();
                rt.spawn(async move {
                    let conn = match zbus::Connection::system().await {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(format!("D-Bus: {e}")));
                            return;
                        }
                    };
                    let proxy = match supermgr_core::dbus::DaemonProxy::new(&conn).await {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(format!("proxy: {e}")));
                            return;
                        }
                    };
                    match proxy.fortigate_push_ssh_key(&host_id, &key_id, &admin_user).await {
                        Ok(_) => {
                            let _ = tx.send(AppMsg::ShowToast(
                                format!("SSH key pushed to FortiGate admin '{admin_user}'"),
                            ));
                        }
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(
                                format!("Push key via API failed: {e}"),
                            ));
                        }
                    }
                });
            });
            dialog.present(Some(&window));
        });
    }

    // --- UniFi Set Inform button -----------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        let toast_overlay = toast_overlay.clone();
        ssh_host_detail.set_inform_btn.connect_clicked(move |_| {
            let host_id = {
                let s = app_state.lock().expect("lock");
                match s.selected_ssh_host.clone() {
                    Some(id) => id,
                    None => return,
                }
            };

            let dialog = adw::AlertDialog::new(
                Some("Set Inform URL"),
                Some("Adopt this UniFi device to a controller by running set-inform via SSH."),
            );
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("set", "Set Inform");
            dialog.set_response_appearance("set", adw::ResponseAppearance::Suggested);

            let content = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Vertical)
                .spacing(8)
                .build();

            let url_entry = adw::EntryRow::builder()
                .title("Controller Inform URL")
                .text("https://unifi.example.com:8443/inform")
                .build();
            let url_group = adw::PreferencesGroup::new();
            url_group.add(&url_entry);
            content.append(&url_group);

            dialog.set_extra_child(Some(&content));

            let tx = tx.clone();
            let rt = rt.clone();
            let toast_overlay = toast_overlay.clone();
            dialog.connect_response(Some("set"), move |_dlg, _resp| {
                let inform_url = url_entry.text().to_string();
                if inform_url.is_empty() {
                    toast_overlay.add_toast(adw::Toast::new("Inform URL is required"));
                    return;
                }
                let host_id = host_id.clone();
                let tx = tx.clone();
                let toast_overlay = toast_overlay.clone();
                rt.spawn(async move {
                    let conn = match zbus::Connection::system().await {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(format!("D-Bus: {e}")));
                            return;
                        }
                    };
                    let proxy = match supermgr_core::dbus::DaemonProxy::new(&conn).await {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(format!("proxy: {e}")));
                            return;
                        }
                    };
                    match proxy.unifi_set_inform(&host_id, &inform_url).await {
                        Ok(resp) => {
                            let _ = tx.send(AppMsg::ShowToast(
                                format!("set-inform sent successfully"),
                            ));
                            tracing::info!("set-inform result: {resp}");
                        }
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(
                                format!("Set Inform failed: {e}"),
                            ));
                        }
                    }
                });
            });
            dialog.present(Some(&window));
        });
    }

    // --- SSH Host Delete button ---------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        let window = window.clone();
        let ssh_content_stack = ssh_content_stack.clone();
        ssh_host_detail.delete_btn.connect_clicked(move |_| {
            let host_id = {
                app_state.lock().expect("lock").selected_ssh_host.clone()
            };
            let Some(host_id) = host_id else { return };
            let dialog = adw::AlertDialog::new(
                Some("Delete this host?"),
                Some("This cannot be undone."),
            );
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("delete", "Delete");
            dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);

            let tx = tx.clone();
            let rt = rt.clone();
            let ssh_content_stack = ssh_content_stack.clone();
            dialog.connect_response(Some("delete"), move |_dlg, _resp| {
                let host_id = host_id.clone();
                let tx = tx.clone();
                let ssh_content_stack = ssh_content_stack.clone();
                rt.spawn(async move {
                    let msg = match crate::dbus_client::dbus_ssh_delete_host(host_id).await {
                        Ok(()) => {
                            let hosts = crate::dbus_client::dbus_ssh_list_hosts().await.unwrap_or_default();
                            AppMsg::SshHostsRefreshed(hosts)
                        }
                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                    };
                    tx.send(msg).ok();
                });
                ssh_content_stack.set_visible_child_name("empty");
            });
            dialog.present(Some(&window));
        });
    }

    // --- Pin toggle button ---------------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        ssh_host_detail.pin_btn.connect_clicked(move |_btn| {
            let host_id = {
                app_state.lock().expect("lock").selected_ssh_host.clone()
            };
            let Some(host_id) = host_id else { return };
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match crate::dbus_client::dbus_ssh_toggle_pin(host_id).await {
                    Ok(hosts) => AppMsg::SshHostsRefreshed(hosts),
                    Err(e) => AppMsg::OperationFailed(e.to_string()),
                };
                tx.send(msg).ok();
            });
        });
    }

    // --- Banner "Retry" button ----------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        banner.connect_button_clicked(move |_| {
            let app_state = Arc::clone(&app_state);
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match fetch_initial_state(&app_state).await {
                    Ok(()) => {
                        let _ = fetch_initial_ssh_state(&app_state).await;
                        let s = app_state.lock().expect("lock");
                        AppMsg::DaemonConnected {
                            profiles: s.profiles.clone(),
                            state: s.vpn_state.clone(),
                        }
                    }
                    Err(e) => {
                        error!("daemon retry failed: {:#}", e);
                        AppMsg::DaemonUnavailable
                    }
                };
                tx.send(msg).ok();
            });
        });
    }

    // --- Background signal listener -----------------------------------------
    {
        let tx = tx.clone();
        let app_state = Arc::clone(&app_state);
        rt.spawn(run_signal_listener(app_state, tx));
    }

    // =========================================================================
    // Message drain loop — polls mpsc channel every 50 ms
    // =========================================================================
    let rx_app_state = Arc::clone(&app_state);
    let rx_profile_list = vpn_profile_list.clone();
    let rx_connect_btn = vpn_detail.connect_btn.clone();
    let rx_rename_btn = vpn_detail.rename_btn.clone();
    let rx_status_label = vpn_detail.status_label.clone();
    let rx_profile_name_label = vpn_detail.profile_name_label.clone();
    let rx_stats_box = vpn_detail.stats_box.clone();
    let rx_stats_sent = vpn_detail.stats_sent.clone();
    let rx_stats_recv = vpn_detail.stats_recv.clone();
    let rx_stats_uptime = vpn_detail.stats_uptime.clone();
    let rx_stats_handshake = vpn_detail.stats_handshake.clone();
    let rx_stats_virtual_ip = vpn_detail.stats_virtual_ip.clone();
    let rx_stats_routes = vpn_detail.stats_routes.clone();
    let rx_vpn_detail_stack = vpn_detail.detail_stack.clone();
    let rx_banner = banner.clone();
    let rx_toast_overlay = toast_overlay.clone();
    let rx_window = window.clone();
    let rx_app = app.clone();
    let rx_rt = rt.clone();
    let rx_tx = tx.clone();
    let rx_tray_handle = Arc::clone(&tray_handle);
    let rx_ssh_key_list = ssh_key_list.clone();
    let rx_ssh_host_list = ssh_host_list.clone();
    let rx_ssh_content_stack = ssh_content_stack.clone();
    let rx_ssh_key_pubkey_view = ssh_key_detail.public_key_view.clone();
    let rx_console_panel = console_panel.clone();
    let rx_ssh_host_detail = ssh_host_detail.clone();
    let rx_dashboard_flow_box = dashboard_flow_box.clone();

    let prev_state_init: VpnState = {
        let s = rx_app_state.lock().expect("lock");
        s.vpn_state.clone()
    };
    let mut rx_prev_state = prev_state_init;

    glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                // === VPN messages =========================================
                AppMsg::DaemonConnected { profiles, state } => {
                    {
                        let mut s = rx_app_state.lock().expect("lock");
                        s.profiles = profiles;
                        s.vpn_state = state;
                        s.daemon_available = true;
                    }
                    rx_banner.set_revealed(false);
                    let s = rx_app_state.lock().expect("lock");
                    populate_vpn_sidebar(
                        &rx_profile_list,
                        &s.profiles,
                        &s.vpn_state,
                        s.selected_profile.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                    );
                    apply_vpn_state(
                        &rx_connect_btn,
                        &rx_rename_btn,
                        &rx_status_label,
                        &rx_stats_box,
                        &s,
                    );
                    push_tray_update(
                        &rx_tray_handle,
                        s.vpn_state.clone(),
                        s.profiles.clone(),
                        &rx_rt,
                    );
                }
                AppMsg::ImportSucceeded { profiles, toast } => {
                    {
                        let mut s = rx_app_state.lock().expect("lock");
                        s.profiles = profiles;
                    }
                    let s = rx_app_state.lock().expect("lock");
                    populate_vpn_sidebar(
                        &rx_profile_list,
                        &s.profiles,
                        &s.vpn_state,
                        s.selected_profile.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                    );
                    if let Some(msg) = toast {
                        rx_toast_overlay.add_toast(adw::Toast::new(msg));
                    }
                    push_tray_update(
                        &rx_tray_handle,
                        s.vpn_state.clone(),
                        s.profiles.clone(),
                        &rx_rt,
                    );
                }
                AppMsg::StateUpdated(state) => {
                    {
                        let mut s = rx_app_state.lock().expect("lock");
                        s.vpn_state = state;
                        s.daemon_available = true;
                    }
                    rx_banner.set_revealed(false);
                    let s = rx_app_state.lock().expect("lock");
                    // Desktop notifications on state transitions.
                    match &s.vpn_state {
                        VpnState::Connected { profile_id, .. } => {
                            if !matches!(&rx_prev_state, VpnState::Connected { .. }) {
                                let body = s
                                    .profiles
                                    .iter()
                                    .find(|p| p.id == *profile_id)
                                    .map(|p| p.name.as_str())
                                    .unwrap_or("Unknown profile");
                                let notif = gio::Notification::new("VPN Connected");
                                notif.set_body(Some(body));
                                rx_app.send_notification(Some("vpn-state"), &notif);
                            }
                        }
                        VpnState::Error { message, .. } => {
                            let notif = gio::Notification::new("VPN Error");
                            notif.set_body(Some(message.as_str()));
                            rx_app.send_notification(Some("vpn-state"), &notif);
                        }
                        VpnState::Disconnected => {
                            if let VpnState::Connected { profile_id, .. } = &rx_prev_state {
                                let body = s
                                    .profiles
                                    .iter()
                                    .find(|p| p.id == *profile_id)
                                    .map(|p| p.name.as_str())
                                    .unwrap_or("Unknown profile");
                                let notif = gio::Notification::new("VPN Disconnected");
                                notif.set_body(Some(body));
                                rx_app.send_notification(Some("vpn-state"), &notif);
                            }
                        }
                        _ => {}
                    }
                    rx_prev_state = s.vpn_state.clone();
                    if !matches!(s.vpn_state, VpnState::Connected { .. }) {
                        rx_stats_uptime.set_visible(false);
                        rx_stats_virtual_ip.set_visible(false);
                        rx_stats_routes.set_visible(false);
                    }
                    let display_name = s
                        .selected_profile
                        .as_deref()
                        .and_then(|sid| s.profiles.iter().find(|p| p.id.to_string() == sid))
                        .map(|p| p.name.as_str())
                        .unwrap_or("");
                    rx_profile_name_label.set_label(display_name);
                    populate_vpn_sidebar(
                        &rx_profile_list,
                        &s.profiles,
                        &s.vpn_state,
                        s.selected_profile.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                    );
                    apply_vpn_state(
                        &rx_connect_btn,
                        &rx_rename_btn,
                        &rx_status_label,
                        &rx_stats_box,
                        &s,
                    );
                    push_tray_update(
                        &rx_tray_handle,
                        s.vpn_state.clone(),
                        s.profiles.clone(),
                        &rx_rt,
                    );
                }
                AppMsg::StatsUpdated {
                    bytes_sent,
                    bytes_received,
                    last_handshake_secs,
                    virtual_ip,
                    active_routes,
                    uptime_secs,
                } => {
                    rx_stats_sent.set_label(&format!("Sent: {}", format_bytes(bytes_sent)));
                    rx_stats_recv
                        .set_label(&format!("Received: {}", format_bytes(bytes_received)));

                    if uptime_secs > 0 {
                        let h = uptime_secs / 3600;
                        let m = (uptime_secs % 3600) / 60;
                        let s = uptime_secs % 60;
                        let uptime_text = if h > 0 {
                            format!("Connected: {h}h {m:02}m")
                        } else if m > 0 {
                            format!("Connected: {m}m {s:02}s")
                        } else {
                            format!("Connected: {s}s")
                        };
                        rx_stats_uptime.set_label(&uptime_text);
                        rx_stats_uptime.set_visible(true);
                    } else {
                        rx_stats_uptime.set_visible(false);
                    }

                    let hs_text = if last_handshake_secs == 0 {
                        "Last handshake: \u{2014}".to_owned()
                    } else {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let elapsed = now.saturating_sub(last_handshake_secs);
                        format!("Last handshake: {}", format_ago(elapsed))
                    };
                    rx_stats_handshake.set_label(&hs_text);

                    if virtual_ip.is_empty() {
                        rx_stats_virtual_ip.set_visible(false);
                    } else {
                        rx_stats_virtual_ip.set_label(&format!("VPN IP: {virtual_ip}"));
                        rx_stats_virtual_ip.set_visible(true);
                    }
                    if active_routes.is_empty() {
                        rx_stats_routes.set_visible(false);
                    } else {
                        rx_stats_routes
                            .set_label(&format!("Routes: {}", active_routes.join(", ")));
                        rx_stats_routes.set_visible(true);
                    }
                }
                AppMsg::ProfileDeleted(deleted_id) => {
                    {
                        let mut s = rx_app_state.lock().expect("lock");
                        s.profiles.retain(|p| p.id.to_string() != deleted_id);
                        if s.selected_profile.as_deref() == Some(deleted_id.as_str()) {
                            s.selected_profile = None;
                        }
                    }
                    let s = rx_app_state.lock().expect("lock");
                    populate_vpn_sidebar(
                        &rx_profile_list,
                        &s.profiles,
                        &s.vpn_state,
                        s.selected_profile.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                    );
                    if s.selected_profile.is_none() {
                        rx_vpn_detail_stack.set_visible_child_name("empty");
                        rx_profile_name_label.set_label("");
                    }
                    apply_vpn_state(
                        &rx_connect_btn,
                        &rx_rename_btn,
                        &rx_status_label,
                        &rx_stats_box,
                        &s,
                    );
                    rx_toast_overlay.add_toast(adw::Toast::new("Profile deleted"));
                    push_tray_update(
                        &rx_tray_handle,
                        s.vpn_state.clone(),
                        s.profiles.clone(),
                        &rx_rt,
                    );
                }
                AppMsg::DaemonUnavailable => {
                    rx_app_state.lock().expect("lock").daemon_available = false;
                    rx_banner.set_revealed(true);
                }
                AppMsg::OperationFailed(msg) => {
                    error!("operation failed: {}", msg);
                    if msg.len() <= 80 {
                        rx_toast_overlay.add_toast(adw::Toast::new(&msg));
                    } else {
                        // Truncated toast with a "Details" button for long errors.
                        let short = format!("{}…", &msg[..77]);
                        let toast = adw::Toast::builder()
                            .title(&short)
                            .button_label("Details")
                            .timeout(5)
                            .build();
                        let full_msg = msg.clone();
                        let win = rx_window.clone();
                        toast.connect_button_clicked(move |_| {
                            let dialog = adw::AlertDialog::builder()
                                .heading("Error Details")
                                .body_use_markup(false)
                                .build();
                            // Use a scrollable monospace TextView for the full error.
                            let text_view = gtk4::TextView::builder()
                                .editable(false)
                                .cursor_visible(false)
                                .wrap_mode(gtk4::WrapMode::WordChar)
                                .monospace(true)
                                .top_margin(8)
                                .bottom_margin(8)
                                .left_margin(8)
                                .right_margin(8)
                                .build();
                            text_view.buffer().set_text(&full_msg);
                            let scroll = gtk4::ScrolledWindow::builder()
                                .min_content_width(400)
                                .min_content_height(200)
                                .child(&text_view)
                                .build();
                            dialog.set_extra_child(Some(&scroll));
                            dialog.add_response("close", "Close");
                            dialog.set_default_response(Some("close"));
                            dialog.present(Some(&win));
                        });
                        rx_toast_overlay.add_toast(toast);
                    }
                }
                AppMsg::ShowToast(msg) => {
                    rx_toast_overlay.add_toast(adw::Toast::new(&msg));
                }
                AppMsg::CopyToClipboard(text) => {
                    let display = gtk4::prelude::WidgetExt::display(&rx_window);
                    display.clipboard().set_text(&text);
                    rx_toast_overlay.add_toast(adw::Toast::new("Copied to clipboard"));
                }
                AppMsg::ShowWindow => {
                    rx_window.present();
                }
                AppMsg::Quit => {
                    rx_app.quit();
                }
                AppMsg::AuthChallenge {
                    user_code,
                    verification_url,
                } => {
                    if user_code.is_empty() {
                        gtk4::show_uri(
                            Some(&rx_window),
                            &verification_url,
                            gtk4::gdk::CURRENT_TIME,
                        );
                    } else {
                        vpn::dialogs::show_auth_challenge_dialog(
                            &rx_window,
                            &user_code,
                            &verification_url,
                        );
                    }
                }
                // === SSH messages =========================================
                AppMsg::SshPublicKeyFetched(pubkey) => {
                    rx_ssh_key_pubkey_view.buffer().set_text(&pubkey);
                }
                AppMsg::SshKeysRefreshed(keys) => {
                    {
                        let mut s = rx_app_state.lock().expect("lock");
                        s.ssh_keys = keys;
                    }
                    let s = rx_app_state.lock().expect("lock");
                    let filter = s.ssh_filter.clone();
                    populate_ssh_key_list(
                        &rx_ssh_key_list,
                        &s.ssh_keys,
                        s.selected_ssh_key.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                        &filter,
                    );
                    // If the selected key was deleted, go back to empty.
                    if let Some(sel) = &s.selected_ssh_key {
                        if !s.ssh_keys.iter().any(|k| k.id.to_string() == *sel) {
                            drop(s);
                            rx_app_state.lock().expect("lock").selected_ssh_key = None;
                            rx_ssh_content_stack.set_visible_child_name("empty");
                        }
                    }
                    rx_toast_overlay.add_toast(adw::Toast::new("SSH keys updated"));
                }
                AppMsg::SshHostsRefreshed(hosts) => {
                    {
                        let mut s = rx_app_state.lock().expect("lock");
                        s.ssh_hosts = hosts;
                    }
                    let s = rx_app_state.lock().expect("lock");
                    let filter = s.ssh_filter.clone();
                    let health = s.host_health.clone();
                    populate_ssh_host_list(
                        &rx_ssh_host_list,
                        &s.ssh_hosts,
                        s.selected_ssh_host.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                        &filter,
                        &health,
                    );
                    if let Some(sel) = &s.selected_ssh_host {
                        if let Some(host) = s.ssh_hosts.iter().find(|h| h.id.to_string() == *sel) {
                            // Refresh the detail panel with updated data.
                            ssh::host_detail::update_ssh_host_detail(&rx_ssh_host_detail, host);
                        } else {
                            drop(s);
                            rx_app_state.lock().expect("lock").selected_ssh_host = None;
                            rx_ssh_content_stack.set_visible_child_name("empty");
                        }
                    }
                }
                AppMsg::HostHealthChanged { host_id, reachable } => {
                    let was_known_before;
                    let old_reachable;
                    {
                        let mut s = rx_app_state.lock().expect("lock");
                        old_reachable = s.host_health.get(&host_id).copied();
                        was_known_before = old_reachable.is_some();
                        s.host_health.insert(host_id.clone(), reachable);
                    }
                    // Desktop notification on state *change* (not initial discovery).
                    if was_known_before && old_reachable != Some(reachable) {
                        let s = rx_app_state.lock().expect("lock");
                        let host_label = s.ssh_hosts.iter()
                            .find(|h| h.id.to_string() == host_id)
                            .map(|h| h.label.clone())
                            .unwrap_or_else(|| host_id.clone());
                        drop(s);
                        let (title, body) = if reachable {
                            (
                                format!("\u{2b24} {} is now reachable", host_label),
                                "Host came back online.".to_owned(),
                            )
                        } else {
                            (
                                format!("\u{2b24} {} is unreachable", host_label),
                                "Host went offline.".to_owned(),
                            )
                        };
                        if let Some(app) = rx_window.application() {
                            let notif = gio::Notification::new(&title);
                            notif.set_body(Some(&body));
                            let notif_id = format!("host-health-{}", host_id);
                            app.send_notification(Some(&notif_id), &notif);
                        }
                    }
                    let s = rx_app_state.lock().expect("lock");
                    let filter = s.ssh_filter.clone();
                    let health = s.host_health.clone();
                    populate_ssh_host_list(
                        &rx_ssh_host_list,
                        &s.ssh_hosts,
                        s.selected_ssh_host.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                        &filter,
                        &health,
                    );
                }
                AppMsg::SshOperationProgress {
                    operation_id: _,
                    host_label,
                    message,
                } => {
                    rx_toast_overlay
                        .add_toast(adw::Toast::new(&format!("{host_label}: {message}")));
                }
                // === FortiGate messages =======================================
                AppMsg::FortigateStatus { host_id, data } => {
                    // Only apply if this host is still the selected one.
                    let s = rx_app_state.lock().expect("lock");
                    if s.selected_ssh_host.as_deref() == Some(&host_id) {
                        ssh::host_detail::apply_fortigate_status(
                            &rx_ssh_host_detail,
                            &data,
                        );
                    }
                }
                AppMsg::FortigateCompliance { host_id: _, data } => {
                    let win = rx_window.clone();
                    ssh::host_detail::show_compliance_dialog(
                        &win,
                        &data,
                    );
                }
                AppMsg::DashboardDeviceStatus { host_id, data } => {
                    ssh::dashboard::apply_dashboard_status(
                        &rx_dashboard_flow_box,
                        &host_id,
                        &data,
                    );
                }
                AppMsg::FortigateBackupDone { host_id: _, result } => {
                    match result {
                        Ok(filename) => {
                            rx_toast_overlay.add_toast(
                                adw::Toast::new(&format!("Backup saved: {filename}")),
                            );
                        }
                        Err(e) => {
                            rx_toast_overlay.add_toast(
                                adw::Toast::new(&format!("Backup failed: {e}")),
                            );
                        }
                    }
                }
                // === Console messages =========================================
                AppMsg::ConsoleResponse(text) => {
                    let tag = if text.starts_with("\n[tool:") {
                        "tool"
                    } else if text.starts_with("\nClaude:") {
                        "assistant"
                    } else {
                        "tool"
                    };
                    console::panel::append_tagged(&rx_console_panel.chat_buffer, &text, tag);
                    // Auto-scroll to bottom.
                    let end = rx_console_panel.chat_buffer.end_iter();
                    rx_console_panel.chat_view.scroll_to_iter(
                        &mut end.clone(), 0.0, false, 0.0, 0.0,
                    );
                }
                AppMsg::ConsoleStreamChunk(chunk) => {
                    console::panel::append_tagged(
                        &rx_console_panel.chat_buffer,
                        &chunk,
                        "assistant",
                    );
                    let end = rx_console_panel.chat_buffer.end_iter();
                    rx_console_panel.chat_view.scroll_to_iter(
                        &mut end.clone(), 0.0, false, 0.0, 0.0,
                    );
                }
                AppMsg::ConsoleThinking(active) => {
                    rx_console_panel.spinner.set_visible(active);
                    rx_console_panel.spinner.set_spinning(active);
                    rx_console_panel.send_btn.set_visible(!active);
                    rx_console_panel.stop_btn.set_visible(active);
                }
                // Provisioning messages — handled locally via polling in
                // the wizard widget; these are reserved for future use.
                AppMsg::ProvisioningConfigGenerated(_) => {}
                AppMsg::ProvisioningPushDone => {}
                AppMsg::DashboardDeviceStatus { .. } => {}
                AppMsg::FortigateBackupDone { .. } => {}
            }
        }
        glib::ControlFlow::Continue
    });

    // =========================================================================
    // Keyboard shortcuts
    // =========================================================================
    {
        let view_stack = view_stack.clone();
        let ssh_search_entry = ssh_search_entry.clone();
        let console_input = console_panel.input_view.clone();
        let outer_stack_k = outer_stack.clone();
        let lock_page_k = lock_page.clone();
        let app_settings_k = Arc::clone(&app_settings);
        let key_ctrl = gtk4::EventControllerKey::new();
        key_ctrl.connect_key_pressed(move |_, key, _, mods| {
            let ctrl = mods.contains(gtk4::gdk::ModifierType::CONTROL_MASK);
            if ctrl {
                match key {
                    gtk4::gdk::Key::_1 => {
                        view_stack.set_visible_child_name("vpn");
                        return glib::Propagation::Stop;
                    }
                    gtk4::gdk::Key::_2 => {
                        view_stack.set_visible_child_name("ssh");
                        return glib::Propagation::Stop;
                    }
                    gtk4::gdk::Key::_3 => {
                        view_stack.set_visible_child_name("console");
                        console_input.grab_focus();
                        return glib::Propagation::Stop;
                    }
                    gtk4::gdk::Key::_4 => {
                        view_stack.set_visible_child_name("provisioning");
                        return glib::Propagation::Stop;
                    }
                    gtk4::gdk::Key::k => {
                        view_stack.set_visible_child_name("ssh");
                        ssh_search_entry.grab_focus();
                        return glib::Propagation::Stop;
                    }
                    // Ctrl+L: manually lock the session.
                    gtk4::gdk::Key::l => {
                        let s = app_settings_k.lock().expect("lock");
                        if s.has_password() {
                            lock_session(&outer_stack_k, &lock_page_k);
                        }
                        return glib::Propagation::Stop;
                    }
                    _ => {}
                }
            }
            glib::Propagation::Proceed
        });
        window.add_controller(key_ctrl);
    }

    // =========================================================================
    // Lock-screen wiring
    // =========================================================================

    // --- Unlock button -------------------------------------------------------
    {
        let app_settings = Arc::clone(&app_settings);
        let outer_stack = outer_stack.clone();
        let lock_page = lock_page.clone();
        let inactivity_counter = inactivity_counter.clone();
        lock_page.unlock_btn.connect_clicked(move |_| {
            let password = lock_page.password_row.text().to_string();
            let s = app_settings.lock().expect("lock");
            if s.verify_password(&password) {
                lock_page.password_row.set_text("");
                lock_page.status_label.set_text("");
                outer_stack.set_visible_child_name("app");
                // Reset inactivity counter on unlock.
                inactivity_counter.set(0);
            } else {
                lock_page.status_label.set_text("Incorrect password.");
            }
        });
    }

    // --- Set Password button (first-time setup, also accessible from lock) ----
    {
        let app_settings = Arc::clone(&app_settings);
        let outer_stack = outer_stack.clone();
        let lock_page = lock_page.clone();
        let inactivity_counter = inactivity_counter.clone();
        lock_page.set_btn.connect_clicked(move |_| {
            let pw = lock_page.password_row.text().to_string();
            let confirm = lock_page.confirm_row.text().to_string();
            if pw.is_empty() {
                lock_page.status_label.set_text("Password cannot be empty.");
                return;
            }
            if pw != confirm {
                lock_page.status_label.set_text("Passwords do not match.");
                return;
            }
            {
                let mut s = app_settings.lock().expect("lock");
                s.set_password(&pw);
            }
            lock_page.password_row.set_text("");
            lock_page.confirm_row.set_text("");
            lock_page.status_label.set_text("");
            outer_stack.set_visible_child_name("app");
            inactivity_counter.set(0);
        });
    }

    // Allow pressing Enter anywhere to trigger unlock/set when the lock page
    // is visible.  Attach to the *window* so the event is caught even if
    // PasswordEntryRow consumes it at the widget level.
    {
        let unlock_btn = lock_page.unlock_btn.clone();
        let set_btn = lock_page.set_btn.clone();
        let outer_stack_enter = outer_stack.clone();
        let key_ctrl = gtk4::EventControllerKey::builder()
            .propagation_phase(gtk4::PropagationPhase::Capture)
            .build();
        key_ctrl.connect_key_pressed(move |_, key, _, _| {
            if (key == gtk4::gdk::Key::Return || key == gtk4::gdk::Key::KP_Enter)
                && outer_stack_enter.visible_child_name().as_deref() == Some("lock")
            {
                if unlock_btn.is_visible() {
                    unlock_btn.emit_clicked();
                    return glib::Propagation::Stop;
                } else if set_btn.is_visible() {
                    set_btn.emit_clicked();
                    return glib::Propagation::Stop;
                }
            }
            glib::Propagation::Proceed
        });
        window.add_controller(key_ctrl);
    }

    // =========================================================================
    // Drag-and-drop file import (.conf / .toml / .ovpn)
    // =========================================================================
    {
        let drop_target =
            gtk4::DropTarget::new(gio::File::static_type(), gtk4::gdk::DragAction::COPY);
        let tx = tx.clone();
        let rt = rt.clone();
        drop_target.connect_drop(move |_, value, _x, _y| {
            let file = match value.get::<gio::File>() {
                Ok(f) => f,
                Err(_) => return false,
            };
            let Some(path) = file.path() else {
                return false;
            };
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("imported")
                .to_string();
            let path_clone = path.clone();
            let tx = tx.clone();
            match ext.as_str() {
                "conf" => {
                    rt.spawn(async move {
                        let msg =
                            match crate::dbus_client::dbus_import_wireguard(path_clone, name).await
                            {
                                Ok(profiles) => AppMsg::ImportSucceeded {
                                    profiles,
                                    toast: Some("WireGuard profile imported via drag-and-drop"),
                                },
                                Err(e) => {
                                    AppMsg::OperationFailed(format!("Import failed: {e}"))
                                }
                            };
                        tx.send(msg).ok();
                    });
                }
                "toml" => {
                    rt.spawn(async move {
                        let msg = match crate::dbus_client::dbus_import_toml(path_clone).await {
                            Ok(_result) => {
                                // Refresh profile list after TOML import.
                                match crate::dbus_client::dbus_list_profiles().await {
                                    Ok(profiles) => AppMsg::ImportSucceeded {
                                        profiles,
                                        toast: Some("TOML config imported via drag-and-drop"),
                                    },
                                    Err(e) => {
                                        AppMsg::OperationFailed(format!("Import OK but refresh failed: {e}"))
                                    }
                                }
                            }
                            Err(e) => AppMsg::OperationFailed(format!("Import failed: {e}")),
                        };
                        tx.send(msg).ok();
                    });
                }
                "ovpn" => {
                    // OpenVPN needs username/password; import with empty credentials
                    // (user can edit them later in the profile detail view).
                    rt.spawn(async move {
                        let msg = match crate::dbus_client::dbus_import_openvpn(
                            path_clone,
                            name,
                            String::new(),
                            String::new(),
                        )
                        .await
                        {
                            Ok(profiles) => AppMsg::ImportSucceeded {
                                profiles,
                                toast: Some("OpenVPN profile imported via drag-and-drop"),
                            },
                            Err(e) => AppMsg::OperationFailed(format!("Import failed: {e}")),
                        };
                        tx.send(msg).ok();
                    });
                }
                _ => {
                    tx.send(AppMsg::OperationFailed(format!(
                        "Unsupported file type: .{ext} (expected .conf, .toml, or .ovpn)"
                    )))
                    .ok();
                }
            }
            true
        });
        window.add_controller(drop_target);
    }

    window.present();
}

// ---------------------------------------------------------------------------
// About dialog
// ---------------------------------------------------------------------------

/// Show the application About dialog.
fn show_about_dialog(window: &adw::ApplicationWindow) {
    let dialog = adw::AboutDialog::builder()
        .application_name("SuperManager")
        .application_icon("org.supermgr.SuperManager")
        .version(env!("CARGO_PKG_VERSION"))
        .developer_name("Sybr AS")
        .website("https://github.com/franzjeger/SuperManager")
        .issue_url("https://github.com/franzjeger/SuperManager/issues")
        .license_type(gtk4::License::Gpl30)
        .developers(vec!["Frank-Andreas Lia"])
        .comments("Unified SSH, VPN, and network device management with AI assistant")
        .build();
    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Lock-screen helpers
// ---------------------------------------------------------------------------

/// Switch the outer stack to the lock page and prepare it for unlock.
fn lock_session(outer_stack: &gtk4::Stack, lock_page: &LockPage) {
    lock_page.password_row.set_text("");
    lock_page.confirm_row.set_text("");
    lock_page.status_label.set_text("Session locked. Enter your password.");
    lock_page.unlock_btn.set_visible(true);
    lock_page.set_btn.set_visible(false);
    lock_page.confirm_row.set_visible(false);
    outer_stack.set_visible_child_name("lock");
    lock_page.password_row.grab_focus();
}
