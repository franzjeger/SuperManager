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
use supermgr_core::host::HostSummary;

use crate::app::{AppMsg, AppState};
use crate::dbus_client::{
    dbus_connect, dbus_disconnect, dbus_export_profile, dbus_get_state,
    dbus_list_profiles, dbus_set_auto_connect, dbus_set_full_tunnel,
    dbus_set_kill_switch, dbus_set_split_routes,
    fetch_initial_state, fetch_initial_ssh_state, run_signal_listener,
};
use crate::settings::AppSettings;
use crate::tray::VpnTray;

use self::vpn::detail::apply_vpn_state;
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
    let handle = match tray_handle.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
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
    quit_btn: gtk4::Button,
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

    let quit_btn = gtk4::Button::builder()
        .label("Quit")
        .css_classes(["destructive-action", "pill"])
        .build();
    btn_box.append(&quit_btn);
    container.append(&btn_box);

    LockPage {
        container,
        password_row,
        confirm_row,
        unlock_btn,
        set_btn,
        quit_btn,
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
        let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
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
        let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                    *tray_handle_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
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

    // -- "Add" popover — contextual per section ------------------------------
    let popover = gtk4::Popover::new();
    let pop_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .spacing(2)
        .build();

    // VPN add menu (shown when VPN section is active).
    //
    // The previous design was five flat buttons (Import WG / Add FG /
    // Import OV / Import Azure / Import TOML). With multiple backends and
    // a "Create new vs. import" distinction, that's too wide and forces
    // the user to re-learn which backends have which option. Switch to a
    // single "Add VPN connection" MenuButton whose model-based popover
    // groups by backend, with submenu entries for "Create new" / "Import"
    // — submenus collapse to a single entry where only one mode is
    // currently supported (e.g. WireGuard import-only until we ship a
    // keypair-generator dialog).
    let vpn_add_group = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(2)
        .build();

    let vpn_add_menu = gio::Menu::new();
    {
        let wg = gio::Menu::new();
        wg.append(Some("Import .conf file\u{2026}"), Some("vpn-add.wg-import"));
        vpn_add_menu.append_submenu(Some("WireGuard"), &wg);

        let fg = gio::Menu::new();
        fg.append(Some("Create new\u{2026}"), Some("vpn-add.fg-new"));
        vpn_add_menu.append_submenu(Some("FortiGate"), &fg);

        let ov = gio::Menu::new();
        ov.append(Some("Import .ovpn file\u{2026}"), Some("vpn-add.ov-import"));
        vpn_add_menu.append_submenu(Some("OpenVPN"), &ov);

        let az = gio::Menu::new();
        az.append(
            Some("Import Azure Portal config\u{2026}"),
            Some("vpn-add.az-import"),
        );
        vpn_add_menu.append_submenu(Some("Azure VPN"), &az);

        // Universal entry at the bottom — picks the backend by reading
        // the TOML's [config] discriminator. Not under any backend
        // submenu because it's intentionally cross-vendor.
        let other = gio::Menu::new();
        other.append(
            Some("Any SuperManager TOML profile\u{2026}"),
            Some("vpn-add.toml-import"),
        );
        vpn_add_menu.append_section(None, &other);
    }
    let vpn_add_menu_btn = gtk4::MenuButton::builder()
        .label("Add VPN connection")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .menu_model(&vpn_add_menu)
        .build();
    vpn_add_group.append(&vpn_add_menu_btn);

    // SSH Keys buttons (shown when SSH > Keys sub-tab is active).
    let ssh_keys_add_group = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(2)
        .build();
    let ssh_gen_key_btn = gtk4::Button::builder()
        .label("Generate SSH Key")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    let ssh_import_keys_btn = gtk4::Button::builder()
        .label("Import SSH Keys\u{2026}")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    let ssh_audit_btn = gtk4::Button::builder()
        .label("SSH Audit Log\u{2026}")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    let ssh_export_all_btn = gtk4::Button::builder()
        .label("Export All to ~/.ssh/")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    ssh_keys_add_group.append(&ssh_gen_key_btn);
    ssh_keys_add_group.append(&ssh_import_keys_btn);
    ssh_keys_add_group.append(&ssh_audit_btn);
    ssh_keys_add_group.append(&ssh_export_all_btn);

    // SSH Hosts buttons (shown when SSH > Hosts sub-tab is active).
    let ssh_hosts_add_group = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(2)
        .build();
    let ssh_add_host_btn = gtk4::Button::builder()
        .label("Add Host")
        .has_frame(false)
        .halign(gtk4::Align::Fill)
        .build();
    ssh_hosts_add_group.append(&ssh_add_host_btn);

    pop_box.append(&vpn_add_group);
    pop_box.append(&ssh_keys_add_group);
    pop_box.append(&ssh_hosts_add_group);
    // Start with only VPN group visible.
    ssh_keys_add_group.set_visible(false);
    ssh_hosts_add_group.set_visible(false);
    popover.set_child(Some(&pop_box));

    let add_menu_btn = gtk4::MenuButton::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Add")
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

    // Notification bell button + popover.
    let notif_btn = gtk4::MenuButton::builder()
        .icon_name("bell-outline-symbolic")
        .tooltip_text("Notifications")
        .css_classes(["flat"])
        .build();
    let notif_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    notif_list.set_widget_name("notif-list");
    let notif_placeholder = adw::ActionRow::builder()
        .title("No notifications")
        .activatable(false)
        .build();
    notif_list.append(&notif_placeholder);
    // Header label + clear button for the notification panel.
    let notif_header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_bottom(4)
        .build();
    let notif_title = gtk4::Label::builder()
        .label("Notifications")
        .css_classes(["heading"])
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    let notif_clear_btn = gtk4::Button::builder()
        .label("Clear")
        .css_classes(["flat"])
        .build();
    {
        let notif_list = notif_list.clone();
        notif_clear_btn.connect_clicked(move |_| {
            while let Some(child) = notif_list.first_child() {
                notif_list.remove(&child);
            }
            let placeholder = adw::ActionRow::builder()
                .title("No notifications")
                .activatable(false)
                .build();
            notif_list.append(&placeholder);
        });
    }
    notif_header.append(&notif_title);
    notif_header.append(&notif_clear_btn);

    let notif_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .min_content_width(420)
        .min_content_height(150)
        .max_content_height(500)
        .child(&notif_list)
        .build();
    let notif_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build();
    notif_box.append(&notif_header);
    notif_box.append(&notif_scroll);
    let notif_popover = gtk4::Popover::builder()
        .child(&notif_box)
        .build();
    notif_btn.set_popover(Some(&notif_popover));

    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&view_switcher));
    header.pack_end(&hamburger_btn);
    header.pack_end(&add_menu_btn);
    header.pack_end(&notif_btn);
    header.pack_end(&logs_btn);
    header.pack_end(&settings_btn);

    // -- Daemon-unavailable banner -------------------------------------------
    let banner = adw::Banner::new("Daemon not running");
    banner.set_button_label(Some("Retry"));
    {
        let available = app_state.lock().unwrap_or_else(|e| e.into_inner()).daemon_available;
        banner.set_revealed(!available);
    }

    // =========================================================================
    // VPN page
    // =========================================================================
    let (vpn_profile_list, vpn_search_entry, vpn_sidebar_page) =
        vpn::sidebar::build_vpn_sidebar(&app_state, &tx, &rt, &window);

    // VPN sidebar search entry — filters profiles by name as the user types.
    {
        let vpn_profile_list = vpn_profile_list.clone();
        let app_state = app_state.clone();
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        vpn_search_entry.connect_search_changed(move |entry| {
            let text = entry.text().to_string();
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            populate_vpn_sidebar(
                &vpn_profile_list,
                &s.profiles,
                &s.vpn_state,
                s.selected_profile.as_deref(),
                &window,
                &rt,
                &tx,
                &text,
            );
            drop(s);
            app_state.lock().unwrap_or_else(|e| e.into_inner()).vpn_filter = text;
        });
    }
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
    // Dashboard page (standalone, full-width)
    // =========================================================================
    let (dashboard_flow_box, dashboard_widget) =
        ssh::dashboard::build_ssh_dashboard(&app_state, &rt, &tx);

    view_stack.add_titled(&dashboard_widget, Some("dashboard"), "Dashboard");
    let dashboard_page_ref = view_stack.page(&dashboard_widget);
    dashboard_page_ref.set_icon_name(Some("utilities-system-monitor-symbolic"));

    // =========================================================================
    // Hosts page
    // =========================================================================
    let ssh_host_list = ssh::host_tree::build_ssh_host_list();

    let ssh_host_search = gtk4::SearchEntry::builder()
        .placeholder_text("Filter hosts\u{2026}")
        .margin_start(8)
        .margin_end(8)
        .margin_top(8)
        .build();
    {
        let ssh_host_list = ssh_host_list.clone();
        let app_state = app_state.clone();
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_search.connect_search_changed(move |entry| {
            let text = entry.text().to_string();
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            let health = s.host_health.clone();
            populate_ssh_host_list(
                &ssh_host_list,
                &s.hosts,
                s.selected_ssh_host.as_deref(),
                &window,
                &rt,
                &tx,
                &text,
                &health,
            );
            drop(s);
            app_state.lock().unwrap_or_else(|e| e.into_inner()).ssh_filter = text;
        });
    }

    let ssh_host_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&ssh_host_list)
        .build();

    // Sync to ~/.ssh/config button.
    let ssh_config_sync_btn = gtk4::Button::builder()
        .icon_name("document-save-symbolic")
        .tooltip_text("Sync hosts to ~/.ssh/config")
        .css_classes(["flat"])
        .build();
    let ssh_host_header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .build();
    ssh_host_search.set_hexpand(true);
    // Batch command button.
    let ssh_batch_btn = gtk4::Button::builder()
        .icon_name("utilities-terminal-symbolic")
        .tooltip_text("Run command on multiple hosts")
        .css_classes(["flat"])
        .build();
    {
        let app_state = Arc::clone(&app_state);
        let window = window.clone();
        let rt = rt.clone();
        ssh_batch_btn.connect_clicked(move |_| {
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            ssh::dialogs::show_batch_command_dialog(&window, &s.hosts, &rt);
        });
    }

    ssh_host_header.append(&ssh_host_search);
    ssh_host_header.append(&ssh_batch_btn);
    ssh_host_header.append(&ssh_config_sync_btn);

    {
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_config_sync_btn.connect_clicked(move |_| {
            let tx = tx.clone();
            rt.spawn(async move {
                match crate::dbus_client::generate_ssh_config().await {
                    Ok(count) => {
                        let _ = tx.send(AppMsg::ShowToast(
                            format!("Synced {count} hosts to ~/.ssh/config"),
                        ));
                    }
                    Err(e) => {
                        let _ = tx.send(AppMsg::OperationFailed(
                            format!("SSH config sync failed: {e}"),
                        ));
                    }
                }
            });
        });
    }

    let hosts_sidebar_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    hosts_sidebar_box.append(&ssh_host_header);
    hosts_sidebar_box.append(&ssh_host_scroll);

    let hosts_sidebar_page = adw::NavigationPage::builder()
        .title("Hosts")
        .child(&hosts_sidebar_box)
        .build();

    let (ssh_host_detail, ssh_host_detail_widget) = ssh::host_detail::build_ssh_host_detail();

    let hosts_content_stack = gtk4::Stack::new();
    let hosts_empty_status = adw::StatusPage::builder()
        .title("Hosts")
        .description("Select a host from the sidebar to view details.")
        .icon_name("computer-symbolic")
        .build();
    hosts_content_stack.add_named(&hosts_empty_status, Some("empty"));
    hosts_content_stack.add_named(&ssh_host_detail_widget, Some("host-detail"));
    hosts_content_stack.set_visible_child_name("empty");

    let hosts_content_page = adw::NavigationPage::builder()
        .title("Details")
        .child(&hosts_content_stack)
        .build();

    let hosts_split = adw::NavigationSplitView::builder().vexpand(true).build();
    hosts_split.set_min_sidebar_width(280.0);
    hosts_split.set_max_sidebar_width(400.0);
    hosts_split.set_sidebar(Some(&hosts_sidebar_page));
    hosts_split.set_content(Some(&hosts_content_page));

    view_stack.add_titled(&hosts_split, Some("hosts"), "Hosts");
    let hosts_page_ref = view_stack.page(&hosts_split);
    hosts_page_ref.set_icon_name(Some("computer-symbolic"));

    // =========================================================================
    // Keys page
    // =========================================================================
    let ssh_key_list = ssh::key_list::build_ssh_key_list();

    let ssh_key_search = gtk4::SearchEntry::builder()
        .placeholder_text("Filter keys\u{2026}")
        .margin_start(8)
        .margin_end(8)
        .margin_top(8)
        .build();
    {
        let ssh_key_list = ssh_key_list.clone();
        let app_state = app_state.clone();
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_key_search.connect_search_changed(move |entry| {
            let text = entry.text().to_string();
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            populate_ssh_key_list(
                &ssh_key_list,
                &s.ssh_keys,
                s.selected_ssh_key.as_deref(),
                &window,
                &rt,
                &tx,
                &text,
            );
        });
    }

    let ssh_key_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&ssh_key_list)
        .build();

    let keys_sidebar_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    keys_sidebar_box.append(&ssh_key_search);
    keys_sidebar_box.append(&ssh_key_scroll);

    let keys_sidebar_page = adw::NavigationPage::builder()
        .title("Keys")
        .child(&keys_sidebar_box)
        .build();

    let (ssh_key_detail, ssh_key_detail_widget) = ssh::key_detail::build_ssh_key_detail();

    let keys_content_stack = gtk4::Stack::new();
    let keys_empty_status = adw::StatusPage::builder()
        .title("Keys")
        .description("Select a key from the sidebar to view details.")
        .icon_name("dialog-password-symbolic")
        .build();
    keys_content_stack.add_named(&keys_empty_status, Some("empty"));
    keys_content_stack.add_named(&ssh_key_detail_widget, Some("key-detail"));
    keys_content_stack.set_visible_child_name("empty");

    let keys_content_page = adw::NavigationPage::builder()
        .title("Details")
        .child(&keys_content_stack)
        .build();

    let keys_split = adw::NavigationSplitView::builder().vexpand(true).build();
    keys_split.set_min_sidebar_width(280.0);
    keys_split.set_max_sidebar_width(400.0);
    keys_split.set_sidebar(Some(&keys_sidebar_page));
    keys_split.set_content(Some(&keys_content_page));

    view_stack.add_titled(&keys_split, Some("keys"), "Keys");
    let keys_page_ref = view_stack.page(&keys_split);
    keys_page_ref.set_icon_name(Some("dialog-password-symbolic"));

    // Search entry alias for keyboard shortcut (Ctrl+K / Ctrl+F).
    let ssh_search_entry = ssh_host_search.clone();

    // Populate SSH lists with initial state.
    {
        let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
            &s.hosts,
            s.selected_ssh_host.as_deref(),
            &window,
            &rt,
            &tx,
            "",
            &health,
        );
    }

    // =========================================================================
    // Right-click context menus on sidebar empty space
    // =========================================================================

    // VPN sidebar: right-click on empty space presents the same submenu
    // tree as the toolbar "+" Add button. The actions themselves live on
    // the window under the `vpn-add` namespace (installed below where
    // toast_overlay is in scope) — both this popover and the MenuButton
    // popover dispatch to the same handlers, so changes only need to be
    // made in one place.
    {
        let menu = gio::Menu::new();
        {
            let wg = gio::Menu::new();
            wg.append(Some("Import .conf file\u{2026}"), Some("vpn-add.wg-import"));
            menu.append_submenu(Some("WireGuard"), &wg);

            let fg = gio::Menu::new();
            fg.append(Some("Create new\u{2026}"), Some("vpn-add.fg-new"));
            menu.append_submenu(Some("FortiGate"), &fg);

            let ov = gio::Menu::new();
            ov.append(Some("Import .ovpn file\u{2026}"), Some("vpn-add.ov-import"));
            menu.append_submenu(Some("OpenVPN"), &ov);

            let az = gio::Menu::new();
            az.append(
                Some("Import Azure Portal config\u{2026}"),
                Some("vpn-add.az-import"),
            );
            menu.append_submenu(Some("Azure VPN"), &az);

            let other = gio::Menu::new();
            other.append(
                Some("Any SuperManager TOML profile\u{2026}"),
                Some("vpn-add.toml-import"),
            );
            menu.append_section(None, &other);
        }

        let popover = gtk4::PopoverMenu::from_model(Some(&menu));
        popover.set_parent(&vpn_profile_list);
        popover.set_has_arrow(false);

        let gesture = gtk4::GestureClick::builder().button(3).build();
        let popover_ref = popover.clone();
        gesture.connect_pressed(move |_, _, x, y| {
            popover_ref.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
            popover_ref.popup();
        });
        vpn_profile_list.add_controller(gesture);
    }

    // Hosts sidebar: right-click → Add SSH Host
    {
        let ssh_add_host_btn = ssh_add_host_btn.clone();

        let menu = gio::Menu::new();
        menu.append(Some("Add Host"), Some("hosts-bg.add-host"));

        let ag = gio::SimpleActionGroup::new();
        {
            let a = gio::SimpleAction::new("add-host", None);
            let b = ssh_add_host_btn.clone();
            a.connect_activate(move |_, _| b.emit_clicked());
            ag.add_action(&a);
        }

        let popover = gtk4::PopoverMenu::from_model(Some(&menu));
        popover.set_parent(&ssh_host_list);
        popover.set_has_arrow(false);
        ssh_host_list.insert_action_group("hosts-bg", Some(&ag));

        let gesture = gtk4::GestureClick::builder().button(3).build();
        let popover_ref = popover.clone();
        gesture.connect_pressed(move |_, _, x, y| {
            popover_ref.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
            popover_ref.popup();
        });
        ssh_host_list.add_controller(gesture);
    }

    // Keys sidebar: right-click → Generate Key / Import Keys
    {
        let ssh_gen_key_btn = ssh_gen_key_btn.clone();
        let ssh_import_keys_btn = ssh_import_keys_btn.clone();

        let menu = gio::Menu::new();
        menu.append(Some("Generate SSH Key"), Some("keys-bg.gen-key"));
        menu.append(Some("Import SSH Keys\u{2026}"), Some("keys-bg.import-keys"));

        let ag = gio::SimpleActionGroup::new();
        {
            let a = gio::SimpleAction::new("gen-key", None);
            let b = ssh_gen_key_btn.clone();
            a.connect_activate(move |_, _| b.emit_clicked());
            ag.add_action(&a);
        }
        {
            let a = gio::SimpleAction::new("import-keys", None);
            let b = ssh_import_keys_btn.clone();
            a.connect_activate(move |_, _| b.emit_clicked());
            ag.add_action(&a);
        }

        let popover = gtk4::PopoverMenu::from_model(Some(&menu));
        popover.set_parent(&ssh_key_list);
        popover.set_has_arrow(false);
        ssh_key_list.insert_action_group("keys-bg", Some(&ag));

        let gesture = gtk4::GestureClick::builder().button(3).build();
        let popover_ref = popover.clone();
        gesture.connect_pressed(move |_, _, x, y| {
            popover_ref.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
            popover_ref.popup();
        });
        ssh_key_list.add_controller(gesture);
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

    // Update the "+" popover contents when switching sections.
    {
        let vpn_add_group = vpn_add_group.clone();
        let ssh_keys_add_group = ssh_keys_add_group.clone();
        let ssh_hosts_add_group = ssh_hosts_add_group.clone();
        let add_menu_btn = add_menu_btn.clone();
        view_stack.connect_notify_local(Some("visible-child-name"), move |stack, _| {
            let page = stack.visible_child_name();
            let page = page.as_deref().unwrap_or("vpn");
            match page {
                "vpn" => {
                    vpn_add_group.set_visible(true);
                    ssh_keys_add_group.set_visible(false);
                    ssh_hosts_add_group.set_visible(false);
                    add_menu_btn.set_visible(true);
                }
                "hosts" => {
                    vpn_add_group.set_visible(false);
                    ssh_keys_add_group.set_visible(false);
                    ssh_hosts_add_group.set_visible(true);
                    add_menu_btn.set_visible(true);
                }
                "keys" => {
                    vpn_add_group.set_visible(false);
                    ssh_keys_add_group.set_visible(true);
                    ssh_hosts_add_group.set_visible(false);
                    add_menu_btn.set_visible(true);
                }
                _ => {
                    // Dashboard, Console, Provisioning — no add actions.
                    add_menu_btn.set_visible(false);
                }
            }
        });
    }

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
        if crate::master_password::is_set() {
            outer_stack.set_visible_child_name("lock");
            lock_page.status_label.set_text("Enter your master password to unlock.");
            lock_page.set_btn.set_visible(false);
            lock_page.confirm_row.set_visible(false);
            lock_page.password_row.grab_focus();
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
                let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
                if crate::master_password::is_set() && s.auto_lock_minutes > 0 {
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
        let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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

    // --- VPN add menu actions -----------------------------------------------
    //
    // One SimpleActionGroup attached to the MenuButton handles every
    // submenu entry. Each closure calls popover.popdown() on the OUTER
    // add-popover (the one with VPN/SSH-keys/SSH-hosts sections) so the
    // chrome closes after a dialog is launched.
    {
        let action_group = gio::SimpleActionGroup::new();

        let make_action = |name: &str| gio::SimpleAction::new(name, None);

        // WireGuard — import only.
        {
            let action = make_action("wg-import");
            let app_state = Arc::clone(&app_state);
            let toast_overlay = toast_overlay.clone();
            let popover = popover.clone();
            let tx = tx.clone();
            let rt = rt.clone();
            let window = window.clone();
            action.connect_activate(move |_, _| {
                popover.popdown();
                vpn::dialogs::import_wireguard(&window, &app_state, &toast_overlay, &tx, &rt);
            });
            action_group.add_action(&action);
        }

        // FortiGate — create new (the only backend with a build-from-form path today).
        {
            let action = make_action("fg-new");
            let popover = popover.clone();
            let window = window.clone();
            let rt = rt.clone();
            let tx = tx.clone();
            action.connect_activate(move |_, _| {
                popover.popdown();
                vpn::dialogs::show_fortigate_dialog(&window, &rt, &tx);
            });
            action_group.add_action(&action);
        }

        // OpenVPN — import only.
        {
            let action = make_action("ov-import");
            let app_state = Arc::clone(&app_state);
            let toast_overlay = toast_overlay.clone();
            let popover = popover.clone();
            let tx = tx.clone();
            let rt = rt.clone();
            let window = window.clone();
            action.connect_activate(move |_, _| {
                popover.popdown();
                vpn::dialogs::import_openvpn(&window, &app_state, &toast_overlay, &tx, &rt);
            });
            action_group.add_action(&action);
        }

        // Azure VPN — import only (config is downloaded from Azure Portal).
        {
            let action = make_action("az-import");
            let popover = popover.clone();
            let tx = tx.clone();
            let rt = rt.clone();
            let window = window.clone();
            action.connect_activate(move |_, _| {
                popover.popdown();
                vpn::dialogs::show_azure_import_dialog(&window, &rt, &tx);
            });
            action_group.add_action(&action);
        }

        // Universal TOML import — backend chosen by the file's [config] discriminator.
        {
            let action = make_action("toml-import");
            let app_state = Arc::clone(&app_state);
            let toast_overlay = toast_overlay.clone();
            let popover = popover.clone();
            let tx = tx.clone();
            let rt = rt.clone();
            let window = window.clone();
            action.connect_activate(move |_, _| {
                popover.popdown();
                vpn::dialogs::import_toml_config(
                    &window,
                    &app_state,
                    &toast_overlay,
                    &tx,
                    &rt,
                );
            });
            action_group.add_action(&action);
        }

        // Install the action group on the window — referenced from both
        // the MenuButton's popover and the sidebar's right-click popover
        // via the `vpn-add.<id>` action paths.
        window.insert_action_group("vpn-add", Some(&action_group));
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
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            ssh::dialogs::show_add_host_dialog(&window, &s.ssh_keys, &s.hosts, &s.profiles, &rt, &tx);
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
    {
        let popover = popover.clone();
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_export_all_btn.connect_clicked(move |_| {
            popover.popdown();
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            ssh::key_list::export_all_keys_to_ssh_dir(&s.ssh_keys, &rt, &tx);
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
        let full_tunnel_row = vpn_detail.full_tunnel_row.clone();
        let full_tunnel_switch = vpn_detail.full_tunnel_switch.clone();
        let kill_switch_switch = vpn_detail.kill_switch_switch.clone();
        let rotate_key_btn = vpn_detail.rotate_key_btn.clone();
        let export_btn = vpn_detail.export_btn.clone();
        let duplicate_btn = vpn_detail.duplicate_btn.clone();
        let split_routes_row = vpn_detail.split_routes_row.clone();
        let split_routes_value = vpn_detail.split_routes_value.clone();
        vpn_profile_list.connect_row_activated(move |list, row| {
            let idx = row.index() as usize;
            let (profile_name, profile_exists, ac, ft, ks, supports_split, split_routes, is_editable, is_wg, azure) = {
                let mut s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                let azure = entry.map_or(false, |p| p.backend.starts_with("Azure"));
                s.selected_profile = entry.map(|p| p.id.to_string());
                if matches!(s.vpn_state, VpnState::Error { .. }) {
                    s.vpn_state = VpnState::Disconnected;
                }
                (name, exists, ac, ft, ks, supports, routes, editable, wg, azure)
            };

            if profile_exists {
                if let Some(ref name) = profile_name {
                    vpn_content_page.set_title(name);
                    profile_name_label.set_label(name.as_str());
                }
                auto_connect_switch.set_active(ac);
                auto_connect_switch.set_sensitive(true);
                // Azure VPN routes are pushed by the gateway; full-tunnel toggle is meaningless.
                full_tunnel_row.set_visible(!azure);
                full_tunnel_switch.set_active(ft);
                full_tunnel_switch.set_sensitive(true);
                kill_switch_switch.set_active(ks);
                kill_switch_switch.set_sensitive(true);
                edit_creds_btn.set_visible(is_editable);
                rotate_key_btn.set_visible(is_wg);
                export_btn.set_sensitive(true);
                duplicate_btn.set_sensitive(true);
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

            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            rename_btn.set_sensitive(s.selected_profile.is_some());
            apply_vpn_state(&connect_btn, &rename_btn, &status_label, &stats_box, &s);
        });
    }

    // --- SSH key list selection ----------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let keys_content_stack = keys_content_stack.clone();
        let ssh_key_detail = &ssh_key_detail;
        let key_name_label = ssh_key_detail.key_name_label.clone();
        let key_type_badge = ssh_key_detail.key_type_badge.clone();
        let fingerprint_label = ssh_key_detail.fingerprint_label.clone();
        let _public_key_view = ssh_key_detail.public_key_view.clone();
        let tags_label = ssh_key_detail.tags_label.clone();
        let deployed_list = ssh_key_detail.deployed_list.clone();
        let key_detail_stack = ssh_key_detail.detail_stack.clone();
        let rt_for_key = rt.clone();
        let tx_for_key = tx.clone();
        ssh_key_list.connect_row_activated(move |_list, row| {
            let idx = row.index() as usize;
            let mut s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                keys_content_stack.set_visible_child_name("key-detail");
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
        let hosts_content_stack = hosts_content_stack.clone();
        let host_detail = ssh_host_detail.clone();
        let _host_label_lbl = host_detail.host_label_lbl.clone();
        let _group_badge = host_detail.group_badge.clone();
        let _hostname_row = host_detail.hostname_row.clone();
        let _port_row = host_detail.port_row.clone();
        let _username_row = host_detail.username_row.clone();
        let _device_type_row = host_detail.device_type_row.clone();
        let _auth_method_row = host_detail.auth_method_row.clone();
        let _host_detail_stack = host_detail.detail_stack.clone();
        let ssh_host_detail_for_closure = ssh_host_detail.clone();
        let rt_sel = rt.clone();
        let tx_sel = tx.clone();
        ssh_host_list.connect_row_activated(move |_list, row| {
            // Skip non-selectable group header rows.
            if !row.is_selectable() {
                return;
            }
            let idx = row.index();
            let mut s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            // Reconstruct the grouped order to find which host this row maps to.
            let mut groups: std::collections::BTreeMap<String, Vec<HostSummary>> =
                std::collections::BTreeMap::new();
            for host in &s.hosts {
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
            let mut flat: Vec<Option<HostSummary>> = Vec::new();
            for (_group_name, hosts_in_group) in &groups {
                flat.push(None); // group header
                for h in hosts_in_group {
                    flat.push(Some(h.clone()));
                }
            }

            if let Some(Some(host)) = flat.get(idx as usize) {
                ssh::host_detail::update_ssh_host_detail(&ssh_host_detail_for_closure, host, &s.hosts);
                hosts_content_stack.set_visible_child_name("host-detail");
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

                // Refresh port forward active status.
                if !host.port_forwards.is_empty() {
                    let tx = tx_sel.clone();
                    rt_sel.spawn(async move {
                        if let Ok(json) = crate::dbus_client::dbus_ssh_list_port_forwards().await {
                            let _ = tx.send(AppMsg::PortForwardsRefreshed(json));
                        }
                    });
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
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(host_id) = &s.selected_ssh_host {
                if let Some(host) = s.hosts.iter().find(|h| h.id.to_string() == *host_id) {
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
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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

    // --- FortiGate Show/Hide API Token button ---------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        let token_row = ssh_host_detail.fg_api_token_row.clone();
        let token_visible = std::rc::Rc::new(std::cell::Cell::new(false));
        ssh_host_detail.fg_show_token_btn.connect_clicked(move |btn| {
            if token_visible.get() {
                token_row.set_subtitle("••••••••");
                btn.set_icon_name("view-reveal-symbolic");
                token_visible.set(false);
                return;
            }
            let host_id = {
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
                s.selected_ssh_host.clone()
            };
            if let Some(host_id) = host_id {
                token_visible.set(true);
                let tx = tx.clone();
                rt.spawn(async move {
                    let result: Result<String, String> = async {
                        let conn = zbus::Connection::system().await
                            .map_err(|e| format!("D-Bus connect: {e}"))?;
                        let proxy = supermgr_core::dbus::DaemonProxy::new(&conn).await
                            .map_err(|e| format!("D-Bus proxy: {e}"))?;
                        proxy.fortigate_get_api_token(&host_id).await
                            .map_err(|e| format!("{e}"))
                    }.await;
                    match result {
                        Ok(token) => {
                            let _ = tx.send(AppMsg::FortigateApiTokenFetched {
                                host_id,
                                token,
                            });
                        }
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(
                                format!("API token: {e}"),
                            ));
                        }
                    }
                });
            }
        });
    }

    // --- Port Forward: "Add Forward" button ----------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        ssh_host_detail.pf_add_btn.connect_clicked(move |_| {
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(host_id) = &s.selected_ssh_host {
                if let Some(host) = s.hosts.iter().find(|h| h.id.to_string() == *host_id) {
                    let host = host.clone();
                    drop(s);
                    ssh::host_detail::show_add_port_forward_dialog(
                        &window, &host, &rt, &tx,
                    );
                }
            }
        });
    }

    // --- Port Forward: Start / Stop via listbox row activation ---------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        let pf_listbox = ssh_host_detail.pf_listbox.clone();
        pf_listbox.connect_row_activated(move |_list, row| {
            let key = row.widget_name().to_string();
            if key.is_empty() {
                return;
            }
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            let host_id = match &s.selected_ssh_host {
                Some(id) => id.clone(),
                None => return,
            };
            drop(s);

            // Parse the key to get local_port, remote_host, remote_port.
            let parts: Vec<&str> = key.splitn(3, ':').collect();
            if parts.len() < 3 {
                return;
            }
            let local_port: u16 = match parts[0].parse() {
                Ok(p) => p,
                Err(_) => return,
            };
            let remote_host = parts[1].to_owned();
            let remote_port: u16 = match parts[2].parse() {
                Ok(p) => p,
                Err(_) => return,
            };

            let tx = tx.clone();
            // Toggle: if forward is active (check via list_port_forwards), stop it;
            // otherwise start it.
            rt.spawn(async move {
                // Check if this forward is already active.
                let active_fwd_id = match crate::dbus_client::dbus_ssh_list_port_forwards().await {
                    Ok(json) => {
                        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&json) {
                            arr.iter().find_map(|entry| {
                                let eid = entry["host_id"].as_str()?;
                                let elp = entry["local_port"].as_u64()? as u16;
                                let erh = entry["remote_host"].as_str()?;
                                let erp = entry["remote_port"].as_u64()? as u16;
                                if eid == host_id && elp == local_port && erh == remote_host && erp == remote_port {
                                    Some(entry["forward_id"].as_str()?.to_owned())
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                };

                if let Some(fwd_id) = active_fwd_id {
                    // Stop the forward.
                    match crate::dbus_client::dbus_ssh_stop_port_forward(fwd_id).await {
                        Ok(()) => {
                            let _ = tx.send(AppMsg::ShowToast("Port forward stopped".into()));
                        }
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(format!("stop forward: {e}")));
                        }
                    }
                } else {
                    // Start the forward.
                    match crate::dbus_client::dbus_ssh_start_port_forward(
                        host_id.clone(),
                        local_port,
                        remote_host.clone(),
                        remote_port,
                    ).await {
                        Ok(_fwd_id) => {
                            let _ = tx.send(AppMsg::ShowToast(
                                format!("Port forward started: :{local_port} \u{2192} {remote_host}:{remote_port}")
                            ));
                        }
                        Err(e) => {
                            let _ = tx.send(AppMsg::OperationFailed(format!("start forward: {e}")));
                        }
                    }
                }

                // Refresh port forwards status.
                match crate::dbus_client::dbus_ssh_list_port_forwards().await {
                    Ok(json) => { let _ = tx.send(AppMsg::PortForwardsRefreshed(json)); }
                    Err(_) => {}
                }
            });
        });
    }

    // --- VPN Connect / Disconnect button ------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        vpn_detail.connect_btn.connect_clicked(move |_| {
            let (should_disconnect, selected) = {
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                app_state.lock().unwrap_or_else(|e| e.into_inner()).selected_profile.clone()
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
            let (profile_id, backend, name, host, username, dns_servers) = {
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                            p.dns_servers
                                .iter()
                                .map(|ip| ip.to_string())
                                .collect::<Vec<_>>()
                                .join(", "),
                        )
                    }
                    None => return,
                }
            };
            if backend.starts_with("FortiGate") {
                vpn::dialogs::show_edit_fortigate_dialog(
                    &window, profile_id, name, host, username, dns_servers, &rt, &tx,
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
                app_state.lock().unwrap_or_else(|e| e.into_inner()).selected_profile.clone()
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
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                app_state.lock().unwrap_or_else(|e| e.into_inner()).selected_profile.clone()
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
                app_state.lock().unwrap_or_else(|e| e.into_inner()).selected_profile.clone()
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
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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

    // --- Duplicate profile button -------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let rt = rt.clone();
        let tx = tx.clone();
        vpn_detail.duplicate_btn.connect_clicked(move |_| {
            let profile_id = {
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
                s.selected_profile.clone()
            };
            let Some(profile_id) = profile_id else { return };
            let tx = tx.clone();
            rt.spawn(async move {
                match dbus_export_profile(profile_id).await {
                    Ok(toml_text) => {
                        // Re-import the exported TOML with a " (copy)" suffix.
                        match crate::dbus_client::dbus_import_toml_string(toml_text, Some(" (copy)".to_string())).await {
                            Ok(profiles) => {
                                let _ = tx.send(AppMsg::ImportSucceeded {
                                    profiles,
                                    toast: Some("Profile duplicated"),
                                });
                            }
                            Err(e) => {
                                let _ = tx.send(AppMsg::OperationFailed(
                                    format!("duplicate profile: {e}"),
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(AppMsg::OperationFailed(
                            format!("export for duplicate: {e}"),
                        ));
                    }
                }
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
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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

    // --- RDP button -----------------------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        ssh_host_detail.rdp_btn.connect_clicked(move |_| {
            let (host_id, hostname, port, username, has_password) = {
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
                let sel = s.selected_ssh_host.as_deref();
                sel.and_then(|id| s.hosts.iter().find(|h| h.id.to_string() == id))
                    .map(|h| (h.id.to_string(), h.hostname.clone(), h.rdp_port.unwrap_or(3389), h.username.clone(), h.has_password))
                    .unwrap_or_default()
            };
            if hostname.is_empty() { return; }
            let tx = tx.clone();
            // Fetch password from daemon if available, then launch.
            if has_password {
                let rt = rt.clone();
                rt.spawn(async move {
                    let pw = async {
                        let conn = zbus::Connection::system().await.ok()?;
                        let proxy = supermgr_core::dbus::DaemonProxy::new(&conn).await.ok()?;
                        proxy.ssh_get_password(&host_id).await.ok()
                    }.await;
                    let result = ssh::host_detail::launch_rdp(&hostname, port, &username, pw.as_deref());
                    match result {
                        Ok(msg) => { let _ = tx.send(AppMsg::ShowToast(msg)); }
                        Err(msg) => { let _ = tx.send(AppMsg::OperationFailed(msg)); }
                    }
                });
            } else {
                match ssh::host_detail::launch_rdp(&hostname, port, &username, None) {
                    Ok(msg) => { let _ = tx.send(AppMsg::ShowToast(msg)); }
                    Err(msg) => { let _ = tx.send(AppMsg::OperationFailed(msg)); }
                }
            }
        });
    }

    // --- VNC button -----------------------------------------------------------
    {
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        ssh_host_detail.vnc_btn.connect_clicked(move |_| {
            let (hostname, port) = {
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
                let sel = s.selected_ssh_host.as_deref();
                sel.and_then(|id| s.hosts.iter().find(|h| h.id.to_string() == id))
                    .map(|h| (h.hostname.clone(), h.vnc_port.unwrap_or(5900)))
                    .unwrap_or_default()
            };
            if hostname.is_empty() { return; }
            let tx = tx.clone();
            match ssh::host_detail::launch_vnc(&hostname, port) {
                Ok(msg) => { let _ = tx.send(AppMsg::ShowToast(msg)); }
                Err(msg) => { let _ = tx.send(AppMsg::OperationFailed(msg)); }
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
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(host_id) = &s.selected_ssh_host {
                if let Some(host) = s.hosts.iter().find(|h| h.id.to_string() == *host_id) {
                    ssh::dialogs::show_edit_host_dialog(
                        &window, host, &s.ssh_keys, &s.hosts, &s.profiles, &rt, &tx,
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
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            ssh::dialogs::show_push_key_dialog(
                &window,
                &s.ssh_keys,
                &s.hosts,
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
        let keys_content_stack = keys_content_stack.clone();
        ssh_key_detail.delete_btn.connect_clicked(move |_| {
            let key_id = {
                app_state.lock().unwrap_or_else(|e| e.into_inner()).selected_ssh_key.clone()
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
            let keys_content_stack = keys_content_stack.clone();
            dialog.connect_response(Some("delete"), move |_dlg, _resp| {
                let key_id = key_id.clone();
                let tx = tx.clone();
                let keys_content_stack = keys_content_stack.clone();
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
                keys_content_stack.set_visible_child_name("empty");
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
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            ssh::dialogs::show_push_key_dialog(
                &window,
                &s.ssh_keys,
                &s.hosts,
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
            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                let _toast_overlay = toast_overlay.clone();
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
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                let _toast_overlay = toast_overlay.clone();
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
        let hosts_content_stack = hosts_content_stack.clone();
        ssh_host_detail.delete_btn.connect_clicked(move |_| {
            let host_id = {
                app_state.lock().unwrap_or_else(|e| e.into_inner()).selected_ssh_host.clone()
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
            let hosts_content_stack = hosts_content_stack.clone();
            dialog.connect_response(Some("delete"), move |_dlg, _resp| {
                let host_id = host_id.clone();
                let tx = tx.clone();
                let hosts_content_stack = hosts_content_stack.clone();
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
                hosts_content_stack.set_visible_child_name("empty");
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
                app_state.lock().unwrap_or_else(|e| e.into_inner()).selected_ssh_host.clone()
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
                        let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
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
    let rx_keys_content_stack = keys_content_stack.clone();
    let rx_hosts_content_stack = hosts_content_stack.clone();
    let rx_ssh_key_pubkey_view = ssh_key_detail.public_key_view.clone();
    let rx_console_panel = console_panel.clone();
    let rx_ssh_host_detail = ssh_host_detail.clone();
    let rx_dashboard_flow_box = dashboard_flow_box.clone();
    let rx_notif_list = notif_list.clone();
    let rx_notif_btn = notif_btn.clone();

    let prev_state_init: VpnState = {
        let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
        s.vpn_state.clone()
    };
    let mut rx_prev_state = prev_state_init;

    glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                // === VPN messages =========================================
                AppMsg::DaemonConnected { profiles, state } => {
                    {
                        let mut s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        s.profiles = profiles;
                        s.vpn_state = state;
                        s.daemon_available = true;
                    }
                    rx_banner.set_revealed(false);
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    populate_vpn_sidebar(
                        &rx_profile_list,
                        &s.profiles,
                        &s.vpn_state,
                        s.selected_profile.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                        &s.vpn_filter,
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
                        let mut s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        s.profiles = profiles;
                    }
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    populate_vpn_sidebar(
                        &rx_profile_list,
                        &s.profiles,
                        &s.vpn_state,
                        s.selected_profile.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                        &s.vpn_filter,
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
                        let mut s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        s.vpn_state = state;
                        s.daemon_available = true;
                    }
                    rx_banner.set_revealed(false);
                    // Snapshot everything we need, then drop the lock.
                    // push_notification() needs to re-lock, so we must not hold it.
                    let (vpn_state_snap, profiles_snap, selected_snap, vpn_filter_snap) = {
                        let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        (s.vpn_state.clone(), s.profiles.clone(),
                         s.selected_profile.clone(), s.vpn_filter.clone())
                    };
                    // Desktop notifications on state transitions.
                    match &vpn_state_snap {
                        VpnState::Connected { profile_id, .. } => {
                            if !matches!(&rx_prev_state, VpnState::Connected { .. }) {
                                let body = profiles_snap
                                    .iter()
                                    .find(|p| p.id == *profile_id)
                                    .map(|p| p.name.as_str())
                                    .unwrap_or("Unknown profile");
                                let notif = gio::Notification::new("VPN Connected");
                                notif.set_body(Some(body));
                                rx_app.send_notification(Some("vpn-state"), &notif);
                                push_notification(
                                    &rx_app_state, &rx_notif_list, &rx_notif_btn,
                                    "network-vpn-symbolic",
                                    &format!("VPN Connected: {body}"),
                                );
                            }
                        }
                        VpnState::Error { message, .. } => {
                            let notif = gio::Notification::new("VPN Error");
                            notif.set_body(Some(message.as_str()));
                            rx_app.send_notification(Some("vpn-state"), &notif);
                            push_notification(
                                &rx_app_state, &rx_notif_list, &rx_notif_btn,
                                "dialog-warning-symbolic",
                                &format!("VPN Error: {message}"),
                            );
                        }
                        VpnState::Disconnected => {
                            if let VpnState::Connected { profile_id, .. } = &rx_prev_state {
                                let body = profiles_snap
                                    .iter()
                                    .find(|p| p.id == *profile_id)
                                    .map(|p| p.name.as_str())
                                    .unwrap_or("Unknown profile");
                                let notif = gio::Notification::new("VPN Disconnected");
                                notif.set_body(Some(body));
                                rx_app.send_notification(Some("vpn-state"), &notif);
                                push_notification(
                                    &rx_app_state, &rx_notif_list, &rx_notif_btn,
                                    "network-vpn-disabled-symbolic",
                                    &format!("VPN Disconnected: {body}"),
                                );
                            }
                        }
                        _ => {}
                    }
                    rx_prev_state = vpn_state_snap.clone();
                    if !matches!(vpn_state_snap, VpnState::Connected { .. }) {
                        rx_stats_uptime.set_visible(false);
                        rx_stats_virtual_ip.set_visible(false);
                        rx_stats_routes.set_visible(false);
                    }
                    let display_name = selected_snap
                        .as_deref()
                        .and_then(|sid| profiles_snap.iter().find(|p| p.id.to_string() == sid))
                        .map(|p| p.name.as_str())
                        .unwrap_or("");
                    rx_profile_name_label.set_label(display_name);
                    populate_vpn_sidebar(
                        &rx_profile_list,
                        &profiles_snap,
                        &vpn_state_snap,
                        selected_snap.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                        &vpn_filter_snap,
                    );
                    // Re-lock briefly for apply_vpn_state (reads multiple fields).
                    {
                        let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        apply_vpn_state(
                            &rx_connect_btn,
                            &rx_rename_btn,
                            &rx_status_label,
                            &rx_stats_box,
                            &s,
                        );
                    }
                    push_tray_update(
                        &rx_tray_handle,
                        vpn_state_snap.clone(),
                        profiles_snap.clone(),
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
                        let mut s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        s.profiles.retain(|p| p.id.to_string() != deleted_id);
                        if s.selected_profile.as_deref() == Some(deleted_id.as_str()) {
                            s.selected_profile = None;
                        }
                    }
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    populate_vpn_sidebar(
                        &rx_profile_list,
                        &s.profiles,
                        &s.vpn_state,
                        s.selected_profile.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                        &s.vpn_filter,
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
                    rx_app_state.lock().unwrap_or_else(|e| e.into_inner()).daemon_available = false;
                    rx_banner.set_revealed(true);
                }
                AppMsg::OperationFailed(msg) => {
                    error!("operation failed: {}", msg);
                    push_notification(
                        &rx_app_state, &rx_notif_list, &rx_notif_btn,
                        "dialog-error-symbolic", &msg,
                    );
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
                    push_notification(
                        &rx_app_state, &rx_notif_list, &rx_notif_btn,
                        "emblem-ok-symbolic", &msg,
                    );
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
                        let launcher = gtk4::UriLauncher::new(&verification_url);
                        launcher.launch(Some(&rx_window), gio::Cancellable::NONE, |_| {});
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
                        let mut s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        s.ssh_keys = keys;
                    }
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
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
                            rx_app_state.lock().unwrap_or_else(|e| e.into_inner()).selected_ssh_key = None;
                            rx_keys_content_stack.set_visible_child_name("empty");
                        }
                    }
                    rx_toast_overlay.add_toast(adw::Toast::new("SSH keys updated"));
                }
                AppMsg::SshHostsRefreshed(hosts) => {
                    {
                        let mut s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        s.hosts = hosts;
                    }
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    let filter = s.ssh_filter.clone();
                    let health = s.host_health.clone();
                    populate_ssh_host_list(
                        &rx_ssh_host_list,
                        &s.hosts,
                        s.selected_ssh_host.as_deref(),
                        &rx_window,
                        &rx_rt,
                        &rx_tx,
                        &filter,
                        &health,
                    );
                    if let Some(sel) = &s.selected_ssh_host {
                        if let Some(host) = s.hosts.iter().find(|h| h.id.to_string() == *sel) {
                            // Refresh the detail panel with updated data.
                            ssh::host_detail::update_ssh_host_detail(&rx_ssh_host_detail, host, &s.hosts);
                        } else {
                            drop(s);
                            rx_app_state.lock().unwrap_or_else(|e| e.into_inner()).selected_ssh_host = None;
                            rx_hosts_content_stack.set_visible_child_name("empty");
                        }
                    }
                }
                AppMsg::HostHealthChanged { host_id, reachable } => {
                    let was_known_before;
                    let old_reachable;
                    {
                        let mut s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        old_reachable = s.host_health.get(&host_id).copied();
                        was_known_before = old_reachable.is_some();
                        s.host_health.insert(host_id.clone(), reachable);
                    }
                    // Desktop notification on state *change* (not initial discovery).
                    if was_known_before && old_reachable != Some(reachable) {
                        let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                        let host_label = s.hosts.iter()
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
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    let filter = s.ssh_filter.clone();
                    let health = s.host_health.clone();
                    populate_ssh_host_list(
                        &rx_ssh_host_list,
                        &s.hosts,
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
                AppMsg::EditSshHost(host_id) => {
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(host) = s.hosts.iter().find(|h| h.id.to_string() == host_id) {
                        ssh::dialogs::show_edit_host_dialog(
                            &rx_window, host, &s.ssh_keys, &s.hosts, &s.profiles, &rx_rt, &rx_tx,
                        );
                    }
                }
                AppMsg::EditVpnProfile(profile_id) => {
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(p) = s.profiles.iter().find(|p| p.id.to_string() == profile_id) {
                        let backend = p.backend.clone();
                        let name = p.name.clone();
                        let host = p.host.clone().unwrap_or_default();
                        let username = p.username.clone().unwrap_or_default();
                        let dns_servers = p
                            .dns_servers
                            .iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        drop(s);
                        if backend.starts_with("FortiGate") {
                            vpn::dialogs::show_edit_fortigate_dialog(
                                &rx_window, profile_id, name, host, username, dns_servers,
                                &rx_rt, &rx_tx,
                            );
                        } else if backend == "OpenVPN3" {
                            vpn::dialogs::show_edit_openvpn_dialog(
                                &rx_window, profile_id, username, &rx_rt, &rx_tx,
                            );
                        }
                    }
                }
                AppMsg::PushSshKey(key_id) => {
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    ssh::dialogs::show_push_key_dialog(
                        &rx_window,
                        &s.ssh_keys,
                        &s.hosts,
                        Some(&key_id),
                        &rx_rt,
                        &rx_tx,
                    );
                }
                // === FortiGate messages =======================================
                AppMsg::PortForwardsRefreshed(json) => {
                    // Build active map: "local_port:remote_host:remote_port" → forward_id
                    let mut active_map = std::collections::HashMap::new();
                    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&json) {
                        for entry in &arr {
                            let fid = entry["forward_id"].as_str().unwrap_or_default().to_owned();
                            let lp = entry["local_port"].as_u64().unwrap_or(0);
                            let rh = entry["remote_host"].as_str().unwrap_or_default();
                            let rp = entry["remote_port"].as_u64().unwrap_or(0);
                            active_map.insert(format!("{lp}:{rh}:{rp}"), fid);
                        }
                    }
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(sel) = &s.selected_ssh_host {
                        if let Some(host) = s.hosts.iter().find(|h| h.id.to_string() == *sel) {
                            ssh::host_detail::populate_port_forwards_list(
                                &rx_ssh_host_detail.pf_listbox,
                                &host.port_forwards,
                                Some(&active_map),
                                Some(&host.id.to_string()),
                                Some(&rx_rt),
                                Some(&rx_tx),
                            );
                        }
                    }
                }
                AppMsg::FortigateStatus { host_id, data } => {
                    // Only apply if this host is still the selected one.
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    if s.selected_ssh_host.as_deref() == Some(&host_id) {
                        ssh::host_detail::apply_fortigate_status(
                            &rx_ssh_host_detail,
                            &data,
                        );
                    }
                }
                AppMsg::FortigateApiTokenFetched { host_id, token } => {
                    let s = rx_app_state.lock().unwrap_or_else(|e| e.into_inner());
                    if s.selected_ssh_host.as_deref() == Some(&host_id) {
                        rx_ssh_host_detail.fg_api_token_row.set_subtitle(&token);
                        rx_ssh_host_detail.fg_show_token_btn.set_icon_name("view-conceal-symbolic");
                    }
                }
                AppMsg::FortigateCompliance { host_id: _, data } => {
                    let win = rx_window.clone();
                    ssh::host_detail::show_compliance_dialog(
                        &win,
                        &data,
                    );
                }
                AppMsg::FortigateConfigDiff { hostname, diff } => {
                    let win = gtk4::Window::builder()
                        .title(&format!("Config diff — {hostname}"))
                        .default_width(700)
                        .default_height(550)
                        .resizable(true)
                        .build();
                    let header = adw::HeaderBar::new();
                    let text_view = gtk4::TextView::builder()
                        .editable(false)
                        .cursor_visible(false)
                        .monospace(true)
                        .top_margin(8)
                        .bottom_margin(8)
                        .left_margin(8)
                        .right_margin(8)
                        .build();
                    text_view.buffer().set_text(&diff);
                    let scroll = gtk4::ScrolledWindow::builder()
                        .vexpand(true)
                        .child(&text_view)
                        .build();
                    let vbox = gtk4::Box::builder()
                        .orientation(gtk4::Orientation::Vertical)
                        .build();
                    vbox.append(&header);
                    vbox.append(&scroll);
                    win.set_child(Some(&vbox));
                    win.present();
                }
                AppMsg::DashboardDeviceStatus { host_id, data } => {
                    ssh::dashboard::apply_dashboard_status(
                        &rx_dashboard_flow_box,
                        &host_id,
                        &data,
                    );
                    rx_dashboard_flow_box.invalidate_sort();
                    ssh::dashboard::refresh_summary(&rx_dashboard_flow_box);
                }
                AppMsg::DashboardCloudDevices { devices } => {
                    ssh::dashboard::add_cloud_device_cards(
                        &rx_dashboard_flow_box,
                        &devices,
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
                        view_stack.set_visible_child_name("dashboard");
                        return glib::Propagation::Stop;
                    }
                    gtk4::gdk::Key::_3 => {
                        view_stack.set_visible_child_name("hosts");
                        return glib::Propagation::Stop;
                    }
                    gtk4::gdk::Key::_4 => {
                        view_stack.set_visible_child_name("keys");
                        return glib::Propagation::Stop;
                    }
                    gtk4::gdk::Key::_5 => {
                        view_stack.set_visible_child_name("console");
                        console_input.grab_focus();
                        return glib::Propagation::Stop;
                    }
                    gtk4::gdk::Key::_6 => {
                        view_stack.set_visible_child_name("provisioning");
                        return glib::Propagation::Stop;
                    }
                    gtk4::gdk::Key::k | gtk4::gdk::Key::f => {
                        ssh_search_entry.grab_focus();
                        return glib::Propagation::Stop;
                    }
                    // Ctrl+L: manually lock the session.
                    gtk4::gdk::Key::l => {
                        if crate::master_password::is_set() {
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
            if crate::master_password::verify(&password) {
                // Transparently upgrade pre-Argon2 hashes on first successful
                // unlock — same password, stronger KDF on disk.
                if crate::master_password::needs_upgrade() {
                    crate::master_password::upgrade_legacy(&password);
                }
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

    // --- Quit button (exits the application from the lock screen) -------------
    {
        let window_quit = window.clone();
        lock_page.quit_btn.connect_clicked(move |_| {
            window_quit.close();
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
                let _ = crate::master_password::set(&pw);
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
        let quit_btn = lock_page.quit_btn.clone();
        key_ctrl.connect_key_pressed(move |_, key, _, _| {
            if outer_stack_enter.visible_child_name().as_deref() == Some("lock") {
                if key == gtk4::gdk::Key::Return || key == gtk4::gdk::Key::KP_Enter {
                    if unlock_btn.is_visible() {
                        unlock_btn.emit_clicked();
                        return glib::Propagation::Stop;
                    } else if set_btn.is_visible() {
                        set_btn.emit_clicked();
                        return glib::Propagation::Stop;
                    }
                } else if key == gtk4::gdk::Key::Escape {
                    quit_btn.emit_clicked();
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

    // =========================================================================
    // Keyboard shortcuts (actions + accelerators)
    // =========================================================================

    // --- Ctrl+Q: Quit -------------------------------------------------------
    {
        let quit_action = gio::SimpleAction::new("quit", None);
        let tx = tx.clone();
        quit_action.connect_activate(move |_, _| {
            tx.send(AppMsg::Quit).ok();
        });
        window.add_action(&quit_action);
        app.set_accels_for_action("win.quit", &["<Control>q"]);
    }

    // --- Ctrl+F: Focus search entry -----------------------------------------
    {
        let focus_search_action = gio::SimpleAction::new("focus-search", None);
        let view_stack = view_stack.clone();
        let ssh_search_entry = ssh_search_entry.clone();
        focus_search_action.connect_activate(move |_, _| {
            let page = view_stack.visible_child_name();
            match page.as_deref() {
                Some("hosts") | Some("keys") => {
                    ssh_search_entry.grab_focus();
                }
                _ => {}
            }
        });
        window.add_action(&focus_search_action);
        app.set_accels_for_action("win.focus-search", &["<Control>f"]);
    }

    // --- Ctrl+N: Open the "Add" popover ------------------------------------
    {
        let open_add_action = gio::SimpleAction::new("open-add", None);
        let add_menu_btn = add_menu_btn.clone();
        let popover = popover.clone();
        open_add_action.connect_activate(move |_, _| {
            if add_menu_btn.is_visible() {
                popover.popup();
            }
        });
        window.add_action(&open_add_action);
        app.set_accels_for_action("win.open-add", &["<Control>n"]);
    }

    // --- Escape: Clear search / close popover -------------------------------
    {
        let escape_action = gio::SimpleAction::new("escape", None);
        let ssh_search_entry = ssh_search_entry.clone();
        let popover = popover.clone();
        let view_stack = view_stack.clone();
        escape_action.connect_activate(move |_, _| {
            // If the popover is open, close it first.
            if popover.is_visible() {
                popover.popdown();
                return;
            }
            // Otherwise, clear search in the active section.
            let page = view_stack.visible_child_name();
            if matches!(page.as_deref(), Some("hosts") | Some("keys")) {
                let text = ssh_search_entry.text();
                if !text.is_empty() {
                    ssh_search_entry.set_text("");
                }
            }
        });
        window.add_action(&escape_action);
        app.set_accels_for_action("win.escape", &["Escape"]);
    }

    // --- F5: Refresh current view -------------------------------------------
    {
        let refresh_action = gio::SimpleAction::new("refresh", None);
        let app_state = Arc::clone(&app_state);
        let tx = tx.clone();
        let rt = rt.clone();
        refresh_action.connect_activate(move |_, _| {
            let app_state = Arc::clone(&app_state);
            let tx = tx.clone();
            rt.spawn(async move {
                // Re-fetch VPN state.
                match fetch_initial_state(&app_state).await {
                    Ok(()) => {
                        let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
                        tx.send(AppMsg::DaemonConnected {
                            profiles: s.profiles.clone(),
                            state: s.vpn_state.clone(),
                        }).ok();
                    }
                    Err(_) => {
                        tx.send(AppMsg::DaemonUnavailable).ok();
                    }
                }
                // Re-fetch SSH state.
                match fetch_initial_ssh_state(&app_state).await {
                    Ok(()) => {
                        let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
                        tx.send(AppMsg::SshKeysRefreshed(s.ssh_keys.clone())).ok();
                        tx.send(AppMsg::SshHostsRefreshed(s.hosts.clone())).ok();
                    }
                    Err(_) => {}
                }
            });
        });
        window.add_action(&refresh_action);
        app.set_accels_for_action("win.refresh", &["F5"]);
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
/// Push a notification into the store and update the popover list.
fn push_notification(
    app_state: &Arc<Mutex<AppState>>,
    notif_list: &gtk4::ListBox,
    notif_btn: &gtk4::MenuButton,
    icon: &'static str,
    message: &str,
) {
    {
        let mut s = app_state.lock().unwrap_or_else(|e| e.into_inner());
        s.push_notification(icon, message);
    }

    // Remove placeholder if present.
    while let Some(child) = notif_list.first_child() {
        if child.downcast_ref::<adw::ActionRow>()
            .map_or(false, |r| r.title() == "No notifications")
        {
            notif_list.remove(&child);
            break;
        } else {
            break;
        }
    }

    // Prepend new row with wrapping text.
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let row_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(8)
        .margin_end(8)
        .build();
    row_box.append(&gtk4::Image::from_icon_name(icon));
    let text_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(2)
        .hexpand(true)
        .build();
    let msg_lbl = gtk4::Label::builder()
        .label(message)
        .halign(gtk4::Align::Start)
        .wrap(true)
        .wrap_mode(gtk4::pango::WrapMode::WordChar)
        .build();
    let time_lbl = gtk4::Label::builder()
        .label(&now)
        .halign(gtk4::Align::Start)
        .css_classes(["caption", "dim-label"])
        .build();
    text_box.append(&msg_lbl);
    text_box.append(&time_lbl);
    row_box.append(&text_box);
    notif_list.prepend(&row_box);

    // Badge: update icon to filled bell.
    notif_btn.set_icon_name("bell-symbolic");
}

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
