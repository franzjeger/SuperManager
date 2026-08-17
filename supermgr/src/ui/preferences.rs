//! Application settings.
//!
//! # Why this is not in `vpn::dialogs`
//!
//! It used to be, which meant the window that configures the theme, the
//! master password, the Claude API key, the UniFi cloud credentials and the
//! RDP client lived in a file whose own doc comment describes it as "VPN
//! import/edit dialogs". Nothing about these settings is a VPN concern; they
//! were there because that is where the first one happened to be written.
//!
//! # Pages, not one long scroll
//!
//! The dialog was a single `AdwPreferencesPage` holding seven groups —
//! Appearance, Claude Console, Remote Desktop, UniFi Cloud, Security,
//! Notifications and Backup — inside a 420x600 box. Seven unrelated topics in
//! one 600px scroller is the settings equivalent of the single-column detail
//! pane the rest of the redesign removed: everything is present, nothing is
//! findable, and the only way to know whether a setting exists is to scroll
//! to the bottom and check.
//!
//! `AdwPreferencesDialog` gives each topic a page and a tab, which is the
//! platform's own answer to exactly this. The groups themselves are unchanged
//! — same rows, same handlers, same `AppSettings` writes. Only what carries
//! them is different.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::{gio, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::error;

use crate::app::AppMsg;
use crate::settings::{AppSettings, ColorScheme};

/// Show the application settings dialog.
pub fn show_settings_dialog(
    window: &adw::ApplicationWindow,
    app_settings: Arc<Mutex<AppSettings>>,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
) {
    let dialog = adw::PreferencesDialog::builder().title("Settings").build();

    let appearance_group = adw::PreferencesGroup::builder()
        .title("Appearance")
        .build();

    let theme_model = gtk4::StringList::new(&["Follow System", "Light", "Dark"]);
    let theme_row = adw::ComboRow::builder()
        .title("Theme")
        .model(&theme_model)
        .build();
    {
        let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
        let idx = match s.color_scheme {
            ColorScheme::Default => 0,
            ColorScheme::Light => 1,
            ColorScheme::Dark => 2,
        };
        theme_row.set_selected(idx);
    }
    appearance_group.add(&theme_row);

    let opacity_action_row = adw::ActionRow::builder()
        .title("Opacity")
        .subtitle("Window transparency")
        .build();
    let opacity_adj = gtk4::Adjustment::new(
        app_settings.lock().unwrap_or_else(|e| e.into_inner()).opacity * 100.0,
        10.0,
        100.0,
        1.0,
        10.0,
        0.0,
    );
    let opacity_scale = gtk4::Scale::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .adjustment(&opacity_adj)
        .digits(0)
        .draw_value(true)
        .value_pos(gtk4::PositionType::Right)
        .width_request(180)
        .valign(gtk4::Align::Center)
        .build();
    opacity_scale.add_mark(10.0, gtk4::PositionType::Bottom, None);
    opacity_scale.add_mark(50.0, gtk4::PositionType::Bottom, None);
    opacity_scale.add_mark(100.0, gtk4::PositionType::Bottom, None);
    opacity_action_row.add_suffix(&opacity_scale);
    appearance_group.add(&opacity_action_row);

    // --- Claude Console group ---
    let console_group = adw::PreferencesGroup::builder()
        .title("Claude Console")
        .description("Choose between Claude subscription (free with Claude Code login) or API key (pay-per-token)")
        .build();

    let sub_row = adw::SwitchRow::builder()
        .title("Use Claude subscription")
        .subtitle("Uses `claude` CLI — requires Claude Code login")
        .build();
    {
        let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
        sub_row.set_active(s.use_claude_subscription);
    }
    console_group.add(&sub_row);

    let api_key_row = adw::PasswordEntryRow::builder()
        .title("Anthropic API Key (only if subscription disabled)")
        .build();
    {
        let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
        if !s.anthropic_api_key.is_empty() {
            api_key_row.set_text(&s.anthropic_api_key);
        }
        api_key_row.set_sensitive(!s.use_claude_subscription);
    }
    console_group.add(&api_key_row);

    {
        let app_settings = Arc::clone(&app_settings);
        let api_key_row = api_key_row.clone();
        sub_row.connect_active_notify(move |row| {
            let active = row.is_active();
            api_key_row.set_sensitive(!active);
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            s.use_claude_subscription = active;
            s.save();
        });
    }

    {
        let app_settings = Arc::clone(&app_settings);
        api_key_row.connect_changed(move |row| {
            let key = row.text().to_string();
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            s.anthropic_api_key = key;
            s.save();
        });
    }

    // --- Security group (master password / auto-lock) ---
    let security_group = adw::PreferencesGroup::builder()
        .title("Security")
        .description("Master password and session lock")
        .build();

    let has_pw = crate::master_password::is_set();

    let pw_status_row = adw::ActionRow::builder()
        .title("Master Password")
        .subtitle(if has_pw { "Set" } else { "Not set" })
        .build();

    let change_pw_btn = gtk4::Button::builder()
        .label(if has_pw { "Change" } else { "Set" })
        .valign(gtk4::Align::Center)
        .css_classes(["flat"])
        .build();
    pw_status_row.add_suffix(&change_pw_btn);

    if has_pw {
        let remove_pw_btn = gtk4::Button::builder()
            .label("Remove")
            .valign(gtk4::Align::Center)
            .css_classes(["flat", "destructive-action"])
            .build();
        pw_status_row.add_suffix(&remove_pw_btn);

        let _app_settings_rm = Arc::clone(&app_settings);
        let pw_status_row_rm = pw_status_row.clone();
        remove_pw_btn.connect_clicked(move |btn| {
            crate::master_password::clear();
            pw_status_row_rm.set_subtitle("Not set");
            btn.set_visible(false);
        });
    }

    security_group.add(&pw_status_row);

    // Change / set password button -> opens a small inline dialog.
    {
        let app_settings = Arc::clone(&app_settings);
        let window = window.clone();
        change_pw_btn.connect_clicked(move |_| {
            show_change_password_dialog(&window, Arc::clone(&app_settings));
        });
    }

    let auto_lock_row = adw::SpinRow::builder()
        .title("Auto-lock timeout")
        .subtitle("Minutes of inactivity (0 = disabled)")
        .adjustment(&gtk4::Adjustment::new(
            app_settings.lock().unwrap_or_else(|e| e.into_inner()).auto_lock_minutes as f64,
            0.0,
            120.0,
            1.0,
            5.0,
            0.0,
        ))
        .build();
    security_group.add(&auto_lock_row);

    {
        let app_settings = Arc::clone(&app_settings);
        auto_lock_row.connect_value_notify(move |row| {
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            {
                s.auto_lock_minutes = row.value() as u64;
            }
            s.save();
        });
    }

    // --- Notifications group (webhook) ---
    let notify_group = adw::PreferencesGroup::builder()
        .title("Notifications")
        .description("Send alerts to Slack, Teams, or Discord via webhook")
        .build();

    let webhook_url_row = adw::EntryRow::builder()
        .title("Webhook URL")
        .build();
    {
        let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
        if !s.webhook_url.is_empty() {
            webhook_url_row.set_text(&s.webhook_url);
        }
    }
    notify_group.add(&webhook_url_row);

    let host_down_toggle = adw::SwitchRow::builder()
        .title("Host down alerts")
        .subtitle("Notify when an SSH host becomes unreachable")
        .build();
    host_down_toggle.set_active(app_settings.lock().unwrap_or_else(|e| e.into_inner()).webhook_on_host_down);
    notify_group.add(&host_down_toggle);

    let vpn_disconnect_toggle = adw::SwitchRow::builder()
        .title("VPN disconnect alerts")
        .subtitle("Notify when a VPN tunnel drops unexpectedly")
        .build();
    vpn_disconnect_toggle.set_active(app_settings.lock().unwrap_or_else(|e| e.into_inner()).webhook_on_vpn_disconnect);
    notify_group.add(&vpn_disconnect_toggle);

    let test_webhook_row = adw::ActionRow::builder()
        .title("Test Webhook")
        .subtitle("Send a test message to verify the URL works")
        .build();
    let test_webhook_btn = gtk4::Button::builder()
        .label("Test")
        .valign(gtk4::Align::Center)
        .css_classes(["flat"])
        .build();
    test_webhook_row.add_suffix(&test_webhook_btn);
    notify_group.add(&test_webhook_row);

    // Helper: push the current webhook settings to the daemon over D-Bus so
    // the daemon's in-memory state stays in sync with the GUI settings file.
    fn push_webhook_to_daemon(
        rt: &tokio::runtime::Handle,
        url: String,
        on_host_down: bool,
        on_vpn_disconnect: bool,
    ) {
        rt.spawn(async move {
            use supermgr_core::dbus::DaemonProxy;
            if let Ok(conn) = supermgr_core::client::system_connection().await {
                if let Ok(proxy) = DaemonProxy::new(conn).await {
                    let _ = proxy.set_webhook(url, on_host_down, on_vpn_disconnect).await;
                }
            }
        });
    }

    // Save webhook URL on change.
    {
        let app_settings = Arc::clone(&app_settings);
        let rt = rt.clone();
        let host_down_toggle = host_down_toggle.clone();
        let vpn_disconnect_toggle = vpn_disconnect_toggle.clone();
        webhook_url_row.connect_changed(move |row| {
            let url = row.text().to_string();
            let on_host_down = host_down_toggle.is_active();
            let on_vpn_disconnect = vpn_disconnect_toggle.is_active();
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            s.webhook_url = url.clone();
            s.save();
            push_webhook_to_daemon(&rt, url, on_host_down, on_vpn_disconnect);
        });
    }

    // Save host-down toggle on change.
    {
        let app_settings = Arc::clone(&app_settings);
        let rt = rt.clone();
        let webhook_url_row = webhook_url_row.clone();
        let vpn_disconnect_toggle = vpn_disconnect_toggle.clone();
        host_down_toggle.connect_active_notify(move |row| {
            let active = row.is_active();
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            s.webhook_on_host_down = active;
            s.save();
            let url = webhook_url_row.text().to_string();
            let on_vpn = vpn_disconnect_toggle.is_active();
            push_webhook_to_daemon(&rt, url, active, on_vpn);
        });
    }

    // Save VPN-disconnect toggle on change.
    {
        let app_settings = Arc::clone(&app_settings);
        let rt = rt.clone();
        let webhook_url_row = webhook_url_row.clone();
        let host_down_toggle = host_down_toggle.clone();
        vpn_disconnect_toggle.connect_active_notify(move |row| {
            let active = row.is_active();
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            s.webhook_on_vpn_disconnect = active;
            s.save();
            let url = webhook_url_row.text().to_string();
            let on_host = host_down_toggle.is_active();
            push_webhook_to_daemon(&rt, url, on_host, active);
        });
    }

    // Test Webhook button.
    {
        let rt = rt.clone();
        let tx = tx.clone();
        test_webhook_btn.connect_clicked(move |_| {
            let tx = tx.clone();
            rt.spawn(async move {
                use supermgr_core::dbus::DaemonProxy;
                if let Ok(conn) = supermgr_core::client::system_connection().await {
                    if let Ok(proxy) = DaemonProxy::new(conn).await {
                        match proxy.test_webhook().await {
                            Ok(_) => {
                                let _ = tx.send(crate::app::AppMsg::ShowToast(
                                    "Webhook test sent successfully".into(),
                                ));
                            }
                            Err(e) => {
                                let _ = tx.send(crate::app::AppMsg::OperationFailed(
                                    format!("Webhook test failed: {e}"),
                                ));
                            }
                        }
                    }
                }
            });
        });
    }

    // --- Backup & Restore group ---
    let backup_group = adw::PreferencesGroup::builder()
        .title("Backup & Restore")
        .description("Export or import all configuration")
        .build();

    let export_row = adw::ActionRow::builder()
        .title("Export Config")
        .subtitle("Save all profiles, SSH keys, and hosts to a JSON file")
        .build();
    let export_btn = gtk4::Button::builder()
        .label("Export")
        .valign(gtk4::Align::Center)
        .css_classes(["flat"])
        .build();
    export_row.add_suffix(&export_btn);
    backup_group.add(&export_row);

    let import_row = adw::ActionRow::builder()
        .title("Import Config")
        .subtitle("Restore configuration from a backup file")
        .build();
    let import_btn = gtk4::Button::builder()
        .label("Import")
        .valign(gtk4::Align::Center)
        .css_classes(["flat"])
        .build();
    import_row.add_suffix(&import_btn);
    backup_group.add(&import_row);

    // Export button: show file save dialog first, then fetch config and write.
    {
        let window = window.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        export_btn.connect_clicked(move |_| {
            let filter = gtk4::FileFilter::new();
            filter.set_name(Some("JSON backup (*.json)"));
            filter.add_pattern("*.json");

            let dialog = gtk4::FileDialog::builder()
                .title("Export SuperManager Config")
                .initial_name("supermanager-backup.json")
                .default_filter(&filter)
                .modal(true)
                .build();

            let tx = tx.clone();
            let rt = rt.clone();
            dialog.save(Some(&window), gio::Cancellable::NONE, move |result| {
                let path = match result {
                    Ok(file) => match file.path() {
                        Some(p) => p,
                        None => return,
                    },
                    Err(ref e)
                        if e.matches(gio::IOErrorEnum::Cancelled)
                            || e.matches(gio::IOErrorEnum::Failed) =>
                    {
                        return;
                    }
                    Err(e) => {
                        error!("export file dialog error: {e}");
                        let _ = tx.send(AppMsg::OperationFailed(format!("File dialog: {e}")));
                        return;
                    }
                };

                let tx = tx.clone();
                rt.spawn(async move {
                    match crate::dbus_client::dbus_export_all().await {
                        Ok(json) => match std::fs::write(&path, &json) {
                            Ok(()) => {
                                let _ = tx.send(AppMsg::ShowToast(
                                    format!("Config exported to {}", path.display()),
                                ));
                            }
                            Err(e) => {
                                let _ = tx.send(AppMsg::OperationFailed(
                                    format!("Failed to write file: {e}"),
                                ));
                            }
                        },
                        Err(e) => {
                            error!("export_all failed: {e}");
                            let _ = tx.send(AppMsg::OperationFailed(
                                format!("Export failed: {e}"),
                            ));
                        }
                    }
                });
            });
        });
    }

    // Import button: open a JSON file, read it, send to daemon via ImportAll.
    {
        let window = window.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        import_btn.connect_clicked(move |_| {
            let filter = gtk4::FileFilter::new();
            filter.set_name(Some("JSON backup (*.json)"));
            filter.add_pattern("*.json");

            let dialog = gtk4::FileDialog::builder()
                .title("Import SuperManager Config")
                .default_filter(&filter)
                .modal(true)
                .build();

            let tx = tx.clone();
            let rt = rt.clone();
            dialog.open(Some(&window), gio::Cancellable::NONE, move |result| {
                let file = match result {
                    Ok(f) => f,
                    Err(ref e)
                        if e.matches(gio::IOErrorEnum::Cancelled)
                            || e.matches(gio::IOErrorEnum::Failed) =>
                    {
                        return;
                    }
                    Err(e) => {
                        error!("import file dialog error: {e}");
                        let _ = tx.send(AppMsg::OperationFailed(format!("File dialog: {e}")));
                        return;
                    }
                };

                let Some(path) = file.path() else {
                    let _ = tx.send(AppMsg::OperationFailed(
                        "Cannot import: file has no local path".into(),
                    ));
                    return;
                };

                let tx = tx.clone();
                rt.spawn(async move {
                    match tokio::fs::read_to_string(&path).await {
                        Ok(data) => match crate::dbus_client::dbus_import_all(data).await {
                            Ok(summary) => {
                                let _ = tx.send(AppMsg::ShowToast(
                                    format!("Import complete: {summary}"),
                                ));
                            }
                            Err(e) => {
                                error!("import_all failed: {e}");
                                let _ = tx.send(AppMsg::OperationFailed(
                                    format!("Import failed: {e}"),
                                ));
                            }
                        },
                        Err(e) => {
                            error!("failed to read backup file: {e}");
                            let _ = tx.send(AppMsg::OperationFailed(
                                format!("Failed to read file: {e}"),
                            ));
                        }
                    }
                });
            });
        });
    }

    // --- UniFi Cloud (Site Manager) group ---
    let unifi_group = adw::PreferencesGroup::builder()
        .title("UniFi Cloud (Site Manager)")
        .description("Connect to ui.com to monitor all UniFi devices on the Dashboard")
        .build();

    let unifi_key_row = adw::PasswordEntryRow::builder()
        .title("UI.com API Key")
        .build();
    {
        let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
        if !s.unifi_cloud_api_key.is_empty() {
            unifi_key_row.set_text(&s.unifi_cloud_api_key);
        }
    }
    unifi_group.add(&unifi_key_row);

    {
        let app_settings = Arc::clone(&app_settings);
        unifi_key_row.connect_changed(move |row| {
            let key = row.text().to_string();
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            s.unifi_cloud_api_key = key;
            s.save();
        });
    }

    // --- Remote Desktop group ---
    let rdp_group = adw::PreferencesGroup::builder()
        .title("Remote Desktop")
        .build();
    let rdp_model = gtk4::StringList::new(&["Auto", "Remmina", "xfreerdp3", "xfreerdp"]);
    let rdp_row = adw::ComboRow::builder()
        .title("RDP Client")
        .subtitle("Which application to use for Remote Desktop connections")
        .model(&rdp_model)
        .build();
    {
        let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
        let idx = match s.rdp_client.as_str() {
            "remmina" => 1,
            "xfreerdp3" => 2,
            "xfreerdp" => 3,
            _ => 0,
        };
        rdp_row.set_selected(idx);
    }
    rdp_group.add(&rdp_row);
    {
        let app_settings = Arc::clone(&app_settings);
        rdp_row.connect_selected_notify(move |row| {
            let client = match row.selected() {
                1 => "remmina",
                2 => "xfreerdp3",
                3 => "xfreerdp",
                _ => "auto",
            };
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            s.rdp_client = client.to_owned();
            s.save();
        });
    }

    // One page per topic, rather than seven groups in one scroller. The
    // groups themselves are untouched — this only decides which page each
    // one is on.
    for (title, icon, groups) in [
        (
            "General",
            "preferences-system-symbolic",
            vec![&appearance_group, &rdp_group],
        ),
        ("Security", crate::ui::design::icon_name(crate::ui::design::icons::SHIELD), vec![&security_group]),
        (
            "Notifications",
            crate::ui::design::icon_name(crate::ui::design::icons::NOTIFICATIONS),
            vec![&notify_group],
        ),
        (
            "Integrations",
            crate::ui::design::icon_name(crate::ui::design::icons::INTEGRATION),
            vec![&console_group, &unifi_group],
        ),
        (
            "Backup",
            "document-save-symbolic",
            vec![&backup_group],
        ),
    ] {
        let page = adw::PreferencesPage::builder()
            .title(title)
            .icon_name(icon)
            .build();
        for group in groups {
            page.add(group);
        }
        dialog.add(&page);
    }

    {
        let app_settings = Arc::clone(&app_settings);
        theme_row.connect_selected_notify(move |row| {
            let scheme = match row.selected() {
                1 => ColorScheme::Light,
                2 => ColorScheme::Dark,
                _ => ColorScheme::Default,
            };
            let adw_scheme = match scheme {
                ColorScheme::Default => adw::ColorScheme::Default,
                ColorScheme::Light => adw::ColorScheme::ForceLight,
                ColorScheme::Dark => adw::ColorScheme::ForceDark,
            };
            adw::StyleManager::default().set_color_scheme(adw_scheme);
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            s.color_scheme = scheme;
            s.save();
        });
    }

    {
        let app_settings = Arc::clone(&app_settings);
        let window = window.clone();
        opacity_scale.connect_value_changed(move |scale| {
            let val = scale.value() / 100.0;
            window.set_opacity(val);
            let mut s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            s.opacity = val;
            s.save();
        });
    }

    dialog.present(Some(window));
}

/// Small dialog to set or change the master password.
fn show_change_password_dialog(
    window: &adw::ApplicationWindow,
    app_settings: Arc<Mutex<AppSettings>>,
) {
    let has_pw = crate::master_password::is_set();

    let dialog = adw::Dialog::builder()
        .title(if has_pw { "Change Password" } else { "Set Password" })
        .content_width(340)
        .build();

    let group = adw::PreferencesGroup::new();

    let current_row = adw::PasswordEntryRow::builder()
        .title("Current Password")
        .build();
    if has_pw {
        group.add(&current_row);
    }

    let new_row = adw::PasswordEntryRow::builder()
        .title("New Password")
        .build();
    group.add(&new_row);

    let confirm_row = adw::PasswordEntryRow::builder()
        .title("Confirm New Password")
        .build();
    group.add(&confirm_row);

    let status = gtk4::Label::builder()
        .css_classes(["error"])
        .wrap(true)
        .visible(false)
        .build();

    let save_btn = gtk4::Button::builder()
        .label("Save")
        .css_classes(["suggested-action", "pill"])
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .build();

    let header = adw::HeaderBar::new();
    let vbox = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .spacing(12)
        .build();
    vbox.append(&header);
    vbox.append(&group);
    vbox.append(&status);
    vbox.append(&save_btn);
    dialog.set_child(Some(&vbox));

    {
        let app_settings = Arc::clone(&app_settings);
        let current_row = current_row.clone();
        let new_row = new_row.clone();
        let confirm_row = confirm_row.clone();
        let status = status.clone();
        let dialog = dialog.clone();
        save_btn.connect_clicked(move |_| {
            let s = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            let has = crate::master_password::is_set();
            if has {
                let cur = current_row.text().to_string();
                if !crate::master_password::verify(&cur) {
                    status.set_text("Current password is incorrect.");
                    status.set_visible(true);
                    return;
                }
            }
            drop(s);

            let new_pw = new_row.text().to_string();
            let confirm = confirm_row.text().to_string();
            if new_pw.is_empty() {
                status.set_text("New password cannot be empty.");
                status.set_visible(true);
                return;
            }
            if new_pw != confirm {
                status.set_text("Passwords do not match.");
                status.set_visible(true);
                return;
            }
            {
                let _ = crate::master_password::set(&new_pw);
            }
            dialog.close();
        });
    }

    dialog.present(Some(window));
}
