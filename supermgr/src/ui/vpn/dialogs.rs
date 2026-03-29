//! VPN import/edit dialogs.
//!
//! Each dialog follows the same pattern:
//! - Build an [`adw::Dialog`] with header bar + form fields.
//! - Validate input to enable/disable the action button.
//! - On submit, close the dialog and spawn a tokio task that makes a D-Bus call
//!   and sends the result as an [`AppMsg`] through the mpsc channel.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::{gio, glib, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::error;

use crate::app::{AppMsg, AppState};
use crate::dbus_client::{
    dbus_get_logs, dbus_import_azure_vpn, dbus_import_fortigate, dbus_import_openvpn,
    dbus_import_toml, dbus_import_wireguard, dbus_list_profiles, dbus_rename_profile,
    dbus_rotate_wireguard_key, dbus_update_fortigate, dbus_update_openvpn_credentials,
};
use crate::settings::{AppSettings, ColorScheme};

// ---------------------------------------------------------------------------
// WireGuard import
// ---------------------------------------------------------------------------

/// Open a file-chooser for a `.conf` file, then import it via D-Bus.
pub fn import_wireguard(
    window: &adw::ApplicationWindow,
    app_state: &Arc<Mutex<AppState>>,
    toast_overlay: &adw::ToastOverlay,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
) {
    if !app_state.lock().expect("lock").daemon_available {
        toast_overlay.add_toast(adw::Toast::new("Daemon not running \u{2014} cannot import"));
        return;
    }

    let filter = gtk4::FileFilter::new();
    filter.set_name(Some("WireGuard config (*.conf)"));
    filter.add_pattern("*.conf");
    filter.add_mime_type("application/x-wireguard-conf");

    let dialog = gtk4::FileDialog::builder()
        .title("Import WireGuard Config")
        .default_filter(&filter)
        .modal(true)
        .build();

    let tx = tx.clone();
    let rt = rt.clone();
    let toast_overlay = toast_overlay.clone();
    dialog.open(Some(window), gio::Cancellable::NONE, move |result| {
        let file = match result {
            Ok(f) => f,
            Err(ref e)
                if e.matches(gio::IOErrorEnum::Cancelled)
                    || e.matches(gio::IOErrorEnum::Failed) =>
            {
                return;
            }
            Err(e) => {
                error!("file dialog error: {e}");
                toast_overlay.add_toast(adw::Toast::new(&format!("File dialog: {e}")));
                return;
            }
        };

        let Some(path) = file.path() else {
            toast_overlay.add_toast(adw::Toast::new("Cannot import: file has no local path"));
            return;
        };

        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Imported Profile".to_owned());

        let tx = tx.clone();
        rt.spawn(async move {
            let msg = match dbus_import_wireguard(path, name).await {
                Ok(profiles) => AppMsg::ImportSucceeded {
                    profiles,
                    toast: Some("Profile imported"),
                },
                Err(e) => {
                    error!("import_wireguard failed: {:#}", e);
                    AppMsg::OperationFailed(e.to_string())
                }
            };
            tx.send(msg).ok();
        });
    });
}

// ---------------------------------------------------------------------------
// TOML config import
// ---------------------------------------------------------------------------

/// Open a file-chooser for a `.toml` configuration file, then import it via
/// D-Bus.  Auto-detects whether the file is a VPN profile, SSH key, or SSH
/// host.
pub fn import_toml_config(
    window: &adw::ApplicationWindow,
    app_state: &Arc<Mutex<AppState>>,
    toast_overlay: &adw::ToastOverlay,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
) {
    if !app_state.lock().expect("lock").daemon_available {
        toast_overlay.add_toast(adw::Toast::new("Daemon not running \u{2014} cannot import"));
        return;
    }

    let filter = gtk4::FileFilter::new();
    filter.set_name(Some("TOML config (*.toml)"));
    filter.add_pattern("*.toml");

    let dialog = gtk4::FileDialog::builder()
        .title("Import TOML Configuration")
        .default_filter(&filter)
        .modal(true)
        .build();

    let tx = tx.clone();
    let rt = rt.clone();
    let toast_overlay = toast_overlay.clone();
    dialog.open(Some(window), gio::Cancellable::NONE, move |result| {
        let file = match result {
            Ok(f) => f,
            Err(ref e)
                if e.matches(gio::IOErrorEnum::Cancelled)
                    || e.matches(gio::IOErrorEnum::Failed) =>
            {
                return;
            }
            Err(e) => {
                error!("file dialog error: {e}");
                toast_overlay.add_toast(adw::Toast::new(&format!("File dialog: {e}")));
                return;
            }
        };

        let Some(path) = file.path() else {
            toast_overlay.add_toast(adw::Toast::new("Cannot import: file has no local path"));
            return;
        };

        let tx = tx.clone();
        rt.spawn(async move {
            match dbus_import_toml(path).await {
                Ok(result_json) => {
                    // Determine what was imported and refresh the right list.
                    let imported_type = serde_json::from_str::<serde_json::Value>(&result_json)
                        .ok()
                        .and_then(|v| v.get("type")?.as_str().map(String::from))
                        .unwrap_or_default();

                    match imported_type.as_str() {
                        "vpn" => {
                            if let Ok(profiles) = dbus_list_profiles().await {
                                tx.send(AppMsg::ImportSucceeded {
                                    profiles,
                                    toast: Some("VPN profile imported"),
                                }).ok();
                            }
                        }
                        "ssh_key" => {
                            if let Ok(keys) = crate::dbus_client::dbus_ssh_list_keys().await {
                                tx.send(AppMsg::SshKeysRefreshed(keys)).ok();
                                tx.send(AppMsg::ShowToast("SSH key imported".into())).ok();
                            }
                        }
                        "ssh_host" => {
                            if let Ok(hosts) = crate::dbus_client::dbus_ssh_list_hosts().await {
                                tx.send(AppMsg::SshHostsRefreshed(hosts)).ok();
                                tx.send(AppMsg::ShowToast("SSH host imported".into())).ok();
                            }
                        }
                        _ => {
                            tx.send(AppMsg::ShowToast("Config imported".into())).ok();
                        }
                    }
                }
                Err(e) => {
                    error!("import_toml failed: {:#}", e);
                    tx.send(AppMsg::OperationFailed(e.to_string())).ok();
                }
            }
        });
    });
}

// ---------------------------------------------------------------------------
// OpenVPN import
// ---------------------------------------------------------------------------

/// Open a file-chooser for a `.ovpn` file, then show a credentials dialog.
pub fn import_openvpn(
    window: &adw::ApplicationWindow,
    app_state: &Arc<Mutex<AppState>>,
    toast_overlay: &adw::ToastOverlay,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
) {
    if !app_state.lock().expect("lock").daemon_available {
        toast_overlay.add_toast(adw::Toast::new("Daemon not running \u{2014} cannot import"));
        return;
    }

    let filter = gtk4::FileFilter::new();
    filter.set_name(Some("OpenVPN config (*.ovpn)"));
    filter.add_pattern("*.ovpn");

    let dialog = gtk4::FileDialog::builder()
        .title("Import OpenVPN Config")
        .default_filter(&filter)
        .modal(true)
        .build();

    let tx = tx.clone();
    let rt = rt.clone();
    let window_ref = window.clone();
    dialog.open(Some(window), gio::Cancellable::NONE, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let default_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("OpenVPN")
            .to_owned();

        // Credentials dialog.
        let creds_dialog = adw::Dialog::builder()
            .title("OpenVPN Credentials")
            .content_width(360)
            .build();

        let vbox = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        creds_dialog.set_child(Some(&vbox));

        let header = adw::HeaderBar::builder()
            .show_end_title_buttons(false)
            .build();
        vbox.append(&header);

        let prefs_group = adw::PreferencesGroup::builder()
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .build();
        vbox.append(&prefs_group);

        let name_row = adw::EntryRow::builder()
            .title("Profile name")
            .text(&default_name)
            .build();
        prefs_group.add(&name_row);

        let user_row = adw::EntryRow::builder()
            .title("Username (optional)")
            .build();
        prefs_group.add(&user_row);

        let pass_row = adw::PasswordEntryRow::builder()
            .title("Password (optional)")
            .build();
        prefs_group.add(&pass_row);

        let btn_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .halign(gtk4::Align::End)
            .spacing(8)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .build();
        vbox.append(&btn_box);

        let cancel_btn = gtk4::Button::builder().label("Cancel").build();
        btn_box.append(&cancel_btn);

        let import_btn = gtk4::Button::builder()
            .label("Import")
            .css_classes(["suggested-action"])
            .build();
        btn_box.append(&import_btn);

        {
            let d = creds_dialog.clone();
            cancel_btn.connect_clicked(move |_| { d.close(); });
        }

        {
            let d = creds_dialog.clone();
            let tx = tx.clone();
            let rt = rt.clone();
            let name_row = name_row.clone();
            let user_row = user_row.clone();
            let pass_row = pass_row.clone();
            import_btn.connect_clicked(move |_| {
                let name = name_row.text().to_string();
                let username = user_row.text().to_string();
                let password = pass_row.text().to_string();
                let path = path.clone();
                let tx = tx.clone();
                rt.spawn(async move {
                    let msg = match dbus_import_openvpn(path, name, username, password).await {
                        Ok(profiles) => AppMsg::ImportSucceeded {
                            profiles,
                            toast: Some("Profile imported"),
                        },
                        Err(e) => {
                            error!("import_openvpn: {e:#}");
                            AppMsg::OperationFailed(e.to_string())
                        }
                    };
                    let _ = tx.send(msg);
                });
                d.close();
            });
        }

        creds_dialog.present(Some(&window_ref));
    });
}

// ---------------------------------------------------------------------------
// Azure VPN import dialog
// ---------------------------------------------------------------------------

/// Show the two-file-picker Azure VPN import dialog.
pub fn show_azure_import_dialog(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::{cell::RefCell, path::PathBuf, rc::Rc};

    let dialog = adw::Dialog::builder()
        .title("Import Azure VPN Config")
        .content_width(420)
        .build();

    let name_row = adw::EntryRow::builder().title("Profile name").build();

    let azure_path: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
    let settings_path: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));

    let azure_row = adw::ActionRow::builder()
        .title("Azure VPN config XML")
        .subtitle("Not selected")
        .build();
    let azure_browse_btn = gtk4::Button::builder()
        .label("Browse\u{2026}")
        .valign(gtk4::Align::Center)
        .build();
    azure_row.add_suffix(&azure_browse_btn);
    azure_row.set_activatable_widget(Some(&azure_browse_btn));

    let settings_row = adw::ActionRow::builder()
        .title("VPN settings XML")
        .subtitle("Not selected")
        .build();
    let settings_browse_btn = gtk4::Button::builder()
        .label("Browse\u{2026}")
        .valign(gtk4::Align::Center)
        .build();
    settings_row.add_suffix(&settings_browse_btn);
    settings_row.set_activatable_widget(Some(&settings_browse_btn));

    let group = adw::PreferencesGroup::new();
    group.add(&name_row);
    group.add(&azure_row);
    group.add(&settings_row);

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let import_btn = gtk4::Button::builder()
        .label("Import")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&import_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    content_box.append(&group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    // Validation.
    let validate: Rc<dyn Fn()> = {
        let name_row = name_row.clone();
        let azure_path = Rc::clone(&azure_path);
        let settings_path = Rc::clone(&settings_path);
        let import_btn = import_btn.clone();
        Rc::new(move || {
            let ok = !name_row.text().is_empty()
                && azure_path.borrow().is_some()
                && settings_path.borrow().is_some();
            import_btn.set_sensitive(ok);
        })
    };
    {
        let v = Rc::clone(&validate);
        name_row.connect_changed(move |_| v());
    }

    // Browse for azure config.
    {
        let window = window.clone();
        let azure_path = Rc::clone(&azure_path);
        let azure_row = azure_row.clone();
        let validate = Rc::clone(&validate);
        azure_browse_btn.connect_clicked(move |_| {
            let filter = gtk4::FileFilter::new();
            filter.set_name(Some("XML files (*.xml)"));
            filter.add_pattern("*.xml");
            let fd = gtk4::FileDialog::builder()
                .title("Select Azure VPN Config")
                .default_filter(&filter)
                .modal(true)
                .build();
            let azure_path = Rc::clone(&azure_path);
            let azure_row = azure_row.clone();
            let validate = Rc::clone(&validate);
            fd.open(Some(&window), gio::Cancellable::NONE, move |result| {
                let Ok(file) = result else { return };
                let Some(path) = file.path() else { return };
                let label = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_owned();
                azure_row.set_subtitle(&label);
                *azure_path.borrow_mut() = Some(path);
                validate();
            });
        });
    }

    // Browse for settings.
    {
        let window = window.clone();
        let settings_path = Rc::clone(&settings_path);
        let settings_row = settings_row.clone();
        let validate = Rc::clone(&validate);
        settings_browse_btn.connect_clicked(move |_| {
            let filter = gtk4::FileFilter::new();
            filter.set_name(Some("XML files (*.xml)"));
            filter.add_pattern("*.xml");
            let fd = gtk4::FileDialog::builder()
                .title("Select VPN Settings")
                .default_filter(&filter)
                .modal(true)
                .build();
            let settings_path = Rc::clone(&settings_path);
            let settings_row = settings_row.clone();
            let validate = Rc::clone(&validate);
            fd.open(Some(&window), gio::Cancellable::NONE, move |result| {
                let Ok(file) = result else { return };
                let Some(path) = file.path() else { return };
                let label = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_owned();
                settings_row.set_subtitle(&label);
                *settings_path.borrow_mut() = Some(path);
                validate();
            });
        });
    }

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    {
        let dialog = dialog.clone();
        let name_row = name_row.clone();
        let azure_path = Rc::clone(&azure_path);
        let settings_path = Rc::clone(&settings_path);
        let rt = rt.clone();
        let tx = tx.clone();
        import_btn.connect_clicked(move |_| {
            let name = name_row.text().to_string();
            let Some(ap) = azure_path.borrow().clone() else {
                return;
            };
            let Some(sp) = settings_path.borrow().clone() else {
                return;
            };
            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match dbus_import_azure_vpn(ap, sp, name).await {
                    Ok(profiles) => AppMsg::ImportSucceeded {
                        profiles,
                        toast: Some("Profile imported"),
                    },
                    Err(e) => {
                        error!("import_azure_vpn: {e:#}");
                        AppMsg::OperationFailed(e.to_string())
                    }
                };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// FortiGate add dialog
// ---------------------------------------------------------------------------

/// Show the "Add FortiGate connection" dialog.
pub fn show_fortigate_dialog(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;

    let dialog = adw::Dialog::builder()
        .title("Add FortiGate Connection")
        .content_width(400)
        .build();

    let name_row = adw::EntryRow::builder().title("Name").build();
    let host_row = adw::EntryRow::builder().title("Host").build();
    let user_row = adw::EntryRow::builder().title("Username").build();
    let pass_row = adw::PasswordEntryRow::builder().title("Password").build();
    let psk_row = adw::PasswordEntryRow::builder()
        .title("Pre-shared Key")
        .build();

    let group = adw::PreferencesGroup::new();
    group.add(&name_row);
    group.add(&host_row);
    group.add(&user_row);
    group.add(&pass_row);
    group.add(&psk_row);

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let add_btn = gtk4::Button::builder()
        .label("Add")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&add_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    content_box.append(&group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    let validate: Rc<dyn Fn()> = {
        let name_row = name_row.clone();
        let host_row = host_row.clone();
        let user_row = user_row.clone();
        let add_btn = add_btn.clone();
        Rc::new(move || {
            let ok = !name_row.text().is_empty()
                && !host_row.text().is_empty()
                && !user_row.text().is_empty();
            add_btn.set_sensitive(ok);
        })
    };
    {
        let v = Rc::clone(&validate);
        name_row.connect_changed(move |_| v());
    }
    {
        let v = Rc::clone(&validate);
        host_row.connect_changed(move |_| v());
    }
    {
        let v = Rc::clone(&validate);
        user_row.connect_changed(move |_| v());
    }

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    {
        let dialog = dialog.clone();
        let name_row = name_row.clone();
        let host_row = host_row.clone();
        let user_row = user_row.clone();
        let pass_row = pass_row.clone();
        let psk_row = psk_row.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        add_btn.connect_clicked(move |_| {
            let name = name_row.text().to_string();
            let host = host_row.text().to_string();
            let username = user_row.text().to_string();
            let password = pass_row.text().to_string();
            let psk = psk_row.text().to_string();
            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match dbus_import_fortigate(name, host, username, password, psk).await {
                    Ok(profiles) => AppMsg::ImportSucceeded {
                        profiles,
                        toast: Some("Profile imported"),
                    },
                    Err(e) => {
                        error!("import_fortigate: {e:#}");
                        AppMsg::OperationFailed(e.to_string())
                    }
                };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Edit FortiGate dialog
// ---------------------------------------------------------------------------

/// Show the "Edit FortiGate connection" dialog pre-filled with current values.
pub fn show_edit_fortigate_dialog(
    window: &adw::ApplicationWindow,
    profile_id: String,
    current_name: String,
    current_host: String,
    current_username: String,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;

    let dialog = adw::Dialog::builder()
        .title("Edit FortiGate Connection")
        .content_width(400)
        .build();

    let name_row = adw::EntryRow::builder().title("Name").build();
    name_row.set_text(&current_name);
    let host_row = adw::EntryRow::builder().title("Host").build();
    host_row.set_text(&current_host);
    let user_row = adw::EntryRow::builder().title("Username").build();
    user_row.set_text(&current_username);
    let pass_row = adw::PasswordEntryRow::builder()
        .title("Password (leave blank to keep)")
        .build();
    let psk_row = adw::PasswordEntryRow::builder()
        .title("Pre-shared Key (leave blank to keep)")
        .build();

    let group = adw::PreferencesGroup::new();
    group.add(&name_row);
    group.add(&host_row);
    group.add(&user_row);
    group.add(&pass_row);
    group.add(&psk_row);

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let save_btn = gtk4::Button::builder()
        .label("Save")
        .css_classes(["suggested-action"])
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&save_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    content_box.append(&group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    let validate: Rc<dyn Fn()> = {
        let name_row = name_row.clone();
        let host_row = host_row.clone();
        let user_row = user_row.clone();
        let save_btn = save_btn.clone();
        Rc::new(move || {
            save_btn.set_sensitive(
                !name_row.text().is_empty()
                    && !host_row.text().is_empty()
                    && !user_row.text().is_empty(),
            );
        })
    };
    validate();
    {
        let v = Rc::clone(&validate);
        name_row.connect_changed(move |_| v());
    }
    {
        let v = Rc::clone(&validate);
        host_row.connect_changed(move |_| v());
    }
    {
        let v = Rc::clone(&validate);
        user_row.connect_changed(move |_| v());
    }

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    {
        let dialog = dialog.clone();
        let name_row = name_row.clone();
        let host_row = host_row.clone();
        let user_row = user_row.clone();
        let pass_row = pass_row.clone();
        let psk_row = psk_row.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        save_btn.connect_clicked(move |_| {
            let name = name_row.text().to_string();
            let host = host_row.text().to_string();
            let username = user_row.text().to_string();
            let password = pass_row.text().to_string();
            let psk = psk_row.text().to_string();
            let pid = profile_id.clone();
            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match dbus_update_fortigate(pid, name, host, username, password, psk)
                    .await
                {
                    Ok(()) => match dbus_list_profiles().await {
                        Ok(profiles) => AppMsg::ImportSucceeded {
                            profiles,
                            toast: None,
                        },
                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                    },
                    Err(e) => AppMsg::OperationFailed(format!("update FortiGate: {e}")),
                };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Edit OpenVPN credentials dialog
// ---------------------------------------------------------------------------

/// Show the "Edit OpenVPN credentials" dialog.
pub fn show_edit_openvpn_dialog(
    window: &adw::ApplicationWindow,
    profile_id: String,
    current_username: String,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let dialog = adw::Dialog::builder()
        .title("Edit OpenVPN Credentials")
        .content_width(400)
        .build();

    let user_row = adw::EntryRow::builder().title("Username").build();
    user_row.set_text(&current_username);
    let pass_row = adw::PasswordEntryRow::builder()
        .title("Password (leave blank to keep)")
        .build();

    let group = adw::PreferencesGroup::new();
    group.add(&user_row);
    group.add(&pass_row);

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let save_btn = gtk4::Button::builder()
        .label("Save")
        .css_classes(["suggested-action"])
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&save_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    content_box.append(&group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    {
        let dialog = dialog.clone();
        let user_row = user_row.clone();
        let pass_row = pass_row.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        save_btn.connect_clicked(move |_| {
            let username = user_row.text().to_string();
            let password = pass_row.text().to_string();
            let pid = profile_id.clone();
            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match dbus_update_openvpn_credentials(pid, username, password).await {
                    Ok(()) => match dbus_list_profiles().await {
                        Ok(profiles) => AppMsg::ImportSucceeded {
                            profiles,
                            toast: None,
                        },
                        Err(e) => AppMsg::OperationFailed(e.to_string()),
                    },
                    Err(e) => {
                        AppMsg::OperationFailed(format!("update OpenVPN credentials: {e}"))
                    }
                };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Rename dialog
// ---------------------------------------------------------------------------

/// Show the "Rename Profile" dialog.
pub fn show_rename_dialog(
    window: &adw::ApplicationWindow,
    profile_id: String,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let entry = gtk4::Entry::new();
    entry.set_placeholder_text(Some("New name"));

    let dialog = adw::AlertDialog::builder()
        .heading("Rename Profile")
        .body("Enter a new display name:")
        .close_response("cancel")
        .build();
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("rename", "Rename");
    dialog.set_response_appearance("rename", adw::ResponseAppearance::Suggested);
    dialog.set_extra_child(Some(&entry));

    let tx = tx.clone();
    let rt = rt.clone();
    dialog.connect_response(None, move |_dialog, response| {
        if response == "rename" {
            let new_name = entry.text().to_string();
            if new_name.trim().is_empty() {
                return;
            }
            let tx = tx.clone();
            let profile_id = profile_id.clone();
            rt.spawn(async move {
                if let Err(e) = dbus_rename_profile(profile_id, new_name).await {
                    let _ = tx.send(AppMsg::OperationFailed(e.to_string()));
                    return;
                }
                match dbus_list_profiles().await {
                    Ok(profiles) => {
                        let _ = tx.send(AppMsg::ImportSucceeded {
                            profiles,
                            toast: None,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(AppMsg::OperationFailed(e.to_string()));
                    }
                }
            });
        }
    });

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Rotate WireGuard key dialog
// ---------------------------------------------------------------------------

/// Rotate a WireGuard key via D-Bus and display the new public key.
pub fn rotate_wireguard_key(
    window: &adw::ApplicationWindow,
    profile_id: String,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let tx = tx.clone();
    let rt2 = rt.clone();
    let window = window.clone();
    glib::MainContext::default().spawn_local(async move {
        let join = rt2.spawn(async move { dbus_rotate_wireguard_key(profile_id).await });
        match join.await {
            Ok(Ok(new_pubkey)) => {
                let dialog = adw::AlertDialog::builder()
                    .heading("Key Rotated")
                    .body("Update your WireGuard server with the new public key:")
                    .close_response("close")
                    .build();
                dialog.add_response("close", "Close");
                let group = adw::PreferencesGroup::new();
                let key_row = adw::ActionRow::builder()
                    .title("New Public Key")
                    .subtitle(&new_pubkey)
                    .subtitle_selectable(true)
                    .build();
                group.add(&key_row);
                dialog.set_extra_child(Some(&group));
                dialog.present(Some(&window));
            }
            Ok(Err(e)) => {
                let _ = tx.send(AppMsg::OperationFailed(format!("rotate key: {e}")));
            }
            Err(e) => {
                let _ = tx.send(AppMsg::OperationFailed(format!("rotate key task: {e}")));
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Auth challenge dialog (Azure device code)
// ---------------------------------------------------------------------------

/// Show a modal dialog for the Entra ID device-code challenge.
pub fn show_auth_challenge_dialog(
    window: &adw::ApplicationWindow,
    user_code: &str,
    verification_url: &str,
) {
    let dialog = adw::AlertDialog::builder()
        .heading("Azure Sign-in Required")
        .body("Open a browser and go to the URL below, then enter the code shown.")
        .close_response("close")
        .build();

    let group = adw::PreferencesGroup::new();
    let url_row = adw::ActionRow::builder()
        .title("Sign-in URL")
        .subtitle(verification_url)
        .subtitle_selectable(true)
        .build();
    group.add(&url_row);

    let code_row = adw::ActionRow::builder()
        .title("Code")
        .subtitle(user_code)
        .subtitle_selectable(true)
        .css_classes(["monospace"])
        .build();
    group.add(&code_row);

    dialog.set_extra_child(Some(&group));
    dialog.add_response("close", "Close");
    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Daemon logs dialog
// ---------------------------------------------------------------------------

/// Show a scrollable dialog of recent daemon log lines.
pub fn show_logs_dialog(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    app_settings: Arc<Mutex<AppSettings>>,
) {
    let log_window = adw::Window::builder()
        .title("Daemon Logs")
        .default_width(820)
        .default_height(600)
        .transient_for(window)
        .build();
    log_window.set_opacity(app_settings.lock().expect("lock").opacity);

    let text_view = gtk4::TextView::builder()
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::None)
        .build();
    text_view.add_css_class("card");

    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .hexpand(true)
        .vexpand(true)
        .margin_top(8)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .child(&text_view)
        .build();

    let toggle_all = gtk4::ToggleButton::builder()
        .label("All")
        .active(true)
        .build();
    let toggle_conn = gtk4::ToggleButton::builder()
        .label("Connection")
        .group(&toggle_all)
        .build();

    let conn_mode = std::rc::Rc::new(std::cell::Cell::new(false));
    {
        let conn_mode = conn_mode.clone();
        toggle_conn.connect_toggled(move |btn| {
            conn_mode.set(btn.is_active());
        });
    }

    let header = adw::HeaderBar::new();
    let toggle_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 0);
    toggle_box.add_css_class("linked");
    toggle_box.append(&toggle_all);
    toggle_box.append(&toggle_conn);
    header.pack_start(&toggle_box);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&scroll));
    log_window.set_content(Some(&toolbar_view));

    let load_logs = {
        let text_view = text_view.clone();
        let scroll = scroll.clone();
        let rt = rt.clone();
        let conn_mode = conn_mode.clone();
        move || {
            let text_view = text_view.clone();
            let scroll = scroll.clone();
            let rt = rt.clone();
            let conn_only = conn_mode.get();
            glib::MainContext::default().spawn_local(async move {
                let join = rt.spawn(async { dbus_get_logs().await });
                let mut lines = match join.await {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => vec![format!("[error] could not fetch logs: {e}")],
                    Err(e) => vec![format!("[error] task failed: {e}")],
                };

                if conn_only {
                    if let Some(start) = lines.iter().rposition(|l| l.contains("=== [")) {
                        lines = lines[start..].to_vec();
                    }
                }

                let text = lines.join("\n");
                let buf = text_view.buffer();

                let vadj = scroll.vadjustment();
                let near_bottom = vadj.value() >= vadj.upper() - vadj.page_size() - 50.0;

                buf.set_text(&text);

                if near_bottom {
                    let mut end = buf.end_iter();
                    text_view.scroll_to_iter(&mut end, 0.0, false, 0.0, 0.0);
                }
            });
        }
    };

    load_logs();

    {
        let load_logs = load_logs.clone();
        toggle_all.connect_toggled(move |_| load_logs());
    }
    {
        let load_logs = load_logs.clone();
        toggle_conn.connect_toggled(move |_| load_logs());
    }

    {
        let load_logs = load_logs.clone();
        let log_window_weak = log_window.downgrade();
        glib::timeout_add_local(std::time::Duration::from_secs(2), move || {
            match log_window_weak.upgrade() {
                Some(w) if w.is_visible() => {
                    load_logs();
                    glib::ControlFlow::Continue
                }
                Some(_) => glib::ControlFlow::Continue,
                None => glib::ControlFlow::Break,
            }
        });
    }

    log_window.present();
}

// ---------------------------------------------------------------------------
// Settings dialog
// ---------------------------------------------------------------------------

/// Show the application settings dialog.
pub fn show_settings_dialog(
    window: &adw::ApplicationWindow,
    app_settings: Arc<Mutex<AppSettings>>,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
) {
    let dialog = adw::Dialog::builder()
        .title("Settings")
        .content_width(380)
        .build();

    let appearance_group = adw::PreferencesGroup::builder()
        .title("Appearance")
        .build();

    let theme_model = gtk4::StringList::new(&["Follow System", "Light", "Dark"]);
    let theme_row = adw::ComboRow::builder()
        .title("Theme")
        .model(&theme_model)
        .build();
    {
        let s = app_settings.lock().expect("lock");
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
        app_settings.lock().expect("lock").opacity * 100.0,
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
        let s = app_settings.lock().expect("lock");
        sub_row.set_active(s.use_claude_subscription);
    }
    console_group.add(&sub_row);

    let api_key_row = adw::PasswordEntryRow::builder()
        .title("Anthropic API Key (only if subscription disabled)")
        .build();
    {
        let s = app_settings.lock().expect("lock");
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
            let mut s = app_settings.lock().expect("lock");
            s.use_claude_subscription = active;
            s.save();
        });
    }

    {
        let app_settings = Arc::clone(&app_settings);
        api_key_row.connect_changed(move |row| {
            let key = row.text().to_string();
            let mut s = app_settings.lock().expect("lock");
            s.anthropic_api_key = key;
            s.save();
        });
    }

    // --- Security group (master password / auto-lock) ---
    let security_group = adw::PreferencesGroup::builder()
        .title("Security")
        .description("Master password and session lock")
        .build();

    let has_pw = app_settings.lock().expect("lock").has_password();

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

        let app_settings_rm = Arc::clone(&app_settings);
        let pw_status_row_rm = pw_status_row.clone();
        remove_pw_btn.connect_clicked(move |btn| {
            let mut s = app_settings_rm.lock().expect("lock");
            s.clear_password();
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
            app_settings.lock().expect("lock").auto_lock_minutes as f64,
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
            let mut s = app_settings.lock().expect("lock");
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            {
                s.auto_lock_minutes = row.value() as u64;
            }
            s.save();
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

    let prefs_page = adw::PreferencesPage::new();
    prefs_page.add(&appearance_group);
    prefs_page.add(&console_group);
    prefs_page.add(&security_group);
    prefs_page.add(&backup_group);

    let header = adw::HeaderBar::new();
    let vbox = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    vbox.append(&header);
    vbox.append(&prefs_page);
    dialog.set_child(Some(&vbox));

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
            let mut s = app_settings.lock().expect("lock");
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
            let mut s = app_settings.lock().expect("lock");
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
    let has_pw = app_settings.lock().expect("lock").has_password();

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
            let s = app_settings.lock().expect("lock");
            let has = s.has_password();
            if has {
                let cur = current_row.text().to_string();
                if !s.verify_password(&cur) {
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
                let mut s = app_settings.lock().expect("lock");
                s.set_password(&new_pw);
            }
            dialog.close();
        });
    }

    dialog.present(Some(window));
}
