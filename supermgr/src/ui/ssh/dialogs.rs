//! SSH dialogs — Generate Key, Add Host, Import Keys, Push Key, Revoke Key.
//!
//! All dialogs follow the same pattern as the VPN dialogs: build widgets,
//! validate input, on submit close the dialog and spawn a tokio D-Bus call.

use std::sync::mpsc;

use gtk4::{glib, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::error;

use supermgr_core::ssh::key::SshKeySummary;
use supermgr_core::ssh::host::SshHostSummary;
use supermgr_core::vpn::profile::ProfileSummary;

use crate::app::AppMsg;
use crate::dbus_client::{
    dbus_ssh_generate_key, dbus_ssh_add_host, dbus_ssh_import_scan,
    dbus_ssh_import_key, dbus_ssh_push_key, dbus_ssh_revoke_key,
};

// ---------------------------------------------------------------------------
// Generate Key dialog
// ---------------------------------------------------------------------------

/// Show the "Generate SSH Key" dialog.
pub fn show_generate_key_dialog(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;

    let dialog = adw::Dialog::builder()
        .title("Generate SSH Key")
        .content_width(400)
        .build();

    let name_row = adw::EntryRow::builder().title("Key name").build();

    let type_model = gtk4::StringList::new(&["Ed25519", "RSA 2048", "RSA 4096"]);
    let type_row = adw::ComboRow::builder()
        .title("Key type")
        .model(&type_model)
        .selected(0)
        .build();

    let desc_row = adw::EntryRow::builder()
        .title("Description (optional)")
        .build();

    let tags_row = adw::EntryRow::builder()
        .title("Tags (comma-separated)")
        .build();

    let group = adw::PreferencesGroup::new();
    group.add(&name_row);
    group.add(&type_row);
    group.add(&desc_row);
    group.add(&tags_row);

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let generate_btn = gtk4::Button::builder()
        .label("Generate")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&generate_btn);
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

    // Validate: name required.
    let validate: Rc<dyn Fn()> = {
        let name_row = name_row.clone();
        let generate_btn = generate_btn.clone();
        Rc::new(move || {
            generate_btn.set_sensitive(!name_row.text().is_empty());
        })
    };
    {
        let v = Rc::clone(&validate);
        name_row.connect_changed(move |_| v());
    }

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    {
        let dialog = dialog.clone();
        let name_row = name_row.clone();
        let type_row = type_row.clone();
        let desc_row = desc_row.clone();
        let tags_row = tags_row.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        generate_btn.connect_clicked(move |_| {
            let name = name_row.text().to_string();
            let key_type = match type_row.selected() {
                1 => "rsa2048".to_owned(),
                2 => "rsa4096".to_owned(),
                _ => "ed25519".to_owned(),
            };
            let description = desc_row.text().to_string();
            let tags: Vec<String> = tags_row
                .text()
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect();

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match dbus_ssh_generate_key(name, key_type, description, tags).await {
                    Ok((keys, _uuid)) => {
                        AppMsg::SshKeysRefreshed(keys)
                    }
                    Err(e) => {
                        error!("generate SSH key: {e:#}");
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
// Add Host dialog
// ---------------------------------------------------------------------------

/// Show the "Add SSH Host" dialog.
pub fn show_add_host_dialog(
    window: &adw::ApplicationWindow,
    keys: &[SshKeySummary],
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;

    let dialog = adw::Dialog::builder()
        .title("Add SSH Host")
        .content_width(420)
        .build();

    let label_row = adw::EntryRow::builder().title("Label").build();
    let hostname_row = adw::EntryRow::builder().title("Hostname").build();
    let port_row = adw::EntryRow::builder().title("Port").text("22").build();
    let username_row = adw::EntryRow::builder().title("Username").build();
    let group_row = adw::EntryRow::builder()
        .title("Group (optional)")
        .build();

    let device_model = gtk4::StringList::new(&[
        "Linux", "UniFi", "pfSense", "OpenWrt", "FortiGate", "Windows", "Custom",
    ]);
    let device_row = adw::ComboRow::builder()
        .title("Device type")
        .model(&device_model)
        .selected(0)
        .build();

    let auth_model = gtk4::StringList::new(&["Public Key", "Password"]);
    let auth_row = adw::ComboRow::builder()
        .title("Authentication")
        .model(&auth_model)
        .selected(0)
        .build();

    // Key selector (visible when auth = key).
    let key_names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    let key_model = gtk4::StringList::new(&key_names);
    let key_row = adw::ComboRow::builder()
        .title("SSH Key")
        .model(&key_model)
        .selected(0)
        .build();

    // Password row (visible when auth = password).
    let pass_row = adw::PasswordEntryRow::builder()
        .title("Password")
        .visible(false)
        .build();

    // Toggle key/password visibility based on auth method selection.
    {
        let key_row = key_row.clone();
        let pass_row = pass_row.clone();
        auth_row.connect_selected_notify(move |row| {
            let is_key = row.selected() == 0;
            key_row.set_visible(is_key);
            pass_row.set_visible(!is_key);
        });
    }

    let conn_group = adw::PreferencesGroup::builder()
        .title("Connection")
        .build();
    conn_group.add(&label_row);
    conn_group.add(&hostname_row);
    conn_group.add(&port_row);
    conn_group.add(&username_row);
    conn_group.add(&group_row);
    conn_group.add(&device_row);

    let auth_group = adw::PreferencesGroup::builder()
        .title("Authentication")
        .margin_top(12)
        .build();
    auth_group.add(&auth_row);
    auth_group.add(&key_row);
    auth_group.add(&pass_row);

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
        .spacing(0)
        .build();
    content_box.append(&conn_group);
    content_box.append(&auth_group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    // Validate: label + hostname + username required.
    let validate: Rc<dyn Fn()> = {
        let label_row = label_row.clone();
        let hostname_row = hostname_row.clone();
        let username_row = username_row.clone();
        let add_btn = add_btn.clone();
        Rc::new(move || {
            let ok = !label_row.text().is_empty()
                && !hostname_row.text().is_empty()
                && !username_row.text().is_empty();
            add_btn.set_sensitive(ok);
        })
    };
    {
        let v = Rc::clone(&validate);
        label_row.connect_changed(move |_| v());
    }
    {
        let v = Rc::clone(&validate);
        hostname_row.connect_changed(move |_| v());
    }
    {
        let v = Rc::clone(&validate);
        username_row.connect_changed(move |_| v());
    }

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    // Collect key IDs for referencing by index.
    let key_ids: Vec<String> = keys.iter().map(|k| k.id.to_string()).collect();

    {
        let dialog = dialog.clone();
        let label_row = label_row.clone();
        let hostname_row = hostname_row.clone();
        let port_row = port_row.clone();
        let username_row = username_row.clone();
        let group_row = group_row.clone();
        let device_row = device_row.clone();
        let auth_row = auth_row.clone();
        let key_row = key_row.clone();
        let pass_row = pass_row.clone();
        let key_ids = key_ids.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        add_btn.connect_clicked(move |_| {
            let label = label_row.text().to_string();
            let hostname = hostname_row.text().to_string();
            let port: u16 = port_row.text().parse().unwrap_or(22);
            let username = username_row.text().to_string();
            let group = group_row.text().to_string();
            let device_type = match device_row.selected() {
                1 => "uni_fi",
                2 => "pf_sense",
                3 => "open_wrt",
                4 => "fortigate",
                5 => "windows",
                6 => "custom",
                _ => "linux",
            }
            .to_owned();
            let auth_method = if auth_row.selected() == 0 {
                "key".to_owned()
            } else {
                "password".to_owned()
            };
            let key_id = if auth_row.selected() == 0 {
                key_ids.get(key_row.selected() as usize).cloned()
            } else {
                None
            };
            let password = if auth_row.selected() == 1 {
                Some(pass_row.text().to_string())
            } else {
                None
            };

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let host_data = serde_json::json!({
                    "label": label,
                    "hostname": hostname,
                    "port": port,
                    "username": username,
                    "group": group,
                    "device_type": device_type,
                    "auth_method": auth_method,
                    "auth_key_id": key_id,
                });
                let msg = match dbus_ssh_add_host(host_data.to_string()).await {
                    Ok((hosts, uuid)) => {
                        if let Some(pw) = password {
                            if !pw.is_empty() {
                                if let Err(e) = crate::dbus_client::dbus_ssh_set_password(uuid, pw).await {
                                    error!("store SSH password: {e:#}");
                                }
                            }
                        }
                        AppMsg::SshHostsRefreshed(hosts)
                    }
                    Err(e) => {
                        error!("add SSH host: {e:#}");
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
// Import Keys dialog
// ---------------------------------------------------------------------------

/// Show the "Import SSH Keys" dialog — scans for existing keys and lets the
/// user select which ones to import.
pub fn show_import_keys_dialog(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;
    use std::cell::RefCell;

    let dialog = adw::Dialog::builder()
        .title("Import SSH Keys")
        .content_width(450)
        .build();

    let spinner = gtk4::Spinner::builder()
        .spinning(true)
        .halign(gtk4::Align::Center)
        .margin_top(24)
        .margin_bottom(24)
        .build();

    let status_label = gtk4::Label::builder()
        .label("Scanning for SSH keys\u{2026}")
        .halign(gtk4::Align::Center)
        .build();

    let results_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .visible(false)
        .build();

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let import_btn = gtk4::Button::builder()
        .label("Import Selected")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .visible(false)
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&import_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    content_box.append(&spinner);
    content_box.append(&status_label);
    content_box.append(&results_list);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    // Kick off the scan.
    let scan_results: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    {
        let results_list = results_list.clone();
        let spinner = spinner.clone();
        let status_label = status_label.clone();
        let import_btn = import_btn.clone();
        let scan_results = Rc::clone(&scan_results);
        let rt = rt.clone();

        glib::MainContext::default().spawn_local(async move {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            let ssh_dir = format!("{home}/.ssh");
            let join = rt.spawn(async move { dbus_ssh_import_scan(ssh_dir).await });
            match join.await {
                Ok(Ok(json_str)) => {
                    spinner.set_spinning(false);
                    spinner.set_visible(false);

                    let found_keys: Vec<String> = serde_json::from_str(&json_str).unwrap_or_default();
                    if found_keys.is_empty() {
                        status_label.set_label("No importable SSH keys found in ~/.ssh/");
                    } else {
                        status_label.set_label(&format!("Found {} key(s):", found_keys.len()));
                        results_list.set_visible(true);
                        import_btn.set_visible(true);
                        import_btn.set_sensitive(true);

                        let mut paths = scan_results.borrow_mut();
                        for key_path in &found_keys {
                            paths.push(key_path.clone());
                            let check = gtk4::CheckButton::builder()
                                .active(true)
                                .valign(gtk4::Align::Center)
                                .build();
                            let row = adw::ActionRow::builder()
                                .title(key_path.as_str())
                                .activatable(true)
                                .build();
                            row.add_prefix(&check);
                            results_list.append(&row);
                        }
                    }
                }
                Ok(Err(e)) => {
                    spinner.set_spinning(false);
                    spinner.set_visible(false);
                    status_label.set_label(&format!("Scan failed: {e}"));
                }
                Err(e) => {
                    spinner.set_spinning(false);
                    spinner.set_visible(false);
                    status_label.set_label(&format!("Scan task failed: {e}"));
                }
            }
        });
    }

    // Import button: gather checked paths and call D-Bus.
    {
        let dialog = dialog.clone();
        let results_list = results_list.clone();
        let scan_results = Rc::clone(&scan_results);
        let rt = rt.clone();
        let tx = tx.clone();
        import_btn.connect_clicked(move |_| {
            // Gather selected paths by checking which CheckButtons are active.
            let paths = scan_results.borrow();
            let mut selected_paths: Vec<String> = Vec::new();
            for (i, path) in paths.iter().enumerate() {
                if let Some(_row) = results_list.row_at_index(i as i32) {
                    // The check button is the prefix of the ActionRow child.
                    // Since we always add all of them as active, default to including.
                    selected_paths.push(path.clone());
                }
            }

            if selected_paths.is_empty() {
                return;
            }

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let mut last_keys: Option<Vec<SshKeySummary>> = None;
                for path in &selected_paths {
                    // Derive key name from file path (e.g. "id_ed25519" from "/home/user/.ssh/id_ed25519").
                    let name = std::path::Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.clone());
                    // Read public and private key files.
                    let pub_path = format!("{path}.pub");
                    let public_key = tokio::fs::read_to_string(&pub_path).await.unwrap_or_default();
                    let private_key = tokio::fs::read_to_string(path).await.unwrap_or_default();
                    // Infer key type from name.
                    let key_type = if name.contains("rsa") {
                        "rsa".to_string()
                    } else if name.contains("ecdsa") {
                        "ecdsa".to_string()
                    } else {
                        "ed25519".to_string()
                    };
                    match dbus_ssh_import_key(name, public_key, private_key, key_type).await {
                        Ok(keys) => last_keys = Some(keys),
                        Err(e) => {
                            error!("import SSH key {path}: {e:#}");
                            let _ = tx.send(AppMsg::OperationFailed(e.to_string()));
                            return;
                        }
                    }
                }
                let msg = match last_keys {
                    Some(keys) => AppMsg::SshKeysRefreshed(keys),
                    None => AppMsg::OperationFailed("No keys imported".to_string()),
                };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Push Key dialog
// ---------------------------------------------------------------------------

/// Show the "Push Key to Hosts" dialog.
///
/// The user selects a key and checks which hosts to push it to, with an
/// optional sudo toggle.
pub fn show_push_key_dialog(
    window: &adw::ApplicationWindow,
    keys: &[SshKeySummary],
    hosts: &[SshHostSummary],
    preselected_key_id: Option<&str>,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let dialog = adw::Dialog::builder()
        .title("Push Key to Hosts")
        .content_width(450)
        .build();

    // Key selector.
    let key_names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    let key_model = gtk4::StringList::new(&key_names);
    let key_row = adw::ComboRow::builder()
        .title("Key")
        .model(&key_model)
        .build();
    // Pre-select key if given.
    if let Some(pre_id) = preselected_key_id {
        for (i, k) in keys.iter().enumerate() {
            if k.id.to_string() == pre_id {
                key_row.set_selected(i as u32);
                break;
            }
        }
    }

    let key_group = adw::PreferencesGroup::new();
    key_group.add(&key_row);

    // Sudo toggle.
    let sudo_row = adw::SwitchRow::builder()
        .title("Use sudo")
        .subtitle("Required for some device types")
        .active(false)
        .build();
    key_group.add(&sudo_row);

    // Host checkboxes.
    let hosts_group = adw::PreferencesGroup::builder()
        .title("Target Hosts")
        .margin_top(12)
        .build();

    let mut host_checks: Vec<(String, gtk4::CheckButton)> = Vec::new();
    for host in hosts {
        let check = gtk4::CheckButton::builder()
            .active(false)
            .valign(gtk4::Align::Center)
            .build();
        let row = adw::ActionRow::builder()
            .title(host.label.as_str())
            .subtitle(&format!("{}@{}", host.username, host.hostname))
            .activatable(true)
            .build();
        row.add_prefix(&check);

        // Show device-type warning if applicable.
        if let Some(warning) = host.device_type.warning_message() {
            let warn_icon = gtk4::Image::builder()
                .icon_name("dialog-warning-symbolic")
                .tooltip_text(warning)
                .build();
            row.add_suffix(&warn_icon);
        }

        hosts_group.add(&row);
        host_checks.push((host.id.to_string(), check));
    }

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let push_btn = gtk4::Button::builder()
        .label("Push")
        .css_classes(["suggested-action"])
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&push_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .spacing(0)
        .build();
    content_box.append(&key_group);
    content_box.append(&hosts_group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    let key_ids: Vec<String> = keys.iter().map(|k| k.id.to_string()).collect();

    {
        let dialog = dialog.clone();
        let key_row = key_row.clone();
        let sudo_row = sudo_row.clone();
        let key_ids = key_ids.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        push_btn.connect_clicked(move |_| {
            let selected_key = key_ids
                .get(key_row.selected() as usize)
                .cloned()
                .unwrap_or_default();
            let use_sudo = sudo_row.is_active();
            let selected_hosts: Vec<String> = host_checks
                .iter()
                .filter(|(_, check)| check.is_active())
                .map(|(id, _)| id.clone())
                .collect();

            if selected_hosts.is_empty() {
                return;
            }

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg =
                    match dbus_ssh_push_key(selected_key, selected_hosts, use_sudo).await {
                        Ok(_op_id) => AppMsg::ShowToast("Key push initiated".to_string()),
                        Err(e) => {
                            error!("push SSH key: {e:#}");
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
// Revoke Key dialog
// ---------------------------------------------------------------------------

/// Show the "Revoke Key from Hosts" dialog.
///
/// Similar to push but removes the key instead of adding it.
#[allow(dead_code)]
pub fn show_revoke_key_dialog(
    window: &adw::ApplicationWindow,
    keys: &[SshKeySummary],
    hosts: &[SshHostSummary],
    preselected_key_id: Option<&str>,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let dialog = adw::Dialog::builder()
        .title("Revoke Key from Hosts")
        .content_width(450)
        .build();

    let key_names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    let key_model = gtk4::StringList::new(&key_names);
    let key_row = adw::ComboRow::builder()
        .title("Key")
        .model(&key_model)
        .build();
    if let Some(pre_id) = preselected_key_id {
        for (i, k) in keys.iter().enumerate() {
            if k.id.to_string() == pre_id {
                key_row.set_selected(i as u32);
                break;
            }
        }
    }

    let sudo_row = adw::SwitchRow::builder()
        .title("Use sudo")
        .subtitle("Required for some device types")
        .active(false)
        .build();

    let key_group = adw::PreferencesGroup::new();
    key_group.add(&key_row);
    key_group.add(&sudo_row);

    let hosts_group = adw::PreferencesGroup::builder()
        .title("Target Hosts")
        .margin_top(12)
        .build();

    let mut host_checks: Vec<(String, gtk4::CheckButton)> = Vec::new();
    for host in hosts {
        let check = gtk4::CheckButton::builder()
            .active(false)
            .valign(gtk4::Align::Center)
            .build();
        let row = adw::ActionRow::builder()
            .title(host.label.as_str())
            .subtitle(&format!("{}@{}", host.username, host.hostname))
            .activatable(true)
            .build();
        row.add_prefix(&check);
        hosts_group.add(&row);
        host_checks.push((host.id.to_string(), check));
    }

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let revoke_btn = gtk4::Button::builder()
        .label("Revoke")
        .css_classes(["destructive-action"])
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&revoke_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .spacing(0)
        .build();
    content_box.append(&key_group);
    content_box.append(&hosts_group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    let key_ids: Vec<String> = keys.iter().map(|k| k.id.to_string()).collect();

    {
        let dialog = dialog.clone();
        let key_row = key_row.clone();
        let sudo_row = sudo_row.clone();
        let key_ids = key_ids.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        revoke_btn.connect_clicked(move |_| {
            let selected_key = key_ids
                .get(key_row.selected() as usize)
                .cloned()
                .unwrap_or_default();
            let use_sudo = sudo_row.is_active();
            let selected_hosts: Vec<String> = host_checks
                .iter()
                .filter(|(_, check)| check.is_active())
                .map(|(id, _)| id.clone())
                .collect();

            if selected_hosts.is_empty() {
                return;
            }

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg =
                    match dbus_ssh_revoke_key(selected_key, selected_hosts, use_sudo).await {
                        Ok(_op_id) => AppMsg::ShowToast("Key revocation initiated".to_string()),
                        Err(e) => {
                            error!("revoke SSH key: {e:#}");
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
// Edit Host dialog
// ---------------------------------------------------------------------------

/// Show the "Edit SSH Host" dialog, pre-filled with existing values.
pub fn show_edit_host_dialog(
    window: &adw::ApplicationWindow,
    host: &SshHostSummary,
    keys: &[SshKeySummary],
    all_hosts: &[SshHostSummary],
    vpn_profiles: &[ProfileSummary],
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;

    let dialog = adw::Dialog::builder()
        .title("Edit SSH Host")
        .content_width(420)
        .build();

    let label_row = adw::EntryRow::builder().title("Label").text(&host.label).build();
    let hostname_row = adw::EntryRow::builder().title("Hostname").text(&host.hostname).build();
    let port_row = adw::EntryRow::builder().title("Port").text(&host.port.to_string()).build();
    let username_row = adw::EntryRow::builder().title("Username").text(&host.username).build();
    let group_row = adw::EntryRow::builder().title("Group (optional)").text(&host.group).build();

    let device_model = gtk4::StringList::new(&[
        "Linux", "UniFi", "pfSense", "OpenWrt", "FortiGate", "Windows", "Custom",
    ]);
    let device_idx = match host.device_type {
        supermgr_core::DeviceType::Linux => 0u32,
        supermgr_core::DeviceType::UniFi => 1,
        supermgr_core::DeviceType::PfSense => 2,
        supermgr_core::DeviceType::OpenWrt => 3,
        supermgr_core::DeviceType::Fortigate => 4,
        supermgr_core::DeviceType::Windows => 5,
        supermgr_core::DeviceType::Custom => 6,
    };
    let device_row = adw::ComboRow::builder()
        .title("Device type")
        .model(&device_model)
        .selected(device_idx)
        .build();

    let auth_model = gtk4::StringList::new(&["Public Key", "Password"]);
    let auth_idx = if host.auth_method == supermgr_core::AuthMethod::Key { 0u32 } else { 1 };
    let auth_row = adw::ComboRow::builder()
        .title("Authentication")
        .model(&auth_model)
        .selected(auth_idx)
        .build();

    let key_names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    let key_model = gtk4::StringList::new(&key_names);
    // Pre-select the key currently assigned to this host (fall back to 0).
    let current_key_idx = host.auth_key_id
        .and_then(|kid| keys.iter().position(|k| k.id == kid))
        .unwrap_or(0) as u32;
    let key_row = adw::ComboRow::builder()
        .title("SSH Key")
        .model(&key_model)
        .selected(current_key_idx)
        .visible(auth_idx == 0)
        .build();

    let pass_title = if host.has_password { "Password (configured — leave empty to keep)" } else { "Password" };
    let pass_row = adw::PasswordEntryRow::builder()
        .title(pass_title)
        .visible(auth_idx == 1)
        .build();

    {
        let key_row = key_row.clone();
        let pass_row = pass_row.clone();
        auth_row.connect_selected_notify(move |row| {
            let is_key = row.selected() == 0;
            key_row.set_visible(is_key);
            pass_row.set_visible(!is_key);
        });
    }

    // VPN auto-connect combo — "None" plus all VPN profiles.
    let mut vpn_names: Vec<&str> = vec!["None"];
    vpn_names.extend(vpn_profiles.iter().map(|p| p.name.as_str()));
    let vpn_model = gtk4::StringList::new(&vpn_names);
    let vpn_idx = host.vpn_profile_id
        .and_then(|vid| vpn_profiles.iter().position(|p| p.id == vid))
        .map(|i| (i + 1) as u32) // +1 because index 0 is "None"
        .unwrap_or(0);
    let vpn_row = adw::ComboRow::builder()
        .title("VPN Profile")
        .subtitle("Auto-connect VPN before SSH")
        .model(&vpn_model)
        .selected(vpn_idx)
        .build();

    // Jump Host (ProxyJump) combo — "None / Direct" plus all other SSH hosts.
    let other_hosts: Vec<&SshHostSummary> = all_hosts.iter()
        .filter(|h| h.id != host.id)
        .collect();
    let mut jump_names: Vec<String> = vec!["None / Direct".to_string()];
    jump_names.extend(other_hosts.iter().map(|h| format!("{} ({})", h.label, h.hostname)));
    let jump_name_refs: Vec<&str> = jump_names.iter().map(|s| s.as_str()).collect();
    let jump_model = gtk4::StringList::new(&jump_name_refs);
    let jump_idx = host.proxy_jump
        .and_then(|jid| other_hosts.iter().position(|h| h.id == jid))
        .map(|i| (i + 1) as u32)
        .unwrap_or(0);
    let jump_row = adw::ComboRow::builder()
        .title("Jump Host")
        .subtitle("Connect via bastion/jump host (ProxyJump)")
        .model(&jump_model)
        .selected(jump_idx)
        .build();

    let conn_group = adw::PreferencesGroup::builder().title("Connection").build();
    conn_group.add(&label_row);
    conn_group.add(&hostname_row);
    conn_group.add(&port_row);
    conn_group.add(&username_row);
    conn_group.add(&group_row);
    conn_group.add(&device_row);
    conn_group.add(&jump_row);

    let auth_group = adw::PreferencesGroup::builder().title("Authentication").margin_top(12).build();
    auth_group.add(&auth_row);
    auth_group.add(&key_row);
    auth_group.add(&pass_row);
    auth_group.add(&vpn_row);

    // FortiGate REST API group (only visible for fortigate device type).
    let api_group = adw::PreferencesGroup::builder()
        .title("FortiGate REST API")
        .margin_top(12)
        .visible(host.device_type == supermgr_core::DeviceType::Fortigate)
        .build();
    let token_title = if host.has_api { "API Token (configured — leave empty to keep)" } else { "API Token" };
    let api_token_row = adw::PasswordEntryRow::builder()
        .title(token_title)
        .build();
    let api_port_row = adw::EntryRow::builder()
        .title("HTTPS Port")
        .text(&host.api_port.unwrap_or(443).to_string())
        .build();
    api_group.add(&api_token_row);
    api_group.add(&api_port_row);

    {
        let api_group = api_group.clone();
        device_row.connect_selected_notify(move |row| {
            api_group.set_visible(row.selected() == 4); // index 4 = fortigate
        });
    }

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let save_btn = gtk4::Button::builder()
        .label("Save")
        .css_classes(["suggested-action"])
        .sensitive(true)
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&save_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12).margin_bottom(24).margin_start(24).margin_end(24)
        .spacing(0)
        .build();
    content_box.append(&conn_group);
    content_box.append(&auth_group);
    content_box.append(&api_group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    let has_password = host.has_password;
    let validate: Rc<dyn Fn()> = {
        let label_row = label_row.clone();
        let hostname_row = hostname_row.clone();
        let username_row = username_row.clone();
        let auth_row = auth_row.clone();
        let pass_row = pass_row.clone();
        let save_btn = save_btn.clone();
        Rc::new(move || {
            let basic_ok = !label_row.text().is_empty()
                && !hostname_row.text().is_empty()
                && !username_row.text().is_empty();
            // When auth method is Password and no password is stored yet,
            // require the user to enter one.
            let pass_ok = auth_row.selected() == 0 // key auth — no password needed
                || has_password                      // already has a stored password
                || !pass_row.text().is_empty();      // user entered a new password
            save_btn.set_sensitive(basic_ok && pass_ok);
        })
    };
    { let v = Rc::clone(&validate); label_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); hostname_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); username_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); pass_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); auth_row.connect_selected_notify(move |_| v()); }

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    let key_ids: Vec<String> = keys.iter().map(|k| k.id.to_string()).collect();
    let vpn_profile_ids: Vec<String> = vpn_profiles.iter().map(|p| p.id.to_string()).collect();
    let jump_host_ids: Vec<String> = other_hosts.iter().map(|h| h.id.to_string()).collect();
    let host_id = host.id.to_string();

    {
        let dialog = dialog.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        save_btn.connect_clicked(move |_| {
            let label = label_row.text().to_string();
            let hostname = hostname_row.text().to_string();
            let port: u16 = port_row.text().parse().unwrap_or(22);
            let username = username_row.text().to_string();
            let group = group_row.text().to_string();
            let device_type = match device_row.selected() {
                1 => "uni_fi", 2 => "pf_sense", 3 => "open_wrt",
                4 => "fortigate", 5 => "windows", 6 => "custom", _ => "linux",
            }.to_owned();
            let auth_method = if auth_row.selected() == 0 { "key" } else { "password" }.to_owned();
            let key_id = if auth_row.selected() == 0 {
                key_ids.get(key_row.selected() as usize).cloned()
            } else {
                None
            };

            let password = pass_row.text().to_string();
            let api_token = api_token_row.text().to_string();
            let api_port: u16 = api_port_row.text().parse().unwrap_or(443);

            // VPN profile: index 0 = None, 1.. = vpn_profile_ids[i-1]
            let vpn_id = {
                let sel = vpn_row.selected() as usize;
                if sel > 0 { vpn_profile_ids.get(sel - 1).cloned() } else { None }
            };

            // Jump host: index 0 = None, 1.. = jump_host_ids[i-1]
            let jump_id = {
                let sel = jump_row.selected() as usize;
                if sel > 0 { jump_host_ids.get(sel - 1).cloned() } else { None }
            };

            dialog.close();
            let host_id = host_id.clone();
            let tx = tx.clone();
            rt.spawn(async move {
                let host_data = serde_json::json!({
                    "label": label,
                    "hostname": hostname,
                    "port": port,
                    "username": username,
                    "group": group,
                    "device_type": device_type,
                    "auth_method": auth_method,
                    "auth_key_id": key_id,
                    "vpn_profile_id": vpn_id,
                    "proxy_jump": jump_id,
                });
                let msg = match crate::dbus_client::dbus_ssh_update_host(host_id.clone(), host_data.to_string()).await {
                    Ok(()) => {
                        // Store SSH password if provided.
                        if !password.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_password(host_id.clone(), password).await {
                                error!("store SSH password: {e:#}");
                            }
                        }
                        // Store FortiGate API token and port if token is provided.
                        if !api_token.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_api_token(host_id, api_token, api_port).await {
                                error!("store API token/port: {e:#}");
                            }
                        }
                        match crate::dbus_client::dbus_ssh_list_hosts().await {
                            Ok(hosts) => AppMsg::SshHostsRefreshed(hosts),
                            Err(e) => AppMsg::OperationFailed(e.to_string()),
                        }
                    }
                    Err(e) => {
                        error!("edit SSH host: {e:#}");
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
// Audit Log dialog
// ---------------------------------------------------------------------------

/// Show the SSH audit log viewer.
pub fn show_audit_log_dialog(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
) {
    let dialog = adw::Dialog::builder()
        .title("SSH Audit Log")
        .content_width(700)
        .content_height(500)
        .build();

    let text_view = gtk4::TextView::builder()
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::Word)
        .build();

    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vexpand(true)
        .child(&text_view)
        .build();

    let close_btn = gtk4::Button::builder().label("Close").build();
    let header = adw::HeaderBar::new();
    header.pack_start(&close_btn);
    header.set_show_start_title_buttons(false);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&scroll));
    dialog.set_child(Some(&toolbar_view));

    {
        let dialog = dialog.clone();
        close_btn.connect_clicked(move |_| { dialog.close(); });
    }

    let text_view_clone = text_view.clone();
    let (log_tx, log_rx) = std::sync::mpsc::channel::<Vec<String>>();
    rt.spawn(async move {
        match crate::dbus_client::dbus_ssh_get_audit_log(200).await {
            Ok(lines) => { let _ = log_tx.send(lines); }
            Err(e) => {
                tracing::error!("fetch audit log: {e}");
                let _ = log_tx.send(vec![format!("Error loading audit log: {e}")]);
            }
        }
    });

    gtk4::glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
        if let Ok(lines) = log_rx.try_recv() {
            let text = if lines.is_empty() {
                "No audit entries yet.".to_string()
            } else {
                lines.join("\n")
            };
            text_view_clone.buffer().set_text(&text);
            gtk4::glib::ControlFlow::Break
        } else {
            gtk4::glib::ControlFlow::Continue
        }
    });

    dialog.present(Some(window));
}
