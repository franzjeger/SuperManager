//! SSH host list sidebar widget with group headers.
//!
//! Builds a [`gtk4::ListBox`] where hosts are grouped by their `group` field.
//! Group headers are bold, non-selectable rows.  Host rows show label and
//! hostname:port as subtitle.

use std::collections::BTreeMap;
use std::sync::mpsc;

use gtk4::{gio, glib, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use supermgr_core::{host::HostSummary, ssh::DeviceType};

use crate::app::AppMsg;
use crate::dbus_client::{dbus_ssh_delete_host, dbus_ssh_toggle_pin};

// ---------------------------------------------------------------------------
// Device-type-aware menu construction
// ---------------------------------------------------------------------------

/// Decide which menu items to offer for a given host.
///
/// The right-click menu used to be a fixed five-item list (Connect, Test,
/// Edit, Pin, Delete) for every host regardless of type — RDP got offered
/// on FortiGate firewalls, "Open WebAdmin" was nowhere even though every
/// appliance has one. This helper returns a curated list based on the
/// host's `device_type` plus what's actually configured (RDP/VNC ports,
/// API token, UniFi controller URL).
///
/// Returned tuples are `(label, action_id)`; `host-ctx.` is prepended to
/// each id when the menu is wired up.
fn host_menu_items(host: &HostSummary) -> Vec<(&'static str, &'static str)> {
    let mut items: Vec<(&'static str, &'static str)> = Vec::new();

    // ---- Primary actions: how do you "open" this host? ----------------
    // Windows boxes get RDP first since that's the natural primary.
    // Everything else gets SSH first.
    if matches!(host.device_type, DeviceType::Windows) && host.rdp_port.is_some() {
        items.push(("Open RDP", "rdp"));
        items.push(("Open SSH terminal", "connect"));
    } else {
        items.push(("Open SSH terminal", "connect"));
        if host.rdp_port.is_some() {
            items.push(("Open RDP", "rdp"));
        }
    }
    if host.vnc_port.is_some() {
        items.push(("Open VNC", "vnc"));
    }

    // ---- Vendor-specific web admin & API actions ---------------------
    // RDP/VNC don't make sense on appliances, but a "click to land in the
    // box's web UI" entry does — these are the things you actually want
    // when a customer call requires fast triage.
    // OpnSense / Sophos land here once their enum variants merge in
    // — the variant additions are tracked in #13/#14. A follow-up PR
    // will extend this match arm.
    let appliance = matches!(
        host.device_type,
        DeviceType::Fortigate | DeviceType::PfSense | DeviceType::OpenWrt
    );
    if appliance {
        items.push(("Open WebAdmin in browser", "open-webadmin"));
    }
    if matches!(host.device_type, DeviceType::UniFi) && host.has_unifi_controller {
        items.push(("Open Controller in browser", "open-webadmin"));
    }

    // ---- Always-applicable maintenance actions -----------------------
    items.push(("Test connection", "test"));
    items.push(("Edit\u{2026}", "edit"));
    items.push((if host.pinned { "Unpin" } else { "Pin" }, "toggle-pin"));
    items.push(("Delete\u{2026}", "delete"));

    items
}

/// Resolve the WebAdmin / Controller URL for `host`, if one can be derived.
///
/// FortiGate / pfSense / OpenWrt use `https://<hostname>:<api_port>/`
/// (defaulting `api_port` to 443). UniFi uses `unifi_controller_url`
/// directly. OpnSense and Sophos URL handling will be added in the
/// follow-up PR that ties this menu to those device-type variants.
fn web_admin_url(host: &HostSummary) -> Option<String> {
    match host.device_type {
        DeviceType::UniFi => host.unifi_controller_url.clone(),
        DeviceType::Fortigate | DeviceType::PfSense | DeviceType::OpenWrt => Some(format!(
            "https://{}:{}/",
            host.hostname,
            host.api_port.unwrap_or(443)
        )),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build the SSH host list.
pub fn build_ssh_host_list() -> gtk4::ListBox {
    gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(["navigation-sidebar"])
        .build()
}

// ---------------------------------------------------------------------------
// Populate
// ---------------------------------------------------------------------------

/// Rebuild the host list from the current SSH hosts, grouped by `group`.
///
/// Ungrouped hosts (empty group string) appear under an "Ungrouped" header.
/// Group headers are non-activatable bold labels.
pub fn populate_ssh_host_list(
    list_box: &gtk4::ListBox,
    hosts: &[HostSummary],
    selected_id: Option<&str>,
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
    filter: &str,
    health: &std::collections::HashMap<String, bool>,
) {
    // Clear.
    let mut child = list_box.first_child();
    while let Some(c) = child {
        let next = c.next_sibling();
        if c.is::<gtk4::ListBoxRow>() {
            list_box.remove(&c);
        }
        child = next;
    }

    // Apply search filter.
    let filter_lower = filter.to_lowercase();
    let filtered: Vec<&HostSummary> = if filter.is_empty() {
        hosts.iter().collect()
    } else {
        hosts.iter()
            .filter(|h| {
                h.label.to_lowercase().contains(&filter_lower)
                    || h.hostname.to_lowercase().contains(&filter_lower)
                    || h.username.to_lowercase().contains(&filter_lower)
                    || h.group.to_lowercase().contains(&filter_lower)
            })
            .collect()
    };

    if filtered.is_empty() {
        let placeholder = adw::ActionRow::builder()
            .title(if filter.is_empty() { "No SSH hosts" } else { "No matching hosts" })
            .subtitle(if filter.is_empty() {
                "Add a host to get started"
            } else {
                "Try a different search term"
            })
            .activatable(false)
            .build();
        list_box.append(&placeholder);
        return;
    }

    // Group hosts by their group field.
    let mut groups: BTreeMap<String, Vec<&HostSummary>> = BTreeMap::new();
    for host in &filtered {
        let group_name = if host.group.is_empty() {
            "Ungrouped".to_owned()
        } else {
            host.group.clone()
        };
        groups.entry(group_name).or_default().push(host);
    }

    // Sort hosts within each group: pinned first, then alphabetically by label.
    for hosts_in_group in groups.values_mut() {
        hosts_in_group.sort_by(|a, b| {
            b.pinned.cmp(&a.pinned)
                .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
        });
    }

    // Track row indices to map selection back to host IDs.
    // We need to remember which indices are group headers (non-selectable).
    let mut _row_idx: i32 = 0;
    let mut host_row_map: Vec<Option<String>> = Vec::new(); // None = group header

    for (group_name, hosts_in_group) in &groups {
        // Group header row.
        let header_row = gtk4::ListBoxRow::builder()
            .selectable(false)
            .activatable(false)
            .build();
        let header_label = gtk4::Label::builder()
            .label(group_name)
            .css_classes(["heading"])
            .halign(gtk4::Align::Start)
            .margin_top(8)
            .margin_bottom(4)
            .margin_start(12)
            .build();
        header_row.set_child(Some(&header_label));
        list_box.append(&header_row);
        host_row_map.push(None);
        _row_idx += 1;

        for host in hosts_in_group {
            let port_str = if host.port == 22 {
                String::new()
            } else {
                format!(":{}", host.port)
            };
            let subtitle = format!(
                "{}{}  \u{b7}  {}@",
                host.hostname, port_str, host.username
            );

            let display_title = if host.pinned {
                format!("\u{2605} {}", host.label)
            } else {
                host.label.clone()
            };
            let row = adw::ActionRow::builder()
                .title(&display_title)
                .subtitle(&subtitle)
                .activatable(true)
                .build();

            // Health indicator: green = reachable, red = unreachable, grey = unknown.
            let (health_char, health_color) = match health.get(&host.id.to_string()) {
                Some(true) => ("●", "success"),   // green
                Some(false) => ("●", "error"),     // red
                None => ("●", "dim-label"),        // grey
            };
            let health_label = gtk4::Label::builder()
                .label(health_char)
                .css_classes([health_color])
                .build();
            row.add_prefix(&health_label);

            let icon = match host.device_type {
                supermgr_core::ssh::DeviceType::Linux => "computer-symbolic",
                supermgr_core::ssh::DeviceType::Windows => "computer-symbolic",
                supermgr_core::ssh::DeviceType::OpenWrt
                | supermgr_core::ssh::DeviceType::PfSense
                | supermgr_core::ssh::DeviceType::OpnSense => "network-server-symbolic",
                supermgr_core::ssh::DeviceType::Fortigate
                | supermgr_core::ssh::DeviceType::Sophos => "security-high-symbolic",
                supermgr_core::ssh::DeviceType::UniFi => "network-wireless-symbolic",
                supermgr_core::ssh::DeviceType::Custom => "computer-symbolic",
            };
            row.add_prefix(&gtk4::Image::from_icon_name(icon));

            // Delete button.
            let delete_btn = gtk4::Button::builder()
                .icon_name("user-trash-symbolic")
                .tooltip_text("Delete host")
                .css_classes(["flat"])
                .valign(gtk4::Align::Center)
                .build();
            row.add_suffix(&delete_btn);

            let host_id = host.id.to_string();
            let host_label = host.label.clone();
            let window_c = window.clone();
            let rt_c = rt.clone();
            let tx_c = tx.clone();
            delete_btn.connect_clicked(move |_| {
                let dialog = adw::AlertDialog::new(
                    Some(&format!("Delete host \"{}\"?", host_label)),
                    Some("This cannot be undone."),
                );
                dialog.add_response("cancel", "Cancel");
                dialog.add_response("delete", "Delete");
                dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
                dialog.set_default_response(Some("cancel"));
                dialog.set_close_response("cancel");

                let host_id = host_id.clone();
                let rt = rt_c.clone();
                let tx = tx_c.clone();
                dialog.connect_response(Some("delete"), move |_dlg, _resp| {
                    let host_id = host_id.clone();
                    let tx = tx.clone();
                    rt.spawn(async move {
                        let msg = match dbus_ssh_delete_host(host_id.clone()).await {
                            Ok(()) => {
                                info!("deleted SSH host {}", host_id);
                                let hosts = crate::dbus_client::dbus_ssh_list_hosts().await.unwrap_or_default();
                                AppMsg::SshHostsRefreshed(hosts)
                            }
                            Err(e) => {
                                error!("delete SSH host failed: {:#}", e);
                                AppMsg::OperationFailed(e.to_string())
                            }
                        };
                        tx.send(msg).ok();
                    });
                });

                dialog.present(Some(&window_c));
            });

            // ----- Right-click context menu -----
            {
                let host_id = host.id.to_string();
                let host_label = host.label.clone();
                let host_hostname = host.hostname.clone();
                let host_username = host.username.clone();
                let host_rdp_port = host.rdp_port;
                let host_vnc_port = host.vnc_port;
                let host_webadmin = web_admin_url(host);
                let window_ctx = window.clone();
                let rt_ctx = rt.clone();
                let tx_ctx = tx.clone();

                // Build the gio::Menu model from the device-type-aware list.
                let menu_model = gio::Menu::new();
                for (label, id) in host_menu_items(host) {
                    let action_path = format!("host-ctx.{id}");
                    menu_model.append(Some(label), Some(&action_path));
                }

                let popover = gtk4::PopoverMenu::from_model(Some(&menu_model));
                popover.set_has_arrow(true);
                // Attach popover as child of the row so it positions correctly.
                // Use set_parent + connect to row's destroy to unparent cleanly.
                popover.set_parent(&row);
                {
                    let popover = popover.clone();
                    row.connect_destroy(move |_| {
                        popover.unparent();
                    });
                }

                // Action group for this row's context menu.
                let action_group = gio::SimpleActionGroup::new();

                // Connect action — launch SSH terminal.
                {
                    let host_id = host_id.clone();
                    let tx = tx_ctx.clone();
                    let rt = rt_ctx.clone();
                    let action = gio::SimpleAction::new("connect", None);
                    action.connect_activate(move |_, _| {
                        let host_id = host_id.clone();
                        let tx = tx.clone();
                        rt.spawn(async move {
                            match crate::dbus_client::dbus_ssh_connect_command(host_id).await {
                                Ok(ssh_cmd) => {
                                    glib::idle_add_once(move || {
                                        crate::ui::ssh::host_detail::launch_ssh_terminal(&ssh_cmd);
                                    });
                                }
                                Err(e) => {
                                    tx.send(AppMsg::OperationFailed(
                                        format!("SSH connect failed: {e}"),
                                    ))
                                    .ok();
                                }
                            }
                        });
                    });
                    action_group.add_action(&action);
                }

                // Test connection action.
                {
                    let host_id = host_id.clone();
                    let tx = tx_ctx.clone();
                    let rt = rt_ctx.clone();
                    let action = gio::SimpleAction::new("test", None);
                    action.connect_activate(move |_, _| {
                        let host_id = host_id.clone();
                        let tx = tx.clone();
                        tx.send(AppMsg::ShowToast("Testing connection\u{2026}".to_string()))
                            .ok();
                        rt.spawn(async move {
                            let msg = match crate::dbus_client::dbus_ssh_test_connection(
                                host_id,
                            )
                            .await
                            {
                                Ok(json) => {
                                    let v: serde_json::Value =
                                        serde_json::from_str(&json).unwrap_or_default();
                                    let ssh_status = v
                                        .get("ssh")
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("unknown");
                                    if ssh_status == "ok" {
                                        AppMsg::ShowToast("Connection test passed".to_string())
                                    } else {
                                        AppMsg::OperationFailed(format!(
                                            "Connection test: SSH {ssh_status}"
                                        ))
                                    }
                                }
                                Err(e) => AppMsg::OperationFailed(format!(
                                    "Connection test failed: {e}"
                                )),
                            };
                            tx.send(msg).ok();
                        });
                    });
                    action_group.add_action(&action);
                }

                // Edit action.
                {
                    let host_id = host_id.clone();
                    let tx = tx_ctx.clone();
                    let action = gio::SimpleAction::new("edit", None);
                    action.connect_activate(move |_, _| {
                        tx.send(AppMsg::EditSshHost(host_id.clone())).ok();
                    });
                    action_group.add_action(&action);
                }

                // RDP action — only registered when the menu actually
                // contains the entry, but registering unconditionally is
                // cheap and keeps the wiring uniform.
                {
                    let hostname = host_hostname.clone();
                    let username = host_username.clone();
                    let port = host_rdp_port;
                    let tx = tx_ctx.clone();
                    let action = gio::SimpleAction::new("rdp", None);
                    action.connect_activate(move |_, _| {
                        if let Some(p) = port {
                            let hostname = hostname.clone();
                            let username = username.clone();
                            let tx = tx.clone();
                            glib::idle_add_once(move || {
                                match super::host_detail::launch_rdp(
                                    &hostname,
                                    p,
                                    &username,
                                    None,
                                ) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        let _ = tx.send(AppMsg::OperationFailed(format!(
                                            "RDP launch failed: {e}"
                                        )));
                                    }
                                }
                            });
                        }
                    });
                    action_group.add_action(&action);
                }

                // VNC action.
                {
                    let hostname = host_hostname.clone();
                    let port = host_vnc_port;
                    let tx = tx_ctx.clone();
                    let action = gio::SimpleAction::new("vnc", None);
                    action.connect_activate(move |_, _| {
                        if let Some(p) = port {
                            let hostname = hostname.clone();
                            let tx = tx.clone();
                            glib::idle_add_once(move || {
                                if let Err(e) =
                                    super::host_detail::launch_vnc(&hostname, p)
                                {
                                    let _ = tx.send(AppMsg::OperationFailed(format!(
                                        "VNC launch failed: {e}"
                                    )));
                                }
                            });
                        }
                    });
                    action_group.add_action(&action);
                }

                // Open WebAdmin / Controller action — xdg-open the URL
                // resolved from device_type and stored fields. Only fires
                // for hosts whose menu listed the entry.
                {
                    let url = host_webadmin.clone();
                    let tx = tx_ctx.clone();
                    let action = gio::SimpleAction::new("open-webadmin", None);
                    action.connect_activate(move |_, _| {
                        let Some(url) = url.clone() else { return };
                        let tx = tx.clone();
                        match std::process::Command::new("xdg-open").arg(&url).spawn() {
                            Ok(_) => {
                                info!("xdg-open {}", url);
                            }
                            Err(e) => {
                                let _ = tx.send(AppMsg::OperationFailed(format!(
                                    "could not launch browser: {e}"
                                )));
                            }
                        }
                    });
                    action_group.add_action(&action);
                }

                // Pin/Unpin action.
                {
                    let host_id = host_id.clone();
                    let tx = tx_ctx.clone();
                    let rt = rt_ctx.clone();
                    let action = gio::SimpleAction::new("toggle-pin", None);
                    action.connect_activate(move |_, _| {
                        let host_id = host_id.clone();
                        let tx = tx.clone();
                        rt.spawn(async move {
                            let msg = match dbus_ssh_toggle_pin(host_id).await {
                                Ok(hosts) => AppMsg::SshHostsRefreshed(hosts),
                                Err(e) => AppMsg::OperationFailed(e.to_string()),
                            };
                            tx.send(msg).ok();
                        });
                    });
                    action_group.add_action(&action);
                }

                // Delete action.
                {
                    let host_id = host_id.clone();
                    let host_label = host_label.clone();
                    let window_del = window_ctx.clone();
                    let rt = rt_ctx.clone();
                    let tx = tx_ctx.clone();
                    let action = gio::SimpleAction::new("delete", None);
                    action.connect_activate(move |_, _| {
                        let dialog = adw::AlertDialog::new(
                            Some(&format!("Delete host \"{}\"?", host_label)),
                            Some("This cannot be undone."),
                        );
                        dialog.add_response("cancel", "Cancel");
                        dialog.add_response("delete", "Delete");
                        dialog.set_response_appearance(
                            "delete",
                            adw::ResponseAppearance::Destructive,
                        );
                        dialog.set_default_response(Some("cancel"));
                        dialog.set_close_response("cancel");

                        let host_id = host_id.clone();
                        let rt = rt.clone();
                        let tx = tx.clone();
                        dialog.connect_response(Some("delete"), move |_dlg, _resp| {
                            let host_id = host_id.clone();
                            let tx = tx.clone();
                            rt.spawn(async move {
                                let msg = match dbus_ssh_delete_host(host_id.clone()).await {
                                    Ok(()) => {
                                        info!("deleted SSH host {}", host_id);
                                        let hosts = crate::dbus_client::dbus_ssh_list_hosts()
                                            .await
                                            .unwrap_or_default();
                                        AppMsg::SshHostsRefreshed(hosts)
                                    }
                                    Err(e) => {
                                        error!("delete SSH host failed: {:#}", e);
                                        AppMsg::OperationFailed(e.to_string())
                                    }
                                };
                                tx.send(msg).ok();
                            });
                        });

                        dialog.present(Some(&window_del));
                    });
                    action_group.add_action(&action);
                }

                row.insert_action_group("host-ctx", Some(&action_group));

                // Attach right-click gesture to show the popover.
                let gesture = gtk4::GestureClick::builder()
                    .button(3) // right-click
                    .build();
                let popover_ref = popover.clone();
                gesture.connect_pressed(move |_gesture, _n, x, y| {
                    popover_ref.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(
                        x as i32, y as i32, 1, 1,
                    )));
                    popover_ref.popup();
                });
                row.add_controller(gesture);
            }

            list_box.append(&row);
            host_row_map.push(Some(host.id.to_string()));
            _row_idx += 1;
        }
    }

    // Highlight selected host.
    if let Some(sid) = selected_id {
        for (i, entry) in host_row_map.iter().enumerate() {
            if entry.as_deref() == Some(sid) {
                if let Some(row) = list_box.row_at_index(i as i32) {
                    list_box.select_row(Some(&row));
                }
                break;
            }
        }
    }
}
