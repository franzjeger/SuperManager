//! SSH host list sidebar widget with group headers.
//!
//! Builds a [`gtk4::ListBox`] where hosts are grouped by their `group` field.
//! Group headers are bold, non-selectable rows.  Host rows show label and
//! hostname:port as subtitle.

use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Mutex};

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use supermgr_core::ssh::host::SshHostSummary;

use crate::app::{AppMsg, AppState};
use crate::dbus_client::dbus_ssh_delete_host;

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
    hosts: &[SshHostSummary],
    selected_id: Option<&str>,
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
    filter: &str,
    health: &std::collections::HashMap<String, bool>,
) {
    // Clear.
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    // Apply search filter.
    let filter_lower = filter.to_lowercase();
    let filtered: Vec<&SshHostSummary> = if filter.is_empty() {
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
    let mut groups: BTreeMap<String, Vec<&SshHostSummary>> = BTreeMap::new();
    for host in &filtered {
        let group_name = if host.group.is_empty() {
            "Ungrouped".to_owned()
        } else {
            host.group.clone()
        };
        groups.entry(group_name).or_default().push(host);
    }

    // Sort hosts within each group alphabetically by label.
    for hosts_in_group in groups.values_mut() {
        hosts_in_group.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));
    }

    // Track row indices to map selection back to host IDs.
    // We need to remember which indices are group headers (non-selectable).
    let mut row_idx: i32 = 0;
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
        row_idx += 1;

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

            let row = adw::ActionRow::builder()
                .title(host.label.as_str())
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
                | supermgr_core::ssh::DeviceType::PfSense => "network-server-symbolic",
                supermgr_core::ssh::DeviceType::Fortigate => "security-high-symbolic",
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

            list_box.append(&row);
            host_row_map.push(Some(host.id.to_string()));
            row_idx += 1;
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
