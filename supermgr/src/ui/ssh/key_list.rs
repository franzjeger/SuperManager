//! SSH key list sidebar widget.
//!
//! Builds a [`gtk4::ListBox`] where each row is an [`adw::ActionRow`] showing
//! key name, type, and truncated fingerprint.  Context menu offers Push,
//! Revoke, Export, and Delete.

use std::sync::mpsc;

use gtk4::{gio, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use supermgr_core::ssh::key::SshKeySummary;

use crate::app::AppMsg;
use crate::dbus_client::dbus_ssh_delete_key;

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build the SSH key list.
///
/// Returns the [`gtk4::ListBox`] so the caller can wire up selection handling.
pub fn build_ssh_key_list() -> gtk4::ListBox {
    gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(["navigation-sidebar"])
        .build()
}

// ---------------------------------------------------------------------------
// Populate
// ---------------------------------------------------------------------------

/// Rebuild the key list from the current SSH keys.
pub fn populate_ssh_key_list(
    list_box: &gtk4::ListBox,
    keys: &[SshKeySummary],
    selected_id: Option<&str>,
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
    filter: &str,
) {
    // Clear.
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    // Apply search filter.
    let filter_lower = filter.to_lowercase();
    let filtered: Vec<&SshKeySummary> = if filter.is_empty() {
        keys.iter().collect()
    } else {
        keys.iter()
            .filter(|k| {
                k.name.to_lowercase().contains(&filter_lower)
                    || k.fingerprint.to_lowercase().contains(&filter_lower)
            })
            .collect()
    };

    if filtered.is_empty() {
        let placeholder = adw::ActionRow::builder()
            .title(if filter.is_empty() { "No SSH keys" } else { "No matching keys" })
            .subtitle(if filter.is_empty() {
                "Generate or import a key to get started"
            } else {
                "Try a different search term"
            })
            .activatable(false)
            .build();
        list_box.append(&placeholder);
        return;
    }

    // Sort alphabetically by name.
    let mut sorted: Vec<&SshKeySummary> = filtered;
    sorted.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    for key in &sorted {
        let type_str = format!("{:?}", key.key_type);
        // Truncate fingerprint for display: "SHA256:abcdef..." -> first 16 chars.
        let fp_short = if key.fingerprint.len() > 20 {
            format!("{}\u{2026}", &key.fingerprint[..20])
        } else {
            key.fingerprint.clone()
        };
        let subtitle = format!("{} \u{b7} {}", type_str, fp_short);

        let row = adw::ActionRow::builder()
            .title(key.name.as_str())
            .subtitle(&subtitle)
            .activatable(true)
            .build();

        row.add_prefix(&gtk4::Image::from_icon_name("dialog-password-symbolic"));

        // Deployed-count badge.
        if key.deployed_count > 0 {
            let badge = gtk4::Label::builder()
                .label(&format!("{}", key.deployed_count))
                .css_classes(["caption", "dim-label"])
                .valign(gtk4::Align::Center)
                .tooltip_text(&format!("Deployed to {} host(s)", key.deployed_count))
                .build();
            row.add_suffix(&badge);
        }

        // Delete button.
        let delete_btn = gtk4::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text("Delete key")
            .css_classes(["flat"])
            .valign(gtk4::Align::Center)
            .build();
        row.add_suffix(&delete_btn);

        let key_id = key.id.to_string();
        let key_name = key.name.clone();
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        {
        let key_id = key_id.clone();
        let key_name = key_name.clone();
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        delete_btn.connect_clicked(move |_| {
            let dialog = adw::AlertDialog::new(
                Some(&format!("Delete key \"{}\"?", key_name)),
                Some("The private key will be removed from the keyring. This cannot be undone."),
            );
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("delete", "Delete");
            dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
            dialog.set_default_response(Some("cancel"));
            dialog.set_close_response("cancel");

            let key_id = key_id.clone();
            let rt = rt.clone();
            let tx = tx.clone();
            dialog.connect_response(Some("delete"), move |_dlg, _resp| {
                let key_id = key_id.clone();
                let tx = tx.clone();
                rt.spawn(async move {
                    let msg = match dbus_ssh_delete_key(key_id.clone()).await {
                        Ok(()) => {
                            info!("deleted SSH key {}", key_id);
                            let keys = crate::dbus_client::dbus_ssh_list_keys().await.unwrap_or_default();
                            AppMsg::SshKeysRefreshed(keys)
                        }
                        Err(e) => {
                            error!("delete SSH key failed: {:#}", e);
                            AppMsg::OperationFailed(e.to_string())
                        }
                    };
                    tx.send(msg).ok();
                });
            });

            dialog.present(Some(&window));
        });
        }

        // ----- Right-click context menu -----
        {
            let key_id = key.id.to_string();
            let key_name = key.name.clone();
            let window_ctx = window.clone();
            let rt_ctx = rt.clone();
            let tx_ctx = tx.clone();

            let menu_model = gio::Menu::new();
            menu_model.append(Some("Push to Hosts"), Some("key-ctx.push"));
            menu_model.append(Some("Delete"), Some("key-ctx.delete"));

            let popover = gtk4::PopoverMenu::from_model(Some(&menu_model));
            popover.set_has_arrow(true);
            popover.set_parent(&row);
            {
                let popover = popover.clone();
                row.connect_destroy(move |_| {
                    popover.unparent();
                });
            }

            let action_group = gio::SimpleActionGroup::new();

            // Push action.
            {
                let key_id = key_id.clone();
                let tx = tx_ctx.clone();
                let action = gio::SimpleAction::new("push", None);
                action.connect_activate(move |_, _| {
                    tx.send(AppMsg::PushSshKey(key_id.clone())).ok();
                });
                action_group.add_action(&action);
            }

            // Delete action.
            {
                let key_id = key_id.clone();
                let key_name = key_name.clone();
                let window_del = window_ctx.clone();
                let rt = rt_ctx.clone();
                let tx = tx_ctx.clone();
                let action = gio::SimpleAction::new("delete", None);
                action.connect_activate(move |_, _| {
                    let dialog = adw::AlertDialog::new(
                        Some(&format!("Delete key \"{}\"?", key_name)),
                        Some("The private key will be removed from the keyring. This cannot be undone."),
                    );
                    dialog.add_response("cancel", "Cancel");
                    dialog.add_response("delete", "Delete");
                    dialog.set_response_appearance(
                        "delete",
                        adw::ResponseAppearance::Destructive,
                    );
                    dialog.set_default_response(Some("cancel"));
                    dialog.set_close_response("cancel");

                    let key_id = key_id.clone();
                    let rt = rt.clone();
                    let tx = tx.clone();
                    dialog.connect_response(Some("delete"), move |_dlg, _resp| {
                        let key_id = key_id.clone();
                        let tx = tx.clone();
                        rt.spawn(async move {
                            let msg = match dbus_ssh_delete_key(key_id.clone()).await {
                                Ok(()) => {
                                    info!("deleted SSH key {}", key_id);
                                    let keys = crate::dbus_client::dbus_ssh_list_keys()
                                        .await
                                        .unwrap_or_default();
                                    AppMsg::SshKeysRefreshed(keys)
                                }
                                Err(e) => {
                                    error!("delete SSH key failed: {:#}", e);
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

            row.insert_action_group("key-ctx", Some(&action_group));

            let gesture = gtk4::GestureClick::builder()
                .button(3)
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
    }

    // Highlight selected key.
    if let Some(sid) = selected_id {
        for (i, key) in sorted.iter().enumerate() {
            if key.id.to_string() == sid {
                if let Some(row) = list_box.row_at_index(i as i32) {
                    list_box.select_row(Some(&row));
                }
                break;
            }
        }
    }
}
