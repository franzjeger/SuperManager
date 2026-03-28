//! SSH key list sidebar widget.
//!
//! Builds a [`gtk4::ListBox`] where each row is an [`adw::ActionRow`] showing
//! key name, type, and truncated fingerprint.  Context menu offers Push,
//! Revoke, Export, and Delete.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::{gio, glib, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use supermgr_core::ssh::key::SshKeySummary;

use crate::app::{AppMsg, AppState};
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
