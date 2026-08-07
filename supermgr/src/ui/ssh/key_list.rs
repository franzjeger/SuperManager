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

use supermgr_core::ssh::key::{SshKeySummary, SshKeyType};

use crate::app::AppMsg;
use crate::dbus_client::{
    dbus_ssh_delete_key, dbus_ssh_export_private_key, dbus_ssh_export_public_key,
};
use crate::ui::design;

// ---------------------------------------------------------------------------
// Row content
// ---------------------------------------------------------------------------

/// Shorten a fingerprint to something that fits in a sidebar row.
///
/// Truncation is by character, not by byte: a fingerprint is Base64 today,
/// but slicing a `String` at a fixed byte offset panics the moment one is
/// not, and a list of keys is not where that should be discovered.
#[must_use]
pub fn short_fingerprint(fingerprint: &str) -> String {
    const KEEP: usize = 20;
    let mut short: String = fingerprint.chars().take(KEEP).collect();
    if fingerprint.chars().nth(KEEP).is_some() {
        short.push('\u{2026}');
    }
    short
}

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
        let row = adw::ActionRow::builder()
            .title(key.name.as_str())
            .subtitle(&short_fingerprint(&key.fingerprint))
            .activatable(true)
            .build();
        row.add_prefix(&design::icon(design::icons::KEY));

        // Key type as a badge, as backends are in the VPN list — the same
        // fact in the same shape, so the two lists read the same way.
        row.add_suffix(&design::badge(&format!("{:?}", key.key_type)));

        // Deployment count. Zero is worth saying: a key that exists but is
        // installed nowhere is the one an operator is usually looking for,
        // and the old list simply omitted the badge in that case, which made
        // "not deployed" indistinguishable from "not rendered".
        let deployed = design::badge(&if key.deployed_count == 0 {
            "unused".to_owned()
        } else {
            format!("{} host(s)", key.deployed_count)
        });
        deployed.set_tooltip_text(Some(&if key.deployed_count == 0 {
            "Not deployed to any host".to_owned()
        } else {
            format!("Deployed to {} host(s)", key.deployed_count)
        }));
        row.add_suffix(&deployed);

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

            let export_section = gio::Menu::new();
            export_section.append(Some("Export Public Key\u{2026}"), Some("key-ctx.export-pub"));
            export_section.append(Some("Export Private Key\u{2026}"), Some("key-ctx.export-priv"));
            export_section.append(Some("Export to ~/.ssh/"), Some("key-ctx.export-ssh-dir"));
            menu_model.append_submenu(Some("Export"), &export_section);

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

            // Export Public Key action.
            {
                let key_id = key_id.clone();
                let key_name = key_name.clone();
                let window_exp = window_ctx.clone();
                let rt = rt_ctx.clone();
                let tx = tx_ctx.clone();
                let action = gio::SimpleAction::new("export-pub", None);
                action.connect_activate(move |_, _| {
                    let dialog = gtk4::FileDialog::builder()
                        .title("Export Public Key")
                        .initial_name(format!("{}.pub", key_name))
                        .build();
                    let key_id = key_id.clone();
                    let rt = rt.clone();
                    let tx = tx.clone();
                    dialog.save(Some(&window_exp), gtk4::gio::Cancellable::NONE, move |result| {
                        if let Ok(file) = result {
                            if let Some(path) = file.path() {
                                let key_id = key_id.clone();
                                let tx = tx.clone();
                                let path = path.clone();
                                rt.spawn(async move {
                                    match dbus_ssh_export_public_key(key_id).await {
                                        Ok(content) => {
                                            if let Err(e) = write_key_file(&path, &content, 0o644) {
                                                tx.send(AppMsg::OperationFailed(
                                                    format!("Failed to write public key: {}", e),
                                                )).ok();
                                            } else {
                                                tx.send(AppMsg::ShowToast(
                                                    format!("Public key exported to {}", path.display()),
                                                )).ok();
                                            }
                                        }
                                        Err(e) => {
                                            tx.send(AppMsg::OperationFailed(e.to_string())).ok();
                                        }
                                    }
                                });
                            }
                        }
                    });
                });
                action_group.add_action(&action);
            }

            // Export Private Key action.
            {
                let key_id = key_id.clone();
                let key_name = key_name.clone();
                let window_exp = window_ctx.clone();
                let rt = rt_ctx.clone();
                let tx = tx_ctx.clone();
                let action = gio::SimpleAction::new("export-priv", None);
                action.connect_activate(move |_, _| {
                    let dialog = gtk4::FileDialog::builder()
                        .title("Export Private Key")
                        .initial_name(key_name.to_string())
                        .build();
                    let key_id = key_id.clone();
                    let rt = rt.clone();
                    let tx = tx.clone();
                    dialog.save(Some(&window_exp), gtk4::gio::Cancellable::NONE, move |result| {
                        if let Ok(file) = result {
                            if let Some(path) = file.path() {
                                let key_id = key_id.clone();
                                let tx = tx.clone();
                                let path = path.clone();
                                rt.spawn(async move {
                                    match dbus_ssh_export_private_key(key_id).await {
                                        Ok(content) => {
                                            if let Err(e) = write_key_file(&path, &content, 0o600) {
                                                tx.send(AppMsg::OperationFailed(
                                                    format!("Failed to write private key: {}", e),
                                                )).ok();
                                            } else {
                                                tx.send(AppMsg::ShowToast(
                                                    format!("Private key exported to {}", path.display()),
                                                )).ok();
                                            }
                                        }
                                        Err(e) => {
                                            tx.send(AppMsg::OperationFailed(e.to_string())).ok();
                                        }
                                    }
                                });
                            }
                        }
                    });
                });
                action_group.add_action(&action);
            }

            // Export to ~/.ssh/ action.
            {
                let key_id = key_id.clone();
                let key_name = key_name.clone();
                let key_type = key.key_type;
                let window_exp = window_ctx.clone();
                let rt = rt_ctx.clone();
                let tx = tx_ctx.clone();
                let action = gio::SimpleAction::new("export-ssh-dir", None);
                action.connect_activate(move |_, _| {
                    let (priv_name, pub_name) = ssh_dir_filenames(key_type, &key_name);
                    let ssh_dir = std::path::PathBuf::from(
                        std::env::var("HOME").unwrap_or_else(|_| "/root".into()),
                    ).join(".ssh");
                    let priv_path = ssh_dir.join(&priv_name);
                    let pub_path = ssh_dir.join(&pub_name);

                    let key_id = key_id.clone();
                    let rt = rt.clone();
                    let tx = tx.clone();
                    let window_exp = window_exp.clone();
                    let _pub_name_display = pub_name.clone();

                    // Check if files exist; if so, confirm overwrite.
                    if priv_path.exists() || pub_path.exists() {
                        let dialog = adw::AlertDialog::new(
                            Some("Overwrite existing keys?"),
                            Some(&format!(
                                "Files already exist in ~/.ssh/:\n{}\n{}\n\nOverwrite them?",
                                priv_name, pub_name,
                            )),
                        );
                        dialog.add_response("cancel", "Cancel");
                        dialog.add_response("overwrite", "Overwrite");
                        dialog.set_response_appearance(
                            "overwrite",
                            adw::ResponseAppearance::Destructive,
                        );
                        dialog.set_default_response(Some("cancel"));
                        dialog.set_close_response("cancel");

                        let priv_path = priv_path.clone();
                        let pub_path = pub_path.clone();
                        dialog.connect_response(Some("overwrite"), move |_dlg, _resp| {
                            do_export_to_ssh_dir(
                                key_id.clone(),
                                priv_path.clone(),
                                pub_path.clone(),
                                priv_name.clone(),
                                rt.clone(),
                                tx.clone(),
                            );
                        });
                        dialog.present(Some(&window_exp));
                    } else {
                        do_export_to_ssh_dir(
                            key_id, priv_path, pub_path, priv_name, rt, tx,
                        );
                    }
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map key type + name to `~/.ssh/` filenames: `(private, public)`.
pub fn ssh_dir_filenames(key_type: SshKeyType, name: &str) -> (String, String) {
    let prefix = match key_type {
        SshKeyType::Ed25519 => "id_ed25519",
        SshKeyType::Rsa2048 | SshKeyType::Rsa4096 => "id_rsa",
    };
    let priv_name = format!("{}_{}", prefix, name);
    let pub_name = format!("{}_{}.pub", prefix, name);
    (priv_name, pub_name)
}

/// Write key content to a file with the given Unix permission mode.
fn write_key_file(
    path: &std::path::Path,
    content: &str,
    mode: u32,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Perform the actual export of both keys to `~/.ssh/`.
fn do_export_to_ssh_dir(
    key_id: String,
    priv_path: std::path::PathBuf,
    pub_path: std::path::PathBuf,
    priv_name: String,
    rt: tokio::runtime::Handle,
    tx: mpsc::Sender<AppMsg>,
) {
    rt.spawn(async move {
        // Export private key.
        let priv_content = match dbus_ssh_export_private_key(key_id.clone()).await {
            Ok(c) => c,
            Err(e) => {
                tx.send(AppMsg::OperationFailed(format!(
                    "Failed to export private key: {}", e
                ))).ok();
                return;
            }
        };
        if let Err(e) = write_key_file(&priv_path, &priv_content, 0o600) {
            tx.send(AppMsg::OperationFailed(format!(
                "Failed to write private key: {}", e
            ))).ok();
            return;
        }

        // Export public key.
        let pub_content = match dbus_ssh_export_public_key(key_id).await {
            Ok(c) => c,
            Err(e) => {
                tx.send(AppMsg::OperationFailed(format!(
                    "Failed to export public key: {}", e
                ))).ok();
                return;
            }
        };
        if let Err(e) = write_key_file(&pub_path, &pub_content, 0o644) {
            tx.send(AppMsg::OperationFailed(format!(
                "Failed to write public key: {}", e
            ))).ok();
            return;
        }

        tx.send(AppMsg::ShowToast(format!(
            "Exported to ~/.ssh/{}", priv_name
        ))).ok();
    });
}

/// Export all keys to `~/.ssh/` using the standard naming convention.
///
/// Called from the "Export All to ~/.ssh/" add-menu button.
pub fn export_all_keys_to_ssh_dir(
    keys: &[SshKeySummary],
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let ssh_dir = std::path::PathBuf::from(
        std::env::var("HOME").unwrap_or_else(|_| "/root".into()),
    ).join(".ssh");

    for key in keys {
        let (priv_name, _pub_name) = ssh_dir_filenames(key.key_type, &key.name);
        let priv_path = ssh_dir.join(&priv_name);
        let pub_path = ssh_dir.join(format!("{priv_name}.pub"));
        let key_id = key.id.to_string();

        do_export_to_ssh_dir(
            key_id,
            priv_path,
            pub_path,
            priv_name,
            rt.clone(),
            tx.clone(),
        );
    }

    if keys.is_empty() {
        tx.send(AppMsg::ShowToast("No keys to export".into())).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_fingerprint_is_left_alone() {
        assert_eq!(short_fingerprint("SHA256:abc"), "SHA256:abc");
        // Exactly at the limit: nothing was cut, so nothing claims it was.
        let exact = "0123456789abcdefghij";
        assert_eq!(exact.chars().count(), 20);
        assert_eq!(short_fingerprint(exact), exact);
    }

    #[test]
    fn a_long_fingerprint_is_cut_and_says_so() {
        let long = "SHA256:1234567890abcdefghijklmnop";
        let short = short_fingerprint(long);
        assert!(short.ends_with('\u{2026}'), "{short}");
        assert_eq!(short.chars().count(), 21, "20 kept plus the ellipsis");
        assert!(long.starts_with(&short[..short.len() - '\u{2026}'.len_utf8()]));
    }

    #[test]
    fn a_multibyte_fingerprint_does_not_panic() {
        // The old code did `&fingerprint[..20]`, which panics if byte 20 is
        // not a character boundary. Base64 never puts one there — but the
        // fingerprint is a string from the daemon, and a list of keys is not
        // where a slicing panic should first be discovered.
        let s = "ü".repeat(30);
        assert_eq!(short_fingerprint(&s).chars().count(), 21);
    }
}
