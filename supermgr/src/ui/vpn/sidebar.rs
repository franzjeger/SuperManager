//! VPN profile list sidebar widget.
//!
//! Builds a [`gtk4::ListBox`] where each row is an [`adw::ActionRow`] displaying
//! the profile name, backend type, and a delete button.  The list is rebuilt
//! from scratch via [`populate_vpn_sidebar`] whenever the profile list changes.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::{gio, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use supermgr_core::vpn::{profile::ProfileSummary, state::VpnState};

use crate::app::{AppMsg, AppState};
use crate::dbus_client::{dbus_connect, dbus_delete_profile, dbus_disconnect};

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build the VPN sidebar widgets.
///
/// Returns the [`gtk4::ListBox`] that holds profile rows, the
/// [`gtk4::SearchEntry`] for filtering, and the enclosing
/// [`adw::NavigationPage`] ready to be placed in a split view.
pub fn build_vpn_sidebar(
    app_state: &Arc<Mutex<AppState>>,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
    window: &adw::ApplicationWindow,
) -> (gtk4::ListBox, gtk4::SearchEntry, adw::NavigationPage) {
    let profile_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(["navigation-sidebar"])
        .build();

    let search_entry = gtk4::SearchEntry::builder()
        .placeholder_text("Search profiles\u{2026}")
        .margin_start(8)
        .margin_end(8)
        .margin_top(8)
        .build();

    let sidebar_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&profile_list)
        .build();

    let sidebar_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    sidebar_box.append(&search_entry);
    sidebar_box.append(&sidebar_scroll);

    let sidebar_page = adw::NavigationPage::builder()
        .title("Profiles")
        .child(&sidebar_box)
        .build();

    // Paint the initial state.
    {
        let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
        populate_vpn_sidebar(
            &profile_list,
            &s.profiles,
            &s.vpn_state,
            s.selected_profile.as_deref(),
            window,
            rt,
            tx,
            "",
        );
    }

    (profile_list, search_entry, sidebar_page)
}

// ---------------------------------------------------------------------------
// Populate
// ---------------------------------------------------------------------------

/// Rebuild the sidebar profile list from `profiles`.
///
/// Each row contains a trash button that shows an [`adw::AlertDialog`]
/// confirmation before calling `DeleteProfile` on the daemon.
///
/// The row matching the currently active profile receives a connected icon and
/// is selected in the list box so it is visually highlighted.
pub fn populate_vpn_sidebar(
    list_box: &gtk4::ListBox,
    profiles: &[ProfileSummary],
    vpn_state: &VpnState,
    selected_id: Option<&str>,
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
    filter: &str,
) {
    // Clear all children. We must iterate via next_sibling and call
    // list_box.remove() only on GtkListBoxRow children; other widgets
    // (such as popovers parented to rows) are cleaned up automatically
    // when their parent row is removed.
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
    let filtered: Vec<&ProfileSummary> = if filter.is_empty() {
        profiles.iter().collect()
    } else {
        profiles
            .iter()
            .filter(|p| {
                p.name.to_lowercase().contains(&filter_lower)
                    || p.backend.as_str().to_lowercase().contains(&filter_lower)
            })
            .collect()
    };

    if filtered.is_empty() {
        let placeholder = adw::ActionRow::builder()
            .title(if filter.is_empty() {
                "No profiles yet"
            } else {
                "No matching profiles"
            })
            .subtitle(if filter.is_empty() {
                "Use the + button to add one"
            } else {
                "Try a different search term"
            })
            .activatable(false)
            .build();
        list_box.append(&placeholder);
        return;
    }

    let active_id = vpn_state.profile_id().map(|id| id.to_string());

    // Display alphabetically so the list is stable.
    let mut sorted: Vec<&ProfileSummary> = filtered;
    sorted.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    for profile in &sorted {
        let pid = profile.id;
        enum RowState {
            Connected,
            Connecting,
            Error,
            Idle,
        }
        let row_state = match vpn_state {
            VpnState::Connected { profile_id, .. } if *profile_id == pid => RowState::Connected,
            VpnState::Connecting { profile_id, .. } if *profile_id == pid => RowState::Connecting,
            VpnState::Disconnecting { profile_id } if *profile_id == pid => RowState::Connecting,
            VpnState::Error {
                profile_id: Some(epid),
                ..
            } if *epid == pid => RowState::Error,
            _ => RowState::Idle,
        };

        let mut subtitle_parts = vec![profile.backend.as_str().to_owned()];
        if profile.auto_connect {
            subtitle_parts.push("Auto".to_owned());
        }
        // Show connection duration for active profile, last-connected for idle.
        if matches!(row_state, RowState::Connected) {
            if let VpnState::Connected { since, .. } = vpn_state {
                let elapsed = chrono::Utc::now()
                    .signed_duration_since(*since)
                    .num_seconds()
                    .max(0) as u64;
                let h = elapsed / 3600;
                let m = (elapsed % 3600) / 60;
                if h > 0 {
                    subtitle_parts.push(format!("Connected {h}h {m:02}m"));
                } else {
                    subtitle_parts.push(format!("Connected {m}m"));
                }
            }
        } else if matches!(row_state, RowState::Connecting) {
            subtitle_parts.push("Connecting\u{2026}".to_owned());
        } else if let Some(ts) = profile.last_connected_secs {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let elapsed = now.saturating_sub(ts);
            subtitle_parts.push(format!("Last: {}", super::super::format_ago(elapsed)));
        }
        let subtitle = subtitle_parts.join(" \u{b7} ");

        let row = adw::ActionRow::builder()
            .title(profile.name.as_str())
            .subtitle(subtitle.as_str())
            .activatable(true)
            .build();

        match row_state {
            RowState::Connected => {
                row.add_prefix(&gtk4::Image::from_icon_name("network-vpn-symbolic"));
            }
            RowState::Connecting => {
                let spinner = gtk4::Spinner::new();
                spinner.start();
                spinner.set_valign(gtk4::Align::Center);
                row.add_prefix(&spinner);
            }
            RowState::Error => {
                row.add_prefix(&gtk4::Image::from_icon_name("dialog-error-symbolic"));
            }
            RowState::Idle => {
                row.add_prefix(&gtk4::Image::from_icon_name(
                    "network-vpn-disabled-symbolic",
                ));
            }
        }

        // Delete button.
        let delete_btn = gtk4::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text("Delete profile")
            .css_classes(["flat"])
            .valign(gtk4::Align::Center)
            .build();
        row.add_suffix(&delete_btn);

        let profile_id = profile.id.to_string();
        let profile_name = profile.name.clone();
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        {
        let profile_id = profile_id.clone();
        let profile_name = profile_name.clone();
        let window = window.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        delete_btn.connect_clicked(move |_btn| {
            let dialog = adw::AlertDialog::new(
                Some(&format!("Delete \"{}\"?", profile_name)),
                Some("This cannot be undone."),
            );
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("delete", "Delete");
            dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
            dialog.set_default_response(Some("cancel"));
            dialog.set_close_response("cancel");

            let profile_id = profile_id.clone();
            let rt = rt.clone();
            let tx = tx.clone();
            dialog.connect_response(Some("delete"), move |_dlg, _response| {
                let profile_id = profile_id.clone();
                let tx = tx.clone();
                rt.spawn(async move {
                    let msg = match dbus_delete_profile(profile_id.clone()).await {
                        Ok(()) => {
                            info!("deleted profile {}", profile_id);
                            AppMsg::ProfileDeleted(profile_id)
                        }
                        Err(e) => {
                            error!("delete_profile failed: {:#}", e);
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
            let profile_id = profile.id.to_string();
            let profile_name = profile.name.clone();
            let backend = profile.backend.clone();
            let is_connected = matches!(row_state, RowState::Connected);
            let window_ctx = window.clone();
            let rt_ctx = rt.clone();
            let tx_ctx = tx.clone();

            let menu_model = gio::Menu::new();
            if is_connected {
                menu_model.append(Some("Disconnect"), Some("vpn-ctx.disconnect"));
            } else {
                menu_model.append(Some("Connect"), Some("vpn-ctx.connect"));
            }
            menu_model.append(Some("Rename"), Some("vpn-ctx.rename"));
            if backend.starts_with("FortiGate") || backend == "OpenVPN3" {
                menu_model.append(Some("Edit Credentials"), Some("vpn-ctx.edit-creds"));
            }
            menu_model.append(Some("Delete"), Some("vpn-ctx.delete"));

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

            // Connect action.
            {
                let profile_id = profile_id.clone();
                let tx = tx_ctx.clone();
                let rt = rt_ctx.clone();
                let action = gio::SimpleAction::new("connect", None);
                action.connect_activate(move |_, _| {
                    let profile_id = profile_id.clone();
                    let tx = tx.clone();
                    rt.spawn(async move {
                        if let Err(e) = dbus_connect(profile_id).await {
                            tx.send(AppMsg::OperationFailed(format!("Connect failed: {e}"))).ok();
                        }
                    });
                });
                action_group.add_action(&action);
            }

            // Disconnect action.
            {
                let tx = tx_ctx.clone();
                let rt = rt_ctx.clone();
                let action = gio::SimpleAction::new("disconnect", None);
                action.connect_activate(move |_, _| {
                    let tx = tx.clone();
                    rt.spawn(async move {
                        if let Err(e) = dbus_disconnect().await {
                            tx.send(AppMsg::OperationFailed(format!("Disconnect failed: {e}"))).ok();
                        }
                    });
                });
                action_group.add_action(&action);
            }

            // Rename action.
            {
                let profile_id = profile_id.clone();
                let tx = tx_ctx.clone();
                let rt = rt_ctx.clone();
                let window_r = window_ctx.clone();
                let action = gio::SimpleAction::new("rename", None);
                action.connect_activate(move |_, _| {
                    super::dialogs::show_rename_dialog(&window_r, profile_id.clone(), &rt, &tx);
                });
                action_group.add_action(&action);
            }

            // Edit credentials action.
            {
                let profile_id = profile_id.clone();
                let tx = tx_ctx.clone();
                let action = gio::SimpleAction::new("edit-creds", None);
                action.connect_activate(move |_, _| {
                    tx.send(AppMsg::EditVpnProfile(profile_id.clone())).ok();
                });
                action_group.add_action(&action);
            }

            // Delete action.
            {
                let profile_id = profile_id.clone();
                let profile_name = profile_name.clone();
                let window_del = window_ctx.clone();
                let rt = rt_ctx.clone();
                let tx = tx_ctx.clone();
                let action = gio::SimpleAction::new("delete", None);
                action.connect_activate(move |_, _| {
                    let dialog = adw::AlertDialog::new(
                        Some(&format!("Delete \"{}\"?", profile_name)),
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

                    let profile_id = profile_id.clone();
                    let rt = rt.clone();
                    let tx = tx.clone();
                    dialog.connect_response(Some("delete"), move |_dlg, _resp| {
                        let profile_id = profile_id.clone();
                        let tx = tx.clone();
                        rt.spawn(async move {
                            let msg = match dbus_delete_profile(profile_id.clone()).await {
                                Ok(()) => {
                                    info!("deleted profile {}", profile_id);
                                    AppMsg::ProfileDeleted(profile_id)
                                }
                                Err(e) => {
                                    error!("delete_profile failed: {:#}", e);
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

            row.insert_action_group("vpn-ctx", Some(&action_group));

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

    // Highlight the selected profile, falling back to the active one.
    let highlight_id = selected_id.or(active_id.as_deref());
    if let Some(hid) = highlight_id {
        for (i, profile) in sorted.iter().enumerate() {
            if profile.id.to_string() == hid {
                if let Some(row) = list_box.row_at_index(i as i32) {
                    list_box.select_row(Some(&row));
                }
                break;
            }
        }
    }
}
