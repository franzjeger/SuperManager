//! VPN profile list sidebar widget.
//!
//! Builds a [`gtk4::ListBox`] where each row is an [`adw::ActionRow`] displaying
//! the profile name, backend type, and a delete button.  The list is rebuilt
//! from scratch via [`populate_vpn_sidebar`] whenever the profile list changes.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use supermgr_core::vpn::{profile::ProfileSummary, state::VpnState};

use crate::app::{AppMsg, AppState};
use crate::dbus_client::dbus_delete_profile;

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build the VPN sidebar widgets.
///
/// Returns the [`gtk4::ListBox`] that holds profile rows and the enclosing
/// [`adw::NavigationPage`] ready to be placed in a split view.
pub fn build_vpn_sidebar(
    app_state: &Arc<Mutex<AppState>>,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
    window: &adw::ApplicationWindow,
) -> (gtk4::ListBox, adw::NavigationPage) {
    let profile_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(["navigation-sidebar"])
        .build();

    let sidebar_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&profile_list)
        .build();

    let sidebar_page = adw::NavigationPage::builder()
        .title("Profiles")
        .child(&sidebar_scroll)
        .build();

    // Paint the initial state.
    {
        let s = app_state.lock().expect("lock");
        populate_vpn_sidebar(
            &profile_list,
            &s.profiles,
            &s.vpn_state,
            s.selected_profile.as_deref(),
            window,
            rt,
            tx,
        );
    }

    (profile_list, sidebar_page)
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
) {
    // Clear all children.
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    if profiles.is_empty() {
        let placeholder = adw::ActionRow::builder()
            .title("No profiles yet")
            .subtitle("Use the + button to add one")
            .activatable(false)
            .build();
        list_box.append(&placeholder);
        return;
    }

    let active_id = vpn_state.profile_id().map(|id| id.to_string());

    // Display alphabetically so the list is stable.
    let mut sorted: Vec<&ProfileSummary> = profiles.iter().collect();
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
        if let Some(ts) = profile.last_connected_secs {
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
