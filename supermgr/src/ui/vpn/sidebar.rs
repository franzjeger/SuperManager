//! VPN profile list sidebar widget.
//!
//! Builds a [`gtk4::ListBox`] where each row is an [`adw::ActionRow`] displaying
//! the profile name, backend type, and a delete button. The list is rebuilt
//! from scratch via [`populate_vpn_sidebar`] whenever the profile list changes.
//!
//! # Undifferentiated rows
//!
//! The redesign brief lists *"undifferentiated list rows"* among the things
//! wrong with the old interface, and this list was the clearest example:
//! every row carried the same subtitle shape — backend, then maybe "Auto",
//! then a timestamp, all dot-separated — so a connected tunnel, a failed one
//! and one that had never been tried looked the same at a glance, separated
//! only by a small monochrome prefix icon.
//!
//! Now the backend shares the secondary line with timing metadata, while the
//! state is a coloured pill that appears **only on rows worth looking at**
//! ([`Status::is_notable`], plus connected). Keeping the backend out of the
//! suffix area is important: a long backend name, status pill and delete
//! button otherwise leave the title no width and make GTK wrap it one letter
//! per line.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::{gio, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use supermgr_core::vpn::{profile::ProfileSummary, state::VpnState};

use crate::app::{AppMsg, AppState};
use crate::dbus_client::{dbus_connect, dbus_delete_profile, dbus_disconnect};
use crate::ui::design::{self, Status};

// ---------------------------------------------------------------------------
// What a row says
// ---------------------------------------------------------------------------

/// One sidebar row's content, decided without reference to any widget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowView {
    /// Which of the shared states this profile is in.
    pub status: Status,
    /// The secondary line: how long, how recently, and whether automatic.
    pub meta: String,
    /// Whether this row is worth marking with a pill.
    pub show_pill: bool,
}

/// Decide what a sidebar row says.
///
/// `now_secs` is Unix time, passed in rather than read, so that a row's text
/// is a function of its inputs and can be checked.
#[must_use]
pub fn row_view(profile: &ProfileSummary, vpn: &VpnState, now_secs: u64) -> RowView {
    let id = profile.id;
    let (status, timing) = match vpn {
        VpnState::Connected { profile_id, since, .. } if *profile_id == id => {
            // A clock that has gone backwards — or a `since` from the
            // future after an NTP step — must not produce a nonsense
            // duration, so the difference is clamped rather than wrapped.
            let now = i64::try_from(now_secs).unwrap_or(i64::MAX);
            let elapsed = u64::try_from(now.saturating_sub(since.timestamp())).unwrap_or(0);
            let (h, m) = (elapsed / 3600, (elapsed % 3600) / 60);
            let text = if h > 0 {
                format!("Up {h}h {m:02}m")
            } else {
                format!("Up {m}m")
            };
            (Status::Connected, text)
        }
        VpnState::Connecting { profile_id, phase, .. } if *profile_id == id => {
            let phase = phase.trim();
            let text =
                if phase.is_empty() { String::new() } else { phase.to_owned() };
            (Status::Connecting, text)
        }
        VpnState::Disconnecting { profile_id } if *profile_id == id => {
            (Status::Connecting, "Disconnecting\u{2026}".to_owned())
        }
        VpnState::Error { profile_id: Some(failed), .. } if *failed == id => {
            (Status::Error, last_connected(profile, now_secs))
        }
        // Everything else — including a tunnel or a failure belonging to some
        // *other* profile — leaves this row idle. A profile that has never
        // been connected is `Unknown` rather than `Disconnected`: nothing has
        // been tried, so nothing is known, and "Disconnected" would imply it
        // had been up at some point.
        _ if profile.last_connected_secs.is_none() => {
            (Status::Unknown, "Never connected".to_owned())
        }
        _ => (Status::Disconnected, last_connected(profile, now_secs)),
    };

    let mut parts = Vec::new();
    if !timing.is_empty() {
        parts.push(timing);
    }
    if profile.auto_connect {
        parts.push("Auto".to_owned());
    }

    RowView {
        status,
        meta: parts.join(" \u{b7} "),
        // A pill on every row is wallpaper. These are the rows an operator
        // scans a list to find.
        show_pill: status.is_notable() || status == Status::Connected,
    }
}

fn last_connected(profile: &ProfileSummary, now_secs: u64) -> String {
    match profile.last_connected_secs {
        Some(ts) => format!("Last {}", crate::ui::format_ago(now_secs.saturating_sub(ts))),
        None => "Never connected".to_owned(),
    }
}

fn row_subtitle(backend: &str, meta: &str) -> String {
    if meta.is_empty() {
        backend.to_owned()
    } else {
        format!("{backend} \u{b7} {meta}")
    }
}

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

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for profile in &sorted {
        let view = row_view(profile, vpn_state, now_secs);
        let subtitle = row_subtitle(profile.backend.as_str(), &view.meta);

        let row = adw::ActionRow::builder()
            .title(profile.name.as_str())
            .title_lines(1)
            .subtitle(subtitle)
            .subtitle_lines(1)
            .activatable(true)
            .build();

        // A spinner where something is genuinely in progress, and a static
        // icon otherwise. The spinner is the one case where movement is the
        // honest rendering — it says "still going" without a timer.
        if view.status == Status::Connecting {
            let spinner = gtk4::Spinner::new();
            spinner.start();
            spinner.set_valign(gtk4::Align::Center);
            row.add_prefix(&spinner);
        } else {
            let icon = design::icon(if view.status == Status::Connected {
                design::icons::VPN
            } else {
                design::icons::VPN_OFF
            });
            icon.add_css_class(view.status.style_class());
            row.add_prefix(&icon);
        }

        if view.show_pill {
            row.add_suffix(&design::status_pill(view.status, view.status.label()));
        }

        // All secondary actions live in one discoverable menu. Keeping a
        // permanent trash button on every row made deletion visually equal
        // to selection and consumed scarce title width.
        {
            let profile_id = profile.id.to_string();
            let profile_name = profile.name.clone();
            let backend = profile.backend.clone();
            let is_connected = view.status == Status::Connected;
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

            let menu_btn = gtk4::MenuButton::builder()
                .icon_name("view-more-symbolic")
                .tooltip_text("Profile actions")
                .css_classes(["flat"])
                .valign(gtk4::Align::Center)
                .build();
            menu_btn.set_popover(Some(&popover));
            row.add_suffix(&menu_btn);

            // Preserve the existing right-click shortcut, pointing the same
            // menu at the pointer rather than maintaining a second menu.
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use supermgr_core::vpn::state::ErrorCode;
    use uuid::Uuid;

    const NOW: u64 = 1_700_000_000;
    const NOW_I64: i64 = 1_700_000_000;

    fn profile(id: Uuid) -> ProfileSummary {
        ProfileSummary {
            id,
            name: "Sybr HQ".into(),
            backend: "WireGuard".into(),
            auto_connect: false,
            full_tunnel: true,
            split_routes: Vec::new(),
            last_connected_secs: None,
            host: None,
            username: None,
            dns_servers: Vec::new(),
            kill_switch: false,
            customer: String::new(),
        }
    }

    fn connected(id: Uuid, seconds_ago: i64) -> VpnState {
        VpnState::Connected {
            profile_id: id,
            since: Utc
                .timestamp_opt(NOW_I64 - seconds_ago, 0)
                .single()
                .expect("a valid timestamp"),
            interface: "wg0".into(),
        }
    }

    #[test]
    fn a_profile_that_has_never_been_tried_is_unknown_not_disconnected() {
        // "Disconnected" claims a history the profile does not have. The
        // difference matters when an operator is looking for the one profile
        // in the list that has never worked.
        let p = profile(Uuid::new_v4());
        let view = row_view(&p, &VpnState::Disconnected, NOW);

        assert_eq!(view.status, Status::Unknown);
        assert_eq!(view.meta, "Never connected");
    }

    #[test]
    fn a_profile_with_a_history_is_disconnected_and_says_when() {
        let mut p = profile(Uuid::new_v4());
        p.last_connected_secs = Some(NOW - 7200);
        let view = row_view(&p, &VpnState::Disconnected, NOW);

        assert_eq!(view.status, Status::Disconnected);
        assert!(view.meta.starts_with("Last "), "{}", view.meta);
    }

    #[test]
    fn only_the_rows_worth_finding_are_marked() {
        // The whole point of the pill. If every row carries one, the list is
        // decorated rather than informative — which is what the brief means
        // by undifferentiated rows.
        let id = Uuid::new_v4();
        let mut p = profile(id);
        p.last_connected_secs = Some(NOW - 60);

        assert!(row_view(&p, &connected(id, 60), NOW).show_pill);
        assert!(row_view(
            &p,
            &VpnState::Error {
                profile_id: Some(id),
                code: ErrorCode::Internal,
                message: "boom".into()
            },
            NOW
        )
        .show_pill);
        assert!(row_view(&p, &VpnState::Disconnecting { profile_id: id }, NOW).show_pill);

        assert!(!row_view(&p, &VpnState::Disconnected, NOW).show_pill);
        assert!(!row_view(&profile(id), &VpnState::Disconnected, NOW).show_pill);
    }

    #[test]
    fn another_profiles_tunnel_does_not_colour_this_row() {
        // Every arm of the match is guarded on the profile id. Drop one of
        // those guards and the whole list lights up green whenever anything
        // is connected.
        let mine = Uuid::new_v4();
        let theirs = Uuid::new_v4();
        let mut p = profile(mine);
        p.last_connected_secs = Some(NOW - 300);

        for state in [
            connected(theirs, 300),
            VpnState::Connecting {
                profile_id: theirs,
                since: Utc.timestamp_opt(NOW_I64, 0).single().expect("valid"),
                phase: "handshake".into(),
            },
            VpnState::Disconnecting { profile_id: theirs },
            VpnState::Error {
                profile_id: Some(theirs),
                code: ErrorCode::Internal,
                message: "boom".into(),
            },
        ] {
            let view = row_view(&p, &state, NOW);
            assert_eq!(view.status, Status::Disconnected, "leaked from {state:?}");
            assert!(!view.show_pill, "leaked from {state:?}");
        }
    }

    #[test]
    fn the_connected_row_says_how_long_it_has_been_up() {
        let id = Uuid::new_v4();
        let p = profile(id);

        assert_eq!(row_view(&p, &connected(id, 90 * 60), NOW).meta, "Up 1h 30m");
        assert_eq!(row_view(&p, &connected(id, 5 * 60), NOW).meta, "Up 5m");
        // A clock that has gone backwards must not produce a nonsense
        // duration or a panic.
        assert_eq!(row_view(&p, &connected(id, -60), NOW).meta, "Up 0m");
    }

    #[test]
    fn auto_connect_is_mentioned_whatever_the_state() {
        // It is a property of the profile, not of the connection, so no state
        // may swallow it.
        let id = Uuid::new_v4();
        let mut p = profile(id);
        p.auto_connect = true;
        p.last_connected_secs = Some(NOW - 60);

        for state in [
            VpnState::Disconnected,
            connected(id, 60),
            VpnState::Disconnecting { profile_id: id },
            VpnState::Error {
                profile_id: Some(id),
                code: ErrorCode::Internal,
                message: "boom".into(),
            },
        ] {
            assert!(
                row_view(&p, &state, NOW).meta.contains("Auto"),
                "auto-connect vanished in {state:?}"
            );
        }
    }

    #[test]
    fn a_connecting_row_shows_the_phase_and_never_a_stray_separator() {
        // The phase is the only thing that distinguishes one moment of a slow
        // connection from the next. An empty one must not leave "· Auto"
        // dangling off the front of the line.
        let id = Uuid::new_v4();
        let since = Utc.timestamp_opt(NOW_I64, 0).single().expect("valid");
        let mut p = profile(id);
        p.auto_connect = true;

        let with_phase = VpnState::Connecting {
            profile_id: id,
            since,
            phase: "IKE_SA_INIT".into(),
        };
        assert_eq!(row_view(&p, &with_phase, NOW).meta, "IKE_SA_INIT \u{b7} Auto");

        let no_phase =
            VpnState::Connecting { profile_id: id, since, phase: "  ".into() };
        assert_eq!(row_view(&p, &no_phase, NOW).meta, "Auto");
    }

    #[test]
    fn backend_and_timing_share_one_compact_secondary_line() {
        assert_eq!(
            row_subtitle("FortiGate (IPsec/IKEv2)", "Never connected"),
            "FortiGate (IPsec/IKEv2) \u{b7} Never connected"
        );
        assert_eq!(row_subtitle("WireGuard", ""), "WireGuard");
    }
}
