//! VPN detail panel — the selected profile's status, facts and controls.
//!
//! # What this pane used to be
//!
//! A single centred column: the profile name in `title-1`, the status in
//! `title-2` underneath it, then a stack of flat buttons and three bare
//! switches, each of which had a left-aligned label and a right-aligned
//! switch with the entire width of the window in between. On a 1900px display
//! that put roughly 1500px of nothing between "Connect automatically" and the
//! control that did it, and rendered "Rename…", "Rotate WireGuard Key…",
//! "Export Profile…" and "Duplicate Profile" as four lines of centred text
//! that did not look like anything you could click.
//!
//! The status line was the worst of it. `VpnState::Error` was rendered as
//! `format!("Error: {message}")` into a `title-2` label, so a driver message
//! several sentences long became several lines of large bold type — the most
//! prominent thing on the screen, and unreadable at that size.
//!
//! # What it is now
//!
//! The [`design`] grammar: a header with the name, a status *pill* and the
//! one primary action; a wrapped, normal-sized line for whatever the state
//! has to say at length; and three cards that reflow into as many columns as
//! the window is wide.
//!
//! # Why the state mapping is a separate function
//!
//! [`status_view`] is pure: `VpnState` in, a description of what the pane
//! should say out. It has no widgets in it, so it can be tested — and what
//! wanted testing was precisely the thing that went wrong on screen, which is
//! *where a long error message ends up*.

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::app::AppState;
use crate::ui::design::{self, Status};
use supermgr_core::vpn::state::VpnState;

// ---------------------------------------------------------------------------
// What the pane should say
// ---------------------------------------------------------------------------

/// Everything the detail pane's header shows, derived from the VPN state.
///
/// Split into a short `headline`, which goes in the status pill, and a
/// possibly long `detail`, which does not. That separation is the whole
/// point: a pill has room for one or two words, and an error message is not
/// one or two words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusView {
    /// Which of the shared status colours this is.
    pub status: Status,
    /// The pill's text. Short by construction.
    pub headline: &'static str,
    /// The line under the header. Empty when there is nothing to add.
    pub detail: String,
    /// The primary button's label.
    pub action: &'static str,
    /// Whether the primary button tears something down.
    pub destructive: bool,
    /// Whether the primary button can be pressed.
    pub action_enabled: bool,
    /// Whether there is a live tunnel worth showing statistics for.
    pub show_stats: bool,
}

/// Decide what the detail pane shows for a given state.
///
/// `selected_profile` is the profile the operator is looking at, which is not
/// necessarily the one the daemon is busy with.
#[must_use]
pub fn status_view(vpn: &VpnState, selected_profile: Option<&str>) -> StatusView {
    let active = vpn.profile_id().map(|id| id.to_string());
    let selected_is_active = match (selected_profile, &active) {
        (Some(sel), Some(act)) => sel == act,
        _ => false,
    };
    let have_selection = selected_profile.is_some();

    // Some other profile is occupying the tunnel. The profile on screen is
    // genuinely disconnected; what is worth saying is *why* the button is
    // dead, which is the one thing the old "Another VPN is active" headline
    // left out.
    if !vpn.is_idle() && !selected_is_active {
        return StatusView {
            status: Status::Disconnected,
            headline: "Disconnected",
            detail: "Another profile is using the tunnel. Disconnect it first."
                .to_owned(),
            action: "Connect",
            destructive: false,
            action_enabled: false,
            show_stats: false,
        };
    }

    match vpn {
        VpnState::Connected { .. } => StatusView {
            status: Status::Connected,
            headline: "Connected",
            // Nothing to add: the interface name is a fact about the tunnel
            // and goes in the Tunnel card with the other facts, rather than
            // as a coloured line under the header.
            detail: String::new(),
            action: "Disconnect",
            destructive: true,
            action_enabled: true,
            show_stats: true,
        },
        VpnState::Connecting { phase, .. } => StatusView {
            status: Status::Connecting,
            headline: "Connecting",
            detail: phase.clone(),
            action: "Force Disconnect",
            destructive: true,
            action_enabled: true,
            show_stats: false,
        },
        VpnState::Disconnecting { .. } => StatusView {
            status: Status::Connecting,
            headline: "Disconnecting",
            detail: String::new(),
            action: "Force Disconnect",
            destructive: true,
            action_enabled: true,
            show_stats: false,
        },
        VpnState::Error { message, .. } => StatusView {
            status: Status::Error,
            headline: "Error",
            // The message goes here rather than into the headline. It is
            // often a whole sentence from a VPN driver, and it belongs at
            // body size where it can be read, not in the pill.
            detail: message.clone(),
            action: "Connect",
            destructive: false,
            action_enabled: have_selection,
            show_stats: false,
        },
        VpnState::Disconnected => StatusView {
            status: Status::Disconnected,
            headline: "Disconnected",
            detail: String::new(),
            action: "Connect",
            destructive: false,
            action_enabled: have_selection,
            show_stats: false,
        },
    }
}

/// What the toolbar pill says about the tunnel as a whole.
///
/// A different question from [`status_view`], and the reason the toolbar
/// status used to be ambiguous: that one is about the profile on screen, this
/// one is about the daemon. An operator looking at profile A while profile B
/// is connected has to see B's name up in the toolbar and "Disconnected" down
/// in the pane, and both readings are correct.
///
/// `active_name` is the name of whichever profile the daemon is busy with, if
/// it can still be resolved.
#[must_use]
pub fn toolbar_status(
    vpn: &VpnState,
    active_name: Option<&str>,
    daemon_available: bool,
) -> (Status, String) {
    // With the daemon unreachable, `vpn` is whatever it was when the last
    // reply arrived. Rendering that as fact is how a pill ends up claiming
    // "No VPN" during an outage that may well have left a tunnel up. The
    // honest reading is: this is stale, and we cannot ask.
    if !daemon_available {
        return (Status::Degraded, "Daemon unreachable".to_owned());
    }

    match vpn {
        // The name alone, because the dot beside it already says "connected"
        // and the tooltip spells it out. "Connected to X" in a pill is mostly
        // the word "connected".
        VpnState::Connected { .. } => (
            Status::Connected,
            active_name.unwrap_or("Connected").to_owned(),
        ),
        VpnState::Connecting { .. } => (Status::Connecting, "Connecting\u{2026}".to_owned()),
        VpnState::Disconnecting { .. } => {
            (Status::Connecting, "Disconnecting\u{2026}".to_owned())
        }
        VpnState::Error { .. } => (Status::Error, "VPN error".to_owned()),
        VpnState::Disconnected => (Status::Disconnected, "No VPN".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Widget bundle
// ---------------------------------------------------------------------------

/// The widgets [`apply_vpn_state`] writes to.
///
/// Bundled and `Clone` because the state arrives from several places — the
/// sidebar, the D-Bus signal handler, the initial paint — and each of them
/// needs its own handle.
#[derive(Clone)]
pub struct VpnStatusWidgets {
    /// The primary action.
    pub connect_btn: gtk4::Button,
    /// Enabled whenever a profile is selected.
    pub rename_btn: gtk4::Button,
    /// Holds the status pill; its child is replaced on every change.
    pub status_slot: adw::Bin,
    /// The wrapped line under the header, for anything too long for the pill.
    pub status_detail: gtk4::Label,
    /// The kernel interface the tunnel is running on, once there is one.
    pub stats_interface: gtk4::Label,
    /// The statistics card, shown only while a tunnel is up.
    pub stats_box: gtk4::Box,
    /// The toolbar pill, which reports the daemon's state rather than the
    /// selected profile's. Wired up once the shell exists.
    pub toolbar_slot: adw::Bin,
}

/// All the widgets in the VPN detail panel that need to be updated when
/// state changes.  Created once by [`build_vpn_detail`] and kept alive in
/// the main `build_ui` scope.
pub struct VpnDetail {
    /// The outer stack that switches between "empty" and "detail".
    pub detail_stack: gtk4::Stack,

    /// The status widgets, as one clonable bundle.
    pub status: VpnStatusWidgets,

    // Detail-view widgets.
    pub profile_name_label: gtk4::Label,
    pub connect_btn: gtk4::Button,
    pub rename_btn: gtk4::Button,
    pub edit_creds_btn: gtk4::Button,
    pub auto_connect_switch: gtk4::Switch,
    pub full_tunnel_row: adw::ActionRow,
    pub full_tunnel_switch: gtk4::Switch,
    pub kill_switch_switch: gtk4::Switch,
    pub rotate_key_btn: gtk4::Button,
    pub export_btn: gtk4::Button,
    pub duplicate_btn: gtk4::Button,
    pub split_routes_row: adw::ActionRow,
    pub split_routes_value: gtk4::Label,
    pub split_routes_edit_btn: gtk4::Button,

    // Stats card widgets. The card itself lives in `status`, which is what
    // shows and hides it.
    pub stats_sent: gtk4::Label,
    pub stats_recv: gtk4::Label,
    pub stats_uptime: gtk4::Label,
    pub stats_handshake: gtk4::Label,
    pub stats_virtual_ip: gtk4::Label,
    pub stats_routes: gtk4::Label,
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Add one row to the statistics card and hand back the label to update.
fn stat_row(card: &adw::PreferencesGroup, title: &str, monospace: bool) -> gtk4::Label {
    let (row, value) = design::live_detail_row(title, monospace);
    card.add(&row);
    value
}

/// Build the VPN detail panel and return the bundle of widgets plus an
/// [`adw::NavigationPage`] ready to be placed into a split view.
#[must_use]
pub fn build_vpn_detail() -> (VpnDetail, adw::NavigationPage) {
    let detail_stack = gtk4::Stack::new();

    // --- Empty state --------------------------------------------------------
    //
    // The brief's complaint about the old one was that it was generic. "No
    // profile selected" tells an operator what they already know; naming the
    // next action does not.
    let empty_status = design::empty_state(
        design::icon_name(design::icons::VPN),
        "No profile selected",
        "Pick a profile from the list to see its status, or use + to add one.",
    );
    detail_stack.add_named(&empty_status, Some("empty"));

    // --- Header -------------------------------------------------------------

    let header = design::DetailHeader::new();
    let profile_name_label = header.title.clone();

    let connect_btn = gtk4::Button::builder()
        .label("Connect")
        .css_classes(["suggested-action", "pill"])
        .width_request(160)
        .sensitive(false)
        .build();
    header.actions.append(&connect_btn);

    // A driver message is a paragraph, not a line, and it has to stay
    // readable at any window width. Wrapping is what makes that work: the
    // label fills the pane and breaks where it runs out, and — because a
    // wrapping label's *minimum* width is only its longest word — the window
    // can still be made narrow without the pane demanding to be wider than
    // the screen. The scroller above has no horizontal bar to fall back on,
    // so that part matters.
    let status_detail = gtk4::Label::builder()
        .label("")
        .xalign(0.0)
        .wrap(true)
        .wrap_mode(gtk4::pango::WrapMode::WordChar)
        .selectable(true)
        .visible(false)
        .margin_bottom(18)
        .css_classes(["dim-label"])
        .build();

    // --- Tunnel card --------------------------------------------------------
    //
    // Every live fact about the connection, as a definition list. All of it
    // is meaningless without a tunnel, so the whole card comes and goes as
    // one.
    let stats_card = design::card("Tunnel");
    let stats_interface = stat_row(&stats_card, "Interface", true);
    let stats_virtual_ip = stat_row(&stats_card, "VPN IP", true);
    let stats_routes = stat_row(&stats_card, "Routes", true);
    let stats_sent = stat_row(&stats_card, "Sent", false);
    let stats_recv = stat_row(&stats_card, "Received", false);
    let stats_uptime = stat_row(&stats_card, "Uptime", false);
    let stats_handshake = stat_row(&stats_card, "Last handshake", false);
    stats_virtual_ip.set_visible(false);
    stats_routes.set_visible(false);
    stats_uptime.set_visible(false);
    stats_routes.set_wrap(true);
    stats_routes.set_max_width_chars(24);

    let stats_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .visible(false)
        .build();
    stats_box.append(&stats_card);

    // --- Settings card ------------------------------------------------------
    //
    // Every one of these was a bare switch at the far edge of the window with
    // a label at the other edge and no explanation of what it did.

    let settings_card = design::card("Settings");

    let auto_connect_switch = gtk4::Switch::builder().active(false).sensitive(false).build();
    settings_card.add(&design::toggle_row(
        &auto_connect_switch,
        "Connect automatically",
        "Bring this tunnel up when SuperManager starts",
    ));

    let full_tunnel_switch = gtk4::Switch::builder().active(true).sensitive(false).build();
    let full_tunnel_row = design::toggle_row(
        &full_tunnel_switch,
        "Route all traffic",
        "Everything goes through the tunnel, not just the routes below",
    );
    settings_card.add(&full_tunnel_row);

    let kill_switch_switch = gtk4::Switch::builder().active(false).sensitive(false).build();
    settings_card.add(&design::toggle_row(
        &kill_switch_switch,
        "Kill switch",
        "Block all traffic if the tunnel drops",
    ));

    // Split routes: a value that can be a long list of CIDRs, plus its own
    // editor. Built by hand rather than with `button_row` because the value
    // and the button share the row's trailing edge.
    let split_routes_row = adw::ActionRow::new();
    split_routes_row.set_title("Split-tunnel routes");
    split_routes_row.set_visible(false);
    let split_routes_value = gtk4::Label::builder()
        .label("None configured")
        .xalign(1.0)
        .wrap(true)
        .max_width_chars(22)
        .valign(gtk4::Align::Center)
        .css_classes(["dim-label", "caption"])
        .build();
    let split_routes_edit_btn = gtk4::Button::builder()
        .icon_name("document-edit-symbolic")
        .tooltip_text("Edit split-tunnel routes")
        .css_classes(["flat"])
        .valign(gtk4::Align::Center)
        .build();
    split_routes_row.add_suffix(&split_routes_value);
    split_routes_row.add_suffix(&split_routes_edit_btn);
    split_routes_row.set_activatable_widget(Some(&split_routes_edit_btn));
    settings_card.add(&split_routes_row);

    // --- Profile card -------------------------------------------------------
    //
    // The four flat centred buttons, now rows that look like things you can
    // press. The buttons themselves survive because `mod.rs` connects its
    // handlers to them; `design::button_row` binds each row's sensitivity and
    // visibility to its button's, so every existing call still means what it
    // meant.

    let profile_card = design::card("Profile");

    let rename_btn = gtk4::Button::builder().sensitive(false).build();
    profile_card.add(&design::button_row(
        &rename_btn,
        "Rename\u{2026}",
        "Change how this profile is listed",
        "document-edit-symbolic",
    ));

    let edit_creds_btn = gtk4::Button::builder().visible(false).build();
    profile_card.add(&design::button_row(
        &edit_creds_btn,
        "Edit credentials\u{2026}",
        "Username, password and certificates",
        design::icon_name(design::icons::KEY),
    ));

    let rotate_key_btn = gtk4::Button::builder().visible(false).build();
    profile_card.add(&design::button_row(
        &rotate_key_btn,
        "Rotate WireGuard key\u{2026}",
        "Generate a new keypair; the peer must be updated too",
        "view-refresh-symbolic",
    ));

    let export_btn = gtk4::Button::builder().sensitive(false).build();
    profile_card.add(&design::button_row(
        &export_btn,
        "Export profile\u{2026}",
        "Write the configuration to a file",
        "document-save-symbolic",
    ));

    let duplicate_btn = gtk4::Button::builder().sensitive(false).build();
    profile_card.add(&design::button_row(
        &duplicate_btn,
        "Duplicate profile",
        "Copy everything except the secrets",
        "edit-copy-symbolic",
    ));

    // --- Assemble -----------------------------------------------------------

    let (scroller, content) = design::detail_body();
    content.append(&header.widget);
    content.append(&status_detail);

    let columns = design::reflowing_columns();
    design::add_card(&columns, &stats_box);
    design::add_card(&columns, &settings_card);
    design::add_card(&columns, &profile_card);
    content.append(&columns);

    detail_stack.add_named(&scroller, Some("detail"));
    detail_stack.set_visible_child_name("empty");

    let content_page = adw::NavigationPage::builder()
        .title("Connection")
        .child(&detail_stack)
        .build();

    let status = VpnStatusWidgets {
        connect_btn: connect_btn.clone(),
        rename_btn: rename_btn.clone(),
        status_slot: header.status_slot.clone(),
        status_detail,
        stats_interface,
        stats_box,
        toolbar_slot: adw::Bin::new(),
    };

    let detail = VpnDetail {
        detail_stack,
        status,
        profile_name_label,
        connect_btn,
        rename_btn,
        edit_creds_btn,
        auto_connect_switch,
        full_tunnel_row,
        full_tunnel_switch,
        kill_switch_switch,
        rotate_key_btn,
        export_btn,
        duplicate_btn,
        split_routes_row,
        split_routes_value,
        split_routes_edit_btn,
        stats_sent,
        stats_recv,
        stats_uptime,
        stats_handshake,
        stats_virtual_ip,
        stats_routes,
    };

    (detail, content_page)
}

// ---------------------------------------------------------------------------
// State display
// ---------------------------------------------------------------------------

/// Paint [`status_view`]'s decision onto the widgets.
///
/// Everything that could be decided without a display already was, in
/// `status_view`. What is left here is only the assignment.
pub fn apply_vpn_state(w: &VpnStatusWidgets, state: &AppState) {
    let active_name = state.vpn_state.profile_id().and_then(|id| {
        state.profiles.iter().find(|p| p.id == id).map(|p| p.name.as_str())
    });
    let (toolbar, toolbar_label) =
        toolbar_status(&state.vpn_state, active_name, state.daemon_available);
    design::set_pill(&w.toolbar_slot, toolbar, &toolbar_label);

    let view = status_view(&state.vpn_state, state.selected_profile.as_deref());

    design::set_pill(&w.status_slot, view.status, view.headline);

    w.status_detail.set_visible(!view.detail.is_empty());
    w.status_detail.set_label(&view.detail);
    // The long line is coloured like the pill it belongs to, so an error
    // reads as an error without being set in headline type.
    for class in ["success", "warning", "error", "accent", "dim-label"] {
        w.status_detail.remove_css_class(class);
    }
    w.status_detail.add_css_class(view.status.style_class());

    w.connect_btn.set_label(view.action);
    w.connect_btn.remove_css_class("suggested-action");
    w.connect_btn.remove_css_class("destructive-action");
    w.connect_btn.add_css_class(if view.destructive {
        "destructive-action"
    } else {
        "suggested-action"
    });
    w.connect_btn.set_sensitive(view.action_enabled);

    match &state.vpn_state {
        VpnState::Connected { interface, .. } => w.stats_interface.set_label(interface),
        _ => w.stats_interface.set_label("\u{2014}"),
    }
    w.stats_box.set_visible(view.show_stats);
    w.rename_btn.set_sensitive(state.selected_profile.is_some());
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use supermgr_core::vpn::state::ErrorCode;
    use uuid::Uuid;

    fn connected(id: Uuid) -> VpnState {
        VpnState::Connected { profile_id: id, since: Utc::now(), interface: "wg0".into() }
    }

    fn error(id: Option<Uuid>, message: &str) -> VpnState {
        VpnState::Error {
            profile_id: id,
            code: ErrorCode::Internal,
            message: message.to_owned(),
        }
    }

    #[test]
    fn a_long_error_message_never_reaches_the_pill() {
        // This is the defect the screenshot showed: the message was rendered
        // into a `title-2` label, so several sentences of driver output
        // became the largest thing on the screen. The pill's text is a
        // `&'static str` chosen from a fixed set, so the message physically
        // cannot land there — but the message must still be *somewhere*, or
        // the fix would be a regression.
        let message = "interface error: WireGuard kernel module not loaded or not \
                       available: ensure CONFIG_WIREGUARD is enabled in your kernel \
                       — Operation not supported (os error 95)";
        let view = status_view(&error(None, message), Some("p"));

        assert_eq!(view.headline, "Error");
        assert!(view.headline.len() < 16, "the pill's text has to fit in a pill");
        assert_eq!(view.detail, message, "the message was dropped instead of moved");
        assert_eq!(view.status, Status::Error);
    }

    #[test]
    fn every_state_says_something() {
        // A blank pill is worse than a wrong one: it looks like a rendering
        // fault rather than a state.
        let id = Uuid::new_v4();
        for state in [
            VpnState::Disconnected,
            VpnState::Connecting { profile_id: id, since: Utc::now(), phase: String::new() },
            connected(id),
            VpnState::Disconnecting { profile_id: id },
            error(Some(id), "boom"),
        ] {
            let view = status_view(&state, Some(&id.to_string()));
            assert!(!view.headline.is_empty(), "{state:?} has no headline");
            assert!(!view.action.is_empty(), "{state:?} has no button label");
        }
    }

    #[test]
    fn a_second_tunnel_cannot_be_started_while_one_is_up() {
        // The daemon runs one tunnel. Offering a live Connect button for a
        // profile that cannot be connected is the interface lying.
        let other = Uuid::new_v4();
        let view = status_view(&connected(other), Some(&Uuid::new_v4().to_string()));

        assert!(!view.action_enabled);
        assert_eq!(view.status, Status::Disconnected, "*this* profile is not connected");
        assert!(
            view.detail.contains("Another profile"),
            "a dead button with no explanation reads as a bug: {:?}",
            view.detail
        );
    }

    #[test]
    fn the_profile_on_screen_being_the_active_one_is_not_another_tunnel() {
        // The mirror image of the test above, and the one that catches an
        // inverted comparison: when the selected profile *is* the connected
        // one, the pane must show a connected tunnel, not a blocked one.
        let id = Uuid::new_v4();
        let view = status_view(&connected(id), Some(&id.to_string()));

        assert_eq!(view.status, Status::Connected);
        assert_eq!(view.action, "Disconnect");
        assert!(view.action_enabled);
        assert!(view.show_stats);
    }

    #[test]
    fn statistics_are_offered_only_when_there_is_a_tunnel_to_measure() {
        let id = Uuid::new_v4();
        let sel = id.to_string();
        assert!(status_view(&connected(id), Some(&sel)).show_stats);
        for state in [
            VpnState::Disconnected,
            VpnState::Connecting { profile_id: id, since: Utc::now(), phase: "IKE".into() },
            VpnState::Disconnecting { profile_id: id },
            error(Some(id), "boom"),
        ] {
            assert!(
                !status_view(&state, Some(&sel)).show_stats,
                "{state:?} would show stale byte counters"
            );
        }
    }

    #[test]
    fn the_button_is_destructive_exactly_when_it_tears_something_down() {
        // Red means "this stops the tunnel". If Connect were ever red, or
        // Disconnect ever green, the colour would stop carrying meaning.
        let id = Uuid::new_v4();
        let sel = id.to_string();
        for state in [
            connected(id),
            VpnState::Connecting { profile_id: id, since: Utc::now(), phase: "IKE".into() },
            VpnState::Disconnecting { profile_id: id },
        ] {
            let view = status_view(&state, Some(&sel));
            assert!(view.destructive, "{state:?} offers a non-destructive-looking teardown");
            assert!(view.action.contains("Disconnect"), "{:?}", view.action);
        }
        for state in [VpnState::Disconnected, error(Some(id), "boom")] {
            let view = status_view(&state, Some(&sel));
            assert!(!view.destructive, "{state:?} paints Connect as destructive");
            assert_eq!(view.action, "Connect");
        }
    }

    #[test]
    fn the_toolbar_names_the_tunnel_the_daemon_is_actually_running() {
        // The pane and the toolbar answer different questions, and the
        // toolbar's answer is the one that must not depend on what happens to
        // be selected in the sidebar.
        let (status, label) = toolbar_status(&connected(Uuid::new_v4()), Some("Sybr HQ"), true);
        assert_eq!(status, Status::Connected);
        assert_eq!(label, "Sybr HQ");

        // A profile connected and then deleted leaves a state referring to an
        // id nothing resolves. Better a generic word than a blank pill.
        let (_, label) = toolbar_status(&connected(Uuid::new_v4()), None, true);
        assert_eq!(label, "Connected");
    }

    #[test]
    fn an_unreachable_daemon_is_not_reported_as_no_vpn() {
        // Without the daemon, `vpn_state` is the last thing it said before it
        // went away — which may well have been a live tunnel. Rendering it as
        // current fact is the interface making something up.
        for state in [VpnState::Disconnected, connected(Uuid::new_v4())] {
            let (status, label) = toolbar_status(&state, Some("Sybr HQ"), false);
            assert_eq!(status, Status::Degraded, "stale state passed off as fact");
            assert!(label.contains("Daemon"), "{label}");
        }
    }

    #[test]
    fn nothing_is_connectable_without_a_profile_to_connect() {
        for state in [VpnState::Disconnected, error(None, "boom")] {
            assert!(
                !status_view(&state, None).action_enabled,
                "{state:?} offers Connect with nothing selected"
            );
        }
    }
}
