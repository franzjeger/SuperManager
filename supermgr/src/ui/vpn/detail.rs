//! VPN detail panel — shows selected profile status, stats, and controls.

use gtk4::prelude::*;
use libadwaita as adw;

use crate::app::AppState;
use supermgr_core::vpn::state::VpnState;

// ---------------------------------------------------------------------------
// Widget bundle
// ---------------------------------------------------------------------------

/// All the widgets in the VPN detail panel that need to be updated when
/// state changes.  Created once by [`build_vpn_detail`] and kept alive in
/// the main `build_ui` scope.
pub struct VpnDetail {
    /// The outer stack that switches between "empty" and "detail".
    pub detail_stack: gtk4::Stack,

    // Detail-view widgets.
    pub profile_name_label: gtk4::Label,
    pub status_label: gtk4::Label,
    pub connect_btn: gtk4::Button,
    pub rename_btn: gtk4::Button,
    pub edit_creds_btn: gtk4::Button,
    pub auto_connect_switch: gtk4::Switch,
    pub full_tunnel_row: gtk4::Box,
    pub full_tunnel_switch: gtk4::Switch,
    pub kill_switch_switch: gtk4::Switch,
    pub rotate_key_btn: gtk4::Button,
    pub export_btn: gtk4::Button,
    pub duplicate_btn: gtk4::Button,
    pub split_routes_row: gtk4::Box,
    pub split_routes_value: gtk4::Label,
    pub split_routes_edit_btn: gtk4::Button,

    // Stats card widgets.
    pub stats_box: gtk4::Box,
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

/// Build the VPN detail panel and return the bundle of widgets plus an
/// [`adw::NavigationPage`] ready to be placed into a split view.
pub fn build_vpn_detail() -> (VpnDetail, adw::NavigationPage) {
    let detail_stack = gtk4::Stack::new();

    // --- Empty state --------------------------------------------------------
    let empty_status = adw::StatusPage::builder()
        .title("No Profile Selected")
        .description("Select a profile from the sidebar, or use the + button to add one.")
        .icon_name("network-vpn-symbolic")
        .build();
    detail_stack.add_named(&empty_status, Some("empty"));

    // --- Detail view --------------------------------------------------------
    let profile_name_label = gtk4::Label::builder()
        .label("")
        .css_classes(["title-1"])
        .halign(gtk4::Align::Center)
        .wrap(true)
        .build();

    let status_label = gtk4::Label::builder()
        .label("Disconnected")
        .css_classes(["title-2"])
        .halign(gtk4::Align::Center)
        .build();

    let connect_btn = gtk4::Button::builder()
        .label("Connect")
        .css_classes(["suggested-action", "pill"])
        .halign(gtk4::Align::Center)
        .width_request(200)
        .sensitive(false)
        .build();

    let rename_btn = gtk4::Button::builder()
        .label("Rename\u{2026}")
        .css_classes(["flat"])
        .halign(gtk4::Align::Center)
        .sensitive(false)
        .build();

    let edit_creds_btn = gtk4::Button::builder()
        .label("Edit Credentials")
        .css_classes(["flat"])
        .visible(false)
        .build();

    // Auto-connect toggle row.
    let auto_connect_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .margin_top(4)
        .build();
    let auto_connect_label = gtk4::Label::builder()
        .label("Connect automatically")
        .hexpand(true)
        .halign(gtk4::Align::Start)
        .build();
    let auto_connect_switch = gtk4::Switch::builder()
        .active(false)
        .sensitive(false)
        .valign(gtk4::Align::Center)
        .build();
    auto_connect_row.append(&auto_connect_label);
    auto_connect_row.append(&auto_connect_switch);

    // Full-tunnel toggle row.
    let full_tunnel_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .margin_top(4)
        .build();
    let full_tunnel_label = gtk4::Label::builder()
        .label("Route all traffic through VPN")
        .hexpand(true)
        .halign(gtk4::Align::Start)
        .build();
    let full_tunnel_switch = gtk4::Switch::builder()
        .active(true)
        .sensitive(false)
        .valign(gtk4::Align::Center)
        .build();
    full_tunnel_row.append(&full_tunnel_label);
    full_tunnel_row.append(&full_tunnel_switch);

    // Kill-switch toggle row.
    let kill_switch_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .margin_top(4)
        .build();
    let kill_switch_label = gtk4::Label::builder()
        .label("Block non-VPN traffic (kill switch)")
        .hexpand(true)
        .halign(gtk4::Align::Start)
        .build();
    let kill_switch_switch = gtk4::Switch::builder()
        .active(false)
        .sensitive(false)
        .valign(gtk4::Align::Center)
        .build();
    kill_switch_row.append(&kill_switch_label);
    kill_switch_row.append(&kill_switch_switch);

    // Rotate WireGuard key button.
    let rotate_key_btn = gtk4::Button::builder()
        .label("Rotate WireGuard Key\u{2026}")
        .css_classes(["flat"])
        .halign(gtk4::Align::Center)
        .visible(false)
        .build();

    // Export button.
    let export_btn = gtk4::Button::builder()
        .label("Export Profile\u{2026}")
        .css_classes(["flat"])
        .halign(gtk4::Align::Center)
        .sensitive(false)
        .build();

    // Duplicate button.
    let duplicate_btn = gtk4::Button::builder()
        .label("Duplicate Profile")
        .css_classes(["flat"])
        .halign(gtk4::Align::Center)
        .sensitive(false)
        .build();

    // Split-routes row.
    let split_routes_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(4)
        .margin_top(4)
        .visible(false)
        .build();
    let split_routes_header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .build();
    let split_routes_label = gtk4::Label::builder()
        .label("Split-tunnel routes")
        .hexpand(true)
        .halign(gtk4::Align::Start)
        .build();
    let split_routes_edit_btn = gtk4::Button::builder()
        .label("Edit")
        .css_classes(["flat"])
        .build();
    split_routes_header.append(&split_routes_label);
    split_routes_header.append(&split_routes_edit_btn);
    let split_routes_value = gtk4::Label::builder()
        .label("None configured")
        .halign(gtk4::Align::Start)
        .css_classes(["caption", "dim-label"])
        .wrap(true)
        .build();
    split_routes_row.append(&split_routes_header);
    split_routes_row.append(&split_routes_value);

    // Stats card.
    let stats_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .css_classes(["card"])
        .margin_top(12)
        .visible(false)
        .build();
    let stats_sent = gtk4::Label::builder()
        .label("Sent: \u{2014}")
        .halign(gtk4::Align::Start)
        .margin_top(12)
        .margin_bottom(4)
        .margin_start(12)
        .margin_end(12)
        .build();
    let stats_recv = gtk4::Label::builder()
        .label("Received: \u{2014}")
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .margin_end(12)
        .build();
    let stats_uptime = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .margin_end(12)
        .visible(false)
        .build();
    let stats_handshake = gtk4::Label::builder()
        .label("Last handshake: \u{2014}")
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .build();
    let stats_virtual_ip = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .margin_end(12)
        .visible(false)
        .build();
    let stats_routes = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .wrap(true)
        .visible(false)
        .build();
    stats_box.append(&stats_sent);
    stats_box.append(&stats_recv);
    stats_box.append(&stats_uptime);
    stats_box.append(&stats_handshake);
    stats_box.append(&stats_virtual_ip);
    stats_box.append(&stats_routes);

    // Assemble detail box.
    let detail_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .valign(gtk4::Align::Start)
        .build();
    detail_box.append(&profile_name_label);
    detail_box.append(&status_label);
    detail_box.append(&connect_btn);
    detail_box.append(&rename_btn);
    detail_box.append(&edit_creds_btn);
    detail_box.append(&auto_connect_row);
    detail_box.append(&full_tunnel_row);
    detail_box.append(&kill_switch_row);
    detail_box.append(&split_routes_row);
    detail_box.append(&rotate_key_btn);
    detail_box.append(&export_btn);
    detail_box.append(&duplicate_btn);
    detail_box.append(&stats_box);

    detail_stack.add_named(&detail_box, Some("detail"));
    detail_stack.set_visible_child_name("empty");

    let content_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&detail_stack)
        .build();

    let content_page = adw::NavigationPage::builder()
        .title("Connection")
        .child(&content_scroll)
        .build();

    let detail = VpnDetail {
        detail_stack,
        profile_name_label,
        status_label,
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
        stats_box,
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

/// Sync the connect/disconnect button label, style, and sensitivity with the
/// current VPN state.
pub fn apply_vpn_state(
    btn: &gtk4::Button,
    rename_btn: &gtk4::Button,
    status_label: &gtk4::Label,
    stats_box: &gtk4::Box,
    state: &AppState,
) {
    btn.remove_css_class("suggested-action");
    btn.remove_css_class("destructive-action");

    let active_id = state.vpn_state.profile_id().map(|u| u.to_string());
    let selected_is_active = match (&state.selected_profile, &active_id) {
        (Some(sel), Some(act)) => sel == act,
        _ => false,
    };
    let another_is_active = !state.vpn_state.is_idle() && !selected_is_active;

    if another_is_active {
        status_label.set_label("Another VPN is active");
        btn.set_label("Connect");
        btn.add_css_class("suggested-action");
        btn.set_sensitive(false);
        stats_box.set_visible(false);
        rename_btn.set_sensitive(state.selected_profile.is_some());
        return;
    }

    match &state.vpn_state {
        VpnState::Connected { .. } => {
            status_label.set_label("Connected");
            btn.set_label("Disconnect");
            btn.add_css_class("destructive-action");
            btn.set_sensitive(true);
            stats_box.set_visible(true);
        }
        VpnState::Connecting { phase, .. } => {
            status_label.set_label(&format!("Connecting\u{2026} {phase}"));
            btn.set_label("Force Disconnect");
            btn.add_css_class("destructive-action");
            btn.set_sensitive(true);
            stats_box.set_visible(false);
        }
        VpnState::Disconnecting { .. } => {
            status_label.set_label("Disconnecting\u{2026}");
            btn.set_label("Force Disconnect");
            btn.add_css_class("destructive-action");
            btn.set_sensitive(true);
            stats_box.set_visible(false);
        }
        VpnState::Error { message, .. } => {
            status_label.set_label(&format!("Error: {message}"));
            btn.set_label("Connect");
            btn.add_css_class("suggested-action");
            btn.set_sensitive(state.selected_profile.is_some());
            stats_box.set_visible(false);
        }
        VpnState::Disconnected => {
            status_label.set_label("Disconnected");
            btn.set_label("Connect");
            btn.add_css_class("suggested-action");
            btn.set_sensitive(state.selected_profile.is_some());
            stats_box.set_visible(false);
        }
    }

    rename_btn.set_sensitive(state.selected_profile.is_some());
}
