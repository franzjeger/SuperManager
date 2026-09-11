//! SSH key detail panel.
//!
//! Shows the selected key's metadata, public key, tags, and deployed hosts.
//!
//! # What changed
//!
//! This pane used to be a single narrow column: an oversized name, a dim
//! type caption, a fingerprint, a text view, a tag line, a "Deployed To"
//! heading, and finally two buttons centred at the bottom. On a wide window
//! all of it sat in a strip down the left with nothing beside it — the
//! brief's *"dead space"* complaint, exactly.
//!
//! It is now the same [`design`] grammar as everything else: a header with
//! the name and the primary action, and cards that reflow into as many
//! columns as fit. Nothing was removed; it stopped being a single column.

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::ui::design;
use supermgr_core::host::HostSummary;
use supermgr_core::ssh::key::SshKeySummary;

// ---------------------------------------------------------------------------
// Widget bundle
// ---------------------------------------------------------------------------

/// All the widgets in the SSH key detail panel that need updating.
pub struct SshKeyDetail {
    /// Outer stack: "empty" vs "detail".
    pub detail_stack: gtk4::Stack,

    pub key_name_label: gtk4::Label,
    pub key_type_badge: gtk4::Label,
    pub fingerprint_label: gtk4::Label,
    pub public_key_view: gtk4::TextView,
    pub tags_label: gtk4::Label,
    pub deployed_list: gtk4::ListBox,
    pub push_btn: gtk4::Button,
    pub delete_btn: gtk4::Button,
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build the SSH key detail panel.
///
/// Returns the widget bundle and the enclosing scrollable content widget.
#[must_use]
pub fn build_ssh_key_detail() -> (SshKeyDetail, gtk4::Widget) {
    let detail_stack = gtk4::Stack::new();

    // Empty state. Names the next action rather than restating the obvious.
    let empty_status = design::empty_state(
        design::icon_name(design::icons::KEY),
        "No key selected",
        "Pick a key from the list to see its fingerprint and where it is deployed.",
    );
    detail_stack.add_named(&empty_status, Some("empty"));

    // --- Header -------------------------------------------------------------

    let header = design::DetailHeader::new();
    let key_name_label = header.title.clone();

    // The key type sits where a status pill sits elsewhere: under the name,
    // left-aligned. A key has no state to report, so the slot carries the one
    // fact that classifies it.
    let key_type_badge = design::badge("");
    header.status_slot.set_child(Some(&key_type_badge));

    let push_btn = gtk4::Button::builder()
        .label("Push to Hosts\u{2026}")
        .css_classes(["suggested-action", "pill"])
        .build();
    header.actions.append(&push_btn);

    // --- Identity card ------------------------------------------------------

    let identity = design::card("Identity");
    let fingerprint_label = gtk4::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .wrap_mode(gtk4::pango::WrapMode::Char)
        .hexpand(true)
        .css_classes(["monospace"])
        .build();
    let fingerprint_body = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
    fingerprint_body.set_hexpand(true);
    fingerprint_body.append(
        &gtk4::Label::builder()
            .label("Fingerprint")
            .xalign(0.0)
            .css_classes(["caption", "dim-label"])
            .build(),
    );
    fingerprint_body.append(&fingerprint_label);
    let fingerprint_content = gtk4::Box::builder()
        .spacing(12)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(14)
        .margin_end(10)
        .build();
    fingerprint_content.append(&fingerprint_body);
    let fingerprint_row = adw::PreferencesRow::builder()
        .child(&fingerprint_content)
        .build();

    let fp_copy_btn = gtk4::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy fingerprint")
        .css_classes(["flat"])
        .valign(gtk4::Align::Center)
        .build();
    fingerprint_content.append(&fp_copy_btn);
    identity.add(&fingerprint_row);

    {
        let fingerprint_label = fingerprint_label.clone();
        fp_copy_btn.connect_clicked(move |_btn| {
            let text = fingerprint_label.label();
            if let Some(display) = gtk4::gdk::Display::default() {
                display.clipboard().set_text(&text);
            }
        });
    }

    let (tags_row, tags_label) = design::live_detail_row("Tags", false);
    tags_label.set_wrap(true);
    tags_label.set_wrap_mode(gtk4::pango::WrapMode::WordChar);
    tags_label.set_max_width_chars(26);
    tags_label.set_visible(false);
    identity.add(&tags_row);

    // --- Public key card ----------------------------------------------------

    let pubkey_card = design::card("Public key");
    let pubkey_copy_btn = gtk4::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy public key")
        .css_classes(["flat"])
        .valign(gtk4::Align::Center)
        .build();
    pubkey_card.set_header_suffix(Some(&pubkey_copy_btn));

    let public_key_view = gtk4::TextView::builder()
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::Char)
        .left_margin(8)
        .right_margin(8)
        .top_margin(8)
        .bottom_margin(8)
        .build();
    let pubkey_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .min_content_height(96)
        .max_content_height(160)
        .css_classes(["card"])
        .child(&public_key_view)
        .build();
    pubkey_card.add(&pubkey_scroll);

    {
        let public_key_view = public_key_view.clone();
        pubkey_copy_btn.connect_clicked(move |_| {
            let buf = public_key_view.buffer();
            let text = buf.text(&buf.start_iter(), &buf.end_iter(), false);
            if let Some(display) = gtk4::gdk::Display::default() {
                display.clipboard().set_text(&text);
            }
        });
    }

    // --- Deployment card ----------------------------------------------------

    let deployed_card = design::card("Key usage");
    deployed_card.set_description(Some("Login assignments and recorded public-key installations. Remote files are not checked in the background."));
    let deployed_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    deployed_card.add(&deployed_list);

    // --- Manage card --------------------------------------------------------
    //
    // One destructive action, in its own card, as a row rather than as a red
    // button sitting next to the primary one. A red button beside a green one
    // is a misclick waiting to happen.

    let manage = design::card("Manage");
    let delete_btn = gtk4::Button::new();
    manage.add(&design::destructive_button_row(
        &delete_btn,
        "Delete key",
        "Removes the private key from this machine. Hosts keep their copy.",
        "user-trash-symbolic",
    ));

    // --- Assemble -----------------------------------------------------------

    let (scroller, content) = design::detail_body();
    content.append(&header.widget);

    let columns = design::reflowing_columns();
    design::add_card(&columns, &identity);
    design::add_card(&columns, &pubkey_card);
    design::add_card(&columns, &deployed_card);
    design::add_card(&columns, &manage);
    content.append(&columns);

    detail_stack.add_named(&scroller, Some("detail"));
    detail_stack.set_visible_child_name("empty");

    // The scrolling lives inside the detail page rather than around the whole
    // stack, so the empty state fills the pane instead of being pinned to the
    // top of a scroller.
    let widget: gtk4::Widget = detail_stack.clone().upcast();

    let bundle = SshKeyDetail {
        detail_stack,
        key_name_label,
        key_type_badge,
        fingerprint_label,
        public_key_view,
        tags_label,
        deployed_list,
        push_btn,
        delete_btn,
    };

    (bundle, widget)
}

pub fn populate_key_usage(
    list: &gtk4::ListBox,
    key: &SshKeySummary,
    hosts: &[HostSummary],
    tx: &std::sync::mpsc::Sender<crate::app::AppMsg>,
) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    let mut ids = key.assigned_host_ids.clone();
    ids.extend(&key.deployed_host_ids);
    ids.sort();
    ids.dedup();
    ids.sort_by_key(|id| {
        hosts
            .iter()
            .find(|host| host.id == *id)
            .map(|host| host.label.to_lowercase())
            .unwrap_or_default()
    });
    if ids.is_empty() {
        list.append(&adw::ActionRow::builder().title("No recorded use")
            .subtitle("Assign this key in a host's connection settings, or use Push to Hosts to install its public key.").subtitle_lines(3).build());
    }
    for id in ids {
        let host = hosts.iter().find(|host| host.id == id);
        let assigned = key.assigned_host_ids.contains(&id);
        let deployed = key.deployed_host_ids.contains(&id);
        let usage = match (assigned, deployed) {
            (true, true) => "Used for login · Deployment recorded",
            (true, false) => "Used for login · No deployment recorded",
            _ => "Deployment recorded · Not assigned for login",
        };
        let row = adw::ActionRow::builder()
            .title(
                &host
                    .map(|host| host.label.clone())
                    .unwrap_or_else(|| format!("Removed host · {id}")),
            )
            .subtitle(usage)
            .title_lines(1)
            .subtitle_lines(2)
            .build();
        row.add_prefix(&design::icon(design::icons::HOST));
        if host.is_some() {
            let open = gtk4::Button::builder()
                .icon_name("go-next-symbolic")
                .tooltip_text("Open host")
                .valign(gtk4::Align::Center)
                .css_classes(["flat"])
                .build();
            let tx = tx.clone();
            open.connect_clicked(move |_| {
                tx.send(crate::app::AppMsg::SelectSshHost(id.to_string()))
                    .ok();
            });
            row.add_suffix(&open);
            row.set_activatable_widget(Some(&open));
        }
        list.append(&row);
    }
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

/// Update the key detail panel to show the given key.
#[allow(dead_code)]
pub fn update_ssh_key_detail(
    detail: &SshKeyDetail,
    key: &SshKeySummary,
    hosts: &[HostSummary],
    public_key_text: &str,
    deployed_host_ids: &[String],
) {
    detail.key_name_label.set_label(&key.name);
    detail
        .key_type_badge
        .set_label(&format!("{:?}", key.key_type));
    detail.fingerprint_label.set_label(&key.fingerprint);
    detail.public_key_view.buffer().set_text(public_key_text);

    // The row carries the "Tags" label, so this is just the values — and an
    // empty label takes its own row away with it.
    detail.tags_label.set_label(&key.tags.join(", "));
    detail.tags_label.set_visible(!key.tags.is_empty());

    // Rebuild deployed-to list.
    while let Some(child) = detail.deployed_list.first_child() {
        detail.deployed_list.remove(&child);
    }

    if deployed_host_ids.is_empty() {
        let row = adw::ActionRow::builder()
            .title("Not deployed anywhere")
            .subtitle("Use Push to Hosts to install it")
            .activatable(false)
            .build();
        detail.deployed_list.append(&row);
    } else {
        for host_id in deployed_host_ids {
            let label = hosts
                .iter()
                .find(|h| h.id.to_string() == *host_id)
                .map_or(host_id.as_str(), |h| h.label.as_str());
            let row = adw::ActionRow::builder()
                .title(label)
                .activatable(false)
                .build();
            row.add_prefix(&design::icon(design::icons::HOST));
            detail.deployed_list.append(&row);
        }
    }

    detail.detail_stack.set_visible_child_name("detail");
}
