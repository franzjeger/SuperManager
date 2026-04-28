//! SSH key detail panel.
//!
//! Shows the selected key's metadata, public key, tags, and deployed hosts.
//! Provides action buttons for pushing keys and deleting.

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use supermgr_core::ssh::key::SshKeySummary;
use supermgr_core::host::HostSummary;


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
/// Returns the widget bundle and the enclosing [`adw::NavigationPage`].
pub fn build_ssh_key_detail() -> (SshKeyDetail, gtk4::Widget) {
    let detail_stack = gtk4::Stack::new();

    // Empty state.
    let empty_status = adw::StatusPage::builder()
        .title("No Key Selected")
        .description("Select a key from the list to view its details.")
        .icon_name("dialog-password-symbolic")
        .build();
    detail_stack.add_named(&empty_status, Some("empty"));

    // Detail view.
    let key_name_label = gtk4::Label::builder()
        .label("")
        .css_classes(["title-1"])
        .halign(gtk4::Align::Start)
        .wrap(true)
        .build();

    let key_type_badge = gtk4::Label::builder()
        .label("")
        .css_classes(["caption", "dim-label"])
        .halign(gtk4::Align::Start)
        .build();

    // Fingerprint row with copy button.
    let fingerprint_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    let fingerprint_label = gtk4::Label::builder()
        .label("")
        .css_classes(["monospace", "caption"])
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .selectable(true)
        .wrap(true)
        .build();
    let fp_copy_btn = gtk4::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy fingerprint")
        .css_classes(["flat"])
        .valign(gtk4::Align::Center)
        .build();
    fingerprint_box.append(&fingerprint_label);
    fingerprint_box.append(&fp_copy_btn);

    // Copy fingerprint to clipboard.
    {
        let fingerprint_label = fingerprint_label.clone();
        fp_copy_btn.connect_clicked(move |_btn| {
            let text = fingerprint_label.label();
            if let Some(display) = gtk4::gdk::Display::default() {
                display.clipboard().set_text(&text);
            }
        });
    }

    // Public key viewer.
    let _pubkey_group = adw::PreferencesGroup::builder()
        .title("Public Key")
        .margin_top(12)
        .build();
    let public_key_view = gtk4::TextView::builder()
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::Char)
        .css_classes(["card"])
        .build();
    let pubkey_scroll = gtk4::ScrolledWindow::builder()
        .min_content_height(80)
        .max_content_height(120)
        .child(&public_key_view)
        .build();

    let pubkey_copy_btn = gtk4::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy public key")
        .css_classes(["flat"])
        .valign(gtk4::Align::Center)
        .build();

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

    let pubkey_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(4)
        .build();
    let pubkey_header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    let pubkey_title = gtk4::Label::builder()
        .label("Public Key")
        .css_classes(["heading"])
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    pubkey_header.append(&pubkey_title);
    pubkey_header.append(&pubkey_copy_btn);
    pubkey_box.append(&pubkey_header);
    pubkey_box.append(&pubkey_scroll);

    // Tags.
    let tags_label = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::Start)
        .css_classes(["caption", "dim-label"])
        .wrap(true)
        .visible(false)
        .build();

    // Deployed-to section.
    let deployed_title = gtk4::Label::builder()
        .label("Deployed To")
        .css_classes(["heading"])
        .halign(gtk4::Align::Start)
        .margin_top(12)
        .build();
    let deployed_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();

    // Action buttons.
    let btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::Center)
        .margin_top(16)
        .build();
    let push_btn = gtk4::Button::builder()
        .label("Push to Hosts\u{2026}")
        .css_classes(["suggested-action"])
        .build();
    let delete_btn = gtk4::Button::builder()
        .label("Delete Key")
        .css_classes(["destructive-action"])
        .build();
    btn_box.append(&push_btn);
    btn_box.append(&delete_btn);

    // Assemble detail box.
    let detail_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(8)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .valign(gtk4::Align::Start)
        .build();
    detail_box.append(&key_name_label);
    detail_box.append(&key_type_badge);
    detail_box.append(&fingerprint_box);
    detail_box.append(&pubkey_box);
    detail_box.append(&tags_label);
    detail_box.append(&deployed_title);
    detail_box.append(&deployed_list);
    detail_box.append(&btn_box);

    detail_stack.add_named(&detail_box, Some("detail"));
    detail_stack.set_visible_child_name("empty");

    let content_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&detail_stack)
        .build();

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

    (bundle, content_scroll.upcast())
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
    detail.key_type_badge.set_label(&format!("{:?}", key.key_type));
    detail.fingerprint_label.set_label(&key.fingerprint);
    detail.public_key_view.buffer().set_text(public_key_text);

    if key.tags.is_empty() {
        detail.tags_label.set_visible(false);
    } else {
        detail.tags_label.set_label(&format!("Tags: {}", key.tags.join(", ")));
        detail.tags_label.set_visible(true);
    }

    // Rebuild deployed-to list.
    while let Some(child) = detail.deployed_list.first_child() {
        detail.deployed_list.remove(&child);
    }

    if deployed_host_ids.is_empty() {
        let row = adw::ActionRow::builder()
            .title("Not deployed to any hosts")
            .activatable(false)
            .build();
        detail.deployed_list.append(&row);
    } else {
        for host_id in deployed_host_ids {
            let label = hosts
                .iter()
                .find(|h| h.id.to_string() == *host_id)
                .map(|h| h.label.as_str())
                .unwrap_or(host_id.as_str());
            let row = adw::ActionRow::builder()
                .title(label)
                .activatable(false)
                .build();
            row.add_prefix(&gtk4::Image::from_icon_name("computer-symbolic"));
            detail.deployed_list.append(&row);
        }
    }

    detail.detail_stack.set_visible_child_name("detail");
}
