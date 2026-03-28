//! SSH host detail panel.
//!
//! Shows the selected host's connection details, device type, and auth method.
//! Provides action buttons: Connect (terminal), Push Key, Edit, Delete.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::{glib, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::{error, info};

use supermgr_core::ssh::host::{AuthMethod, SshHostSummary};
use supermgr_core::ssh::DeviceType;

use crate::app::{AppMsg, AppState};

// ---------------------------------------------------------------------------
// Widget bundle
// ---------------------------------------------------------------------------

/// All the widgets in the SSH host detail panel that need updating.
#[derive(Clone)]
pub struct SshHostDetail {
    /// Outer stack: "empty" vs "detail".
    pub detail_stack: gtk4::Stack,

    pub host_label_lbl: gtk4::Label,
    pub group_badge: gtk4::Label,
    pub hostname_row: adw::ActionRow,
    pub port_row: adw::ActionRow,
    pub username_row: adw::ActionRow,
    pub device_type_row: adw::ActionRow,
    pub auth_method_row: adw::ActionRow,

    pub connect_btn: gtk4::Button,
    pub push_key_btn: gtk4::Button,
    pub edit_btn: gtk4::Button,
    pub delete_btn: gtk4::Button,
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build the SSH host detail panel.
///
/// Returns the widget bundle and the scrollable content widget.
pub fn build_ssh_host_detail() -> (SshHostDetail, gtk4::Widget) {
    let detail_stack = gtk4::Stack::new();

    // Empty state.
    let empty_status = adw::StatusPage::builder()
        .title("No Host Selected")
        .description("Select a host from the list to view its details.")
        .icon_name("computer-symbolic")
        .build();
    detail_stack.add_named(&empty_status, Some("empty"));

    // Detail view.
    let host_label_lbl = gtk4::Label::builder()
        .label("")
        .css_classes(["title-1"])
        .halign(gtk4::Align::Start)
        .wrap(true)
        .build();

    let group_badge = gtk4::Label::builder()
        .label("")
        .css_classes(["caption", "dim-label"])
        .halign(gtk4::Align::Start)
        .visible(false)
        .build();

    // Connection details as AdwActionRows in a boxed list.
    let details_group = adw::PreferencesGroup::builder()
        .title("Connection Details")
        .margin_top(12)
        .build();

    let hostname_row = adw::ActionRow::builder()
        .title("Hostname")
        .subtitle("")
        .activatable(false)
        .build();
    details_group.add(&hostname_row);

    let port_row = adw::ActionRow::builder()
        .title("Port")
        .subtitle("")
        .activatable(false)
        .build();
    details_group.add(&port_row);

    let username_row = adw::ActionRow::builder()
        .title("Username")
        .subtitle("")
        .activatable(false)
        .build();
    details_group.add(&username_row);

    let device_type_row = adw::ActionRow::builder()
        .title("Device Type")
        .subtitle("")
        .activatable(false)
        .build();
    details_group.add(&device_type_row);

    let auth_method_row = adw::ActionRow::builder()
        .title("Authentication")
        .subtitle("")
        .activatable(false)
        .build();
    details_group.add(&auth_method_row);

    // Action buttons.
    let btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::Center)
        .margin_top(16)
        .build();
    let connect_btn = gtk4::Button::builder()
        .label("Connect")
        .css_classes(["suggested-action"])
        .tooltip_text("Open SSH session in terminal")
        .build();
    let push_key_btn = gtk4::Button::builder()
        .label("Push Key\u{2026}")
        .css_classes(["flat"])
        .build();
    let edit_btn = gtk4::Button::builder()
        .label("Edit\u{2026}")
        .css_classes(["flat"])
        .build();
    let delete_btn = gtk4::Button::builder()
        .label("Delete")
        .css_classes(["destructive-action"])
        .build();
    btn_box.append(&connect_btn);
    btn_box.append(&push_key_btn);
    btn_box.append(&edit_btn);
    btn_box.append(&delete_btn);

    // Assemble.
    let detail_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(8)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .valign(gtk4::Align::Start)
        .build();
    detail_box.append(&host_label_lbl);
    detail_box.append(&group_badge);
    detail_box.append(&details_group);
    detail_box.append(&btn_box);

    detail_stack.add_named(&detail_box, Some("detail"));
    detail_stack.set_visible_child_name("empty");

    let content_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&detail_stack)
        .build();

    let bundle = SshHostDetail {
        detail_stack,
        host_label_lbl,
        group_badge,
        hostname_row,
        port_row,
        username_row,
        device_type_row,
        auth_method_row,
        connect_btn,
        push_key_btn,
        edit_btn,
        delete_btn,
    };

    (bundle, content_scroll.upcast())
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

/// Update the host detail panel to show the given host.
pub fn update_ssh_host_detail(detail: &SshHostDetail, host: &SshHostSummary) {
    detail.host_label_lbl.set_label(&host.label);

    if host.group.is_empty() {
        detail.group_badge.set_visible(false);
    } else {
        detail.group_badge.set_label(&format!("Group: {}", host.group));
        detail.group_badge.set_visible(true);
    }

    detail.hostname_row.set_subtitle(&host.hostname);
    detail.port_row.set_subtitle(&host.port.to_string());
    detail.username_row.set_subtitle(&host.username);
    detail.device_type_row.set_subtitle(&host.device_type.to_string());

    let auth_str = match host.auth_method {
        AuthMethod::Password => "Password",
        AuthMethod::Key => "Public Key",
    };
    detail.auth_method_row.set_subtitle(auth_str);

    detail.detail_stack.set_visible_child_name("detail");
}

// ---------------------------------------------------------------------------
// Terminal launch
// ---------------------------------------------------------------------------

/// Detect available terminal emulator and spawn an SSH session.
///
/// `ssh_cmd` is the complete `ssh …` invocation (including `-i` for key auth),
/// built by the daemon's `ssh_connect_command` D-Bus method.
///
/// The SSH command is wrapped so the terminal stays open if the connection
/// fails or the user wants to reconnect — the shell prompt remains active.
pub fn launch_ssh_terminal(ssh_cmd: &str) {

    // Wrap in a shell that keeps the terminal open after SSH exits.
    // The user gets dropped into a shell and can re-run the command or
    // inspect errors without the window vanishing.
    let shell_wrapper = format!(
        "{ssh_cmd}; echo ''; echo 'SSH session ended (exit status: '$?')'; echo 'Press Enter to close...'; read _"
    );

    // Each terminal needs its arguments in a specific order.
    // konsole: `konsole -e /bin/sh -c "cmd"` — but `-e` only takes ONE
    //          argument unless using `--` with recent versions.  The safest
    //          is to pass a single shell invocation.
    let terminals: &[(&str, &[&str])] = &[
        ("konsole",         &["--noclose", "-e", "/bin/sh", "-c"]),
        ("gnome-terminal",  &["--", "sh", "-c"]),
        ("kgx",             &["--", "sh", "-c"]),
        ("xfce4-terminal",  &["--hold", "-e", "sh -c"]),
        ("alacritty",       &["--hold", "-e", "sh", "-c"]),
        ("kitty",           &["sh", "-c"]),
        ("foot",            &["sh", "-c"]),
        ("wezterm",         &["start", "--", "sh", "-c"]),
        ("xterm",           &["-hold", "-e", "sh", "-c"]),
    ];

    for (term, prefix_args) in terminals {
        if which_exists(term) {
            let mut cmd = std::process::Command::new(term);
            for arg in *prefix_args {
                cmd.arg(arg);
            }
            cmd.arg(&shell_wrapper);
            match cmd.spawn() {
                Ok(_) => {
                    info!("launched SSH session in {term}: {ssh_cmd}");
                    return;
                }
                Err(e) => {
                    error!("failed to launch {term}: {e}");
                    continue;
                }
            }
        }
    }

    error!("no suitable terminal emulator found for SSH session");
}

/// Check whether an executable is on PATH.
fn which_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .any(|dir| dir.join(name).is_file())
        })
        .unwrap_or(false)
}
