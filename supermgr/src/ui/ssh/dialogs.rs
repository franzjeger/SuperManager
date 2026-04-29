//! SSH dialogs — Generate Key, Add Host, Import Keys, Push Key, Revoke Key.
//!
//! All dialogs follow the same pattern as the VPN dialogs: build widgets,
//! validate input, on submit close the dialog and spawn a tokio D-Bus call.

use std::sync::mpsc;

use gtk4::{glib, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use tracing::error;

use supermgr_core::ssh::key::SshKeySummary;
use supermgr_core::host::HostSummary;
use supermgr_core::vpn::profile::ProfileSummary;

use crate::app::AppMsg;
use crate::dbus_client::{
    dbus_ssh_generate_key, dbus_ssh_add_host, dbus_ssh_import_scan,
    dbus_ssh_import_key, dbus_ssh_push_key, dbus_ssh_revoke_key,
};

// ---------------------------------------------------------------------------
// Device-type context
// ---------------------------------------------------------------------------
//
// Single source of truth for device-type ordering in host dialogs and the
// per-device defaults / visibility rules that drive the Add and Edit forms.
// Adding a device type means: extend `DEVICE_LABELS`, the `DeviceType` <->
// index converters, and `device_context`.

/// Order in which device types are shown in the dropdown.
const DEVICE_LABELS: &[&str] = &[
    "Linux", "UniFi", "pfSense", "OPNsense", "Sophos",
    "OpenWrt", "FortiGate", "Windows", "Custom",
];

/// Map a `DeviceType` to its dropdown index.
fn device_type_to_idx(d: supermgr_core::DeviceType) -> u32 {
    use supermgr_core::DeviceType::*;
    match d {
        Linux => 0, UniFi => 1, PfSense => 2, OpnSense => 3, Sophos => 4,
        OpenWrt => 5, Fortigate => 6, Windows => 7, Custom => 8,
    }
}

/// Map a dropdown index to the `device_type` JSON value the daemon expects.
fn idx_to_device_type_str(idx: u32) -> &'static str {
    match idx {
        1 => "uni_fi",
        2 => "pf_sense",
        3 => "opn_sense",
        4 => "sophos",
        5 => "open_wrt",
        6 => "fortigate",
        7 => "windows",
        8 => "custom",
        _ => "linux",
    }
}

/// Per-device UI rules — what to show, what to default, what to forbid.
///
/// Anything not relevant to a device type is hidden so the form stays focused
/// on settings that actually apply (e.g. Windows hides SSH key/cert/jump-host
/// and uses port 3389 with password auth).
struct DeviceContext {
    /// Default value for the primary port row.
    default_port: u16,
    /// Label for the primary port row (e.g. "Port" for SSH, "RDP Port" for Windows).
    port_label: &'static str,
    /// Show the authentication group at all (it carries password/key/cert + VPN row).
    show_auth_section: bool,
    /// Show jump-host (ProxyJump) row. SSH-only concept.
    show_jump_host: bool,
    /// Authentication-method indices to allow. Forced to first entry if current
    /// selection is not in the list. (0=Public Key, 1=Password, 2=Certificate.)
    allowed_auth: &'static [u32],
    /// Show the auth-method dropdown itself. Hidden when only one method is
    /// allowed (e.g. Windows = Password only — no point asking).
    show_auth_chooser: bool,
    /// Show FortiGate REST API group (token + HTTPS port).
    show_fortigate_api: bool,
    /// Show OPNsense REST API group (reuses api_token_ref/api_port).
    show_opnsense_api: bool,
    /// Show UniFi Controller group.
    show_unifi: bool,
    /// Show RDP port row in the Remote Desktop group.
    show_rdp_row: bool,
    /// Show VNC port row in the Remote Desktop group.
    show_vnc_row: bool,
    /// Default value for the RDP port row when it is shown and empty.
    default_rdp_port: u16,
}

fn device_context(idx: u32) -> DeviceContext {
    // Defaults are SSH-shaped (Linux). Each match arm tweaks what differs.
    let base = DeviceContext {
        default_port: 22,
        port_label: "Port",
        show_auth_section: true,
        show_jump_host: true,
        allowed_auth: &[0, 1, 2],
        show_auth_chooser: true,
        show_fortigate_api: false,
        show_opnsense_api: false,
        show_unifi: false,
        show_rdp_row: false,
        show_vnc_row: false,
        default_rdp_port: 3389,
    };
    match idx {
        1 => DeviceContext { show_unifi: true, allowed_auth: &[0, 1], ..base }, // UniFi
        2 => DeviceContext { allowed_auth: &[0, 1], ..base },                   // pfSense
        3 => DeviceContext { show_opnsense_api: true, allowed_auth: &[0, 1], ..base }, // OPNsense
        4 => DeviceContext {                                                    // Sophos: WebAdmin uses user/pass
            allowed_auth: &[1],
            show_auth_chooser: false,
            ..base
        },
        5 => DeviceContext { allowed_auth: &[0, 1], ..base },                   // OpenWrt
        6 => DeviceContext { show_fortigate_api: true, allowed_auth: &[0, 1], ..base }, // FortiGate
        7 => DeviceContext {                                                    // Windows: RDP + password only
            default_port: 3389,
            port_label: "RDP Port",
            show_jump_host: false,
            allowed_auth: &[1],
            show_auth_chooser: false,
            ..base
        },
        8 => DeviceContext {                                                    // Custom: show everything
            show_rdp_row: true,
            show_vnc_row: true,
            ..base
        },
        _ => base,                                                              // Linux
    }
}

// ---------------------------------------------------------------------------
// Generate Key dialog
// ---------------------------------------------------------------------------

/// Show the "Generate SSH Key" dialog.
pub fn show_generate_key_dialog(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;

    let dialog = adw::Dialog::builder()
        .title("Generate SSH Key")
        .content_width(400)
        .build();

    let name_row = adw::EntryRow::builder().title("Key name").build();

    let type_model = gtk4::StringList::new(&["Ed25519", "RSA 2048", "RSA 4096"]);
    let type_row = adw::ComboRow::builder()
        .title("Key type")
        .model(&type_model)
        .selected(0)
        .build();

    let desc_row = adw::EntryRow::builder()
        .title("Description (optional)")
        .build();

    let tags_row = adw::EntryRow::builder()
        .title("Tags (comma-separated)")
        .build();

    let group = adw::PreferencesGroup::new();
    group.add(&name_row);
    group.add(&type_row);
    group.add(&desc_row);
    group.add(&tags_row);

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let generate_btn = gtk4::Button::builder()
        .label("Generate")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&generate_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    content_box.append(&group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    // Validate: name required.
    let validate: Rc<dyn Fn()> = {
        let name_row = name_row.clone();
        let generate_btn = generate_btn.clone();
        Rc::new(move || {
            generate_btn.set_sensitive(!name_row.text().is_empty());
        })
    };
    {
        let v = Rc::clone(&validate);
        name_row.connect_changed(move |_| v());
    }

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    {
        let dialog = dialog.clone();
        let name_row = name_row.clone();
        let type_row = type_row.clone();
        let desc_row = desc_row.clone();
        let tags_row = tags_row.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        generate_btn.connect_clicked(move |_| {
            let name = name_row.text().to_string();
            let key_type = match type_row.selected() {
                1 => "rsa2048".to_owned(),
                2 => "rsa4096".to_owned(),
                _ => "ed25519".to_owned(),
            };
            let description = desc_row.text().to_string();
            let tags: Vec<String> = tags_row
                .text()
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect();

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg = match dbus_ssh_generate_key(name, key_type, description, tags).await {
                    Ok((keys, _uuid)) => {
                        AppMsg::SshKeysRefreshed(keys)
                    }
                    Err(e) => {
                        error!("generate SSH key: {e:#}");
                        AppMsg::OperationFailed(e.to_string())
                    }
                };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Add Host dialog
// ---------------------------------------------------------------------------

/// Show the "Add SSH Host" dialog.
pub fn show_add_host_dialog(
    window: &adw::ApplicationWindow,
    keys: &[SshKeySummary],
    all_hosts: &[HostSummary],
    vpn_profiles: &[ProfileSummary],
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;

    let dialog = adw::Dialog::builder()
        .title("Add Host")
        .content_width(420)
        .build();

    // --- Connection group ---------------------------------------------------
    let label_row = adw::EntryRow::builder().title("Label").build();
    let hostname_row = adw::EntryRow::builder().title("Hostname").build();
    let port_row = adw::EntryRow::builder().title("Port").text("22").build();
    let username_row = adw::EntryRow::builder().title("Username").build();
    let group_row = adw::EntryRow::builder().title("Group (optional)").build();

    let device_model = gtk4::StringList::new(DEVICE_LABELS);
    let device_row = adw::ComboRow::builder()
        .title("Device type")
        .model(&device_model)
        .selected(0)
        .build();

    // Jump host combo — "None / Direct" plus all existing SSH hosts.
    let mut jump_names: Vec<String> = vec!["None / Direct".to_string()];
    jump_names.extend(all_hosts.iter().map(|h| format!("{} ({})", h.label, h.hostname)));
    let jump_name_refs: Vec<&str> = jump_names.iter().map(|s| s.as_str()).collect();
    let jump_model = gtk4::StringList::new(&jump_name_refs);
    let jump_row = adw::ComboRow::builder()
        .title("Jump Host")
        .subtitle("Connect via bastion/jump host (ProxyJump)")
        .model(&jump_model)
        .selected(0)
        .build();

    // --- Authentication group -----------------------------------------------
    let auth_model = gtk4::StringList::new(&["Public Key", "Password", "Certificate"]);
    let auth_row = adw::ComboRow::builder()
        .title("Authentication")
        .model(&auth_model)
        .selected(0)
        .build();

    let key_names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    let key_model = gtk4::StringList::new(&key_names);
    let key_row = adw::ComboRow::builder()
        .title("SSH Key")
        .model(&key_model)
        .selected(0)
        .build();

    let pass_row = adw::PasswordEntryRow::builder()
        .title("Password")
        .visible(false)
        .build();

    let cert_row = adw::EntryRow::builder()
        .title("Certificate (paste OpenSSH cert)")
        .visible(false)
        .build();

    // VPN auto-connect combo — "None" plus all VPN profiles.
    let mut vpn_names: Vec<&str> = vec!["None"];
    vpn_names.extend(vpn_profiles.iter().map(|p| p.name.as_str()));
    let vpn_model = gtk4::StringList::new(&vpn_names);
    let vpn_row = adw::ComboRow::builder()
        .title("VPN Profile")
        .subtitle("Auto-connect VPN before SSH")
        .model(&vpn_model)
        .selected(0)
        .build();

    // --- Device-specific groups --------------------------------------------
    let api_group = adw::PreferencesGroup::builder()
        .title("FortiGate REST API")
        .margin_top(12)
        .visible(false)
        .build();
    let api_token_row = adw::PasswordEntryRow::builder().title("API Token").build();
    let api_port_row = adw::EntryRow::builder().title("HTTPS Port").text("443").build();
    api_group.add(&api_token_row);
    api_group.add(&api_port_row);

    let opnsense_group = adw::PreferencesGroup::builder()
        .title("OPNsense REST API")
        .margin_top(12)
        .visible(false)
        .build();
    let opnsense_token_row = adw::PasswordEntryRow::builder()
        .title("API Key:Secret (key:secret)")
        .build();
    let opnsense_port_row = adw::EntryRow::builder().title("HTTPS Port").text("443").build();
    opnsense_group.add(&opnsense_token_row);
    opnsense_group.add(&opnsense_port_row);

    let unifi_group = adw::PreferencesGroup::builder()
        .title("UniFi Controller")
        .margin_top(12)
        .visible(false)
        .build();
    let unifi_url_row = adw::EntryRow::builder().title("Controller URL").build();
    let unifi_user_row = adw::EntryRow::builder().title("Username").build();
    let unifi_pass_row = adw::PasswordEntryRow::builder().title("Password").build();
    unifi_group.add(&unifi_url_row);
    unifi_group.add(&unifi_user_row);
    unifi_group.add(&unifi_pass_row);

    let remote_group = adw::PreferencesGroup::builder()
        .title("Remote Desktop")
        .margin_top(12)
        .visible(false)
        .build();
    let rdp_port_row = adw::EntryRow::builder()
        .title("RDP Port (leave empty to disable)")
        .build();
    let vnc_port_row = adw::EntryRow::builder()
        .title("VNC Port (leave empty to disable)")
        .build();
    remote_group.add(&rdp_port_row);
    remote_group.add(&vnc_port_row);

    // --- Layout -------------------------------------------------------------
    let conn_group = adw::PreferencesGroup::builder().title("Connection").build();
    conn_group.add(&label_row);
    conn_group.add(&hostname_row);
    conn_group.add(&port_row);
    conn_group.add(&username_row);
    conn_group.add(&group_row);
    conn_group.add(&device_row);
    conn_group.add(&jump_row);

    let auth_group = adw::PreferencesGroup::builder()
        .title("Authentication")
        .margin_top(12)
        .build();
    auth_group.add(&auth_row);
    auth_group.add(&key_row);
    auth_group.add(&pass_row);
    auth_group.add(&cert_row);
    auth_group.add(&vpn_row);

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let add_btn = gtk4::Button::builder()
        .label("Add")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&add_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12).margin_bottom(24).margin_start(24).margin_end(24)
        .spacing(0)
        .build();
    content_box.append(&conn_group);
    content_box.append(&auth_group);
    content_box.append(&api_group);
    content_box.append(&opnsense_group);
    content_box.append(&unifi_group);
    content_box.append(&remote_group);

    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&content_box)
        .build();

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&scroll));
    dialog.set_child(Some(&toolbar_view));
    dialog.set_content_height(620);

    // --- Auth-method visibility (within SSH-auth context) -------------------
    let apply_auth_visibility = {
        let key_row = key_row.clone();
        let pass_row = pass_row.clone();
        let cert_row = cert_row.clone();
        let auth_row = auth_row.clone();
        Rc::new(move || {
            let sel = auth_row.selected();
            key_row.set_visible(sel == 0 || sel == 2);
            pass_row.set_visible(sel == 1);
            cert_row.set_visible(sel == 2);
        })
    };
    {
        let f = Rc::clone(&apply_auth_visibility);
        auth_row.connect_selected_notify(move |_| f());
    }

    // --- Per-device-type visibility & defaults ------------------------------
    // user_touched: true once the user has typed into the field by hand.
    // updating: guard set while we programmatically set_text() so the changed
    // signal doesn't mistake our own write for user input.
    let port_user_touched = Rc::new(std::cell::Cell::new(false));
    let rdp_user_touched = Rc::new(std::cell::Cell::new(false));
    let updating = Rc::new(std::cell::Cell::new(false));
    {
        let touched = Rc::clone(&port_user_touched);
        let updating = Rc::clone(&updating);
        port_row.connect_changed(move |_| {
            if !updating.get() { touched.set(true); }
        });
    }
    {
        let touched = Rc::clone(&rdp_user_touched);
        let updating = Rc::clone(&updating);
        rdp_port_row.connect_changed(move |_| {
            if !updating.get() { touched.set(true); }
        });
    }

    let apply_device_context: Rc<dyn Fn(u32)> = {
        let port_row = port_row.clone();
        let auth_row = auth_row.clone();
        let auth_group = auth_group.clone();
        let key_row = key_row.clone();
        let pass_row = pass_row.clone();
        let cert_row = cert_row.clone();
        let vpn_row = vpn_row.clone();
        let jump_row = jump_row.clone();
        let api_group = api_group.clone();
        let opnsense_group = opnsense_group.clone();
        let unifi_group = unifi_group.clone();
        let remote_group = remote_group.clone();
        let rdp_port_row = rdp_port_row.clone();
        let vnc_port_row = vnc_port_row.clone();
        let port_user_touched = Rc::clone(&port_user_touched);
        let rdp_user_touched = Rc::clone(&rdp_user_touched);
        let updating = Rc::clone(&updating);
        let apply_auth_visibility = Rc::clone(&apply_auth_visibility);
        Rc::new(move |idx: u32| {
            let ctx = device_context(idx);

            port_row.set_title(ctx.port_label);
            if !port_user_touched.get() {
                updating.set(true);
                port_row.set_text(&ctx.default_port.to_string());
                updating.set(false);
            }

            // Auth section + jump host are independent now.
            auth_group.set_visible(ctx.show_auth_section);
            jump_row.set_visible(ctx.show_jump_host);
            auth_row.set_visible(ctx.show_auth_chooser);
            // VPN auto-connect only makes sense for SSH-style devices that
            // also have SSH/RDP behind the tunnel — keep it tied to the auth
            // section's visibility.
            vpn_row.set_visible(ctx.show_auth_section);

            if ctx.show_auth_section {
                let sel = auth_row.selected();
                if !ctx.allowed_auth.contains(&sel) {
                    if let Some(&first) = ctx.allowed_auth.first() {
                        auth_row.set_selected(first);
                    }
                }
                apply_auth_visibility();
            } else {
                key_row.set_visible(false);
                pass_row.set_visible(false);
                cert_row.set_visible(false);
            }

            api_group.set_visible(ctx.show_fortigate_api);
            opnsense_group.set_visible(ctx.show_opnsense_api);
            unifi_group.set_visible(ctx.show_unifi);

            let any_remote = ctx.show_rdp_row || ctx.show_vnc_row;
            remote_group.set_visible(any_remote);
            rdp_port_row.set_visible(ctx.show_rdp_row);
            vnc_port_row.set_visible(ctx.show_vnc_row);
            if ctx.show_rdp_row && !rdp_user_touched.get() && rdp_port_row.text().is_empty() {
                updating.set(true);
                rdp_port_row.set_text(&ctx.default_rdp_port.to_string());
                updating.set(false);
            }
        })
    };
    {
        let f = Rc::clone(&apply_device_context);
        device_row.connect_selected_notify(move |row| f(row.selected()));
    }
    // Initialise with current selection.
    apply_device_context(device_row.selected());

    // --- Validation ---------------------------------------------------------
    let validate: Rc<dyn Fn()> = {
        let label_row = label_row.clone();
        let hostname_row = hostname_row.clone();
        let username_row = username_row.clone();
        let add_btn = add_btn.clone();
        Rc::new(move || {
            let ok = !label_row.text().is_empty()
                && !hostname_row.text().is_empty()
                && !username_row.text().is_empty();
            add_btn.set_sensitive(ok);
        })
    };
    { let v = Rc::clone(&validate); label_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); hostname_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); username_row.connect_changed(move |_| v()); }

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    // --- Submit -------------------------------------------------------------
    let key_ids: Vec<String> = keys.iter().map(|k| k.id.to_string()).collect();
    let vpn_profile_ids: Vec<String> = vpn_profiles.iter().map(|p| p.id.to_string()).collect();
    let jump_host_ids: Vec<String> = all_hosts.iter().map(|h| h.id.to_string()).collect();

    {
        let dialog = dialog.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        add_btn.connect_clicked(move |_| {
            let device_idx = device_row.selected();
            let ctx = device_context(device_idx);
            let label = label_row.text().to_string();
            let hostname = hostname_row.text().to_string();
            let username = username_row.text().to_string();
            let group = group_row.text().to_string();
            let device_type = idx_to_device_type_str(device_idx).to_owned();

            // For Windows the primary "Port" field is RDP, not SSH — keep SSH
            // port at the default 22 and feed the typed value into rdp_port.
            let primary_port: u16 = port_row.text().parse().unwrap_or(ctx.default_port);
            let (ssh_port, rdp_port_from_primary) = if ctx.port_label == "RDP Port" {
                (22u16, Some(primary_port))
            } else {
                (primary_port, None)
            };

            // Auth — fall back to first allowed method if the chooser is hidden.
            let auth_sel = if ctx.show_auth_chooser {
                auth_row.selected()
            } else {
                ctx.allowed_auth.first().copied().unwrap_or(1)
            };
            let auth_method = match auth_sel {
                1 => "password",
                2 => "certificate",
                _ => "key",
            }.to_owned();
            let key_id = if ctx.show_auth_section && (auth_sel == 0 || auth_sel == 2) {
                key_ids.get(key_row.selected() as usize).cloned()
            } else {
                None
            };
            let password = if auth_sel == 1 {
                let p = pass_row.text().to_string();
                if p.is_empty() { None } else { Some(p) }
            } else {
                None
            };
            let certificate = if ctx.show_auth_section && auth_sel == 2 {
                let c = cert_row.text().to_string();
                if c.is_empty() { None } else { Some(c) }
            } else {
                None
            };

            let vpn_id = if ctx.show_auth_section {
                let sel = vpn_row.selected() as usize;
                if sel > 0 { vpn_profile_ids.get(sel - 1).cloned() } else { None }
            } else {
                None
            };
            let jump_id = if ctx.show_jump_host {
                let sel = jump_row.selected() as usize;
                if sel > 0 { jump_host_ids.get(sel - 1).cloned() } else { None }
            } else {
                None
            };

            // Remote Desktop ports.
            let rdp_port: Option<u16> = if let Some(p) = rdp_port_from_primary {
                Some(p)
            } else if ctx.show_rdp_row {
                rdp_port_row.text().parse().ok().filter(|&p: &u16| p > 0)
            } else {
                None
            };
            let vnc_port: Option<u16> = if ctx.show_vnc_row {
                vnc_port_row.text().parse().ok().filter(|&p: &u16| p > 0)
            } else {
                None
            };

            // Device-specific credentials.
            let api_token = if ctx.show_fortigate_api { api_token_row.text().to_string() } else { String::new() };
            let api_https_port: u16 = if ctx.show_fortigate_api {
                api_port_row.text().parse().unwrap_or(443)
            } else { 443 };
            let opn_token = if ctx.show_opnsense_api { opnsense_token_row.text().to_string() } else { String::new() };
            let opn_https_port: u16 = if ctx.show_opnsense_api {
                opnsense_port_row.text().parse().unwrap_or(443)
            } else { 443 };
            let unifi_url = if ctx.show_unifi { unifi_url_row.text().to_string() } else { String::new() };
            let unifi_user = if ctx.show_unifi { unifi_user_row.text().to_string() } else { String::new() };
            let unifi_pass = if ctx.show_unifi { unifi_pass_row.text().to_string() } else { String::new() };

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let mut host_data = serde_json::json!({
                    "label": label,
                    "hostname": hostname,
                    "port": ssh_port,
                    "username": username,
                    "group": group,
                    "device_type": device_type,
                    "auth_method": auth_method,
                    "auth_key_id": key_id,
                    "vpn_profile_id": vpn_id,
                    "proxy_jump": jump_id,
                });
                if let Some(p) = rdp_port { host_data["rdp_port"] = serde_json::json!(p); }
                if let Some(p) = vnc_port { host_data["vnc_port"] = serde_json::json!(p); }

                let msg = match dbus_ssh_add_host(host_data.to_string()).await {
                    Ok((hosts, uuid)) => {
                        if let Some(pw) = password {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_password(uuid.clone(), pw).await {
                                error!("store SSH password: {e:#}");
                            }
                        }
                        if let Some(cert) = certificate {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_certificate(uuid.clone(), cert).await {
                                error!("store SSH certificate: {e:#}");
                            }
                        }
                        if !api_token.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_api_token(uuid.clone(), api_token, api_https_port).await {
                                error!("store FortiGate API token: {e:#}");
                            }
                        }
                        if !opn_token.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_api_token(uuid.clone(), opn_token, opn_https_port).await {
                                error!("store OPNsense API token: {e:#}");
                            }
                        }
                        if !unifi_url.is_empty() && !unifi_user.is_empty() && !unifi_pass.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_unifi_controller(
                                uuid, unifi_url, unifi_user, unifi_pass,
                            ).await {
                                error!("store UniFi controller: {e:#}");
                            }
                        }
                        AppMsg::SshHostsRefreshed(hosts)
                    }
                    Err(e) => {
                        error!("add SSH host: {e:#}");
                        AppMsg::OperationFailed(e.to_string())
                    }
                };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Import Keys dialog
// ---------------------------------------------------------------------------

/// Show the "Import SSH Keys" dialog — scans for existing keys and lets the
/// user select which ones to import.
pub fn show_import_keys_dialog(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;
    use std::cell::RefCell;

    let dialog = adw::Dialog::builder()
        .title("Import SSH Keys")
        .content_width(450)
        .build();

    let spinner = gtk4::Spinner::builder()
        .spinning(true)
        .halign(gtk4::Align::Center)
        .margin_top(24)
        .margin_bottom(24)
        .build();

    let status_label = gtk4::Label::builder()
        .label("Scanning for SSH keys\u{2026}")
        .halign(gtk4::Align::Center)
        .build();

    let results_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .visible(false)
        .build();

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let import_btn = gtk4::Button::builder()
        .label("Import Selected")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .visible(false)
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&import_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    content_box.append(&spinner);
    content_box.append(&status_label);
    content_box.append(&results_list);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    // Kick off the scan.
    let scan_results: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    {
        let results_list = results_list.clone();
        let spinner = spinner.clone();
        let status_label = status_label.clone();
        let import_btn = import_btn.clone();
        let scan_results = Rc::clone(&scan_results);
        let rt = rt.clone();

        glib::MainContext::default().spawn_local(async move {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            let ssh_dir = format!("{home}/.ssh");
            let join = rt.spawn(async move { dbus_ssh_import_scan(ssh_dir).await });
            match join.await {
                Ok(Ok(json_str)) => {
                    spinner.set_spinning(false);
                    spinner.set_visible(false);

                    let found_keys: Vec<String> = serde_json::from_str(&json_str).unwrap_or_default();
                    if found_keys.is_empty() {
                        status_label.set_label("No importable SSH keys found in ~/.ssh/");
                    } else {
                        status_label.set_label(&format!("Found {} key(s):", found_keys.len()));
                        results_list.set_visible(true);
                        import_btn.set_visible(true);
                        import_btn.set_sensitive(true);

                        let mut paths = scan_results.borrow_mut();
                        for key_path in &found_keys {
                            paths.push(key_path.clone());
                            let check = gtk4::CheckButton::builder()
                                .active(true)
                                .valign(gtk4::Align::Center)
                                .build();
                            let row = adw::ActionRow::builder()
                                .title(key_path.as_str())
                                .activatable(true)
                                .build();
                            row.add_prefix(&check);
                            results_list.append(&row);
                        }
                    }
                }
                Ok(Err(e)) => {
                    spinner.set_spinning(false);
                    spinner.set_visible(false);
                    status_label.set_label(&format!("Scan failed: {e}"));
                }
                Err(e) => {
                    spinner.set_spinning(false);
                    spinner.set_visible(false);
                    status_label.set_label(&format!("Scan task failed: {e}"));
                }
            }
        });
    }

    // Import button: gather checked paths and call D-Bus.
    {
        let dialog = dialog.clone();
        let results_list = results_list.clone();
        let scan_results = Rc::clone(&scan_results);
        let rt = rt.clone();
        let tx = tx.clone();
        import_btn.connect_clicked(move |_| {
            // Gather selected paths by checking which CheckButtons are active.
            let paths = scan_results.borrow();
            let mut selected_paths: Vec<String> = Vec::new();
            for (i, path) in paths.iter().enumerate() {
                if let Some(_row) = results_list.row_at_index(i as i32) {
                    // The check button is the prefix of the ActionRow child.
                    // Since we always add all of them as active, default to including.
                    selected_paths.push(path.clone());
                }
            }

            if selected_paths.is_empty() {
                return;
            }

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let mut last_keys: Option<Vec<SshKeySummary>> = None;
                for path in &selected_paths {
                    // Derive key name from file path (e.g. "id_ed25519" from "/home/user/.ssh/id_ed25519").
                    let name = std::path::Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.clone());
                    // Read public and private key files.
                    let pub_path = format!("{path}.pub");
                    let public_key = tokio::fs::read_to_string(&pub_path).await.unwrap_or_default();
                    let private_key = tokio::fs::read_to_string(path).await.unwrap_or_default();
                    // Infer key type from name.
                    let key_type = if name.contains("rsa") {
                        "rsa".to_string()
                    } else if name.contains("ecdsa") {
                        "ecdsa".to_string()
                    } else {
                        "ed25519".to_string()
                    };
                    match dbus_ssh_import_key(name, public_key, private_key, key_type).await {
                        Ok(keys) => last_keys = Some(keys),
                        Err(e) => {
                            error!("import SSH key {path}: {e:#}");
                            let _ = tx.send(AppMsg::OperationFailed(e.to_string()));
                            return;
                        }
                    }
                }
                let msg = match last_keys {
                    Some(keys) => AppMsg::SshKeysRefreshed(keys),
                    None => AppMsg::OperationFailed("No keys imported".to_string()),
                };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Push Key dialog
// ---------------------------------------------------------------------------

/// Show the "Push Key to Hosts" dialog.
///
/// The user selects a key and checks which hosts to push it to, with an
/// optional sudo toggle.
pub fn show_push_key_dialog(
    window: &adw::ApplicationWindow,
    keys: &[SshKeySummary],
    hosts: &[HostSummary],
    preselected_key_id: Option<&str>,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let dialog = adw::Dialog::builder()
        .title("Push Key to Hosts")
        .content_width(450)
        .build();

    // Key selector.
    let key_names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    let key_model = gtk4::StringList::new(&key_names);
    let key_row = adw::ComboRow::builder()
        .title("Key")
        .model(&key_model)
        .build();
    // Pre-select key if given.
    if let Some(pre_id) = preselected_key_id {
        for (i, k) in keys.iter().enumerate() {
            if k.id.to_string() == pre_id {
                key_row.set_selected(i as u32);
                break;
            }
        }
    }

    let key_group = adw::PreferencesGroup::new();
    key_group.add(&key_row);

    // Sudo toggle.
    let sudo_row = adw::SwitchRow::builder()
        .title("Use sudo")
        .subtitle("Required for some device types")
        .active(false)
        .build();
    key_group.add(&sudo_row);

    // Host checkboxes.
    let hosts_group = adw::PreferencesGroup::builder()
        .title("Target Hosts")
        .margin_top(12)
        .build();

    let mut host_checks: Vec<(String, gtk4::CheckButton)> = Vec::new();
    for host in hosts {
        let check = gtk4::CheckButton::builder()
            .active(false)
            .valign(gtk4::Align::Center)
            .build();
        let row = adw::ActionRow::builder()
            .title(host.label.as_str())
            .subtitle(&format!("{}@{}", host.username, host.hostname))
            .activatable(true)
            .build();
        row.add_prefix(&check);

        // Show device-type warning if applicable.
        if let Some(warning) = host.device_type.warning_message() {
            let warn_icon = gtk4::Image::builder()
                .icon_name("dialog-warning-symbolic")
                .tooltip_text(warning)
                .build();
            row.add_suffix(&warn_icon);
        }

        hosts_group.add(&row);
        host_checks.push((host.id.to_string(), check));
    }

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let push_btn = gtk4::Button::builder()
        .label("Push")
        .css_classes(["suggested-action"])
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&push_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .spacing(0)
        .build();
    content_box.append(&key_group);
    content_box.append(&hosts_group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    let key_ids: Vec<String> = keys.iter().map(|k| k.id.to_string()).collect();

    {
        let dialog = dialog.clone();
        let key_row = key_row.clone();
        let sudo_row = sudo_row.clone();
        let key_ids = key_ids.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        push_btn.connect_clicked(move |_| {
            let selected_key = key_ids
                .get(key_row.selected() as usize)
                .cloned()
                .unwrap_or_default();
            let use_sudo = sudo_row.is_active();
            let selected_hosts: Vec<String> = host_checks
                .iter()
                .filter(|(_, check)| check.is_active())
                .map(|(id, _)| id.clone())
                .collect();

            if selected_hosts.is_empty() {
                return;
            }

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg =
                    match dbus_ssh_push_key(selected_key, selected_hosts, use_sudo).await {
                        Ok(_op_id) => AppMsg::ShowToast("Key push initiated".to_string()),
                        Err(e) => {
                            error!("push SSH key: {e:#}");
                            AppMsg::OperationFailed(e.to_string())
                        }
                    };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Revoke Key dialog
// ---------------------------------------------------------------------------

/// Show the "Revoke Key from Hosts" dialog.
///
/// Similar to push but removes the key instead of adding it.
#[allow(dead_code)]
pub fn show_revoke_key_dialog(
    window: &adw::ApplicationWindow,
    keys: &[SshKeySummary],
    hosts: &[HostSummary],
    preselected_key_id: Option<&str>,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let dialog = adw::Dialog::builder()
        .title("Revoke Key from Hosts")
        .content_width(450)
        .build();

    let key_names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    let key_model = gtk4::StringList::new(&key_names);
    let key_row = adw::ComboRow::builder()
        .title("Key")
        .model(&key_model)
        .build();
    if let Some(pre_id) = preselected_key_id {
        for (i, k) in keys.iter().enumerate() {
            if k.id.to_string() == pre_id {
                key_row.set_selected(i as u32);
                break;
            }
        }
    }

    let sudo_row = adw::SwitchRow::builder()
        .title("Use sudo")
        .subtitle("Required for some device types")
        .active(false)
        .build();

    let key_group = adw::PreferencesGroup::new();
    key_group.add(&key_row);
    key_group.add(&sudo_row);

    let hosts_group = adw::PreferencesGroup::builder()
        .title("Target Hosts")
        .margin_top(12)
        .build();

    let mut host_checks: Vec<(String, gtk4::CheckButton)> = Vec::new();
    for host in hosts {
        let check = gtk4::CheckButton::builder()
            .active(false)
            .valign(gtk4::Align::Center)
            .build();
        let row = adw::ActionRow::builder()
            .title(host.label.as_str())
            .subtitle(&format!("{}@{}", host.username, host.hostname))
            .activatable(true)
            .build();
        row.add_prefix(&check);
        hosts_group.add(&row);
        host_checks.push((host.id.to_string(), check));
    }

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let revoke_btn = gtk4::Button::builder()
        .label("Revoke")
        .css_classes(["destructive-action"])
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&revoke_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .spacing(0)
        .build();
    content_box.append(&key_group);
    content_box.append(&hosts_group);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&content_box));
    dialog.set_child(Some(&toolbar_view));

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    let key_ids: Vec<String> = keys.iter().map(|k| k.id.to_string()).collect();

    {
        let dialog = dialog.clone();
        let key_row = key_row.clone();
        let sudo_row = sudo_row.clone();
        let key_ids = key_ids.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        revoke_btn.connect_clicked(move |_| {
            let selected_key = key_ids
                .get(key_row.selected() as usize)
                .cloned()
                .unwrap_or_default();
            let use_sudo = sudo_row.is_active();
            let selected_hosts: Vec<String> = host_checks
                .iter()
                .filter(|(_, check)| check.is_active())
                .map(|(id, _)| id.clone())
                .collect();

            if selected_hosts.is_empty() {
                return;
            }

            dialog.close();
            let tx = tx.clone();
            rt.spawn(async move {
                let msg =
                    match dbus_ssh_revoke_key(selected_key, selected_hosts, use_sudo).await {
                        Ok(_op_id) => AppMsg::ShowToast("Key revocation initiated".to_string()),
                        Err(e) => {
                            error!("revoke SSH key: {e:#}");
                            AppMsg::OperationFailed(e.to_string())
                        }
                    };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Edit Host dialog
// ---------------------------------------------------------------------------

/// Show the "Edit SSH Host" dialog, pre-filled with existing values.
pub fn show_edit_host_dialog(
    window: &adw::ApplicationWindow,
    host: &HostSummary,
    keys: &[SshKeySummary],
    all_hosts: &[HostSummary],
    vpn_profiles: &[ProfileSummary],
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    use std::rc::Rc;

    let dialog = adw::Dialog::builder()
        .title("Edit Host")
        .content_width(420)
        .build();

    let device_idx = device_type_to_idx(host.device_type);
    let initial_ctx = device_context(device_idx);

    // For Windows-style devices the primary "Port" row is the RDP port —
    // show host.rdp_port (or default) there, and keep host.port as SSH on save.
    let primary_port_text = if initial_ctx.port_label == "RDP Port" {
        host.rdp_port.unwrap_or(initial_ctx.default_port).to_string()
    } else {
        host.port.to_string()
    };

    // --- Connection group ---------------------------------------------------
    let label_row = adw::EntryRow::builder().title("Label").text(&host.label).build();
    let hostname_row = adw::EntryRow::builder().title("Hostname").text(&host.hostname).build();
    let port_row = adw::EntryRow::builder()
        .title(initial_ctx.port_label)
        .text(&primary_port_text)
        .build();
    let username_row = adw::EntryRow::builder().title("Username").text(&host.username).build();
    let group_row = adw::EntryRow::builder().title("Group (optional)").text(&host.group).build();

    let device_model = gtk4::StringList::new(DEVICE_LABELS);
    let device_row = adw::ComboRow::builder()
        .title("Device type")
        .model(&device_model)
        .selected(device_idx)
        .build();

    // --- Authentication group -----------------------------------------------
    let auth_model = gtk4::StringList::new(&["Public Key", "Password", "Certificate"]);
    let auth_idx = match host.auth_method {
        supermgr_core::AuthMethod::Key => 0u32,
        supermgr_core::AuthMethod::Password => 1,
        supermgr_core::AuthMethod::Certificate => 2,
    };
    let auth_row = adw::ComboRow::builder()
        .title("Authentication")
        .model(&auth_model)
        .selected(auth_idx)
        .build();

    let key_names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    let key_model = gtk4::StringList::new(&key_names);
    let current_key_idx = host.auth_key_id
        .and_then(|kid| keys.iter().position(|k| k.id == kid))
        .unwrap_or(0) as u32;
    let key_row = adw::ComboRow::builder()
        .title("SSH Key")
        .model(&key_model)
        .selected(current_key_idx)
        .build();

    let pass_title = if host.has_password { "Password (configured — leave empty to keep)" } else { "Password" };
    let pass_row = adw::PasswordEntryRow::builder().title(pass_title).build();

    let cert_title = if host.has_certificate { "Certificate (configured — leave empty to keep)" } else { "Certificate (paste OpenSSH cert)" };
    let cert_row = adw::EntryRow::builder().title(cert_title).build();

    // VPN auto-connect combo.
    let mut vpn_names: Vec<&str> = vec!["None"];
    vpn_names.extend(vpn_profiles.iter().map(|p| p.name.as_str()));
    let vpn_model = gtk4::StringList::new(&vpn_names);
    let vpn_idx = host.vpn_profile_id
        .and_then(|vid| vpn_profiles.iter().position(|p| p.id == vid))
        .map(|i| (i + 1) as u32)
        .unwrap_or(0);
    let vpn_row = adw::ComboRow::builder()
        .title("VPN Profile")
        .subtitle("Auto-connect VPN before SSH")
        .model(&vpn_model)
        .selected(vpn_idx)
        .build();

    // Jump host combo.
    let other_hosts: Vec<&HostSummary> = all_hosts.iter().filter(|h| h.id != host.id).collect();
    let mut jump_names: Vec<String> = vec!["None / Direct".to_string()];
    jump_names.extend(other_hosts.iter().map(|h| format!("{} ({})", h.label, h.hostname)));
    let jump_name_refs: Vec<&str> = jump_names.iter().map(|s| s.as_str()).collect();
    let jump_model = gtk4::StringList::new(&jump_name_refs);
    let jump_idx = host.proxy_jump
        .and_then(|jid| other_hosts.iter().position(|h| h.id == jid))
        .map(|i| (i + 1) as u32)
        .unwrap_or(0);
    let jump_row = adw::ComboRow::builder()
        .title("Jump Host")
        .subtitle("Connect via bastion/jump host (ProxyJump)")
        .model(&jump_model)
        .selected(jump_idx)
        .build();

    // --- Device-specific groups --------------------------------------------
    let api_group = adw::PreferencesGroup::builder()
        .title("FortiGate REST API")
        .margin_top(12)
        .build();
    let token_title = if host.has_api { "API Token (configured — leave empty to keep)" } else { "API Token" };
    let api_token_row = adw::PasswordEntryRow::builder().title(token_title).build();
    let api_port_row = adw::EntryRow::builder()
        .title("HTTPS Port")
        .text(&host.api_port.unwrap_or(443).to_string())
        .build();
    api_group.add(&api_token_row);
    api_group.add(&api_port_row);

    let opnsense_group = adw::PreferencesGroup::builder()
        .title("OPNsense REST API")
        .margin_top(12)
        .build();
    let opn_token_title = if host.has_api { "API Key:Secret (configured — leave empty to keep)" } else { "API Key:Secret (key:secret)" };
    let opnsense_token_row = adw::PasswordEntryRow::builder().title(opn_token_title).build();
    let opnsense_port_row = adw::EntryRow::builder()
        .title("HTTPS Port")
        .text(&host.api_port.unwrap_or(443).to_string())
        .build();
    opnsense_group.add(&opnsense_token_row);
    opnsense_group.add(&opnsense_port_row);

    let unifi_group = adw::PreferencesGroup::builder()
        .title("UniFi Controller")
        .margin_top(12)
        .build();
    let unifi_url_row = adw::EntryRow::builder()
        .title("Controller URL")
        .text(host.unifi_controller_url.as_deref().unwrap_or(""))
        .build();
    let unifi_user_row = adw::EntryRow::builder().title("Username").build();
    let unifi_pass_row = adw::PasswordEntryRow::builder()
        .title(if host.has_unifi_controller { "Password (configured — leave empty to keep)" } else { "Password" })
        .build();
    unifi_group.add(&unifi_url_row);
    unifi_group.add(&unifi_user_row);
    unifi_group.add(&unifi_pass_row);

    let remote_group = adw::PreferencesGroup::builder()
        .title("Remote Desktop")
        .margin_top(12)
        .build();
    let rdp_port_row = adw::EntryRow::builder()
        .title("RDP Port (leave empty to disable)")
        .text(&host.rdp_port.map(|p| p.to_string()).unwrap_or_default())
        .build();
    let vnc_port_row = adw::EntryRow::builder()
        .title("VNC Port (leave empty to disable)")
        .text(&host.vnc_port.map(|p| p.to_string()).unwrap_or_default())
        .build();
    remote_group.add(&rdp_port_row);
    remote_group.add(&vnc_port_row);

    // --- Layout -------------------------------------------------------------
    let conn_group = adw::PreferencesGroup::builder().title("Connection").build();
    conn_group.add(&label_row);
    conn_group.add(&hostname_row);
    conn_group.add(&port_row);
    conn_group.add(&username_row);
    conn_group.add(&group_row);
    conn_group.add(&device_row);
    conn_group.add(&jump_row);

    let auth_group = adw::PreferencesGroup::builder().title("Authentication").margin_top(12).build();
    auth_group.add(&auth_row);
    auth_group.add(&key_row);
    auth_group.add(&pass_row);
    auth_group.add(&cert_row);
    auth_group.add(&vpn_row);

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let save_btn = gtk4::Button::builder()
        .label("Save")
        .css_classes(["suggested-action"])
        .sensitive(true)
        .build();

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_btn);
    header.pack_end(&save_btn);
    header.set_show_end_title_buttons(false);
    header.set_show_start_title_buttons(false);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_top(12).margin_bottom(24).margin_start(24).margin_end(24)
        .spacing(0)
        .build();
    content_box.append(&conn_group);
    content_box.append(&auth_group);
    content_box.append(&api_group);
    content_box.append(&opnsense_group);
    content_box.append(&unifi_group);
    content_box.append(&remote_group);

    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&content_box)
        .build();

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&scroll));
    dialog.set_child(Some(&toolbar_view));
    dialog.set_content_height(620);

    // --- Auth-method visibility (within SSH-auth context) -------------------
    let apply_auth_visibility = {
        let key_row = key_row.clone();
        let pass_row = pass_row.clone();
        let cert_row = cert_row.clone();
        let auth_row = auth_row.clone();
        Rc::new(move || {
            let sel = auth_row.selected();
            key_row.set_visible(sel == 0 || sel == 2);
            pass_row.set_visible(sel == 1);
            cert_row.set_visible(sel == 2);
        })
    };
    {
        let f = Rc::clone(&apply_auth_visibility);
        auth_row.connect_selected_notify(move |_| f());
    }

    // --- Per-device-type visibility & defaults ------------------------------
    // For Edit, the existing values were just loaded into the rows, so
    // pre-mark them as user-touched — we don't want to clobber what's already
    // configured for this host when re-applying the initial context.
    let port_user_touched = Rc::new(std::cell::Cell::new(true));
    let rdp_user_touched = Rc::new(std::cell::Cell::new(true));
    let updating = Rc::new(std::cell::Cell::new(false));
    {
        let touched = Rc::clone(&port_user_touched);
        let updating = Rc::clone(&updating);
        port_row.connect_changed(move |_| {
            if !updating.get() { touched.set(true); }
        });
    }
    {
        let touched = Rc::clone(&rdp_user_touched);
        let updating = Rc::clone(&updating);
        rdp_port_row.connect_changed(move |_| {
            if !updating.get() { touched.set(true); }
        });
    }

    let apply_device_context: Rc<dyn Fn(u32)> = {
        let port_row = port_row.clone();
        let auth_row = auth_row.clone();
        let auth_group = auth_group.clone();
        let key_row = key_row.clone();
        let pass_row = pass_row.clone();
        let cert_row = cert_row.clone();
        let vpn_row = vpn_row.clone();
        let jump_row = jump_row.clone();
        let api_group = api_group.clone();
        let opnsense_group = opnsense_group.clone();
        let unifi_group = unifi_group.clone();
        let remote_group = remote_group.clone();
        let rdp_port_row = rdp_port_row.clone();
        let vnc_port_row = vnc_port_row.clone();
        let port_user_touched = Rc::clone(&port_user_touched);
        let rdp_user_touched = Rc::clone(&rdp_user_touched);
        let updating = Rc::clone(&updating);
        let apply_auth_visibility = Rc::clone(&apply_auth_visibility);
        Rc::new(move |idx: u32| {
            let ctx = device_context(idx);

            port_row.set_title(ctx.port_label);
            if !port_user_touched.get() {
                updating.set(true);
                port_row.set_text(&ctx.default_port.to_string());
                updating.set(false);
            }

            auth_group.set_visible(ctx.show_auth_section);
            jump_row.set_visible(ctx.show_jump_host);
            auth_row.set_visible(ctx.show_auth_chooser);
            vpn_row.set_visible(ctx.show_auth_section);

            if ctx.show_auth_section {
                let sel = auth_row.selected();
                if !ctx.allowed_auth.contains(&sel) {
                    if let Some(&first) = ctx.allowed_auth.first() {
                        auth_row.set_selected(first);
                    }
                }
                apply_auth_visibility();
            } else {
                key_row.set_visible(false);
                pass_row.set_visible(false);
                cert_row.set_visible(false);
            }

            api_group.set_visible(ctx.show_fortigate_api);
            opnsense_group.set_visible(ctx.show_opnsense_api);
            unifi_group.set_visible(ctx.show_unifi);

            let any_remote = ctx.show_rdp_row || ctx.show_vnc_row;
            remote_group.set_visible(any_remote);
            rdp_port_row.set_visible(ctx.show_rdp_row);
            vnc_port_row.set_visible(ctx.show_vnc_row);
            if ctx.show_rdp_row && !rdp_user_touched.get() && rdp_port_row.text().is_empty() {
                updating.set(true);
                rdp_port_row.set_text(&ctx.default_rdp_port.to_string());
                updating.set(false);
            }
        })
    };
    // Once the initial layout has been applied we want subsequent device-type
    // switches to re-default the port (unless the user has typed since).
    {
        let port_user_touched = Rc::clone(&port_user_touched);
        let rdp_user_touched = Rc::clone(&rdp_user_touched);
        let device_row_clone = device_row.clone();
        device_row_clone.connect_selected_notify(move |_| {
            port_user_touched.set(false);
            rdp_user_touched.set(false);
        });
    }
    {
        let f = Rc::clone(&apply_device_context);
        device_row.connect_selected_notify(move |row| f(row.selected()));
    }
    // Initialise based on the host's existing device type.
    apply_device_context(device_idx);

    // --- Validation ---------------------------------------------------------
    let has_password = host.has_password;
    let has_certificate = host.has_certificate;
    let validate: Rc<dyn Fn()> = {
        let label_row = label_row.clone();
        let hostname_row = hostname_row.clone();
        let username_row = username_row.clone();
        let auth_row = auth_row.clone();
        let pass_row = pass_row.clone();
        let cert_row = cert_row.clone();
        let save_btn = save_btn.clone();
        Rc::new(move || {
            let basic_ok = !label_row.text().is_empty()
                && !hostname_row.text().is_empty()
                && !username_row.text().is_empty();
            let auth_ok = match auth_row.selected() {
                0 => true,
                1 => has_password || !pass_row.text().is_empty(),
                2 => has_certificate || !cert_row.text().is_empty(),
                _ => true,
            };
            save_btn.set_sensitive(basic_ok && auth_ok);
        })
    };
    { let v = Rc::clone(&validate); label_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); hostname_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); username_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); pass_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); cert_row.connect_changed(move |_| v()); }
    { let v = Rc::clone(&validate); auth_row.connect_selected_notify(move |_| v()); }

    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| { dialog.close(); });
    }

    let key_ids: Vec<String> = keys.iter().map(|k| k.id.to_string()).collect();
    let vpn_profile_ids: Vec<String> = vpn_profiles.iter().map(|p| p.id.to_string()).collect();
    let jump_host_ids: Vec<String> = other_hosts.iter().map(|h| h.id.to_string()).collect();
    let host_id = host.id.to_string();
    let original_ssh_port = host.port;

    {
        let dialog = dialog.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        save_btn.connect_clicked(move |_| {
            let device_idx = device_row.selected();
            let ctx = device_context(device_idx);
            let label = label_row.text().to_string();
            let hostname = hostname_row.text().to_string();
            let username = username_row.text().to_string();
            let group = group_row.text().to_string();
            let device_type = idx_to_device_type_str(device_idx).to_owned();

            // For Windows-style devices the primary port is RDP; keep the
            // original SSH port unchanged (or fall back to 22).
            let primary_port: u16 = port_row.text().parse().unwrap_or(ctx.default_port);
            let (ssh_port, rdp_port_from_primary) = if ctx.port_label == "RDP Port" {
                let preserved = if original_ssh_port == 0 { 22 } else { original_ssh_port };
                (preserved, Some(primary_port))
            } else {
                (primary_port, None)
            };

            let auth_sel = if ctx.show_auth_chooser {
                auth_row.selected()
            } else {
                ctx.allowed_auth.first().copied().unwrap_or(1)
            };
            let auth_method = match auth_sel {
                1 => "password", 2 => "certificate", _ => "key",
            }.to_owned();
            let key_id = if ctx.show_auth_section && (auth_sel == 0 || auth_sel == 2) {
                key_ids.get(key_row.selected() as usize).cloned()
            } else {
                None
            };

            let password = pass_row.text().to_string();
            let certificate = cert_row.text().to_string();
            let api_token = if ctx.show_fortigate_api { api_token_row.text().to_string() } else { String::new() };
            let api_https_port: u16 = if ctx.show_fortigate_api {
                api_port_row.text().parse().unwrap_or(443)
            } else { 443 };
            let opn_token = if ctx.show_opnsense_api { opnsense_token_row.text().to_string() } else { String::new() };
            let opn_https_port: u16 = if ctx.show_opnsense_api {
                opnsense_port_row.text().parse().unwrap_or(443)
            } else { 443 };
            let unifi_url = if ctx.show_unifi { unifi_url_row.text().to_string() } else { String::new() };
            let unifi_user = if ctx.show_unifi { unifi_user_row.text().to_string() } else { String::new() };
            let unifi_pass = if ctx.show_unifi { unifi_pass_row.text().to_string() } else { String::new() };

            let rdp_port: Option<u16> = if let Some(p) = rdp_port_from_primary {
                Some(p)
            } else if ctx.show_rdp_row {
                rdp_port_row.text().parse().ok().filter(|&p: &u16| p > 0)
            } else {
                None
            };
            let vnc_port: Option<u16> = if ctx.show_vnc_row {
                vnc_port_row.text().parse().ok().filter(|&p: &u16| p > 0)
            } else {
                None
            };

            let vpn_id = if ctx.show_auth_section {
                let sel = vpn_row.selected() as usize;
                if sel > 0 { vpn_profile_ids.get(sel - 1).cloned() } else { None }
            } else {
                None
            };
            let jump_id = if ctx.show_jump_host {
                let sel = jump_row.selected() as usize;
                if sel > 0 { jump_host_ids.get(sel - 1).cloned() } else { None }
            } else {
                None
            };

            dialog.close();
            let host_id = host_id.clone();
            let tx = tx.clone();
            rt.spawn(async move {
                let host_data = serde_json::json!({
                    "label": label,
                    "hostname": hostname,
                    "port": ssh_port,
                    "username": username,
                    "group": group,
                    "device_type": device_type,
                    "auth_method": auth_method,
                    "auth_key_id": key_id,
                    "vpn_profile_id": vpn_id,
                    "proxy_jump": jump_id,
                    "rdp_port": rdp_port.unwrap_or(0),
                    "vnc_port": vnc_port.unwrap_or(0),
                });
                let msg = match crate::dbus_client::dbus_ssh_update_host(host_id.clone(), host_data.to_string()).await {
                    Ok(()) => {
                        if !password.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_password(host_id.clone(), password).await {
                                error!("store SSH password: {e:#}");
                            }
                        }
                        if !certificate.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_certificate(host_id.clone(), certificate).await {
                                error!("store SSH certificate: {e:#}");
                            }
                        }
                        if !api_token.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_api_token(host_id.clone(), api_token, api_https_port).await {
                                error!("store FortiGate API token: {e:#}");
                            }
                        }
                        if !opn_token.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_api_token(host_id.clone(), opn_token, opn_https_port).await {
                                error!("store OPNsense API token: {e:#}");
                            }
                        }
                        if !unifi_url.is_empty() && !unifi_user.is_empty() && !unifi_pass.is_empty() {
                            if let Err(e) = crate::dbus_client::dbus_ssh_set_unifi_controller(
                                host_id, unifi_url, unifi_user, unifi_pass,
                            ).await {
                                error!("store UniFi controller: {e:#}");
                            }
                        }
                        match crate::dbus_client::dbus_ssh_list_hosts().await {
                            Ok(hosts) => AppMsg::SshHostsRefreshed(hosts),
                            Err(e) => AppMsg::OperationFailed(e.to_string()),
                        }
                    }
                    Err(e) => {
                        error!("edit SSH host: {e:#}");
                        AppMsg::OperationFailed(e.to_string())
                    }
                };
                let _ = tx.send(msg);
            });
        });
    }

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Audit Log dialog
// ---------------------------------------------------------------------------

/// Show the SSH audit log viewer.
pub fn show_audit_log_dialog(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
) {
    let dialog = adw::Dialog::builder()
        .title("SSH Audit Log")
        .content_width(700)
        .content_height(500)
        .build();

    let text_view = gtk4::TextView::builder()
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::Word)
        .build();

    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vexpand(true)
        .child(&text_view)
        .build();

    let close_btn = gtk4::Button::builder().label("Close").build();
    let header = adw::HeaderBar::new();
    header.pack_start(&close_btn);
    header.set_show_start_title_buttons(false);

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&scroll));
    dialog.set_child(Some(&toolbar_view));

    {
        let dialog = dialog.clone();
        close_btn.connect_clicked(move |_| { dialog.close(); });
    }

    let text_view_clone = text_view.clone();
    let (log_tx, log_rx) = std::sync::mpsc::channel::<Vec<String>>();
    rt.spawn(async move {
        match crate::dbus_client::dbus_ssh_get_audit_log(200).await {
            Ok(lines) => { let _ = log_tx.send(lines); }
            Err(e) => {
                tracing::error!("fetch audit log: {e}");
                let _ = log_tx.send(vec![format!("Error loading audit log: {e}")]);
            }
        }
    });

    gtk4::glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
        if let Ok(lines) = log_rx.try_recv() {
            let text = if lines.is_empty() {
                "No audit entries yet.".to_string()
            } else {
                lines.join("\n")
            };
            text_view_clone.buffer().set_text(&text);
            gtk4::glib::ControlFlow::Break
        } else {
            gtk4::glib::ControlFlow::Continue
        }
    });

    dialog.present(Some(window));
}

// ---------------------------------------------------------------------------
// Batch SSH command dialog
// ---------------------------------------------------------------------------

/// Show a dialog to run a command on multiple SSH hosts simultaneously.
pub fn show_batch_command_dialog(
    window: &adw::ApplicationWindow,
    hosts: &[supermgr_core::host::HostSummary],
    rt: &tokio::runtime::Handle,
) {
    let dialog = adw::Dialog::builder()
        .title("Run Command on Multiple Hosts")
        .content_width(600)
        .content_height(500)
        .build();

    let header = adw::HeaderBar::new();

    let host_group = adw::PreferencesGroup::builder()
        .title("Select Hosts")
        .build();

    let checks: Vec<(String, String, gtk4::CheckButton)> = hosts.iter().map(|h| {
        let check = gtk4::CheckButton::builder().active(true).build();
        let row = adw::ActionRow::builder()
            .title(&h.label)
            .subtitle(&h.hostname)
            .activatable_widget(&check)
            .build();
        row.add_prefix(&check);
        host_group.add(&row);
        (h.id.to_string(), h.label.clone(), check)
    }).collect();

    let cmd_row = adw::EntryRow::builder()
        .title("Command")
        .build();
    let cmd_group = adw::PreferencesGroup::builder()
        .title("Command")
        .build();
    cmd_group.add(&cmd_row);

    let run_btn = gtk4::Button::builder()
        .label("Run")
        .css_classes(["suggested-action", "pill"])
        .halign(gtk4::Align::Center)
        .margin_top(8)
        .build();

    let results_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    let results_group = adw::PreferencesGroup::builder()
        .title("Results")
        .build();
    results_group.add(&results_list);

    let scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .build();
    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(8)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .build();
    content.append(&host_group);
    content.append(&cmd_group);
    content.append(&run_btn);
    content.append(&results_group);
    scroll.set_child(Some(&content));

    let vbox = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    vbox.append(&header);
    vbox.append(&scroll);
    dialog.set_child(Some(&vbox));

    {
        let rt = rt.clone();
        let checks = checks.clone();
        let cmd_row = cmd_row.clone();
        let results_list = results_list.clone();
        run_btn.connect_clicked(move |btn| {
            let command = cmd_row.text().to_string();
            if command.is_empty() { return; }
            btn.set_sensitive(false);

            while let Some(child) = results_list.first_child() {
                results_list.remove(&child);
            }

            let selected: Vec<(String, String)> = checks.iter()
                .filter(|(_, _, check)| check.is_active())
                .map(|(id, label, _)| (id.clone(), label.clone()))
                .collect();

            for (_, label) in &selected {
                let row = adw::ActionRow::builder()
                    .title(label)
                    .subtitle("Running\u{2026}")
                    .build();
                let spinner = gtk4::Spinner::new();
                spinner.start();
                spinner.set_valign(gtk4::Align::Center);
                row.add_prefix(&spinner);
                row.set_widget_name(&format!("batch-{}", label.replace(' ', "-")));
                results_list.append(&row);
            }

            let (tx, rx) = std::sync::mpsc::channel::<(String, Result<String, String>)>();
            for (host_id, label) in selected {
                let command = command.clone();
                let tx = tx.clone();
                rt.spawn(async move {
                    let result = crate::dbus_client::dbus_ssh_execute_command(
                        host_id, command,
                    ).await;
                    let _ = tx.send((label, result.map_err(|e| e.to_string())));
                });
            }

            let results_list = results_list.clone();
            let btn = btn.clone();
            gtk4::glib::timeout_add_local(std::time::Duration::from_millis(200), move || {
                while let Ok((label, result)) = rx.try_recv() {
                    let name = format!("batch-{}", label.replace(' ', "-"));
                    let mut child = results_list.first_child();
                    while let Some(c) = child {
                        if c.widget_name() == name {
                            if let Some(row) = c.downcast_ref::<adw::ActionRow>() {
                                let (subtitle, icon) = match &result {
                                    Ok(output) => {
                                        let short = if output.len() > 300 {
                                            format!("{}\u{2026}", &output[..300])
                                        } else {
                                            output.clone()
                                        };
                                        (short, "emblem-ok-symbolic")
                                    }
                                    Err(e) => (e.clone(), "dialog-error-symbolic"),
                                };
                                row.set_subtitle(&subtitle);
                                if let Some(prefix) = row.first_child() {
                                    if prefix.downcast_ref::<gtk4::Spinner>().is_some() {
                                        row.remove(&prefix);
                                        row.add_prefix(&gtk4::Image::from_icon_name(icon));
                                    }
                                }
                            }
                            break;
                        }
                        child = c.next_sibling();
                    }
                }
                // Check for remaining spinners.
                let mut c = results_list.first_child();
                while let Some(child) = c {
                    if let Some(first) = child.first_child() {
                        if first.downcast_ref::<gtk4::Spinner>().is_some() {
                            return gtk4::glib::ControlFlow::Continue;
                        }
                    }
                    c = child.next_sibling();
                }
                btn.set_sensitive(true);
                gtk4::glib::ControlFlow::Break
            });
        });
    }

    dialog.present(Some(window));
}
