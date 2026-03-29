//! SSH host detail panel.
//!
//! Shows the selected host's connection details, device type, and auth method.
//! Provides action buttons: Connect (terminal), Push Key, Edit, Delete.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::{glib, prelude::*};
use libadwaita as adw;
use libadwaita::prelude::*;
use serde_json::Value;
use tracing::{error, info, warn};

use supermgr_core::dbus::DaemonProxy;
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
    pub test_btn: gtk4::Button,
    pub push_key_btn: gtk4::Button,
    pub push_key_api_btn: gtk4::Button,
    pub edit_btn: gtk4::Button,
    pub delete_btn: gtk4::Button,
    pub pin_btn: gtk4::ToggleButton,

    // UniFi set-inform button (only visible for UniFi device type).
    pub set_inform_btn: gtk4::Button,

    // FortiGate dashboard widgets (only visible for FortiGate hosts with API).
    pub fg_dashboard_group: adw::PreferencesGroup,
    pub fg_firmware_row: adw::ActionRow,
    pub fg_update_badge: gtk4::Label,
    pub fg_hostname_row: adw::ActionRow,
    pub fg_serial_row: adw::ActionRow,
    pub fg_ha_row: adw::ActionRow,
    pub fg_cpu_row: adw::ActionRow,
    pub fg_memory_row: adw::ActionRow,
    pub fg_refresh_btn: gtk4::Button,
    pub fg_backup_btn: gtk4::Button,

    // FortiGate compliance check button (only visible for FortiGate hosts).
    pub fg_compliance_btn: gtk4::Button,
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

    // FortiGate dashboard (hidden by default).
    let fg_dashboard_group = adw::PreferencesGroup::builder()
        .title("FortiGate Dashboard")
        .margin_top(12)
        .visible(false)
        .build();

    let fg_firmware_row = adw::ActionRow::builder()
        .title("Firmware")
        .subtitle("--")
        .activatable(false)
        .build();
    let fg_update_badge = gtk4::Label::builder()
        .label("Update available")
        .css_classes(["caption", "accent"])
        .visible(false)
        .build();
    fg_firmware_row.add_suffix(&fg_update_badge);
    fg_dashboard_group.add(&fg_firmware_row);

    let fg_hostname_row = adw::ActionRow::builder()
        .title("Hostname")
        .subtitle("--")
        .activatable(false)
        .build();
    fg_dashboard_group.add(&fg_hostname_row);

    let fg_serial_row = adw::ActionRow::builder()
        .title("Serial Number")
        .subtitle("--")
        .activatable(false)
        .build();
    fg_dashboard_group.add(&fg_serial_row);

    let fg_ha_row = adw::ActionRow::builder()
        .title("HA Status")
        .subtitle("--")
        .activatable(false)
        .build();
    fg_dashboard_group.add(&fg_ha_row);

    let fg_cpu_row = adw::ActionRow::builder()
        .title("CPU Usage")
        .subtitle("--")
        .activatable(false)
        .build();
    fg_dashboard_group.add(&fg_cpu_row);

    let fg_memory_row = adw::ActionRow::builder()
        .title("Memory Usage")
        .subtitle("--")
        .activatable(false)
        .build();
    fg_dashboard_group.add(&fg_memory_row);

    let fg_btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(4)
        .build();
    let fg_refresh_btn = gtk4::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Refresh FortiGate dashboard")
        .css_classes(["flat"])
        .build();
    let fg_backup_btn = gtk4::Button::builder()
        .icon_name("document-save-symbolic")
        .tooltip_text("Backup FortiGate config")
        .css_classes(["flat"])
        .build();
    let fg_compliance_btn = gtk4::Button::builder()
        .icon_name("shield-safe-symbolic")
        .tooltip_text("CIS compliance check")
        .css_classes(["flat"])
        .build();
    fg_btn_box.append(&fg_refresh_btn);
    fg_btn_box.append(&fg_backup_btn);
    fg_btn_box.append(&fg_compliance_btn);
    fg_dashboard_group.set_header_suffix(Some(&fg_btn_box));

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
    let test_btn = gtk4::Button::builder()
        .label("Test")
        .css_classes(["flat"])
        .tooltip_text("Test SSH and API connectivity")
        .build();
    let push_key_btn = gtk4::Button::builder()
        .label("Push Key\u{2026}")
        .css_classes(["flat"])
        .build();
    let push_key_api_btn = gtk4::Button::builder()
        .label("Push Key via API\u{2026}")
        .css_classes(["flat"])
        .tooltip_text("Push SSH key to FortiGate admin via REST API")
        .visible(false)
        .build();
    let set_inform_btn = gtk4::Button::builder()
        .label("Set Inform\u{2026}")
        .css_classes(["flat"])
        .tooltip_text("Adopt this UniFi device to a controller")
        .visible(false)
        .build();
    let edit_btn = gtk4::Button::builder()
        .label("Edit\u{2026}")
        .css_classes(["flat"])
        .build();
    let delete_btn = gtk4::Button::builder()
        .label("Delete")
        .css_classes(["destructive-action"])
        .build();
    let pin_btn = gtk4::ToggleButton::builder()
        .icon_name("starred-symbolic")
        .tooltip_text("Pin / unpin this host")
        .css_classes(["flat"])
        .build();
    btn_box.append(&pin_btn);
    btn_box.append(&connect_btn);
    btn_box.append(&test_btn);
    btn_box.append(&push_key_btn);
    btn_box.append(&push_key_api_btn);
    btn_box.append(&set_inform_btn);
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
    detail_box.append(&fg_dashboard_group);

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
        test_btn,
        push_key_btn,
        push_key_api_btn,
        set_inform_btn,
        edit_btn,
        delete_btn,
        pin_btn,
        fg_dashboard_group,
        fg_firmware_row,
        fg_update_badge,
        fg_hostname_row,
        fg_serial_row,
        fg_ha_row,
        fg_cpu_row,
        fg_memory_row,
        fg_refresh_btn,
        fg_backup_btn,
        fg_compliance_btn,
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

    detail.pin_btn.set_active(host.pinned);

    // Show FortiGate dashboard and "Push Key via API" button when applicable.
    let is_fortigate_api = host.device_type == DeviceType::Fortigate && host.has_api;
    detail.fg_dashboard_group.set_visible(is_fortigate_api);
    detail.push_key_api_btn.set_visible(is_fortigate_api);

    // Show "Set Inform" button for UniFi devices.
    detail.set_inform_btn.set_visible(host.device_type == DeviceType::UniFi);

    if is_fortigate_api {
        // Reset dashboard rows to loading placeholders.
        detail.fg_firmware_row.set_subtitle("Loading\u{2026}");
        detail.fg_update_badge.set_visible(false);
        detail.fg_hostname_row.set_subtitle("Loading\u{2026}");
        detail.fg_serial_row.set_subtitle("Loading\u{2026}");
        detail.fg_ha_row.set_subtitle("Loading\u{2026}");
        detail.fg_cpu_row.set_subtitle("Loading\u{2026}");
        detail.fg_memory_row.set_subtitle("Loading\u{2026}");
    }

    detail.detail_stack.set_visible_child_name("detail");
}

// ---------------------------------------------------------------------------
// FortiGate dashboard
// ---------------------------------------------------------------------------

/// Kick off an async fetch of the FortiGate system status and send the result
/// back to the GTK main thread via `AppMsg::FortigateStatus`.
pub fn refresh_fortigate_dashboard(
    host_id: String,
    hostname: String,
    api_port: u16,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let tx = tx.clone();
    rt.spawn(async move {
        // Quick TCP check before making the full API call — avoids a 30s
        // timeout when the host is unreachable (e.g. VPN not connected).
        let addr = format!("{hostname}:{api_port}");
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::TcpStream::connect(&addr),
        ).await {
            Ok(Ok(_)) => {} // reachable, proceed
            _ => {
                // Not reachable — show "Unreachable" without error toast.
                let _ = tx.send(AppMsg::FortigateStatus {
                    host_id,
                    data: serde_json::json!({ "error": "host unreachable" }),
                });
                return;
            }
        }

        let result = async {
            let conn = zbus::Connection::system().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            // Fetch system status (hostname, firmware, serial).
            let resp = proxy
                .fortigate_api(&host_id, "GET", "/api/v2/monitor/system/status", "")
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let mut data: Value = serde_json::from_str(&resp)
                .map_err(|e| anyhow::anyhow!("parse error: {e}"))?;
            info!("FortiGate status top-level: {:?}",
                data.as_object().map(|o| o.keys().collect::<Vec<_>>()));
            if let Some(r) = data.get("results") {
                info!("FortiGate status results: {r}");
            }

            // Try multiple endpoints for CPU/memory (varies by firmware version).
            let mut found_resource = false;
            for ep in &[
                "/api/v2/monitor/system/resource/usage",
                "/api/v2/monitor/system/performance/status",
            ] {
                if let Ok(res_resp) = proxy.fortigate_api(&host_id, "GET", ep, "").await {
                    if let Ok(res_data) = serde_json::from_str::<Value>(&res_resp) {
                        let res = res_data.get("results").unwrap_or(&res_data);
                        if res.get("cpu").is_some() || res.get("mem").is_some() {
                            data["resource"] = res.clone();
                            found_resource = true;
                            break;
                        }
                    }
                }
            }

            // Fallback: some FortiGate versions include cpu/ram directly in the
            // main status response under "results".
            if !found_resource {
                if let Some(results) = data.get("results") {
                    let has_cpu = results.get("cpu").is_some();
                    let has_mem = results.get("mem").is_some()
                        || results.get("ram").is_some();
                    if has_cpu || has_mem {
                        data["resource"] = results.clone();
                    }
                }
            }

            // Fetch firmware upgrade availability (informational only).
            if let Ok(fw_resp) = proxy
                .fortigate_api(&host_id, "GET", "/api/v2/monitor/system/firmware", "")
                .await
            {
                if let Ok(fw_data) = serde_json::from_str::<Value>(&fw_resp) {
                    let results = fw_data.get("results").unwrap_or(&fw_data);
                    // The firmware endpoint returns "available" array when updates exist.
                    let has_update = results
                        .get("available")
                        .and_then(|a| a.as_array())
                        .map(|a| !a.is_empty())
                        .unwrap_or(false);
                    if has_update {
                        data["firmware_update_available"] = Value::Bool(true);
                        // Include the latest available version for display.
                        if let Some(latest) = results
                            .get("available")
                            .and_then(|a| a.as_array())
                            .and_then(|a| a.first())
                        {
                            data["firmware_update_version"] = latest.clone();
                        }
                    }
                }
            }

            Ok::<Value, anyhow::Error>(data)
        }
        .await;

        match result {
            Ok(data) => {
                let _ = tx.send(AppMsg::FortigateStatus {
                    host_id,
                    data,
                });
            }
            Err(e) => {
                warn!("FortiGate dashboard fetch failed for {host_id}: {e}");
                // Show "Unreachable" in dashboard instead of noisy error toast.
                let _ = tx.send(AppMsg::FortigateStatus {
                    host_id,
                    data: serde_json::json!({ "error": e.to_string() }),
                });
            }
        }
    });
}

/// Apply FortiGate status data to the dashboard rows.
pub fn apply_fortigate_status(detail: &SshHostDetail, data: &Value) {
    // Handle error case — show "Unreachable" in all fields.
    if data.get("error").is_some() {
        let msg = "Unreachable";
        detail.fg_firmware_row.set_subtitle(msg);
        detail.fg_update_badge.set_visible(false);
        detail.fg_hostname_row.set_subtitle(msg);
        detail.fg_serial_row.set_subtitle(msg);
        detail.fg_ha_row.set_subtitle(msg);
        detail.fg_cpu_row.set_subtitle(msg);
        detail.fg_memory_row.set_subtitle(msg);
        return;
    }

    // FortiGate /api/v2/monitor/system/status puts some fields at top level
    // (version, serial, build) and others inside "results" (hostname, etc.).
    let results = data.get("results").unwrap_or(data);

    // Helper: check both top-level and results for a field.
    let get_str = |key: &str| -> &str {
        data.get(key)
            .and_then(|v| v.as_str())
            .or_else(|| results.get(key).and_then(|v| v.as_str()))
            .unwrap_or("--")
    };

    let version = get_str("version");
    let build = data.get("build").and_then(|v| v.as_u64()).unwrap_or(0);
    let firmware = if build > 0 {
        format!("{version} (build {build})")
    } else {
        version.to_string()
    };
    detail.fg_firmware_row.set_subtitle(&firmware);

    // Show "Update available" badge if firmware update info is present.
    let has_fw_update = data
        .get("firmware_update_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    detail.fg_update_badge.set_visible(has_fw_update);
    if has_fw_update {
        if let Some(ver) = data.get("firmware_update_version") {
            let ver_str = ver
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("new version");
            detail
                .fg_update_badge
                .set_tooltip_text(Some(&format!("Available: {ver_str}")));
        }
    }

    detail.fg_hostname_row.set_subtitle(get_str("hostname"));
    detail.fg_serial_row.set_subtitle(get_str("serial"));
    detail.fg_ha_row.set_subtitle(get_str("ha_mode"));

    // CPU/Memory — check multiple locations (varies by firmware version).
    let resource = data.get("resource");
    let cpu = resource
        .and_then(|r| r.get("cpu"))
        .and_then(|v| v.as_u64())
        .or_else(|| results.get("cpu").and_then(|v| v.as_u64()))
        .or_else(|| data.get("cpu").and_then(|v| v.as_u64()))
        .map(|v| format!("{v}%"))
        .unwrap_or_else(|| "--".to_owned());
    detail.fg_cpu_row.set_subtitle(&cpu);

    // Memory — also check "ram" key used by some firmware versions.
    let mem = resource
        .and_then(|r| r.get("mem").or_else(|| r.get("ram")))
        .and_then(|v| v.as_u64())
        .or_else(|| results.get("mem").and_then(|v| v.as_u64()))
        .or_else(|| results.get("ram").and_then(|v| v.as_u64()))
        .or_else(|| data.get("mem").and_then(|v| v.as_u64()))
        .map(|v| format!("{v}%"))
        .unwrap_or_else(|| "--".to_owned());
    detail.fg_memory_row.set_subtitle(&mem);
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

// ---------------------------------------------------------------------------
// FortiGate CIS compliance check
// ---------------------------------------------------------------------------

/// Kick off an async CIS compliance check and send the result back to the
/// GTK main thread via `AppMsg::FortigateCompliance`.
pub fn run_fortigate_compliance(
    host_id: String,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    let tx = tx.clone();
    rt.spawn(async move {
        let result = async {
            let conn = zbus::Connection::system().await?;
            let proxy = DaemonProxy::new(&conn).await?;
            let resp = proxy
                .fortigate_compliance_check(&host_id)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let data: Value = serde_json::from_str(&resp)
                .map_err(|e| anyhow::anyhow!("parse error: {e}"))?;
            Ok::<Value, anyhow::Error>(data)
        }
        .await;

        match result {
            Ok(data) => {
                let _ = tx.send(AppMsg::FortigateCompliance {
                    host_id,
                    data,
                });
            }
            Err(e) => {
                warn!("FortiGate compliance check failed for {host_id}: {e}");
                let _ = tx.send(AppMsg::FortigateCompliance {
                    host_id,
                    data: serde_json::json!({ "error": e.to_string() }),
                });
            }
        }
    });
}

/// Show a dialog with CIS compliance check results.
pub fn show_compliance_dialog(parent: &adw::ApplicationWindow, data: &Value) {
    let dialog = adw::AlertDialog::builder()
        .heading("CIS Compliance Check")
        .build();

    if let Some(err) = data.get("error").and_then(|v| v.as_str()) {
        dialog.set_body(&format!("Compliance check failed: {err}"));
        dialog.add_response("close", "Close");
        dialog.present(Some(parent));
        return;
    }

    let score = data.get("score").and_then(|v| v.as_str()).unwrap_or("--");
    let passed = data.get("passed").and_then(|v| v.as_u64()).unwrap_or(0);
    let failed = data.get("failed").and_then(|v| v.as_u64()).unwrap_or(0);
    let total = data.get("total").and_then(|v| v.as_u64()).unwrap_or(0);

    let mut body = format!("Score: {score}  ({passed} passed, {failed} failed, {total} total)\n\n");

    if let Some(checks) = data.get("checks").and_then(|v| v.as_array()) {
        for check in checks {
            let name = check.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let status = check.get("status").and_then(|v| v.as_str()).unwrap_or("?");
            let detail = check.get("detail").and_then(|v| v.as_str()).unwrap_or("");
            let icon = if status == "pass" { "[PASS]" } else { "[FAIL]" };
            if detail.is_empty() {
                body.push_str(&format!("{icon} {name}\n"));
            } else {
                body.push_str(&format!("{icon} {name} - {detail}\n"));
            }
        }
    }

    dialog.set_body(&body);
    dialog.add_response("close", "Close");
    dialog.present(Some(parent));
}
