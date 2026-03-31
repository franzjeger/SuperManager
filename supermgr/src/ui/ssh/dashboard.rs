//! Multi-device dashboard — shows all FortiGate hosts at a glance.
//!
//! Displays a grid of cards, one per FortiGate host with `has_api: true`,
//! showing hostname, firmware, CPU/memory bars, health dot, and VPN tunnel count.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use serde_json::Value;
use tracing::warn;

use supermgr_core::dbus::DaemonProxy;
use supermgr_core::ssh::host::SshHostSummary;
use supermgr_core::ssh::DeviceType;

use crate::app::{AppMsg, AppState};

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build the multi-device SSH dashboard widget.
///
/// Returns `(flow_box, widget)` — the flow_box is needed by the drain loop
/// to apply per-device status updates.
pub fn build_ssh_dashboard(
    app_state: &Arc<Mutex<AppState>>,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) -> (gtk4::FlowBox, gtk4::Widget) {
    let outer_stack = gtk4::Stack::new();

    // Empty state when no FortiGate hosts have API configured.
    let empty_status = adw::StatusPage::builder()
        .title("No FortiGate Devices")
        .description("Add FortiGate hosts with API tokens to see them here.")
        .icon_name("network-server-symbolic")
        .build();
    outer_stack.add_named(&empty_status, Some("empty"));

    // Scrollable flow box for device cards.
    let flow_box = gtk4::FlowBox::builder()
        .homogeneous(true)
        .min_children_per_line(1)
        .max_children_per_line(4)
        .selection_mode(gtk4::SelectionMode::None)
        .row_spacing(12)
        .column_spacing(12)
        .margin_top(16)
        .margin_bottom(16)
        .margin_start(16)
        .margin_end(16)
        .build();

    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&flow_box)
        .build();

    // Refresh button in a toolbar at the top.
    let refresh_btn = gtk4::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Refresh all devices")
        .css_classes(["flat"])
        .build();

    let header_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .margin_start(16)
        .margin_end(16)
        .margin_top(8)
        .build();
    let title_lbl = gtk4::Label::builder()
        .label("FortiGate Dashboard")
        .css_classes(["title-2"])
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    header_box.append(&title_lbl);
    header_box.append(&refresh_btn);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    content_box.append(&header_box);
    content_box.append(&scroll);
    outer_stack.add_named(&content_box, Some("content"));

    // Initial populate.
    populate_dashboard(&outer_stack, &flow_box, app_state, rt, tx);

    // Refresh button handler.
    {
        let outer_stack = outer_stack.clone();
        let flow_box = flow_box.clone();
        let app_state = app_state.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        refresh_btn.connect_clicked(move |_| {
            populate_dashboard(&outer_stack, &flow_box, &app_state, &rt, &tx);
        });
    }

    (flow_box.clone(), outer_stack.upcast())
}

// ---------------------------------------------------------------------------
// Populate
// ---------------------------------------------------------------------------

/// Rebuild the dashboard cards from current AppState, then kick off async
/// fetches for each FortiGate host with API.
fn populate_dashboard(
    outer_stack: &gtk4::Stack,
    flow_box: &gtk4::FlowBox,
    app_state: &Arc<Mutex<AppState>>,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    // Clear existing cards.
    while let Some(child) = flow_box.first_child() {
        flow_box.remove(&child);
    }

    let fg_hosts: Vec<SshHostSummary> = {
        let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
        s.ssh_hosts
            .iter()
            .filter(|h| h.device_type == DeviceType::Fortigate && h.has_api)
            .cloned()
            .collect()
    };

    if fg_hosts.is_empty() {
        outer_stack.set_visible_child_name("empty");
        return;
    }

    outer_stack.set_visible_child_name("content");

    for host in &fg_hosts {
        let card = build_device_card(host, app_state);
        flow_box.append(&card);

        // Kick off async status fetch for this host.
        let host_id = host.id.to_string();
        let hostname = host.hostname.clone();
        let api_port = host.api_port.unwrap_or(443);
        let tx = tx.clone();
        let flow_box_clone = flow_box.clone();
        let host_id_for_card = host_id.clone();

        rt.spawn(async move {
            // Quick reachability check.
            let addr = format!("{hostname}:{api_port}");
            let reachable = match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(_)) => true,
                _ => false,
            };

            if !reachable {
                let _ = tx.send(AppMsg::DashboardDeviceStatus {
                    host_id: host_id_for_card,
                    data: serde_json::json!({ "error": "host unreachable" }),
                });
                return;
            }

            let result = async {
                let conn = zbus::Connection::system().await?;
                let proxy = DaemonProxy::new(&conn).await?;

                let resp = proxy
                    .fortigate_api(&host_id, "GET", "/api/v2/monitor/system/status", "")
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let mut data: Value = serde_json::from_str(&resp)?;

                // Try to get CPU/memory.
                for ep in &[
                    "/api/v2/monitor/system/resource/usage",
                    "/api/v2/monitor/system/performance/status",
                ] {
                    if let Ok(res_resp) = proxy.fortigate_api(&host_id, "GET", ep, "").await {
                        if let Ok(res_data) = serde_json::from_str::<Value>(&res_resp) {
                            let res = res_data.get("results").unwrap_or(&res_data);
                            if res.get("cpu").is_some() || res.get("mem").is_some() {
                                data["resource"] = res.clone();
                                break;
                            }
                        }
                    }
                }

                // Try to get VPN tunnel count.
                if let Ok(vpn_resp) = proxy
                    .fortigate_api(&host_id, "GET", "/api/v2/monitor/vpn/ipsec", "")
                    .await
                {
                    if let Ok(vpn_data) = serde_json::from_str::<Value>(&vpn_resp) {
                        if let Some(results) = vpn_data.get("results").and_then(|r| r.as_array()) {
                            data["vpn_tunnel_count"] = Value::from(results.len());
                        }
                    }
                }

                Ok::<Value, anyhow::Error>(data)
            }
            .await;

            match result {
                Ok(data) => {
                    let _ = tx.send(AppMsg::DashboardDeviceStatus {
                        host_id: host_id_for_card,
                        data,
                    });
                }
                Err(e) => {
                    warn!("dashboard fetch failed for {host_id_for_card}: {e}");
                    let _ = tx.send(AppMsg::DashboardDeviceStatus {
                        host_id: host_id_for_card,
                        data: serde_json::json!({ "error": e.to_string() }),
                    });
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Card builder
// ---------------------------------------------------------------------------

/// Build a single device card for the flow box.
fn build_device_card(host: &SshHostSummary, app_state: &Arc<Mutex<AppState>>) -> gtk4::FlowBoxChild {
    let card = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(8)
        .css_classes(["card"])
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .build();
    card.set_size_request(260, -1);

    // Header row: health dot + host label.
    let header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_top(12)
        .margin_start(12)
        .margin_end(12)
        .build();

    let health_dot = gtk4::Label::builder()
        .label("\u{25CF}") // filled circle
        .css_classes(["dim-label"])
        .build();
    // Will be updated to green/red when data arrives; mark with widget name.
    health_dot.set_widget_name(&format!("health-dot-{}", host.id));

    let name_lbl = gtk4::Label::builder()
        .label(&host.label)
        .css_classes(["heading"])
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .ellipsize(gtk4::pango::EllipsizeMode::End)
        .build();

    header.append(&health_dot);
    header.append(&name_lbl);
    card.append(&header);

    // Hostname subtitle.
    let host_lbl = gtk4::Label::builder()
        .label(&host.hostname)
        .css_classes(["caption", "dim-label"])
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .build();
    card.append(&host_lbl);

    // Info rows (firmware, CPU, memory, tunnels) — populated as "Loading...".
    let info_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(4)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .margin_top(4)
        .build();

    let firmware_lbl = gtk4::Label::builder()
        .label("Firmware: Loading\u{2026}")
        .css_classes(["caption"])
        .halign(gtk4::Align::Start)
        .build();
    firmware_lbl.set_widget_name(&format!("firmware-{}", host.id));
    info_box.append(&firmware_lbl);

    // CPU progress bar.
    let cpu_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(6)
        .build();
    let cpu_label = gtk4::Label::builder()
        .label("CPU")
        .css_classes(["caption", "dim-label"])
        .width_chars(4)
        .build();
    let cpu_bar = gtk4::ProgressBar::builder()
        .hexpand(true)
        .valign(gtk4::Align::Center)
        .build();
    cpu_bar.set_widget_name(&format!("cpu-bar-{}", host.id));
    cpu_bar.set_fraction(0.0);
    let cpu_pct = gtk4::Label::builder()
        .label("--%")
        .css_classes(["caption"])
        .width_chars(4)
        .build();
    cpu_pct.set_widget_name(&format!("cpu-pct-{}", host.id));
    cpu_box.append(&cpu_label);
    cpu_box.append(&cpu_bar);
    cpu_box.append(&cpu_pct);
    info_box.append(&cpu_box);

    // Memory progress bar.
    let mem_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(6)
        .build();
    let mem_label = gtk4::Label::builder()
        .label("Mem")
        .css_classes(["caption", "dim-label"])
        .width_chars(4)
        .build();
    let mem_bar = gtk4::ProgressBar::builder()
        .hexpand(true)
        .valign(gtk4::Align::Center)
        .build();
    mem_bar.set_widget_name(&format!("mem-bar-{}", host.id));
    mem_bar.set_fraction(0.0);
    let mem_pct = gtk4::Label::builder()
        .label("--%")
        .css_classes(["caption"])
        .width_chars(4)
        .build();
    mem_pct.set_widget_name(&format!("mem-pct-{}", host.id));
    mem_box.append(&mem_label);
    mem_box.append(&mem_bar);
    mem_box.append(&mem_pct);
    info_box.append(&mem_box);

    // VPN tunnel count.
    let tunnel_lbl = gtk4::Label::builder()
        .label("VPN Tunnels: --")
        .css_classes(["caption"])
        .halign(gtk4::Align::Start)
        .build();
    tunnel_lbl.set_widget_name(&format!("tunnels-{}", host.id));
    info_box.append(&tunnel_lbl);

    card.append(&info_box);

    let child = gtk4::FlowBoxChild::builder().child(&card).build();
    child
}

// ---------------------------------------------------------------------------
// Apply status data to a card
// ---------------------------------------------------------------------------

/// Update a dashboard card with fetched FortiGate status data.
///
/// Called from the GTK drain loop when `AppMsg::DashboardDeviceStatus` arrives.
/// Walks the flow_box children looking for widgets named with the host_id.
pub fn apply_dashboard_status(flow_box: &gtk4::FlowBox, host_id: &str, data: &Value) {
    let is_error = data.get("error").is_some();

    // Find and update widgets by name suffix.
    update_label_by_name(flow_box, &format!("health-dot-{host_id}"), |lbl| {
        if is_error {
            lbl.set_css_classes(&["error"]);  // red via Adwaita
        } else {
            lbl.set_css_classes(&["success"]); // green via Adwaita
        }
    });

    if is_error {
        update_label_by_name(flow_box, &format!("firmware-{host_id}"), |lbl| {
            lbl.set_label("Firmware: Unreachable");
        });
        update_label_by_name(flow_box, &format!("cpu-pct-{host_id}"), |lbl| {
            lbl.set_label("--");
        });
        update_label_by_name(flow_box, &format!("mem-pct-{host_id}"), |lbl| {
            lbl.set_label("--");
        });
        update_label_by_name(flow_box, &format!("tunnels-{host_id}"), |lbl| {
            lbl.set_label("VPN Tunnels: --");
        });
        return;
    }

    let results = data.get("results").unwrap_or(data);

    // Firmware.
    let version = data
        .get("version")
        .and_then(|v| v.as_str())
        .or_else(|| results.get("version").and_then(|v| v.as_str()))
        .unwrap_or("--");
    let build = data.get("build").and_then(|v| v.as_u64()).unwrap_or(0);
    let fw = if build > 0 {
        format!("Firmware: {version} (b{build})")
    } else {
        format!("Firmware: {version}")
    };
    update_label_by_name(flow_box, &format!("firmware-{host_id}"), |lbl| {
        lbl.set_label(&fw);
    });

    // CPU.
    let resource = data.get("resource");
    let cpu_val = resource
        .and_then(|r| r.get("cpu"))
        .and_then(|v| v.as_u64())
        .or_else(|| results.get("cpu").and_then(|v| v.as_u64()));
    if let Some(cpu) = cpu_val {
        update_label_by_name(flow_box, &format!("cpu-pct-{host_id}"), |lbl| {
            lbl.set_label(&format!("{cpu}%"));
        });
        update_progress_by_name(flow_box, &format!("cpu-bar-{host_id}"), cpu as f64 / 100.0);
    }

    // Memory.
    let mem_val = resource
        .and_then(|r| r.get("mem"))
        .and_then(|v| v.as_u64())
        .or_else(|| results.get("mem").and_then(|v| v.as_u64()));
    if let Some(mem) = mem_val {
        update_label_by_name(flow_box, &format!("mem-pct-{host_id}"), |lbl| {
            lbl.set_label(&format!("{mem}%"));
        });
        update_progress_by_name(flow_box, &format!("mem-bar-{host_id}"), mem as f64 / 100.0);
    }

    // VPN tunnels.
    if let Some(count) = data.get("vpn_tunnel_count").and_then(|v| v.as_u64()) {
        update_label_by_name(flow_box, &format!("tunnels-{host_id}"), |lbl| {
            lbl.set_label(&format!("VPN Tunnels: {count}"));
        });
    }
}

// ---------------------------------------------------------------------------
// Widget-tree search helpers
// ---------------------------------------------------------------------------

/// Walk the flow_box children and find a Label with the given widget name.
fn update_label_by_name(flow_box: &gtk4::FlowBox, name: &str, f: impl FnOnce(&gtk4::Label)) {
    if let Some(widget) = find_widget_by_name(flow_box.upcast_ref(), name) {
        if let Some(lbl) = widget.downcast_ref::<gtk4::Label>() {
            f(lbl);
        }
    }
}

/// Walk the flow_box children and find a ProgressBar with the given widget name.
fn update_progress_by_name(flow_box: &gtk4::FlowBox, name: &str, fraction: f64) {
    if let Some(widget) = find_widget_by_name(flow_box.upcast_ref(), name) {
        if let Some(bar) = widget.downcast_ref::<gtk4::ProgressBar>() {
            bar.set_fraction(fraction.clamp(0.0, 1.0));
        }
    }
}

/// Recursively search for a widget with the given name.
fn find_widget_by_name(root: &gtk4::Widget, name: &str) -> Option<gtk4::Widget> {
    if root.widget_name().as_str() == name {
        return Some(root.clone());
    }
    let mut child = root.first_child();
    while let Some(c) = child {
        if let Some(found) = find_widget_by_name(&c, name) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}
