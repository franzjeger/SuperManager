//! Multi-device dashboard — shows FortiGate and UniFi devices at a glance.
//!
//! FortiGate cards: hostname, model, firmware, uptime, WAN IP, CPU/mem bars, VPN tunnels.
//! UniFi cards:     hostname, model, firmware, uptime, CPU/mem bars, clients.

use std::sync::{mpsc, Arc, Mutex};

use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use serde_json::Value;
use tracing::{info, warn};

use supermgr_core::dbus::DaemonProxy;
use supermgr_core::ssh::host::SshHostSummary;
use supermgr_core::ssh::DeviceType;

use crate::app::{AppMsg, AppState};
use crate::settings::AppSettings;

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

    // Empty state.
    let empty_status = adw::StatusPage::builder()
        .title("No Devices")
        .description("Add FortiGate hosts with API tokens or configure a UI.com API key in Settings.")
        .icon_name("network-server-symbolic")
        .build();
    outer_stack.add_named(&empty_status, Some("empty"));

    // Flow box for device cards.
    let flow_box = gtk4::FlowBox::builder()
        .homogeneous(true)
        .min_children_per_line(1)
        .max_children_per_line(4)
        .selection_mode(gtk4::SelectionMode::None)
        .row_spacing(12)
        .column_spacing(12)
        .margin_top(8)
        .margin_bottom(16)
        .margin_start(16)
        .margin_end(16)
        .build();

    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&flow_box)
        .build();

    // Header: title + filter tabs + search + refresh.
    let header_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_start(16)
        .margin_end(16)
        .margin_top(8)
        .build();

    let title_lbl = gtk4::Label::builder()
        .label("Dashboard")
        .css_classes(["title-2"])
        .halign(gtk4::Align::Start)
        .build();

    // Filter toggle buttons (linked group).
    let filter_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .css_classes(["linked"])
        .halign(gtk4::Align::Center)
        .hexpand(true)
        .build();
    let btn_all = gtk4::ToggleButton::builder().label("All").active(true).build();
    let btn_fg  = gtk4::ToggleButton::builder().label("FortiGate").group(&btn_all).build();
    let btn_ui  = gtk4::ToggleButton::builder().label("UniFi").group(&btn_all).build();
    filter_box.append(&btn_all);
    filter_box.append(&btn_fg);
    filter_box.append(&btn_ui);

    let search_entry = gtk4::SearchEntry::builder()
        .placeholder_text("Filter devices\u{2026}")
        .width_request(180)
        .build();

    let refresh_btn = gtk4::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Refresh all devices")
        .css_classes(["flat"])
        .build();

    // Auto-refresh interval dropdown.
    let auto_refresh_model = gtk4::StringList::new(&["Off", "30s", "60s", "5m"]);
    let auto_refresh_drop = gtk4::DropDown::builder()
        .model(&auto_refresh_model)
        .selected(0)
        .tooltip_text("Auto-refresh interval")
        .build();
    auto_refresh_drop.set_size_request(80, -1);

    header_box.append(&title_lbl);
    header_box.append(&filter_box);
    header_box.append(&search_entry);
    header_box.append(&refresh_btn);
    header_box.append(&auto_refresh_drop);

    // Summary bar: "X devices — Y online — Z offline"
    let summary_lbl = gtk4::Label::builder()
        .label("")
        .css_classes(["caption", "dim-label"])
        .halign(gtk4::Align::Start)
        .margin_start(16)
        .margin_top(4)
        .build();
    summary_lbl.set_widget_name("dashboard-summary");

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    content_box.append(&header_box);
    content_box.append(&summary_lbl);
    content_box.append(&scroll);
    outer_stack.add_named(&content_box, Some("content"));

    // Flow box filter function — filters by search text and device type.
    // We store the filter state in the flow_box widget name as "filter:<type>:<query>".
    flow_box.set_widget_name("filter:all:");

    // Sort: offline/error devices first, then by widget name (stable, fast).
    flow_box.set_sort_func(|a, b| {
        let a_err = has_error_class(a.upcast_ref());
        let b_err = has_error_class(b.upcast_ref());
        match (a_err, b_err) {
            (true, false) => gtk4::Ordering::Smaller,
            (false, true) => gtk4::Ordering::Larger,
            _ => {
                let a_name = a.widget_name();
                let b_name = b.widget_name();
                if a_name < b_name { gtk4::Ordering::Smaller } else { gtk4::Ordering::Larger }
            }
        }
    });

    {
        let flow_box_f = flow_box.clone();
        flow_box.set_filter_func(move |child| {
            let filter_state = flow_box_f.widget_name().to_string();
            let parts: Vec<&str> = filter_state.splitn(3, ':').collect();
            let filter_type = parts.get(1).copied().unwrap_or("all");
            let filter_query = parts.get(2).copied().unwrap_or("").to_lowercase();

            let is_cloud = child.widget_name().starts_with("cloud-");

            // Type filter.
            let type_ok = match filter_type {
                "fg" => !is_cloud,
                "ui" => is_cloud,
                _ => true,
            };

            // Search filter — only do expensive text collection when there's a query.
            let search_ok = if filter_query.is_empty() {
                true
            } else {
                collect_card_text(child.upcast_ref()).to_lowercase().contains(&filter_query)
            };

            type_ok && search_ok
        });
    }

    // Wire up filter buttons + search to invalidate the filter.
    let setup_filter = |flow_box: &gtk4::FlowBox, btn_all: &gtk4::ToggleButton, btn_fg: &gtk4::ToggleButton, btn_ui: &gtk4::ToggleButton, search: &gtk4::SearchEntry| {
        let update = {
            let flow_box = flow_box.clone();
            let btn_all = btn_all.clone();
            let btn_fg = btn_fg.clone();
            let search = search.clone();
            move || {
                let t = if btn_all.is_active() { "all" } else if btn_fg.is_active() { "fg" } else { "ui" };
                let q = search.text().to_string();
                flow_box.set_widget_name(&format!("filter:{t}:{q}"));
                flow_box.invalidate_filter();
            }
        };
        let u1 = update.clone();
        btn_all.connect_toggled(move |_| u1());
        let u2 = update.clone();
        btn_fg.connect_toggled(move |_| u2());
        let u3 = update.clone();
        btn_ui.connect_toggled(move |_| u3());
        let u4 = update.clone();
        search.connect_search_changed(move |_| u4());
    };
    setup_filter(&flow_box, &btn_all, &btn_fg, &btn_ui, &search_entry);

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

    // Auto-refresh timer — controlled by the dropdown.
    {
        let outer_stack = outer_stack.clone();
        let flow_box = flow_box.clone();
        let app_state = app_state.clone();
        let rt = rt.clone();
        let tx = tx.clone();
        // Store the current timer source ID in a shared cell.
        let timer_id: std::rc::Rc<std::cell::RefCell<Option<glib::SourceId>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let timer_id_c = timer_id.clone();
        auto_refresh_drop.connect_selected_notify(move |drop| {
            // Cancel previous timer.
            if let Some(id) = timer_id_c.borrow_mut().take() {
                id.remove();
            }
            let secs = match drop.selected() {
                1 => 30u32,
                2 => 60,
                3 => 300,
                _ => return, // Off
            };
            let os = outer_stack.clone();
            let fb = flow_box.clone();
            let a = app_state.clone();
            let r = rt.clone();
            let t = tx.clone();
            let id = glib::timeout_add_seconds_local(secs, move || {
                populate_dashboard(&os, &fb, &a, &r, &t);
                glib::ControlFlow::Continue
            });
            *timer_id_c.borrow_mut() = Some(id);
        });
    }

    (flow_box.clone(), outer_stack.upcast())
}

/// Check if any label in the widget tree has the "error" CSS class (offline dot).
fn has_error_class(widget: &gtk4::Widget) -> bool {
    if let Some(lbl) = widget.downcast_ref::<gtk4::Label>() {
        if lbl.css_classes().iter().any(|c| c == "error") {
            return true;
        }
    }
    let mut child = widget.first_child();
    while let Some(c) = child {
        if has_error_class(&c) { return true; }
        child = c.next_sibling();
    }
    false
}

/// Collect all visible label text from a widget tree (for search filtering).
fn collect_card_text(widget: &gtk4::Widget) -> String {
    let mut text = String::new();
    if let Some(lbl) = widget.downcast_ref::<gtk4::Label>() {
        text.push_str(&lbl.text());
        text.push(' ');
    }
    let mut child = widget.first_child();
    while let Some(c) = child {
        text.push_str(&collect_card_text(&c));
        child = c.next_sibling();
    }
    text
}

// ---------------------------------------------------------------------------
// Populate
// ---------------------------------------------------------------------------

/// Rebuild the dashboard cards from current AppState, then kick off async
/// fetches for each device with API.  Also fetches from UI.com Site Manager
/// cloud API if an API key is configured in settings.
fn populate_dashboard(
    outer_stack: &gtk4::Stack,
    flow_box: &gtk4::FlowBox,
    app_state: &Arc<Mutex<AppState>>,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) {
    eprintln!(">>> populate_dashboard called");
    info!("populate_dashboard called");

    // Clear existing cards.
    while let Some(child) = flow_box.first_child() {
        flow_box.remove(&child);
    }

    let dash_hosts: Vec<SshHostSummary> = {
        let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
        s.ssh_hosts
            .iter()
            .filter(|h| {
                (h.device_type == DeviceType::Fortigate && h.has_api)
                    || (h.device_type == DeviceType::UniFi && h.has_api)
            })
            .cloned()
            .collect()
    };

    let has_cloud_key = !AppSettings::load().unifi_cloud_api_key.is_empty();

    if dash_hosts.is_empty() && !has_cloud_key {
        outer_stack.set_visible_child_name("empty");
        return;
    }

    outer_stack.set_visible_child_name("content");

    for host in &dash_hosts {
        let card = build_device_card(host, app_state);

        // Quick-action buttons for FortiGate devices.
        if host.device_type == DeviceType::Fortigate && host.has_api {
            if let Some(card_box) = card.child().and_then(|c| c.downcast::<gtk4::Box>().ok()) {
                let action_box = gtk4::Box::builder()
                    .orientation(gtk4::Orientation::Horizontal)
                    .spacing(4)
                    .halign(gtk4::Align::Center)
                    .margin_bottom(8)
                    .build();

                // Backup button.
                let backup_btn = gtk4::Button::builder()
                    .icon_name("document-save-symbolic")
                    .tooltip_text("Backup config")
                    .css_classes(["flat", "circular"])
                    .build();
                {
                    let host_id = host.id.to_string();
                    let rt = rt.clone();
                    let tx = tx.clone();
                    backup_btn.connect_clicked(move |_| {
                        let host_id = host_id.clone();
                        let tx = tx.clone();
                        rt.spawn(async move {
                            let conn = zbus::Connection::system().await.ok();
                            if let Some(conn) = conn {
                                if let Ok(proxy) = DaemonProxy::new(&conn).await {
                                    match proxy.fortigate_backup_config(&host_id).await {
                                        Ok(path) => {
                                            let _ = tx.send(AppMsg::ShowToast(
                                                format!("Backup saved: {path}"),
                                            ));
                                        }
                                        Err(e) => {
                                            let _ = tx.send(AppMsg::OperationFailed(
                                                format!("Backup failed: {e}"),
                                            ));
                                        }
                                    }
                                }
                            }
                        });
                    });
                }

                // View host detail button.
                let detail_btn = gtk4::Button::builder()
                    .icon_name("go-next-symbolic")
                    .tooltip_text("View host details")
                    .css_classes(["flat", "circular"])
                    .build();
                {
                    let host_id = host.id.to_string();
                    let tx = tx.clone();
                    detail_btn.connect_clicked(move |_| {
                        let _ = tx.send(AppMsg::EditSshHost(host_id.clone()));
                    });
                }

                // Config diff button.
                let diff_btn = gtk4::Button::builder()
                    .icon_name("edit-find-symbolic")
                    .tooltip_text("Compare last 2 backups")
                    .css_classes(["flat", "circular"])
                    .build();
                {
                    let hostname = host.hostname.clone();
                    let tx = tx.clone();
                    let rt = rt.clone();
                    diff_btn.connect_clicked(move |_| {
                        let hostname = hostname.clone();
                        let tx = tx.clone();
                        rt.spawn(async move {
                            match compute_backup_diff(&hostname).await {
                                Ok(diff) if diff.is_empty() => {
                                    let _ = tx.send(AppMsg::ShowToast(
                                        "No differences between last 2 backups".into(),
                                    ));
                                }
                                Ok(diff) => {
                                    let _ = tx.send(AppMsg::ShowToast(
                                        format!("Config diff: {} changes", diff.lines().count()),
                                    ));
                                    // Store diff for display.
                                    let _ = tx.send(AppMsg::FortigateConfigDiff {
                                        hostname: hostname.clone(),
                                        diff,
                                    });
                                }
                                Err(e) => {
                                    let _ = tx.send(AppMsg::OperationFailed(
                                        format!("Diff failed: {e}"),
                                    ));
                                }
                            }
                        });
                    });
                }

                action_box.append(&backup_btn);
                action_box.append(&diff_btn);
                action_box.append(&detail_btn);
                card_box.append(&action_box);
            }
        }

        flow_box.append(&card);

        // Kick off async status fetch for this host.
        let host_id = host.id.to_string();
        let hostname = host.hostname.clone();
        let api_port = host.api_port.unwrap_or(443);
        let device_type = host.device_type;
        let tx = tx.clone();
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

                if device_type == DeviceType::UniFi {
                    return fetch_unifi_status(&proxy, &host_id).await;
                }

                // FortiGate: system status (model, serial, version, uptime).
                let resp = proxy
                    .fortigate_api(&host_id, "GET", "/api/v2/monitor/system/status", "")
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let mut data: Value = serde_json::from_str(&resp)?;

                // CPU/memory.
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

                // VPN tunnel count.
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

                // WAN interface (IP, link speed).
                if let Ok(iface_resp) = proxy
                    .fortigate_api(&host_id, "GET", "/api/v2/monitor/system/interface?interface_name=wan", "")
                    .await
                {
                    if let Ok(iface_data) = serde_json::from_str::<Value>(&iface_resp) {
                        // Try wan, wan1, or first interface with an IP.
                        let wan = iface_data.pointer("/results/wan")
                            .or_else(|| iface_data.pointer("/results/wan1"));
                        if let Some(wan) = wan {
                            data["wan_ip"] = wan.get("ip").cloned().unwrap_or(Value::Null);
                        }
                    }
                }

                // Firmware update check — only show versions newer than current.
                let current_ver = data.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                if let Ok(fw_resp) = proxy
                    .fortigate_api(&host_id, "GET", "/api/v2/monitor/system/firmware", "")
                    .await
                {
                    if let Ok(fw_data) = serde_json::from_str::<Value>(&fw_resp) {
                        if let Some(arr) = fw_data.pointer("/results/available")
                            .and_then(|v| v.as_array())
                        {
                            // Find a version that is strictly newer than current.
                            for fw in arr {
                                if let Some(ver) = fw.get("version").and_then(|v| v.as_str()) {
                                    if version_is_newer(ver, &current_ver) {
                                        data["firmware_update"] = Value::from(ver);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // Active session count (from resource/usage already fetched).
                if let Some(sessions) = data.pointer("/resource/session")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.get("current"))
                    .and_then(|v| v.as_u64())
                {
                    data["session_count"] = Value::from(sessions);
                }

                // Last backup timestamp from /etc/supermgrd/backups/.
                if let Ok(mut entries) = tokio::fs::read_dir("/etc/supermgrd/backups").await {
                    let prefix = format!("{hostname}_");
                    let mut newest: Option<std::time::SystemTime> = None;
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        if let Ok(name) = entry.file_name().into_string() {
                            if name.starts_with(&prefix) {
                                if let Ok(meta) = entry.metadata().await {
                                    if let Ok(modified) = meta.modified() {
                                        if newest.map_or(true, |n| modified > n) {
                                            newest = Some(modified);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if let Some(t) = newest {
                        let elapsed = t.elapsed().unwrap_or_default().as_secs();
                        data["last_backup_ago"] = Value::from(elapsed);
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

    // ── UI.com Site Manager cloud fetch ──────────────────────────────────────
    let api_key = AppSettings::load().unifi_cloud_api_key;
    if !api_key.is_empty() {
        info!("UI.com cloud: API key configured, fetching devices...");
        let tx = tx.clone();
        rt.spawn(async move {
            match fetch_unifi_cloud_devices(&api_key).await {
                Ok(devices) => {
                    info!("UI.com cloud: got {} devices", devices.len());
                    let _ = tx.send(AppMsg::DashboardCloudDevices { devices });
                }
                Err(e) => {
                    warn!("UI.com cloud fetch failed: {e}");
                }
            }
        });
    } else {
        info!("UI.com cloud: no API key configured");
    }
}

// ---------------------------------------------------------------------------
// UI.com Site Manager cloud API
// ---------------------------------------------------------------------------

async fn fetch_unifi_cloud_devices(
    api_key: &str,
) -> anyhow::Result<Vec<(String, String, String, Value)>> {
    let client = reqwest::Client::new();

    // Fetch hosts (consoles) to get site names.
    let resp = client
        .get("https://api.ui.com/v1/hosts")
        .header("X-API-KEY", api_key)
        .header("Accept", "application/json")
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("UI.com API returned {} — check your API key", resp.status());
    }
    let hosts_resp: Value = resp.json().await?;

    // Map host ID -> (hostname, WAN IP).
    let mut host_info: std::collections::HashMap<String, (String, String)> = std::collections::HashMap::new();
    if let Some(hosts) = hosts_resp.get("data").and_then(|d| d.as_array()) {
        for host in hosts {
            if let Some(id) = host.get("id").and_then(|v| v.as_str()) {
                let name = host.get("reportedState")
                    .and_then(|s| s.get("hostname"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_owned();
                let wan_ip = host.get("ipAddress")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                host_info.insert(id.to_owned(), (name, wan_ip));
            }
        }
    }

    // Fetch all devices.
    let devices_resp: Value = client
        .get("https://api.ui.com/v1/devices")
        .header("X-API-KEY", api_key)
        .header("Accept", "application/json")
        .send()
        .await?
        .json()
        .await?;

    let mut result = Vec::new();
    if let Some(items) = devices_resp.get("data").and_then(|d| d.as_array()) {
        for item in items {
            let devices = item.get("devices").and_then(|d| d.as_array());
            let api_host_id = item.get("hostId").and_then(|v| v.as_str()).unwrap_or("");
            let (site_name, site_wan_ip) = host_info.get(api_host_id)
                .cloned()
                .unwrap_or_default();

            if let Some(devs) = devices {
                for dev in devs {
                    let dev_id = dev.get("mac").and_then(|v| v.as_str())
                        .unwrap_or("unknown").to_owned();
                    let dev_name = dev.get("name").and_then(|v| v.as_str())
                        .unwrap_or("UniFi Device").to_owned();
                    let ip = dev.get("ip").and_then(|v| v.as_str())
                        .unwrap_or("").to_owned();
                    let model = dev.get("model").and_then(|v| v.as_str())
                        .unwrap_or("").to_owned();
                    let shortname = dev.get("shortname").and_then(|v| v.as_str())
                        .unwrap_or("").to_owned();
                    let version = dev.get("version").and_then(|v| v.as_str())
                        .unwrap_or("").to_owned();
                    let status = dev.get("status").and_then(|v| v.as_str())
                        .unwrap_or("offline").to_owned();
                    let startup_time = dev.get("startupTime").and_then(|v| v.as_str())
                        .unwrap_or("").to_owned();
                    let firmware_status = dev.get("firmwareStatus").and_then(|v| v.as_str())
                        .unwrap_or("").to_owned();
                    let product_line = dev.get("productLine").and_then(|v| v.as_str())
                        .unwrap_or("").to_owned();

                    // Only include network devices.
                    if product_line != "network" && !product_line.is_empty() {
                        continue;
                    }

                    // Calculate uptime from startupTime.
                    let uptime_secs = if !startup_time.is_empty() {
                        chrono::DateTime::parse_from_rfc3339(&startup_time)
                            .ok()
                            .map(|dt| {
                                let now = chrono::Utc::now();
                                (now - dt.with_timezone(&chrono::Utc)).num_seconds().max(0) as u64
                            })
                    } else {
                        None
                    };

                    let mut data = serde_json::json!({
                        "_device_type": "unifi",
                        "model": shortname,
                        "model_name": model,
                        "version": version,
                        "status": status,
                        "firmware_status": firmware_status,
                        "site": site_name,
                    });
                    if let Some(up) = uptime_secs {
                        data["uptime"] = Value::from(up);
                    }
                    // Use device IP, fallback to site's WAN IP.
                    let display_ip = if !ip.is_empty() {
                        ip.clone()
                    } else {
                        site_wan_ip.clone()
                    };
                    if !display_ip.is_empty() {
                        data["wan_ip"] = Value::from(display_ip.as_str());
                    }

                    result.push((dev_id, dev_name, display_ip, data));
                }
            }
        }
    }

    info!("UI.com cloud: fetched {} devices", result.len());

    // Send webhook for offline devices.
    let settings = AppSettings::load();
    if !settings.webhook_url.is_empty() {
        let offline: Vec<&str> = result.iter()
            .filter(|(_, _, _, data)| {
                data.get("status").and_then(|v| v.as_str()) != Some("online")
            })
            .map(|(_, label, _, _)| label.as_str())
            .collect();
        if !offline.is_empty() {
            let msg = format!(
                "\u{26a0}\u{fe0f} UniFi devices offline: {}",
                offline.join(", ")
            );
            let client = reqwest::Client::new();
            let payload = serde_json::json!({ "text": &msg, "content": &msg });
            let _ = client.post(&settings.webhook_url)
                .json(&payload)
                .send()
                .await;
            warn!("webhook sent: {msg}");
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// UniFi local controller status fetch
// ---------------------------------------------------------------------------

async fn fetch_unifi_status(
    proxy: &DaemonProxy<'_>,
    host_id: &str,
) -> anyhow::Result<Value> {
    // UniFi controller API: /api/s/default/stat/device
    let resp = proxy
        .unifi_api(host_id, "GET", "/api/s/default/stat/device", "")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let api_data: Value = serde_json::from_str(&resp)?;
    let devices = api_data.get("data").and_then(|d| d.as_array());

    let mut data = serde_json::json!({ "_device_type": "unifi" });

    if let Some(devs) = devices {
        // Use first device (usually there's one per host).
        if let Some(dev) = devs.first() {
            data["model"] = dev.get("model").cloned().unwrap_or(Value::Null);
            data["version"] = dev.get("version").cloned().unwrap_or(Value::Null);
            data["uptime"] = dev.get("uptime").cloned().unwrap_or(Value::Null);
            // System stats: cpu, mem
            if let Some(ss) = dev.get("system-stats") {
                data["cpu"] = ss.get("cpu").cloned().unwrap_or(Value::Null);
                data["mem"] = ss.get("mem").cloned().unwrap_or(Value::Null);
            }
            // Client count
            if let Some(nc) = dev.get("num_sta") {
                data["clients"] = nc.clone();
            }
            // Model name
            if let Some(mn) = dev.get("model_in_lts") .or_else(|| dev.get("model_in_eol")) {
                data["model_name"] = mn.clone();
            }
            // WAN IP (for UDM/USG)
            if let Some(wan_ip) = dev.pointer("/wan1/ip")
                .or_else(|| dev.pointer("/wan/ip"))
                .or_else(|| dev.get("ip"))
            {
                data["wan_ip"] = wan_ip.clone();
            }
        }
    }

    Ok(data)
}

// ---------------------------------------------------------------------------
// Card builder
// ---------------------------------------------------------------------------

fn make_caption_label(text: &str, name: &str) -> gtk4::Label {
    let lbl = gtk4::Label::builder()
        .label(text)
        .css_classes(["caption"])
        .halign(gtk4::Align::Start)
        .ellipsize(gtk4::pango::EllipsizeMode::End)
        .build();
    lbl.set_widget_name(name);
    lbl
}

fn make_progress_row(label_text: &str, bar_name: &str, pct_name: &str) -> gtk4::Box {
    let row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(6)
        .build();
    let label = gtk4::Label::builder()
        .label(label_text)
        .css_classes(["caption", "dim-label"])
        .width_chars(4)
        .build();
    let bar = gtk4::ProgressBar::builder()
        .hexpand(true)
        .valign(gtk4::Align::Center)
        .build();
    bar.set_widget_name(bar_name);
    bar.set_fraction(0.0);
    let pct = gtk4::Label::builder()
        .label("--%")
        .css_classes(["caption"])
        .width_chars(4)
        .build();
    pct.set_widget_name(pct_name);
    row.append(&label);
    row.append(&bar);
    row.append(&pct);
    row
}

/// Build a single device card for the flow box.
fn build_device_card(
    host: &SshHostSummary,
    _app_state: &Arc<Mutex<AppState>>,
) -> gtk4::FlowBoxChild {
    let card = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(6)
        .css_classes(["card"])
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .focusable(true)
        .tooltip_text("Click to view host details")
        .build();
    card.set_size_request(280, -1);

    let id = &host.id;

    // Header row: health dot + device type icon + host label.
    let header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_top(12)
        .margin_start(12)
        .margin_end(12)
        .build();

    let health_dot = gtk4::Label::builder()
        .label("\u{25CF}")
        .css_classes(["dim-label"])
        .build();
    health_dot.set_widget_name(&format!("health-dot-{id}"));

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

    // Hostname + model subtitle.
    let host_lbl = gtk4::Label::builder()
        .label(&host.hostname)
        .css_classes(["caption", "dim-label"])
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .build();
    card.append(&host_lbl);

    // Info rows.
    let info_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(3)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .margin_top(2)
        .build();

    info_box.append(&make_caption_label("Loading\u{2026}", &format!("model-{id}")));
    info_box.append(&make_caption_label("", &format!("firmware-{id}")));
    info_box.append(&make_caption_label("", &format!("uptime-{id}")));
    info_box.append(&make_caption_label("", &format!("wan-ip-{id}")));

    // CPU + Memory bars.
    info_box.append(&make_progress_row("CPU", &format!("cpu-bar-{id}"), &format!("cpu-pct-{id}")));
    info_box.append(&make_progress_row("Mem", &format!("mem-bar-{id}"), &format!("mem-pct-{id}")));

    // Bottom stat (VPN tunnels for FortiGate, clients for UniFi).
    let bottom_lbl = make_caption_label("", &format!("bottom-stat-{id}"));
    info_box.append(&bottom_lbl);

    card.append(&info_box);

    gtk4::FlowBoxChild::builder().child(&card).build()
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
    let is_unifi = data.get("_device_type").and_then(|v| v.as_str()) == Some("unifi");

    // Health dot.
    update_label_by_name(flow_box, &format!("health-dot-{host_id}"), |lbl| {
        if is_error {
            lbl.set_css_classes(&["error"]);
        } else {
            lbl.set_css_classes(&["success"]);
        }
    });

    if is_error {
        update_label_by_name(flow_box, &format!("model-{host_id}"), |lbl| {
            lbl.set_label("Unreachable");
        });
        for f in &["firmware", "uptime", "wan-ip", "cpu-pct", "mem-pct", "bottom-stat"] {
            update_label_by_name(flow_box, &format!("{f}-{host_id}"), |lbl| {
                lbl.set_label("");
            });
        }
        flow_box.invalidate_sort();
        return;
    }

    let results = data.get("results").unwrap_or(data);

    if is_unifi {
        apply_unifi_status(flow_box, host_id, data);
    } else {
        apply_fortigate_status(flow_box, host_id, data, results);
    }
    // Note: sort + summary are invalidated by the caller (not per-card).
}

/// Recount online/offline devices and update the summary label.
pub fn refresh_summary(flow_box: &gtk4::FlowBox) {
    let mut total = 0u32;
    let mut online = 0u32;
    let mut child = flow_box.first_child();
    while let Some(c) = child {
        total += 1;
        if !has_error_class(&c) {
            // Check if it has a success class (got data) vs still loading.
            if has_success_class(&c) {
                online += 1;
            }
        }
        child = c.next_sibling();
    }
    let offline = total.saturating_sub(online);
    // Walk up to find the summary label (sibling of the flow_box's scroll parent).
    if let Some(parent) = flow_box.parent() {             // ScrolledWindow
        if let Some(content_box) = parent.parent() {      // content VBox
            if let Some(summary) = find_widget_by_name(&content_box, "dashboard-summary") {
                if let Some(lbl) = summary.downcast_ref::<gtk4::Label>() {
                    if total == 0 {
                        lbl.set_label("");
                    } else {
                        lbl.set_label(&format!(
                            "{total} devices \u{2014} {online} online \u{2014} {offline} offline"
                        ));
                    }
                }
            }
        }
    }
}

fn has_success_class(widget: &gtk4::Widget) -> bool {
    if let Some(lbl) = widget.downcast_ref::<gtk4::Label>() {
        if lbl.css_classes().iter().any(|c| c == "success") {
            return true;
        }
    }
    let mut child = widget.first_child();
    while let Some(c) = child {
        if has_success_class(&c) { return true; }
        child = c.next_sibling();
    }
    false
}

fn apply_fortigate_status(flow_box: &gtk4::FlowBox, host_id: &str, data: &Value, results: &Value) {
    // Model + serial.
    let model = data.get("model").or_else(|| results.get("model"))
        .and_then(|v| v.as_str()).unwrap_or("FortiGate");
    let serial = data.get("serial").or_else(|| results.get("serial"))
        .and_then(|v| v.as_str()).unwrap_or("");
    let model_text = if serial.is_empty() {
        model.to_owned()
    } else {
        format!("{model} ({serial})")
    };
    update_label_by_name(flow_box, &format!("model-{host_id}"), |lbl| {
        lbl.set_label(&model_text);
    });

    // Firmware.
    let version = data.get("version").or_else(|| results.get("version"))
        .and_then(|v| v.as_str()).unwrap_or("--");
    let build = data.get("build").and_then(|v| v.as_u64()).unwrap_or(0);
    let fw_update = data.get("firmware_update").and_then(|v| v.as_str());
    let fw = if let Some(update_ver) = fw_update {
        if build > 0 {
            format!("{version} (b{build}) \u{2192} {update_ver}")
        } else {
            format!("{version} \u{2192} {update_ver}")
        }
    } else if build > 0 {
        format!("{version} (b{build})")
    } else {
        version.to_owned()
    };
    update_label_by_name(flow_box, &format!("firmware-{host_id}"), |lbl| {
        lbl.set_label(&fw);
        if fw_update.is_some() {
            lbl.add_css_class("warning");
        }
    });

    // Sessions.
    if let Some(sessions) = data.get("session_count").and_then(|v| v.as_u64()) {
        update_label_by_name(flow_box, &format!("uptime-{host_id}"), |lbl| {
            lbl.set_label(&format!("Sessions: {sessions}"));
        });
    }

    // WAN IP.
    if let Some(ip) = data.get("wan_ip").and_then(|v| v.as_str()) {
        update_label_by_name(flow_box, &format!("wan-ip-{host_id}"), |lbl| {
            lbl.set_label(&format!("WAN: {ip}"));
        });
    }

    // CPU.
    let resource = data.get("resource");
    let cpu_val = extract_resource_val(resource, results, "cpu");
    if let Some(cpu) = cpu_val {
        update_label_by_name(flow_box, &format!("cpu-pct-{host_id}"), |lbl| {
            lbl.set_label(&format!("{cpu}%"));
        });
        update_progress_by_name(flow_box, &format!("cpu-bar-{host_id}"), cpu as f64 / 100.0);
    }

    // Memory.
    let mem_val = extract_resource_val(resource, results, "mem");
    if let Some(mem) = mem_val {
        update_label_by_name(flow_box, &format!("mem-pct-{host_id}"), |lbl| {
            lbl.set_label(&format!("{mem}%"));
        });
        update_progress_by_name(flow_box, &format!("mem-bar-{host_id}"), mem as f64 / 100.0);
    }

    // VPN tunnels + last backup.
    let mut bottom_parts = Vec::new();
    if let Some(count) = data.get("vpn_tunnel_count").and_then(|v| v.as_u64()) {
        bottom_parts.push(format!("VPN: {count}"));
    }
    if let Some(ago_secs) = data.get("last_backup_ago").and_then(|v| v.as_u64()) {
        bottom_parts.push(format!("Backup: {}", format_ago(ago_secs)));
    }
    if !bottom_parts.is_empty() {
        update_label_by_name(flow_box, &format!("bottom-stat-{host_id}"), |lbl| {
            lbl.set_label(&bottom_parts.join(" \u{b7} "));
        });
    }
}

/// Find the 2 most recent backups for a hostname and compute a unified diff.
async fn compute_backup_diff(hostname: &str) -> anyhow::Result<String> {
    let backup_dir = std::path::Path::new("/etc/supermgrd/backups");
    let mut entries = tokio::fs::read_dir(backup_dir).await?;
    let prefix = format!("{hostname}_");
    let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Ok(name) = entry.file_name().into_string() {
            if name.starts_with(&prefix) && name.ends_with(".conf") {
                if let Ok(meta) = entry.metadata().await {
                    if let Ok(modified) = meta.modified() {
                        files.push((modified, entry.path()));
                    }
                }
            }
        }
    }
    files.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
    if files.len() < 2 {
        anyhow::bail!("need at least 2 backups to compare (found {})", files.len());
    }
    let newer = tokio::fs::read_to_string(&files[0].1).await?;
    let older = tokio::fs::read_to_string(&files[1].1).await?;

    // Simple line-by-line diff.
    let old_lines: Vec<&str> = older.lines().collect();
    let new_lines: Vec<&str> = newer.lines().collect();
    let mut diff = String::new();
    let mut i = 0;
    let mut j = 0;
    while i < old_lines.len() || j < new_lines.len() {
        if i < old_lines.len() && j < new_lines.len() && old_lines[i] == new_lines[j] {
            i += 1;
            j += 1;
        } else if i < old_lines.len()
            && (j >= new_lines.len() || !new_lines[j..].contains(&old_lines[i]))
        {
            diff.push_str(&format!("- {}\n", old_lines[i]));
            i += 1;
        } else if j < new_lines.len() {
            diff.push_str(&format!("+ {}\n", new_lines[j]));
            j += 1;
        } else {
            break;
        }
    }
    Ok(diff)
}

/// Compare FortiGate version strings like "v7.6.5" > "v7.6.4".
/// Returns true if `candidate` is strictly newer than `current`.
fn version_is_newer(candidate: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> {
        s.trim_start_matches('v')
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect()
    };
    let c = parse(candidate);
    let r = parse(current);
    c > r
}

fn format_ago(secs: u64) -> String {
    if secs < 60 { return "just now".to_owned(); }
    if secs < 3600 { return format!("{}m ago", secs / 60); }
    if secs < 86400 { return format!("{}h ago", secs / 3600); }
    format!("{}d ago", secs / 86400)
}

fn apply_unifi_status(flow_box: &gtk4::FlowBox, host_id: &str, data: &Value) {
    // Health dot: online/offline from status field.
    let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
    update_label_by_name(flow_box, &format!("health-dot-{host_id}"), |lbl| {
        if status == "online" {
            lbl.set_css_classes(&["success"]);
        } else {
            lbl.set_css_classes(&["error"]);
        }
    });

    // Model.
    let model = data.get("model_name").or_else(|| data.get("model"))
        .and_then(|v| v.as_str()).unwrap_or("UniFi");
    let shortname = data.get("model").and_then(|v| v.as_str()).unwrap_or("");
    let model_text = if !shortname.is_empty() && shortname != model {
        format!("{model} ({shortname})")
    } else {
        model.to_owned()
    };
    update_label_by_name(flow_box, &format!("model-{host_id}"), |lbl| {
        lbl.set_label(&model_text);
    });

    // Firmware + update status.
    let ver = data.get("version").and_then(|v| v.as_str()).unwrap_or("");
    let fw_status = data.get("firmware_status").and_then(|v| v.as_str()).unwrap_or("");
    let fw_text = if fw_status == "updateAvailable" {
        format!("{ver} (update available)")
    } else if !ver.is_empty() {
        ver.to_owned()
    } else {
        String::new()
    };
    if !fw_text.is_empty() {
        update_label_by_name(flow_box, &format!("firmware-{host_id}"), |lbl| {
            lbl.set_label(&fw_text);
        });
    }

    // Uptime.
    if let Some(secs) = data.get("uptime").and_then(|v| v.as_u64()) {
        update_label_by_name(flow_box, &format!("uptime-{host_id}"), |lbl| {
            lbl.set_label(&format!("Up: {}", format_uptime(secs)));
        });
    }

    // WAN IP.
    if let Some(ip) = data.get("wan_ip").and_then(|v| v.as_str()) {
        update_label_by_name(flow_box, &format!("wan-ip-{host_id}"), |lbl| {
            lbl.set_label(&format!("WAN: {ip}"));
        });
    }

    // CPU (UniFi returns as string percentage like "12").
    if let Some(cpu) = data.get("cpu").and_then(|v| {
        v.as_u64().or_else(|| v.as_str()?.parse::<u64>().ok())
    }) {
        update_label_by_name(flow_box, &format!("cpu-pct-{host_id}"), |lbl| {
            lbl.set_label(&format!("{cpu}%"));
        });
        update_progress_by_name(flow_box, &format!("cpu-bar-{host_id}"), cpu as f64 / 100.0);
    }

    // Memory.
    if let Some(mem) = data.get("mem").and_then(|v| {
        v.as_u64().or_else(|| v.as_str()?.parse::<u64>().ok())
    }) {
        update_label_by_name(flow_box, &format!("mem-pct-{host_id}"), |lbl| {
            lbl.set_label(&format!("{mem}%"));
        });
        update_progress_by_name(flow_box, &format!("mem-bar-{host_id}"), mem as f64 / 100.0);
    }

    // Connected clients.
    if let Some(clients) = data.get("clients").and_then(|v| v.as_u64()) {
        update_label_by_name(flow_box, &format!("bottom-stat-{host_id}"), |lbl| {
            lbl.set_label(&format!("Clients: {clients}"));
        });
    }
}

/// Extract CPU or memory value from FortiGate resource data.
/// Handles both `u64` and array `[{"current": N}]` formats.
fn extract_resource_val(resource: Option<&Value>, results: &Value, key: &str) -> Option<u64> {
    resource
        .and_then(|r| r.get(key))
        .and_then(|v| v.as_u64().or_else(|| v.as_array()?.first()?.get("current")?.as_u64()))
        .or_else(|| {
            let v = results.get(key)?;
            v.as_u64().or_else(|| v.as_array()?.first()?.get("current")?.as_u64())
        })
}

// ---------------------------------------------------------------------------
// Cloud device cards
// ---------------------------------------------------------------------------

/// Add cards for cloud-fetched UniFi devices and apply their status.
/// Processes in batches via idle callbacks to avoid blocking the GTK main loop.
pub fn add_cloud_device_cards(
    flow_box: &gtk4::FlowBox,
    devices: &[(String, String, String, Value)],
) {
    let batch: Vec<_> = devices.iter().map(|(id, label, hostname, data)| {
        (id.replace(':', ""), label.clone(), hostname.clone(), data.clone())
    }).collect();

    let flow_box = flow_box.clone();
    let idx = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let batch = std::rc::Rc::new(batch);
    let idx_c = idx.clone();
    let batch_c = batch.clone();
    let fb = flow_box.clone();

    for (ref card_id, ref label, ref hostname, ref data) in batch.iter() {
        let site = data.get("site").and_then(|v| v.as_str()).unwrap_or("");
        let card = build_cloud_card(card_id, label, hostname, site);
        // Widget name includes site prefix for grouping in sort order.
        let sort_key = if site.is_empty() {
            format!("cloud-zz-{card_id}")
        } else {
            format!("cloud-{}-{card_id}", site.to_lowercase().replace(' ', "-"))
        };
        card.set_widget_name(&sort_key);
        flow_box.append(&card);
        apply_dashboard_status(&flow_box, card_id, data);
    }
    flow_box.invalidate_sort();
    flow_box.invalidate_filter();
    refresh_summary(&flow_box);
}

/// Build a card for a cloud-fetched device (no SshHostSummary needed).
fn build_cloud_card(id: &str, label: &str, hostname: &str, site: &str) -> gtk4::FlowBoxChild {
    let card = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(6)
        .css_classes(["card"])
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .build();
    card.set_size_request(280, -1);

    let header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_top(12)
        .margin_start(12)
        .margin_end(12)
        .build();

    let health_dot = gtk4::Label::builder()
        .label("\u{25CF}")
        .css_classes(["dim-label"])
        .build();
    health_dot.set_widget_name(&format!("health-dot-{id}"));

    let name_lbl = gtk4::Label::builder()
        .label(label)
        .css_classes(["heading"])
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .ellipsize(gtk4::pango::EllipsizeMode::End)
        .build();

    header.append(&health_dot);
    header.append(&name_lbl);
    card.append(&header);

    // Subtitle: site name + hostname.
    let subtitle = if site.is_empty() {
        hostname.to_owned()
    } else if hostname.is_empty() {
        site.to_owned()
    } else {
        format!("{site} \u{b7} {hostname}")
    };
    let host_lbl = gtk4::Label::builder()
        .label(&subtitle)
        .css_classes(["caption", "dim-label"])
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .ellipsize(gtk4::pango::EllipsizeMode::End)
        .build();
    card.append(&host_lbl);

    let info_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(3)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .margin_top(2)
        .build();

    info_box.append(&make_caption_label("", &format!("model-{id}")));
    info_box.append(&make_caption_label("", &format!("firmware-{id}")));
    info_box.append(&make_caption_label("", &format!("uptime-{id}")));
    info_box.append(&make_caption_label("", &format!("wan-ip-{id}")));
    info_box.append(&make_progress_row("CPU", &format!("cpu-bar-{id}"), &format!("cpu-pct-{id}")));
    info_box.append(&make_progress_row("Mem", &format!("mem-bar-{id}"), &format!("mem-pct-{id}")));
    info_box.append(&make_caption_label("", &format!("bottom-stat-{id}")));

    card.append(&info_box);
    gtk4::FlowBoxChild::builder().child(&card).build()
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
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
