//! Opt-in visual QA using real widgets and synthetic data, without a daemon.

use super::{design, shell, vpn};
use crate::app::AppState;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::sync::{mpsc, Arc, Mutex};

/// Run under Xvfb with `--ignored --test-threads=1`; writes to the supplied
/// SUPERMGR_PREVIEW_DIR. No real hosts, credentials or connections are loaded.
#[test]
#[ignore = "requires a display and SUPERMGR_PREVIEW_DIR"]
fn render_linux_preview() {
    let out = std::path::PathBuf::from(
        std::env::var("SUPERMGR_PREVIEW_DIR").expect("preview output directory"),
    );
    std::fs::create_dir_all(&out).unwrap();
    adw::init().unwrap();
    design::install_stylesheet();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (tx, _rx) = mpsc::channel();
    let id = uuid::Uuid::from_u128(1);
    let profiles = [
        (id, "Oslo office", "WireGuard", "Nordic Systems"),
        (
            uuid::Uuid::from_u128(2),
            "Customer gateway",
            "FortiGate IPsec",
            "Acme",
        ),
        (
            uuid::Uuid::from_u128(3),
            "Development",
            "OpenVPN",
            "Internal",
        ),
    ]
    .into_iter()
    .map(|(id, name, backend, customer)| {
        serde_json::from_value(serde_json::json!({
            "id": id, "name": name, "backend": backend, "customer": customer,
            "auto_connect": true, "full_tunnel": false, "kill_switch": true,
            "last_connected_secs": chrono::Utc::now().timestamp(),
        }))
        .unwrap()
    })
    .collect();
    let state = Arc::new(Mutex::new(AppState {
        profiles,
        selected_profile: Some(id.to_string()),
        daemon_available: true,
        vpn_state: supermgr_core::vpn::state::VpnState::Connected {
            profile_id: id,
            since: chrono::Utc::now(),
            interface: "wg-office".into(),
        },
        ..AppState::default()
    }));
    let window = adw::ApplicationWindow::builder()
        .title("SuperManager")
        .css_classes(["supermgr-window"])
        .default_width(1280)
        .default_height(800)
        .build();
    let (_list, _, sidebar) = vpn::sidebar::build_vpn_sidebar(&state, &tx, rt.handle(), &window);
    let (mut detail, page) = vpn::detail::build_vpn_detail();
    detail.profile_name_label.set_label("Oslo office");
    detail.detail_stack.set_visible_child_name("detail");
    for switch in [
        &detail.auto_connect_switch,
        &detail.full_tunnel_switch,
        &detail.kill_switch_switch,
    ] {
        switch.set_sensitive(true);
    }
    detail.auto_connect_switch.set_active(true);
    detail.kill_switch_switch.set_active(true);
    detail.stats_sent.set_label("12.4 MB");
    detail.stats_recv.set_label("86.2 MB");
    detail.stats_uptime.set_label("24m 08s");
    detail.stats_uptime.set_visible(true);
    detail.stats_handshake.set_label("18 seconds ago");
    detail.stats_virtual_ip.set_label("10.24.0.2");
    detail.stats_virtual_ip.set_visible(true);
    detail.rename_btn.set_sensitive(true);
    detail.export_btn.set_sensitive(true);
    detail.duplicate_btn.set_sensitive(true);
    let split = super::layout::split(&sidebar, &page, 320);
    let stack = adw::ViewStack::new();
    let sample_host: supermgr_core::host::HostSummary = serde_json::from_value(serde_json::json!({
        "id":uuid::Uuid::from_u128(100),"label":"Oslo application server","hostname":"app01.example.test","port":22,
        "username":"operator","device_type":"linux","auth_method":"key","auth_key_id":uuid::Uuid::from_u128(10),
        "group":"Nordic Systems","customer":"Nordic-Systems","has_api":false,"pinned":false
    })).unwrap();
    let sample_key: supermgr_core::ssh::key::SshKeySummary = serde_json::from_value(serde_json::json!({
        "id":uuid::Uuid::from_u128(10),"name":"Production operations","key_type":"ED25519","fingerprint":"SHA256:SyntheticPreviewFingerprintOnly123456789",
        "deployed_count":1,"assigned_host_ids":[sample_host.id],"deployed_host_ids":[sample_host.id],"created_at":chrono::Utc::now()
    })).unwrap();
    for section in shell::all_sections() {
        if section.id == "vpn" {
            stack.add_titled(&split, Some(section.id), section.title);
        } else if section.id == "customers" {
            let view = super::customers::build_customer_page(&window, rt.handle(), &tx);
            let customer = supermgr_core::customer::Customer {
                slug: "Nordic-Systems".into(),
                display_name: "Nordic Systems".into(),
                contact_name: "Operations team".into(),
                contact_email: "operations@example.test".into(),
                sites: vec![supermgr_core::customer::Site {
                    id: "oslo".into(),
                    display_name: "Oslo office".into(),
                    ..Default::default()
                }],
                ..Default::default()
            };
            view.render(
                &[customer],
                std::slice::from_ref(&sample_host),
                &state.lock().unwrap().profiles,
            );
            stack.add_titled(&view.widget, Some(section.id), section.title);
        } else if section.id == "fleet" {
            let (flow, inner, widget) =
                super::ssh::dashboard::build_ssh_dashboard(&state, rt.handle(), &tx);
            let mut gateway = sample_host.clone();
            gateway.id = uuid::Uuid::from_u128(200);
            gateway.label = "Office firewall".into();
            gateway.device_type = supermgr_core::ssh::DeviceType::Fortigate;
            gateway.has_api = true;
            super::ssh::dashboard::preview_cards(&flow, &[gateway], &state);
            inner.set_visible_child_name("content");
            stack.add_titled(&widget, Some(section.id), section.title);
        } else if section.id == "tailscale" {
            let view = super::tailscale::build_tailscale_page(rt.handle(), &tx, &window, &state);
            let nodes = serde_json::from_value(serde_json::json!([
                {"id":"self","hostname":"linux-workstation","dns_name":"linux-workstation.example.ts.net","os":"linux","tailscale_ips":["100.64.0.10"],"online":true,"is_self":true,"exit_node":false,"last_seen":"","rx_bytes":0,"tx_bytes":0},
                {"id":"peer","hostname":"office-gateway","dns_name":"office-gateway.example.ts.net","os":"linux","tailscale_ips":["100.64.0.20","fd7a:115c:a1e0::20"],"online":true,"is_self":false,"exit_node":false,"exit_node_option":true,"last_seen":"2026-09-09T18:00:00Z","rx_bytes":18452388,"tx_bytes":5001234,"current_address":"192.168.10.1:41641","relay":"Oslo"},
                {"id":"offline","hostname":"office-mac","dns_name":"office-mac.example.ts.net","os":"macOS","tailscale_ips":["100.64.0.30"],"online":false,"is_self":false,"exit_node":false,"last_seen":"2026-09-08T12:00:00Z","rx_bytes":0,"tx_bytes":0}
            ])).unwrap();
            view.render(&Ok(nodes));
            view.render_management(&Ok(serde_json::from_value(serde_json::json!({
                "profiles":[{"id":"work","account":"work@example.test","tailnet":"Office","selected":true},{"id":"home","account":"home@example.test","tailnet":"Home","selected":false}],
                "preferences":{"profile_id":"work","want_running":true,"accept_dns":true,"accept_routes":false,"shields_up":false,"run_ssh":false,"exit_node_allow_lan":true,"advertise_exit_node":false,"advertise_routes":[],"hostname":"","auto_update":false}
            })).unwrap()));
            stack.add_titled(&view.widget, Some(section.id), section.title);
        } else if section.id == "hosts" {
            let mut missing = sample_host.clone();
            missing.id = uuid::Uuid::from_u128(101);
            missing.label = "Staging Linux".into();
            missing.auth_key_id = Some(uuid::Uuid::from_u128(999));
            let hosts = vec![sample_host.clone(), missing.clone()];
            let list = super::ssh::host_tree::build_ssh_host_list();
            super::ssh::host_tree::populate_ssh_host_list(
                &list,
                &hosts,
                Some(&missing.id.to_string()),
                &window,
                rt.handle(),
                &tx,
                "",
                &Default::default(),
            );
            let side = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
            side.append(
                &gtk4::SearchEntry::builder()
                    .placeholder_text("Find an SSH host")
                    .margin_start(10)
                    .margin_end(10)
                    .margin_top(10)
                    .build(),
            );
            side.append(
                &gtk4::ScrolledWindow::builder()
                    .hscrollbar_policy(gtk4::PolicyType::Never)
                    .vexpand(true)
                    .child(&list)
                    .build(),
            );
            let (detail, widget) = super::ssh::host_detail::build_ssh_host_detail();
            super::ssh::host_detail::update_ssh_host_detail(
                &detail,
                &missing,
                &hosts,
                std::slice::from_ref(&sample_key),
            );
            stack.add_titled(
                &super::layout::split(&side, &widget, 320),
                Some(section.id),
                section.title,
            );
        } else if section.id == "keys" {
            let list = super::ssh::key_list::build_ssh_key_list();
            let keys = [
                "Production operations",
                "Linux-VM",
                "RouterLaptopKontor",
                "ssd",
                "Very long key name for customer production servers",
            ]
            .into_iter()
            .enumerate()
            .map(|(i, name)| supermgr_core::ssh::key::SshKeySummary {
                id: uuid::Uuid::from_u128(10 + i as u128),
                name: name.into(),
                key_type: supermgr_core::ssh::key::SshKeyType::Ed25519,
                fingerprint: "SHA256:SyntheticPreviewFingerprintOnly123456789".into(),
                tags: vec![],
                deployed_count: usize::from(i == 0),
                assigned_host_ids: if i == 0 { vec![sample_host.id] } else { vec![] },
                deployed_host_ids: if i == 0 { vec![sample_host.id] } else { vec![] },
                created_at: chrono::Utc::now(),
            })
            .collect::<Vec<_>>();
            super::ssh::key_list::populate_ssh_key_list(
                &list,
                &keys,
                Some(&sample_key.id.to_string()),
                &window,
                rt.handle(),
                &tx,
                "",
            );
            let search = gtk4::SearchEntry::builder()
                .placeholder_text("Filter keys…")
                .margin_start(8)
                .margin_end(8)
                .margin_top(8)
                .build();
            let sidebar = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
            sidebar.append(&search);
            sidebar.append(
                &gtk4::ScrolledWindow::builder()
                    .hscrollbar_policy(gtk4::PolicyType::Never)
                    .vexpand(true)
                    .child(&list)
                    .build(),
            );
            let side = adw::NavigationPage::builder()
                .title("Keys")
                .child(&sidebar)
                .build();
            let (key_detail, detail) = super::ssh::key_detail::build_ssh_key_detail();
            super::ssh::key_detail::update_ssh_key_detail(
                &key_detail,
                &sample_key,
                std::slice::from_ref(&sample_host),
                "ssh-ed25519 AAAA-SYNTHETIC-PREVIEW-ONLY operations@example.test",
                &[],
            );
            super::ssh::key_detail::populate_key_usage(
                &key_detail.deployed_list,
                &sample_key,
                std::slice::from_ref(&sample_host),
                &tx,
            );
            let content = adw::NavigationPage::builder()
                .title("Details")
                .child(&detail)
                .build();
            let split = super::ssh::key_list::build_ssh_key_split(&side, &content);
            stack.add_titled(&split, Some(section.id), section.title);
        } else if section.id == "console" {
            let settings = Arc::new(Mutex::new(crate::settings::AppSettings::default()));
            let (_, console) =
                super::console::panel::build_console_page(&state, &settings, &tx, rt.handle());
            stack.add_titled(&console, Some(section.id), section.title);
        } else if section.id == "provisioning" {
            let review = super::provisioning::wizard::preview_review(&state, &tx, rt.handle());
            stack.add_titled(&review, Some(section.id), section.title);
        } else if section.id == "recon" {
            let view = super::recon::build_recon_page(&state, &window, rt.handle(), &tx);
            let result = serde_json::from_value(serde_json::json!({
                "target":"192.168.1.0/24","ports":[22,443],"started_at":"2026-09-09T12:00:00Z",
                "finished_at":"2026-09-09T12:00:02Z","hosts":[
                    {"ip":"192.168.1.1","open_ports":[22,443],"managed_host_id":"fixture","managed_label":"Oslo gateway","customer":"Nordic Systems",
                     "services":[{"port":22,"name":"SSH","source":"ssh_banner","banner":"SSH-2.0-Fixture"},{"port":443,"name":"HTTPS","source":"port"}]},
                    {"ip":"192.168.1.24","open_ports":[443],"services":[{"port":443,"name":"HTTPS","source":"port"}]}
                ]
            })).unwrap();
            view.show_result(&result);
            stack.add_titled(&view.widget, Some(section.id), section.title);
        } else if section.id == "security" {
            let view = super::security::build_security_page(rt.handle(), &tx);
            view.set_saved_scopes(vec!["Nordic-Systems".into()]);
            let findings = vec![serde_json::from_value(serde_json::json!({
                "key":"fixture|web01|-|-", "disposition":{"kind":"open"},
                "first_seen":"2026-09-01T10:00:00Z","last_seen":"2026-09-09T12:00:00Z","scan_count":3,
                "finding":{"id":"linux.ssh.root-login-disabled","host_ip":"web01","severity":"high",
                    "title":"Direct root login enabled","detail":"Observed: permitrootlogin yes",
                    "recommendation":"Use individual accounts with sudo; verify access before changing sshd."}
            })).unwrap()];
            let summary = serde_json::from_value(serde_json::json!({
                "open":1,"high":1,"critical":0,"medium":0,"low":0,"info":0,
                "accepted_risk":0,"fixed":0,"false_positive":0,"total":1,"last_scan_at":"2026-09-09T12:00:00Z"
            })).unwrap();
            view.show_findings("Nordic-Systems", &summary, &findings);
            stack.add_titled(&view.widget, Some(section.id), section.title);
        } else if section.id == "compliance" {
            let view = super::compliance::build_compliance_page(rt.handle(), &tx);
            let hosts = vec![serde_json::from_value(serde_json::json!({
                "id":uuid::Uuid::from_u128(5),"label":"Web server","hostname":"web01","port":22,
                "username":"admin","device_type":"linux","auth_method":"key","key_name":"Operations",
                "group":"Nordic Systems","customer":"Nordic-Systems","has_api":false,"pinned":false
            })).unwrap()];
            view.set_hosts(&hosts);
            stack.add_titled(&view.widget, Some(section.id), section.title);
        } else {
            stack.add_titled(
                &gtk4::Box::new(gtk4::Orientation::Vertical, 0),
                Some(section.id),
                section.title,
            );
        }
    }
    let shell = shell::build(&stack, &stack);
    super::layout::adapt_shell(&window, &shell.widget);
    detail.status.toolbar_slot = shell.vpn_status;
    for name in ["list-add-symbolic", "preferences-system-symbolic"] {
        shell.header_end.append(&gtk4::Button::from_icon_name(name));
    }
    window.set_content(Some(&shell.widget));
    window.present();
    for (name, width, dark, error) in [
        ("linux-light", 1280, false, false),
        ("linux-dark", 1280, true, false),
        ("linux-narrow", 1024, false, false),
        ("linux-error", 1280, false, true),
        ("linux-console", 1280, false, false),
        ("linux-console-narrow", 900, true, false),
        ("linux-customers", 1280, false, false),
        ("linux-customers-narrow", 900, true, false),
        ("linux-fleet", 1280, true, false),
        ("linux-fleet-narrow", 900, false, false),
        ("linux-compliance-narrow", 900, true, false),
        ("linux-security-narrow", 900, true, false),
        ("linux-security", 1280, false, false),
        ("linux-recon", 1280, false, false),
        ("linux-compliance", 1280, false, false),
        ("linux-security-dark", 1280, true, false),
        ("linux-recon-narrow", 1024, false, false),
        ("linux-provisioning-narrow", 1024, false, false),
        ("linux-keys-dark", 1262, true, false),
        ("linux-keys-narrow", 900, false, false),
        ("linux-hosts-dark", 1280, true, false),
        ("linux-hosts-narrow", 900, false, false),
        ("linux-tailscale-dark", 1262, true, false),
        ("linux-tailscale-narrow", 1024, false, false),
        ("linux-tailscale-settings", 1262, true, false),
        ("linux-tailscale-add-account", 900, false, false),
    ] {
        if let Some(dialog) = window.visible_dialog() { dialog.force_close(); }
        adw::StyleManager::default().set_color_scheme(if dark {
            adw::ColorScheme::ForceDark
        } else {
            adw::ColorScheme::ForceLight
        });
        window.set_default_size(width, 800);
        let section_name = if name.contains("console") {
            "console"
        } else if name.contains("customers") {
            "customers"
        } else if name.contains("fleet") {
            "fleet"
        } else if name.contains("tailscale") {
            "tailscale"
        } else if name.contains("hosts") {
            "hosts"
        } else if name.contains("keys") {
            "keys"
        } else if name.contains("security") {
            "security"
        } else if name.contains("recon") {
            "recon"
        } else if name.contains("provisioning") {
            "provisioning"
        } else if name.contains("compliance") {
            "compliance"
        } else {
            "vpn"
        };
        stack.set_visible_child_name(section_name);
        if error {
            state.lock().unwrap().vpn_state = supermgr_core::vpn::state::VpnState::Error {
                profile_id: Some(id), code: supermgr_core::vpn::state::ErrorCode::Internal,
                message: "The gateway is currently unreachable. Kill switch remains active while reconnecting. Disconnect to release it.".into(),
            };
        }
        vpn::detail::apply_vpn_state(&detail.status, &state.lock().unwrap());
        if name == "linux-tailscale-settings" || name == "linux-tailscale-add-account" {
            fn click_button(widget: &gtk4::Widget, label: &str) -> bool {
                if let Some(button) = widget.downcast_ref::<gtk4::Button>() {
                    if button.label().as_deref() == Some(label) {
                        button.emit_clicked();
                        return true;
                    }
                }
                let mut child = widget.first_child();
                while let Some(widget) = child {
                    if click_button(&widget, label) {
                        return true;
                    }
                    child = widget.next_sibling();
                }
                false
            }
            let label = if name.ends_with("add-account") { "Add account…" } else { "Settings" };
            assert!(click_button(stack.visible_child().unwrap().upcast_ref(), label));
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(450);
        while std::time::Instant::now() < deadline {
            while gtk4::glib::MainContext::default().iteration(false) {}
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            stack.visible_child_name().as_deref(),
            Some(section_name),
            "resize changed workspace for {name}"
        );
        let paintable = gtk4::WidgetPaintable::new(Some(&window));
        let snapshot = gtk4::Snapshot::new();
        paintable.snapshot(
            &snapshot,
            f64::from(window.width()),
            f64::from(window.height()),
        );
        let node = snapshot.to_node().expect("rendered window");
        let texture = window.renderer().unwrap().render_texture(&node, None);
        texture
            .save_to_png(out.join(format!("{name}.png")))
            .unwrap();
    }
    window.close();
}
