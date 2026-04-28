//! Multi-step provisioning wizard for FortiGate and UniFi devices.
//!
//! Collects customer info, network design, services, security policies,
//! then generates device configuration via Claude and pushes it over
//! REST API or SSH.

use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::io::Write as IoWrite;
use std::rc::Rc;
use std::sync::{mpsc, Arc, Mutex};

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::app::{AppMsg, AppState};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TOTAL_STEPS: u32 = 5;

const PROVISIONING_SYSTEM_PROMPT: &str = "\
You are an expert network engineer specializing in FortiGate and UniFi device \
configuration. Generate production-ready configurations following CIS benchmarks \
and industry best practices.\n\n\
CRITICAL RULES — FOLLOW EXACTLY:\n\
- Output FortiGate config as CLI commands ONLY. No markdown fences, no explanations, \
  no text before or after the config. Just pure FortiGate CLI.\n\
- Output UniFi config as JSON suitable for the UniFi Controller API.\n\
- The LAN base subnet MUST match the subnet specified in the input — use the EXACT value.\n\
- All VLAN subnets must use the exact values from the input — do not change octets.\n\
- For web filter categories, add an inline comment with the category name \
  (e.g. set category 2  # Adult/Mature Content).\n\
- Mark all placeholder credentials with CHANGE-ME.\n\
- Add a deployment checklist at the end as CLI comments.\n\n\
VPN RULES:\n\
- ONLY include VPN configuration if the input has a '## VPN' section.\n\
- If there is NO '## VPN' section in the input, do NOT generate ANY VPN config — \
  no phase1, no phase2, no VPN policies, no VPN users, no VPN references at all.\n\
- NEVER use SSL-VPN. NEVER mention SSL-VPN in config or comments.\n\
- For remote access, use IPsec IKEv2 with EAP authentication.\n\
- For S2S VPN, use IKEv2 with AES-256-GCM and DH group 20 (ECP384).\n\n\
CREDENTIALS:\n\
- Use the pre-generated credentials from the '## Pre-generated Credentials' section.\n\
- Do NOT use 'CHANGE-ME' for items that already have a generated value.\n\
- Only use 'CHANGE-ME' for items that genuinely need manual configuration \
  (e.g. S2S remote gateway IP, remote subnets).\n\n\
WIFI RULES:\n\
- ONLY include WiFi/FortiAP configuration if the input has a '## WiFi / FortiAP' section.\n\
- Configure SSIDs on the correct VLAN interfaces.\n\
- Apply the specified security mode (WPA3-Enterprise, WPA3-Personal, WPA2-Personal).\n\
- If Guest Portal is Yes, configure a captive portal on the guest SSID.\n\n\
SD-WAN RULES:\n\
- ONLY include SD-WAN configuration if the input has a '## SD-WAN' section.\n\
- Use the specified health check target and load balance mode.\n\
- Configure performance SLA with ping and HTTP probes.\n\n\
SNMP RULES:\n\
- ONLY include SNMP configuration if the input has a '## SNMP' section.\n\
- Use the specified community string and version.\n\
- Configure trap targets if provided.\n\
- For v3, configure USM user with auth (SHA) and priv (AES128).\n\n\
FORTIGATE SPECIFICS:\n\
- Use policy IDs in ranges: 100s=Staff, 200s=Guests, 300s=IoT, 400s=Mgmt, 999=deny-all.\n\
- Always include DoS policy on WAN interface.\n\
- Disable unused interfaces (wan2, dmz, etc.).\n\
- Enable FortiGuard auto-updates.\n\n\
UNIFI SPECIFICS:\n\
- Configure networks, VLANs, firewall rules, and RADIUS profiles as JSON.\n\
- Include threat management and DPI settings.\n\
- Use proper WPA3/WPA2 for wireless if applicable.";

// ---------------------------------------------------------------------------
// Wizard state
// ---------------------------------------------------------------------------

/// VLAN definition collected in the network design step.
#[derive(Debug, Clone, Default)]
struct VlanEntry {
    id: u32,
    name: String,
    subnet: String,
}

/// All data collected across the wizard steps.
#[derive(Debug, Clone, Default)]
struct WizardState {
    // Step 1: Customer info
    customer_name: String,
    location: String,
    device_type: String, // "FortiGate" or "UniFi"
    target_host_id: String,
    target_host_label: String,

    // Step 2: Network design
    wan_type: String, // "DHCP", "Static", "PPPoE"
    wan_ip: String,
    wan_gateway: String,
    wan_dns: String,
    lan_subnet: String,
    vlans: Vec<VlanEntry>,
    management_vlan: bool,

    // Step 3: Services
    vpn_site_to_site: bool,
    vpn_remote_access: bool,
    dns_servers: String,
    ntp_server: String,
    syslog_enabled: bool,
    syslog_target: String,
    admin_https_port: u32,

    // Step 3: WiFi / FortiAP
    wifi_enabled: bool,
    wifi_ssid_staff: String,
    wifi_ssid_guest: String,
    wifi_security: String,
    wifi_guest_portal: bool,

    // Step 3: SD-WAN (FortiGate only)
    sdwan_enabled: bool,
    sdwan_health_target: String,
    sdwan_mode: String,

    // Step 3: SNMP
    snmp_enabled: bool,
    snmp_community: String,
    snmp_trap_target: String,
    snmp_version: String,

    // Step 4: Security (FortiGate only)
    default_deny: bool,
    allow_outbound_web: bool,
    allow_dns: bool,
    enable_ips: bool,
    enable_web_filter: bool,
    enable_antivirus: bool,

    // Step 5: Generated config
    generated_config: String,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Build the provisioning page widget.
///
/// Returns a widget suitable for adding to the main `AdwViewStack`.
pub fn build_provisioning_page(
    app_state: &Arc<Mutex<AppState>>,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
) -> gtk4::Widget {
    let state = Rc::new(RefCell::new(WizardState {
        dns_servers: "1.1.1.1, 8.8.8.8".into(),
        ntp_server: "pool.ntp.org".into(),
        admin_https_port: 443,
        default_deny: true,
        allow_outbound_web: true,
        allow_dns: true,
        enable_ips: true,
        enable_web_filter: true,
        enable_antivirus: true,
        ..Default::default()
    }));

    // Main stack for wizard steps
    let step_stack = gtk4::Stack::builder()
        .transition_type(gtk4::StackTransitionType::SlideLeftRight)
        .transition_duration(200)
        .vexpand(true)
        .hexpand(true)
        .build();

    // Step indicator label
    let step_label = gtk4::Label::builder()
        .label("Step 1 of 5")
        .css_classes(["dim-label"])
        .build();

    // Navigation buttons
    let back_btn = gtk4::Button::builder()
        .label("Back")
        .css_classes(["flat"])
        .sensitive(false)
        .build();

    let next_btn = gtk4::Button::builder()
        .label("Next")
        .css_classes(["suggested-action", "pill"])
        .build();

    // Build each step page
    let step1 = build_step1_customer_info(&state, app_state);
    let step2 = build_step2_network_design(&state);
    let step3 = build_step3_services(&state);
    let step4 = build_step4_security(&state);
    let step5 = build_step5_review(&state, app_state, tx, rt);

    step_stack.add_named(&step1, Some("step1"));
    step_stack.add_named(&step2, Some("step2"));
    step_stack.add_named(&step3, Some("step3"));
    step_stack.add_named(&step4, Some("step4"));
    step_stack.add_named(&step5, Some("step5"));

    step_stack.set_visible_child_name("step1");

    // Bottom action bar with navigation
    let nav_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .margin_start(16)
        .margin_end(16)
        .margin_top(12)
        .margin_bottom(12)
        .halign(gtk4::Align::Fill)
        .build();

    nav_box.append(&back_btn);
    let spacer = gtk4::Box::builder()
        .hexpand(true)
        .build();
    nav_box.append(&spacer);
    nav_box.append(&step_label);
    let spacer2 = gtk4::Box::builder()
        .hexpand(true)
        .build();
    nav_box.append(&spacer2);
    nav_box.append(&next_btn);

    let action_bar = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    let separator = gtk4::Separator::new(gtk4::Orientation::Horizontal);
    action_bar.append(&separator);
    action_bar.append(&nav_box);

    // Track current step
    let current_step = Rc::new(RefCell::new(1u32));

    // Navigation logic
    {
        let step_stack = step_stack.clone();
        let step_label = step_label.clone();
        let back_btn = back_btn.clone();
        let next_btn = next_btn.clone();
        let current_step = Rc::clone(&current_step);
        let state = Rc::clone(&state);

        let update_nav = Rc::new({
            let step_label = step_label.clone();
            let back_btn = back_btn.clone();
            let next_btn = next_btn.clone();
            let current_step = Rc::clone(&current_step);
            let state = Rc::clone(&state);
            move || {
                let step = *current_step.borrow();
                step_label.set_label(&format!("Step {} of {}", step, TOTAL_STEPS));
                back_btn.set_sensitive(step > 1);

                // Skip security step for UniFi
                let is_fortigate = state.borrow().device_type == "FortiGate";
                let effective_max = if is_fortigate { TOTAL_STEPS } else { TOTAL_STEPS };

                if step >= effective_max {
                    next_btn.set_label("Finish");
                    next_btn.set_css_classes(&["suggested-action", "pill"]);
                } else {
                    next_btn.set_label("Next");
                    next_btn.set_css_classes(&["suggested-action", "pill"]);
                }
            }
        });

        // Next button
        {
            let step_stack = step_stack.clone();
            let current_step = Rc::clone(&current_step);
            let update_nav = Rc::clone(&update_nav);
            let state_ref = Rc::clone(&state);
            next_btn.connect_clicked(move |_| {
                let mut step = current_step.borrow_mut();
                if *step < TOTAL_STEPS {
                    // Sync state from widgets before advancing
                    *step += 1;

                    // Skip step 4 (security) for UniFi
                    let is_fortigate = state_ref.borrow().device_type == "FortiGate";
                    if *step == 4 && !is_fortigate {
                        *step = 5;
                    }

                    step_stack.set_visible_child_name(&format!("step{}", *step));
                    drop(step);
                    update_nav();
                }
            });
        }

        // Back button
        {
            let step_stack = step_stack.clone();
            let current_step = Rc::clone(&current_step);
            let update_nav = Rc::clone(&update_nav);
            let state_ref = Rc::clone(&state);
            back_btn.connect_clicked(move |_| {
                let mut step = current_step.borrow_mut();
                if *step > 1 {
                    *step -= 1;

                    // Skip step 4 (security) for UniFi when going back
                    let is_fortigate = state_ref.borrow().device_type == "FortiGate";
                    if *step == 4 && !is_fortigate {
                        *step = 3;
                    }

                    step_stack.set_visible_child_name(&format!("step{}", *step));
                    drop(step);
                    update_nav();
                }
            });
        }

        update_nav();
    }

    // Assemble the page
    let page = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .vexpand(true)
        .hexpand(true)
        .build();

    // Title banner
    let title_bar = adw::Banner::builder()
        .title("Device Provisioning Wizard")
        .revealed(true)
        .build();
    title_bar.add_css_class("accent");

    page.append(&title_bar);
    page.append(&step_stack);
    page.append(&action_bar);

    page.upcast()
}

// ---------------------------------------------------------------------------
// Step 1: Customer Info
// ---------------------------------------------------------------------------

fn build_step1_customer_info(
    state: &Rc<RefCell<WizardState>>,
    app_state: &Arc<Mutex<AppState>>,
) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    // Customer details group
    let customer_group = adw::PreferencesGroup::builder()
        .title("Customer Information")
        .description("Enter the customer and site details for this deployment.")
        .build();

    // Template selector — pre-fills the wizard with common setups
    let template_row = adw::ComboRow::builder()
        .title("Template")
        .subtitle("Pre-fill with a common deployment profile")
        .build();
    let template_list = gtk4::StringList::new(&[
        "Custom",
        "SMB Office",
        "Retail Store",
        "Branch Office",
        "Home Office",
    ]);
    template_row.set_model(Some(&template_list));

    let name_row = adw::EntryRow::builder()
        .title("Customer Name")
        .build();

    let location_row = adw::EntryRow::builder()
        .title("Location")
        .build();

    // Device type combo
    let device_type_row = adw::ComboRow::builder()
        .title("Device Type")
        .subtitle("Select the target device platform")
        .build();
    let device_types = gtk4::StringList::new(&["FortiGate", "UniFi"]);
    device_type_row.set_model(Some(&device_types));

    // Target host combo (populated from AppState)
    let host_row = adw::ComboRow::builder()
        .title("Target Host")
        .subtitle("Select an SSH host to push configuration to")
        .build();

    // Populate hosts from app state filtered by device type
    let host_model = gtk4::StringList::new(&[] as &[&str]);
    host_row.set_model(Some(&host_model));

    // Store host IDs alongside labels for lookup
    let host_ids: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));

    let populate_hosts = {
        let host_model = host_model.clone();
        let host_ids = Rc::clone(&host_ids);
        let app_state = Arc::clone(app_state);
        let host_row = host_row.clone();
        move |device_filter: &str| {
            // Clear existing
            let n = host_model.n_items();
            if n > 0 {
                host_model.splice(0, n, &[] as &[&str]);
            }
            host_ids.borrow_mut().clear();

            let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
            let filter = match device_filter {
                "FortiGate" => "Fortigate",
                "UniFi" => "UniFi",
                _ => "",
            };
            let mut labels = Vec::new();
            for host in &s.hosts {
                let dt = format!("{:?}", host.device_type);
                if filter.is_empty() || dt == filter {
                    labels.push(format!("{} ({}@{})", host.label, host.username, host.hostname));
                    host_ids.borrow_mut().push(host.id.to_string());
                }
            }
            drop(s);

            if labels.is_empty() {
                host_model.append("(no matching hosts)");
                host_ids.borrow_mut().push(String::new());
                host_row.set_sensitive(false);
            } else {
                host_row.set_sensitive(true);
                for label in &labels {
                    host_model.append(label);
                }
            }
        }
    };

    // Initial population
    populate_hosts("FortiGate");

    // Re-populate when device type changes
    {
        let populate_hosts = populate_hosts.clone();
        let state = Rc::clone(state);
        device_type_row.connect_selected_notify(move |row| {
            let idx = row.selected();
            let dt = if idx == 0 { "FortiGate" } else { "UniFi" };
            state.borrow_mut().device_type = dt.to_string();
            populate_hosts(dt);
        });
    }

    // Sync fields to state on change
    {
        let state = Rc::clone(state);
        name_row.connect_changed(move |row| {
            let text = row.text().to_string();
            // Auto-generate LAN subnet from customer name hash
            let mut hasher = DefaultHasher::new();
            text.hash(&mut hasher);
            let h = hasher.finish();
            let octet2 = ((h >> 8) & 0xFF) as u8;
            let octet3 = (h & 0xFF) as u8;
            let subnet = format!("10.{}.{}.0/24", octet2, octet3);
            let mut s = state.borrow_mut();
            s.customer_name = text;
            s.lan_subnet = subnet;
        });
    }
    {
        let state = Rc::clone(state);
        location_row.connect_changed(move |row| {
            state.borrow_mut().location = row.text().to_string();
        });
    }
    {
        let state = Rc::clone(state);
        let host_ids = Rc::clone(&host_ids);
        host_row.connect_selected_notify(move |row| {
            let idx = row.selected() as usize;
            let ids = host_ids.borrow();
            if let Some(id) = ids.get(idx) {
                state.borrow_mut().target_host_id = id.clone();
            }
            if let Some(model) = row.model() {
                if let Some(item) = model.item(idx as u32) {
                    if let Ok(s) = item.downcast::<gtk4::StringObject>() {
                        state.borrow_mut().target_host_label = s.string().to_string();
                    }
                }
            }
        });
    }

    // Set initial device type
    state.borrow_mut().device_type = "FortiGate".to_string();

    // Template selection handler — fills WizardState with template defaults
    // but preserves customer_name and location.
    {
        let state = Rc::clone(state);
        template_row.connect_selected_notify(move |row| {
            let idx = row.selected();
            let mut s = state.borrow_mut();
            // Preserve customer-specific fields
            let name = s.customer_name.clone();
            let loc = s.location.clone();
            let host_id = s.target_host_id.clone();
            let host_label = s.target_host_label.clone();
            let device_type = s.device_type.clone();

            match idx {
                1 => {
                    // SMB Office — 3 VLANs (Staff/Guests/Mgmt), full security, S2S VPN
                    s.wan_type = "Static".into();
                    s.wan_ip = String::new();
                    s.wan_gateway = String::new();
                    s.wan_dns = "1.1.1.1".into();
                    s.lan_subnet = "10.10.0.0/24".into();
                    s.management_vlan = true;
                    s.vlans = vec![
                        VlanEntry { id: 10, name: "Staff".into(), subnet: "10.10.10.0/24".into() },
                        VlanEntry { id: 20, name: "Guests".into(), subnet: "10.10.20.0/24".into() },
                        VlanEntry { id: 99, name: "Management".into(), subnet: "10.10.99.0/24".into() },
                    ];
                    s.vpn_site_to_site = true;
                    s.vpn_remote_access = false;
                    s.dns_servers = "1.1.1.1, 8.8.8.8".into();
                    s.ntp_server = "pool.ntp.org".into();
                    s.syslog_enabled = true;
                    s.syslog_target = String::new();
                    s.admin_https_port = 8443;
                    s.default_deny = true;
                    s.allow_outbound_web = true;
                    s.allow_dns = true;
                    s.enable_ips = true;
                    s.enable_web_filter = true;
                    s.enable_antivirus = true;
                    // WiFi
                    s.wifi_enabled = true;
                    s.wifi_ssid_staff = String::new(); // auto-filled from customer name
                    s.wifi_ssid_guest = String::new();
                    s.wifi_security = "WPA3-Enterprise".into();
                    s.wifi_guest_portal = true;
                    // SD-WAN
                    s.sdwan_enabled = false;
                    s.sdwan_health_target = "8.8.8.8".into();
                    s.sdwan_mode = "Source IP".into();
                    // SNMP
                    s.snmp_enabled = true;
                    s.snmp_community = String::new(); // auto-generated on enable
                    s.snmp_trap_target = String::new();
                    s.snmp_version = "v2c".into();
                }
                2 => {
                    // Retail Store — 2 VLANs (POS/Guests), no VPN, strict security
                    s.wan_type = "DHCP".into();
                    s.wan_ip = String::new();
                    s.wan_gateway = String::new();
                    s.wan_dns = String::new();
                    s.lan_subnet = "10.20.0.0/24".into();
                    s.management_vlan = false;
                    s.vlans = vec![
                        VlanEntry { id: 10, name: "POS".into(), subnet: "10.20.10.0/24".into() },
                        VlanEntry { id: 20, name: "Guests".into(), subnet: "10.20.20.0/24".into() },
                    ];
                    s.vpn_site_to_site = false;
                    s.vpn_remote_access = false;
                    s.dns_servers = "1.1.1.1, 1.0.0.1".into();
                    s.ntp_server = "pool.ntp.org".into();
                    s.syslog_enabled = false;
                    s.syslog_target = String::new();
                    s.admin_https_port = 443;
                    s.default_deny = true;
                    s.allow_outbound_web = true;
                    s.allow_dns = true;
                    s.enable_ips = true;
                    s.enable_web_filter = true;
                    s.enable_antivirus = true;
                    // WiFi
                    s.wifi_enabled = true;
                    s.wifi_ssid_staff = String::new();
                    s.wifi_ssid_guest = String::new();
                    s.wifi_security = "WPA2-Personal".into();
                    s.wifi_guest_portal = true;
                    // SD-WAN
                    s.sdwan_enabled = false;
                    s.sdwan_health_target = "8.8.8.8".into();
                    s.sdwan_mode = "Source IP".into();
                    // SNMP
                    s.snmp_enabled = false;
                    s.snmp_community = String::new();
                    s.snmp_trap_target = String::new();
                    s.snmp_version = "v2c".into();
                }
                3 => {
                    // Branch Office — 4 VLANs (Staff/Guests/IoT/Mgmt), S2S VPN, remote access
                    s.wan_type = "Static".into();
                    s.wan_ip = String::new();
                    s.wan_gateway = String::new();
                    s.wan_dns = "1.1.1.1".into();
                    s.lan_subnet = "10.30.0.0/24".into();
                    s.management_vlan = true;
                    s.vlans = vec![
                        VlanEntry { id: 10, name: "Staff".into(), subnet: "10.30.10.0/24".into() },
                        VlanEntry { id: 20, name: "Guests".into(), subnet: "10.30.20.0/24".into() },
                        VlanEntry { id: 30, name: "IoT".into(), subnet: "10.30.30.0/24".into() },
                        VlanEntry { id: 99, name: "Management".into(), subnet: "10.30.99.0/24".into() },
                    ];
                    s.vpn_site_to_site = true;
                    s.vpn_remote_access = true;
                    s.dns_servers = "1.1.1.1, 8.8.8.8".into();
                    s.ntp_server = "pool.ntp.org".into();
                    s.syslog_enabled = true;
                    s.syslog_target = String::new();
                    s.admin_https_port = 8443;
                    s.default_deny = true;
                    s.allow_outbound_web = true;
                    s.allow_dns = true;
                    s.enable_ips = true;
                    s.enable_web_filter = true;
                    s.enable_antivirus = true;
                    // WiFi
                    s.wifi_enabled = true;
                    s.wifi_ssid_staff = String::new();
                    s.wifi_ssid_guest = String::new();
                    s.wifi_security = "WPA3-Enterprise".into();
                    s.wifi_guest_portal = true;
                    // SD-WAN
                    s.sdwan_enabled = true;
                    s.sdwan_health_target = "8.8.8.8".into();
                    s.sdwan_mode = "Source IP".into();
                    // SNMP
                    s.snmp_enabled = true;
                    s.snmp_community = String::new();
                    s.snmp_trap_target = String::new();
                    s.snmp_version = "v2c".into();
                }
                4 => {
                    // Home Office — 1 VLAN, remote access VPN, basic security
                    s.wan_type = "DHCP".into();
                    s.wan_ip = String::new();
                    s.wan_gateway = String::new();
                    s.wan_dns = String::new();
                    s.lan_subnet = "192.168.1.0/24".into();
                    s.management_vlan = false;
                    s.vlans = vec![
                        VlanEntry { id: 10, name: "LAN".into(), subnet: "192.168.1.0/24".into() },
                    ];
                    s.vpn_site_to_site = false;
                    s.vpn_remote_access = true;
                    s.dns_servers = "1.1.1.1, 8.8.8.8".into();
                    s.ntp_server = "pool.ntp.org".into();
                    s.syslog_enabled = false;
                    s.syslog_target = String::new();
                    s.admin_https_port = 443;
                    s.default_deny = true;
                    s.allow_outbound_web = true;
                    s.allow_dns = true;
                    s.enable_ips = false;
                    s.enable_web_filter = false;
                    s.enable_antivirus = true;
                    // WiFi
                    s.wifi_enabled = true;
                    s.wifi_ssid_staff = String::new();
                    s.wifi_ssid_guest = String::new();
                    s.wifi_security = "WPA3-Personal".into();
                    s.wifi_guest_portal = false;
                    // SD-WAN
                    s.sdwan_enabled = false;
                    s.sdwan_health_target = "8.8.8.8".into();
                    s.sdwan_mode = "Source IP".into();
                    // SNMP
                    s.snmp_enabled = false;
                    s.snmp_community = String::new();
                    s.snmp_trap_target = String::new();
                    s.snmp_version = "v2c".into();
                }
                _ => {
                    // "Custom" (idx 0) — no changes
                    return;
                }
            }

            // Restore customer-specific fields
            s.customer_name = name;
            s.location = loc;
            s.target_host_id = host_id;
            s.target_host_label = host_label;
            s.device_type = device_type;
        });
    }

    // Demo button — fills all wizard steps with test data
    let demo_btn = gtk4::Button::builder()
        .label("Load Demo Data")
        .tooltip_text("Fill all steps with sample data for testing")
        .css_classes(["flat"])
        .build();
    {
        let state = Rc::clone(state);
        let name_row = name_row.clone();
        let location_row = location_row.clone();
        let host_model = host_model.clone();
        let host_ids = Rc::clone(&host_ids);
        let host_row = host_row.clone();
        demo_btn.connect_clicked(move |_| {
            let mut s = state.borrow_mut();
            s.customer_name = "Acme Corporation".into();
            s.location = "Oslo HQ".into();
            s.device_type = "FortiGate".into();
            s.target_host_id = "demo".into();
            s.target_host_label = "Demo FortiGate (192.168.1.99)".into();
            s.wan_type = "Static".into();
            s.wan_ip = "203.0.113.10".into();
            s.wan_gateway = "203.0.113.1".into();
            s.wan_dns = "1.1.1.1".into();
            s.lan_subnet = "10.42.100.0/24".into();
            s.management_vlan = true;
            s.vlans = vec![
                VlanEntry { id: 10, name: "Staff".into(), subnet: "10.42.10.0/24".into() },
                VlanEntry { id: 20, name: "Guests".into(), subnet: "10.42.20.0/24".into() },
                VlanEntry { id: 30, name: "IoT".into(), subnet: "10.42.30.0/24".into() },
                VlanEntry { id: 99, name: "Management".into(), subnet: "10.42.99.0/24".into() },
            ];
            s.vpn_site_to_site = true;
            s.vpn_remote_access = true;
            s.dns_servers = "1.1.1.1, 8.8.8.8".into();
            s.ntp_server = "pool.ntp.org".into();
            s.syslog_enabled = true;
            s.syslog_target = "10.42.99.10".into();
            s.admin_https_port = 8443;
            s.default_deny = true;
            s.allow_outbound_web = true;
            s.allow_dns = true;
            s.enable_ips = true;
            s.enable_web_filter = true;
            s.enable_antivirus = true;
            // WiFi
            s.wifi_enabled = true;
            s.wifi_ssid_staff = "Acme-Staff".into();
            s.wifi_ssid_guest = "Acme-Guest".into();
            s.wifi_security = "WPA3-Enterprise".into();
            s.wifi_guest_portal = true;
            // SD-WAN
            s.sdwan_enabled = true;
            s.sdwan_health_target = "8.8.8.8".into();
            s.sdwan_mode = "Source IP".into();
            // SNMP
            s.snmp_enabled = true;
            s.snmp_community = "acme-snmp-demo".into();
            s.snmp_trap_target = "10.42.99.10".into();
            s.snmp_version = "v2c".into();
            drop(s);

            name_row.set_text("Acme Corporation");
            location_row.set_text("Oslo HQ");

            // Add demo host to the dropdown.
            host_model.append("Demo FortiGate (192.168.1.99)");
            host_ids.borrow_mut().push("demo".into());
            host_row.set_selected(host_model.n_items() - 1);
            host_row.set_sensitive(true);
        });
    }

    customer_group.add(&template_row);
    customer_group.add(&name_row);
    customer_group.add(&location_row);
    customer_group.add(&device_type_row);
    customer_group.add(&host_row);

    let demo_group = adw::PreferencesGroup::builder()
        .title("Quick Start")
        .description("Load sample data to test the wizard without a real device.")
        .build();
    let demo_action_row = adw::ActionRow::builder()
        .title("Demo Mode")
        .subtitle("Fills all steps with Acme Corporation test data")
        .activatable_widget(&demo_btn)
        .build();
    demo_action_row.add_suffix(&demo_btn);
    demo_group.add(&demo_action_row);

    // Batch provisioning group
    let batch_btn = gtk4::Button::builder()
        .label("Batch Mode")
        .tooltip_text("Provision multiple devices from a CSV table")
        .css_classes(["flat"])
        .build();
    {
        let state = Rc::clone(state);
        let app_state = Arc::clone(app_state);
        batch_btn.connect_clicked(move |btn| {
            let window = btn
                .root()
                .and_then(|r| r.downcast::<gtk4::Window>().ok());
            show_batch_dialog(window.as_ref(), &state, &app_state);
        });
    }
    let batch_group = adw::PreferencesGroup::builder()
        .title("Batch Provisioning")
        .description("Generate configs for multiple devices from a CSV table.")
        .build();
    let batch_action_row = adw::ActionRow::builder()
        .title("Batch Mode")
        .subtitle("Paste or load a CSV with multiple device entries")
        .activatable_widget(&batch_btn)
        .build();
    batch_action_row.add_suffix(&batch_btn);
    batch_group.add(&batch_action_row);

    page.add(&customer_group);
    page.add(&demo_group);
    page.add(&batch_group);

    page.upcast()
}

// ---------------------------------------------------------------------------
// Step 2: Network Design
// ---------------------------------------------------------------------------

fn build_step2_network_design(state: &Rc<RefCell<WizardState>>) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    // WAN group
    let wan_group = adw::PreferencesGroup::builder()
        .title("WAN Configuration")
        .description("Configure the upstream internet connection.")
        .build();

    let wan_type_row = adw::ComboRow::builder()
        .title("WAN Type")
        .build();
    let wan_types = gtk4::StringList::new(&["DHCP", "Static", "PPPoE"]);
    wan_type_row.set_model(Some(&wan_types));

    let wan_ip_row = adw::EntryRow::builder()
        .title("WAN IP Address")
        .visible(false)
        .build();

    let wan_gw_row = adw::EntryRow::builder()
        .title("WAN Gateway")
        .visible(false)
        .build();

    let wan_dns_row = adw::EntryRow::builder()
        .title("WAN DNS")
        .visible(false)
        .build();

    // Show/hide static fields based on WAN type
    {
        let wan_ip_row = wan_ip_row.clone();
        let wan_gw_row = wan_gw_row.clone();
        let wan_dns_row = wan_dns_row.clone();
        let state = Rc::clone(state);
        wan_type_row.connect_selected_notify(move |row| {
            let idx = row.selected();
            let is_static = idx == 1; // "Static"
            wan_ip_row.set_visible(is_static);
            wan_gw_row.set_visible(is_static);
            wan_dns_row.set_visible(is_static);
            let wt = match idx {
                0 => "DHCP",
                1 => "Static",
                2 => "PPPoE",
                _ => "DHCP",
            };
            state.borrow_mut().wan_type = wt.to_string();
        });
    }

    // Sync static WAN fields
    {
        let state = Rc::clone(state);
        wan_ip_row.connect_changed(move |row| {
            state.borrow_mut().wan_ip = row.text().to_string();
        });
    }
    {
        let state = Rc::clone(state);
        wan_gw_row.connect_changed(move |row| {
            state.borrow_mut().wan_gateway = row.text().to_string();
        });
    }
    {
        let state = Rc::clone(state);
        wan_dns_row.connect_changed(move |row| {
            state.borrow_mut().wan_dns = row.text().to_string();
        });
    }

    wan_group.add(&wan_type_row);
    wan_group.add(&wan_ip_row);
    wan_group.add(&wan_gw_row);
    wan_group.add(&wan_dns_row);
    page.add(&wan_group);

    // LAN group
    let lan_group = adw::PreferencesGroup::builder()
        .title("LAN Configuration")
        .description("The LAN subnet is auto-generated from the customer name.")
        .build();

    let lan_subnet_row = adw::EntryRow::builder()
        .title("LAN Subnet")
        .text(&state.borrow().lan_subnet)
        .build();
    {
        let state = Rc::clone(state);
        lan_subnet_row.connect_changed(move |row| {
            state.borrow_mut().lan_subnet = row.text().to_string();
        });
    }

    let mgmt_vlan_row = adw::SwitchRow::builder()
        .title("Management VLAN")
        .subtitle("Create a dedicated management VLAN (VLAN 99)")
        .build();
    {
        let state = Rc::clone(state);
        mgmt_vlan_row.connect_active_notify(move |row| {
            state.borrow_mut().management_vlan = row.is_active();
        });
    }

    lan_group.add(&lan_subnet_row);
    lan_group.add(&mgmt_vlan_row);
    page.add(&lan_group);

    // VLANs group
    let vlan_group = adw::PreferencesGroup::builder()
        .title("Additional VLANs")
        .description("Define additional VLANs for network segmentation.")
        .build();

    let vlan_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();

    let vlan_entries: Rc<RefCell<Vec<(adw::EntryRow, adw::EntryRow, adw::EntryRow)>>> =
        Rc::new(RefCell::new(Vec::new()));

    let add_vlan_btn = gtk4::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Add VLAN")
        .css_classes(["flat", "circular"])
        .halign(gtk4::Align::Center)
        .margin_top(8)
        .build();

    {
        let vlan_list = vlan_list.clone();
        let vlan_entries = Rc::clone(&vlan_entries);
        let state = Rc::clone(state);
        add_vlan_btn.connect_clicked(move |_| {
            let row_box = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Horizontal)
                .spacing(8)
                .margin_start(12)
                .margin_end(12)
                .margin_top(8)
                .margin_bottom(8)
                .build();

            let vlan_id_entry = adw::EntryRow::builder()
                .title("VLAN ID")
                .build();
            let vlan_name_entry = adw::EntryRow::builder()
                .title("Name")
                .build();
            let vlan_subnet_entry = adw::EntryRow::builder()
                .title("Subnet")
                .build();

            let remove_btn = gtk4::Button::builder()
                .icon_name("list-remove-symbolic")
                .css_classes(["flat", "circular", "error"])
                .valign(gtk4::Align::Center)
                .tooltip_text("Remove VLAN")
                .build();

            row_box.append(&vlan_id_entry);
            row_box.append(&vlan_name_entry);
            row_box.append(&vlan_subnet_entry);
            row_box.append(&remove_btn);

            let list_row = gtk4::ListBoxRow::builder()
                .child(&row_box)
                .activatable(false)
                .build();

            vlan_list.append(&list_row);
            vlan_entries.borrow_mut().push((
                vlan_id_entry.clone(),
                vlan_name_entry.clone(),
                vlan_subnet_entry.clone(),
            ));

            // Sync all VLANs to state whenever any field changes
            let sync_vlans = {
                let vlan_entries = Rc::clone(&vlan_entries);
                let state = Rc::clone(&state);
                move || {
                    let entries = vlan_entries.borrow();
                    let vlans: Vec<VlanEntry> = entries
                        .iter()
                        .map(|(id_e, name_e, subnet_e)| VlanEntry {
                            id: id_e.text().to_string().parse().unwrap_or(0),
                            name: name_e.text().to_string(),
                            subnet: subnet_e.text().to_string(),
                        })
                        .collect();
                    state.borrow_mut().vlans = vlans;
                }
            };

            let sync1 = sync_vlans.clone();
            vlan_id_entry.connect_changed(move |_| sync1());
            let sync2 = sync_vlans.clone();
            vlan_name_entry.connect_changed(move |_| sync2());
            let sync3 = sync_vlans.clone();
            vlan_subnet_entry.connect_changed(move |_| sync3());

            // Remove button
            {
                let vlan_list = vlan_list.clone();
                let vlan_entries = Rc::clone(&vlan_entries);
                let state = Rc::clone(&state);
                let vlan_id_entry = vlan_id_entry.clone();
                remove_btn.connect_clicked(move |_| {
                    vlan_list.remove(&list_row);
                    let mut entries = vlan_entries.borrow_mut();
                    entries.retain(|(id_e, _, _)| id_e != &vlan_id_entry);
                    // Sync after removal
                    let vlans: Vec<VlanEntry> = entries
                        .iter()
                        .map(|(id_e, name_e, subnet_e)| VlanEntry {
                            id: id_e.text().to_string().parse().unwrap_or(0),
                            name: name_e.text().to_string(),
                            subnet: subnet_e.text().to_string(),
                        })
                        .collect();
                    state.borrow_mut().vlans = vlans;
                });
            }
        });
    }

    vlan_group.add(&vlan_list);
    vlan_group.add(&add_vlan_btn);
    page.add(&vlan_group);

    page.upcast()
}

// ---------------------------------------------------------------------------
// Step 3: Services
// ---------------------------------------------------------------------------

fn build_step3_services(state: &Rc<RefCell<WizardState>>) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    // VPN group
    let vpn_group = adw::PreferencesGroup::builder()
        .title("VPN")
        .description("Configure VPN services on the device.")
        .build();

    let s2s_row = adw::SwitchRow::builder()
        .title("Site-to-Site VPN")
        .subtitle("IPsec tunnel to another site")
        .build();
    {
        let state = Rc::clone(state);
        s2s_row.connect_active_notify(move |row| {
            state.borrow_mut().vpn_site_to_site = row.is_active();
        });
    }

    let ra_row = adw::SwitchRow::builder()
        .title("Remote Access VPN")
        .subtitle("SSL VPN / client-to-site connectivity")
        .build();
    {
        let state = Rc::clone(state);
        ra_row.connect_active_notify(move |row| {
            state.borrow_mut().vpn_remote_access = row.is_active();
        });
    }

    vpn_group.add(&s2s_row);
    vpn_group.add(&ra_row);
    page.add(&vpn_group);

    // DNS / NTP group
    let infra_group = adw::PreferencesGroup::builder()
        .title("Infrastructure Services")
        .description("DNS, NTP, and time synchronization settings.")
        .build();

    let dns_row = adw::EntryRow::builder()
        .title("DNS Servers")
        .text("1.1.1.1, 8.8.8.8")
        .build();
    {
        let state = Rc::clone(state);
        dns_row.connect_changed(move |row| {
            state.borrow_mut().dns_servers = row.text().to_string();
        });
    }

    let ntp_row = adw::EntryRow::builder()
        .title("NTP Server")
        .text("pool.ntp.org")
        .build();
    {
        let state = Rc::clone(state);
        ntp_row.connect_changed(move |row| {
            state.borrow_mut().ntp_server = row.text().to_string();
        });
    }

    infra_group.add(&dns_row);
    infra_group.add(&ntp_row);
    page.add(&infra_group);

    // Logging group
    let log_group = adw::PreferencesGroup::builder()
        .title("Logging")
        .description("Syslog and audit logging configuration.")
        .build();

    let syslog_row = adw::SwitchRow::builder()
        .title("Enable Syslog")
        .subtitle("Forward logs to a remote syslog server")
        .build();

    let syslog_target_row = adw::EntryRow::builder()
        .title("Syslog Target IP")
        .sensitive(false)
        .build();

    {
        let syslog_target_row = syslog_target_row.clone();
        let state = Rc::clone(state);
        syslog_row.connect_active_notify(move |row| {
            let active = row.is_active();
            syslog_target_row.set_sensitive(active);
            state.borrow_mut().syslog_enabled = active;
        });
    }
    {
        let state = Rc::clone(state);
        syslog_target_row.connect_changed(move |row| {
            state.borrow_mut().syslog_target = row.text().to_string();
        });
    }

    log_group.add(&syslog_row);
    log_group.add(&syslog_target_row);
    page.add(&log_group);

    // WiFi / FortiAP group
    let wifi_group = adw::PreferencesGroup::builder()
        .title("Wireless / FortiAP")
        .description("WiFi SSID and security settings.")
        .build();

    let wifi_enable_row = adw::SwitchRow::builder()
        .title("Enable WiFi")
        .subtitle("Configure wireless access points")
        .build();

    let wifi_ssid_staff_row = adw::EntryRow::builder()
        .title("SSID (Staff)")
        .sensitive(false)
        .build();

    let wifi_ssid_guest_row = adw::EntryRow::builder()
        .title("SSID (Guest)")
        .sensitive(false)
        .build();

    let wifi_security_model = gtk4::StringList::new(&[
        "WPA3-Enterprise",
        "WPA3-Personal",
        "WPA2-Personal",
    ]);
    let wifi_security_row = adw::ComboRow::builder()
        .title("Security")
        .model(&wifi_security_model)
        .sensitive(false)
        .build();

    let wifi_guest_portal_row = adw::SwitchRow::builder()
        .title("Guest Portal")
        .subtitle("Captive portal for guest network")
        .sensitive(false)
        .build();

    // Populate initial values from state
    {
        let s = state.borrow();
        if !s.wifi_ssid_staff.is_empty() {
            wifi_ssid_staff_row.set_text(&s.wifi_ssid_staff);
        }
        if !s.wifi_ssid_guest.is_empty() {
            wifi_ssid_guest_row.set_text(&s.wifi_ssid_guest);
        }
        wifi_enable_row.set_active(s.wifi_enabled);
        wifi_guest_portal_row.set_active(s.wifi_guest_portal);
        let sec_idx = match s.wifi_security.as_str() {
            "WPA3-Personal" => 1,
            "WPA2-Personal" => 2,
            _ => 0,
        };
        wifi_security_row.set_selected(sec_idx);
        let sensitive = s.wifi_enabled;
        wifi_ssid_staff_row.set_sensitive(sensitive);
        wifi_ssid_guest_row.set_sensitive(sensitive);
        wifi_security_row.set_sensitive(sensitive);
        wifi_guest_portal_row.set_sensitive(sensitive);
    }

    {
        let state = Rc::clone(state);
        let staff = wifi_ssid_staff_row.clone();
        let guest = wifi_ssid_guest_row.clone();
        let sec = wifi_security_row.clone();
        let portal = wifi_guest_portal_row.clone();
        wifi_enable_row.connect_active_notify(move |row| {
            let active = row.is_active();
            staff.set_sensitive(active);
            guest.set_sensitive(active);
            sec.set_sensitive(active);
            portal.set_sensitive(active);
            state.borrow_mut().wifi_enabled = active;
            // Auto-fill SSIDs from customer name when enabling
            if active {
                let s = state.borrow();
                let cust = &s.customer_name;
                if staff.text().is_empty() && !cust.is_empty() {
                    drop(s);
                    let cust = state.borrow().customer_name.clone();
                    staff.set_text(&format!("{}-Staff", cust));
                    guest.set_text(&format!("{}-Guest", cust));
                }
            }
        });
    }
    {
        let state = Rc::clone(state);
        wifi_ssid_staff_row.connect_changed(move |row| {
            state.borrow_mut().wifi_ssid_staff = row.text().to_string();
        });
    }
    {
        let state = Rc::clone(state);
        wifi_ssid_guest_row.connect_changed(move |row| {
            state.borrow_mut().wifi_ssid_guest = row.text().to_string();
        });
    }
    {
        let state = Rc::clone(state);
        wifi_security_row.connect_selected_notify(move |row| {
            let val = match row.selected() {
                1 => "WPA3-Personal",
                2 => "WPA2-Personal",
                _ => "WPA3-Enterprise",
            };
            state.borrow_mut().wifi_security = val.to_string();
        });
    }
    {
        let state = Rc::clone(state);
        wifi_guest_portal_row.connect_active_notify(move |row| {
            state.borrow_mut().wifi_guest_portal = row.is_active();
        });
    }

    wifi_group.add(&wifi_enable_row);
    wifi_group.add(&wifi_ssid_staff_row);
    wifi_group.add(&wifi_ssid_guest_row);
    wifi_group.add(&wifi_security_row);
    wifi_group.add(&wifi_guest_portal_row);
    page.add(&wifi_group);

    // SD-WAN group (FortiGate only)
    let sdwan_group = adw::PreferencesGroup::builder()
        .title("SD-WAN")
        .description("Software-defined WAN path selection and health monitoring.")
        .build();

    let sdwan_enable_row = adw::SwitchRow::builder()
        .title("Enable SD-WAN")
        .subtitle("Intelligent WAN path selection")
        .build();

    let sdwan_health_row = adw::EntryRow::builder()
        .title("Health Check Target")
        .text("8.8.8.8")
        .sensitive(false)
        .build();

    let sdwan_mode_model = gtk4::StringList::new(&[
        "Source IP",
        "Bandwidth",
        "Session",
        "Spillover",
    ]);
    let sdwan_mode_row = adw::ComboRow::builder()
        .title("Load Balance Mode")
        .model(&sdwan_mode_model)
        .sensitive(false)
        .build();

    // Only show SD-WAN for FortiGate
    {
        let is_fortigate = state.borrow().device_type == "FortiGate";
        sdwan_group.set_visible(is_fortigate);
    }

    // Populate initial values
    {
        let s = state.borrow();
        sdwan_enable_row.set_active(s.sdwan_enabled);
        if !s.sdwan_health_target.is_empty() {
            sdwan_health_row.set_text(&s.sdwan_health_target);
        }
        let mode_idx = match s.sdwan_mode.as_str() {
            "Bandwidth" => 1,
            "Session" => 2,
            "Spillover" => 3,
            _ => 0,
        };
        sdwan_mode_row.set_selected(mode_idx);
        let sensitive = s.sdwan_enabled;
        sdwan_health_row.set_sensitive(sensitive);
        sdwan_mode_row.set_sensitive(sensitive);
    }

    {
        let state = Rc::clone(state);
        let health = sdwan_health_row.clone();
        let mode = sdwan_mode_row.clone();
        sdwan_enable_row.connect_active_notify(move |row| {
            let active = row.is_active();
            health.set_sensitive(active);
            mode.set_sensitive(active);
            state.borrow_mut().sdwan_enabled = active;
        });
    }
    {
        let state = Rc::clone(state);
        sdwan_health_row.connect_changed(move |row| {
            state.borrow_mut().sdwan_health_target = row.text().to_string();
        });
    }
    {
        let state = Rc::clone(state);
        sdwan_mode_row.connect_selected_notify(move |row| {
            let val = match row.selected() {
                1 => "Bandwidth",
                2 => "Session",
                3 => "Spillover",
                _ => "Source IP",
            };
            state.borrow_mut().sdwan_mode = val.to_string();
        });
    }

    sdwan_group.add(&sdwan_enable_row);
    sdwan_group.add(&sdwan_health_row);
    sdwan_group.add(&sdwan_mode_row);
    page.add(&sdwan_group);

    // SNMP group
    let snmp_group = adw::PreferencesGroup::builder()
        .title("SNMP")
        .description("Simple Network Management Protocol for monitoring.")
        .build();

    let snmp_enable_row = adw::SwitchRow::builder()
        .title("Enable SNMP")
        .subtitle("Allow network monitoring via SNMP")
        .build();

    let snmp_community_row = adw::EntryRow::builder()
        .title("Community String")
        .sensitive(false)
        .build();

    let snmp_trap_row = adw::EntryRow::builder()
        .title("Trap Target")
        .sensitive(false)
        .build();

    let snmp_version_model = gtk4::StringList::new(&["v2c", "v3"]);
    let snmp_version_row = adw::ComboRow::builder()
        .title("SNMP Version")
        .model(&snmp_version_model)
        .sensitive(false)
        .build();

    // Populate initial values
    {
        let s = state.borrow();
        snmp_enable_row.set_active(s.snmp_enabled);
        if !s.snmp_community.is_empty() {
            snmp_community_row.set_text(&s.snmp_community);
        }
        if !s.snmp_trap_target.is_empty() {
            snmp_trap_row.set_text(&s.snmp_trap_target);
        }
        let ver_idx = match s.snmp_version.as_str() {
            "v3" => 1,
            _ => 0,
        };
        snmp_version_row.set_selected(ver_idx);
        let sensitive = s.snmp_enabled;
        snmp_community_row.set_sensitive(sensitive);
        snmp_trap_row.set_sensitive(sensitive);
        snmp_version_row.set_sensitive(sensitive);
    }

    {
        let state = Rc::clone(state);
        let community = snmp_community_row.clone();
        let trap = snmp_trap_row.clone();
        let version = snmp_version_row.clone();
        snmp_enable_row.connect_active_notify(move |row| {
            let active = row.is_active();
            community.set_sensitive(active);
            trap.set_sensitive(active);
            version.set_sensitive(active);
            state.borrow_mut().snmp_enabled = active;
            // Auto-generate community string if empty
            if active && community.text().is_empty() {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .hash(&mut hasher);
                let hash = hasher.finish();
                let generated = format!("snmp-{:x}", hash & 0xFFFF_FFFF);
                community.set_text(&generated);
            }
        });
    }
    {
        let state = Rc::clone(state);
        snmp_community_row.connect_changed(move |row| {
            state.borrow_mut().snmp_community = row.text().to_string();
        });
    }
    {
        let state = Rc::clone(state);
        snmp_trap_row.connect_changed(move |row| {
            state.borrow_mut().snmp_trap_target = row.text().to_string();
        });
    }
    {
        let state = Rc::clone(state);
        snmp_version_row.connect_selected_notify(move |row| {
            let val = match row.selected() {
                1 => "v3",
                _ => "v2c",
            };
            state.borrow_mut().snmp_version = val.to_string();
        });
    }

    snmp_group.add(&snmp_enable_row);
    snmp_group.add(&snmp_community_row);
    snmp_group.add(&snmp_trap_row);
    snmp_group.add(&snmp_version_row);
    page.add(&snmp_group);

    // Admin group
    let admin_group = adw::PreferencesGroup::builder()
        .title("Administration")
        .build();

    let https_port_row = adw::SpinRow::builder()
        .title("Admin HTTPS Port")
        .subtitle("Management interface HTTPS port")
        .adjustment(&gtk4::Adjustment::new(
            443.0,   // value
            1.0,     // lower
            65535.0, // upper
            1.0,     // step
            100.0,   // page
            0.0,     // page_size
        ))
        .build();
    {
        let state = Rc::clone(state);
        https_port_row.connect_value_notify(move |row| {
            state.borrow_mut().admin_https_port = row.value() as u32;
        });
    }

    admin_group.add(&https_port_row);
    page.add(&admin_group);

    page.upcast()
}

// ---------------------------------------------------------------------------
// Step 4: Security (FortiGate only)
// ---------------------------------------------------------------------------

fn build_step4_security(state: &Rc<RefCell<WizardState>>) -> gtk4::Widget {
    let page = adw::PreferencesPage::new();

    let policy_group = adw::PreferencesGroup::builder()
        .title("Firewall Policies")
        .description("Default security policies for the FortiGate. CIS Benchmark recommended.")
        .build();

    let deny_row = adw::SwitchRow::builder()
        .title("Default Policy: Deny All")
        .subtitle("Implicit deny on all interfaces (recommended)")
        .active(true)
        .build();
    {
        let state = Rc::clone(state);
        deny_row.connect_active_notify(move |row| {
            state.borrow_mut().default_deny = row.is_active();
        });
    }

    let web_row = adw::SwitchRow::builder()
        .title("Allow Outbound Web (80/443)")
        .subtitle("Permit HTTP and HTTPS traffic to the internet")
        .active(true)
        .build();
    {
        let state = Rc::clone(state);
        web_row.connect_active_notify(move |row| {
            state.borrow_mut().allow_outbound_web = row.is_active();
        });
    }

    let dns_allow_row = adw::SwitchRow::builder()
        .title("Allow DNS (53)")
        .subtitle("Permit DNS queries to configured servers")
        .active(true)
        .build();
    {
        let state = Rc::clone(state);
        dns_allow_row.connect_active_notify(move |row| {
            state.borrow_mut().allow_dns = row.is_active();
        });
    }

    policy_group.add(&deny_row);
    policy_group.add(&web_row);
    policy_group.add(&dns_allow_row);
    page.add(&policy_group);

    // Security profiles group
    let profile_group = adw::PreferencesGroup::builder()
        .title("Security Profiles")
        .description("Enable UTM security inspection features.")
        .build();

    let ips_row = adw::SwitchRow::builder()
        .title("Intrusion Prevention (IPS)")
        .subtitle("Detect and block network attacks")
        .active(true)
        .build();
    {
        let state = Rc::clone(state);
        ips_row.connect_active_notify(move |row| {
            state.borrow_mut().enable_ips = row.is_active();
        });
    }

    let wf_row = adw::SwitchRow::builder()
        .title("Web Filter")
        .subtitle("Category-based URL filtering")
        .active(true)
        .build();
    {
        let state = Rc::clone(state);
        wf_row.connect_active_notify(move |row| {
            state.borrow_mut().enable_web_filter = row.is_active();
        });
    }

    let av_row = adw::SwitchRow::builder()
        .title("Antivirus")
        .subtitle("Scan traffic for malware and viruses")
        .active(true)
        .build();
    {
        let state = Rc::clone(state);
        av_row.connect_active_notify(move |row| {
            state.borrow_mut().enable_antivirus = row.is_active();
        });
    }

    profile_group.add(&ips_row);
    profile_group.add(&wf_row);
    profile_group.add(&av_row);
    page.add(&profile_group);

    page.upcast()
}

// ---------------------------------------------------------------------------
// Step 5: Review & Deploy
// ---------------------------------------------------------------------------

fn build_step5_review(
    state: &Rc<RefCell<WizardState>>,
    _app_state: &Arc<Mutex<AppState>>,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
) -> gtk4::Widget {
    let page = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .vexpand(true)
        .hexpand(true)
        .build();

    // Config preview
    let config_buffer = gtk4::TextBuffer::new(None::<&gtk4::TextTagTable>);
    config_buffer.set_text("# Configuration will appear here after generation.\n\
                            # Click \"Generate with Claude\" to create the device config.\n");

    let config_view = gtk4::TextView::builder()
        .buffer(&config_buffer)
        .editable(true)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::Word)
        .vexpand(true)
        .hexpand(true)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(16)
        .right_margin(16)
        .build();

    let config_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vexpand(true)
        .child(&config_view)
        .build();
    config_scroll.add_css_class("card");

    // Summary label above config
    let summary_label = gtk4::Label::builder()
        .label("Generated Configuration")
        .css_classes(["title-3"])
        .halign(gtk4::Align::Start)
        .margin_start(16)
        .margin_top(16)
        .margin_bottom(8)
        .build();

    // Button bar
    let btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .margin_bottom(16)
        .build();

    let generate_btn = gtk4::Button::builder()
        .label("Generate with Claude")
        .css_classes(["suggested-action", "pill"])
        .build();

    let generate_spinner = gtk4::Spinner::builder()
        .visible(false)
        .build();

    let push_btn = gtk4::Button::builder()
        .label("Push Config")
        .css_classes(["pill"])
        .sensitive(false)
        .tooltip_text("Deploy configuration to the target device via SSH")
        .build();

    let export_btn = gtk4::Button::builder()
        .label("Export")
        .css_classes(["flat", "pill"])
        .sensitive(false)
        .tooltip_text("Save configuration to a file")
        .build();

    let export_html_btn = gtk4::Button::builder()
        .label("Export HTML")
        .css_classes(["flat", "pill"])
        .sensitive(false)
        .tooltip_text("Save a professional HTML report")
        .build();

    let export_pdf_btn = gtk4::Button::builder()
        .label("Export PDF")
        .css_classes(["flat", "pill"])
        .sensitive(false)
        .tooltip_text("Save report as PDF (requires wkhtmltopdf or weasyprint)")
        .build();

    let diagram_btn = gtk4::Button::builder()
        .label("Network Diagram")
        .css_classes(["flat", "pill"])
        .tooltip_text("Generate an SVG network topology diagram")
        .build();

    let diff_btn = gtk4::Button::builder()
        .label("Diff with Device")
        .css_classes(["flat", "pill"])
        .sensitive(false)
        .tooltip_text("Compare generated config with the device's current config via SSH")
        .build();

    let history_btn = gtk4::Button::builder()
        .label("History")
        .css_classes(["flat", "pill"])
        .tooltip_text("View previous config versions for this customer")
        .build();

    btn_box.append(&generate_spinner);
    btn_box.append(&generate_btn);
    btn_box.append(&push_btn);
    btn_box.append(&diff_btn);
    btn_box.append(&export_btn);
    btn_box.append(&export_html_btn);
    btn_box.append(&export_pdf_btn);
    btn_box.append(&diagram_btn);
    btn_box.append(&history_btn);

    // Generate button — sends wizard state to Claude.
    //
    // The generated config text is ferried back via an Arc<Mutex> slot
    // polled by `glib::timeout_add_local` (GTK widgets are not Send).
    {
        let config_buffer = config_buffer.clone();
        let state = Rc::clone(state);
        let rt = rt.clone();
        let push_btn = push_btn.clone();
        let diff_btn = diff_btn.clone();
        let export_btn = export_btn.clone();
        let export_html_btn = export_html_btn.clone();
        let export_pdf_btn = export_pdf_btn.clone();
        let generate_btn_inner = generate_btn.clone();
        let generate_spinner = generate_spinner.clone();
        generate_btn.connect_clicked(move |_| {
            let generate_btn = generate_btn_inner.clone();
            let s = state.borrow().clone();
            let prompt = build_generation_prompt(&s);

            // UI feedback
            generate_btn.set_sensitive(false);
            generate_spinner.set_visible(true);
            generate_spinner.set_spinning(true);
            config_buffer.set_text("Generating configuration...\n");

            let result_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

            {
                let slot = Arc::clone(&result_slot);
                rt.spawn(async move {
                    let use_sub = super::super::console::claude::use_subscription();

                    let result = if use_sub {
                        send_provisioning_subscription(&prompt).await
                    } else {
                        let api_key = super::super::console::claude::load_api_key();
                        match api_key {
                            Some(key) => send_provisioning_api(&key, &prompt).await,
                            None => Err(anyhow::anyhow!(
                                "No API key configured. Go to Settings to add one, \
                                 or enable 'Use Claude subscription'."
                            )),
                        }
                    };

                    let config_text = match result {
                        Ok(text) => text,
                        Err(e) => format!("# Error generating config: {e}\n"),
                    };

                    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(config_text);
                });
            }

            // Poll for the result on the GTK main thread.
            let buf = config_buffer.clone();
            let pb = push_btn.clone();
            let db = diff_btn.clone();
            let eb = export_btn.clone();
            let ehb = export_html_btn.clone();
            let epb = export_pdf_btn.clone();
            let gb = generate_btn.clone();
            let gs = generate_spinner.clone();
            let ws = Rc::clone(&state);
            let rt_poll = rt.clone();
            glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                let maybe = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(config_text) = maybe {
                    ws.borrow_mut().generated_config = config_text.clone();
                    buf.set_text(&config_text);
                    let ok = !config_text.starts_with("# Error");
                    pb.set_sensitive(ok);
                    db.set_sensitive(ok);
                    eb.set_sensitive(ok);
                    ehb.set_sensitive(ok);
                    epb.set_sensitive(ok);
                    gb.set_sensitive(true);
                    gs.set_visible(false);
                    gs.set_spinning(false);

                    // Auto-save config version via D-Bus
                    if ok {
                        let s = ws.borrow();
                        let customer = s.customer_name.clone();
                        let device_type = s.device_type.clone();
                        let config = config_text.clone();
                        drop(s);
                        rt_poll.spawn(async move {
                            match save_config_version_dbus(&customer, &device_type, &config).await {
                                Ok(filename) => {
                                    tracing::info!("auto-saved config version: {filename}");
                                }
                                Err(e) => {
                                    tracing::warn!("failed to auto-save config version: {e}");
                                }
                            }
                        });
                    }

                    return glib::ControlFlow::Break;
                }
                glib::ControlFlow::Continue
            });
        });
    }

    // Push Config button — sends config via SSH
    {
        let state = Rc::clone(state);
        let tx = tx.clone();
        let rt = rt.clone();
        push_btn.connect_clicked(move |btn| {
            let s = state.borrow().clone();
            let tx = tx.clone();

            btn.set_sensitive(false);
            btn.set_label("Pushing...");

            let done_flag: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

            {
                let flag = Arc::clone(&done_flag);
                rt.spawn(async move {
                    let result = push_config_to_device(&s).await;

                    let msg = match result {
                        Ok(output) => format!("Config pushed successfully:\n{output}"),
                        Err(e) => format!("Push failed: {e}"),
                    };

                    let _ = tx.send(AppMsg::ShowToast(msg));
                    *flag.lock().unwrap_or_else(|e| e.into_inner()) = true;
                });
            }

            let btn = btn.clone();
            glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                if *done_flag.lock().unwrap_or_else(|e| e.into_inner()) {
                    btn.set_sensitive(true);
                    btn.set_label("Push Config");
                    return glib::ControlFlow::Break;
                }
                glib::ControlFlow::Continue
            });
        });
    }

    // Diff with Device button — SSH into device, fetch config, show diff
    {
        let state = Rc::clone(state);
        let rt = rt.clone();
        let tx = tx.clone();
        diff_btn.connect_clicked(move |btn| {
            let s = state.borrow().clone();
            if s.generated_config.is_empty() || s.target_host_id.is_empty() {
                let _ = tx.send(AppMsg::ShowToast(
                    "Generate a config and select a target host first.".into(),
                ));
                return;
            }

            btn.set_sensitive(false);
            btn.set_label("Fetching...");

            let result_slot: Arc<Mutex<Option<Result<String, String>>>> =
                Arc::new(Mutex::new(None));

            {
                let slot = Arc::clone(&result_slot);
                let host_id = s.target_host_id.clone();
                let device_type = s.device_type.clone();
                rt.spawn(async move {
                    let res = fetch_device_config(&host_id, &device_type).await;
                    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(
                        res.map_err(|e| format!("{e}"))
                    );
                });
            }

            let btn = btn.clone();
            let generated = s.generated_config.clone();
            let device_label = s.target_host_label.clone();
            glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                let maybe = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(result) = maybe {
                    btn.set_sensitive(true);
                    btn.set_label("Diff with Device");
                    match result {
                        Ok(device_config) => {
                            let window = btn
                                .root()
                                .and_then(|r| r.downcast::<gtk4::Window>().ok());
                            show_diff_dialog(
                                window.as_ref(),
                                &device_config,
                                &generated,
                                &format!("Current ({})", device_label),
                                "Generated Config",
                            );
                        }
                        Err(e) => {
                            tracing::error!("Failed to fetch device config: {e}");
                        }
                    }
                    return glib::ControlFlow::Break;
                }
                glib::ControlFlow::Continue
            });
        });
    }

    // Export button — save to file
    {
        let state = Rc::clone(state);
        export_btn.connect_clicked(move |btn| {
            let s = state.borrow().clone();
            let config = s.generated_config.clone();
            if config.is_empty() {
                return;
            }

            let dialog = gtk4::FileDialog::builder()
                .title("Export Configuration")
                .initial_name(format!(
                    "{}-{}.conf",
                    s.device_type.to_lowercase(),
                    s.customer_name.to_lowercase().replace(' ', "-")
                ))
                .build();

            let btn = btn.clone();
            dialog.save(
                None::<&gtk4::Window>,
                None::<&gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(path) = file.path() {
                            match std::fs::write(&path, &config) {
                                Ok(()) => {
                                    btn.set_tooltip_text(Some(&format!(
                                        "Exported to {}",
                                        path.display()
                                    )));
                                }
                                Err(e) => {
                                    tracing::error!("Failed to export config: {e}");
                                }
                            }
                        }
                    }
                },
            );
        });
    }

    // Export HTML button
    {
        let state = Rc::clone(state);
        let tx = tx.clone();
        export_html_btn.connect_clicked(move |btn| {
            let s = state.borrow().clone();
            if s.generated_config.is_empty() {
                return;
            }
            let html = generate_html_report(&s, &s.generated_config);

            let dialog = gtk4::FileDialog::builder()
                .title("Export HTML Report")
                .initial_name(format!(
                    "{}-{}-report.html",
                    s.device_type.to_lowercase(),
                    s.customer_name.to_lowercase().replace(' ', "-")
                ))
                .build();

            let btn = btn.clone();
            let tx = tx.clone();
            dialog.save(
                None::<&gtk4::Window>,
                None::<&gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(path) = file.path() {
                            match std::fs::write(&path, &html) {
                                Ok(()) => {
                                    btn.set_tooltip_text(Some(&format!(
                                        "Exported to {}",
                                        path.display()
                                    )));
                                    let _ = tx.send(AppMsg::ShowToast(format!(
                                        "HTML report saved to {}",
                                        path.display()
                                    )));
                                }
                                Err(e) => {
                                    tracing::error!("Failed to export HTML report: {e}");
                                }
                            }
                        }
                    }
                },
            );
        });
    }

    // Export PDF button — uses wkhtmltopdf or weasyprint subprocess
    {
        let state = Rc::clone(state);
        let tx = tx.clone();
        export_pdf_btn.connect_clicked(move |btn| {
            let s = state.borrow().clone();
            if s.generated_config.is_empty() {
                return;
            }
            let html = generate_html_report(&s, &s.generated_config);

            let dialog = gtk4::FileDialog::builder()
                .title("Export PDF Report")
                .initial_name(format!(
                    "{}-{}-report.pdf",
                    s.device_type.to_lowercase(),
                    s.customer_name.to_lowercase().replace(' ', "-")
                ))
                .build();

            let btn = btn.clone();
            let tx = tx.clone();
            dialog.save(
                None::<&gtk4::Window>,
                None::<&gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(pdf_path) = file.path() {
                            // Write the HTML to a temp file first
                            let tmp_html = std::env::temp_dir().join("supermgr-report.html");
                            if let Err(e) = std::fs::write(&tmp_html, &html) {
                                tracing::error!("Failed to write temp HTML: {e}");
                                return;
                            }

                            // Try wkhtmltopdf first, then weasyprint
                            let pdf_result = std::process::Command::new("wkhtmltopdf")
                                .args([
                                    "--enable-local-file-access",
                                    "--page-size", "A4",
                                    "--margin-top", "10mm",
                                    "--margin-bottom", "10mm",
                                ])
                                .arg(&tmp_html)
                                .arg(&pdf_path)
                                .output()
                                .or_else(|_| {
                                    std::process::Command::new("weasyprint")
                                        .arg(&tmp_html)
                                        .arg(&pdf_path)
                                        .output()
                                });

                            let _ = std::fs::remove_file(&tmp_html);

                            match pdf_result {
                                Ok(output) if output.status.success() => {
                                    btn.set_tooltip_text(Some(&format!(
                                        "Exported to {}",
                                        pdf_path.display()
                                    )));
                                    let _ = tx.send(AppMsg::ShowToast(format!(
                                        "PDF report saved to {}",
                                        pdf_path.display()
                                    )));
                                }
                                Ok(output) => {
                                    let stderr =
                                        String::from_utf8_lossy(&output.stderr);
                                    tracing::error!(
                                        "PDF converter exited with error: {stderr}"
                                    );
                                    // Fall back: save as HTML instead
                                    let html_fallback =
                                        pdf_path.with_extension("html");
                                    let _ = std::fs::write(&html_fallback, &html);
                                    let _ = tx.send(AppMsg::ShowToast(format!(
                                        "PDF conversion failed. Saved HTML to {}. \
                                         Install wkhtmltopdf or weasyprint for PDF export.",
                                        html_fallback.display()
                                    )));
                                }
                                Err(_) => {
                                    // No converter available — save as HTML
                                    let html_fallback =
                                        pdf_path.with_extension("html");
                                    let _ = std::fs::write(&html_fallback, &html);
                                    let _ = tx.send(AppMsg::ShowToast(format!(
                                        "No PDF converter found. Saved HTML to {}. \
                                         Install wkhtmltopdf or weasyprint for PDF export.",
                                        html_fallback.display()
                                    )));
                                }
                            }
                        }
                    }
                },
            );
        });
    }

    // Network Diagram button — generates SVG and shows in a dialog
    {
        let state = Rc::clone(state);
        let tx = tx.clone();
        diagram_btn.connect_clicked(move |btn| {
            let s = state.borrow().clone();
            let svg = generate_network_svg(&s);

            // Write SVG to a temp file so gtk4::Picture can load it
            let tmp_svg = std::env::temp_dir().join("supermgr-network-diagram.svg");
            if let Err(e) = std::fs::write(&tmp_svg, &svg) {
                tracing::error!("Failed to write temp SVG: {e}");
                return;
            }

            let picture = gtk4::Picture::builder()
                .file(&gio::File::for_path(&tmp_svg))
                .can_shrink(true)
                .content_fit(gtk4::ContentFit::Contain)
                .width_request(820)
                .height_request(620)
                .build();

            let scroll = gtk4::ScrolledWindow::builder()
                .hscrollbar_policy(gtk4::PolicyType::Automatic)
                .vscrollbar_policy(gtk4::PolicyType::Automatic)
                .vexpand(true)
                .hexpand(true)
                .child(&picture)
                .build();

            let export_svg_btn = gtk4::Button::builder()
                .label("Export SVG")
                .css_classes(["suggested-action", "pill"])
                .halign(gtk4::Align::Center)
                .margin_top(8)
                .margin_bottom(8)
                .build();

            let content = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Vertical)
                .spacing(8)
                .margin_start(12)
                .margin_end(12)
                .margin_top(12)
                .margin_bottom(12)
                .build();
            content.append(&scroll);
            content.append(&export_svg_btn);

            let dialog = adw::Dialog::builder()
                .title("Network Topology Diagram")
                .content_width(860)
                .content_height(680)
                .child(&content)
                .build();

            // Export SVG button inside the dialog
            {
                let svg_data = svg.clone();
                let customer = s.customer_name.to_lowercase().replace(' ', "-");
                let tx = tx.clone();
                export_svg_btn.connect_clicked(move |_| {
                    let file_dialog = gtk4::FileDialog::builder()
                        .title("Export Network Diagram")
                        .initial_name(format!("{customer}-network-diagram.svg"))
                        .build();

                    let svg_data = svg_data.clone();
                    let tx = tx.clone();
                    file_dialog.save(
                        None::<&gtk4::Window>,
                        None::<&gio::Cancellable>,
                        move |result| {
                            if let Ok(file) = result {
                                if let Some(path) = file.path() {
                                    match std::fs::write(&path, &svg_data) {
                                        Ok(()) => {
                                            let _ = tx.send(AppMsg::ShowToast(format!(
                                                "SVG diagram saved to {}",
                                                path.display()
                                            )));
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "Failed to export SVG diagram: {e}"
                                            );
                                        }
                                    }
                                }
                            }
                        },
                    );
                });
            }

            // Present dialog — get the root widget as the parent
            if let Some(root) = btn.root() {
                if let Some(window) = root.downcast_ref::<gtk4::Window>() {
                    dialog.present(Some(window));
                } else {
                    dialog.present(None::<&gtk4::Widget>);
                }
            } else {
                dialog.present(None::<&gtk4::Widget>);
            }
        });
    }

    // History button — list and view/diff previous config versions
    {
        let state = Rc::clone(state);
        let rt = rt.clone();
        let config_buffer = config_buffer.clone();
        history_btn.connect_clicked(move |btn| {
            let customer = state.borrow().customer_name.clone();
            if customer.is_empty() {
                return;
            }
            let result_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let btn = btn.clone();
            btn.set_sensitive(false);
            {
                let slot = Arc::clone(&result_slot);
                let customer = customer.clone();
                rt.spawn(async move {
                    match list_config_versions_dbus(&customer).await {
                        Ok(json) => *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(json),
                        Err(e) => *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!("ERROR:{e}")),
                    }
                });
            }
            let config_buffer = config_buffer.clone();
            let rt2 = rt.clone();
            glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                let maybe = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(json) = maybe {
                    btn.set_sensitive(true);
                    if json.starts_with("ERROR:") {
                        tracing::warn!("failed to list config versions: {}", &json[6..]);
                        return glib::ControlFlow::Break;
                    }
                    show_history_dialog(&json, &config_buffer, &rt2);
                    return glib::ControlFlow::Break;
                }
                glib::ControlFlow::Continue
            });
        });
    }

    page.append(&summary_label);
    page.append(&config_scroll);
    page.append(&btn_box);

    page.upcast()
}

// ---------------------------------------------------------------------------
// SVG network diagram generation
// ---------------------------------------------------------------------------

/// Generate an SVG network topology diagram from the wizard state.
///
/// Produces a clean, professional diagram showing:
/// - Internet cloud at top
/// - WAN interface with IP
/// - Firewall/Router box in centre (labelled with hostname)
/// - VLAN segments as coloured boxes below
/// - VPN tunnel indicators if S2S/RA VPN is enabled
fn generate_network_svg(state: &WizardState) -> String {
    // Assign a colour to each VLAN based on name keywords.
    fn vlan_color(name: &str) -> &'static str {
        let lower = name.to_lowercase();
        if lower.contains("staff") || lower.contains("corporate") || lower.contains("employee") {
            "#4CAF50"
        } else if lower.contains("guest") {
            "#FF9800"
        } else if lower.contains("iot") || lower.contains("device") {
            "#2196F3"
        } else if lower.contains("mgmt") || lower.contains("management") {
            "#9C27B0"
        } else {
            "#607D8B"
        }
    }

    /// Return a suitable text colour (white or dark) for a given VLAN background.
    fn text_color_for(bg: &str) -> &'static str {
        match bg {
            "#4CAF50" | "#2196F3" | "#9C27B0" | "#607D8B" => "white",
            _ => "#333",
        }
    }

    let hostname = if state.customer_name.is_empty() {
        "Firewall".to_string()
    } else {
        let loc = if state.location.is_empty() {
            String::new()
        } else {
            format!("-{}", state.location.to_uppercase().replace(' ', "-"))
        };
        format!(
            "FG-{}{loc}",
            state
                .customer_name
                .to_uppercase()
                .replace(' ', "-")
                .chars()
                .take(16)
                .collect::<String>()
        )
    };

    let wan_ip_label = if state.wan_ip.is_empty() {
        match state.wan_type.as_str() {
            "DHCP" => "DHCP".to_string(),
            "PPPoE" => "PPPoE".to_string(),
            _ => "WAN".to_string(),
        }
    } else {
        state.wan_ip.clone()
    };

    let vlan_count = state.vlans.len().max(1);
    let vlan_box_w: u32 = 160;
    let vlan_box_h: u32 = 80;
    let vlan_spacing: u32 = 24;
    let total_vlan_width =
        (vlan_count as u32) * vlan_box_w + (vlan_count as u32).saturating_sub(1) * vlan_spacing;
    let svg_w = total_vlan_width.max(600) + 100;
    let svg_h: u32 = if state.vpn_site_to_site || state.vpn_remote_access {
        580
    } else {
        520
    };
    let cx = svg_w / 2;

    // Firewall box geometry
    let fw_w: u32 = 280;
    let fw_h: u32 = 60;
    let fw_x = cx - fw_w / 2;
    let fw_y: u32 = 170;

    // LAN label
    let lan_label_y = fw_y + fw_h + 30;
    let lan_subnet_label = if state.lan_subnet.is_empty() {
        String::new()
    } else {
        format!("LAN: {}", state.lan_subnet)
    };

    // VLAN row
    let vlan_row_y = lan_label_y + 30;
    let vlan_start_x = cx - total_vlan_width / 2;

    let mut svg = String::with_capacity(4096);

    // SVG header
    svg.push_str(&format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{svg_w}" height="{svg_h}" viewBox="0 0 {svg_w} {svg_h}">
<defs>
  <style>
    text {{ font-family: 'Cantarell', 'Segoe UI', sans-serif; }}
    .label {{ font-size: 11px; fill: #666; }}
    .title {{ font-size: 13px; font-weight: bold; }}
    .small {{ font-size: 10px; }}
  </style>
  <filter id="shadow" x="-4%" y="-4%" width="108%" height="108%">
    <feDropShadow dx="1" dy="2" stdDeviation="2" flood-opacity="0.15"/>
  </filter>
</defs>
<rect width="100%" height="100%" fill="#fafafa" rx="12"/>
"##
    ));

    // Internet cloud
    svg.push_str(&format!(
        r##"<ellipse cx="{cx}" cy="50" rx="110" ry="38" fill="#e8e8e8" stroke="#999" stroke-width="1.5" filter="url(#shadow)"/>
<text x="{cx}" y="46" text-anchor="middle" class="title" fill="#555">Internet</text>
<text x="{cx}" y="62" text-anchor="middle" class="small" fill="#888">WAN: {wan_type}</text>
"##,
        wan_type = html_escape(&state.wan_type)
    ));

    // WAN link (cloud to firewall)
    let ip_label_w = wan_ip_label.len() as u32 * 8 + 16;
    svg.push_str(&format!(
        r##"<line x1="{cx}" y1="88" x2="{cx}" y2="{fw_y}" stroke="#555" stroke-width="2.5" stroke-dasharray="6,3"/>
<rect x="{ip_x}" y="110" width="{ip_label_w}" height="20" rx="4" fill="white" stroke="#ccc" stroke-width="0.5"/>
<text x="{ip_tx}" y="124" text-anchor="middle" class="label" fill="#333">{wan_ip}</text>
"##,
        ip_x = cx + 8,
        ip_tx = cx + 8 + ip_label_w / 2,
        wan_ip = html_escape(&wan_ip_label),
    ));

    // Firewall box
    svg.push_str(&format!(
        r##"<rect x="{fw_x}" y="{fw_y}" width="{fw_w}" height="{fw_h}" rx="10" fill="#1a365d" stroke="#0d1b2a" stroke-width="1.5" filter="url(#shadow)"/>
<text x="{cx}" y="{name_y}" text-anchor="middle" font-size="14" font-weight="bold" fill="white">{hostname}</text>
<text x="{cx}" y="{type_y}" text-anchor="middle" font-size="10" fill="#aac4e0">{device_type}</text>
"##,
        name_y = fw_y + 26,
        type_y = fw_y + 44,
        device_type = html_escape(&state.device_type),
        hostname = html_escape(&hostname),
    ));

    // Vertical line from firewall to VLAN row
    svg.push_str(&format!(
        r##"<line x1="{cx}" y1="{y1}" x2="{cx}" y2="{y2}" stroke="#555" stroke-width="2"/>
"##,
        y1 = fw_y + fw_h,
        y2 = lan_label_y - 6,
    ));

    // LAN subnet label
    if !lan_subnet_label.is_empty() {
        svg.push_str(&format!(
            r##"<text x="{cx}" y="{lan_label_y}" text-anchor="middle" class="label">{lan}</text>
"##,
            lan = html_escape(&lan_subnet_label)
        ));
    }

    // VLAN boxes
    if state.vlans.is_empty() {
        // Show a placeholder LAN box
        let bx = cx - 80;
        svg.push_str(&format!(
            r##"<rect x="{bx}" y="{vlan_row_y}" width="160" height="70" rx="8" fill="#607D8B" stroke="#455A64" stroke-width="1" filter="url(#shadow)"/>
<text x="{cx}" y="{t1}" text-anchor="middle" font-size="12" font-weight="bold" fill="white">LAN</text>
<text x="{cx}" y="{t2}" text-anchor="middle" font-size="10" fill="#ddd">{sub}</text>
"##,
            t1 = vlan_row_y + 30,
            t2 = vlan_row_y + 48,
            sub = if state.lan_subnet.is_empty() {
                "No VLANs configured"
            } else {
                &state.lan_subnet
            }
        ));
    } else {
        for (i, vlan) in state.vlans.iter().enumerate() {
            let bx = vlan_start_x + (i as u32) * (vlan_box_w + vlan_spacing);
            let bcx = bx + vlan_box_w / 2;
            let color = vlan_color(&vlan.name);
            let text_c = text_color_for(color);

            // Connecting line from centre to each VLAN box
            svg.push_str(&format!(
                r##"<line x1="{cx}" y1="{y1}" x2="{bcx}" y2="{vlan_row_y}" stroke="#888" stroke-width="1.5"/>
"##,
                y1 = vlan_row_y - 4,
            ));

            // VLAN box
            svg.push_str(&format!(
                r##"<rect x="{bx}" y="{vlan_row_y}" width="{vlan_box_w}" height="{vlan_box_h}" rx="8" fill="{color}" stroke="#333" stroke-width="0.8" filter="url(#shadow)"/>
<text x="{bcx}" y="{t1}" text-anchor="middle" font-size="12" font-weight="bold" fill="{text_c}">{name}</text>
<text x="{bcx}" y="{t2}" text-anchor="middle" font-size="10" fill="{text_c}">VLAN {vid}</text>
<text x="{bcx}" y="{t3}" text-anchor="middle" font-size="10" fill="{text_c}" opacity="0.85">{subnet}</text>
"##,
                t1 = vlan_row_y + 28,
                t2 = vlan_row_y + 46,
                t3 = vlan_row_y + 62,
                name = html_escape(&vlan.name),
                vid = vlan.id,
                subnet = html_escape(&vlan.subnet),
            ));
        }
    }

    // VPN tunnel indicators
    if state.vpn_site_to_site || state.vpn_remote_access {
        let vpn_labels: Vec<&str> = {
            let mut v = Vec::new();
            if state.vpn_site_to_site {
                v.push("Site-to-Site VPN (IKEv2)");
            }
            if state.vpn_remote_access {
                v.push("Remote Access VPN (IPsec)");
            }
            v
        };

        let fw_mid = fw_y + fw_h / 2;

        // VPN dashed line and icon to the right of the firewall
        svg.push_str(&format!(
            r##"<line x1="{x1}" y1="{fw_mid}" x2="{x2}" y2="{fw_mid}" stroke="#e65100" stroke-width="2" stroke-dasharray="8,4"/>
<ellipse cx="{vpn_cx}" cy="{fw_mid}" rx="14" ry="14" fill="#fff3e0" stroke="#e65100" stroke-width="1.5"/>
<text x="{vpn_cx}" y="{lock_y}" text-anchor="middle" font-size="14" fill="#e65100">&#x26BF;</text>
"##,
            x1 = fw_x + fw_w,
            x2 = fw_x + fw_w + 50,
            vpn_cx = fw_x + fw_w + 70,
            lock_y = fw_mid + 5,
        ));

        for (i, label) in vpn_labels.iter().enumerate() {
            svg.push_str(&format!(
                r##"<text x="{tx}" y="{ty}" text-anchor="start" class="label" fill="#e65100">{label}</text>
"##,
                tx = fw_x + fw_w + 92,
                ty = fw_mid - 2 + (i as u32) * 16,
            ));
        }

        // Legend
        let legend_y = vlan_row_y + vlan_box_h + 30;
        svg.push_str(&format!(
            r##"<line x1="30" y1="{legend_y}" x2="60" y2="{legend_y}" stroke="#e65100" stroke-width="2" stroke-dasharray="8,4"/>
<text x="68" y="{ty}" text-anchor="start" class="small" fill="#888">VPN tunnel</text>
"##,
            ty = legend_y + 4,
        ));
    }

    // Footer
    svg.push_str(&format!(
        r##"<text x="{cx}" y="{fy}" text-anchor="middle" font-size="9" fill="#bbb">Generated by SuperManager</text>
"##,
        fy = svg_h - 10,
    ));

    svg.push_str("</svg>\n");
    svg
}

// ---------------------------------------------------------------------------
// HTML report generation
// ---------------------------------------------------------------------------

/// Generate a professional HTML report from the wizard state and config text.
fn generate_html_report(state: &WizardState, config: &str) -> String {
    let now = glib::DateTime::now_local().unwrap();
    let date_str = now
        .format("%Y-%m-%d %H:%M")
        .map(|s| s.to_string())
        .unwrap_or_else(|_| "Unknown date".into());

    let yn = |b: bool| if b { "Enabled" } else { "Disabled" };
    let check = |b: bool| if b { "&#x2705;" } else { "&#x274C;" };

    // Build VLAN rows
    let vlan_rows = if state.vlans.is_empty() {
        "<tr><td colspan=\"3\" style=\"text-align:center;color:#888;\">No additional VLANs configured</td></tr>".to_string()
    } else {
        let colors = ["#e3f2fd", "#fff3e0", "#e8f5e9", "#fce4ec", "#f3e5f5"];
        state
            .vlans
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let bg = colors[i % colors.len()];
                format!(
                    "<tr><td style=\"background:{bg};font-weight:bold;\">{id}</td>\
                     <td style=\"background:{bg};\">{name}</td>\
                     <td style=\"background:{bg};font-family:monospace;\">{subnet}</td></tr>",
                    id = v.id,
                    name = html_escape(&v.name),
                    subnet = html_escape(&v.subnet),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    // Security section (FortiGate only)
    let security_section = if state.device_type == "FortiGate" {
        format!(
            r#"<h2 id="security">4. Security Policies</h2>
<table>
<thead><tr><th>Policy</th><th>Status</th></tr></thead>
<tbody>
<tr><td>Default Deny</td><td>{}</td></tr>
<tr><td>Allow Outbound Web (80/443)</td><td>{}</td></tr>
<tr><td>Allow DNS</td><td>{}</td></tr>
<tr><td>Intrusion Prevention (IPS)</td><td>{}</td></tr>
<tr><td>Web Filter</td><td>{}</td></tr>
<tr><td>Antivirus</td><td>{}</td></tr>
</tbody>
</table>"#,
            check(state.default_deny),
            check(state.allow_outbound_web),
            check(state.allow_dns),
            check(state.enable_ips),
            check(state.enable_web_filter),
            check(state.enable_antivirus),
        )
    } else {
        String::new()
    };

    let security_toc = if state.device_type == "FortiGate" {
        "<li><a href=\"#security\">Security Policies</a></li>"
    } else {
        ""
    };

    let wan_details = if state.wan_type == "Static" {
        format!(
            "<tr><td>WAN IP</td><td><code>{}</code></td></tr>\n\
             <tr><td>Gateway</td><td><code>{}</code></td></tr>\n\
             <tr><td>WAN DNS</td><td><code>{}</code></td></tr>",
            html_escape(&state.wan_ip),
            html_escape(&state.wan_gateway),
            html_escape(&state.wan_dns),
        )
    } else {
        String::new()
    };

    let wan_type_display = if state.wan_type.is_empty() {
        "DHCP"
    } else {
        &state.wan_type
    };
    let lan_display = if state.lan_subnet.is_empty() {
        "10.0.0.0/24"
    } else {
        &state.lan_subnet
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{customer} &mdash; {device} Deployment Report</title>
<style>
  :root {{
    --navy: #1a237e;
    --navy-light: #283593;
    --accent: #1565c0;
    --bg: #fafafa;
    --card-bg: #ffffff;
    --border: #e0e0e0;
    --text: #212121;
    --text-muted: #757575;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    color: var(--text);
    background: var(--bg);
    line-height: 1.6;
  }}
  header {{
    background: linear-gradient(135deg, var(--navy), var(--navy-light));
    color: #fff;
    padding: 2rem 2.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  header h1 {{ font-size: 1.6rem; font-weight: 600; }}
  header .meta {{ text-align: right; font-size: 0.9rem; opacity: 0.9; }}
  header .meta strong {{ display: block; font-size: 1.1rem; }}
  .logo-placeholder {{
    width: 64px; height: 64px;
    background: rgba(255,255,255,0.15);
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.5rem; font-weight: bold; margin-right: 1.5rem;
    flex-shrink: 0;
  }}
  header .left {{ display: flex; align-items: center; }}
  main {{ max-width: 960px; margin: 0 auto; padding: 2rem; }}
  h2 {{
    color: var(--navy);
    border-bottom: 2px solid var(--accent);
    padding-bottom: 0.3rem;
    margin: 2rem 0 1rem;
    font-size: 1.3rem;
  }}
  h3 {{ margin: 1rem 0 0.5rem; color: var(--navy-light); font-size: 1.05rem; }}
  nav.toc {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1.5rem;
  }}
  nav.toc h3 {{ margin-bottom: 0.5rem; color: var(--navy); }}
  nav.toc ol {{ padding-left: 1.2rem; }}
  nav.toc li {{ margin-bottom: 0.3rem; }}
  nav.toc a {{ color: var(--accent); text-decoration: none; }}
  nav.toc a:hover {{ text-decoration: underline; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1.5rem;
    background: var(--card-bg);
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  }}
  th {{
    background: var(--navy);
    color: #fff;
    text-align: left;
    padding: 0.7rem 1rem;
    font-weight: 600;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }}
  tbody tr:nth-child(even) {{ background: #f5f7fa; }}
  tbody tr:hover {{ background: #e8eaf6; }}
  code {{
    background: #eceff1;
    padding: 0.15rem 0.4rem;
    border-radius: 3px;
    font-size: 0.9em;
  }}
  .config-block {{
    background: #263238;
    color: #cfd8dc;
    padding: 1.2rem 1.5rem;
    border-radius: 8px;
    overflow-x: auto;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.85rem;
    line-height: 1.5;
    white-space: pre-wrap;
    word-wrap: break-word;
    margin-bottom: 1.5rem;
  }}
  .checklist {{ list-style: none; padding: 0; }}
  .checklist li {{
    padding: 0.5rem 0.8rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  .checklist li::before {{ content: '\2610'; font-size: 1.1rem; }}
  footer {{
    text-align: center;
    color: var(--text-muted);
    font-size: 0.8rem;
    padding: 2rem 1rem 1rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
  }}
  @media print {{
    body {{ background: #fff; }}
    header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    th {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .config-block {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    main {{ max-width: 100%; padding: 0 1rem; }}
    h2 {{ page-break-after: avoid; }}
    table, .config-block {{ page-break-inside: avoid; }}
  }}
</style>
</head>
<body>

<header>
  <div class="left">
    <div class="logo-placeholder">SM</div>
    <div>
      <h1>{device} Deployment Report</h1>
      <div style="opacity:0.85;margin-top:0.2rem;">{location}</div>
    </div>
  </div>
  <div class="meta">
    <strong>{customer}</strong>
    {date}
  </div>
</header>

<main>

<nav class="toc">
<h3>Table of Contents</h3>
<ol>
  <li><a href="#customer">Customer Information</a></li>
  <li><a href="#network">Network Design</a></li>
  <li><a href="#services">Services</a></li>
  {security_toc}
  <li><a href="#config">Generated Configuration</a></li>
  <li><a href="#checklist">Deployment Checklist</a></li>
</ol>
</nav>

<h2 id="customer">1. Customer Information</h2>
<table>
<thead><tr><th>Field</th><th>Value</th></tr></thead>
<tbody>
<tr><td>Customer Name</td><td><strong>{customer}</strong></td></tr>
<tr><td>Location</td><td>{location}</td></tr>
<tr><td>Device Type</td><td>{device}</td></tr>
<tr><td>Target Host</td><td>{target_host}</td></tr>
<tr><td>Report Date</td><td>{date}</td></tr>
</tbody>
</table>

<h2 id="network">2. Network Design</h2>
<h3>WAN Configuration</h3>
<table>
<thead><tr><th>Parameter</th><th>Value</th></tr></thead>
<tbody>
<tr><td>WAN Type</td><td>{wan_type}</td></tr>
{wan_details}
</tbody>
</table>

<h3>LAN Configuration</h3>
<table>
<thead><tr><th>Parameter</th><th>Value</th></tr></thead>
<tbody>
<tr><td>LAN Subnet</td><td><code>{lan_subnet}</code></td></tr>
<tr><td>Management VLAN</td><td>{mgmt_vlan}</td></tr>
</tbody>
</table>

<h3>VLANs</h3>
<table>
<thead><tr><th>VLAN ID</th><th>Name</th><th>Subnet</th></tr></thead>
<tbody>
{vlan_rows}
</tbody>
</table>

<h2 id="services">3. Services</h2>
<table>
<thead><tr><th>Service</th><th>Configuration</th></tr></thead>
<tbody>
<tr><td>Site-to-Site VPN</td><td>{s2s_vpn}</td></tr>
<tr><td>Remote Access VPN</td><td>{ra_vpn}</td></tr>
<tr><td>DNS Servers</td><td><code>{dns}</code></td></tr>
<tr><td>NTP Server</td><td><code>{ntp}</code></td></tr>
<tr><td>Syslog</td><td>{syslog}</td></tr>
<tr><td>Admin HTTPS Port</td><td>{admin_port}</td></tr>
</tbody>
</table>

{security_section}

<h2 id="config">5. Generated Configuration</h2>
<div class="config-block">{config_escaped}</div>

<h2 id="checklist">6. Deployment Checklist</h2>
<ul class="checklist">
<li>Verify physical connectivity and cabling</li>
<li>Confirm WAN link is active and IP assigned</li>
<li>Test LAN connectivity from management workstation</li>
<li>Verify VLAN segmentation and inter-VLAN routing</li>
<li>Confirm DNS resolution is working</li>
<li>Validate NTP synchronization</li>
<li>Test VPN tunnel establishment (if applicable)</li>
<li>Verify firewall policies match security requirements</li>
<li>Run vulnerability scan against device management interface</li>
<li>Document any deviations from this report</li>
<li>Obtain customer sign-off</li>
</ul>

</main>

<footer>
Generated by SuperManager &mdash; {date}
</footer>

</body>
</html>"##,
        customer = html_escape(&state.customer_name),
        device = html_escape(&state.device_type),
        location = html_escape(&state.location),
        date = html_escape(&date_str),
        target_host = html_escape(&state.target_host_label),
        wan_type = html_escape(wan_type_display),
        wan_details = wan_details,
        lan_subnet = html_escape(lan_display),
        mgmt_vlan = if state.management_vlan { "Yes (VLAN 99)" } else { "No" },
        vlan_rows = vlan_rows,
        s2s_vpn = yn(state.vpn_site_to_site),
        ra_vpn = yn(state.vpn_remote_access),
        dns = html_escape(&state.dns_servers),
        ntp = html_escape(&state.ntp_server),
        syslog = if state.syslog_enabled {
            format!("Enabled (target: <code>{}</code>)", html_escape(&state.syslog_target))
        } else {
            "Disabled".to_string()
        },
        admin_port = state.admin_https_port,
        security_toc = security_toc,
        security_section = security_section,
        config_escaped = html_escape(config),
    )
}

/// Minimal HTML escaping for safe embedding in the report.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ---------------------------------------------------------------------------
// Claude integration helpers
// ---------------------------------------------------------------------------

/// Build a detailed prompt from the wizard state for Claude to generate config.
fn build_generation_prompt(s: &WizardState) -> String {
    let mut prompt = format!(
        "Generate a complete, production-ready {device} configuration for the following deployment:\n\n\
         ## Customer\n\
         - Name: {name}\n\
         - Location: {location}\n\n\
         ## WAN\n\
         - Type: {wan_type}\n",
        device = s.device_type,
        name = s.customer_name,
        location = s.location,
        wan_type = if s.wan_type.is_empty() { "DHCP" } else { &s.wan_type },
    );

    if s.wan_type == "Static" {
        prompt.push_str(&format!(
            "- IP: {}\n- Gateway: {}\n- DNS: {}\n",
            s.wan_ip, s.wan_gateway, s.wan_dns
        ));
    }

    prompt.push_str(&format!(
        "\n## LAN\n\
         - Subnet: {}\n\
         - Management VLAN: {}\n",
        if s.lan_subnet.is_empty() { "10.0.0.0/24" } else { &s.lan_subnet },
        if s.management_vlan { "Yes (VLAN 99)" } else { "No" },
    ));

    if !s.vlans.is_empty() {
        prompt.push_str("\n## Additional VLANs\n");
        for v in &s.vlans {
            prompt.push_str(&format!(
                "- VLAN {}: {} ({})\n",
                v.id, v.name, v.subnet
            ));
        }
    }

    prompt.push_str(&format!(
        "\n## Services\n\
         - DNS Servers: {}\n\
         - NTP Server: {}\n\
         - Syslog: {}{}\n\
         - Admin HTTPS Port: {}\n",
        s.dns_servers,
        s.ntp_server,
        if s.syslog_enabled { "Yes" } else { "No" },
        if s.syslog_enabled {
            format!(" (target: {})", s.syslog_target)
        } else {
            String::new()
        },
        s.admin_https_port,
    ));

    // Only include VPN section if at least one VPN type is enabled.
    // Do NOT mention VPN at all if disabled — Claude will add it otherwise.
    if s.vpn_site_to_site || s.vpn_remote_access {
        prompt.push_str("\n## VPN\n");
        if s.vpn_site_to_site {
            prompt.push_str("- Site-to-Site VPN: Yes (IPsec IKEv2)\n");
        }
        if s.vpn_remote_access {
            prompt.push_str("- Remote Access VPN: Yes (IPsec IKEv2 with EAP, NOT SSL-VPN)\n");
        }
    }

    // Only include WiFi section if enabled.
    if s.wifi_enabled {
        prompt.push_str("\n## WiFi / FortiAP\n");
        prompt.push_str(&format!("- Staff SSID: {}\n", s.wifi_ssid_staff));
        prompt.push_str(&format!("- Guest SSID: {}\n", s.wifi_ssid_guest));
        prompt.push_str(&format!("- Security: {}\n",
            if s.wifi_security.is_empty() { "WPA3-Enterprise" } else { &s.wifi_security }
        ));
        prompt.push_str(&format!("- Guest Portal: {}\n",
            if s.wifi_guest_portal { "Yes" } else { "No" }
        ));
    }

    // Only include SD-WAN section if enabled (FortiGate only).
    if s.sdwan_enabled && s.device_type == "FortiGate" {
        prompt.push_str("\n## SD-WAN\n");
        prompt.push_str(&format!("- Health Check Target: {}\n",
            if s.sdwan_health_target.is_empty() { "8.8.8.8" } else { &s.sdwan_health_target }
        ));
        prompt.push_str(&format!("- Load Balance Mode: {}\n",
            if s.sdwan_mode.is_empty() { "Source IP" } else { &s.sdwan_mode }
        ));
    }

    // Only include SNMP section if enabled.
    if s.snmp_enabled {
        prompt.push_str("\n## SNMP\n");
        prompt.push_str(&format!("- Community String: {}\n", s.snmp_community));
        if !s.snmp_trap_target.is_empty() {
            prompt.push_str(&format!("- Trap Target: {}\n", s.snmp_trap_target));
        }
        prompt.push_str(&format!("- Version: {}\n",
            if s.snmp_version.is_empty() { "v2c" } else { &s.snmp_version }
        ));
    }

    // Auto-generate secure passwords/PSKs for the config.
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut gen_pass = |len: usize| -> String {
        const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%&*";
        (0..len).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
    };

    prompt.push_str(&format!(
        "\n## Pre-generated Credentials (use these exact values in the config)\n\
         - Admin password: {}\n\
         - WiFi PSK (if applicable): {}\n",
        gen_pass(20),
        gen_pass(16),
    ));
    if s.vpn_site_to_site {
        prompt.push_str(&format!("- S2S VPN PSK: {}\n", gen_pass(32)));
    }
    if s.vpn_remote_access {
        prompt.push_str(&format!(
            "- VPN user 'vpnuser1' password: {}\n\
             - VPN EAP PSK: {}\n",
            gen_pass(16),
            gen_pass(32),
        ));
    }

    prompt.push_str(
        "\nIMPORTANT RULES:\n\
         - Use the EXACT subnets listed above. The LAN base interface IP must be \
           the .1 address of the LAN Subnet.\n\
         - Use the pre-generated credentials above — do NOT use CHANGE-ME placeholders \
           for items that have a generated value.\n\
         - Do NOT include any VPN configuration unless the VPN section above is present.\n\
         - Do NOT include WiFi/FortiAP config unless the WiFi section above is present.\n\
         - Do NOT include SD-WAN config unless the SD-WAN section above is present.\n\
         - Do NOT include SNMP config unless the SNMP section above is present.\n\
         - Do NOT mention SSL-VPN anywhere — not in config, not in comments.\n\
         - Output ONLY the config commands. No markdown, no explanations, no text before or after.\n"
    );

    if s.device_type == "FortiGate" {
        prompt.push_str(&format!(
            "\n## Security Policies\n\
             - Default Deny: {}\n\
             - Allow Outbound Web (80/443): {}\n\
             - Allow DNS: {}\n\
             - IPS: {}\n\
             - Web Filter: {}\n\
             - Antivirus: {}\n",
            if s.default_deny { "Yes" } else { "No" },
            if s.allow_outbound_web { "Yes" } else { "No" },
            if s.allow_dns { "Yes" } else { "No" },
            if s.enable_ips { "Yes" } else { "No" },
            if s.enable_web_filter { "Yes" } else { "No" },
            if s.enable_antivirus { "Yes" } else { "No" },
        ));
    }

    if s.device_type == "FortiGate" {
        prompt.push_str(
            "\nOutput the complete FortiGate CLI configuration commands. \
             Include comments explaining each section. \
             Follow CIS FortiGate Benchmark recommendations.\n",
        );
    } else {
        prompt.push_str(
            "\nOutput the complete UniFi controller API JSON configuration. \
             Include comments explaining each section. \
             Structure as a series of API calls with method, endpoint, and body.\n",
        );
    }

    prompt
}

/// Send a provisioning prompt via the Claude Code CLI (subscription mode).
async fn send_provisioning_subscription(prompt: &str) -> anyhow::Result<String> {
    use tokio::process::Command;

    let full_prompt = format!(
        "{}\n\n---\n\nUser request:\n{}",
        PROVISIONING_SYSTEM_PROMPT, prompt
    );

    let output = Command::new("claude")
        .args(["--print"])
        .arg(&full_prompt)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Claude CLI failed: {stderr}");
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Send a provisioning prompt via the Anthropic API (API key mode).
async fn send_provisioning_api(api_key: &str, prompt: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 8192,
        "system": PROVISIONING_SYSTEM_PROMPT,
        "messages": [{
            "role": "user",
            "content": prompt,
        }],
    });

    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("API error {status}: {text}");
    }

    let json: serde_json::Value = resp.json().await?;
    let text = json["content"][0]["text"]
        .as_str()
        .unwrap_or("(no content in response)")
        .to_string();

    Ok(text)
}

/// Push generated config to the target device via the daemon's SSH execute.
async fn push_config_to_device(state: &WizardState) -> anyhow::Result<String> {
    use anyhow::Context;

    if state.target_host_id.is_empty() {
        anyhow::bail!("No target host selected");
    }
    if state.generated_config.is_empty() {
        anyhow::bail!("No configuration generated yet");
    }

    let conn = zbus::Connection::system()
        .await
        .context("D-Bus connection failed — is the daemon running?")?;

    // Use the daemon's SshExecute method to push config line by line
    let proxy = supermgr_core::dbus::DaemonProxy::new(&conn)
        .await
        .context("DaemonProxy creation failed")?;

    // For FortiGate, we can send the config as a single SSH command batch.
    // For UniFi, the config would be API calls — for now, push via SSH.
    let result = proxy
        .ssh_execute_command(&state.target_host_id, &state.generated_config)
        .await
        .context("SSH execute failed")?;

    Ok(result)
}

use gtk4::gio;
use gtk4::glib;

// ---------------------------------------------------------------------------
// Config versioning D-Bus helpers
// ---------------------------------------------------------------------------

/// Save a config version via D-Bus.
async fn save_config_version_dbus(
    customer: &str,
    device_type: &str,
    config: &str,
) -> anyhow::Result<String> {
    use supermgr_core::dbus::DaemonProxy;
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let filename = proxy.save_config_version(customer, device_type, config).await?;
    Ok(filename)
}

/// List config versions for a customer via D-Bus.
async fn list_config_versions_dbus(customer: &str) -> anyhow::Result<String> {
    use supermgr_core::dbus::DaemonProxy;
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let json = proxy.list_config_versions(customer).await?;
    Ok(json)
}

/// Retrieve a config version by filename via D-Bus.
async fn get_config_version_dbus(filename: &str) -> anyhow::Result<String> {
    use supermgr_core::dbus::DaemonProxy;
    let conn = zbus::Connection::system().await?;
    let proxy = DaemonProxy::new(&conn).await?;
    let config = proxy.get_config_version(filename).await?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// History dialog
// ---------------------------------------------------------------------------

/// Show a dialog listing saved config versions with ability to view or diff.
fn show_history_dialog(
    versions_json: &str,
    current_buffer: &gtk4::TextBuffer,
    rt: &tokio::runtime::Handle,
) {
    let entries: Vec<serde_json::Value> = match serde_json::from_str(versions_json) {
        Ok(v) => v,
        Err(_) => return,
    };

    let dialog = adw::Dialog::builder()
        .title("Config Version History")
        .content_width(700)
        .content_height(500)
        .build();

    let toolbar_view = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    toolbar_view.add_top_bar(&header);

    if entries.is_empty() {
        let status = adw::StatusPage::builder()
            .title("No Versions Found")
            .description("Generate a configuration first to create a saved version.")
            .icon_name("document-open-recent-symbolic")
            .build();
        toolbar_view.set_content(Some(&status));
        dialog.set_child(Some(&toolbar_view));
        dialog.present(None::<&gtk4::Widget>);
        return;
    }

    let list_box = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .margin_start(16)
        .margin_end(16)
        .margin_top(8)
        .margin_bottom(8)
        .build();

    let current_text = {
        let (start, end) = current_buffer.bounds();
        current_buffer.text(&start, &end, false).to_string()
    };

    for entry in &entries {
        let filename = entry["filename"].as_str().unwrap_or("unknown").to_string();
        let timestamp = entry["timestamp"].as_str().unwrap_or("").to_string();

        // Trim the timestamp for display
        let display_ts = if timestamp.len() > 19 {
            &timestamp[..19]
        } else {
            &timestamp
        };

        let row = adw::ActionRow::builder()
            .title(&filename)
            .subtitle(display_ts)
            .build();

        let view_btn = gtk4::Button::builder()
            .label("View")
            .css_classes(["flat"])
            .valign(gtk4::Align::Center)
            .build();

        let diff_btn = gtk4::Button::builder()
            .label("Diff")
            .css_classes(["flat"])
            .valign(gtk4::Align::Center)
            .build();

        // View button — load this version's config into a new dialog
        {
            let filename = filename.clone();
            let rt = rt.clone();
            view_btn.connect_clicked(move |btn| {
                let filename = filename.clone();
                let result_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
                btn.set_sensitive(false);
                let btn2 = btn.clone();
                {
                    let slot = Arc::clone(&result_slot);
                    rt.spawn(async move {
                        match get_config_version_dbus(&filename).await {
                            Ok(config) => *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(config),
                            Err(e) => *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!("# Error: {e}")),
                        }
                    });
                }
                glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                    let maybe = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(config) = maybe {
                        btn2.set_sensitive(true);
                        show_config_viewer_dialog(&config);
                        return glib::ControlFlow::Break;
                    }
                    glib::ControlFlow::Continue
                });
            });
        }

        // Diff button — show unified diff between this version and current
        {
            let filename = filename.clone();
            let rt = rt.clone();
            let current_text = current_text.clone();
            diff_btn.connect_clicked(move |btn| {
                let filename = filename.clone();
                let current_text = current_text.clone();
                let result_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
                btn.set_sensitive(false);
                let btn2 = btn.clone();
                {
                    let slot = Arc::clone(&result_slot);
                    rt.spawn(async move {
                        match get_config_version_dbus(&filename).await {
                            Ok(old_config) => {
                                let diff = compute_unified_diff(&old_config, &current_text);
                                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(diff);
                            }
                            Err(e) => {
                                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!("# Error: {e}"));
                            }
                        }
                    });
                }
                glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                    let maybe = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(diff_text) = maybe {
                        btn2.set_sensitive(true);
                        show_config_viewer_dialog(&diff_text);
                        return glib::ControlFlow::Break;
                    }
                    glib::ControlFlow::Continue
                });
            });
        }

        row.add_suffix(&diff_btn);
        row.add_suffix(&view_btn);
        list_box.append(&row);
    }

    let scrolled = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .child(&list_box)
        .build();

    toolbar_view.set_content(Some(&scrolled));
    dialog.set_child(Some(&toolbar_view));
    dialog.present(None::<&gtk4::Widget>);
}

/// Show a read-only dialog with config or diff text.
fn show_config_viewer_dialog(text: &str) {
    let dialog = adw::Dialog::builder()
        .title("Config Version")
        .content_width(800)
        .content_height(600)
        .build();

    let toolbar_view = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    toolbar_view.add_top_bar(&header);

    let buf = gtk4::TextBuffer::new(None::<&gtk4::TextTagTable>);
    buf.set_text(text);

    let view = gtk4::TextView::builder()
        .buffer(&buf)
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::Word)
        .vexpand(true)
        .hexpand(true)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(16)
        .right_margin(16)
        .build();

    let scrolled = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .child(&view)
        .build();
    scrolled.add_css_class("card");

    toolbar_view.set_content(Some(&scrolled));
    dialog.set_child(Some(&toolbar_view));
    dialog.present(None::<&gtk4::Widget>);
}

/// Compute a simple unified diff between two texts.
fn compute_unified_diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut output = String::new();
    output.push_str("--- previous version\n");
    output.push_str("+++ current\n");

    // Simple line-by-line diff (Myers-like would be better but this is functional)
    let max = old_lines.len().max(new_lines.len());
    let mut i = 0;
    let mut j = 0;
    while i < old_lines.len() || j < new_lines.len() {
        if i < old_lines.len() && j < new_lines.len() && old_lines[i] == new_lines[j] {
            output.push_str(&format!(" {}\n", old_lines[i]));
            i += 1;
            j += 1;
        } else {
            // Try to find the old line later in new (addition before it)
            let mut found_in_new = false;
            for k in (j + 1)..new_lines.len().min(j + 5) {
                if i < old_lines.len() && new_lines[k] == old_lines[i] {
                    // Lines j..k in new are additions
                    for add in j..k {
                        output.push_str(&format!("+{}\n", new_lines[add]));
                    }
                    j = k;
                    found_in_new = true;
                    break;
                }
            }
            if !found_in_new {
                // Try to find the new line later in old (deletion before it)
                let mut found_in_old = false;
                for k in (i + 1)..old_lines.len().min(i + 5) {
                    if j < new_lines.len() && old_lines[k] == new_lines[j] {
                        for del in i..k {
                            output.push_str(&format!("-{}\n", old_lines[del]));
                        }
                        i = k;
                        found_in_old = true;
                        break;
                    }
                }
                if !found_in_old {
                    if i < old_lines.len() {
                        output.push_str(&format!("-{}\n", old_lines[i]));
                        i += 1;
                    }
                    if j < new_lines.len() {
                        output.push_str(&format!("+{}\n", new_lines[j]));
                        j += 1;
                    }
                }
            }
        }
        if i >= max && j >= max {
            break;
        }
    }
    if output.lines().count() <= 2 {
        output.push_str("\n(no differences)\n");
    }
    output
}

// ---------------------------------------------------------------------------
// Batch provisioning
// ---------------------------------------------------------------------------

/// A single row parsed from the batch CSV.
#[derive(Debug, Clone)]
struct BatchEntry {
    customer_name: String,
    location: String,
    device_type: String,
    wan_type: String,
    wan_ip: String,
    lan_subnet: String,
}

/// Parse CSV text into batch entries.
/// Expected columns: customer_name, location, device_type, wan_type, wan_ip, lan_subnet
fn parse_batch_csv(text: &str) -> Result<Vec<BatchEntry>, String> {
    let mut entries = Vec::new();
    let mut lines = text.lines();

    // Skip header if present
    let first = match lines.next() {
        Some(l) => l.trim(),
        None => return Err("Empty CSV input".into()),
    };

    let is_header = first.to_lowercase().contains("customer")
        || first.to_lowercase().contains("name");
    if !is_header {
        if let Some(entry) = parse_csv_line(first)? {
            entries.push(entry);
        }
    }

    for (i, line) in lines.enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_csv_line(line) {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => {}
            Err(e) => return Err(format!("Line {}: {}", i + 2, e)),
        }
    }

    if entries.is_empty() {
        return Err("No valid entries found in CSV".into());
    }
    Ok(entries)
}

fn parse_csv_line(line: &str) -> Result<Option<BatchEntry>, String> {
    let fields: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
    if fields.len() < 6 {
        return Err(format!(
            "Expected 6 columns (customer_name, location, device_type, wan_type, \
             wan_ip, lan_subnet), got {}",
            fields.len()
        ));
    }
    Ok(Some(BatchEntry {
        customer_name: fields[0].to_string(),
        location: fields[1].to_string(),
        device_type: fields[2].to_string(),
        wan_type: fields[3].to_string(),
        wan_ip: fields[4].to_string(),
        lan_subnet: fields[5].to_string(),
    }))
}

/// Build a WizardState from a BatchEntry with sensible defaults.
fn batch_entry_to_state(entry: &BatchEntry) -> WizardState {
    WizardState {
        customer_name: entry.customer_name.clone(),
        location: entry.location.clone(),
        device_type: entry.device_type.clone(),
        wan_type: entry.wan_type.clone(),
        wan_ip: entry.wan_ip.clone(),
        wan_gateway: String::new(),
        wan_dns: "1.1.1.1".into(),
        lan_subnet: entry.lan_subnet.clone(),
        vlans: Vec::new(),
        management_vlan: false,
        dns_servers: "1.1.1.1, 8.8.8.8".into(),
        ntp_server: "pool.ntp.org".into(),
        admin_https_port: 443,
        default_deny: true,
        allow_outbound_web: true,
        allow_dns: true,
        enable_ips: true,
        enable_web_filter: true,
        enable_antivirus: true,
        ..Default::default()
    }
}

/// Show the batch provisioning dialog.
fn show_batch_dialog(
    parent: Option<&gtk4::Window>,
    _state: &Rc<RefCell<WizardState>>,
    _app_state: &Arc<Mutex<AppState>>,
) {
    let dialog = gtk4::Window::builder()
        .title("Batch Provisioning")
        .default_width(900)
        .default_height(650)
        .modal(true)
        .build();

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    let main_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(8)
        .build();

    let header = adw::HeaderBar::new();
    main_box.append(&header);

    let content_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(8)
        .margin_start(16)
        .margin_end(16)
        .margin_bottom(16)
        .build();

    let info_label = gtk4::Label::builder()
        .label(
            "Paste CSV data or load a CSV file. Columns: customer_name, \
             location, device_type, wan_type, wan_ip, lan_subnet",
        )
        .wrap(true)
        .css_classes(["dim-label"])
        .halign(gtk4::Align::Start)
        .build();
    content_box.append(&info_label);

    // CSV text area
    let csv_buffer = gtk4::TextBuffer::new(None::<&gtk4::TextTagTable>);
    csv_buffer.set_text(
        "customer_name, location, device_type, wan_type, wan_ip, lan_subnet\n\
         Acme Corp, Oslo HQ, FortiGate, Static, 203.0.113.10, 10.42.100.0/24\n\
         Beta Inc, Bergen, FortiGate, DHCP, , 10.50.0.0/24\n",
    );

    let csv_view = gtk4::TextView::builder()
        .buffer(&csv_buffer)
        .editable(true)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::None)
        .vexpand(true)
        .hexpand(true)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(12)
        .right_margin(12)
        .build();
    let csv_scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .min_content_height(150)
        .child(&csv_view)
        .build();
    csv_scroll.add_css_class("card");
    content_box.append(&csv_scroll);

    // Buttons row
    let btn_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::Center)
        .margin_top(8)
        .build();

    let load_btn = gtk4::Button::builder()
        .label("Load CSV")
        .css_classes(["flat"])
        .build();

    let preview_btn = gtk4::Button::builder()
        .label("Preview")
        .css_classes(["suggested-action", "pill"])
        .build();

    let generate_all_btn = gtk4::Button::builder()
        .label("Generate All")
        .css_classes(["pill"])
        .sensitive(false)
        .build();

    let export_all_btn = gtk4::Button::builder()
        .label("Export All")
        .css_classes(["flat", "pill"])
        .sensitive(false)
        .build();

    btn_row.append(&load_btn);
    btn_row.append(&preview_btn);
    btn_row.append(&generate_all_btn);
    btn_row.append(&export_all_btn);
    content_box.append(&btn_row);

    // Preview table
    let preview_label = gtk4::Label::builder()
        .label("Preview")
        .css_classes(["title-4"])
        .halign(gtk4::Align::Start)
        .margin_top(8)
        .build();
    content_box.append(&preview_label);

    let preview_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    let preview_scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .min_content_height(150)
        .child(&preview_list)
        .build();
    content_box.append(&preview_scroll);

    // Status area
    let status_buffer = gtk4::TextBuffer::new(None::<&gtk4::TextTagTable>);
    let status_view = gtk4::TextView::builder()
        .buffer(&status_buffer)
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::Word)
        .vexpand(true)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(12)
        .right_margin(12)
        .build();
    let status_scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .min_content_height(100)
        .child(&status_view)
        .build();
    status_scroll.add_css_class("card");
    content_box.append(&status_scroll);

    main_box.append(&content_box);

    // Shared state
    let parsed_entries: Rc<RefCell<Vec<BatchEntry>>> = Rc::new(RefCell::new(Vec::new()));
    let generated_configs: Rc<RefCell<Vec<(String, String)>>> =
        Rc::new(RefCell::new(Vec::new()));

    // Load CSV button
    {
        let csv_buffer = csv_buffer.clone();
        let dialog_ref = dialog.clone();
        load_btn.connect_clicked(move |_| {
            let file_dialog = gtk4::FileDialog::builder()
                .title("Load CSV File")
                .build();
            let csv_buffer = csv_buffer.clone();
            file_dialog.open(
                Some(&dialog_ref),
                None::<&gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(path) = file.path() {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                csv_buffer.set_text(&content);
                            }
                        }
                    }
                },
            );
        });
    }

    // Preview button
    {
        let csv_buffer = csv_buffer.clone();
        let preview_list = preview_list.clone();
        let parsed_entries = Rc::clone(&parsed_entries);
        let generate_all_btn = generate_all_btn.clone();
        let status_buffer = status_buffer.clone();
        preview_btn.connect_clicked(move |_| {
            let (start, end) = csv_buffer.bounds();
            let text = csv_buffer.text(&start, &end, false).to_string();

            while let Some(child) = preview_list.first_child() {
                preview_list.remove(&child);
            }

            match parse_batch_csv(&text) {
                Ok(entries) => {
                    for (i, entry) in entries.iter().enumerate() {
                        let row = adw::ActionRow::builder()
                            .title(&format!(
                                "{}. {} — {}",
                                i + 1,
                                entry.customer_name,
                                entry.location,
                            ))
                            .subtitle(&format!(
                                "{} | WAN: {} {} | LAN: {}",
                                entry.device_type,
                                entry.wan_type,
                                if entry.wan_ip.is_empty() {
                                    ""
                                } else {
                                    &entry.wan_ip
                                },
                                entry.lan_subnet,
                            ))
                            .build();
                        preview_list.append(&row);
                    }
                    status_buffer.set_text(&format!(
                        "Parsed {} entries. Click \"Generate All\" to generate configs.",
                        entries.len()
                    ));
                    *parsed_entries.borrow_mut() = entries;
                    generate_all_btn.set_sensitive(true);
                }
                Err(e) => {
                    status_buffer.set_text(&format!("Parse error: {e}"));
                    parsed_entries.borrow_mut().clear();
                    generate_all_btn.set_sensitive(false);
                }
            }
        });
    }

    // Generate All button
    {
        let parsed_entries = Rc::clone(&parsed_entries);
        let generated_configs = Rc::clone(&generated_configs);
        let status_buffer = status_buffer.clone();
        let export_all_btn = export_all_btn.clone();
        generate_all_btn.connect_clicked(move |btn| {
            let entries = parsed_entries.borrow().clone();
            if entries.is_empty() {
                return;
            }

            btn.set_sensitive(false);
            btn.set_label("Generating...");
            status_buffer.set_text("Generating configs for all entries...\n");

            let mut configs = Vec::new();
            let mut status_text = String::new();
            for (i, entry) in entries.iter().enumerate() {
                let ws = batch_entry_to_state(entry);
                let prompt = build_generation_prompt(&ws);
                let filename = format!(
                    "{}-{}.conf",
                    ws.device_type.to_lowercase(),
                    ws.customer_name.to_lowercase().replace(' ', "-"),
                );
                let config_text = format!(
                    "# Generated config for: {} ({})\n\
                     # Location: {}\n\
                     # Device: {} | WAN: {} {}\n\
                     # LAN: {}\n\
                     #\n\
                     # --- Prompt sent to Claude ---\n\
                     {}\n",
                    entry.customer_name,
                    filename,
                    entry.location,
                    entry.device_type,
                    entry.wan_type,
                    entry.wan_ip,
                    entry.lan_subnet,
                    prompt,
                );
                configs.push((filename, config_text));
                status_text.push_str(&format!(
                    "[{}/{}] Prepared: {}\n",
                    i + 1,
                    entries.len(),
                    entry.customer_name,
                ));
            }

            status_text.push_str(&format!(
                "\nDone. {} configs ready. Click \"Export All\" to save as ZIP.\n",
                configs.len()
            ));
            status_buffer.set_text(&status_text);
            *generated_configs.borrow_mut() = configs;
            export_all_btn.set_sensitive(true);
            btn.set_sensitive(true);
            btn.set_label("Generate All");
        });
    }

    // Export All button
    {
        let generated_configs = Rc::clone(&generated_configs);
        let status_buffer = status_buffer.clone();
        let dialog_ref = dialog.clone();
        export_all_btn.connect_clicked(move |_| {
            let configs = generated_configs.borrow().clone();
            if configs.is_empty() {
                return;
            }

            let file_dialog = gtk4::FileDialog::builder()
                .title("Save Batch Configs (ZIP)")
                .initial_name("batch-configs.zip")
                .build();

            let configs = configs.clone();
            let sb = status_buffer.clone();
            file_dialog.save(
                Some(&dialog_ref),
                None::<&gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(path) = file.path() {
                            match export_configs_as_zip(&path, &configs) {
                                Ok(()) => {
                                    sb.set_text(&format!(
                                        "Exported {} configs to {}",
                                        configs.len(),
                                        path.display()
                                    ));
                                }
                                Err(e) => {
                                    sb.set_text(&format!("Export failed: {e}"));
                                }
                            }
                        }
                    }
                },
            );
        });
    }

    dialog.set_child(Some(&main_box));
    dialog.present();
}

/// Export configs as a minimal uncompressed ZIP archive (no external crate needed).
fn export_configs_as_zip(
    path: &std::path::Path,
    configs: &[(String, String)],
) -> Result<(), String> {
    let file = std::fs::File::create(path).map_err(|e| format!("Create file: {e}"))?;
    let mut writer = std::io::BufWriter::new(file);

    let mut central_dir = Vec::new();
    let mut offset: u32 = 0;

    for (name, content) in configs {
        let name_bytes = name.as_bytes();
        let content_bytes = content.as_bytes();
        let crc = crc32_simple(content_bytes);

        let local_header = build_zip_local_header(name_bytes, content_bytes, crc);
        writer
            .write_all(&local_header)
            .map_err(|e| format!("Write: {e}"))?;
        writer
            .write_all(content_bytes)
            .map_err(|e| format!("Write: {e}"))?;

        let cd_entry = build_zip_cd_entry(name_bytes, content_bytes, crc, offset);
        central_dir.push(cd_entry);

        offset += local_header.len() as u32 + content_bytes.len() as u32;
    }

    let cd_offset = offset;
    let mut cd_size: u32 = 0;
    for entry in &central_dir {
        writer
            .write_all(entry)
            .map_err(|e| format!("Write: {e}"))?;
        cd_size += entry.len() as u32;
    }

    let num_entries = configs.len() as u16;
    let eocd = build_zip_eocd(num_entries, cd_size, cd_offset);
    writer
        .write_all(&eocd)
        .map_err(|e| format!("Write: {e}"))?;

    Ok(())
}

fn build_zip_local_header(name: &[u8], content: &[u8], crc: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&0x04034b50u32.to_le_bytes()); // local file header signature
    h.extend_from_slice(&20u16.to_le_bytes()); // version needed
    h.extend_from_slice(&0u16.to_le_bytes()); // flags
    h.extend_from_slice(&0u16.to_le_bytes()); // compression: store
    h.extend_from_slice(&0u16.to_le_bytes()); // mod time
    h.extend_from_slice(&0u16.to_le_bytes()); // mod date
    h.extend_from_slice(&crc.to_le_bytes());
    h.extend_from_slice(&(content.len() as u32).to_le_bytes()); // compressed size
    h.extend_from_slice(&(content.len() as u32).to_le_bytes()); // uncompressed size
    h.extend_from_slice(&(name.len() as u16).to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // extra field length
    h.extend_from_slice(name);
    h
}

fn build_zip_cd_entry(name: &[u8], content: &[u8], crc: u32, offset: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&0x02014b50u32.to_le_bytes()); // central dir signature
    h.extend_from_slice(&20u16.to_le_bytes()); // version made by
    h.extend_from_slice(&20u16.to_le_bytes()); // version needed
    h.extend_from_slice(&0u16.to_le_bytes()); // flags
    h.extend_from_slice(&0u16.to_le_bytes()); // compression: store
    h.extend_from_slice(&0u16.to_le_bytes()); // mod time
    h.extend_from_slice(&0u16.to_le_bytes()); // mod date
    h.extend_from_slice(&crc.to_le_bytes());
    h.extend_from_slice(&(content.len() as u32).to_le_bytes()); // compressed size
    h.extend_from_slice(&(content.len() as u32).to_le_bytes()); // uncompressed size
    h.extend_from_slice(&(name.len() as u16).to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // extra field length
    h.extend_from_slice(&0u16.to_le_bytes()); // comment length
    h.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    h.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    h.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    h.extend_from_slice(&offset.to_le_bytes()); // local header offset
    h.extend_from_slice(name);
    h
}

fn build_zip_eocd(num_entries: u16, cd_size: u32, cd_offset: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&0x06054b50u32.to_le_bytes()); // end of central dir signature
    h.extend_from_slice(&0u16.to_le_bytes()); // disk number
    h.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    h.extend_from_slice(&num_entries.to_le_bytes()); // entries on disk
    h.extend_from_slice(&num_entries.to_le_bytes()); // total entries
    h.extend_from_slice(&cd_size.to_le_bytes());
    h.extend_from_slice(&cd_offset.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // comment length
    h
}

/// Simple CRC-32 (ISO 3309) without external crate.
fn crc32_simple(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Config diff (device comparison)
// ---------------------------------------------------------------------------

/// Fetch current config from a device via SSH.
async fn fetch_device_config(host_id: &str, device_type: &str) -> anyhow::Result<String> {
    use anyhow::Context;

    let conn = zbus::Connection::system()
        .await
        .context("D-Bus connection failed — is the daemon running?")?;

    let proxy = supermgr_core::dbus::DaemonProxy::new(&conn)
        .await
        .context("DaemonProxy creation failed")?;

    let command = match device_type {
        "FortiGate" => "show full-configuration",
        "UniFi" => "cat /tmp/system.cfg",
        _ => "show full-configuration",
    };

    let result = proxy
        .ssh_execute_command(host_id, command)
        .await
        .context("SSH execute failed")?;

    Ok(result)
}

/// Compute a simple line-based diff for side-by-side display.
/// Returns (tag, line) pairs: ' ' = unchanged, '-' = removed, '+' = added.
fn compute_line_diff(old_text: &str, new_text: &str) -> Vec<(char, String)> {
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    let old_set: HashSet<&str> = old_lines.iter().copied().collect();
    let new_set: HashSet<&str> = new_lines.iter().copied().collect();

    let mut result = Vec::new();
    let mut oi = 0;
    let mut ni = 0;

    while oi < old_lines.len() && ni < new_lines.len() {
        if old_lines[oi] == new_lines[ni] {
            result.push((' ', old_lines[oi].to_string()));
            oi += 1;
            ni += 1;
        } else if !new_set.contains(old_lines[oi]) {
            result.push(('-', old_lines[oi].to_string()));
            oi += 1;
        } else if !old_set.contains(new_lines[ni]) {
            result.push(('+', new_lines[ni].to_string()));
            ni += 1;
        } else {
            result.push(('-', old_lines[oi].to_string()));
            oi += 1;
        }
    }

    while oi < old_lines.len() {
        result.push(('-', old_lines[oi].to_string()));
        oi += 1;
    }
    while ni < new_lines.len() {
        result.push(('+', new_lines[ni].to_string()));
        ni += 1;
    }

    result
}

/// Show a side-by-side diff dialog comparing old (device) config vs new (generated) config.
///
/// Left pane shows the device's current config with removed lines highlighted red.
/// Right pane shows the generated config with added lines highlighted green.
/// A "Copy Unified Diff" button copies the diff in unified format.
fn show_diff_dialog(
    parent: Option<&gtk4::Window>,
    old_text: &str,
    new_text: &str,
    old_label: &str,
    new_label: &str,
) {
    let dialog = gtk4::Window::builder()
        .title("Config Diff")
        .default_width(1100)
        .default_height(700)
        .modal(true)
        .build();

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    let main_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();

    let header = adw::HeaderBar::new();
    main_box.append(&header);

    // Stats bar
    let diff_lines = compute_line_diff(old_text, new_text);
    let added = diff_lines.iter().filter(|(t, _)| *t == '+').count();
    let removed = diff_lines.iter().filter(|(t, _)| *t == '-').count();
    let unchanged = diff_lines.iter().filter(|(t, _)| *t == ' ').count();

    let stats_label = gtk4::Label::builder()
        .label(&format!(
            "  +{added} added   -{removed} removed   {unchanged} unchanged",
        ))
        .css_classes(["dim-label"])
        .halign(gtk4::Align::Start)
        .margin_start(16)
        .margin_top(8)
        .margin_bottom(4)
        .build();
    main_box.append(&stats_label);

    // Side-by-side paned view
    let paned = gtk4::Paned::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .vexpand(true)
        .hexpand(true)
        .build();

    // Left side: old (device) config
    let left_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    let left_title = gtk4::Label::builder()
        .label(old_label)
        .css_classes(["title-4"])
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .margin_top(8)
        .margin_bottom(4)
        .build();
    left_box.append(&left_title);

    let left_tag_table = gtk4::TextTagTable::new();
    let removed_tag = gtk4::TextTag::builder()
        .name("removed")
        .background("rgba(255, 80, 80, 0.25)")
        .build();
    left_tag_table.add(&removed_tag);

    let left_buffer = gtk4::TextBuffer::new(Some(&left_tag_table));
    let left_view = gtk4::TextView::builder()
        .buffer(&left_buffer)
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::None)
        .vexpand(true)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(12)
        .right_margin(12)
        .build();
    let left_scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .child(&left_view)
        .build();
    left_scroll.add_css_class("card");
    left_box.append(&left_scroll);

    // Right side: new (generated) config
    let right_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    let right_title = gtk4::Label::builder()
        .label(new_label)
        .css_classes(["title-4"])
        .halign(gtk4::Align::Start)
        .margin_start(12)
        .margin_top(8)
        .margin_bottom(4)
        .build();
    right_box.append(&right_title);

    let right_tag_table = gtk4::TextTagTable::new();
    let added_tag = gtk4::TextTag::builder()
        .name("added")
        .background("rgba(80, 200, 80, 0.25)")
        .build();
    right_tag_table.add(&added_tag);

    let right_buffer = gtk4::TextBuffer::new(Some(&right_tag_table));
    let right_view = gtk4::TextView::builder()
        .buffer(&right_buffer)
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::None)
        .vexpand(true)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(12)
        .right_margin(12)
        .build();
    let right_scroll = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .child(&right_view)
        .build();
    right_scroll.add_css_class("card");
    right_box.append(&right_scroll);

    // Populate buffers with colored diff lines
    for (tag, line) in &diff_lines {
        match tag {
            '-' => {
                let start_offset = left_buffer.end_iter().offset();
                left_buffer.insert(&mut left_buffer.end_iter(), &format!("- {line}\n"));
                let start = left_buffer.iter_at_offset(start_offset);
                let end = left_buffer.end_iter();
                left_buffer.apply_tag_by_name("removed", &start, &end);
            }
            '+' => {
                let start_offset = right_buffer.end_iter().offset();
                right_buffer.insert(&mut right_buffer.end_iter(), &format!("+ {line}\n"));
                let start = right_buffer.iter_at_offset(start_offset);
                let end = right_buffer.end_iter();
                right_buffer.apply_tag_by_name("added", &start, &end);
            }
            _ => {
                left_buffer.insert(&mut left_buffer.end_iter(), &format!("  {line}\n"));
                right_buffer.insert(&mut right_buffer.end_iter(), &format!("  {line}\n"));
            }
        }
    }

    paned.set_start_child(Some(&left_box));
    paned.set_end_child(Some(&right_box));
    paned.set_position(550);

    main_box.append(&paned);

    // Bottom bar
    let bottom_bar = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::Center)
        .margin_top(8)
        .margin_bottom(12)
        .build();

    let copy_btn = gtk4::Button::builder()
        .label("Copy Unified Diff")
        .css_classes(["flat", "pill"])
        .build();
    {
        let diff_lines = diff_lines.clone();
        copy_btn.connect_clicked(move |btn| {
            let mut unified = String::new();
            unified.push_str("--- Device Config\n");
            unified.push_str("+++ Generated Config\n");
            for (tag, line) in &diff_lines {
                unified.push(*tag);
                unified.push(' ');
                unified.push_str(line);
                unified.push('\n');
            }
            let clipboard = btn.display().clipboard();
            clipboard.set_text(&unified);
        });
    }
    bottom_bar.append(&copy_btn);
    main_box.append(&bottom_bar);

    dialog.set_child(Some(&main_box));
    dialog.present();
}
