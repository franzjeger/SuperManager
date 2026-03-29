//! Multi-step provisioning wizard for FortiGate and UniFi devices.
//!
//! Collects customer info, network design, services, security policies,
//! then generates device configuration via Claude and pushes it over
//! REST API or SSH.

use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
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
IMPORTANT RULES:\n\
- Output FortiGate config as CLI commands ONLY (no markdown, no explanation before/after the config block).\n\
- Output UniFi config as controller API JSON.\n\
- The LAN base subnet MUST match the subnet specified in the wizard input — do not invent a different one.\n\
- All VLAN subnets must use the exact values from the input — do not change octets.\n\
- For web filter categories, add a comment with the category name next to each numeric ID \
  (e.g. set category 2  # Adult/Mature Content).\n\
- Mark all placeholder credentials with CHANGE-ME and add a deployment checklist at the end \
  listing every item that must be changed before production use.\n\
- For S2S VPN, clearly mark remote-gw and dst-subnet as placeholders that MUST be updated.\n\
- Use IKEv2 with AES-256-GCM or AES-256/SHA-256 and DH group 14+ for all VPN configs.";

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

            let s = app_state.lock().unwrap();
            let filter = match device_filter {
                "FortiGate" => "Fortigate",
                "UniFi" => "UniFi",
                _ => "",
            };
            let mut labels = Vec::new();
            for host in &s.ssh_hosts {
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

    page.add(&customer_group);
    page.add(&demo_group);

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

    btn_box.append(&generate_spinner);
    btn_box.append(&generate_btn);
    btn_box.append(&push_btn);
    btn_box.append(&export_btn);
    btn_box.append(&export_html_btn);
    btn_box.append(&export_pdf_btn);

    // Generate button — sends wizard state to Claude.
    //
    // The generated config text is ferried back via an Arc<Mutex> slot
    // polled by `glib::timeout_add_local` (GTK widgets are not Send).
    {
        let config_buffer = config_buffer.clone();
        let state = Rc::clone(state);
        let rt = rt.clone();
        let push_btn = push_btn.clone();
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

                    *slot.lock().unwrap() = Some(config_text);
                });
            }

            // Poll for the result on the GTK main thread.
            let buf = config_buffer.clone();
            let pb = push_btn.clone();
            let eb = export_btn.clone();
            let ehb = export_html_btn.clone();
            let epb = export_pdf_btn.clone();
            let gb = generate_btn.clone();
            let gs = generate_spinner.clone();
            let ws = Rc::clone(&state);
            glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                let maybe = result_slot.lock().unwrap().take();
                if let Some(config_text) = maybe {
                    ws.borrow_mut().generated_config = config_text.clone();
                    buf.set_text(&config_text);
                    let ok = !config_text.starts_with("# Error");
                    pb.set_sensitive(ok);
                    eb.set_sensitive(ok);
                    ehb.set_sensitive(ok);
                    epb.set_sensitive(ok);
                    gb.set_sensitive(true);
                    gs.set_visible(false);
                    gs.set_spinning(false);
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
                    *flag.lock().unwrap() = true;
                });
            }

            let btn = btn.clone();
            glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
                if *done_flag.lock().unwrap() {
                    btn.set_sensitive(true);
                    btn.set_label("Push Config");
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

    page.append(&summary_label);
    page.append(&config_scroll);
    page.append(&btn_box);

    page.upcast()
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
         - Site-to-Site VPN: {}\n\
         - Remote Access VPN: {}\n\
         - DNS Servers: {}\n\
         - NTP Server: {}\n\
         - Syslog: {}{}\n\
         - Admin HTTPS Port: {}\n",
        if s.vpn_site_to_site { "Yes" } else { "No" },
        if s.vpn_remote_access { "Yes" } else { "No" },
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

    prompt.push_str(
        "\nIMPORTANT: Use the EXACT subnets listed above. The LAN base interface \
         IP must be the .1 address of the LAN Subnet specified. Do NOT generate \
         different octets.\n"
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
