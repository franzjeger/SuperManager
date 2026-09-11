//! Tailscale workspace: saved accounts, connection controls, network settings,
//! peer search, diagnostics and exit-node selection.
//!
//! The daemon projects preferences into typed fields and applies only explicit
//! edits to the expected active account. Reading never requests authorization.
//! Mutations and diagnostics run on operator action; routing changes retain
//! their separate polkit policy. Login and repair keep persistent status pages.

use std::sync::{mpsc, Arc, Mutex};
use std::{cell::RefCell, rc::Rc};

mod controls;
mod preferences;
mod accounts;
mod diagnostics;

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use supermgr_core::tailscale::{TailscaleHealth, TailscaleNode};

use crate::app::{AppMsg, AppState};
use crate::ui::design::{self, Status};

/// Which daemon method a remedy button invokes. Two, not one per state:
/// repair covers everything the daemon can do unattended (install, start,
/// bring up), login is the one flow that needs a browser and a human.
enum Remedy {
    Repair,
    Login,
}

/// Diagnose the stack and send whichever message renders the truth: the
/// device list when everything is up, the health state otherwise.
///
/// This is the page's single entry point for "show me the current state" —
/// used on page open, after a repair, after a login, after a timeout. One
/// function so the health-before-nodes ordering cannot be forgotten at one
/// of the call sites.
static REFRESH_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub async fn refresh(tx: &mpsc::Sender<AppMsg>) {
    use std::sync::atomic::Ordering;
    let generation = REFRESH_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    let health = crate::dbus_client::dbus_tailscale_health().await.map_err(|e| format!("{e:#}"));
    let nodes = if health.as_ref().is_ok_and(|health| health.is_running()) {
        Some(crate::dbus_client::dbus_tailscale_list_nodes().await.map_err(|e| format!("{e:#}")))
    } else { None };
    let management = crate::dbus_client::dbus_tailscale_management().await.map_err(|e| format!("{e:#}"));
    if generation != REFRESH_GENERATION.load(Ordering::SeqCst) { return; }
    tx.send(AppMsg::TailscaleManagementUpdated(management)).ok();
    if let Some(nodes) = nodes { tx.send(AppMsg::TailscaleNodesUpdated(nodes)).ok(); }
    else { tx.send(AppMsg::TailscaleHealthUpdated(health)).ok(); }
}

/// Refresh on network changes and resume, without reconnecting or changing routes.
pub fn watch_environment(rt: &tokio::runtime::Handle, tx: &mpsc::Sender<AppMsg>) {
    let network_tx = tx.clone();
    gtk4::gio::NetworkMonitor::default().connect_network_changed(move |_, _| {
        network_tx.send(AppMsg::TailscaleEnvironmentChanged).ok();
    });
    let tx = tx.clone();
    rt.spawn(async move {
        use futures_util::StreamExt;
        let Ok(conn) = zbus::Connection::system().await else { return };
        let Ok(proxy) = zbus::Proxy::new(&conn, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager").await else { return };
        let Ok(mut signals) = proxy.receive_signal("PrepareForSleep").await else { return };
        while let Some(message) = signals.next().await {
            if message.body().deserialize::<(bool,)>().is_ok_and(|(sleeping,)| !sleeping) {
                tx.send(AppMsg::TailscaleEnvironmentChanged).ok();
            }
        }
    });
}

/// Handles the page needs in order to re-render without being rebuilt.
pub struct TailscaleView {
    /// Root widget, handed to the view stack.
    pub widget: gtk4::Widget,
    /// Swaps between the device list and a full-page status.
    stack: gtk4::Stack,
    /// Container the device rows are rebuilt into on every refresh.
    list: gtk4::Box,
    /// Full-page status for the empty and error cases.
    status_slot: adw::Bin,
    /// Row count, shown beside the heading.
    subtitle: gtk4::Label,
    /// Runtime the exit-node D-Bus calls are spawned on.
    rt: tokio::runtime::Handle,
    /// Where those calls report back to.
    tx: mpsc::Sender<AppMsg>,
    controls: gtk4::Box,
    window: adw::ApplicationWindow,
    app_state: Arc<Mutex<AppState>>,
    rows: Rc<RefCell<Vec<(adw::ExpanderRow, TailscaleNode)>>>,
    search: gtk4::SearchEntry,
    filter: gtk4::DropDown,
    profile_id: Rc<RefCell<Option<String>>>,
    operation_status: gtk4::Label,
    operation_pending: Rc<std::cell::Cell<bool>>,
}

/// Build the page. Starts in the "asking" state — the first render replaces it.
#[must_use]
pub fn build_tailscale_page(
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
    window: &adw::ApplicationWindow,
    app_state: &Arc<Mutex<AppState>>,
) -> TailscaleView {
    let (scroller, content) = design::workspace_body(
        "Tailscale",
        "Manage your accounts, network preferences and connected devices.",
    );

    let heading = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
    let title_box = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
    let subtitle = gtk4::Label::new(Some("Reading local tailscaled…"));
    subtitle.add_css_class("dim-label");
    subtitle.set_halign(gtk4::Align::Start);
    title_box.append(&subtitle);
    title_box.set_hexpand(true);
    heading.append(&title_box);
    let reload = gtk4::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Refresh Tailscale")
        .build();
    {
        let rt = rt.clone();
        let tx = tx.clone();
        reload.connect_clicked(move |_| {
            let tx = tx.clone();
            rt.spawn(async move {
                refresh(&tx).await;
            });
        });
    }
    heading.append(&reload);
    content.append(&heading);
    let operation_status = gtk4::Label::builder().wrap(true).xalign(0.0).visible(false).build();
    content.append(&operation_status);

    let controls = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    content.append(&controls);
    let search = gtk4::SearchEntry::builder()
        .placeholder_text("Find a device, address or OS")
        .hexpand(true)
        .build();
    let filter = gtk4::DropDown::from_strings(&["All devices", "Online", "Offline", "Exit nodes"]);
    let searchbar = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
    searchbar.append(&search);
    searchbar.append(&filter);
    content.append(&searchbar);
    let rows: Rc<RefCell<Vec<(adw::ExpanderRow, TailscaleNode)>>> = Rc::new(RefCell::new(vec![]));
    let apply_filter = {
        let rows = Rc::clone(&rows);
        let search = search.clone();
        let filter = filter.clone();
        Rc::new(move || {
            for (row, node) in rows.borrow().iter() {
                row.set_visible(controls::matches_node(
                    node,
                    &search.text(),
                    filter.selected(),
                ));
            }
        })
    };
    {
        let apply = Rc::clone(&apply_filter);
        search.connect_search_changed(move |_| apply());
    }
    filter.connect_selected_notify(move |_| apply_filter());

    let list = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    let status_slot = adw::Bin::new();

    let stack = gtk4::Stack::new();
    stack.add_named(&list, Some("list"));
    stack.add_named(&status_slot, Some("status"));
    stack.set_visible_child_name("status");
    content.append(&stack);

    status_slot.set_child(Some(&design::empty_state(
        design::icon_name(design::icons::MESH),
        "Reading the tailnet",
        "Asking the local Tailscale daemon which devices it can see.",
    )));

    TailscaleView {
        widget: scroller.upcast(),
        stack,
        list,
        status_slot,
        subtitle,
        rt: rt.clone(),
        tx: tx.clone(),
        controls,
        window: window.clone(),
        app_state: Arc::clone(app_state),
        rows,
        search,
        filter,
        profile_id: Rc::new(RefCell::new(None)),
        operation_status,
        operation_pending: Rc::new(std::cell::Cell::new(false)),
    }
}

impl TailscaleView {
    pub fn render_management(
        &self,
        result: &Result<supermgr_core::tailscale::TailscaleManagement, String>,
    ) {
        *self.profile_id.borrow_mut() = result.as_ref().ok().and_then(|management| management.preferences.as_ref()).and_then(|preferences| preferences.profile_id.clone());
        controls::render_management(self, result);
    }
    /// Render the outcome of a `TailscaleListNodes` call.
    ///
    /// Takes the whole `Result` rather than just the nodes so the error path
    /// cannot be forgotten at a call site — the three states are decided here,
    /// once, instead of at each caller.
    pub fn render(&self, result: &Result<Vec<TailscaleNode>, String>) {
        match result {
            Err(message) => self.show_status(
                design::icon_name(design::icons::VPN_OFF),
                "Tailscale is not answering",
                message,
            ),
            Ok(nodes) if nodes.is_empty() => self.show_status(
                design::icon_name(design::icons::MESH),
                "No devices",
                "The daemon answered, but reported no devices on the tailnet. \
                 If this machine is logged in, `tailscale status` will say the same.",
            ),
            Ok(nodes) => self.show_nodes(nodes),
        }
    }

    /// Render the outcome of a `TailscaleHealth` call — the not-up states.
    ///
    /// Same shape as [`Self::render`], same reason: the whole `Result` comes
    /// in so the error path is decided here, once. Every state the daemon can
    /// repair gets the button that repairs it; the two it cannot — the
    /// browser half of a login, an unreachable supermgrd — render as what
    /// they are.
    pub fn render_health(&self, result: &Result<TailscaleHealth, String>) {
        match result {
            Err(message) => self.show_status(
                design::icon_name(design::icons::VPN_OFF),
                "Tailscale is not answering",
                message,
            ),
            Ok(h) if !h.cli_present => self.show_remedy(
                "Tailscale is not installed",
                "SuperManager can install the tailscale package and start \
                 its service. An authentication prompt will appear.",
                "Install Tailscale",
                Remedy::Repair,
            ),
            Ok(h) if !h.daemon_running => self.show_remedy(
                "Tailscale is installed but not running",
                "The tailscaled service is stopped. SuperManager can start \
                 it and enable it at boot.",
                "Start Tailscale",
                Remedy::Repair,
            ),
            Ok(h) if h.needs_login() => self.show_remedy(
                "This machine is logged out of Tailscale",
                "Logging in opens a browser page. The tailnet appears here \
                 by itself once the login completes.",
                "Log in to Tailscale",
                Remedy::Login,
            ),
            // `tailscale down`: the daemon runs but was told to carry
            // nothing. Distinct from "not running" because the remedy the
            // daemon applies is `tailscale up`, not systemctl.
            Ok(h) if h.backend_state == "Stopped" => self.show_remedy(
                "Tailscale is switched off",
                "tailscaled is running but has been brought down. \
                 SuperManager can bring it back up.",
                "Bring Tailscale up",
                Remedy::Repair,
            ),
            // Healthy, so a node listing is on its way — whoever sent this
            // message follows it with one. Render the in-between honestly.
            Ok(h) if h.is_running() => self.show_status(
                design::icon_name(design::icons::MESH),
                "Reading the tailnet",
                "Asking the local Tailscale daemon which devices it can see.",
            ),
            // "Starting", or a state this build has never heard of. No
            // button, because no remedy is known to apply; the detail or the
            // state name is the most honest thing available.
            Ok(h) => {
                let description = if h.detail.is_empty() {
                    format!(
                        "tailscaled reports state \u{201c}{}\u{201d}.",
                        h.backend_state
                    )
                } else {
                    h.detail.clone()
                };
                self.show_status(
                    design::icon_name(design::icons::VPN_OFF),
                    "Tailscale is not ready",
                    &description,
                );
            }
        }
    }

    fn show_status(&self, icon: &str, title: &str, description: &str) {
        self.status_slot
            .set_child(Some(&design::empty_state(icon, title, description)));
        self.stack.set_visible_child_name("status");
        self.subtitle.set_text("");
    }

    /// A full-page status whose description names the next action and whose
    /// child performs it.
    fn show_remedy(&self, title: &str, description: &str, button_label: &str, remedy: Remedy) {
        let page = design::empty_state(
            design::icon_name(design::icons::VPN_OFF),
            title,
            description,
        );
        let button = gtk4::Button::with_label(button_label);
        button.add_css_class("suggested-action");
        button.add_css_class("pill");
        button.set_halign(gtk4::Align::Center);
        match remedy {
            Remedy::Repair => self.wire_repair_button(&button),
            Remedy::Login => self.wire_login_button(&button),
        }
        page.set_child(Some(&button));
        self.status_slot.set_child(Some(&page));
        self.stack.set_visible_child_name("status");
        self.subtitle.set_text("");
    }

    /// Ask the daemon to repair the stack, then re-render whatever is true
    /// afterwards.
    ///
    /// The button disables itself and the whole status page is replaced by a
    /// "working" one, so a slow package installation does not look like a
    /// dead click. The ending is always [`refresh`]: on success it renders
    /// the next state (often the login prompt), on failure it re-renders the
    /// unrepaired state with its button back — the toast carries the error.
    fn wire_repair_button(&self, button: &gtk4::Button) {
        let rt = self.rt.clone();
        let tx = self.tx.clone();
        let status_slot = self.status_slot.clone();
        button.connect_clicked(move |btn| {
            btn.set_sensitive(false);
            status_slot.set_child(Some(&design::empty_state(
                design::icon_name(design::icons::MESH),
                "Repairing Tailscale",
                "Installing the package and starting the service as needed. \
                 An authentication prompt may appear.",
            )));
            let tx = tx.clone();
            rt.spawn(async move {
                if let Err(e) = crate::dbus_client::dbus_tailscale_repair().await {
                    tx.send(AppMsg::OperationFailed(format!("{e:#}"))).ok();
                }
                refresh(&tx).await;
            });
        });
    }

    /// Start a login, open the URL, and watch health until the tailnet
    /// appears.
    ///
    /// The URL can arrive on the login call or on a later health tick —
    /// control-plane round-trips are usually fast and occasionally half a
    /// minute — so both paths feed [`AppMsg::TailscaleLoginUrl`], guarded to
    /// fire once. The poll is bounded: five minutes of somebody not
    /// finishing the browser flow ends with the page saying the machine is
    /// still logged out, which it is.
    fn wire_login_button(&self, button: &gtk4::Button) {
        let rt = self.rt.clone(); let tx = self.tx.clone(); let window = self.window.clone();
        let profile = Rc::clone(&self.profile_id);
        button.connect_clicked(move |_| accounts::show(&window, &rt, &tx, profile.borrow().as_deref().unwrap_or("")));
    }

    fn show_nodes(&self, nodes: &[TailscaleNode]) {
        while let Some(child) = self.list.first_child() {
            self.list.remove(&child);
        }
        self.rows.borrow_mut().clear();

        // This device first, then online peers, then offline — the order the
        // question is usually asked in. Stable within each group by name so
        // rows do not jump around between refreshes of the same tailnet.
        let mut ordered: Vec<&TailscaleNode> = nodes.iter().collect();
        ordered.sort_by_key(|n| (!n.is_self, !n.online, n.display_name().to_ascii_lowercase()));

        let online = nodes.iter().filter(|n| n.online).count();
        self.subtitle.set_text(&format!(
            "{} device{} · {online} online",
            nodes.len(),
            if nodes.len() == 1 { "" } else { "s" },
        ));

        if let Some(card) = self.exit_node_card(nodes) {
            self.list.append(&card);
        }

        let group = design::card("Devices");
        for node in ordered {
            let row = controls::node_row(self, node);
            row.set_visible(controls::matches_node(
                node,
                &self.search.text(),
                self.filter.selected(),
            ));
            group.add(&row);
            self.rows.borrow_mut().push((row, node.clone()));
        }
        self.list.append(&group);
        self.stack.set_visible_child_name("list");
    }

    /// The exit-node card, or `None` when there is nothing to offer.
    ///
    /// Absent rather than empty when no peer advertises the capability: a card
    /// headed "Exit node" containing only the words "none available" is worse
    /// than no card, because it reads as a broken feature rather than a tailnet
    /// where nobody runs `--advertise-exit-node`.
    fn exit_node_card(&self, nodes: &[TailscaleNode]) -> Option<adw::PreferencesGroup> {
        let active = nodes.iter().find(|n| n.exit_node);
        let mut candidates: Vec<&TailscaleNode> = nodes
            .iter()
            .filter(|n| n.exit_node_option && !n.is_self)
            .collect();
        if candidates.is_empty() && active.is_none() {
            return None;
        }
        candidates.sort_by_key(|n| (!n.online, n.display_name().to_ascii_lowercase()));

        let card = design::card("Exit node");
        card.set_description(Some(
            "Route internet traffic through a device. Switching checks TCP access to 1.1.1.1 and 8.8.8.8 on port 443 and restores the previous selection if connectivity fails.",
        ));

        if let Some(node) = active {
            let row = adw::ActionRow::new();
            row.set_title(node.display_name());
            row.set_subtitle("Selected for internet traffic");
            row.add_prefix(&design::status_pill(if node.online { Status::Connected } else { Status::Error }, if node.online { "Selected" } else { "Offline" }));
            let stop = gtk4::Button::with_label("Stop using");
            stop.add_css_class("destructive-action");
            stop.set_valign(gtk4::Align::Center);
            self.wire_exit_node_button(&stop, String::new());
            row.add_suffix(&stop);
            card.add(&row);
        }

        for node in candidates {
            // Skip the active one: it already has a row above, with the
            // control that applies to it.
            if node.exit_node {
                continue;
            }
            let row = adw::ActionRow::new();
            row.set_title(node.display_name());
            row.set_subtitle(if node.online {
                "Available"
            } else {
                "Offline — tailscale will refuse this one"
            });
            let use_btn = gtk4::Button::with_label("Use and verify");
            use_btn.set_valign(gtk4::Align::Center);
            // An offline peer cannot carry traffic, and tailscaled says so
            // rather than trying. Disabling the button says the same thing
            // without spending a polkit prompt to find out.
            use_btn.set_sensitive(node.online);
            if let Some(target) = node.primary_ip() {
                self.wire_exit_node_button(&use_btn, target.to_owned());
            } else {
                // No address to name it by. Nothing to send.
                use_btn.set_sensitive(false);
            }
            row.add_suffix(&use_btn);
            card.add(&row);
        }

        Some(card)
    }

    /// Send `value` to the daemon when `button` is clicked; empty clears.
    ///
    /// The button goes insensitive on click so a double-click cannot queue two
    /// polkit prompts. Nothing re-enables it, and nothing needs to: the reply
    /// carries a fresh node list, `show_nodes` rebuilds every row, and this
    /// button is replaced by a new one. Re-enabling it from the worker would
    /// mean touching a GTK widget off the main thread anyway.
    ///
    /// Both calls happen in the worker: set, then re-list. The authority on
    /// which node is in use is tailscaled, not what we just asked for — a
    /// `set` that reported success and a peer that then refused traffic would
    /// otherwise leave the page claiming something untrue.
    fn wire_exit_node_button(&self, button: &gtk4::Button, value: String) {
        let rt = self.rt.clone(); let tx = self.tx.clone();
        let profile = Rc::clone(&self.profile_id); let pending = Rc::clone(&self.operation_pending);
        let status = self.operation_status.clone(); let controls = self.controls.clone(); let list = self.list.clone();
        button.connect_clicked(move |_| {
            if pending.replace(true) { return; }
            let Some(profile) = profile.borrow().clone() else {
                pending.set(false); tx.send(AppMsg::OperationFailed("Account settings are not available yet. Refresh Tailscale first.".into())).ok(); return;
            };
            controls.set_sensitive(false); list.set_sensitive(false);
            status.set_visible(true); status.remove_css_class("error"); status.set_label("Updating exit node and checking connectivity…");
            let value = value.clone();
            let controls = controls.clone(); let list = list.clone(); let status = status.clone(); let pending = Rc::clone(&pending);
            let rt = rt.clone(); let tx = tx.clone();
            // The D-Bus call runs on the tokio runtime; the widget updates
            // await it back on the GTK main thread.
            gtk4::glib::spawn_future_local(async move {
                match rt.spawn(async move { crate::dbus_client::dbus_tailscale_change_exit_node(&profile, &value).await }).await {
                    Ok(Ok(message)) => status.set_label(&message),
                    Ok(Err(error)) => { status.set_label(&format!("{error}")); status.add_css_class("error"); },
                    Err(error) => { status.set_label(&format!("Exit-node task stopped: {error}")); status.add_css_class("error"); },
                }
                pending.set(false); controls.set_sensitive(true); list.set_sensitive(true);
                rt.spawn(async move { refresh(&tx).await; });
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, online: bool, is_self: bool) -> TailscaleNode {
        TailscaleNode {
            id: format!("n{name}"),
            hostname: name.to_owned(),
            dns_name: format!("{name}.tailnet.ts.net."),
            os: "linux".to_owned(),
            tailscale_ips: vec!["100.64.0.1".to_owned()],
            online,
            is_self,
            exit_node: false,
            exit_node_option: false,
            last_seen: String::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            current_address: String::new(),
            relay: String::new(),
        }
    }

    /// The ordering key, lifted out so it can be checked without a display.
    /// Everything else on this page needs a GTK main context; the sort does
    /// not, and it is the part with a decision in it.
    fn sort_key(n: &TailscaleNode) -> (bool, bool, String) {
        (!n.is_self, !n.online, n.display_name().to_ascii_lowercase())
    }

    #[test]
    fn this_device_sorts_first_even_when_offline() {
        // An operator looking for their own machine should not have to scan
        // past every online peer to find it.
        let mut nodes = [
            node("zeta", true, false),
            node("mine", false, true),
            node("alpha", true, false),
        ];
        nodes.sort_by_key(sort_key);
        assert_eq!(nodes[0].hostname, "mine");
    }

    #[test]
    fn online_peers_precede_offline_ones() {
        let mut nodes = [node("alpha", false, false), node("zeta", true, false)];
        nodes.sort_by_key(sort_key);
        assert_eq!(nodes[0].hostname, "zeta", "offline peer sorted above online");
    }

    #[test]
    fn ties_break_on_name_case_insensitively() {
        // Stable order across refreshes: without this rows shuffle whenever
        // tailscaled returns peers in a different order, which it does.
        let mut nodes = [
            node("Beta", true, false),
            node("alpha", true, false),
            node("Gamma", true, false),
        ];
        nodes.sort_by_key(sort_key);
        let names: Vec<&str> = nodes.iter().map(|n| n.hostname.as_str()).collect();
        assert_eq!(names, ["alpha", "Beta", "Gamma"]);
    }
}
