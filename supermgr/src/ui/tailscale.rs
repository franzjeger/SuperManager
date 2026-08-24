//! Tailscale page — the tailnet as a device list, with self-heal.
//!
//! # What this can and cannot do
//!
//! List the tailnet, choose an exit node, and repair a broken stack. The
//! first two are `TailscaleListNodes` and `TailscaleSetExitNode`; the third
//! is `TailscaleHealth` + `TailscaleRepair` + `TailscaleLogin`. The one
//! thing the page cannot do for you is the browser half of a login — it
//! opens the URL and waits.
//!
//! # Exit nodes
//!
//! Only peers advertising the capability are offered — `exit_node_option`, not
//! `exit_node`. The second means "this is the one currently carrying my
//! traffic", and offering every peer as a choice when tailscaled would refuse
//! most of them is how a control teaches people not to trust it.
//!
//! Selecting one is polkit-gated in the daemon, so the first use per session
//! raises an authentication prompt. That is deliberate: it decides where every
//! packet this machine sends goes, and this bus is reachable by every local
//! account. A dismissed prompt comes back as an error and is shown as one.
//!
//! # Broken is a state with a button, not an error
//!
//! An empty list and a broken tailscale are different facts, and collapsing
//! them into "no devices" is how someone spends ten minutes wondering why
//! their tailnet is missing when the answer is that tailscaled is not
//! running. It used to stop there — the failure was at least named. But
//! naming a condition the daemon can fix, on a machine the operator manages
//! with this very app, is a dead end wearing a diagnosis: every state of
//! the stack the daemon can distinguish (CLI missing, service stopped,
//! logged out, brought down) renders as that state *with the button that
//! fixes it*. Only the states nobody but a human can fix — the browser
//! login, an unreachable supermgrd — render without a remedy attached.
//!
//! # The login flow, from this side
//!
//! Log in → daemon spawns `tailscale login` and hands back the URL (or the
//! URL arrives on a later health poll — the control plane can be slow) →
//! [`AppMsg::TailscaleLoginUrl`] opens the browser once → this page shows
//! "waiting" while a poll task watches `TailscaleHealth` → the moment the
//! backend reports `Running`, the poll fetches nodes and the page becomes
//! the device list. The poll is bounded; someone abandoning the browser tab
//! leaves the page saying it is still logged out, which is the truth.

use std::sync::mpsc;

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use supermgr_core::tailscale::{TailscaleHealth, TailscaleNode};

use crate::app::AppMsg;
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
pub async fn refresh(tx: &mpsc::Sender<AppMsg>) {
    match crate::dbus_client::dbus_tailscale_health().await {
        Err(e) => {
            tx.send(AppMsg::TailscaleHealthUpdated(Err(format!("{e:#}")))).ok();
        }
        Ok(h) if h.is_running() => {
            let nodes = crate::dbus_client::dbus_tailscale_list_nodes()
                .await
                .map_err(|e| format!("{e:#}"));
            tx.send(AppMsg::TailscaleNodesUpdated(nodes)).ok();
        }
        Ok(h) => {
            tx.send(AppMsg::TailscaleHealthUpdated(Ok(h))).ok();
        }
    }
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
}

/// Build the page. Starts in the "asking" state — the first render replaces it.
#[must_use]
pub fn build_tailscale_page(
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) -> TailscaleView {
    let (scroller, content) = design::detail_body();

    let heading = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
    let title_box = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
    let title = gtk4::Label::new(Some("Tailnet"));
    title.add_css_class("title-2");
    title.set_halign(gtk4::Align::Start);
    let subtitle = gtk4::Label::new(Some("Reading local tailscaled…"));
    subtitle.add_css_class("dim-label");
    subtitle.set_halign(gtk4::Align::Start);
    title_box.append(&title);
    title_box.append(&subtitle);
    title_box.set_hexpand(true);
    heading.append(&title_box);
    content.append(&heading);

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
    }
}

impl TailscaleView {
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
                    format!("tailscaled reports state \u{201c}{}\u{201d}.", h.backend_state)
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
        let rt = self.rt.clone();
        let tx = self.tx.clone();
        let status_slot = self.status_slot.clone();
        button.connect_clicked(move |btn| {
            btn.set_sensitive(false);
            status_slot.set_child(Some(&design::empty_state(
                design::icon_name(design::icons::MESH),
                "Waiting for the browser login",
                "A Tailscale login page is opening in your browser. This \
                 page updates by itself once the login completes.",
            )));
            let tx = tx.clone();
            rt.spawn(async move {
                let mut url_opened = false;
                match crate::dbus_client::dbus_tailscale_login().await {
                    Err(e) => {
                        tx.send(AppMsg::OperationFailed(format!("{e:#}"))).ok();
                        refresh(&tx).await;
                        return;
                    }
                    Ok(url) if !url.is_empty() => {
                        tx.send(AppMsg::TailscaleLoginUrl(url)).ok();
                        url_opened = true;
                    }
                    // Empty URL: the control plane had not handed one out
                    // within the daemon's patience. The poll below picks it
                    // up from health.auth_url.
                    Ok(_) => {}
                }
                const TICKS: u32 = 150; // × 2 s = five minutes
                for _ in 0..TICKS {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    match crate::dbus_client::dbus_tailscale_health().await {
                        // Transient bus trouble mid-poll: keep going, the
                        // deadline bounds the total wait either way.
                        Err(_) => {}
                        Ok(h) if h.is_running() => {
                            refresh(&tx).await;
                            return;
                        }
                        Ok(h) => {
                            if !url_opened && !h.auth_url.is_empty() {
                                tx.send(AppMsg::TailscaleLoginUrl(h.auth_url.clone())).ok();
                                url_opened = true;
                            }
                        }
                    }
                }
                // Timed out. Render the truth — still logged out — with the
                // login button back.
                refresh(&tx).await;
            });
        });
    }

    fn show_nodes(&self, nodes: &[TailscaleNode]) {
        while let Some(child) = self.list.first_child() {
            self.list.remove(&child);
        }

        // This device first, then online peers, then offline — the order the
        // question is usually asked in. Stable within each group by name so
        // rows do not jump around between refreshes of the same tailnet.
        let mut ordered: Vec<&TailscaleNode> = nodes.iter().collect();
        ordered.sort_by_key(|n| {
            (
                !n.is_self,
                !n.online,
                n.display_name().to_ascii_lowercase(),
            )
        });

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
            group.add(&Self::node_row(node));
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
            "All traffic from this machine leaves through the device you pick.",
        ));

        if let Some(node) = active {
            let row = adw::ActionRow::new();
            row.set_title(node.display_name());
            row.set_subtitle("Carrying this machine's traffic");
            row.add_prefix(&design::status_pill(Status::Connected, "In use"));
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
            let use_btn = gtk4::Button::with_label("Use");
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
        let rt = self.rt.clone();
        let tx = self.tx.clone();
        button.connect_clicked(move |btn| {
            btn.set_sensitive(false);
            let tx = tx.clone();
            let value = value.clone();
            rt.spawn(async move {
                let outcome = crate::dbus_client::dbus_tailscale_set_exit_node(&value)
                    .await
                    .map_err(|e| format!("{e:#}"));
                if let Err(message) = outcome {
                    tx.send(AppMsg::OperationFailed(message)).ok();
                }
                // Re-list either way: on success to pick up the new active
                // node, on failure because the page's picture of the tailnet
                // is now unverified — including the case where the operator
                // dismissed the authentication prompt.
                let nodes = crate::dbus_client::dbus_tailscale_list_nodes()
                    .await
                    .map_err(|e| format!("{e:#}"));
                tx.send(AppMsg::TailscaleNodesUpdated(nodes)).ok();
            });
        });
    }

    /// One device. Title is the name, subtitle carries the address and the
    /// MagicDNS name — the two things that get copied into an ssh command.
    fn node_row(node: &TailscaleNode) -> adw::ActionRow {
        let row = adw::ActionRow::new();
        row.set_title(node.display_name());

        let mut detail = String::new();
        if let Some(ip) = node.primary_ip() {
            detail.push_str(ip);
        }
        if !node.dns_name.is_empty() {
            let dns = node.dns_name.trim_end_matches('.');
            if !detail.is_empty() {
                detail.push_str(" · ");
            }
            detail.push_str(dns);
        }
        if !node.os.is_empty() {
            if !detail.is_empty() {
                detail.push_str(" · ");
            }
            detail.push_str(&node.os);
        }
        row.set_subtitle(&detail);
        // Addresses and DNS names are for copying, and a row that renders them
        // without letting you select them just moves the terminal trip later.
        row.set_subtitle_selectable(true);

        if node.is_self {
            row.add_suffix(&design::badge("This device"));
        }
        if node.exit_node {
            row.add_suffix(&design::badge("Exit node"));
        }
        let (status, label) = if node.online {
            (Status::Connected, "Online")
        } else {
            (Status::Disconnected, "Offline")
        };
        row.add_suffix(&design::status_pill(status, label));
        row
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
