//! Tailscale page — the tailnet as a device list.
//!
//! # What this can and cannot do
//!
//! Read-only, because that is all the Linux daemon exposes: one D-Bus method,
//! `TailscaleListNodes`, backed by `tailscale status --json`. There is no
//! bring-up, no exit-node selection and no login flow here, and the page does
//! not pretend otherwise — no disabled buttons hinting at features that do not
//! exist behind them. Adding control means adding daemon methods first.
//!
//! That is still worth a screen. "Which of my machines are on the tailnet,
//! what are their addresses, which one is advertising an exit node" is the
//! question an operator actually asks before SSH-ing somewhere, and answering
//! it here beats dropping to a terminal for `tailscale status`.
//!
//! # Why three states and not two
//!
//! An empty list and a broken tailscale are different facts, and collapsing
//! them into "no devices" is how someone spends ten minutes wondering why
//! their tailnet is missing when the answer is that tailscaled is not running.
//! Every failure the daemon can report is somebody else's software being
//! absent or asleep — CLI not installed, daemon down, not logged in — so the
//! error text is surfaced verbatim rather than summarised into a shrug.

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use supermgr_core::tailscale::TailscaleNode;

use crate::ui::design::{self, Status};

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
}

/// Build the page. Starts in the "asking" state — the first render replaces it.
#[must_use]
pub fn build_tailscale_page() -> TailscaleView {
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

    fn show_status(&self, icon: &str, title: &str, description: &str) {
        self.status_slot
            .set_child(Some(&design::empty_state(icon, title, description)));
        self.stack.set_visible_child_name("status");
        self.subtitle.set_text("");
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

        let group = design::card("Devices");
        for node in ordered {
            group.add(&Self::node_row(node));
        }
        self.list.append(&group);
        self.stack.set_visible_child_name("list");
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
