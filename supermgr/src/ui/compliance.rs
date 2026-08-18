//! Compliance page — run the CIS Linux baseline and read the result.
//!
//! # Scope, and why it is narrower than the macOS app's
//!
//! Linux hosts only. The daemon exposes the Linux baseline (seven checks over
//! SSH) and not the `FortiGate` one, because `FortiGate` compliance wants a REST
//! client `supermgrd` does not have. So a `FortiGate` host appears in the picker
//! with its reason rather than being hidden — "no scan button because this
//! platform cannot audit `FortiGate` yet" is a different message from "this
//! device has no baseline", and both are better than a silently missing row.
//!
//! Which baseline applies to which device type comes from
//! [`DeviceType::compliance_dispatch`] in core, shared with the macOS app so
//! the two cannot disagree about what a device gets audited against.
//!
//! # Why failures sort first
//!
//! A passing control is a fact; a failing one is work. Twenty-two passes above
//! the one failure is the layout equivalent of burying it, so the list is
//! ordered by consequence: failures by descending severity, then errors, then
//! everything that passed.

use std::sync::mpsc;

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use supermgr_core::compliance::{CheckDefinition, ComplianceRun, RunSummary, Severity, Status};
use supermgr_core::host::HostSummary;
use supermgr_core::ssh::device_type::ComplianceDispatch;

use crate::app::AppMsg;
use crate::ui::design::{self, Status as PillStatus};

/// Everything the page needs to re-render without being rebuilt.
pub struct ComplianceView {
    /// Root widget, handed to the view stack.
    pub widget: gtk4::Widget,
    /// Host picker. Rebuilt when the host list changes.
    host_list: gtk4::Box,
    /// Result area: score, checks, history.
    body: gtk4::Box,
    /// Swaps between the body and a full-page status.
    stack: gtk4::Stack,
    /// Full-page status for "pick a host" and error cases.
    status_slot: adw::Bin,
    /// Runtime the D-Bus calls are spawned on.
    rt: tokio::runtime::Handle,
    /// Where those calls report back to.
    tx: mpsc::Sender<AppMsg>,
}

/// Build the page. Starts asking the operator to pick a host.
#[must_use]
pub fn build_compliance_page(
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) -> ComplianceView {
    let (scroller, content) = design::detail_body();

    let title = gtk4::Label::new(Some("Compliance"));
    title.add_css_class("title-2");
    title.set_halign(gtk4::Align::Start);
    content.append(&title);

    let host_list = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    content.append(&host_list);

    let body = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    let status_slot = adw::Bin::new();
    let stack = gtk4::Stack::new();
    stack.add_named(&body, Some("body"));
    stack.add_named(&status_slot, Some("status"));
    stack.set_visible_child_name("status");
    content.append(&stack);

    status_slot.set_child(Some(&design::empty_state(
        design::icon_name(design::icons::SHIELD),
        "No scan selected",
        "Pick a Linux host above and run a scan, or open a previous run from its history.",
    )));

    ComplianceView {
        widget: scroller.upcast(),
        host_list,
        body,
        stack,
        status_slot,
        rt: rt.clone(),
        tx: tx.clone(),
    }
}

impl ComplianceView {
    /// Rebuild the host picker from the current host list.
    pub fn set_hosts(&self, hosts: &[HostSummary]) {
        while let Some(c) = self.host_list.first_child() {
            self.host_list.remove(&c);
        }

        if hosts.is_empty() {
            let group = design::card("Hosts");
            let row = adw::ActionRow::new();
            row.set_title("No SSH hosts");
            row.set_subtitle("Add a host in the SSH section first — compliance runs over SSH.");
            group.add(&row);
            self.host_list.append(&group);
            return;
        }

        let group = design::card("Hosts");
        group.set_description(Some(
            "Seven read-only checks over SSH: sshd config, kernel core pattern, \
             automatic updates, journald and the host firewall.",
        ));
        for host in hosts {
            group.add(&self.host_row(host));
        }
        self.host_list.append(&group);
    }

    /// One host, with a Run-scan button when a baseline applies to it.
    fn host_row(&self, host: &HostSummary) -> adw::ActionRow {
        let row = adw::ActionRow::new();
        row.set_title(&host.label);
        let dispatch = host.device_type.compliance_dispatch();

        match dispatch {
            ComplianceDispatch::LinuxBaseline => {
                row.set_subtitle(&format!("{}@{}", host.username, host.hostname));
                let btn = gtk4::Button::with_label("Run scan");
                btn.add_css_class("suggested-action");
                btn.set_valign(gtk4::Align::Center);
                let rt = self.rt.clone();
                let tx = self.tx.clone();
                let host_id = host.id.to_string();
                btn.connect_clicked(move |b| {
                    // Seven SSH round-trips. Disabling the button is the only
                    // progress signal there is until the reply lands, and it
                    // also stops a second scan racing the first.
                    b.set_sensitive(false);
                    b.set_label("Scanning…");
                    let tx = tx.clone();
                    let host_id = host_id.clone();
                    rt.spawn(async move {
                        let outcome =
                            crate::dbus_client::dbus_compliance_run_linux(&host_id, "manual")
                                .await
                                .map_err(|e| format!("{e:#}"));
                        tx.send(AppMsg::ComplianceRunFinished {
                            host_id,
                            result: outcome,
                        })
                        .ok();
                    });
                });
                row.add_suffix(&btn);
            }
            ComplianceDispatch::FortigateBaseline => {
                // Deliberately shown rather than hidden. A FortiGate host that
                // simply vanished from this list reads as a bug in the list.
                row.set_subtitle(
                    "FortiGate baseline is not available on Linux yet — the daemon has no REST client for it.",
                );
                row.add_suffix(&design::badge("Not on Linux"));
            }
            ComplianceDispatch::NotApplicable => {
                row.set_subtitle("No CIS baseline exists for this device type.");
                row.add_suffix(&design::badge("N/A"));
            }
        }
        row
    }

    /// Render a finished or loaded run.
    ///
    /// `host_id` is carried so history rows can fetch a past run — a history
    /// list you cannot open is decoration.
    pub fn show_run(
        &self,
        host_id: &str,
        run: &ComplianceRun,
        library: &[CheckDefinition],
        history: &[RunSummary],
    ) {
        while let Some(c) = self.body.first_child() {
            self.body.remove(&c);
        }

        self.body.append(&Self::score_card(run));
        self.body.append(&Self::checks_card(run, library));
        if !history.is_empty() {
            self.body.append(&self.history_card(host_id, history));
        }
        self.stack.set_visible_child_name("body");
    }

    /// Show a message instead of a run.
    pub fn show_message(&self, icon: &str, title: &str, description: &str) {
        self.status_slot
            .set_child(Some(&design::empty_state(icon, title, description)));
        self.stack.set_visible_child_name("status");
    }

    fn score_card(run: &ComplianceRun) -> adw::PreferencesGroup {
        let card = design::card("Result");
        let row = adw::ActionRow::new();
        row.set_title(&format!("{}/100", run.score));
        row.set_subtitle(&format!(
            "{} passed · {} failed · {} errored · {} skipped",
            run.passed, run.failed, run.errored, run.skipped
        ));
        // Degraded rather than Error when something failed: the scan itself
        // succeeded. Error is reserved for "we could not tell", which is what
        // `errored` counts.
        let status = if run.errored > 0 {
            PillStatus::Degraded
        } else if run.failed > 0 {
            PillStatus::Error
        } else {
            PillStatus::Connected
        };
        row.add_prefix(&design::status_pill(status, &format!("{}", run.score)));
        card.add(&row);
        card
    }

    fn checks_card(run: &ComplianceRun, library: &[CheckDefinition]) -> adw::PreferencesGroup {
        let card = design::card("Checks");

        let mut ordered: Vec<&_> = run.checks.iter().collect();
        ordered.sort_by_key(|c| {
            let bucket = match c.status {
                Status::Fail => 0,
                Status::Error => 1,
                Status::Skip => 2,
                Status::Pass => 3,
            };
            (bucket, severity_rank(&c.severity), c.title.clone())
        });

        for check in ordered {
            let row = adw::ExpanderRow::new();
            row.set_title(&check.title);
            row.set_subtitle(&check.detail);
            let (pill, label) = match check.status {
                Status::Pass => (PillStatus::Connected, "Pass"),
                Status::Fail => (PillStatus::Error, "Fail"),
                Status::Error => (PillStatus::Degraded, "Error"),
                Status::Skip => (PillStatus::Unknown, "Skip"),
            };
            row.add_suffix(&design::status_pill(pill, label));

            // The library carries what the run does not: intent, the benchmark
            // section where one exists, and the fix.
            if let Some(def) = library.iter().find(|d| d.id == check.check_id) {
                if !def.description.is_empty() {
                    row.add_row(&detail_row("About", &def.description));
                }
                if let Some(cis) = &def.cis_reference {
                    row.add_row(&detail_row(
                        "Benchmark",
                        &format!("{} § {cis}", def.framework),
                    ));
                } else {
                    // Saying nothing here would read as "we forgot". The
                    // absence is a finding: see ssh_compliance::cis_reference.
                    row.add_row(&detail_row(
                        "Benchmark",
                        &format!("{} — no numbered control for this check", def.framework),
                    ));
                }
                if check.status == Status::Fail {
                    if let Some(fix) = &def.remediation {
                        row.add_row(&detail_row("Remediation", fix));
                    }
                }
            }
            if let Some(raw) = &check.raw_value {
                row.add_row(&detail_row("Observed", raw));
            }
            card.add(&row);
        }
        card
    }

    /// Previous runs, each openable. Clicking one loads it from disk rather
    /// than re-scanning — the point of history is to read what was true then,
    /// not to ask the host again.
    fn history_card(&self, host_id: &str, history: &[RunSummary]) -> adw::PreferencesGroup {
        let card = design::card("History");
        for summary in history.iter().take(10) {
            let row = adw::ActionRow::new();
            row.set_title(&summary.started_at.format("%Y-%m-%d %H:%M").to_string());
            row.set_subtitle(&format!(
                "{}/100 · {} failed · {}",
                summary.score,
                summary.failed,
                trigger_label(&summary.triggered_by)
            ));
            row.set_activatable(true);
            let rt = self.rt.clone();
            let tx = self.tx.clone();
            let host_id = host_id.to_owned();
            let run_id = summary.id.clone();
            row.connect_activated(move |_| {
                let tx = tx.clone();
                let host_id = host_id.clone();
                let run_id = run_id.clone();
                rt.spawn(async move {
                    let result =
                        crate::dbus_client::dbus_compliance_get_run(&host_id, &run_id)
                            .await
                            .map_err(|e| format!("{e:#}"));
                    // Same message as a fresh scan: from the page's point of
                    // view a loaded run and a new one render identically, and
                    // routing them through one path keeps it that way.
                    tx.send(AppMsg::ComplianceRunFinished { host_id, result }).ok();
                });
            });
            card.add(&row);
        }
        card
    }
}

/// A wrapping label row for long text — descriptions and remediation snippets
/// are sentences, not values, and truncating them defeats the point.
fn detail_row(label: &str, value: &str) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_title(label);
    let body = gtk4::Label::new(Some(value));
    body.set_wrap(true);
    body.set_xalign(0.0);
    body.set_selectable(true);
    body.add_css_class("dim-label");
    body.set_max_width_chars(60);
    row.add_suffix(&body);
    row
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn trigger_label(t: &supermgr_core::compliance::TriggerKind) -> &'static str {
    use supermgr_core::compliance::TriggerKind;
    match t {
        TriggerKind::Manual => "manual",
        TriggerKind::Scheduled => "scheduled",
        TriggerKind::PostDeploy => "after deploy",
    }
}

#[cfg(test)]
mod tests {
    use supermgr_core::compliance::Status;
    use supermgr_core::ssh::device_type::{ComplianceDispatch, DeviceType};

    /// The ordering key, lifted out so it can be checked without a display.
    fn bucket(status: &Status) -> u8 {
        match status {
            Status::Fail => 0,
            Status::Error => 1,
            Status::Skip => 2,
            Status::Pass => 3,
        }
    }

    #[test]
    fn failures_sort_above_everything_else() {
        // A passing control is a fact; a failing one is work. Twenty-two
        // passes above the one failure buries the only actionable row.
        assert!(bucket(&Status::Fail) < bucket(&Status::Pass));
        assert!(bucket(&Status::Fail) < bucket(&Status::Error));
        assert!(bucket(&Status::Fail) < bucket(&Status::Skip));
    }

    #[test]
    fn errors_outrank_skips_and_passes() {
        // "We could not tell" needs looking at; "not applicable" does not.
        assert!(bucket(&Status::Error) < bucket(&Status::Skip));
        assert!(bucket(&Status::Error) < bucket(&Status::Pass));
    }

    #[test]
    fn only_linux_hosts_get_a_scan_button() {
        // The page offers what the daemon can actually run. FortiGate needs a
        // REST client supermgrd does not have, so offering the button would
        // produce a failure the operator cannot act on.
        assert_eq!(
            DeviceType::Linux.compliance_dispatch(),
            ComplianceDispatch::LinuxBaseline
        );
        assert_eq!(
            DeviceType::Fortigate.compliance_dispatch(),
            ComplianceDispatch::FortigateBaseline
        );
        for dt in [DeviceType::UniFi, DeviceType::Windows, DeviceType::Custom] {
            assert_eq!(dt.compliance_dispatch(), ComplianceDispatch::NotApplicable);
        }
    }
}
