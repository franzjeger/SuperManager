//! Security page — the findings store, with triage.
//!
//! # What fills this page
//!
//! Compliance failures. `supermgrd` files them after every Linux baseline run:
//! a failed control becomes a [`PersistedFinding`] with a first-seen date, a
//! scan count and a disposition. That is the whole difference between this page
//! and the Compliance page — a run tells you what failed *this time*, a finding
//! tracks a problem over time and lets an operator accept it as a known risk.
//!
//! Not the port scanner. `vuln::analyse_host` needs the port prober and the five
//! recon enumerators behind it, none of which the Linux daemon has. Findings
//! from compliance are a source it already has, which is why this page can exist
//! before that port is done. When the scanner arrives its findings land in the
//! same store and render here with no change to this file.
//!
//! # Scope
//!
//! Inventory labels are merged with persisted scopes reported by the daemon.
//! Archived findings remain accessible after a host is removed or retagged.
//! Both writer and picker use the shared scope resolver.
//!
//! # Order
//!
//! Open findings first, by descending severity; then everything dispositioned.
//! A store with two criticals and forty accepted risks should not open on the
//! forty. Same reasoning as the Compliance page putting failures above passes.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::mpsc;

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use supermgr_core::findings_store::{Disposition, PersistedFinding, StoreSummary};
use supermgr_core::host::HostSummary;
use supermgr_core::severity::Severity;

use crate::app::AppMsg;
use crate::ui::design::{self, Status as PillStatus};

/// Everything the page needs to re-render without being rebuilt.
pub struct SecurityView {
    /// Root widget, handed to the view stack.
    pub widget: gtk4::Widget,
    /// Scope picker. Rebuilt when the host list changes.
    scope_picker: adw::ComboRow,
    scopes: Rc<RefCell<Vec<(String, String)>>>,
    inventory_scopes: RefCell<Vec<(String, String)>>,
    saved_scopes: RefCell<Vec<String>>,
    /// Summary + findings for the selected scope.
    body: gtk4::Box,
    /// Swaps between the body and a full-page status.
    stack: gtk4::Stack,
    /// Full-page status for "pick a scope" and error cases.
    status_slot: adw::Bin,
    /// Scope currently shown, so a disposition change can reload it.
    current_scope: RefCell<Option<String>>,
    requested_scope: Rc<RefCell<Option<String>>>,
    /// Runtime the D-Bus calls are spawned on.
    rt: tokio::runtime::Handle,
    /// Where those calls report back to.
    tx: mpsc::Sender<AppMsg>,
}

/// Build the page. Starts asking the operator to pick a scope.
#[must_use]
pub fn build_security_page(rt: &tokio::runtime::Handle, tx: &mpsc::Sender<AppMsg>) -> SecurityView {
    let (scroller, content) = design::workspace_body(
        "Security",
        "Investigate findings, track decisions and keep customer history accessible.",
    );
    let scopes: Rc<RefCell<Vec<(String, String)>>> = Rc::new(RefCell::new(vec![]));
    let requested_scope = Rc::new(RefCell::new(None));
    let scope_picker = adw::ComboRow::builder()
        .title("Customer or host")
        .subtitle("Includes archived scopes with saved findings")
        .model(&gtk4::StringList::new(&[]))
        .build();
    let open = gtk4::Button::builder()
        .label("Open findings")
        .valign(gtk4::Align::Center)
        .css_classes(["suggested-action"])
        .build();
    scope_picker.add_suffix(&open);
    let scope_group = design::card("");
    scope_group.add(&scope_picker);
    content.append(&scope_group);
    {
        let scopes = Rc::clone(&scopes);
        let picker = scope_picker.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        let requested = Rc::clone(&requested_scope);
        open.connect_clicked(move |_| {
            if let Some((scope, _)) = scopes.borrow().get(picker.selected() as usize) {
                *requested.borrow_mut() = Some(scope.clone());
                load_scope(&rt, &tx, scope.clone());
            }
        });
    }

    let body = gtk4::Box::new(gtk4::Orientation::Vertical, 12);

    let status_slot = adw::Bin::new();
    status_slot.set_child(Some(&design::empty_state(
        design::icon_name(design::icons::SHIELD),
        "No scope selected",
        "Pick a customer or host to see its findings. Findings are filed by the \
         daemon after each compliance scan.",
    )));

    let stack = gtk4::Stack::new();
    stack.add_named(&body, Some("body"));
    stack.add_named(&status_slot, Some("status"));
    stack.set_visible_child_name("status");
    content.append(&stack);

    SecurityView {
        widget: scroller.upcast(),
        scope_picker,
        scopes,
        inventory_scopes: RefCell::new(vec![]),
        saved_scopes: RefCell::new(vec![]),
        body,
        stack,
        status_slot,
        current_scope: RefCell::new(None),
        requested_scope,
        rt: rt.clone(),
        tx: tx.clone(),
    }
}

impl SecurityView {
    pub fn accepts_result(&self, scope: &str) -> bool {
        self.requested_scope
            .borrow()
            .as_deref()
            .is_none_or(|expected| expected == scope)
    }

    /// Refresh inventory labels and independently discover persisted scopes.
    pub fn set_hosts(&self, hosts: &[HostSummary]) {
        *self.inventory_scopes.borrow_mut() = hosts
            .iter()
            .map(|host| {
                let scope =
                    supermgr_core::findings_store::scope_for_customer(&host.customer, &host.id);
                let label = if scope == host.customer.trim() {
                    host.customer.clone()
                } else {
                    host.label.clone()
                };
                (scope, label)
            })
            .collect();
        self.update_scope_picker();
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            tx.send(AppMsg::FindingsScopesLoaded(
                crate::dbus_client::dbus_findings_scopes()
                    .await
                    .map_err(|e| e.to_string()),
            ))
            .ok();
        });
    }

    pub fn set_saved_scopes(&self, scopes: Vec<String>) {
        *self.saved_scopes.borrow_mut() = scopes;
        self.update_scope_picker();
    }

    fn update_scope_picker(&self) {
        let selected = self
            .scopes
            .borrow()
            .get(self.scope_picker.selected() as usize)
            .map(|s| s.0.clone());
        let mut options: BTreeMap<String, String> = self
            .saved_scopes
            .borrow()
            .iter()
            .map(|scope| (scope.clone(), format!("{scope} · archived")))
            .collect();
        options.extend(self.inventory_scopes.borrow().iter().cloned());
        let mut options: Vec<_> = options.into_iter().collect();
        options.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
        let model =
            gtk4::StringList::new(&options.iter().map(|x| x.1.as_str()).collect::<Vec<_>>());
        let index = options
            .iter()
            .position(|x| Some(&x.0) == selected.as_ref())
            .unwrap_or(0);
        *self.scopes.borrow_mut() = options;
        self.scope_picker.set_model(Some(&model));
        self.scope_picker.set_selected(index as u32);
        self.scope_picker.set_sensitive(model.n_items() > 0);
    }

    /// Render a loaded scope.
    pub fn show_findings(
        &self,
        scope: &str,
        summary: &StoreSummary,
        findings: &[PersistedFinding],
    ) {
        *self.current_scope.borrow_mut() = Some(scope.to_owned());

        while let Some(c) = self.body.first_child() {
            self.body.remove(&c);
        }
        self.body.append(&Self::summary_card(scope, summary));

        if findings.is_empty() {
            let group = design::card("Findings");
            let row = adw::ActionRow::new();
            row.set_title("Nothing recorded");
            row.set_subtitle(
                "No findings for this scope. Run a compliance scan on one of its hosts \
                 to populate it.",
            );
            group.add(&row);
            self.body.append(&group);
        } else {
            self.body.append(&self.findings_card(scope, findings));
        }
        self.stack.set_visible_child_name("body");
    }

    /// Show a message instead of findings.
    pub fn show_message(&self, icon: &str, title: &str, description: &str) {
        self.status_slot
            .set_child(Some(&design::empty_state(icon, title, description)));
        self.stack.set_visible_child_name("status");
    }

    /// Reload whatever scope is on screen. Used after a disposition change so
    /// the row reflects what the daemon actually stored rather than what the
    /// widget hoped it stored.
    pub fn reload_current(&self) {
        let Some(scope) = self.current_scope.borrow().clone() else {
            return;
        };
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let result = async {
                let summary = crate::dbus_client::dbus_findings_summary(&scope).await?;
                let findings = crate::dbus_client::dbus_findings_list(&scope).await?;
                Ok::<_, anyhow::Error>((summary, findings))
            }
            .await
            .map_err(|e| format!("{e:#}"));
            tx.send(AppMsg::FindingsLoaded { scope, result }).ok();
        });
    }

    /// Counts, with the open ones given the prominence.
    fn summary_card(scope: &str, s: &StoreSummary) -> adw::PreferencesGroup {
        let group = design::card("Summary");
        group.set_description(Some(&format!("Scope: {scope}")));

        let open_row = adw::ActionRow::new();
        open_row.set_title("Open");
        open_row.set_subtitle(&format!(
            "{} critical · {} high · {} medium · {} low · {} info",
            s.critical, s.high, s.medium, s.low, s.info
        ));
        // The pill reflects the worst open severity, because that is the number
        // that decides whether this scope needs attention today.
        //
        // `design::Status` is named for VPN states, which is where it came from.
        // The mapping used across this page: `Error` is the red one, `Degraded`
        // the amber, `Connected` the green, `Disconnected` the deliberate-and-
        // not-a-fault grey, `Unknown` the nothing-known grey.
        let (status, label) = if s.critical > 0 {
            (PillStatus::Error, format!("{} critical", s.critical))
        } else if s.high > 0 {
            (PillStatus::Error, format!("{} high", s.high))
        } else if s.open > 0 {
            (PillStatus::Degraded, format!("{} open", s.open))
        } else if s.last_scan_at.is_none() {
            (PillStatus::Unknown, "not scanned".to_owned())
        } else {
            (PillStatus::Disconnected, "no open findings".to_owned())
        };
        open_row.add_suffix(&design::status_pill(status, &label));
        group.add(&open_row);

        let other = adw::ActionRow::new();
        other.set_title("Dispositioned");
        other.set_subtitle(&format!(
            "{} accepted risk · {} fixed · {} false positive",
            s.accepted_risk, s.fixed, s.false_positive
        ));
        other.add_suffix(&design::badge(&format!("{} total", s.total)));
        group.add(&other);

        if let Some(at) = s.last_scan_at {
            let row = adw::ActionRow::new();
            row.set_title("Last reconciled");
            row.set_subtitle(&at.format("%Y-%m-%d %H:%M UTC").to_string());
            group.add(&row);
        }
        group
    }

    /// The findings themselves, open and worst first.
    fn findings_card(&self, scope: &str, findings: &[PersistedFinding]) -> adw::PreferencesGroup {
        let group = design::card("Findings");

        let mut sorted: Vec<&PersistedFinding> = findings.iter().collect();
        sorted.sort_by_key(|f| {
            (
                // Open before dispositioned.
                u8::from(!matches!(f.disposition, Disposition::Open)),
                // Then worst severity first.
                severity_rank(f.finding.severity),
                // Then stable, so repeated loads do not reshuffle equal rows.
                f.key.clone(),
            )
        });

        let rows: Rc<Vec<_>> = Rc::new(
            sorted
                .into_iter()
                .map(|f| {
                    let row = self.finding_row(scope, f);
                    group.add(&row);
                    (row, f.clone())
                })
                .collect(),
        );
        let search = gtk4::SearchEntry::builder()
            .placeholder_text("Search findings or hosts")
            .hexpand(true)
            .build();
        let filter = gtk4::DropDown::from_strings(&[
            "All findings",
            "Open",
            "High / critical",
            "Accepted risk",
            "Fixed",
        ]);
        let controls = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
        controls.append(&search);
        controls.append(&filter);
        let apply = {
            let rows = Rc::clone(&rows);
            let search = search.clone();
            let filter = filter.clone();
            Rc::new(move || {
                for (row, finding) in rows.iter() {
                    row.set_visible(matches_finding(finding, &search.text(), filter.selected()));
                }
            })
        };
        {
            let apply = Rc::clone(&apply);
            search.connect_search_changed(move |_| apply());
        }
        filter.connect_selected_notify(move |_| apply());
        self.body.append(&controls);
        let export = gtk4::Button::with_label("Export JSON");
        let data =
            serde_json::json!({"scope":scope,"exported_at":chrono::Utc::now(),"findings":findings});
        let tx = self.tx.clone();
        let widget = self.widget.clone();
        export.connect_clicked(move |_| {
            let parent = widget.root().and_downcast::<gtk4::Window>();
            design::export_json(parent.as_ref(), "security-findings.json", &data, &tx);
        });
        group.set_header_suffix(Some(&export));
        group
    }

    /// One finding: what it is, since when, and what an operator can do about it.
    fn finding_row(&self, scope: &str, f: &PersistedFinding) -> adw::ExpanderRow {
        let row = adw::ExpanderRow::new();
        row.set_title(&f.finding.title);
        row.set_subtitle(&format!(
            "{} · seen {}× since {}",
            f.finding.host_ip,
            f.scan_count,
            f.first_seen.format("%Y-%m-%d")
        ));

        let (pill, label) = match &f.disposition {
            Disposition::Open => (
                severity_pill(f.finding.severity),
                severity_label(f.finding.severity),
            ),
            // Accepted risk stays amber: it is a live problem someone chose to
            // live with, not a solved one, and colouring it green would lose
            // that distinction on the only screen that shows it.
            Disposition::AcceptedRisk { .. } => (PillStatus::Degraded, "accepted".to_owned()),
            Disposition::Fixed { .. } => (PillStatus::Connected, "fixed".to_owned()),
            Disposition::FalsePositive { .. } => {
                (PillStatus::Disconnected, "false positive".to_owned())
            }
        };
        row.add_suffix(&design::status_pill(pill, &label));

        // Detail carries the observed value the check actually read, which is
        // what makes the finding actionable without re-running the scan.
        let detail = adw::ActionRow::new();
        detail.set_title("Detail");
        detail.set_subtitle(&f.finding.detail);
        detail.set_subtitle_lines(0);
        row.add_row(&detail);

        let rec = adw::ActionRow::new();
        rec.set_title("Remediation");
        rec.set_subtitle(&f.finding.recommendation);
        rec.set_subtitle_lines(0);
        row.add_row(&rec);

        if let Some(cve) = &f.finding.cve {
            let r = adw::ActionRow::new();
            r.set_title("CVE");
            r.set_subtitle(cve);
            row.add_row(&r);
        }

        // The audit trail, shown rather than hidden: "who accepted this risk and
        // when" is the question this data exists to answer.
        for change in &f.history {
            let r = adw::ActionRow::new();
            r.set_title(&format!("{} → {}", change.from.label(), change.to.label()));
            let mut sub = format!("{} by {}", change.at.format("%Y-%m-%d %H:%M"), change.by);
            if !change.note.trim().is_empty() {
                sub.push_str(" — ");
                sub.push_str(&change.note);
            }
            r.set_subtitle(&sub);
            row.add_row(&r);
        }

        row.add_row(&self.actions_row(scope, f));
        row
    }

    /// Triage buttons. Which ones appear depends on where the finding already is.
    fn actions_row(&self, scope: &str, f: &PersistedFinding) -> adw::ActionRow {
        let row = adw::ActionRow::new();
        row.set_title("Triage");

        let bar = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
        bar.set_valign(gtk4::Align::Center);

        // An open finding can be accepted or dismissed; anything already
        // dispositioned can only be reopened. Offering "accept" on an accepted
        // finding would be a button that does nothing visible.
        if matches!(f.disposition, Disposition::Open) {
            bar.append(&self.action_button(
                scope,
                &f.key,
                "Accept risk",
                Disposition::AcceptedRisk {
                    reason: "Accepted from the Security page".to_owned(),
                    until: None,
                },
            ));
            bar.append(&self.action_button(
                scope,
                &f.key,
                "False positive",
                Disposition::FalsePositive {
                    reason: "Marked from the Security page".to_owned(),
                },
            ));
        } else {
            bar.append(&self.action_button(scope, &f.key, "Reopen", Disposition::Open));
        }

        row.add_suffix(&bar);
        row
    }

    /// One triage button, wired to `FindingsSetDisposition`.
    fn action_button(
        &self,
        scope: &str,
        key: &str,
        label: &str,
        disposition: Disposition,
    ) -> gtk4::Button {
        let btn = gtk4::Button::with_label(label);
        btn.set_valign(gtk4::Align::Center);
        let rt = self.rt.clone();
        let tx = self.tx.clone();
        let scope = scope.to_owned();
        let key = key.to_owned();
        btn.connect_clicked(move |b| {
            // Disabled while in flight: the reply reloads the whole scope, and a
            // second click before it lands would file a second history entry for
            // a state the operator only chose once.
            b.set_sensitive(false);
            let tx = tx.clone();
            let scope = scope.clone();
            let key = key.clone();
            let disposition = disposition.clone();
            rt.spawn(async move {
                let result = crate::dbus_client::dbus_findings_set_disposition(
                    &scope,
                    &key,
                    &disposition,
                    "",
                )
                .await
                .map(|_| ())
                .map_err(|e| format!("{e:#}"));
                tx.send(AppMsg::FindingDispositionSet { scope, result })
                    .ok();
            });
        });
        btn
    }
}

/// Sort key: worst first.
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

/// Pill colour for an open finding's severity.
fn severity_pill(s: Severity) -> PillStatus {
    match s {
        Severity::Critical | Severity::High => PillStatus::Error,
        Severity::Medium | Severity::Low => PillStatus::Degraded,
        Severity::Info => PillStatus::Unknown,
    }
}

/// Pill text for an open finding's severity.
fn severity_label(s: Severity) -> String {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn finding_search_combines_case_insensitive_text_and_triage_filters() {
        let mut finding: PersistedFinding = serde_json::from_value(serde_json::json!({
            "key":"fixture", "disposition":{"kind":"open"},
            "first_seen":"2026-09-01T10:00:00Z","last_seen":"2026-09-09T12:00:00Z","scan_count":1,
            "finding":{"id":"fixture","host_ip":"WEB01","severity":"high",
                "title":"Root login","detail":"PermitRootLogin yes","recommendation":"Review access"}
        })).unwrap();
        assert!(matches_finding(&finding, " web01 ", 2));
        assert!(matches_finding(&finding, "permitrootlogin", 1));
        assert!(!matches_finding(&finding, "web02", 0));
        finding.disposition = Disposition::AcceptedRisk {
            reason: "Reviewed".into(),
            until: None,
        };
        assert!(!matches_finding(&finding, "", 2));
        assert!(matches_finding(&finding, "ROOT", 3));
        assert!(!matches_finding(&finding, "", 4));
    }

    #[test]
    fn severity_ranks_worst_first() {
        // The page's whole ordering promise. A transposed pair here buries a
        // critical under a pile of info rows.
        let mut all = vec![
            Severity::Info,
            Severity::Critical,
            Severity::Low,
            Severity::High,
            Severity::Medium,
        ];
        all.sort_by_key(|s| severity_rank(*s));
        assert_eq!(
            all,
            [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info
            ]
        );
    }

    #[test]
    fn every_severity_has_a_distinct_rank() {
        let ranks: BTreeSet<u8> = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ]
        .iter()
        .map(|s| severity_rank(*s))
        .collect();
        assert_eq!(
            ranks.len(),
            5,
            "two severities sharing a rank sort at random"
        );
    }

    #[test]
    fn only_the_top_two_severities_read_as_an_error() {
        // The pill is what an operator scans for. Making everything red means
        // nothing is red.
        assert!(matches!(
            severity_pill(Severity::Critical),
            PillStatus::Error
        ));
        assert!(matches!(severity_pill(Severity::High), PillStatus::Error));
        assert!(!matches!(
            severity_pill(Severity::Medium),
            PillStatus::Error
        ));
        assert!(!matches!(severity_pill(Severity::Info), PillStatus::Error));
    }
}

fn load_scope(rt: &tokio::runtime::Handle, tx: &mpsc::Sender<AppMsg>, scope: String) {
    let tx = tx.clone();
    rt.spawn(async move {
        let result = async {
            Ok::<_, anyhow::Error>((
                crate::dbus_client::dbus_findings_summary(&scope).await?,
                crate::dbus_client::dbus_findings_list(&scope).await?,
            ))
        }
        .await
        .map_err(|e| e.to_string());
        tx.send(AppMsg::FindingsLoaded { scope, result }).ok();
    });
}

fn matches_finding(f: &PersistedFinding, query: &str, filter: u32) -> bool {
    let status = match filter {
        1 => matches!(f.disposition, Disposition::Open),
        2 => {
            matches!(f.disposition, Disposition::Open)
                && matches!(f.finding.severity, Severity::High | Severity::Critical)
        }
        3 => matches!(f.disposition, Disposition::AcceptedRisk { .. }),
        4 => matches!(f.disposition, Disposition::Fixed { .. }),
        _ => true,
    };
    status
        && format!(
            "{} {} {}",
            f.finding.title, f.finding.host_ip, f.finding.detail
        )
        .to_lowercase()
        .contains(&query.trim().to_lowercase())
}
