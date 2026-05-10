//! Unified activity timeline per customer.
//!
//! Today, evidence of "what we did for this customer" is scattered:
//!   - Engagement audit log (passive/active scan events)
//!   - Provisioning deployment history (config pushes)
//!   - Compliance scan history (per-host pass/fail)
//!   - Findings store changes (disposition transitions)
//!
//! This module is the aggregator. It walks the four sources and
//! produces a single sorted feed `Vec<ActivityEvent>` that the
//! UI renders as one chronological customer-portfolio timeline.
//!
//! # Source-of-truth
//!
//! We don't write to a separate timeline file — that would
//! introduce dual-write hazards. Instead, on every read, we
//! pull from the existing per-feature stores and merge. Cost is
//! negligible (a typical customer has <500 events/year and each
//! source is a small JSON/TOML file).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub at: chrono::DateTime<chrono::Utc>,
    pub kind: ActivityKind,
    pub title: String,
    pub detail: String,
    /// Optional short identifier of the host / engagement /
    /// finding the event refers to. UI uses this to deep-link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    PassiveScan,
    ActiveScan,
    ComplianceRun,
    Deploy,
    DispositionChange,
    DnsAudit,
    Finding,
    Misc,
}

/// Build a unified timeline for `customer_slug`. Returns events
/// sorted newest-first, capped at `limit` so the UI doesn't have
/// to handle paging.
pub fn timeline(customer_slug: &str, limit: usize) -> Vec<ActivityEvent> {
    let mut out: Vec<ActivityEvent> = Vec::new();

    out.extend(from_engagements(customer_slug));
    out.extend(from_findings_store(customer_slug));

    // Sort newest first.
    out.sort_by(|a, b| b.at.cmp(&a.at));
    out.truncate(limit);
    out
}

/// Pull events from every engagement that's tied to this customer.
/// Engagements own their own audit logs; we just transcribe each
/// log entry to the unified `ActivityEvent` shape.
fn from_engagements(customer_slug: &str) -> Vec<ActivityEvent> {
    let Ok(list) = crate::engagement::list_all() else {
        return Vec::new();
    };
    let mut out: Vec<ActivityEvent> = Vec::new();
    for e in list {
        if e.customer_slug != customer_slug {
            continue;
        }
        for ev in &e.log {
            let kind = match ev.action.as_str() {
                "passive_scan" => ActivityKind::PassiveScan,
                "active_scan" => ActivityKind::ActiveScan,
                "compliance_run" => ActivityKind::ComplianceRun,
                _ => ActivityKind::Misc,
            };
            out.push(ActivityEvent {
                at: ev.at,
                kind,
                title: format!("{} — {}", e.title, ev.action.replace('_', " ")),
                detail: ev.notes.clone(),
                ref_id: Some(e.id.clone()),
            });
        }
    }
    out
}

/// Surface the most-recent disposition change on every finding
/// in the customer's findings_store. The history was previously
/// only visible inside the FindingDetailSheet — now operators
/// can see "we accepted CVE-X 30 days ago" at the customer level.
fn from_findings_store(customer_slug: &str) -> Vec<ActivityEvent> {
    let Ok(findings) = crate::findings_store::list_findings(customer_slug) else {
        return Vec::new();
    };
    let mut out: Vec<ActivityEvent> = Vec::new();
    for f in findings {
        // First-detection event.
        out.push(ActivityEvent {
            at: f.first_seen,
            kind: ActivityKind::Finding,
            title: format!("Finding: {}", f.finding.title),
            detail: format!(
                "First detected on {}{}",
                f.finding.host_ip,
                f.finding
                    .port
                    .map(|p| format!(":{p}"))
                    .unwrap_or_default()
            ),
            ref_id: Some(f.key.clone()),
        });
        // Each disposition transition.
        for change in &f.history {
            out.push(ActivityEvent {
                at: change.at,
                kind: ActivityKind::DispositionChange,
                title: format!(
                    "{}: {} → {}",
                    f.finding.title,
                    change.from.label(),
                    change.to.label()
                ),
                detail: change.note.clone(),
                ref_id: Some(f.key.clone()),
            });
        }
    }
    out
}
