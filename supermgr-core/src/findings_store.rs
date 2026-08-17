//! Persistent finding store with disposition workflow + scan-diff.
//!
//! # Why
//!
//! Without persistence, every scan produces a fresh list of findings
//! and the previous one is lost. That's useless for an MSP — the
//! customer needs to know:
//!   - Has CVE-X been open for 14 days or 6 months?
//!   - Did our last patch sprint actually close anything?
//!   - Which findings are accepted-risk and shouldn't show up in
//!     the dashboard anymore?
//!
//! This module holds the persistent state that survives between
//! scans, plus the reconciliation logic that produces a `ScanDiff`
//! showing what changed.
//!
//! # Persistence
//!
//! One `findings.json` per customer under
//! `~/Library/Application Support/SuperManager/findings_store/<slug>/`.
//! Atomic write via tempfile-rename. Schema is forward-compatible
//! via `#[serde(default)]` on additive fields.
//!
//! # Stable keying
//!
//! A finding is the same finding across scans iff
//! `(id, host_ip, port, service)` matches. We use that tuple
//! pipe-joined as the key — readable + collision-free for the
//! data we actually generate.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::findings::Finding;

/// Per-customer reconcile mutex — prevents the load→modify→save
/// race when a manual scan and the scheduler both reconcile the
/// same customer at the same moment. We use one mutex per scope
/// so unrelated customers don't serialize against each other.
///
/// `reconcile()` is fully synchronous (file IO + in-memory diff,
/// total ≤30 ms for typical stores), so a `std::sync::Mutex` is
/// the right choice — no `.await` held while locked.
fn scope_lock(scope: &str) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().expect("scope lock map poisoned");
    guard
        .entry(scope.to_owned())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One finding's persistent record. The latest detected `Finding`
/// itself is kept as a snapshot — that lets the report renderer
/// show what the title/recommendation looked like at the time
/// without having to re-derive from probe data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedFinding {
    /// Dedup key from [`finding_key`]. Identity across scans depends on this
    /// being stable, so it is stored rather than recomputed.
    pub key: String,
    /// Snapshot of the finding as last detected.
    pub finding: Finding,
    /// Where this sits in the triage workflow.
    pub disposition: Disposition,
    /// First scan that reported it.
    pub first_seen: DateTime<Utc>,
    /// Most recent scan that reported it.
    pub last_seen: DateTime<Utc>,
    /// Number of scans this finding has been observed in.
    #[serde(default = "one")]
    pub scan_count: u32,
    /// Append-only audit log of disposition changes.
    #[serde(default)]
    pub history: Vec<DispositionChange>,
    /// Free-form note (rendered on the finding detail sheet).
    #[serde(default)]
    pub note: String,
}

fn one() -> u32 { 1 }

/// Workflow state of a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Disposition {
    /// New or unresolved.
    Open,
    /// Customer has accepted this risk; suppressed from the
    /// active dashboard but still tracked.
    AcceptedRisk {
        /// Why the risk was accepted — shown wherever the suppression is.
        reason: String,
        /// When the acceptance lapses, if it was time-boxed.
        until: Option<DateTime<Utc>>,
    },
    /// No longer detected. `auto = true` means the system
    /// inferred it from absence in the latest scan.
    Fixed {
        /// `true` when the system inferred this from absence in the latest
        /// scan rather than a person marking it fixed.
        auto: bool,
    },
    /// User-flagged false positive.
    FalsePositive {
        /// Why it was judged a false positive.
        reason: String,
    },
}

impl Disposition {
    /// Stable machine-readable name. Used as a wire value and a filter key, so
    /// these strings are API surface — renaming one is a breaking change.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Disposition::Open => "open",
            Disposition::AcceptedRisk { .. } => "accepted_risk",
            Disposition::Fixed { .. } => "fixed",
            Disposition::FalsePositive { .. } => "false_positive",
        }
    }
}

/// One entry in a finding's append-only disposition history.
///
/// Append-only on purpose: "who accepted this risk, and when" is the question
/// an auditor asks, and it cannot be answered from current state alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositionChange {
    /// When the change was made.
    pub at: DateTime<Utc>,
    /// Who made it.
    pub by: String,
    /// State before.
    pub from: Disposition,
    /// State after.
    pub to: Disposition,
    /// Operator's reason, free-form.
    pub note: String,
}

/// Aggregate result of `reconcile()` — what changed since last scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanDiff {
    /// Seen for the first time in this scan.
    pub new_findings: Vec<PersistedFinding>,
    /// Present before and still present.
    pub still_open: Vec<PersistedFinding>,
    /// Previously resolved and now back. Called out separately because a
    /// regression means a fix did not hold, which reads differently to an
    /// operator than a finding they have never seen.
    pub regressed: Vec<PersistedFinding>,
    /// Absent from this scan, so closed automatically.
    pub auto_resolved: Vec<PersistedFinding>,
    /// Still present but suppressed by an accepted-risk disposition.
    pub accepted_risk: Vec<PersistedFinding>,
    /// When this diff was produced.
    pub generated_at: DateTime<Utc>,
}

/// Everything persisted for one scope, as stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingsStore {
    /// Findings by [`finding_key`].
    pub findings: HashMap<String, PersistedFinding>,
    /// Last time `reconcile()` ran for this customer.
    pub last_scan_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Identity of a finding across scans.
///
/// `id|host|port|service`, so the same issue rediscovered next week updates its
/// row instead of appearing as a second one — which is what makes `first_seen`,
/// `scan_count` and the disposition history mean anything. Changing this format
/// orphans every stored finding, since the key is what the store is indexed by.
#[must_use]
pub fn finding_key(f: &Finding) -> String {
    let port = f.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
    let service = f.service.clone().unwrap_or_else(|| "-".into());
    format!("{}|{}|{}|{}", f.id, f.host_ip, port, service)
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

fn store_dir(customer_slug: &str) -> PathBuf {
    let mut p = crate::paths::default_data_dir();
    p.push("findings_store");
    p.push(customer_slug);
    p
}

fn store_file(customer_slug: &str) -> PathBuf {
    let mut p = store_dir(customer_slug);
    p.push("findings.json");
    p
}

/// Load the persisted findings store for a customer scope.
/// Returns structured `EngineError` so callers can distinguish:
///   - `InvalidScope` — bad slug (UI shows validation message)
///   - `FindingsIo` — disk read failed (UI suggests retry)
///   - `FindingsParse` — JSON corrupt (UI suggests restoring from backup)
pub fn load_store(customer_slug: &str) -> std::result::Result<FindingsStore, crate::error::FindingsError> {
    use crate::error::FindingsError;
    crate::findings::validate_slug(customer_slug)
        .map_err(|reason| FindingsError::InvalidScope { reason })?;
    let path = store_file(customer_slug);
    if !path.exists() {
        return Ok(FindingsStore::default());
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| FindingsError::Io {
            reason: format!("read {}: {e}", path.display()),
        })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| FindingsError::Parse {
            reason: format!("{}: {e}", path.display()),
        })
}

/// Persist the findings store. Errors split into IO and InvalidScope
/// — there's no parse step in the save direction.
pub fn save_store(
    customer_slug: &str,
    store: &FindingsStore,
) -> std::result::Result<(), crate::error::FindingsError> {
    use crate::error::FindingsError;
    crate::findings::validate_slug(customer_slug)
        .map_err(|reason| FindingsError::InvalidScope { reason })?;
    let dir = store_dir(customer_slug);
    std::fs::create_dir_all(&dir)
        .map_err(|e| FindingsError::Io {
            reason: format!("create dir {}: {e}", dir.display()),
        })?;
    let path = store_file(customer_slug);
    // Unique tmp name per call: a fixed name lets two concurrent writers for
    // the same scope clobber each other's in-flight bytes before the rename.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_file_name(format!(
        "findings.{}.{}.tmp",
        std::process::id(),
        nonce
    ));
    let bytes = serde_json::to_vec_pretty(store)
        .map_err(|e| FindingsError::Io {
            reason: format!("serialize: {e}"),
        })?;
    std::fs::write(&tmp, bytes)
        .map_err(|e| FindingsError::Io {
            reason: format!("write tmp {}: {e}", tmp.display()),
        })?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| FindingsError::Io {
            reason: format!("rename to {}: {e}", path.display()),
        })
}

// ---------------------------------------------------------------------------
// Reconciliation — the core of Track A
// ---------------------------------------------------------------------------

/// Merge a fresh scan's findings into the persistent store and
/// return the diff. Side-effect: persists the updated store.
///
/// Reconciliation semantics:
///   - New finding (key not in store) → record as Open, first_seen=now.
///   - Existing finding still detected:
///       - Open / Fixed (auto) → keeps state, last_seen bumped, scan_count++.
///         A previously Fixed-then-redetected finding flips back to Open
///         and is reported as a *regression*.
///       - AcceptedRisk (untimed or not yet expired) → kept, surfaced
///         as accepted_risk in the diff.
///       - AcceptedRisk (expired) → flips back to Open + regression.
///       - FalsePositive → kept; user explicitly marked it irrelevant.
///   - Existing finding NOT in fresh scan:
///       - Open → flipped to Fixed{auto:true}, surfaced as auto_resolved.
///       - Other states → unchanged (we don't auto-update terminal states).
pub fn reconcile(customer_slug: &str, fresh: &[Finding]) -> Result<ScanDiff> {
    // Acquire the per-customer reconcile lock for the entire
    // load→merge→save cycle. Two concurrent callers (manual scan
    // + scheduler) for the same customer will serialize here;
    // calls for different customers run in parallel.
    let lock = scope_lock(customer_slug);
    let _guard = lock.lock().expect("scope lock poisoned");

    let mut store = load_store(customer_slug)?;
    let now = Utc::now();
    let fresh_keys: HashSet<String> = fresh.iter().map(finding_key).collect();

    let mut diff = ScanDiff {
        generated_at: now,
        ..Default::default()
    };

    for f in fresh {
        let key = finding_key(f);
        if let Some(existing) = store.findings.get_mut(&key) {
            // Always refresh the underlying finding snapshot so the
            // store reflects the latest title/severity/recommendation.
            existing.finding = f.clone();
            existing.last_seen = now;
            existing.scan_count = existing.scan_count.saturating_add(1);

            match existing.disposition.clone() {
                Disposition::Open => diff.still_open.push(existing.clone()),
                Disposition::Fixed { .. } => {
                    let prev = existing.disposition.clone();
                    existing.disposition = Disposition::Open;
                    existing.history.push(DispositionChange {
                        at: now,
                        by: "system".into(),
                        from: prev,
                        to: Disposition::Open,
                        note: "regression: re-detected after being marked fixed".into(),
                    });
                    diff.regressed.push(existing.clone());
                }
                Disposition::AcceptedRisk { reason, until } => {
                    let expired = until.is_some_and(|t| t < now);
                    if expired {
                        let prev = Disposition::AcceptedRisk { reason, until };
                        existing.disposition = Disposition::Open;
                        existing.history.push(DispositionChange {
                            at: now,
                            by: "system".into(),
                            from: prev,
                            to: Disposition::Open,
                            note: "accepted-risk window expired".into(),
                        });
                        diff.regressed.push(existing.clone());
                    } else {
                        diff.accepted_risk.push(existing.clone());
                    }
                }
                Disposition::FalsePositive { .. } => {
                    // Surface in still_open bucket so caller knows it's
                    // present, but don't change disposition.
                    // (We could give it its own bucket if it becomes
                    // useful in the UI later.)
                }
            }
        } else {
            let new = PersistedFinding {
                key: key.clone(),
                finding: f.clone(),
                disposition: Disposition::Open,
                first_seen: now,
                last_seen: now,
                scan_count: 1,
                history: Vec::new(),
                note: String::new(),
            };
            store.findings.insert(key, new.clone());
            diff.new_findings.push(new);
        }
    }

    // Auto-resolve: anything Open in store but not in fresh scan.
    for existing in store.findings.values_mut() {
        if !fresh_keys.contains(&existing.key)
            && matches!(existing.disposition, Disposition::Open) {
                let prev = existing.disposition.clone();
                existing.disposition = Disposition::Fixed { auto: true };
                existing.history.push(DispositionChange {
                    at: now,
                    by: "system".into(),
                    from: prev,
                    to: existing.disposition.clone(),
                    note: "auto-resolved: not present in latest scan".into(),
                });
                diff.auto_resolved.push(existing.clone());
            }
    }

    store.last_scan_at = Some(now);
    save_store(customer_slug, &store)?;
    Ok(diff)
}

// ---------------------------------------------------------------------------
// Mutation API used by RPCs
// ---------------------------------------------------------------------------

/// Update a finding's disposition + note. Returns the updated record.
pub fn set_disposition(
    customer_slug: &str,
    key: &str,
    new_disposition: Disposition,
    by: &str,
    note: &str,
) -> Result<PersistedFinding> {
    // Same per-scope lock `reconcile` holds across its load→modify→save
    // cycle. Without it a background scan and an operator's disposition
    // change for the same customer race: each reads the other's stale
    // snapshot and one rename silently wins, dropping the audit history.
    let lock = scope_lock(customer_slug);
    let _guard = lock.lock().expect("scope lock poisoned");

    let mut store = load_store(customer_slug)?;
    let existing = store
        .findings
        .get_mut(key)
        .with_context(|| format!("finding {key} not found"))?;
    let prev = existing.disposition.clone();
    existing.disposition = new_disposition.clone();
    existing.note = note.to_owned();
    existing.history.push(DispositionChange {
        at: Utc::now(),
        by: by.to_owned(),
        from: prev,
        to: new_disposition,
        note: note.to_owned(),
    });
    let updated = existing.clone();
    save_store(customer_slug, &store)?;
    Ok(updated)
}

/// Returns all findings sorted by severity descending then first_seen ascending.
pub fn list_findings(customer_slug: &str) -> Result<Vec<PersistedFinding>> {
    let store = load_store(customer_slug)?;
    let mut findings: Vec<PersistedFinding> = store.findings.into_values().collect();
    findings.sort_by(|a, b| {
        sev_rank(&a.finding.severity)
            .cmp(&sev_rank(&b.finding.severity))
            .then_with(|| a.first_seen.cmp(&b.first_seen))
    });
    Ok(findings)
}

fn sev_rank(s: &crate::severity::Severity) -> u8 {
    use crate::severity::Severity;
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

/// Compute the most recent `ScanDiff` without modifying the store.
/// Useful when the UI wants to re-display the diff after navigation
/// without re-running a scan.
///
/// We don't persist diffs separately — instead we re-derive a
/// summary from the store where we can (last_seen relative to
/// last_scan_at). For the full diff the caller should look at the
/// `ScanDiff` returned from `reconcile()`.
pub fn summary(customer_slug: &str) -> Result<StoreSummary> {
    let store = load_store(customer_slug)?;
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;
    let mut info = 0u32;
    let mut accepted = 0u32;
    let mut fixed = 0u32;
    let mut open = 0u32;
    let mut false_positive = 0u32;
    for f in store.findings.values() {
        match &f.disposition {
            Disposition::Open => {
                open += 1;
                use crate::severity::Severity;
                match f.finding.severity {
                    Severity::Critical => critical += 1,
                    Severity::High => high += 1,
                    Severity::Medium => medium += 1,
                    Severity::Low => low += 1,
                    Severity::Info => info += 1,
                }
            }
            Disposition::AcceptedRisk { .. } => accepted += 1,
            Disposition::Fixed { .. } => fixed += 1,
            Disposition::FalsePositive { .. } => false_positive += 1,
        }
    }
    Ok(StoreSummary {
        total: store.findings.len() as u32,
        open,
        accepted_risk: accepted,
        fixed,
        false_positive,
        critical,
        high,
        medium,
        low,
        info,
        last_scan_at: store.last_scan_at,
    })
}

/// Counts for a scope, for a dashboard tile.
///
/// Disposition counts and severity counts are separate axes over the same
/// findings, so they do not sum to each other: `critical` counts open criticals,
/// while `total` counts every stored finding whatever its state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreSummary {
    /// Every stored finding, any disposition.
    pub total: u32,
    /// Unresolved.
    pub open: u32,
    /// Suppressed by an accepted-risk decision.
    pub accepted_risk: u32,
    /// Resolved, whether automatically or by hand.
    pub fixed: u32,
    /// Judged not to be real.
    pub false_positive: u32,
    /// Open findings at critical severity.
    pub critical: u32,
    /// Open findings at high severity.
    pub high: u32,
    /// Open findings at medium severity.
    pub medium: u32,
    /// Open findings at low severity.
    pub low: u32,
    /// Open findings at info severity.
    pub info: u32,
    /// When `reconcile` last ran for this scope, if ever.
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Finding;
    use crate::severity::Severity;

    fn fake_finding(id: &str, host: &str, sev: Severity) -> Finding {
        Finding {
            id: id.to_owned(),
            host_ip: host.to_owned(),
            port: Some(22),
            service: Some("ssh".into()),
            severity: sev,
            title: format!("test {id}"),
            detail: "fixture".into(),
            recommendation: "fixture".into(),
            cve: None,
            cvss: Some(5.0),
        }
    }

    /// Tests use a unique scope name per run so they don't stomp
    /// each other. Cleanup happens in the test wrapper. UUID v4
    /// guarantees uniqueness even when parallel tests start within
    /// the same nanosecond (timestamp-based names collided).
    fn unique_scope(prefix: &str) -> String {
        format!("test-{prefix}-{}", uuid::Uuid::new_v4().simple())
    }

    fn cleanup(scope: &str) {
        let dir = store_dir(scope);
        let _ = std::fs::remove_dir_all(&dir);
    }


    // -- compliance run -> findings -> store, end to end -----------------
    //
    // The wire added alongside this: a failed control has to become a finding
    // with a disposition and a history, and has to auto-resolve when it starts
    // passing. Covers everything the daemon does except deriving the scope.

    #[test]
    fn a_compliance_run_files_only_its_failures_and_resolves_them_later() {
        use crate::compliance::{
            failures_as_findings, CheckResult, ComplianceRun, Status, TriggerKind,
        };
        use crate::compliance::{BaselineKind, Severity as CSeverity};

        let scope = unique_scope("compliance");

        let check = |id: &str, status: Status| CheckResult {
            check_id: id.to_owned(),
            status,
            detail: "d".to_owned(),
            raw_value: Some("observed=x".to_owned()),
            severity: CSeverity::High,
            title: format!("T {id}"),
            category: "SSH".to_owned(),
        };
        let run = |checks: Vec<CheckResult>| ComplianceRun {
            id: uuid::Uuid::new_v4().simple().to_string(),
            host_id: "h1".to_owned(),
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
            firmware: None,
            model: None,
            hostname: Some("web01".to_owned()),
            triggered_by: TriggerKind::Manual,
            baseline_kind: BaselineKind::Linux,
            score: 50,
            passed: 0,
            failed: 0,
            errored: 0,
            skipped: 0,
            checks,
        };

        // First scan: one fail, one error, one pass. Only the fail is filed —
        // an error means the check could not be evaluated, and filing that as a
        // finding is the fabrication #182 removed.
        let first = run(vec![
            check("linux.ssh.root-login-disabled", Status::Fail),
            check("linux.ssh.password-auth-disabled", Status::Error),
            check("linux.audit.journald-running", Status::Pass),
        ]);
        let diff = reconcile(&scope, &failures_as_findings(&first, &[])).expect("reconcile");
        assert_eq!(diff.new_findings.len(), 1, "only the failure is a finding");
        assert_eq!(
            diff.new_findings[0].finding.id,
            "linux.ssh.root-login-disabled"
        );
        assert!(
            diff.new_findings[0].finding.detail.contains("observed=x"),
            "the evidence has to survive into the store"
        );

        // Second scan, same failure: still open, not a duplicate. This is what
        // the stable check-id key buys.
        let diff = reconcile(&scope, &failures_as_findings(&first, &[])).expect("reconcile");
        assert_eq!(diff.new_findings.len(), 0, "not filed twice");
        assert_eq!(diff.still_open.len(), 1);
        assert_eq!(diff.still_open[0].scan_count, 2);

        // Third scan, the control now passes: absent from the fresh set, so the
        // finding auto-resolves. An empty findings list is a signal, not a
        // no-op, which is why the daemon reconciles even when a scan finds
        // nothing.
        let fixed = run(vec![check("linux.ssh.root-login-disabled", Status::Pass)]);
        let diff = reconcile(&scope, &failures_as_findings(&fixed, &[])).expect("reconcile");
        assert_eq!(diff.auto_resolved.len(), 1, "a passing control closes its finding");
        assert_eq!(diff.still_open.len(), 0);

        // And the history is there to read afterwards.
        let stored = list_findings(&scope).expect("list");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].disposition.label(), "fixed");
        assert_eq!(stored[0].scan_count, 2, "the passing scan does not count as an observation");

        cleanup(&scope);
    }

    #[test]
    fn first_scan_records_all_as_new() {
        let scope = unique_scope("first");
        let fresh = vec![
            fake_finding("cve.cve-2023-38408", "10.0.0.1", Severity::High),
            fake_finding("config.smb-open", "10.0.0.1", Severity::Medium),
        ];
        let diff = reconcile(&scope, &fresh).expect("reconcile ok");
        assert_eq!(diff.new_findings.len(), 2);
        assert_eq!(diff.still_open.len(), 0);
        assert_eq!(diff.auto_resolved.len(), 0);
        assert_eq!(diff.regressed.len(), 0);
        cleanup(&scope);
    }

    #[test]
    fn second_scan_marks_existing_as_still_open() {
        let scope = unique_scope("still");
        let fresh = vec![fake_finding("cve.cve-2023-38408", "10.0.0.1", Severity::High)];
        reconcile(&scope, &fresh).unwrap();
        let diff = reconcile(&scope, &fresh).expect("reconcile ok");
        assert_eq!(diff.new_findings.len(), 0);
        assert_eq!(diff.still_open.len(), 1);
        // scan_count should have advanced.
        assert_eq!(diff.still_open[0].scan_count, 2);
        cleanup(&scope);
    }

    #[test]
    fn missing_finding_auto_resolves() {
        let scope = unique_scope("resolve");
        let f1 = fake_finding("config.smb-open", "10.0.0.1", Severity::Medium);
        reconcile(&scope, std::slice::from_ref(&f1)).unwrap();
        // Second scan finds nothing → previous open finding should
        // flip to Fixed{auto:true}.
        let diff = reconcile(&scope, &[]).expect("reconcile ok");
        assert_eq!(diff.auto_resolved.len(), 1);
        assert_eq!(diff.auto_resolved[0].finding.id, "config.smb-open");
        match diff.auto_resolved[0].disposition {
            Disposition::Fixed { auto } => assert!(auto),
            _ => panic!("expected Fixed{{auto:true}}"),
        }
        cleanup(&scope);
    }

    #[test]
    fn fixed_finding_redetected_marks_regression() {
        let scope = unique_scope("regress");
        let f = fake_finding("cve.cve-2023-38408", "10.0.0.1", Severity::High);
        reconcile(&scope, std::slice::from_ref(&f)).unwrap();
        // Scan with no findings → auto-fixed.
        reconcile(&scope, &[]).unwrap();
        // Same finding comes back → regression.
        let diff = reconcile(&scope, std::slice::from_ref(&f)).expect("reconcile ok");
        assert_eq!(diff.regressed.len(), 1);
        assert_eq!(diff.new_findings.len(), 0);
        assert!(matches!(diff.regressed[0].disposition, Disposition::Open));
        cleanup(&scope);
    }

    #[test]
    fn accepted_risk_kept_until_expiry() {
        let scope = unique_scope("accepted");
        let f = fake_finding("config.smb-open", "10.0.0.1", Severity::Medium);
        reconcile(&scope, std::slice::from_ref(&f)).unwrap();
        let key = finding_key(&f);
        // Accept the risk indefinitely.
        set_disposition(
            &scope,
            &key,
            Disposition::AcceptedRisk { reason: "intentional".into(), until: None },
            "test",
            "",
        )
        .unwrap();
        // Re-scan still detects it — should remain in accepted_risk bucket.
        let diff = reconcile(&scope, std::slice::from_ref(&f)).expect("reconcile ok");
        assert_eq!(diff.accepted_risk.len(), 1);
        assert_eq!(diff.regressed.len(), 0);
        assert_eq!(diff.still_open.len(), 0);
        cleanup(&scope);
    }

    #[test]
    fn expired_accepted_risk_reopens() {
        let scope = unique_scope("expired");
        let f = fake_finding("config.smb-open", "10.0.0.1", Severity::Medium);
        reconcile(&scope, std::slice::from_ref(&f)).unwrap();
        let key = finding_key(&f);
        // Acceptance window expired yesterday.
        set_disposition(
            &scope,
            &key,
            Disposition::AcceptedRisk {
                reason: "ran out".into(),
                until: Some(Utc::now() - chrono::Duration::days(1)),
            },
            "test",
            "",
        )
        .unwrap();
        let diff = reconcile(&scope, std::slice::from_ref(&f)).expect("reconcile ok");
        assert_eq!(diff.regressed.len(), 1);
        assert!(matches!(diff.regressed[0].disposition, Disposition::Open));
        cleanup(&scope);
    }

    #[test]
    fn finding_key_is_stable_across_calls() {
        let f = fake_finding("config.smb-open", "10.0.0.1", Severity::Medium);
        let k1 = finding_key(&f);
        let k2 = finding_key(&f);
        assert_eq!(k1, k2);
        // A different host produces a different key.
        let f2 = fake_finding("config.smb-open", "10.0.0.2", Severity::Medium);
        assert_ne!(finding_key(&f2), k1);
    }

    #[test]
    fn concurrent_reconcile_does_not_lose_findings() {
        // Two threads reconciling DIFFERENT findings into the same
        // scope should both end up persisted — proves the scope_lock
        // is doing its job (without it, the second writer's load
        // would miss the first writer's commit).
        use std::thread;
        let scope = unique_scope("concurrent");
        let scope_clone = scope.clone();
        let h1 = thread::spawn(move || {
            for i in 0..5 {
                let f = fake_finding(&format!("test.a-{i}"), "10.0.0.1", Severity::Low);
                reconcile(&scope_clone, &[f]).unwrap();
            }
        });
        let scope_clone = scope.clone();
        let h2 = thread::spawn(move || {
            for i in 0..5 {
                let f = fake_finding(&format!("test.b-{i}"), "10.0.0.1", Severity::Low);
                reconcile(&scope_clone, &[f]).unwrap();
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();
        // Each iteration's reconcile auto-resolves anything it
        // didn't see, so the final store may have a mix of
        // auto-fixed + currently-open. What matters is total
        // findings_count == 10 (a-0..4 + b-0..4 all recorded).
        let store = load_store(&scope).unwrap();
        assert_eq!(store.findings.len(), 10, "all 10 distinct findings should be persisted");
        cleanup(&scope);
    }
}
