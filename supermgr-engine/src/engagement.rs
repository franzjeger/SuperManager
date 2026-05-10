//! Engagement — time-bounded, scoped authorization record for
//! security testing.
//!
//! Every active scan / pen-test action SHOULD be associated with
//! an Engagement. This is what makes the difference between a
//! professional MSP toolchain and a script-kiddie's collection
//! of binaries. The model carries:
//!
//!   - **scope_cidrs**: which subnets are allowed targets
//!   - **scope_hosts**: specific hostnames in scope
//!   - **exclusions**: explicitly-out-of-scope addresses (e.g.
//!     production payment gateways)
//!   - **allowed_techniques**: what kinds of action are allowed
//!     (Recon, Discovery, VulnScan, CredTest, WebExploit, …)
//!   - **expires_at**: contract-end date; scans against expired
//!     engagements are flagged in the GUI
//!   - **authorization_doc_path**: optional reference to a
//!     signed authorization PDF (proof for later legal
//!     questions)
//!   - **log**: append-only audit trail of every scan run
//!
//! Persistence: one TOML file per engagement under
//! `~/Library/Application Support/SuperManager/engagements/`.
//! Same pattern as customers — git-friendly, exportable, no DB.
//!
//! # Why not enforce hard scope-blocking?
//!
//! For now the Engagement is metadata + audit trail. The GUI
//! warns when a scan target falls outside scope but doesn't
//! block — operators are presumed competent and there are
//! legitimate "spot-check this random IP" cases that would be
//! disrupted by hard enforcement. A future hardening pass can
//! add a strict-mode toggle in settings.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engagement {
    pub id: String,
    pub customer_slug: String,
    pub title: String,

    /// CIDRs that are in-scope. Empty list = "no CIDR scope
    /// specified" (the GUI treats this as "ad-hoc engagement").
    #[serde(default)]
    pub scope_cidrs: Vec<String>,

    /// Specific FQDNs/hostnames also in scope (for engagements
    /// that target named hosts rather than full subnets).
    #[serde(default)]
    pub scope_hosts: Vec<String>,

    /// Explicitly-excluded addresses or CIDRs. Trumps scope.
    #[serde(default)]
    pub exclusions: Vec<String>,

    /// Allowed techniques for this engagement. Restricts which
    /// SuperManager actions can run within scope. See
    /// [`Technique`] for the enum.
    #[serde(default)]
    pub allowed_techniques: Vec<Technique>,

    pub started_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,

    /// Free-form: who authorized this on the customer side.
    /// "Frank Liaaen, Aarsleff CTO". Surfaced on every report
    /// generated under this engagement.
    #[serde(default)]
    pub authorized_by: String,

    /// Optional path to a signed authorization PDF / email
    /// thread. Hashed on save so later tampering is detectable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_doc_path: Option<String>,

    /// Append-only audit trail of every action run under this
    /// engagement. Each entry is a one-line summary with
    /// timestamp + technique + target + outcome.
    #[serde(default)]
    pub log: Vec<EngagementEvent>,

    /// Free-form notes — context for the engagement (scope
    /// rationale, customer concerns, etc.).
    #[serde(default)]
    pub notes: String,

    /// Optional recurring active-scan schedule. When set, the
    /// background scheduler in `scheduler.rs` fires scans at the
    /// specified cadence and updates `next_scan_at` after each run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Schedule {
    pub cadence: Cadence,
    /// When the *next* scheduled scan should run. The scheduler
    /// uses this as the timer trigger; `chrono::Utc::now() >= next_scan_at`
    /// → fire + advance.
    pub next_scan_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Cadence {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl Cadence {
    pub fn advance(self, from: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
        match self {
            Self::Hourly => from + chrono::Duration::hours(1),
            Self::Daily => from + chrono::Duration::days(1),
            Self::Weekly => from + chrono::Duration::weeks(1),
            Self::Monthly => from + chrono::Duration::days(30),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Hourly => "Hourly",
            Self::Daily => "Daily",
            Self::Weekly => "Weekly",
            Self::Monthly => "Monthly",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Technique {
    /// Passive recon: mDNS, ARP cache, OUI lookup. Sends nothing.
    Recon,
    /// Active L3+L4 discovery: ICMP, TCP connect, banner grab.
    Discovery,
    /// Templated vulnerability scanning (Nuclei).
    VulnScan,
    /// TLS/SSL configuration audit (testssl).
    TlsAudit,
    /// Default-credential testing against discovered services.
    CredTest,
    /// Web application testing (sqlmap read-only, XSS detection).
    WebExploit,
    /// SMB enumeration / shares / users.
    SmbEnum,
    /// SNMP read-only walking.
    SnmpRead,
    /// Wireless attacks. NOT implemented; reserved for future.
    Wireless,
    /// DoS testing. Explicitly NOT implemented.
    DosTest,
}

impl Technique {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Recon => "Recon",
            Self::Discovery => "Discovery",
            Self::VulnScan => "Vulnerability scan",
            Self::TlsAudit => "TLS audit",
            Self::CredTest => "Credential testing",
            Self::WebExploit => "Web testing",
            Self::SmbEnum => "SMB enumeration",
            Self::SnmpRead => "SNMP read",
            Self::Wireless => "Wireless attacks",
            Self::DosTest => "DoS testing",
        }
    }

    /// Default starter set — appropriate for most professional
    /// MSP engagements. Includes everything except wireless and
    /// DoS, which are out-of-scope for typical pen-tests.
    #[must_use]
    pub fn default_set() -> Vec<Technique> {
        vec![
            Self::Recon,
            Self::Discovery,
            Self::VulnScan,
            Self::TlsAudit,
            Self::CredTest,
            Self::WebExploit,
            Self::SmbEnum,
            Self::SnmpRead,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementEvent {
    pub at: chrono::DateTime<chrono::Utc>,
    pub technique: Technique,
    pub target: String,                            // CIDR or host
    pub action: String,                            // "passive_scan", "nuclei_run", etc.
    pub findings: u32,                             // count of new findings produced
    pub notes: String,                             // free-form summary
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

fn engagements_dir() -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("engagements");
    p
}

pub fn list_all() -> Result<Vec<Engagement>> {
    let dir = engagements_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Engagement> = Vec::new();
    for entry in std::fs::read_dir(&dir).context("read engagements dir")? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("engagement listing entry error: {e}");
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        match load_path(&path) {
            Ok(e) => out.push(e),
            Err(e) => tracing::warn!("engagement load failed for {path:?}: {e:#}"),
        }
    }
    // Sort: active (non-expired) first, then by expiry desc.
    let now = chrono::Utc::now();
    out.sort_by(|a, b| {
        let a_active = a.expires_at > now;
        let b_active = b.expires_at > now;
        if a_active != b_active {
            return b_active.cmp(&a_active);
        }
        b.expires_at.cmp(&a.expires_at)
    });
    Ok(out)
}

pub fn load(id: &str) -> Result<Engagement> {
    crate::customer::validate_slug(id).context("invalid engagement id")?;
    let mut path = engagements_dir();
    path.push(format!("{id}.toml"));
    load_path(&path)
}

fn load_path(path: &Path) -> Result<Engagement> {
    let bytes = std::fs::read_to_string(path).with_context(|| format!("read {path:?}"))?;
    toml::from_str(&bytes).with_context(|| format!("parse {path:?}"))
}

/// Per-engagement save mutex. Prevents the load→modify→save race
/// when two RPC calls (e.g. `engagement_save` + `log_event`) hit
/// the same engagement TOML simultaneously.
fn engagement_lock(id: &str) -> std::sync::Arc<std::sync::Mutex<()>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().expect("engagement lock map poisoned");
    guard
        .entry(id.to_owned())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

pub fn save(engagement: &Engagement) -> Result<()> {
    crate::customer::validate_slug(&engagement.id).context("invalid engagement id")?;
    if !engagement.customer_slug.is_empty() {
        crate::customer::validate_slug(&engagement.customer_slug)
            .context("invalid customer_slug on engagement")?;
    }
    let lock = engagement_lock(&engagement.id);
    let _guard = lock.lock().expect("engagement lock poisoned");

    let dir = engagements_dir();
    std::fs::create_dir_all(&dir).context("create engagements dir")?;
    let mut path = dir;
    path.push(format!("{}.toml", engagement.id));
    // Atomic tempfile-rename so a partial write can't corrupt the
    // existing TOML on a crash/ENOSPC.
    let tmp = path.with_extension("toml.tmp");
    let serialized = toml::to_string_pretty(engagement).context("serialize engagement")?;
    std::fs::write(&tmp, serialized).with_context(|| format!("write {tmp:?}"))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("rename {path:?}"))?;
    Ok(())
}

pub fn delete(id: &str) -> Result<()> {
    crate::customer::validate_slug(id).context("invalid engagement id")?;
    let mut path = engagements_dir();
    path.push(format!("{id}.toml"));
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("delete {path:?}"))?;
    }
    Ok(())
}

/// Append a one-line audit event to an engagement's log. Used
/// by every active scan to record what happened.
pub fn log_event(engagement_id: &str, event: EngagementEvent) -> Result<()> {
    // Acquire the engagement lock around the load→append→save
    // cycle. Without this, two concurrent log_event calls would
    // race: both load the same state, append different events,
    // and one of them overwrites the other on save.
    let lock = engagement_lock(engagement_id);
    let _guard = lock.lock().expect("engagement lock poisoned");

    let mut e = load(engagement_id)?;
    e.log.push(event);
    // Save bypasses the (re-entrant) lock since we already hold
    // it. Drop into the inner write directly.
    save_inner(&e)
}

/// Inner save without the lock — call only when the caller
/// already holds `engagement_lock(id)`.
fn save_inner(engagement: &Engagement) -> Result<()> {
    crate::customer::validate_slug(&engagement.id).context("invalid engagement id")?;
    if !engagement.customer_slug.is_empty() {
        crate::customer::validate_slug(&engagement.customer_slug)
            .context("invalid customer_slug on engagement")?;
    }
    let dir = engagements_dir();
    std::fs::create_dir_all(&dir).context("create engagements dir")?;
    let mut path = dir;
    path.push(format!("{}.toml", engagement.id));
    let tmp = path.with_extension("toml.tmp");
    let serialized = toml::to_string_pretty(engagement).context("serialize engagement")?;
    std::fs::write(&tmp, serialized).with_context(|| format!("write {tmp:?}"))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("rename {path:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn fixture_engagement(suffix: &str) -> Engagement {
        Engagement {
            id: format!("test-engagement-{}-{suffix}", uuid::Uuid::new_v4().simple()),
            customer_slug: "aarsleff-norge".into(),
            title: "Q1 audit".into(),
            scope_cidrs: vec!["10.0.0.0/16".into()],
            scope_hosts: vec![],
            exclusions: vec![],
            allowed_techniques: Technique::default_set(),
            started_at: Utc::now() - chrono::Duration::days(1),
            expires_at: Utc::now() + chrono::Duration::days(89),
            authorized_by: "test".into(),
            authorization_doc_path: None,
            log: vec![],
            notes: String::new(),
            schedule: None,
        }
    }

    fn cleanup(id: &str) {
        let mut path = engagements_dir();
        path.push(format!("{id}.toml"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let e = fixture_engagement("roundtrip");
        save(&e).expect("save");
        let loaded = load(&e.id).expect("load");
        assert_eq!(loaded.id, e.id);
        assert_eq!(loaded.title, e.title);
        assert_eq!(loaded.scope_cidrs, e.scope_cidrs);
        cleanup(&e.id);
    }

    #[test]
    fn save_rejects_bad_id() {
        let mut e = fixture_engagement("badid");
        e.id = "../escape".into();
        let res = save(&e);
        assert!(res.is_err(), "path-traversal id must be rejected");
    }

    #[test]
    fn save_rejects_dot_prefix() {
        let mut e = fixture_engagement("dot");
        e.id = ".hidden".into();
        let res = save(&e);
        assert!(res.is_err(), "leading-dot id must be rejected");
    }

    #[test]
    fn delete_removes_file() {
        let e = fixture_engagement("delete");
        save(&e).unwrap();
        delete(&e.id).expect("delete");
        let mut path = engagements_dir();
        path.push(format!("{}.toml", e.id));
        assert!(!path.exists(), "TOML should be gone after delete");
    }

    #[test]
    fn delete_idempotent_on_missing_file() {
        // Deleting a non-existent engagement should NOT error —
        // makes the cleanup path safe to call repeatedly.
        let res = delete(&format!("never-existed-{}", uuid::Uuid::new_v4().simple()));
        assert!(res.is_ok());
    }

    #[test]
    fn log_event_appends_to_log() {
        let e = fixture_engagement("logevent");
        save(&e).unwrap();
        let event = EngagementEvent {
            at: Utc::now(),
            technique: Technique::Discovery,
            target: "10.0.0.0/16".into(),
            action: "active_scan".into(),
            findings: 3,
            notes: "test".into(),
        };
        log_event(&e.id, event.clone()).expect("log");
        let loaded = load(&e.id).unwrap();
        assert_eq!(loaded.log.len(), 1);
        assert_eq!(loaded.log[0].action, "active_scan");
        assert_eq!(loaded.log[0].findings, 3);
        cleanup(&e.id);
    }

    #[test]
    fn concurrent_log_event_does_not_lose_entries() {
        // Two threads append to the same engagement's log
        // simultaneously. With the engagement_lock around
        // load→append→save, both events must persist.
        let e = fixture_engagement("concurrent");
        save(&e).unwrap();
        let id1 = e.id.clone();
        let id2 = e.id.clone();
        let h1 = std::thread::spawn(move || {
            for i in 0..5 {
                let ev = EngagementEvent {
                    at: Utc::now(),
                    technique: Technique::Recon,
                    target: format!("a-{i}"),
                    action: "passive_scan".into(),
                    findings: i,
                    notes: String::new(),
                };
                log_event(&id1, ev).unwrap();
            }
        });
        let h2 = std::thread::spawn(move || {
            for i in 0..5 {
                let ev = EngagementEvent {
                    at: Utc::now(),
                    technique: Technique::Discovery,
                    target: format!("b-{i}"),
                    action: "active_scan".into(),
                    findings: i + 100,
                    notes: String::new(),
                };
                log_event(&id2, ev).unwrap();
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();
        let loaded = load(&e.id).unwrap();
        assert_eq!(loaded.log.len(), 10, "all 10 events should persist (no race losses)");
        cleanup(&e.id);
    }
}
