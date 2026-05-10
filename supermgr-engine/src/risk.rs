//! Risk scoring — turns the findings store into a single 0-100
//! number per host that drives the Fleet heat-map + remediation
//! prioritisation.
//!
//! # Formula
//!
//! For every Open finding on a host:
//!   `weight = base_weight(severity) × age_factor × exposure_factor`
//!
//! where:
//!   - `base_weight` = Critical 100, High 60, Medium 30, Low 10, Info 0
//!   - `age_factor` = 1.0 + 0.02 × days_open (capped at 2.0)
//!     → a 50-day-old finding weighs double a fresh one
//!   - `exposure_factor` = 1.0 for internal hosts, 1.5 for public
//!     (when zone is known)
//!
//! Host risk = `min(100, sum_of_weights)`. The clamp keeps the
//! score interpretable (single percentage) regardless of how
//! many findings stack up.
//!
//! # Why custom over CVSS aggregation
//!
//! CVSS gives per-vuln severity but no model for age or
//! exposure context. A 5-year-old Medium with public WAN exposure
//! is a bigger problem than a fresh High behind two firewalls;
//! standard aggregation can't express that.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::findings_store::{Disposition, PersistedFinding};
use crate::vuln::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRisk {
    pub host_ip: String,
    /// 0-100 clamped. Higher = worse.
    pub score: u8,
    pub band: RiskBand,
    /// Number of Open findings contributing to the score.
    pub open_findings: u32,
    /// Hint string shown beside the score in the UI ("3 critical
    /// open for >30d, public-zone").
    pub hint: String,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskBand {
    Critical,  // 80-100
    Elevated,  // 50-79
    Moderate,  // 20-49
    Low,       // 1-19
    Clean,     // 0
}

impl RiskBand {
    pub fn from_score(score: u8) -> Self {
        match score {
            0       => Self::Clean,
            1..=19  => Self::Low,
            20..=49 => Self::Moderate,
            50..=79 => Self::Elevated,
            _       => Self::Critical,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::Elevated => "Elevated",
            Self::Moderate => "Moderate",
            Self::Low      => "Low",
            Self::Clean    => "Clean",
        }
    }
}

/// Compute risk per host across the whole findings store of a
/// scope. `host_zones` is optional context from `asset_enrich`:
/// when provided, public-zone hosts get a 1.5× exposure multiplier.
pub fn score_hosts(
    findings: &[PersistedFinding],
    host_zones: &HashMap<String, String>,
) -> Vec<HostRisk> {
    let mut by_host: HashMap<String, Vec<&PersistedFinding>> = HashMap::new();
    for f in findings {
        if matches!(f.disposition, Disposition::Open) {
            by_host.entry(f.finding.host_ip.clone()).or_default().push(f);
        }
    }
    let now = chrono::Utc::now();
    let mut out: Vec<HostRisk> = Vec::with_capacity(by_host.len());
    for (host_ip, fs) in by_host {
        let (mut crit, mut high, mut med, mut low_) = (0u32, 0u32, 0u32, 0u32);
        let mut weight_sum: f32 = 0.0;
        let exposure = host_zones
            .get(&host_ip)
            .map(|z| if z == "public" { 1.5 } else { 1.0 })
            .unwrap_or(1.0);
        let mut oldest_days = 0i64;
        for f in &fs {
            match f.finding.severity {
                Severity::Critical => crit += 1,
                Severity::High     => high += 1,
                Severity::Medium   => med += 1,
                Severity::Low      => low_ += 1,
                Severity::Info     => {}
            }
            let base = base_weight(f.finding.severity);
            let days = (now - f.first_seen).num_days().max(0);
            oldest_days = oldest_days.max(days);
            let age_factor = (1.0 + 0.02 * days as f32).min(2.0);
            weight_sum += base * age_factor * exposure;
        }
        let score = weight_sum.min(100.0).round() as u8;
        let band = RiskBand::from_score(score);
        let hint = format!(
            "{}{} open · oldest {}d",
            if crit > 0 { format!("{crit} crit, ") } else { String::new() },
            if high > 0 { format!("{high} high") } else { format!("{} total", fs.len()) },
            oldest_days,
        );
        out.push(HostRisk {
            host_ip,
            score,
            band,
            open_findings: fs.len() as u32,
            hint,
            critical: crit,
            high,
            medium: med,
            low: low_,
        });
    }
    out.sort_by(|a, b| b.score.cmp(&a.score));
    out
}

fn base_weight(s: Severity) -> f32 {
    match s {
        Severity::Critical => 100.0,
        Severity::High     => 60.0,
        Severity::Medium   => 30.0,
        Severity::Low      => 10.0,
        Severity::Info     => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings_store::{Disposition, PersistedFinding};
    use crate::vuln::{Finding, Severity};

    fn p(host: &str, sev: Severity, days_old: i64) -> PersistedFinding {
        PersistedFinding {
            key: format!("test|{host}|0|x"),
            finding: Finding {
                id: "test".into(),
                host_ip: host.to_owned(),
                port: None,
                service: None,
                severity: sev,
                title: "t".into(),
                detail: "".into(),
                recommendation: "".into(),
                cve: None,
                cvss: None,
            },
            disposition: Disposition::Open,
            first_seen: chrono::Utc::now() - chrono::Duration::days(days_old),
            last_seen: chrono::Utc::now(),
            scan_count: 1,
            history: vec![],
            note: String::new(),
        }
    }

    #[test]
    fn band_thresholds() {
        assert_eq!(RiskBand::from_score(0), RiskBand::Clean);
        assert_eq!(RiskBand::from_score(1), RiskBand::Low);
        assert_eq!(RiskBand::from_score(19), RiskBand::Low);
        assert_eq!(RiskBand::from_score(20), RiskBand::Moderate);
        assert_eq!(RiskBand::from_score(49), RiskBand::Moderate);
        assert_eq!(RiskBand::from_score(50), RiskBand::Elevated);
        assert_eq!(RiskBand::from_score(79), RiskBand::Elevated);
        assert_eq!(RiskBand::from_score(80), RiskBand::Critical);
        assert_eq!(RiskBand::from_score(100), RiskBand::Critical);
    }

    #[test]
    fn empty_findings_yields_no_rows() {
        let zones = std::collections::HashMap::new();
        assert!(score_hosts(&[], &zones).is_empty());
    }

    #[test]
    fn closed_findings_excluded() {
        let mut f = p("10.0.0.1", Severity::Critical, 0);
        f.disposition = Disposition::Fixed { auto: true };
        let zones = std::collections::HashMap::new();
        let scored = score_hosts(&[f], &zones);
        assert!(scored.is_empty(), "fixed findings shouldn't contribute");
    }

    #[test]
    fn fresh_critical_scores_at_least_100() {
        // Single Critical, age 0, internal zone.
        // weight = 100 * 1.0 * 1.0 = 100. Clamped to 100.
        let zones = std::collections::HashMap::new();
        let scored = score_hosts(&[p("10.0.0.1", Severity::Critical, 0)], &zones);
        assert_eq!(scored.len(), 1);
        assert_eq!(scored[0].score, 100);
        assert_eq!(scored[0].band, RiskBand::Critical);
    }

    #[test]
    fn fresh_low_internal_scores_low_band() {
        let zones = std::collections::HashMap::new();
        let scored = score_hosts(&[p("10.0.0.1", Severity::Low, 0)], &zones);
        // 10 base × 1.0 × 1.0 = 10 → Low band.
        assert_eq!(scored[0].score, 10);
        assert_eq!(scored[0].band, RiskBand::Low);
    }

    #[test]
    fn old_finding_age_factor_caps_at_2x() {
        // 200 days × 0.02 = 4.0 → capped at 2.0.
        // Medium=30, age=2, exposure=1 → 60.
        let zones = std::collections::HashMap::new();
        let scored = score_hosts(&[p("10.0.0.1", Severity::Medium, 200)], &zones);
        assert_eq!(scored[0].score, 60);
        assert_eq!(scored[0].band, RiskBand::Elevated);
    }

    #[test]
    fn public_zone_multiplies_by_one_point_five() {
        let mut zones = std::collections::HashMap::new();
        zones.insert("8.8.8.8".to_owned(), "public".to_owned());
        // Medium=30, age=0, exposure=1.5 → 45.
        let scored = score_hosts(&[p("8.8.8.8", Severity::Medium, 0)], &zones);
        assert_eq!(scored[0].score, 45);
    }

    #[test]
    fn score_clamped_at_100() {
        // Three criticals → 300 raw → clamped to 100.
        let zones = std::collections::HashMap::new();
        let findings = vec![
            p("10.0.0.1", Severity::Critical, 0),
            p("10.0.0.1", Severity::Critical, 0),
            p("10.0.0.1", Severity::Critical, 0),
        ];
        let scored = score_hosts(&findings, &zones);
        assert_eq!(scored[0].score, 100);
    }

    #[test]
    fn sorted_descending_by_score() {
        let zones = std::collections::HashMap::new();
        let findings = vec![
            p("low.example", Severity::Low, 0),
            p("crit.example", Severity::Critical, 0),
            p("med.example", Severity::Medium, 0),
        ];
        let scored = score_hosts(&findings, &zones);
        assert_eq!(scored[0].host_ip, "crit.example");
        assert_eq!(scored[1].host_ip, "med.example");
        assert_eq!(scored[2].host_ip, "low.example");
    }

    #[test]
    fn severity_bucket_counts_accurate() {
        let zones = std::collections::HashMap::new();
        let findings = vec![
            p("h.example", Severity::Critical, 0),
            p("h.example", Severity::Critical, 0),
            p("h.example", Severity::High, 0),
            p("h.example", Severity::Medium, 0),
            p("h.example", Severity::Low, 0),
        ];
        let scored = score_hosts(&findings, &zones);
        assert_eq!(scored[0].critical, 2);
        assert_eq!(scored[0].high, 1);
        assert_eq!(scored[0].medium, 1);
        assert_eq!(scored[0].low, 1);
        assert_eq!(scored[0].open_findings, 5);
    }
}
