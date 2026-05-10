//! DNS health audit — SPF / DKIM / DMARC / MTA-STS / DNSSEC / DNS-RR sanity.
//!
//! Pulled together by shelling out to `dig +short`. Each check is
//! one DNS lookup; the whole audit fits in <2 s for a domain.
//!
//! All findings are scoped to (domain, kind) — kept stable so
//! `findings_store::reconcile` can track "SPF missing for domain.no"
//! across scans the same way it tracks CVE findings.
//!
//! # Why shell out instead of trust-dns
//!
//! `dig` is system-installed (or one `brew install bind` away);
//! it's the canonical DNS query tool. Pulling in `trust-dns` adds
//! ~200 KB of Rust deps and parsing complexity for queries we
//! could express in three command-line args.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::vuln::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHealthReport {
    pub domain: String,
    pub spf: SpfState,
    pub dkim_selectors_found: Vec<String>,
    pub dmarc: DmarcState,
    pub mta_sts: MtaStsState,
    pub dnssec: DnssecState,
    pub mx_records: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpfState {
    Missing,
    Multiple { records: Vec<String> },
    Soft { record: String },        // ends with ~all
    Strict { record: String },      // ends with -all
    Permissive { record: String },  // ends with +all (very bad)
    Neutral { record: String },     // ?all
    NoTerminator { record: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DmarcState {
    Missing,
    None { record: String },         // p=none
    Quarantine { record: String },
    Reject { record: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MtaStsState {
    Missing,
    Present { mode: String },        // enforce / testing / none
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnssecState {
    Disabled,
    Enabled { ds_count: u32 },
}

/// Run the full audit for a single domain.
pub async fn audit(domain: &str) -> DnsHealthReport {
    let domain = domain.trim().trim_end_matches('.');
    let (spf, dmarc, mta_sts, dnssec, mx, dkim) = tokio::join!(
        check_spf(domain),
        check_dmarc(domain),
        check_mta_sts(domain),
        check_dnssec(domain),
        list_mx(domain),
        find_dkim_selectors(domain),
    );

    let mut findings: Vec<Finding> = Vec::new();
    derive_findings(domain, &spf, &dmarc, &mta_sts, &dnssec, &dkim, &mut findings);

    DnsHealthReport {
        domain: domain.to_owned(),
        spf,
        dkim_selectors_found: dkim,
        dmarc,
        mta_sts,
        dnssec,
        mx_records: mx,
        findings,
    }
}

// ---------------------------------------------------------------------------
// Per-record checks
// ---------------------------------------------------------------------------

async fn check_spf(domain: &str) -> SpfState {
    let txt = dig_txt(domain).await;
    let spf: Vec<String> = txt
        .iter()
        .filter(|r| r.to_lowercase().starts_with("v=spf1"))
        .cloned()
        .collect();
    if spf.is_empty() {
        return SpfState::Missing;
    }
    if spf.len() > 1 {
        return SpfState::Multiple { records: spf };
    }
    let record = spf.into_iter().next().unwrap();
    let lower = record.to_lowercase();
    if lower.contains(" -all") || lower.ends_with("-all") {
        SpfState::Strict { record }
    } else if lower.contains(" ~all") || lower.ends_with("~all") {
        SpfState::Soft { record }
    } else if lower.contains(" +all") || lower.ends_with("+all") {
        SpfState::Permissive { record }
    } else if lower.contains(" ?all") || lower.ends_with("?all") {
        SpfState::Neutral { record }
    } else {
        SpfState::NoTerminator { record }
    }
}

async fn check_dmarc(domain: &str) -> DmarcState {
    let target = format!("_dmarc.{domain}");
    let records: Vec<String> = dig_txt(&target)
        .await
        .into_iter()
        .filter(|r| r.to_lowercase().contains("v=dmarc1"))
        .collect();
    let Some(record) = records.into_iter().next() else {
        return DmarcState::Missing;
    };
    let lower = record.to_lowercase();
    if lower.contains("p=reject") {
        DmarcState::Reject { record }
    } else if lower.contains("p=quarantine") {
        DmarcState::Quarantine { record }
    } else {
        DmarcState::None { record }
    }
}

async fn check_mta_sts(domain: &str) -> MtaStsState {
    let target = format!("_mta-sts.{domain}");
    let records: Vec<String> = dig_txt(&target).await;
    let mta = records.iter().find(|r| r.to_lowercase().contains("v=stsv1"));
    match mta {
        None => MtaStsState::Missing,
        Some(r) => {
            // Mode is set in the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt,
            // but the TXT record only confirms the policy version + ID.
            // We surface the TXT presence; mode would need an HTTP fetch.
            let _ = r;
            MtaStsState::Present { mode: "TXT-published".into() }
        }
    }
}

async fn check_dnssec(domain: &str) -> DnssecState {
    // DS records live at the parent zone — `dig DS <domain>` asks
    // the parent. Count of records ≥ 1 indicates DNSSEC delegation.
    let res = dig(domain, "DS").await;
    let count = res.iter().filter(|line| !line.is_empty()).count() as u32;
    if count == 0 {
        DnssecState::Disabled
    } else {
        DnssecState::Enabled { ds_count: count }
    }
}

async fn list_mx(domain: &str) -> Vec<String> {
    dig(domain, "MX").await
}

async fn find_dkim_selectors(domain: &str) -> Vec<String> {
    // Try the most common selectors used by major mail providers.
    // No exhaustive enumeration — that would require an authoritative
    // source. This catches Microsoft 365, Google Workspace, Mailchimp,
    // SendGrid, plus typical per-org defaults.
    const SELECTORS: &[&str] = &[
        "selector1", "selector2",            // Microsoft 365
        "google",                            // Google Workspace
        "k1", "k2", "k3",                    // Mailchimp / Mandrill
        "s1", "s2",                          // SendGrid
        "default", "dkim",                   // DIY
        "smtp",
        "mxvault",                           // Cloudmark
        "pf2014",                            // Pardot
        "ml",                                // MailerLite
    ];
    let mut found: Vec<String> = Vec::new();
    for sel in SELECTORS {
        let target = format!("{sel}._domainkey.{domain}");
        let txt = dig_txt(&target).await;
        if txt.iter().any(|r| r.to_lowercase().contains("v=dkim1")) {
            found.push((*sel).to_owned());
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Findings derivation — turn states into customer-facing recommendations
// ---------------------------------------------------------------------------

fn derive_findings(
    domain: &str,
    spf: &SpfState,
    dmarc: &DmarcState,
    mta_sts: &MtaStsState,
    dnssec: &DnssecState,
    dkim: &[String],
    out: &mut Vec<Finding>,
) {
    let mk = |id: &str, sev: Severity, cvss: f32, title: String, detail: String, rec: String| Finding {
        id: id.to_owned(),
        host_ip: domain.to_owned(),  // Use domain as the "host" for keying.
        port: None,
        service: Some("dns".into()),
        severity: sev,
        title,
        detail,
        recommendation: rec,
        cve: None,
        cvss: Some(cvss),
    };

    // --- SPF ---
    match spf {
        SpfState::Missing => out.push(mk(
            "dns.spf-missing",
            Severity::High,
            7.0,
            format!("No SPF record published for {domain}"),
            "Without SPF, attackers can spoof email From: <anything@your-domain> with no detection at the receiver. Modern receivers (Microsoft 365, Google) treat absent SPF as a strong spam signal.".into(),
            "Publish a TXT record at the apex: `v=spf1 include:<your-mailer> -all`. Use `~all` only during a controlled rollout.".into(),
        )),
        SpfState::Permissive { .. } => out.push(mk(
            "dns.spf-permissive",
            Severity::Critical,
            8.5,
            format!("SPF policy is `+all` for {domain} (anyone can send)"),
            "`+all` explicitly authorises any host to send mail as you. Indistinguishable from no SPF — worse, because some receivers stop checking once they see SPF=pass.".into(),
            "Replace `+all` with `-all` (strict) or `~all` (soft-fail). Audit the include: list to confirm no orphan mailers.".into(),
        )),
        SpfState::Multiple { .. } => out.push(mk(
            "dns.spf-multiple",
            Severity::High,
            6.5,
            format!("Multiple SPF records on {domain} (RFC 7208 violation)"),
            "RFC 7208 §3.2 disallows more than one SPF record per domain. Most receivers fail-closed (treat as PermError) when they find multiple, which weakens deliverability AND invalidates the policy.".into(),
            "Merge into a single TXT record with the union of `include:` mechanisms.".into(),
        )),
        SpfState::NoTerminator { .. } | SpfState::Neutral { .. } => out.push(mk(
            "dns.spf-no-terminator",
            Severity::Medium,
            5.0,
            format!("SPF for {domain} lacks a definitive terminator"),
            "An SPF record without `-all` or `~all` defaults to `?all` (neutral) — receivers fall back to other signals, which weakens DMARC alignment.".into(),
            "Append `-all` (strict) or `~all` (during rollout) to the record.".into(),
        )),
        SpfState::Soft { .. } | SpfState::Strict { .. } => {} // OK
    }

    // --- DMARC ---
    match dmarc {
        DmarcState::Missing => out.push(mk(
            "dns.dmarc-missing",
            Severity::High,
            7.0,
            format!("No DMARC record published for {domain}"),
            "DMARC ties SPF + DKIM together and tells receivers what to do when alignment fails. Without DMARC, spoofed mail still lands in inboxes even when SPF/DKIM exist.".into(),
            "Publish a TXT record at `_dmarc.{domain}`: `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com`. Start with `p=none` to monitor, escalate to `p=reject` after audit.".into(),
        )),
        DmarcState::None { .. } => out.push(mk(
            "dns.dmarc-policy-none",
            Severity::Medium,
            5.5,
            format!("DMARC policy `p=none` on {domain} — monitor only, no enforcement"),
            "`p=none` lets DMARC reports flow but instructs receivers to take no action when alignment fails. Useful for initial rollout but should be a temporary state.".into(),
            "After auditing aggregate reports for ~30 days, escalate to `p=quarantine` and then `p=reject`.".into(),
        )),
        DmarcState::Quarantine { .. } | DmarcState::Reject { .. } => {}
    }

    // --- DKIM ---
    if dkim.is_empty() {
        out.push(mk(
            "dns.dkim-missing",
            Severity::Medium,
            5.0,
            format!("No DKIM selectors found for {domain}"),
            "We probed common selectors (selector1/selector2, google, k1, etc.) and found none. Either DKIM uses a custom selector we didn't try, or DKIM signing is genuinely missing.".into(),
            "Verify DKIM with `dig TXT <selector>._domainkey.{domain}`. Configure DKIM via your mail provider (M365 Defender, Google Admin SDK, etc.).".into(),
        ));
    }

    // --- MTA-STS ---
    if matches!(mta_sts, MtaStsState::Missing) {
        out.push(mk(
            "dns.mta-sts-missing",
            Severity::Low,
            3.5,
            format!("No MTA-STS policy published for {domain}"),
            "MTA-STS forces SMTP delivery to use TLS to your published MX hosts. Without it, an active attacker can downgrade SMTP to plaintext.".into(),
            "Publish `_mta-sts.{domain}` TXT record + the policy file at `https://mta-sts.{domain}/.well-known/mta-sts.txt`. Start with `mode: testing`.".into(),
        ));
    }

    // --- DNSSEC ---
    if matches!(dnssec, DnssecState::Disabled) {
        out.push(mk(
            "dns.dnssec-disabled",
            Severity::Low,
            3.0,
            format!("DNSSEC not enabled for {domain}"),
            "Without DNSSEC, DNS responses can be tampered with via cache-poisoning or BGP hijack. DANE (TLSA records) and verifiable email policy require DNSSEC to be useful.".into(),
            "Enable DNSSEC at the registrar and publish the DS records at the parent zone. Most registrars offer one-click DNSSEC for managed zones.".into(),
        ));
    }
}

// ---------------------------------------------------------------------------
// dig helpers
// ---------------------------------------------------------------------------

async fn dig_txt(name: &str) -> Vec<String> {
    let lines = dig(name, "TXT").await;
    // dig +short TXT returns lines like:
    //   "v=spf1 include:_spf.google.com -all"
    // Each value is double-quoted; multi-string TXTs come as several
    // adjacent quoted segments. Strip and concatenate.
    lines
        .into_iter()
        .map(|l| {
            // Concatenate all "..." segments on a line.
            let mut buf = String::new();
            let mut in_quote = false;
            for ch in l.chars() {
                if ch == '"' {
                    in_quote = !in_quote;
                    continue;
                }
                if in_quote {
                    buf.push(ch);
                }
            }
            if buf.is_empty() {
                l.trim().to_owned()
            } else {
                buf
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

async fn dig(name: &str, rrtype: &str) -> Vec<String> {
    let res = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::process::Command::new("dig")
            .args(["+short", "+timeout=2", "+tries=1", rrtype, name])
            .output(),
    )
    .await;
    let Ok(Ok(out)) = res else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fixture state-machine input: drive the SPF
    /// classification logic without actually doing DNS. We
    /// pull the classification core into a closure-style test
    /// by exercising `derive_findings` against synthetic state.
    fn classify_spf(record: &str) -> SpfState {
        // Mirror the classification in `check_spf` minus the dig.
        let lower = record.to_lowercase();
        if lower.contains(" -all") || lower.ends_with("-all") {
            SpfState::Strict { record: record.into() }
        } else if lower.contains(" ~all") || lower.ends_with("~all") {
            SpfState::Soft { record: record.into() }
        } else if lower.contains(" +all") || lower.ends_with("+all") {
            SpfState::Permissive { record: record.into() }
        } else if lower.contains(" ?all") || lower.ends_with("?all") {
            SpfState::Neutral { record: record.into() }
        } else {
            SpfState::NoTerminator { record: record.into() }
        }
    }

    #[test]
    fn spf_strict_minus_all() {
        assert!(matches!(
            classify_spf("v=spf1 include:_spf.google.com -all"),
            SpfState::Strict { .. }
        ));
    }

    #[test]
    fn spf_soft_tilde_all() {
        assert!(matches!(
            classify_spf("v=spf1 include:mailgun.org ~all"),
            SpfState::Soft { .. }
        ));
    }

    #[test]
    fn spf_permissive_plus_all_is_critical() {
        // +all is the worst possible SPF — anyone can send.
        assert!(matches!(
            classify_spf("v=spf1 +all"),
            SpfState::Permissive { .. }
        ));
    }

    #[test]
    fn spf_neutral_question_all() {
        assert!(matches!(
            classify_spf("v=spf1 ?all"),
            SpfState::Neutral { .. }
        ));
    }

    #[test]
    fn spf_no_terminator() {
        // Record without any *all qualifier — defaults to ?all
        // at the receiver but we flag it as non-terminator so
        // the operator sees the policy is incomplete.
        assert!(matches!(
            classify_spf("v=spf1 include:_spf.google.com"),
            SpfState::NoTerminator { .. }
        ));
    }

    #[test]
    fn dmarc_state_renders() {
        // Just exercise the enum to ensure variants compile +
        // serde rendering doesn't drift. Real DMARC parsing
        // happens in check_dmarc which is dig-bound.
        let states = vec![
            DmarcState::Missing,
            DmarcState::None { record: "v=DMARC1;p=none".into() },
            DmarcState::Quarantine { record: "p=quarantine".into() },
            DmarcState::Reject { record: "p=reject".into() },
        ];
        for s in &states {
            // Each state must be JSON-serializable round-trip.
            let json = serde_json::to_string(s).unwrap();
            let _: DmarcState = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn derive_findings_flags_missing_spf_high() {
        let mut out = Vec::new();
        derive_findings(
            "example.com",
            &SpfState::Missing,
            &DmarcState::Reject { record: "v=DMARC1;p=reject".into() },
            &MtaStsState::Present { mode: "TXT".into() },
            &DnssecState::Enabled { ds_count: 1 },
            &["selector1".into()],
            &mut out,
        );
        assert!(out.iter().any(|f| f.id == "dns.spf-missing"));
        let spf = out.iter().find(|f| f.id == "dns.spf-missing").unwrap();
        assert_eq!(spf.severity, crate::vuln::Severity::High);
    }

    #[test]
    fn derive_findings_flags_permissive_spf_critical() {
        let mut out = Vec::new();
        derive_findings(
            "example.com",
            &SpfState::Permissive { record: "v=spf1 +all".into() },
            &DmarcState::Reject { record: "v=DMARC1;p=reject".into() },
            &MtaStsState::Present { mode: "TXT".into() },
            &DnssecState::Enabled { ds_count: 1 },
            &["selector1".into()],
            &mut out,
        );
        let spf = out.iter().find(|f| f.id == "dns.spf-permissive").unwrap();
        assert_eq!(spf.severity, crate::vuln::Severity::Critical);
    }

    #[test]
    fn derive_findings_clean_record_produces_no_findings() {
        let mut out = Vec::new();
        derive_findings(
            "example.com",
            &SpfState::Strict { record: "v=spf1 -all".into() },
            &DmarcState::Reject { record: "v=DMARC1;p=reject".into() },
            &MtaStsState::Present { mode: "TXT".into() },
            &DnssecState::Enabled { ds_count: 1 },
            &["selector1".into()],
            &mut out,
        );
        assert!(out.is_empty(), "fully-locked-down DNS should produce no findings");
    }

    #[test]
    fn derive_findings_dkim_missing_emits_finding() {
        let mut out = Vec::new();
        derive_findings(
            "example.com",
            &SpfState::Strict { record: "v=spf1 -all".into() },
            &DmarcState::Reject { record: "v=DMARC1;p=reject".into() },
            &MtaStsState::Present { mode: "TXT".into() },
            &DnssecState::Enabled { ds_count: 1 },
            &[],  // no DKIM selectors
            &mut out,
        );
        assert!(out.iter().any(|f| f.id == "dns.dkim-missing"));
    }
}
