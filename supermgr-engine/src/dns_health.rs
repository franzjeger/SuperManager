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
    /// Names of lookups that could not be completed (timeout, spawn
    /// failure, non-zero exit). A finding for a check in this list is
    /// intentionally NOT emitted — an absent record and a failed query
    /// must not be reported the same way, or a transient DNS outage is
    /// indistinguishable from "SPF/DNSSEC missing" and gets shipped to
    /// the customer and `PagerDuty` as a real gap.
    #[serde(default)]
    pub query_failures: Vec<String>,
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
    let ((spf, spf_err), (dmarc, dmarc_err), (mta_sts, mta_err), (dnssec, dnssec_err), (mx, mx_err), dkim) =
        tokio::join!(
            check_spf(domain),
            check_dmarc(domain),
            check_mta_sts(domain),
            check_dnssec(domain),
            list_mx(domain),
            find_dkim_selectors(domain),
        );

    // A check whose lookup failed is recorded, not reported as a gap.
    let mut query_failures: Vec<String> = Vec::new();
    if let Some(ref e) = spf_err { query_failures.push(format!("spf: {e}")); }
    if let Some(ref e) = dmarc_err { query_failures.push(format!("dmarc: {e}")); }
    if let Some(ref e) = mta_err { query_failures.push(format!("mta-sts: {e}")); }
    if let Some(ref e) = dnssec_err { query_failures.push(format!("dnssec: {e}")); }
    if let Some(ref e) = mx_err { query_failures.push(format!("mx: {e}")); }
    if !dkim.any_succeeded {
        if let Some(ref e) = dkim.first_error { query_failures.push(format!("dkim: {e}")); }
    }

    let mut findings: Vec<Finding> = Vec::new();
    derive_findings(
        domain,
        &spf,
        &dmarc,
        &mta_sts,
        &dnssec,
        &dkim,
        DnsCheckFailures {
            spf: spf_err.is_some(),
            dmarc: dmarc_err.is_some(),
            mta_sts: mta_err.is_some(),
            dnssec: dnssec_err.is_some(),
        },
        &mut findings,
    );

    DnsHealthReport {
        domain: domain.to_owned(),
        spf,
        dkim_selectors_found: dkim.found,
        dmarc,
        mta_sts,
        dnssec,
        mx_records: mx,
        findings,
        query_failures,
    }
}

// ---------------------------------------------------------------------------
// Per-record checks
// ---------------------------------------------------------------------------

async fn check_spf(domain: &str) -> (SpfState, Option<DigError>) {
    let txt = match dig_txt(domain).await {
        Ok(t) => t,
        Err(e) => return (SpfState::Missing, Some(e)),
    };
    let spf: Vec<String> = txt
        .iter()
        .filter(|r| r.to_lowercase().starts_with("v=spf1"))
        .cloned()
        .collect();
    if spf.is_empty() {
        return (SpfState::Missing, None);
    }
    if spf.len() > 1 {
        return (SpfState::Multiple { records: spf }, None);
    }
    let record = spf.into_iter().next().unwrap();
    let lower = record.to_lowercase();
    let state = if lower.contains(" -all") || lower.ends_with("-all") {
        SpfState::Strict { record }
    } else if lower.contains(" ~all") || lower.ends_with("~all") {
        SpfState::Soft { record }
    } else if lower.contains(" +all") || lower.ends_with("+all") {
        SpfState::Permissive { record }
    } else if lower.contains(" ?all") || lower.ends_with("?all") {
        SpfState::Neutral { record }
    } else {
        SpfState::NoTerminator { record }
    };
    (state, None)
}

async fn check_dmarc(domain: &str) -> (DmarcState, Option<DigError>) {
    let target = format!("_dmarc.{domain}");
    let records: Vec<String> = match dig_txt(&target).await {
        Ok(r) => r,
        Err(e) => return (DmarcState::Missing, Some(e)),
    }
    .into_iter()
    .filter(|r| r.to_lowercase().contains("v=dmarc1"))
    .collect();
    let Some(record) = records.into_iter().next() else {
        return (DmarcState::Missing, None);
    };
    let state = match dmarc_policy(&record).as_str() {
        "reject" => DmarcState::Reject { record },
        "quarantine" => DmarcState::Quarantine { record },
        _ => DmarcState::None { record },
    };
    (state, None)
}

/// Extract the apex DMARC policy (`p` tag) from a record string.
///
/// DMARC records are `;`-separated tags (`v=DMARC1; p=none; sp=reject; …`).
/// We match the `p` key exactly — a substring check like
/// `contains("p=reject")` would also fire on `sp=reject` and report a
/// monitor-only domain as rejecting. Returns the empty string when the
/// record has no `p` tag.
fn dmarc_policy(record: &str) -> String {
    record
        .split(';')
        .find_map(|tag| {
            let tag = tag.trim();
            let (k, v) = tag.split_once('=')?;
            (k.trim().eq("p")).then_some(v.trim().to_lowercase())
        })
        .unwrap_or_default()
}

async fn check_mta_sts(domain: &str) -> (MtaStsState, Option<DigError>) {
    let target = format!("_mta-sts.{domain}");
    let records: Vec<String> = match dig_txt(&target).await {
        Ok(r) => r,
        Err(e) => return (MtaStsState::Missing, Some(e)),
    };
    let mta = records.iter().find(|r| r.to_lowercase().contains("v=stsv1"));
    match mta {
        None => (MtaStsState::Missing, None),
        Some(r) => {
            // Mode is set in the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt,
            // but the TXT record only confirms the policy version + ID.
            // We surface the TXT presence; mode would need an HTTP fetch.
            let _ = r;
            (MtaStsState::Present { mode: "TXT-published".into() }, None)
        }
    }
}

async fn check_dnssec(domain: &str) -> (DnssecState, Option<DigError>) {
    // DS records live at the parent zone — `dig DS <domain>` asks
    // the parent. Count of records ≥ 1 indicates DNSSEC delegation.
    let res = match dig(domain, "DS").await {
        Ok(r) => r,
        Err(e) => return (DnssecState::Disabled, Some(e)),
    };
    let count = u32::try_from(res.iter().filter(|line| !line.is_empty()).count()).unwrap_or(u32::MAX);
    let state = if count == 0 {
        DnssecState::Disabled
    } else {
        DnssecState::Enabled { ds_count: count }
    };
    (state, None)
}

async fn list_mx(domain: &str) -> (Vec<String>, Option<DigError>) {
    match dig(domain, "MX").await {
        Ok(r) => (r, None),
        Err(e) => (Vec::new(), Some(e)),
    }
}

/// DKIM probe result. `any_succeeded` distinguishes "we looked and found
/// nothing" (a real gap) from "every probe failed" (a DNS outage — not a
/// gap).
struct DkimProbe {
    found: Vec<String>,
    any_succeeded: bool,
    first_error: Option<DigError>,
}

async fn find_dkim_selectors(domain: &str) -> DkimProbe {
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
    let mut any_succeeded = false;
    let mut first_error: Option<DigError> = None;
    for sel in SELECTORS {
        let target = format!("{sel}._domainkey.{domain}");
        match dig_txt(&target).await {
            Ok(txt) => {
                any_succeeded = true;
                if txt.iter().any(|r| r.to_lowercase().contains("v=dkim1")) {
                    found.push((*sel).to_owned());
                }
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }
    DkimProbe { found, any_succeeded, first_error }
}

// ---------------------------------------------------------------------------
// Findings derivation — turn states into customer-facing recommendations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
struct DnsCheckFailures {
    spf: bool,
    dmarc: bool,
    mta_sts: bool,
    dnssec: bool,
}

fn derive_findings(
    domain: &str,
    spf: &SpfState,
    dmarc: &DmarcState,
    mta_sts: &MtaStsState,
    dnssec: &DnssecState,
    dkim: &DkimProbe,
    failures: DnsCheckFailures,
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

    // --- SPF --- (suppressed if the lookup itself failed)
    if !failures.spf {
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
    }

    // --- DMARC --- (suppressed if the lookup itself failed)
    if !failures.dmarc {
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
    }

    // --- DKIM --- (suppressed if every probe failed — a DNS outage is not a gap)
    if dkim.any_succeeded && dkim.found.is_empty() {
        out.push(mk(
            "dns.dkim-missing",
            Severity::Medium,
            5.0,
            format!("No DKIM selectors found for {domain}"),
            "We probed common selectors (selector1/selector2, google, k1, etc.) and found none. Either DKIM uses a custom selector we didn't try, or DKIM signing is genuinely missing.".into(),
            "Verify DKIM with `dig TXT <selector>._domainkey.{domain}`. Configure DKIM via your mail provider (M365 Defender, Google Admin SDK, etc.).".into(),
        ));
    }

    // --- MTA-STS --- (suppressed if the lookup itself failed)
    if !failures.mta_sts && matches!(mta_sts, MtaStsState::Missing) {
        out.push(mk(
            "dns.mta-sts-missing",
            Severity::Low,
            3.5,
            format!("No MTA-STS policy published for {domain}"),
            "MTA-STS forces SMTP delivery to use TLS to your published MX hosts. Without it, an active attacker can downgrade SMTP to plaintext.".into(),
            "Publish `_mta-sts.{domain}` TXT record + the policy file at `https://mta-sts.{domain}/.well-known/mta-sts.txt`. Start with `mode: testing`.".into(),
        ));
    }

    // --- DNSSEC --- (suppressed if the lookup itself failed)
    if !failures.dnssec && matches!(dnssec, DnssecState::Disabled) {
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

async fn dig_txt(name: &str) -> Result<Vec<String>, DigError> {
    let lines = dig(name, "TXT").await?;
    // dig +short TXT returns lines like:
    //   "v=spf1 include:_spf.google.com -all"
    // Each value is double-quoted; multi-string TXTs come as several
    // adjacent quoted segments. Strip and concatenate.
    Ok(lines
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
        .collect())
}

/// A `dig` lookup that could not be completed. Kept as a plain string so
/// the report can carry it verbatim; the cause is one of timeout, spawn
/// failure, or a non-zero exit (SERVFAIL / NXDOMAIN handled by the caller).
type DigError = String;

async fn dig(name: &str, rrtype: &str) -> Result<Vec<String>, DigError> {
    let res = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::process::Command::new("dig")
            .args(["+short", "+timeout=2", "+tries=1", rrtype, name])
            .output(),
    )
    .await;
    let out = match res {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => return Err(format!("dig {rrtype} {name}: {e}")),
        Err(_) => return Err(format!("dig {rrtype} {name}: timed out after 4s")),
    };
    if !out.status.success() {
        let code = out.status.code().unwrap_or(-1);
        return Err(format!("dig {rrtype} {name}: exit {code}"));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
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
    fn dmarc_policy_matches_the_p_tag_not_sp() {
        // The apex policy is the `p` tag. A substring match on "p=reject"
        // would wrongly fire on `sp=reject` (subdomain policy) and report a
        // monitor-only domain as rejecting.
        assert_eq!(dmarc_policy("v=DMARC1; p=none; sp=reject"), "none");
        assert_eq!(dmarc_policy("v=DMARC1; p=quarantine; sp=reject"), "quarantine");
        assert_eq!(dmarc_policy("v=DMARC1; p=reject; sp=none"), "reject");
        assert_eq!(dmarc_policy("v=DMARC1; p=REJECT"), "reject");
        assert_eq!(dmarc_policy("v=DMARC1; sp=reject"), ""); // no apex policy
        assert_eq!(dmarc_policy("v=DMARC1; p = reject"), "reject"); // spaces
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

    fn dkim(found: Vec<String>, any_succeeded: bool) -> DkimProbe {
        DkimProbe { found, any_succeeded, first_error: None }
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
            &dkim(vec!["selector1".into()], true),
            DnsCheckFailures::default(),
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
            &dkim(vec!["selector1".into()], true),
            DnsCheckFailures::default(),
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
            &dkim(vec!["selector1".into()], true),
            DnsCheckFailures::default(),
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
            &dkim(Vec::new(), true),  // probes succeeded, none found
            DnsCheckFailures::default(),
            &mut out,
        );
        assert!(out.iter().any(|f| f.id == "dns.dkim-missing"));
    }

    #[test]
    fn derive_findings_suppresses_spf_when_lookup_failed() {
        // A failed SPF lookup must NOT be reported as "SPF missing".
        let mut out = Vec::new();
        derive_findings(
            "example.com",
            &SpfState::Missing,
            &DmarcState::Reject { record: "v=DMARC1;p=reject".into() },
            &MtaStsState::Present { mode: "TXT".into() },
            &DnssecState::Enabled { ds_count: 1 },
            &dkim(vec!["selector1".into()], true),
            DnsCheckFailures { spf: true, ..Default::default() },
            &mut out,
        );
        assert!(!out.iter().any(|f| f.id == "dns.spf-missing"));
    }

    #[test]
    fn derive_findings_suppresses_dkim_when_all_probes_failed() {
        // Every DKIM probe failed (DNS outage) — not a gap, no finding.
        let mut out = Vec::new();
        derive_findings(
            "example.com",
            &SpfState::Strict { record: "v=spf1 -all".into() },
            &DmarcState::Reject { record: "v=DMARC1;p=reject".into() },
            &MtaStsState::Present { mode: "TXT".into() },
            &DnssecState::Enabled { ds_count: 1 },
            &dkim(Vec::new(), false),  // no probe succeeded
            DnsCheckFailures::default(),
            &mut out,
        );
        assert!(!out.iter().any(|f| f.id == "dns.dkim-missing"));
    }
}
