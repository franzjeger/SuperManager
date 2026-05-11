//! Engagement report renderer — Markdown.
//!
//! Aggregates engagement metadata + persisted findings + audit log
//! into a customer-deliverable Markdown document. Frontend can
//! show this in a sheet, copy to clipboard, or save to disk.
//!
//! # Why Markdown
//!
//! Two reasons:
//!   1. **Pandoc-friendly.** The Mac app can shell out to pandoc
//!      later to produce PDF/DOCX without code changes here.
//!   2. **Human-readable as-is.** No styling lock-in — customer
//!      can paste it into their own template.
//!
//! Sections, in order:
//!   1. Title block (engagement title, customer, dates, scope)
//!   2. Executive summary (severity counts, posture)
//!   3. Scope & methodology
//!   4. Findings detail (sorted by severity then first_seen)
//!   5. Resolved during this engagement
//!   6. Audit log
//!   7. Generated-at footer

use anyhow::{Context, Result};
use chrono::Utc;

use crate::engagement::Engagement;
use crate::findings_store::{Disposition, PersistedFinding};
use crate::vuln::Severity;

pub struct ReportInput<'a> {
    pub engagement: &'a Engagement,
    pub customer_slug: Option<&'a str>,
    pub findings: Vec<PersistedFinding>,
}

pub fn render_markdown(input: &ReportInput<'_>) -> Result<String> {
    let mut out = String::new();
    title_block(&mut out, input);
    executive_summary(&mut out, input);
    scope_methodology(&mut out, input);
    findings_section(&mut out, input);
    resolved_section(&mut out, input);
    audit_log(&mut out, input);
    footer(&mut out);
    Ok(out)
}

/// Render the engagement report to PDF via pandoc shell-out.
/// Requires `pandoc` on PATH (probed by `tools::status`) **plus**
/// at least one PDF-engine — `tectonic`, `xelatex`, `pdflatex`,
/// `lualatex`, `wkhtmltopdf`, or `weasyprint` (tried in that order).
/// Returns the PDF bytes — the caller writes to disk via NSSavePanel.
///
/// Temp paths use `tempfile::NamedTempFile` (mode 0o600, random
/// suffix, auto-cleanup on drop) so a local attacker can't symlink-
/// hijack a predictable filename in /tmp.
/// Returns `EngineError::PdfEngineMissing` (downcastable via
/// `anyhow::Error::downcast_ref::<EngineError>`) when no LaTeX /
/// HTML-PDF engine is on PATH. All other failures (timeouts,
/// pandoc-rejected the markdown, tempfile IO) come through as
/// regular `anyhow::Error`. The handler downcasts at the boundary
/// to emit a structured RPC error for the pdf-engine-missing case
/// — that's the case the Mac client wants to handle differently
/// (silent WebKit fallback vs. hard dialog).
pub async fn render_pdf(input: &ReportInput<'_>) -> Result<Vec<u8>> {
    use std::io::Write;
    use std::time::Duration;

    let markdown = render_markdown(input)?;

    // Pick the first available PDF engine. We probe binaries here
    // (rather than at startup) so a freshly-installed `brew install
    // basictex` is picked up without a daemon restart. Ordering:
    //   1. `tectonic`   — self-contained, ~80 MB, "just works"
    //   2. `xelatex`/`lualatex` — Unicode-friendly LaTeX (MacTeX)
    //   3. `pdflatex`   — classic, ASCII-only (BasicTeX)
    //   4. `wkhtmltopdf`/`weasyprint` — HTML→PDF, no LaTeX needed
    let engine = match pick_pdf_engine() {
        Some(e) => e,
        // anyhow::Error::new() wraps the EngineError so the handler
        // can `downcast_ref::<EngineError>()` to recognise this
        // specific case structurally — not by error-message regex.
        None => return Err(anyhow::Error::new(crate::error::EngineError::PdfEngineMissing)),
    };

    // Markdown input — written + closed before invoking pandoc.
    // `NamedTempFile` ships the file mode at 0o600 by default and
    // unlinks on drop even if we panic mid-render.
    let mut in_file = tempfile::Builder::new()
        .prefix("supermgr-report-")
        .suffix(".md")
        .tempfile()
        .context("create temp md")?;
    in_file
        .write_all(markdown.as_bytes())
        .context("write md")?;
    in_file.flush().ok();
    let in_path = in_file.path().to_path_buf();

    // Output path — let pandoc create the file. We hold the
    // tempfile guard so the directory entry is unlinked when this
    // function returns regardless of pandoc's exit status.
    let out_file = tempfile::Builder::new()
        .prefix("supermgr-report-")
        .suffix(".pdf")
        .tempfile()
        .context("create temp pdf")?;
    let out_path = out_file.path().to_path_buf();
    // Pandoc wants to write the file itself — drop our handle so
    // it doesn't fight over the file lock. The directory entry
    // remains; we'll re-read it after pandoc finishes.
    drop(out_file);

    let mut cmd = tokio::process::Command::new("pandoc");
    cmd.args([
        "--from=gfm",
        "--standalone",
        "--metadata",
        &format!("title={}", input.engagement.title),
        "-V",
        "geometry:margin=2cm",
        "-V",
        "colorlinks=true",
    ]);
    cmd.arg(format!("--pdf-engine={engine}"));
    cmd.arg("-o").arg(&out_path).arg(&in_path);

    let res = tokio::time::timeout(Duration::from_secs(60), cmd.output())
        .await
        .context("pandoc timeout")??;

    if !res.status.success() {
        let stderr = String::from_utf8_lossy(&res.stderr);
        // Cleanup the (possibly-empty) output before bailing.
        let _ = std::fs::remove_file(&out_path);
        anyhow::bail!("pandoc ({engine}) failed: {stderr}");
    }

    let bytes = std::fs::read(&out_path)
        .with_context(|| format!("read pdf output {out_path:?}"))?;
    let _ = std::fs::remove_file(&out_path);
    // `in_file` (still held) drops here and unlinks the markdown.
    Ok(bytes)
}

/// Probe PATH + the usual Homebrew/MacTeX prefixes for a usable
/// PDF engine. Returns the engine *name* (not path) so pandoc can
/// resolve it the same way as a manual invocation — we just need
/// to confirm one exists. Order matters: lighter / more-likely
/// engines first.
fn pick_pdf_engine() -> Option<&'static str> {
    const ENGINES: &[&str] = &[
        "tectonic",
        "xelatex",
        "lualatex",
        "pdflatex",
        "wkhtmltopdf",
        "weasyprint",
    ];
    // Same fallback prefixes as `tools::probe_one` — launchd's
    // default PATH misses /opt/homebrew and /Library/TeX/texbin.
    const PREFIXES: &[&str] = &[
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/Library/TeX/texbin",
        "/opt/local/bin",
    ];
    for engine in ENGINES {
        // First check PATH via `which`-like resolution.
        if let Ok(path) = std::env::var("PATH") {
            for dir in path.split(':') {
                let candidate = std::path::Path::new(dir).join(engine);
                if candidate.exists() {
                    return Some(engine);
                }
            }
        }
        // Fallback to known install prefixes.
        for prefix in PREFIXES {
            let candidate = std::path::Path::new(prefix).join(engine);
            if candidate.exists() {
                return Some(engine);
            }
        }
    }
    None
}

/// Render the engagement report to a self-contained HTML document.
/// Used as a fallback when no LaTeX/PDF engine is installed — the
/// Mac client renders this via WKWebView and prints to PDF locally.
///
/// Only depends on `pandoc` itself (no LaTeX), so it always works
/// on a fresh Homebrew install.
pub async fn render_html(input: &ReportInput<'_>) -> Result<String> {
    use std::io::Write;
    use std::time::Duration;

    let markdown = render_markdown(input)?;
    let mut in_file = tempfile::Builder::new()
        .prefix("supermgr-report-")
        .suffix(".md")
        .tempfile()
        .context("create temp md")?;
    in_file.write_all(markdown.as_bytes()).context("write md")?;
    in_file.flush().ok();
    let in_path = in_file.path().to_path_buf();

    let res = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("pandoc")
            .args([
                "--from=gfm",
                "--to=html5",
                "--standalone",
                "--embed-resources",
                "--metadata",
                &format!("title={}", input.engagement.title),
                "--css=data:text/css;base64,",
            ])
            .arg(&in_path)
            .output(),
    )
    .await
    .context("pandoc timeout")??;

    if !res.status.success() {
        let stderr = String::from_utf8_lossy(&res.stderr);
        anyhow::bail!("pandoc html failed: {stderr}");
    }
    let html = String::from_utf8(res.stdout).context("pandoc html output not utf-8")?;
    // Inline a small style block so the WKWebView render looks
    // tidy without an external CSS file. Pandoc emits `<head>`
    // around line 6 — splice ours just before `</head>`.
    let styled = inject_default_style(&html);
    Ok(styled)
}

fn inject_default_style(html: &str) -> String {
    const STYLE: &str = r#"<style>
body{font-family:-apple-system,'Helvetica Neue',Arial,sans-serif;color:#1d1d1f;max-width:780px;margin:2em auto;padding:0 1.5em;line-height:1.55;font-size:11pt}
h1{font-size:24pt;margin-top:0;border-bottom:1px solid #d2d2d7;padding-bottom:0.3em}
h2{font-size:16pt;margin-top:1.6em;border-bottom:1px solid #e5e5ea;padding-bottom:0.2em}
h3{font-size:13pt;margin-top:1.2em}
h4{font-size:11pt;margin-top:1em;color:#0a64f3}
table{border-collapse:collapse;margin:1em 0}
th,td{border:1px solid #d2d2d7;padding:4px 8px;text-align:left;vertical-align:top}
th{background:#f5f5f7}
code{font-family:'SF Mono',Menlo,Consolas,monospace;background:#f5f5f7;padding:1px 4px;border-radius:3px;font-size:10pt}
pre{background:#f5f5f7;padding:8px;border-radius:6px;overflow-x:auto;font-size:9.5pt}
hr{border:0;border-top:1px solid #d2d2d7;margin:2em 0}
@media print{body{margin:0;max-width:none;padding:0 1cm}h1,h2,h3{page-break-after:avoid}}
</style>"#;
    if let Some(idx) = html.find("</head>") {
        let (head, tail) = html.split_at(idx);
        format!("{head}{STYLE}{tail}")
    } else {
        format!("{STYLE}{html}")
    }
}

fn title_block(out: &mut String, input: &ReportInput<'_>) {
    let e = input.engagement;
    out.push_str(&format!("# {}\n\n", e.title));
    out.push_str("| | |\n|---|---|\n");
    if let Some(slug) = input.customer_slug {
        if !slug.is_empty() {
            out.push_str(&format!("| Customer | `{slug}` |\n"));
        }
    }
    out.push_str(&format!(
        "| Engagement ID | `{}` |\n",
        e.id
    ));
    out.push_str(&format!(
        "| Started | {} |\n",
        e.started_at.format("%Y-%m-%d")
    ));
    out.push_str(&format!(
        "| Expires | {} |\n",
        e.expires_at.format("%Y-%m-%d")
    ));
    if !e.authorized_by.is_empty() {
        out.push_str(&format!("| Authorized by | {} |\n", e.authorized_by));
    }
    if !e.scope_cidrs.is_empty() {
        out.push_str(&format!("| Scope CIDRs | {} |\n", e.scope_cidrs.join(", ")));
    }
    if !e.scope_hosts.is_empty() {
        out.push_str(&format!("| Scope hosts | {} |\n", e.scope_hosts.join(", ")));
    }
    if !e.exclusions.is_empty() {
        out.push_str(&format!("| Exclusions | {} |\n", e.exclusions.join(", ")));
    }
    out.push('\n');
}

fn executive_summary(out: &mut String, input: &ReportInput<'_>) {
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;
    let mut accepted = 0u32;
    let mut fixed = 0u32;
    let mut open = 0u32;
    for f in &input.findings {
        match &f.disposition {
            Disposition::Open => {
                open += 1;
                match f.finding.severity {
                    Severity::Critical => critical += 1,
                    Severity::High => high += 1,
                    Severity::Medium => medium += 1,
                    Severity::Low => low += 1,
                    Severity::Info => {}
                }
            }
            Disposition::AcceptedRisk { .. } => accepted += 1,
            Disposition::Fixed { .. } => fixed += 1,
            Disposition::FalsePositive { .. } => {}
        }
    }

    out.push_str("## Executive summary\n\n");
    out.push_str(&format!(
        "{open} open finding(s): **{critical} Critical**, **{high} High**, \
         {medium} Medium, {low} Low. \
         {accepted} accepted-risk, {fixed} resolved.\n\n"
    ));

    let posture = if critical > 0 {
        "**Critical**. Remediate Critical findings within 7 days."
    } else if high > 0 {
        "**Elevated**. Remediate High findings within 30 days."
    } else if medium > 0 {
        "**Moderate**. Address Medium findings as part of normal hygiene."
    } else if open > 0 {
        "**Acceptable**. Only Low findings remain — informational hardening."
    } else {
        "**Clean**. No outstanding findings."
    };
    out.push_str(&format!("Posture: {posture}\n\n"));
}

fn scope_methodology(out: &mut String, input: &ReportInput<'_>) {
    let e = input.engagement;
    out.push_str("## Scope & methodology\n\n");
    out.push_str(
        "Active discovery, banner-grab + service fingerprinting, \
         TLS audit, CVE matching against banner versions, and \
         configuration checks against well-known misconfigurations. \
         Default-credential testing where the engagement permits.\n\n",
    );
    out.push_str("Permitted techniques for this engagement:\n");
    if e.allowed_techniques.is_empty() {
        out.push_str("- _(none specified)_\n");
    } else {
        for t in &e.allowed_techniques {
            out.push_str(&format!("- {}\n", technique_label(t)));
        }
    }
    out.push('\n');
}

fn technique_label(t: &crate::engagement::Technique) -> &'static str {
    use crate::engagement::Technique::*;
    match t {
        Recon => "Reconnaissance (passive discovery, ARP, mDNS)",
        Discovery => "Active discovery (TCP sweep, banner-grab)",
        VulnScan => "Vulnerability scan (CVE matching)",
        TlsAudit => "TLS audit",
        CredTest => "Default-credential testing",
        WebExploit => "Web testing",
        SmbEnum => "SMB enumeration",
        SnmpRead => "SNMP read",
        Wireless => "Wireless (reserved)",
        DosTest => "DoS testing (reserved)",
    }
}

fn findings_section(out: &mut String, input: &ReportInput<'_>) {
    let open: Vec<&PersistedFinding> = input
        .findings
        .iter()
        .filter(|f| matches!(f.disposition, Disposition::Open))
        .collect();
    out.push_str("## Open findings\n\n");
    if open.is_empty() {
        out.push_str("_No open findings._\n\n");
        return;
    }
    let mut by_sev: std::collections::BTreeMap<u8, Vec<&PersistedFinding>> = Default::default();
    for f in &open {
        by_sev.entry(sev_rank(&f.finding.severity)).or_default().push(f);
    }
    for (rank, group) in by_sev {
        out.push_str(&format!("### {}\n\n", sev_heading(rank)));
        for f in group {
            render_finding(out, f);
        }
    }

    // Accepted risk summary
    let accepted: Vec<&PersistedFinding> = input
        .findings
        .iter()
        .filter(|f| matches!(f.disposition, Disposition::AcceptedRisk { .. }))
        .collect();
    if !accepted.is_empty() {
        out.push_str("## Accepted risk\n\n");
        out.push_str(
            "Findings explicitly accepted by the customer. Tracked but \
             excluded from the open-finding count above.\n\n",
        );
        for f in accepted {
            if let Disposition::AcceptedRisk { reason, until } = &f.disposition {
                out.push_str(&format!(
                    "- **{}** on `{}`",
                    f.finding.title, f.finding.host_ip
                ));
                if let Some(u) = until {
                    out.push_str(&format!(" — until {}", u.format("%Y-%m-%d")));
                }
                if !reason.is_empty() {
                    out.push_str(&format!(" — _{reason}_"));
                }
                out.push('\n');
            }
        }
        out.push('\n');
    }
}

fn render_finding(out: &mut String, f: &PersistedFinding) {
    let cve = f
        .finding
        .cve
        .as_deref()
        .map(|c| format!(" `{c}`"))
        .unwrap_or_default();
    let cvss = f
        .finding
        .cvss
        .map(|c| format!(" (CVSS {c:.1})"))
        .unwrap_or_default();
    out.push_str(&format!(
        "#### {}{}{}\n\n",
        f.finding.title, cve, cvss
    ));
    out.push_str(&format!(
        "- Host: `{}`{}\n",
        f.finding.host_ip,
        f.finding
            .port
            .map(|p| format!(" — port {p}"))
            .unwrap_or_default(),
    ));
    out.push_str(&format!(
        "- First seen: {}\n",
        f.first_seen.format("%Y-%m-%d")
    ));
    out.push_str(&format!(
        "- Last seen: {} (across {} scan(s))\n",
        f.last_seen.format("%Y-%m-%d"),
        f.scan_count
    ));
    let age_days = (Utc::now() - f.first_seen).num_days();
    if age_days > 0 {
        out.push_str(&format!("- Open for: {age_days} days\n"));
    }
    out.push('\n');
    out.push_str(&format!("**Detail.** {}\n\n", f.finding.detail));
    out.push_str(&format!(
        "**Recommendation.** {}\n\n",
        f.finding.recommendation
    ));
    if !f.note.is_empty() {
        out.push_str(&format!("**Note.** {}\n\n", f.note));
    }
}

fn resolved_section(out: &mut String, input: &ReportInput<'_>) {
    let resolved: Vec<&PersistedFinding> = input
        .findings
        .iter()
        .filter(|f| matches!(f.disposition, Disposition::Fixed { .. }))
        .collect();
    if resolved.is_empty() {
        return;
    }
    out.push_str("## Resolved\n\n");
    out.push_str(&format!(
        "{} finding(s) resolved during the engagement window.\n\n",
        resolved.len()
    ));
    out.push_str("| Severity | Title | Host | Resolved |\n");
    out.push_str("|---|---|---|---|\n");
    for f in resolved {
        out.push_str(&format!(
            "| {} | {} | `{}` | {} |\n",
            sev_label(&f.finding.severity),
            f.finding.title,
            f.finding.host_ip,
            f.last_seen.format("%Y-%m-%d"),
        ));
    }
    out.push('\n');
}

fn audit_log(out: &mut String, input: &ReportInput<'_>) {
    let log = &input.engagement.log;
    if log.is_empty() {
        return;
    }
    out.push_str("## Audit log\n\n");
    out.push_str("| When | Technique | Action | Findings | Notes |\n");
    out.push_str("|---|---|---|---|---|\n");
    for ev in log.iter().rev().take(50) {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            ev.at.format("%Y-%m-%d %H:%M"),
            technique_label(&ev.technique),
            ev.action,
            ev.findings,
            ev.notes,
        ));
    }
    out.push('\n');
}

fn footer(out: &mut String) {
    out.push_str(&format!(
        "---\n\nGenerated {} by SuperManager.\n",
        Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));
}

fn sev_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn sev_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn sev_heading(rank: u8) -> &'static str {
    match rank {
        0 => "Critical",
        1 => "High",
        2 => "Medium",
        3 => "Low",
        _ => "Informational",
    }
}
