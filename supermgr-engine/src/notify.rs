//! Notification hooks — Slack-compatible incoming webhooks.
//!
//! Triggered after `findings_store::reconcile()` produces a diff
//! that contains Critical or High severity new/regressed findings.
//! We deliberately don't notify on every scan — only when something
//! actually changes for the worse.
//!
//! # Webhook format
//!
//! Standard Slack incoming-webhook JSON. Compatible with:
//!   - Slack
//!   - Mattermost
//!   - Discord (with /slack suffix)
//!   - Most chat platforms that accept Slack-shaped payloads.
//!
//! Webhook URL is read from `~/.config/supermanager/notify.toml`
//! (per-customer mapping) so each customer can have its own
//! channel. Missing config = no-op.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::findings_store::{PersistedFinding, ScanDiff};
use crate::vuln::Severity;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyConfig {
    /// Per-customer-slug → Slack/Mattermost incoming webhook URL.
    #[serde(default)]
    pub webhooks: std::collections::HashMap<String, String>,
    /// Per-customer-slug → PagerDuty Events API v2 routing key.
    /// When set, Critical findings (and Critical regressions) page
    /// the on-call rota in addition to any Slack notification.
    #[serde(default)]
    pub pagerduty_keys: std::collections::HashMap<String, String>,
    /// Per-customer-slug → OpsGenie Genie API key. Same routing
    /// behaviour as PagerDuty — Critical findings escalate.
    #[serde(default)]
    pub opsgenie_keys: std::collections::HashMap<String, String>,
}

fn config_path() -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("notify.toml");
    p
}

pub fn load_config() -> NotifyConfig {
    let path = config_path();
    if !path.exists() {
        return NotifyConfig::default();
    }
    match std::fs::read_to_string(&path) {
        Ok(s) => toml::from_str(&s).unwrap_or_default(),
        Err(_) => NotifyConfig::default(),
    }
}

pub fn save_config(cfg: &NotifyConfig) -> Result<()> {
    let path = config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let s = toml::to_string_pretty(cfg).context("serialize notify config")?;
    std::fs::write(&path, s).with_context(|| format!("write {path:?}"))?;
    Ok(())
}

/// Send a digest notification for a `ScanDiff` to the customer's
/// configured webhook. No-op if no webhook is configured or if
/// the diff contains no Critical/High items in the new/regressed
/// buckets (we don't spam the channel for noise).
pub async fn notify_scan_diff(customer_slug: &str, diff: &ScanDiff) -> Result<bool> {
    let cfg = load_config();

    // Identify the alarming subset early — we use it for both
    // Slack digest + PagerDuty/OpsGenie escalation routing.
    let critical_or_high = |f: &PersistedFinding| {
        matches!(f.finding.severity, Severity::Critical | Severity::High)
    };
    let alarming_new: Vec<&PersistedFinding> =
        diff.new_findings.iter().filter(|f| critical_or_high(f)).collect();
    let alarming_regressed: Vec<&PersistedFinding> =
        diff.regressed.iter().filter(|f| critical_or_high(f)).collect();

    if alarming_new.is_empty() && alarming_regressed.is_empty() {
        return Ok(false);
    }

    // PagerDuty + OpsGenie fire in parallel with Slack — they're
    // independent transports and one failing shouldn't block
    // the other.
    if let Some(key) = cfg.pagerduty_keys.get(customer_slug).cloned() {
        let critical_only: Vec<&PersistedFinding> = alarming_new
            .iter()
            .chain(alarming_regressed.iter())
            .filter(|f| matches!(f.finding.severity, Severity::Critical))
            .copied()
            .collect();
        // Only page on Critical (PagerDuty pages a human; High
        // findings stay in Slack so we don't wake people for
        // <Critical signal).
        if !critical_only.is_empty() {
            if let Err(e) = pagerduty_event(&key, customer_slug, &critical_only).await {
                tracing::warn!("pagerduty event failed for {customer_slug}: {e:#}");
            }
        }
    }
    if let Some(key) = cfg.opsgenie_keys.get(customer_slug).cloned() {
        let critical_only: Vec<&PersistedFinding> = alarming_new
            .iter()
            .chain(alarming_regressed.iter())
            .filter(|f| matches!(f.finding.severity, Severity::Critical))
            .copied()
            .collect();
        if !critical_only.is_empty() {
            if let Err(e) = opsgenie_alert(&key, customer_slug, &critical_only).await {
                tracing::warn!("opsgenie alert failed for {customer_slug}: {e:#}");
            }
        }
    }

    let Some(url) = cfg.webhooks.get(customer_slug).cloned() else {
        // No Slack webhook configured. PagerDuty/OpsGenie may
        // still have fired above — return true if EITHER pinged.
        let any_paged = cfg.pagerduty_keys.contains_key(customer_slug)
            || cfg.opsgenie_keys.contains_key(customer_slug);
        return Ok(any_paged);
    };
    // Webhooks must be HTTPS — sending finding details over
    // plain HTTP would leak Critical findings + customer scope
    // in transit. A misconfigured webhook URL gets rejected here.
    if !url.starts_with("https://") {
        anyhow::bail!("webhook URL must use https://");
    }

    let payload = build_payload(customer_slug, diff, &alarming_new, &alarming_regressed);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build notify client")?;
    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .context("post webhook")?;
    if !resp.status().is_success() {
        anyhow::bail!("webhook returned {}", resp.status());
    }
    Ok(true)
}

fn build_payload(
    customer_slug: &str,
    diff: &ScanDiff,
    new_alarming: &[&PersistedFinding],
    regressed: &[&PersistedFinding],
) -> serde_json::Value {
    let mut text = format!(
        "*SuperManager scan — {customer_slug}*\n\
         {} new finding(s), {} regressed, {} still open, {} auto-resolved",
        diff.new_findings.len(),
        diff.regressed.len(),
        diff.still_open.len(),
        diff.auto_resolved.len()
    );

    if !new_alarming.is_empty() {
        text.push_str("\n\n*New Critical/High:*");
        for f in new_alarming.iter().take(8) {
            text.push_str(&format!(
                "\n• `{}` {}{} — {}",
                f.finding.host_ip,
                f.finding
                    .port
                    .map(|p| format!(":{p} "))
                    .unwrap_or_default(),
                severity_emoji(&f.finding.severity),
                f.finding.title
            ));
        }
        if new_alarming.len() > 8 {
            text.push_str(&format!("\n…and {} more", new_alarming.len() - 8));
        }
    }
    if !regressed.is_empty() {
        text.push_str("\n\n*Regressions (re-detected after fix):*");
        for f in regressed.iter().take(5) {
            text.push_str(&format!(
                "\n• `{}` — {}",
                f.finding.host_ip, f.finding.title
            ));
        }
    }

    serde_json::json!({ "text": text })
}

fn severity_emoji(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => ":rotating_light:",
        Severity::High => ":warning:",
        Severity::Medium => ":large_yellow_circle:",
        Severity::Low => ":large_blue_circle:",
        Severity::Info => ":information_source:",
    }
}

/// PagerDuty Events API v2 — fires a `trigger` event with one
/// summary per finding. The dedup_key folds repeated detections
/// of the same finding into a single PD incident so we don't
/// fan-out 1 incident per scan.
async fn pagerduty_event(
    routing_key: &str,
    customer_slug: &str,
    findings: &[&PersistedFinding],
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build pagerduty client")?;

    for f in findings {
        let dedup_key = format!("supermgr:{customer_slug}:{}", f.key);
        let payload = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": format!("[{}] {} — {}", customer_slug, f.finding.title, f.finding.host_ip),
                "severity": "critical",
                "source": f.finding.host_ip,
                "component": f.finding.service.as_deref().unwrap_or("unknown"),
                "class": "supermgr-finding",
                "custom_details": {
                    "cve": f.finding.cve,
                    "cvss": f.finding.cvss,
                    "first_seen": f.first_seen,
                    "scan_count": f.scan_count,
                    "recommendation": f.finding.recommendation,
                },
            },
        });
        let resp = client
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&payload)
            .send()
            .await
            .context("post pagerduty")?;
        if !resp.status().is_success() {
            anyhow::bail!("pagerduty returned {}", resp.status());
        }
    }
    Ok(())
}

/// OpsGenie Alert API. Same as PagerDuty: one alert per finding,
/// alias = stable dedup-key so re-detections fold into the
/// existing alert.
async fn opsgenie_alert(
    api_key: &str,
    customer_slug: &str,
    findings: &[&PersistedFinding],
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build opsgenie client")?;

    for f in findings {
        let alias = format!("supermgr-{customer_slug}-{}", f.key);
        let payload = serde_json::json!({
            "message": format!("[{}] {}", customer_slug, f.finding.title),
            "alias": alias,
            "description": format!(
                "{}\n\nHost: {}\nCVE: {}\nFirst seen: {}\nRecommendation: {}",
                f.finding.detail,
                f.finding.host_ip,
                f.finding.cve.as_deref().unwrap_or("—"),
                f.first_seen,
                f.finding.recommendation,
            ),
            "priority": "P1",
            "tags": ["supermgr", customer_slug, "critical"],
            "details": {
                "cvss": f.finding.cvss.map(|c| format!("{c:.1}")).unwrap_or_default(),
                "scan_count": f.scan_count.to_string(),
            },
        });
        let resp = client
            .post("https://api.opsgenie.com/v2/alerts")
            .header("Authorization", format!("GenieKey {api_key}"))
            .json(&payload)
            .send()
            .await
            .context("post opsgenie")?;
        if !resp.status().is_success() {
            anyhow::bail!("opsgenie returned {}", resp.status());
        }
    }
    Ok(())
}
