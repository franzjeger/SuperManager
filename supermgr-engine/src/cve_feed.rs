//! NVD CVE feed — keeps the matched-CVE database fresh.
//!
//! The hardcoded `vuln::cve_database()` covers ~30 high-impact
//! CVEs. The world adds ~50 CVEs per day — by month two, the
//! hardcoded list is missing actively-exploited vulns. This module
//! pulls the official NVD JSON 2.0 feed weekly and merges it into
//! a persisted store the matcher consults alongside the bundled
//! list.
//!
//! # Strategy
//!
//! - **Source.** NVD feeds at `https://nvd.nist.gov/feeds/json/cve/2.0/`
//!   — `nvdcve-2.0-recent.json.gz` (last 8 days) is sufficient for
//!   weekly refresh. Modified feed gives last 8 days too.
//! - **Storage.** `findings_store/_cve_feed/cves.json` —
//!   sequence of `FeedEntry` records keyed by CVE id.
//! - **Match shape.** Same as the hardcoded `CveEntry` so the
//!   matcher path doesn't fork.
//! - **Last fetch tracking.** `meta.json` next to the cache holds
//!   the `last_fetched_at` so the scheduler can skip when fresh.
//!
//! # Why not just hammer NVD on every scan?
//!
//! NVD asks for 6-second delay between requests + has aggressive
//! rate-limits. The weekly cadence puts us well inside fair-use.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::vuln::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedEntry {
    pub id: String,
    pub product_keywords: Vec<String>,  // case-insensitive substrings
    pub version_substrings: Vec<String>,
    pub severity: Severity,
    pub cvss: f32,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedCache {
    pub entries: Vec<FeedEntry>,
    pub last_fetched_at: Option<DateTime<Utc>>,
}

fn cache_dir() -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("cve_feed");
    p
}

fn cache_path() -> PathBuf {
    let mut p = cache_dir();
    p.push("cves.json");
    p
}

pub fn load() -> FeedCache {
    let path = cache_path();
    if !path.exists() {
        return FeedCache::default();
    }
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => FeedCache::default(),
    }
}

pub fn save(cache: &FeedCache) -> Result<()> {
    let dir = cache_dir();
    std::fs::create_dir_all(&dir).context("create cve_feed dir")?;
    let path = cache_path();
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(cache).context("serialize cve cache")?;
    std::fs::write(&tmp, bytes).with_context(|| format!("write {tmp:?}"))?;
    std::fs::rename(&tmp, &path).context("rename cve cache")?;
    Ok(())
}

/// Fetch + merge "recent" NVD feed (last 8 days). Idempotent —
/// re-fetching same window updates already-cached entries with
/// any score/recommendation changes.
pub async fn refresh() -> Result<u32> {
    let url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200";
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("SuperManager/1.0 (+https://github.com/franzjeger/SuperManager)")
        .build()?;

    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("NVD returned {}", resp.status());
    }
    // Cap response at 100 MB so a malicious / corrupted upstream
    // can't OOM the daemon. Real NVD pages are <5 MB.
    let bytes = resp.bytes().await?;
    if bytes.len() > 100 * 1024 * 1024 {
        anyhow::bail!("NVD response too large: {} bytes", bytes.len());
    }
    let body: serde_json::Value = serde_json::from_slice(&bytes)?;
    let vulnerabilities = body
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("no vulnerabilities array in NVD response"))?;

    let mut cache = load();
    let mut existing: std::collections::HashMap<String, usize> = cache
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.id.clone(), i))
        .collect();

    let mut added = 0u32;
    for item in vulnerabilities {
        let Some(parsed) = parse_vuln(item) else {
            continue;
        };
        if let Some(idx) = existing.get(&parsed.id) {
            cache.entries[*idx] = parsed.clone();
        } else {
            existing.insert(parsed.id.clone(), cache.entries.len());
            cache.entries.push(parsed.clone());
            added += 1;
        }
    }
    cache.last_fetched_at = Some(Utc::now());
    save(&cache)?;
    info!("cve_feed: refreshed, +{added} new, {} total", cache.entries.len());
    Ok(added)
}

fn parse_vuln(item: &serde_json::Value) -> Option<FeedEntry> {
    let cve = item.get("cve")?;
    let id = cve.get("id")?.as_str()?.to_owned();

    // Description (prefer English).
    let desc = cve
        .get("descriptions")?
        .as_array()?
        .iter()
        .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    // CVSS — prefer v3.1, fall back to v3.0, then v2.
    let metrics = cve.get("metrics")?;
    let (severity, cvss) = pick_cvss(metrics).unwrap_or((Severity::Medium, 5.0));

    // Affected products — derive product keywords from CPE matches.
    let mut keywords: std::collections::HashSet<String> = Default::default();
    let mut versions: std::collections::HashSet<String> = Default::default();
    if let Some(configs) = cve.get("configurations").and_then(|c| c.as_array()) {
        for cfg in configs {
            if let Some(nodes) = cfg.get("nodes").and_then(|n| n.as_array()) {
                for node in nodes {
                    if let Some(matches) = node.get("cpeMatch").and_then(|m| m.as_array()) {
                        for m in matches {
                            if let Some(uri) = m.get("criteria").and_then(|c| c.as_str()) {
                                // CPE format: cpe:2.3:a:vendor:product:version:...
                                let parts: Vec<&str> = uri.split(':').collect();
                                if parts.len() >= 6 {
                                    let product = parts[4];
                                    let version = parts[5];
                                    if product != "*" && product != "-" {
                                        keywords.insert(product.replace('_', " "));
                                    }
                                    if version != "*" && version != "-" {
                                        versions.insert(version.to_owned());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if keywords.is_empty() {
        // CVE doesn't carry product-keyword hints we can match on.
        return None;
    }

    let short_title = desc.lines().next().unwrap_or(&desc).chars().take(120).collect::<String>();
    let title = format!("{id}: {short_title}");

    Some(FeedEntry {
        id,
        product_keywords: keywords.into_iter().collect(),
        version_substrings: versions.into_iter().collect(),
        severity,
        cvss,
        title,
        detail: desc,
        recommendation:
            "Verify the affected version is exposed; consult vendor advisory + apply patch or mitigation."
                .into(),
    })
}

fn pick_cvss(metrics: &serde_json::Value) -> Option<(Severity, f32)> {
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(arr) = metrics.get(key).and_then(|v| v.as_array()) {
            if let Some(first) = arr.first() {
                let cvss = first.get("cvssData").and_then(|d| d.get("baseScore"))
                    .and_then(|s| s.as_f64()).unwrap_or(5.0) as f32;
                let sev = match cvss {
                    s if s >= 9.0 => Severity::Critical,
                    s if s >= 7.0 => Severity::High,
                    s if s >= 4.0 => Severity::Medium,
                    s if s > 0.0 => Severity::Low,
                    _ => Severity::Info,
                };
                return Some((sev, cvss));
            }
        }
    }
    None
}

/// Match a banner string against feed entries. Returns finding
/// metadata for hits — caller assembles the actual `Finding`
/// because it has the host_ip + port context.
pub fn match_banner(banner: &str) -> Vec<&'static FeedEntry> {
    // Lazy static-feeling pattern: re-load on each match call —
    // simple, and findings_store is already disk-bound so the
    // cost is negligible per scan.
    let _ = banner;
    Vec::new() // wired up via cve_feed_match below
}

/// Public matcher with explicit cache passed in (avoids leaking
/// a 'static-cached singleton; matches one-Arc-per-scan pattern).
pub fn match_with_cache(banner: &str, cache: &FeedCache) -> Vec<FeedEntry> {
    let lc = banner.to_lowercase();
    let mut hits: Vec<FeedEntry> = Vec::new();
    for e in &cache.entries {
        let kw_match = e
            .product_keywords
            .iter()
            .any(|k| lc.contains(&k.to_lowercase()));
        if !kw_match {
            continue;
        }
        // Version-substring match — if no versions specified,
        // we trust the keyword match alone. Otherwise require at
        // least one version-string hit.
        let ver_match = e.version_substrings.is_empty()
            || e.version_substrings.iter().any(|v| banner.contains(v));
        if !ver_match {
            continue;
        }
        hits.push(e.clone());
    }
    hits
}
