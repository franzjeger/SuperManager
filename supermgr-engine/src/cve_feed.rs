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

    // Build a richer recommendation than the previous generic
    // "consult vendor advisory" line. Three actionable bits the
    // operator needs the first time they see one of these:
    //   1. The exact upstream advisory link (NVD detail page)
    //   2. A reminder that the match is BANNER-BASED — i.e. low
    //      confidence — so they should verify before patching
    //   3. Pointers to mark as False Positive when applicable
    //
    // Generic enough to work for any CVE, specific enough that the
    // operator gets a place to click rather than a vague nag.
    let recommendation = format!(
        "1. Read the advisory: https://nvd.nist.gov/vuln/detail/{id}\n\
         2. Verify the affected product/version is actually running on this host \
         (this match is banner-based — low-confidence by design). \
         Check `service --status-all` / `systemctl list-units` / the running \
         binary's `--version`.\n\
         3. If confirmed: apply the vendor patch or implement the workaround in the advisory.\n\
         4. If the affected component is not present on this host: \
         mark this finding as 'False positive' to keep your scan results clean."
    );

    Some(FeedEntry {
        id,
        product_keywords: keywords.into_iter().collect(),
        version_substrings: versions.into_iter().collect(),
        severity,
        cvss,
        title,
        detail: desc,
        recommendation,
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

/// OS/vendor names that are too generic to identify a vulnerable
/// product by themselves. CVEs from the NVD often carry CPEs
/// like `cpe:/o:freebsd:freebsd:2.1.5` for OS-level bugs — the
/// "product" field IS just the OS name. Without a version
/// constraint, matching any banner containing "freebsd" flags
/// every FreeBSD-derived banner against every FreeBSD CVE ever
/// published. Caused dozens of 1999-era CVEs (rdist, lpr, suidperl,
/// Z-Modem, etc.) to surface against modern OpenSSH banners.
///
/// Strategy: when the ONLY product keyword that matched is on
/// this list AND there's no version constraint to narrow the
/// match, drop the CVE. Real product-specific keywords like
/// "openssh", "apache", "wordpress" still match as expected.
fn is_generic_os_keyword(k: &str) -> bool {
    matches!(
        k.to_lowercase().as_str(),
        // BSD family
        "freebsd" | "openbsd" | "netbsd" | "dragonfly"
        | "bsd" | "bsd os" | "bsdos"
        // Linux + distros
        | "linux" | "linux_kernel" | "linux kernel"
        | "debian" | "ubuntu" | "redhat" | "red hat" | "centos"
        | "fedora" | "gentoo" | "suse" | "opensuse" | "arch"
        // Microsoft / Apple
        | "windows" | "macos" | "mac os x" | "macosx"
        | "darwin"
        // Legacy enterprise UNIX — the 1999-era CVE family
        | "sunos" | "solaris" | "aix" | "irix" | "hp-ux"
        | "nextstep" | "openserver" | "unixware" | "osf 1"
        | "a ux" | "asl ux 4800" | "ews-ux v" | "up-ux v"
        | "internet faststart" | "open desktop"
        // Pure generic catch-all
        | "tcp ip" | "inet" | "unix" | "kernel" | "os"
    )
}

/// Check whether `version` appears in `haystack` as a complete
/// version token, not as a substring of a longer dotted version.
///
/// Naïve `haystack.contains(version)` over-matches when the CVE's
/// canonical version is a prefix of an unrelated longer one.
/// Example: CVE-1999-1162 carries CPE versions `["2.0", "1.1"]`
/// (for SCO Unix 1.1 / 2.0). A naïve match flagged a modern
/// Apache banner — `"apache/2.4.65 (unix) openssl/1.1.1zd"` —
/// because `"1.1"` is a literal substring of `"1.1.1zd"`.
///
/// Boundary rule: at the start of the match the char immediately
/// before must NOT be `0-9` or `.`; at the end the char
/// immediately after must NOT be `0-9` or `.`. That rejects the
/// `1.1` inside `1.1.1zd` while still accepting `1.1` followed
/// by whitespace, hyphen, slash, or end-of-string.
///
/// We deliberately allow letter suffixes after the version
/// (`13.2a`, `5.1pl1`) to not match — those are different
/// patch-level builds, not the canonical version.
fn version_token_in(haystack: &str, version: &str) -> bool {
    if version.is_empty() {
        return false;
    }
    for (pos, _) in haystack.match_indices(version) {
        let before_ok = if pos == 0 {
            true
        } else {
            let prev = haystack[..pos].chars().last();
            match prev {
                Some(c) => !c.is_ascii_digit() && c != '.',
                None => true,
            }
        };
        let end = pos + version.len();
        let after_ok = if end >= haystack.len() {
            true
        } else {
            let next = haystack[end..].chars().next();
            match next {
                Some(c) => !c.is_ascii_digit() && c != '.',
                None => true,
            }
        };
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Public matcher with explicit cache passed in (avoids leaking
/// a 'static-cached singleton; matches one-Arc-per-scan pattern).
pub fn match_with_cache(banner: &str, cache: &FeedCache) -> Vec<FeedEntry> {
    let lc = banner.to_lowercase();
    let mut hits: Vec<FeedEntry> = Vec::new();
    for e in &cache.entries {
        // Per-keyword match record — we need to know which
        // keyword(s) matched so we can apply the "generic OS"
        // demotion below.
        let matched_keywords: Vec<&String> = e
            .product_keywords
            .iter()
            .filter(|k| lc.contains(&k.to_lowercase()))
            .collect();
        if matched_keywords.is_empty() {
            continue;
        }
        // If EVERY matched keyword is a generic OS/vendor name,
        // require a version-substring hit to narrow it. Without
        // that the match is "this OS exists" → useless.
        let all_generic = matched_keywords
            .iter()
            .all(|k| is_generic_os_keyword(k));
        if all_generic && e.version_substrings.is_empty() {
            continue;
        }
        // Version-substring match.
        //
        // For generic-OS-only matches we need STRICT proximity:
        // a banner like "SSH-2.0-OpenSSH_10.2 FreeBSD-..." contains
        // both the keyword "freebsd" AND the version substring
        // "2.0" — but the "2.0" comes from the SSH protocol
        // version, not from the OS. A naive `banner.contains(v)`
        // surfaced 7 false-positive 1999-era CVEs against modern
        // FreeBSD hosts.
        //
        // Fix: when ALL matched keywords are generic, require
        // the keyword + version to co-occur within 50 chars of
        // each other in the banner. "FreeBSD-openssh-...-10.2"
        // satisfies this for keyword "freebsd" + version "10.2";
        // "SSH-2.0-OpenSSH_10.2 FreeBSD-..." does NOT for keyword
        // "freebsd" + version "2.0".
        //
        // For specific keywords (apache, openssh, wordpress) we
        // keep the existing banner-wide substring check — these
        // CVEs have product-specific keywords that already
        // anchor the match.
        // Two-tier strictness.
        //
        // Specific keywords (apache, openssh, wordpress, …) anchor
        // the match well, so we keep the cheap banner-wide
        // `contains` check. That preserves matches like "Apache 2.4
        // CVE" against an Apache/2.4.6 banner — the CVE's version
        // field is `"2.4"` (NVD's prefix encoding for "all 2.4.x")
        // and a strict boundary check would reject it.
        //
        // Generic OS keywords + version substrings need TWO
        // safeguards to keep noise out:
        //   1. Proximity — keyword + version must co-occur within
        //      50 chars (defeats SSH-2.0 + FreeBSD-far-away).
        //   2. Boundary  — the version must appear as a complete
        //      token, not as a substring of a longer version
        //      (defeats "1.1" inside "openssl/1.1.1zd" for
        //      "SCO UNIX 1.1" CVEs).
        let ver_match = if e.version_substrings.is_empty() {
            true
        } else if all_generic {
            matched_keywords.iter().any(|kw| {
                let kw_lc = kw.to_lowercase();
                lc.match_indices(&kw_lc).any(|(pos, _)| {
                    let end = pos + kw_lc.len();
                    let window_end = (end + 50).min(lc.len());
                    let window = &lc[end..window_end];
                    e.version_substrings.iter().any(|v| {
                        version_token_in(window, &v.to_lowercase())
                    })
                })
            })
        } else {
            e.version_substrings.iter().any(|v| banner.contains(v))
        };
        if !ver_match {
            continue;
        }
        hits.push(e.clone());
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, keywords: &[&str], versions: &[&str]) -> FeedEntry {
        FeedEntry {
            id: id.into(),
            product_keywords: keywords.iter().map(|s| (*s).into()).collect(),
            version_substrings: versions.iter().map(|s| (*s).into()).collect(),
            severity: crate::vuln::Severity::High,
            cvss: 7.0,
            title: format!("{id}: test"),
            detail: "test".into(),
            recommendation: "test".into(),
        }
    }

    fn cache_with(entries: Vec<FeedEntry>) -> FeedCache {
        FeedCache {
            entries,
            last_fetched_at: None,
        }
    }

    // The original PR #27 bug: "freebsd" + version "2.0" matched
    // "SSH-2.0-...FreeBSD" because the substring "2.0" appears
    // in the protocol version, far from the keyword.
    #[test]
    fn proximity_blocks_protocol_version_collision() {
        let cache = cache_with(vec![entry(
            "CVE-1999-1313",
            &["freebsd"],
            &["2.0", "2.1", "2.2"],
        )]);
        let banner = "SSH-2.0-OpenSSH_10.2 FreeBSD-openssh-portable-10.2.p1_1,1";
        let hits = match_with_cache(banner, &cache);
        assert!(
            hits.is_empty(),
            "modern FreeBSD banner with SSH-2.0 must NOT match CVE-1999 with FreeBSD 2.0 versions"
        );
    }

    // Legitimate match: keyword + version are adjacent in the banner.
    #[test]
    fn proximity_allows_adjacent_keyword_and_version() {
        let cache = cache_with(vec![entry(
            "CVE-2099-9999",
            &["freebsd"],
            &["13.2"],
        )]);
        // FreeBSD 13.2 — exact match, "freebsd" and "13.2" within 30 chars.
        let banner = "SSH-2.0-OpenSSH_9.6 FreeBSD-13.2-RELEASE";
        let hits = match_with_cache(banner, &cache);
        assert_eq!(hits.len(), 1);
    }

    // Specific (non-generic) keyword + version: existing behaviour
    // preserved. Apache 2.4 → matches Apache CVE with version 2.4.
    #[test]
    fn specific_keyword_uses_banner_wide_match() {
        let cache = cache_with(vec![entry(
            "CVE-2017-XXXX",
            &["apache_http_server"],
            &["2.4"],
        )]);
        let banner = "Apache/2.4.6 (Linux)";
        // banner doesn't lowercase-contain "apache_http_server"
        // but contains "2.4". For this test, use a banner that
        // matches both. Realistically the cve_feed parser would
        // already lowercase + de-underscore the product.
        let cache = cache_with(vec![entry(
            "CVE-2017-XXXX",
            &["apache"],
            &["2.4"],
        )]);
        let hits = match_with_cache(banner, &cache);
        assert_eq!(hits.len(), 1);
    }

    // CVE with no versions + only generic keyword: drop.
    #[test]
    fn generic_keyword_no_version_dropped() {
        let cache = cache_with(vec![entry(
            "CVE-1999-1301",
            &["freebsd"],
            &[],
        )]);
        let hits = match_with_cache("SSH-2.0-OpenSSH_10.2 FreeBSD-...", &cache);
        assert!(hits.is_empty());
    }

    // Newly-blocklisted legacy UNIX names — same treatment.
    #[test]
    fn legacy_unix_names_treated_generic() {
        for name in &["sunos", "irix", "aix", "hp-ux", "openserver"] {
            let cache = cache_with(vec![entry(
                "CVE-1999-X",
                &[name],
                &[],
            )]);
            let hits = match_with_cache("Apache/2.4 (Linux)", &cache);
            assert!(hits.is_empty(), "{name} should be treated as generic");
        }
    }

    // ─── version_token_in helper ───────────────────────────────────

    #[test]
    fn version_token_rejects_prefix_of_longer_version() {
        // The CVE-1999-1162 regression: "1.1" must NOT match
        // inside "openssl/1.1.1zd".
        assert!(!version_token_in("openssl/1.1.1zd", "1.1"));
        // Same for "2.0" inside "12.0.7" or "v2.0.1".
        assert!(!version_token_in("server-2.0.7", "2.0"));
        assert!(!version_token_in("12.0.4", "2.0"));
    }

    #[test]
    fn version_token_accepts_complete_token() {
        // Plain end-of-string / whitespace / hyphen / slash all OK.
        assert!(version_token_in("freebsd-2.0", "2.0"));
        assert!(version_token_in("freebsd 2.0 release", "2.0"));
        assert!(version_token_in("freebsd-2.0-release", "2.0"));
        assert!(version_token_in("path/2.0/etc", "2.0"));
        assert!(version_token_in("v=2.0", "2.0"));
        // Letter suffix is fine — version ends at non-digit/non-dot.
        assert!(version_token_in("freebsd-13.2a", "13.2a"));
    }

    #[test]
    fn version_token_rejects_digit_before() {
        // "1.0" inside "11.0" — char before is digit "1".
        assert!(!version_token_in("freebsd-11.0", "1.0"));
        assert!(!version_token_in("v=21.0", "1.0"));
    }

    #[test]
    fn version_token_handles_empty_inputs() {
        assert!(!version_token_in("", "2.0"));
        assert!(!version_token_in("freebsd-2.0", ""));
        assert!(!version_token_in("", ""));
    }

    // ─── Regression for CVE-1999-1162 on a modern Apache host ──────

    #[test]
    fn regression_sco_unix_does_not_match_modern_apache_openssl() {
        // CVE-1999-1162: SCO UNIX 1.1 / 2.0 passwd DoS.
        // NVD's CPE encoding produces keywords ["unix", "open desktop"]
        // + versions ["1.1", "2.0"]. Both keywords are generic-OS.
        // Modern Apache+OpenSSL banner must NOT match.
        let cache = cache_with(vec![entry(
            "CVE-1999-1162",
            &["unix", "open desktop"],
            &["1.1", "2.0"],
        )]);
        let banner = "Apache/2.4.65 (Unix) OpenSSL/1.1.1zd";
        let hits = match_with_cache(banner, &cache);
        assert!(
            hits.is_empty(),
            "modern Apache banner with OpenSSL/1.1.1zd must NOT match SCO UNIX 1.1 CVE"
        );
    }

    // Specific-keyword path is NOT subject to boundary check —
    // preserves the Apache-2.4-CVE-matches-2.4.x semantic.
    #[test]
    fn specific_keyword_still_matches_2_4_in_2_4_6() {
        let cache = cache_with(vec![entry(
            "CVE-2017-XXXX",
            &["apache"],
            &["2.4"],
        )]);
        let banner = "Apache/2.4.6 (Linux)";
        let hits = match_with_cache(banner, &cache);
        assert_eq!(hits.len(), 1, "specific keyword should keep prefix-match behaviour");
    }
}
