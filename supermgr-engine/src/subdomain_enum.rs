//! Subdomain enumeration via Certificate Transparency logs.
//!
//! Pulls every certificate ever issued for a domain from the
//! public CT logs (queried through crt.sh's JSON endpoint), then
//! extracts the unique hostnames from each cert's subject + SAN
//! list. This is one of the highest-yield reconnaissance
//! techniques: every public TLS cert eventually shows up in CT,
//! and most orgs have far more subdomains than the operator
//! remembers (staging, dev, monitoring, vendor portals, …).
//!
//! # Why crt.sh
//!
//! - Free, no API key, no rate-limits for reasonable volumes.
//! - JSON output is straightforward to parse.
//! - Coverage is excellent — mirrors most major CT logs.
//!
//! # Output
//!
//! `enumerate(domain) -> SubdomainResult { domain, found: Vec<String> }`
//!
//! Caller can choose to feed `found` back into `discovery::active_scan`
//! or just display them as informational. We don't auto-add to
//! engagement scope — that crosses the manual-authorisation line
//! the operator is responsible for.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub domain: String,
    pub found: Vec<String>,
    /// Total certificates returned by the CT log query —
    /// proxies for "how many certs has this org ever issued?".
    pub cert_count: u32,
    pub queried_at: chrono::DateTime<chrono::Utc>,
}

/// Query crt.sh for `%.<domain>` and return the unique
/// hostnames seen across all returned certificates.
pub async fn enumerate(domain: &str) -> Result<SubdomainResult> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || !domain.contains('.') {
        anyhow::bail!("invalid domain: {domain}");
    }
    let url = format!("https://crt.sh/?q=%.{domain}&output=json");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("SuperManager/1.0 (Subdomain enum via CT logs)")
        .build()?;

    let resp = client.get(&url).send().await.context("crt.sh GET")?;
    if !resp.status().is_success() {
        anyhow::bail!("crt.sh returned {}", resp.status());
    }
    // Cap at 50 MB. A domain with a million certs would still
    // fit in this; anything bigger is suspect.
    let bytes = resp.bytes().await.context("crt.sh body")?;
    if bytes.len() > 50 * 1024 * 1024 {
        anyhow::bail!("crt.sh response too large: {} bytes", bytes.len());
    }
    let entries: Vec<CrtEntry> = serde_json::from_slice(&bytes)
        .context("parse crt.sh JSON")?;
    let cert_count = entries.len() as u32;

    let mut found: HashSet<String> = HashSet::new();
    for entry in &entries {
        // common_name (`name_value` in older API) — single name.
        if let Some(name) = entry.common_name.as_deref() {
            extract_hostnames(name, domain, &mut found);
        }
        // name_value contains newline-delimited names.
        extract_hostnames(&entry.name_value, domain, &mut found);
    }

    let mut sorted: Vec<String> = found.into_iter().collect();
    sorted.sort();
    Ok(SubdomainResult {
        domain: domain.to_owned(),
        found: sorted,
        cert_count,
        queried_at: chrono::Utc::now(),
    })
}

#[derive(Debug, Deserialize)]
struct CrtEntry {
    #[serde(default, rename = "common_name")]
    common_name: Option<String>,
    #[serde(default)]
    name_value: String,
}

/// Pull hostnames out of a crt.sh string. crt.sh occasionally
/// returns wildcard entries (`*.dev.example.com`) — strip the
/// wildcard prefix so the result is a pingable hostname. Filter
/// to the requested apex domain only (no leakage of sibling orgs
/// that happen to share infrastructure CT logs).
fn extract_hostnames(blob: &str, apex: &str, out: &mut HashSet<String>) {
    let apex_lc = apex.to_lowercase();
    for raw in blob.split(|c: char| c == '\n' || c == ' ' || c == ',' || c == ';') {
        let mut name = raw.trim().to_lowercase();
        if name.is_empty() { continue; }
        if let Some(rest) = name.strip_prefix("*.") {
            name = rest.to_owned();
        }
        // Filter: only keep names that are within the apex.
        if name == apex_lc || name.ends_with(&format!(".{apex_lc}")) {
            out.insert(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn extract_keeps_apex_only() {
        let mut out: HashSet<String> = HashSet::new();
        extract_hostnames(
            "api.example.com\nstaging.example.com\nfoo.evil.org\n*.dev.example.com",
            "example.com",
            &mut out,
        );
        assert!(out.contains("api.example.com"));
        assert!(out.contains("staging.example.com"));
        assert!(out.contains("dev.example.com"));  // wildcard prefix stripped
        assert!(!out.contains("evil.org"));
        assert!(!out.contains("foo.evil.org"));
    }

    #[test]
    fn extract_handles_empty() {
        let mut out: HashSet<String> = HashSet::new();
        extract_hostnames("", "example.com", &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn extract_apex_itself_included() {
        let mut out: HashSet<String> = HashSet::new();
        extract_hostnames("example.com", "example.com", &mut out);
        assert!(out.contains("example.com"));
    }

    proptest::proptest! {
        /// Property: every hostname `extract_hostnames` produces
        /// must end with the apex domain (or BE the apex). This
        /// is the security invariant — leaking sibling-org names
        /// from CT logs would expose customers we're not auditing.
        #[test]
        fn prop_extract_never_leaks_outside_apex(
            blob in ".{0,2048}",
            apex in "[a-z0-9-]{2,32}\\.[a-z]{2,8}"
        ) {
            let mut out: HashSet<String> = HashSet::new();
            extract_hostnames(&blob, &apex, &mut out);
            for name in &out {
                let apex_lc = apex.to_lowercase();
                proptest::prop_assert!(
                    *name == apex_lc || name.ends_with(&format!(".{apex_lc}")),
                    "extracted name '{name}' is not within apex '{apex}'"
                );
            }
        }

        /// Property: `extract_hostnames` doesn't panic on arbitrary
        /// input (CT log entries can have weird formatting).
        #[test]
        fn prop_extract_never_panics(blob in ".{0,2048}", apex in ".{0,64}") {
            let mut out: HashSet<String> = HashSet::new();
            extract_hostnames(&blob, &apex, &mut out);
        }
    }
}
