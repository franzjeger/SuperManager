//! Security findings — the model, shared by every platform.
//!
//! Moved here from `supermgr-engine::vuln` for the same reason
//! [`crate::compliance`] was: the engine is macOS-only and this is not. The
//! Linux daemon has to be able to record and serve findings so the GTK GUI can
//! show a Security page, and the Windows daemon will want the same.
//!
//! # What did *not* move
//!
//! The scanner. `vuln::analyse_host` and its CVE matching take
//! `probes::PortProbe` and `probes::TlsInfo` as parameters, which drags in the
//! port prober and the recon enumerators behind it — 1300 lines of engine that
//! nothing on Linux can use yet. The split is the same one the compliance move
//! made: the model and the store are shared, the thing that *produces* the data
//! stays where its dependencies are.
//!
//! That split is not just convenient. It is what lets the Linux daemon populate
//! findings from a source the engine does not have — its CIS compliance runs —
//! without waiting for a port scanner to be ported.

use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// One security finding about one host.
///
/// Deliberately flat and free of scanner concepts. A finding is a claim an
/// operator has to act on, and it needs to render identically whether it came
/// from a TLS probe, a CVE banner match, or a failed compliance control — so it
/// carries no reference to how it was produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Stable identifier for this finding. Used as the dedup key by
    /// [`crate::findings_store`], so the same issue rediscovered on a later
    /// scan updates its row rather than adding a second one.
    pub id: String,
    /// Host this concerns, as an address string.
    pub host_ip: String,
    /// Port, when the finding is about a specific service.
    pub port: Option<u16>,
    /// Service name, when known.
    pub service: Option<String>,
    /// Operator-facing magnitude. Drives sort order and the risk score.
    pub severity: Severity,
    /// One line naming the problem.
    pub title: String,
    /// What is wrong, in enough detail to act on.
    pub detail: String,
    /// What to do about it.
    pub recommendation: String,
    /// CVE identifier, when this maps to one.
    pub cve: Option<String>,
    /// CVSS base score, when one is published.
    pub cvss: Option<f32>,
}

/// Validate a customer / scope slug used as a directory name.
///
/// This is a path-traversal guard before it is a tidiness rule: the slug is
/// interpolated into a filesystem path by [`crate::findings_store`], so `..`
/// and `/` have to be impossible rather than merely unusual. Leading `.` and
/// `-` are refused too — the first hides a directory, the second is read as an
/// option by half the CLI tools that might later touch it.
///
/// Moved here from `supermgr-engine::customer`, which cannot come along: it
/// pulls in provisioning and engine state. Only this function was needed, so
/// only this function moved, and the engine re-exports it.
///
/// # Errors
///
/// Returns a message naming the specific rule broken, since the caller shows it
/// to whoever typed the slug.
pub fn validate_slug(slug: &str) -> Result<(), String> {
    if slug.is_empty() {
        return Err("slug must not be empty".to_owned());
    }
    if slug.len() > 64 {
        return Err("slug must be ≤64 chars".to_owned());
    }
    if slug.starts_with('.') || slug.starts_with('-') {
        return Err("slug must not start with '.' or '-'".to_owned());
    }
    for ch in slug.chars() {
        if !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
            return Err(format!("slug contains illegal character: {ch:?}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slug_cannot_escape_its_directory() {
        // The reason this function exists. Every one of these would otherwise
        // be interpolated straight into a path by the findings store.
        for bad in [
            "..",
            "../etc",
            "a/b",
            "a\\b",
            "a/../../root",
            "/absolute",
            "with space",
            "trailing/",
        ] {
            assert!(
                validate_slug(bad).is_err(),
                "{bad:?} was accepted as a slug"
            );
        }
    }

    #[test]
    fn a_slug_cannot_hide_or_look_like_a_flag() {
        assert!(validate_slug(".hidden").is_err());
        assert!(validate_slug("-rf").is_err());
        // Legal in the middle, only the first character is refused.
        assert!(validate_slug("acme-corp").is_ok());
        assert!(validate_slug("acme_corp_2").is_ok());
    }

    #[test]
    fn the_boundaries_are_where_they_claim_to_be() {
        assert!(validate_slug("").is_err(), "empty");
        assert!(validate_slug(&"a".repeat(64)).is_ok(), "64 is allowed");
        assert!(validate_slug(&"a".repeat(65)).is_err(), "65 is not");
    }

    #[test]
    fn the_error_names_the_rule_that_was_broken() {
        // The message reaches whoever typed the slug, so "invalid" alone would
        // make them guess between four different rules.
        assert!(validate_slug("").unwrap_err().contains("empty"));
        assert!(validate_slug(".x").unwrap_err().contains("start"));
        assert!(validate_slug("a b").unwrap_err().contains("illegal"));
        assert!(validate_slug(&"a".repeat(65)).unwrap_err().contains("64"));
    }

    #[test]
    fn a_finding_round_trips_through_json() {
        // The store persists these as JSON, so a field that does not survive
        // the round trip is a field silently lost between scans.
        let f = Finding {
            id: "tls-weak-1".to_owned(),
            host_ip: "10.0.0.1".to_owned(),
            port: Some(443),
            service: Some("https".to_owned()),
            severity: Severity::High,
            title: "TLS 1.0 enabled".to_owned(),
            detail: "Server negotiates TLS 1.0.".to_owned(),
            recommendation: "Disable TLS 1.0 and 1.1.".to_owned(),
            cve: None,
            cvss: Some(7.4),
        };
        let json = serde_json::to_string(&f).expect("serialise");
        let back: Finding = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(f, back);
    }
}
