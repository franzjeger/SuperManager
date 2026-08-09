//! Finding and check severity.
//!
//! Moved here from `supermgr-engine::vuln` so the compliance model can live in
//! core without dragging 1300 lines of vulnerability analysis along with it.
//! The engine re-exports it, so `vuln::Severity` still resolves at its eight
//! existing call sites.
//!
//! Note there is a *second* `Severity` in `compliance`, and the two are not
//! redundant: this one grades a finding (how bad is what we found), the
//! compliance one grades a control (how bad is failing it). `map_severity` in
//! the Linux baseline converts between them, and collapsing them would lose
//! that distinction.

use serde::{Deserialize, Serialize};

/// How serious a finding is.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, not worth acting on.
    Info,
    /// Act eventually.
    Low,
    /// Act this sprint.
    Medium,
    /// Act now.
    High,
    /// Act before doing anything else.
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialises_lowercase_for_the_wire() {
        // Stored in findings on disk and sent over D-Bus. A casing change here
        // silently fails to deserialise every existing record.
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
        let back: Severity = serde_json::from_str("\"high\"").unwrap();
        assert_eq!(back, Severity::High);
    }
}
