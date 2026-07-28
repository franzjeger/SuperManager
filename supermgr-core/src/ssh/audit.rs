//! SSH audit log types.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An action recorded in the SSH audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditAction {
    /// Key was pushed to a remote host.
    Push,
    /// Key was revoked from a remote host.
    Revoke,
    /// A new key pair was generated.
    Generate,
    /// An existing key was imported.
    Import,
    /// A key was deleted.
    Delete,
    /// An SSH connection was established.
    Connect,
}

/// A single entry in the SSH audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the action occurred.
    pub timestamp: DateTime<Utc>,

    /// What action was performed.
    pub action: AuditAction,

    /// Name of the key involved.
    pub key_name: String,

    /// Fingerprint of the key (SHA256 format).
    pub key_fingerprint: String,

    /// Human-readable label of the target host.
    pub host_label: String,

    /// Hostname or IP of the target host.
    pub hostname: String,

    /// SSH port of the target host.
    pub port: u16,

    /// Whether the action completed successfully.
    pub success: bool,
}

impl fmt::Display for AuditEntry {
    /// Formats the entry as a pipe-delimited log line:
    ///
    /// ```text
    /// 2026-03-28T14:30:00Z | PUSH | my-key | SHA256:abc... | webserver | 10.0.0.1:22 | OK
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self.action {
            AuditAction::Push => "PUSH",
            AuditAction::Revoke => "REVOKE",
            AuditAction::Generate => "GENERATE",
            AuditAction::Import => "IMPORT",
            AuditAction::Delete => "DELETE",
            AuditAction::Connect => "CONNECT",
        };
        let status = if self.success { "OK" } else { "FAIL" };

        write!(
            f,
            "{} | {} | {} | {} | {} | {}:{} | {}",
            // Seconds precision, not `%+`. `%+` emits whatever
            // sub-second digits the clock happened to produce
            // (`…:18.026235+00:00`), and the macOS reader parses these
            // lines with `ISO8601DateFormatter`, which rejects
            // fractional seconds unless explicitly configured for
            // them. Sub-second resolution buys an audit log nothing.
            self.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            action,
            self.key_name,
            self.key_fingerprint,
            self.host_label,
            self.hostname,
            self.port,
            status,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(action: AuditAction, host: &str, port: u16, success: bool) -> AuditEntry {
        AuditEntry {
            timestamp: "2026-03-28T14:30:00Z".parse::<DateTime<Utc>>().unwrap(),
            action,
            key_name: "my-key".to_owned(),
            key_fingerprint: "SHA256:abc".to_owned(),
            host_label: if host.is_empty() { String::new() } else { "webserver".to_owned() },
            hostname: host.to_owned(),
            port,
            success,
        }
    }

    /// The macOS reader parses these lines with `ISO8601DateFormatter`
    /// configured for `.withInternetDateTime`, which rejects fractional
    /// seconds. A timestamp like `…:00.026235Z` makes every entry parse
    /// to nil and the audit pane silently shows nothing.
    #[test]
    fn timestamp_has_no_fractional_seconds() {
        let line = entry(AuditAction::Push, "10.0.0.1", 22, true).to_string();
        let ts = line.split(" | ").next().unwrap();
        assert_eq!(ts, "2026-03-28T14:30:00Z");
        assert!(!ts.contains('.'), "fractional seconds break the reader: {ts}");
    }

    #[test]
    fn renders_documented_shape() {
        assert_eq!(
            entry(AuditAction::Push, "10.0.0.1", 22, true).to_string(),
            "2026-03-28T14:30:00Z | PUSH | my-key | SHA256:abc | webserver | 10.0.0.1:22 | OK"
        );
    }

    #[test]
    fn failures_render_as_fail() {
        let line = entry(AuditAction::Revoke, "10.0.0.1", 22, false).to_string();
        assert!(line.ends_with(" | FAIL"), "{line}");
        assert!(line.contains(" | REVOKE | "), "{line}");
    }

    /// Key-lifecycle events carry no host. The reader splits host:port on
    /// the last colon, so the empty form still has to keep its `:0`.
    #[test]
    fn key_lifecycle_entry_keeps_seven_fields() {
        let line = entry(AuditAction::Generate, "", 0, true).to_string();
        assert_eq!(line.split(" | ").count(), 7, "{line}");
        assert!(line.contains(" |  | :0 | "), "{line}");
    }
}
