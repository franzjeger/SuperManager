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
            self.timestamp.format("%+"),
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
