//! SSH audit façade routing all key push/revoke events and log queries through
//! the daemon's single authoritative [`crate::audit`] log.

use std::io;

use supermgr_core::ssh::audit::{AuditAction, AuditEntry};

use crate::audit::AuditCaller;

/// Record an SSH key push/revoke [`AuditEntry`] in the unified daemon audit log.
///
/// # Errors
///
/// Propagates any underlying [`crate::audit::record_event`] I/O error (already
/// logged at `ERROR` level).
pub fn append_audit(caller: &AuditCaller, entry: &AuditEntry) -> io::Result<()> {
    let action = match entry.action {
        AuditAction::Push => "SSH_KEY_PUSH",
        AuditAction::Revoke => "SSH_KEY_REVOKE",
        AuditAction::Generate => "SSH_KEY_GENERATE",
        AuditAction::Import => "SSH_KEY_IMPORT",
        AuditAction::Delete => "SSH_KEY_DELETE",
        AuditAction::Connect => "SSH_CONNECT",
    };
    let target = format!(
        "key={} ({}) -> {} ({}:{})",
        entry.key_name, entry.key_fingerprint, entry.host_label, entry.hostname, entry.port
    );
    let outcome = if entry.success { "ok" } else { "failed" };
    crate::audit::record_event(caller, action, &target, outcome)
}

/// Read the last `max_lines` entries from the unified daemon audit log.
///
/// # Errors
///
/// Propagates any [`crate::audit::read_events`] read error.
pub fn read_audit(max_lines: usize) -> io::Result<Vec<String>> {
    crate::audit::read_events(max_lines)
}
