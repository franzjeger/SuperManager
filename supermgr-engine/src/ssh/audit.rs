//! SSH audit log — append-only plaintext log of push/revoke/connect operations.

use std::path::PathBuf;

use supermgr_core::ssh::audit::AuditEntry;

/// Determine the path to the SSH audit log file.
fn audit_log_path() -> PathBuf {
    let data_dir = crate::secrets::default_data_dir();
    data_dir.join("ssh-audit.log")
}

/// Append an audit entry to the log file.
///
/// Creates the parent directory if it does not exist. Errors are silently
/// ignored — audit logging should never cause an operation to fail.
pub fn append_audit(entry: &AuditEntry) {
    use std::io::Write;

    let path = audit_log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{entry}");
    }
}

/// Read the last `max_lines` entries from the audit log.
///
/// Returns an empty vector if the log file does not exist or cannot be read.
pub fn read_audit(max_lines: usize) -> Vec<String> {
    let path = audit_log_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].iter().map(|s| (*s).to_owned()).collect()
}
