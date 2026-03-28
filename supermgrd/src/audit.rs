//! Daemon-wide audit log — append-only plaintext log of SSH, VPN, and API operations.
//!
//! The log file location depends on whether the daemon is running as root:
//! - Root: `/var/log/supermgrd/audit.log`
//! - User: `$HOME/.local/share/supermgrd/audit.log`

use std::path::PathBuf;

use chrono::Local;

/// Determine the path to the audit log file.
fn audit_path() -> PathBuf {
    if nix::unistd::getuid().is_root() {
        PathBuf::from("/var/log/supermgrd/audit.log")
    } else {
        // dev mode
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(".local/share/supermgrd/audit.log")
    }
}

/// Append an audit event to the log file.
///
/// Creates the parent directory if it does not exist. Errors are silently
/// ignored — audit logging should never cause an operation to fail.
pub fn log_event(action: &str, detail: &str) {
    let path = audit_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let ts = Local::now().format("%Y-%m-%dT%H:%M:%S");
    let line = format!("{ts} | {action} | {detail}\n");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
}
