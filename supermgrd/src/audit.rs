//! Authoritative daemon audit log (`0600`, size-bounded rotation, structured entries).
//!
//! Consolidates all VPN, SSH, key-deployment, and appliance-API audit events
//! into a single private log file:
//! - Root: `/var/log/supermgrd/audit.log` (rotated to `/var/log/supermgrd/audit.log.1`)
//! - Non-root (dev/test): `$XDG_DATA_HOME/supermgrd/audit.log`
//!
//! Every entry records:
//! `<rfc3339-timestamp> | caller=<uid/sender> | action=<action> | target=<target> | outcome=<outcome>`
//!
//! Write and read failures are logged at `ERROR` level and returned to callers
//! rather than silently discarded.

use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::SecondsFormat;

/// Maximum size of the active `audit.log` before rotating to `audit.log.1` (5 MiB).
pub const AUDIT_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// Process-wide lock serialising audit rotation, writes, and reads.
static AUDIT_LOCK: Mutex<()> = Mutex::new(());

/// Identity of the principal responsible for an audited operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditCaller {
    /// Effective Unix UID of the D-Bus peer, or daemon UID for internal actions.
    pub uid: Option<u32>,
    /// Unique D-Bus bus name (e.g. `:1.42`) or `"daemon"` for internal tasks.
    pub sender: String,
}

impl AuditCaller {
    /// Construct an [`AuditCaller`] representing the daemon itself (background
    /// tasks, startup recovery, auto-connect).
    #[must_use]
    pub fn daemon() -> Self {
        Self {
            uid: Some(nix::unistd::getuid().as_raw()),
            sender: "daemon".to_owned(),
        }
    }

    /// Resolve the [`AuditCaller`] from an incoming D-Bus message header via the
    /// bus daemon.
    pub async fn from_dbus(
        connection: &zbus::Connection,
        header: &zbus::message::Header<'_>,
    ) -> Self {
        let Some(sender) = header.sender() else {
            return Self {
                uid: None,
                sender: "unknown".to_owned(),
            };
        };
        let sender_str = sender.as_str().to_owned();
        let uid = match zbus::fdo::DBusProxy::new(connection).await {
            Ok(dbus) => dbus
                .get_connection_unix_user(sender.to_owned().into())
                .await
                .ok(),
            Err(_) => None,
        };
        Self {
            uid,
            sender: sender_str,
        }
    }

    fn format_field(&self) -> String {
        let safe_sender = sanitize_field(&self.sender);
        match self.uid {
            Some(uid) => format!("uid={uid}({safe_sender})"),
            None => format!("uid=?({safe_sender})"),
        }
    }
}

/// Determine the canonical path to the single authoritative audit log file.
fn audit_path() -> io::Result<PathBuf> {
    #[cfg(test)]
    if let Ok(override_path) = std::env::var("SUPERMGRD_TEST_AUDIT_PATH") {
        if !override_path.is_empty() {
            return Ok(PathBuf::from(override_path));
        }
    }

    if nix::unistd::getuid().is_root() {
        Ok(PathBuf::from("/var/log/supermgrd/audit.log"))
    } else {
        supermgr_core::paths::try_default_data_dir()
            .map(|dir| dir.join("audit.log"))
            .map_err(io::Error::other)
    }
}

/// Return the `.1` rotated sibling path for `log_path`.
fn rotated_audit_path(log_path: &Path) -> PathBuf {
    let mut os = log_path.as_os_str().to_os_string();
    os.push(".1");
    PathBuf::from(os)
}

/// Sanitize a single audit field so control characters, newlines, and column
/// delimiters (`|`) cannot forge synthetic audit lines or corrupt parsing.
fn sanitize_field(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\r' | '\n' | '\t' => out.push(' '),
            '|' => out.push('/'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        "-".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn rotate_if_needed(path: &Path, max_bytes: u64) -> io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };

    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to write audit log through symlink {}",
                path.display()
            ),
        ));
    }

    if meta.len() >= max_bytes {
        let rotated = rotated_audit_path(path);
        if let Ok(rot_meta) = std::fs::symlink_metadata(&rotated) {
            if rot_meta.file_type().is_symlink() {
                std::fs::remove_file(&rotated)?;
            }
        }
        std::fs::rename(path, &rotated)?;
        let _ = std::fs::set_permissions(&rotated, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn record_event_at(
    path: &Path,
    max_bytes: u64,
    caller: &AuditCaller,
    action: &str,
    target: &str,
    outcome: &str,
) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("audit log path {} has no parent directory", path.display()),
        )
    })?;
    crate::secure_file::ensure_private_dir(dir, 0o700)?;

    rotate_if_needed(path, max_bytes)?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;

    let meta = file.metadata()?;
    if meta.permissions().mode() & 0o777 != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Secs, false);
    let line = format!(
        "{ts} | caller={} | action={} | target={} | outcome={}\n",
        caller.format_field(),
        sanitize_field(action),
        sanitize_field(target),
        sanitize_field(outcome),
    );

    file.write_all(line.as_bytes())?;
    file.flush()
}

/// Record a structured audit event and return any I/O failure after logging it
/// loudly at `ERROR` level.
///
/// # Errors
///
/// Returns an [`io::Error`] if the audit directory cannot be secured, rotation
/// fails, a symlink is encountered, or writing/flushing fails.
pub fn record_event(
    caller: &AuditCaller,
    action: &str,
    target: &str,
    outcome: &str,
) -> io::Result<()> {
    let _guard = AUDIT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = audit_path()
        .and_then(|path| record_event_at(&path, AUDIT_MAX_BYTES, caller, action, target, outcome));
    if let Err(ref err) = result {
        tracing::error!(
            error = %err,
            action,
            target,
            outcome,
            "AUDIT LOG WRITE FAILED"
        );
    }
    result
}

/// Convenience wrapper around [`record_event`] for D-Bus and background call
/// sites that do not abort the user operation on an audit I/O failure (the
/// error is still logged loudly at `ERROR` level by [`record_event`]).
pub fn log_event_with_caller(caller: &AuditCaller, action: &str, target: &str, outcome: &str) {
    let _ = record_event(caller, action, target, outcome);
}

fn read_events_at(path: &Path, max_lines: usize) -> io::Result<Vec<String>> {
    if max_lines == 0 {
        return Ok(Vec::new());
    }

    let current_lines: Vec<String> = match std::fs::read_to_string(path) {
        Ok(text) => text.lines().map(str::to_owned).collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };

    if current_lines.len() >= max_lines {
        let start = current_lines.len() - max_lines;
        return Ok(current_lines[start..].to_vec());
    }

    let rotated = rotated_audit_path(path);
    let mut combined: Vec<String> = match std::fs::read_to_string(&rotated) {
        Ok(text) => {
            let needed = max_lines - current_lines.len();
            let rot_lines: Vec<&str> = text.lines().collect();
            let start = rot_lines.len().saturating_sub(needed);
            rot_lines[start..].iter().map(|s| (*s).to_owned()).collect()
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    combined.extend(current_lines);
    Ok(combined)
}

/// Read up to `max_lines` most recent entries from the unified audit log
/// (spanning `audit.log.1` and `audit.log` across rotations).
///
/// # Errors
///
/// Returns an [`io::Error`] (and logs at `ERROR` level) if the audit log exists
/// and cannot be read.
pub fn read_events(max_lines: usize) -> io::Result<Vec<String>> {
    let _guard = AUDIT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = audit_path().and_then(|path| read_events_at(&path, max_lines));
    if let Err(ref err) = result {
        tracing::error!(error = %err, "AUDIT LOG READ FAILED");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_enforces_0600_rotates_and_sanitizes_fields() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("logs/audit.log");
        let caller = AuditCaller {
            uid: Some(1000),
            sender: ":1.77".to_owned(),
        };

        record_event_at(
            &path,
            240,
            &caller,
            "SSH_EXEC",
            "admin@fw1\nforged | line",
            "ok",
        )
        .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit.log mode was {mode:o}");

        // Push past 240-byte test cap to trigger rotation to `.1`.
        for idx in 0..4 {
            record_event_at(
                &path,
                240,
                &caller,
                "VPN_CONNECT",
                &format!("profile-{idx}"),
                "ok",
            )
            .unwrap();
        }

        let rotated = rotated_audit_path(&path);
        assert!(rotated.exists(), "expected rotated audit.log.1 to exist");
        let rot_mode = std::fs::metadata(&rotated).unwrap().permissions().mode() & 0o777;
        assert_eq!(rot_mode, 0o600);

        let lines = read_events_at(&path, 10).unwrap();
        assert!(lines.len() >= 2);
        for line in &lines {
            assert!(!line.contains('\n'));
            assert!(line.contains("caller=uid=1000(:1.77)"));
            assert!(!line.contains("forged | line"));
        }
    }

    #[test]
    fn refuses_symlink_at_audit_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("logs");
        crate::secure_file::ensure_private_dir(&dir, 0o700).unwrap();
        let victim = tmp.path().join("victim");
        let path = dir.join("audit.log");
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        let err = record_event_at(&path, 1024, &AuditCaller::daemon(), "TEST", "t", "ok")
            .expect_err("must refuse symlink");
        assert!(!victim.exists(), "wrote through symlink: {err}");
    }
}
