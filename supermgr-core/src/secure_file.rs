//! Secure file writing shared by every crate that persists secrets.
//!
//! The failure mode this guards against is the "write-then-chmod" pattern:
//! `std::fs::write` creates the file at the process umask (typically 0644),
//! so for the duration of the write the secret is group/world-readable on
//! disk before a follow-up `set_permissions(0o600)` narrows it. On a
//! multi-user box (or a laptop left unlocked) that window is real.
//!
//! [`write_private`] instead creates the file at 0600 *at creation*, in a
//! random-named temp file in the same directory, then renames it into
//! place — so the secret never exists at any wider mode, and the rename is
//! atomic on the same filesystem.

use std::io;
use std::path::{Path, PathBuf};

/// Write `bytes` to `path` at 0600, atomically, without any window where
/// the file exists at a wider mode.
///
/// The parent directory is created if missing. On Unix the file is created
/// with `O_CREAT|O_EXCL` and mode 0600; on non-Unix platforms the umask
/// still applies (there is no portable way to set the mode at creation).
///
/// # Errors
///
/// Any I/O error from creating the directory, opening the temp file, or
/// writing/renaming.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path
        .parent()
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    std::fs::create_dir_all(&dir)?;

    // Random suffix so a pre-existing symlink at the temp path can't be
    // followed (O_EXCL refuses to create over one).
    let tmp = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create_new(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(&tmp).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("open temp file {}: {e}", tmp.display()),
        )
    })?;
    file.write_all(bytes).map_err(|e| {
        io::Error::new(e.kind(), format!("write temp file {}: {e}", tmp.display()))
    })?;
    file.flush().map_err(|e| {
        io::Error::new(e.kind(), format!("flush temp file {}: {e}", tmp.display()))
    })?;
    drop(file);

    std::fs::rename(&tmp, path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("rename {} -> {}: {e}", tmp.display(), path.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_file_is_created_at_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret.cfg");
        write_private(&path, b"tls-crypt key").unwrap();
        let mode = std::fs::metadata(&path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn it_overwrites_an_existing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secret.cfg");
        write_private(&path, b"one").unwrap();
        write_private(&path, b"two").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
    }

    #[test]
    fn it_creates_missing_parent_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("a/b/c/secret.cfg");
        write_private(&path, b"x").unwrap();
        assert!(path.exists());
    }
}
