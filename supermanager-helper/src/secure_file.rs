//! Writing secret material to disk without a moment where it is readable.
//!
//! The helper runs as root and hands credentials to processes it spawns: a
//! `swanctl` config carrying an EAP password and a group PSK, an `openvpn`
//! given a static key and password, a WireGuard conf embedding a private key.
//! Every one of those was written with `fs::write`, which creates at
//! `0666 & !umask` — **0644** in practice — and then narrowed with a
//! `set_permissions` afterwards, leaving the file readable for the length of
//! the write (or, when the chmod was `.ok()`d, forever).
//!
//! So the mode is set at creation, in the same syscall, and every path that
//! writes a secret goes through here rather than deciding for itself.
//!
//! # What the guarantees are
//!
//! - [`write_private`] — the file never exists at a mode other than 0600, and
//!   the open cannot follow a symlink planted at the path.
//!
//! # Blocking I/O
//!
//! These are synchronous. The files are a few hundred bytes on a real
//! filesystem — the write is microseconds, and the callers here are already
//! doing blocking `std::fs` work (or run on a small runtime), so a
//! `spawn_blocking` wrapper would cost more than it saves.

use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Write `bytes` to `path` as a file only its owner can read.
///
/// Created with `O_CREAT | O_EXCL` at mode 0600 in one step, so it never
/// exists at a wider mode and the open refuses to follow a symlink someone
/// planted at the path. An existing file at `path` is removed first so a
/// previous connect's 0644 file is not inherited.
///
/// # Errors
///
/// Anything the open or write returns.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

/// Write `bytes` to `path` at 0600, creating the parent directory at `dir_mode`.
///
/// Convenience for the common "secret under a private dir" shape: the dir is
/// created (or narrowed) before the file is born, so neither is ever wider
/// than intended.
///
/// # Errors
///
/// Anything the directory creation, open, or write returns.
pub fn write_private_in_dir(path: &Path, bytes: &[u8], dir_mode: u32) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        ensure_private_dir(dir, dir_mode)?;
    }
    write_private(path, bytes)
}

/// Create `dir` at `mode`, or narrow an existing one down to it.
///
/// A pre-existing directory wider than `mode` is narrowed, so an install
/// carrying one from an earlier version does not keep it.
///
/// # Errors
///
/// `AlreadyExists` if the path is not a directory, or whatever the
/// underlying calls return.
pub fn ensure_private_dir(dir: impl AsRef<Path>, mode: u32) -> io::Result<()> {
    let dir = dir.as_ref();
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match std::fs::DirBuilder::new().mode(mode).create(dir) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a directory", dir.display()),
        ));
    }
    if meta.permissions().mode() & 0o777 != mode {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_secret_is_never_written_group_or_world_readable() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secrets.conf");

        write_private(&path, b"EAP password + PSK").unwrap();

        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"EAP password + PSK");
    }

    #[test]
    fn rewriting_narrows_a_file_left_wide_by_an_older_version() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auto_reconnect.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, b"new").unwrap();

        assert_eq!(mode_of(&path), 0o600, "inherited the old mode");
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn a_planted_symlink_is_not_written_through() {
        let dir = tempfile::TempDir::new().unwrap();
        let victim = dir.path().join("victim");
        let planted = dir.path().join("conf");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        write_private(&planted, b"secret").unwrap();

        assert!(!victim.exists(), "written through the symlink");
        assert_eq!(std::fs::read(&planted).unwrap(), b"secret");
        assert_eq!(mode_of(&planted), 0o600);
    }
}
