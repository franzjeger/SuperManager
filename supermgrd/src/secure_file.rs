//! Writing secret material to disk without a moment where it is readable.
//!
//! # Why this exists
//!
//! The daemon runs as root and has to hand credentials to processes it
//! spawns: an `openvpn` given a static key and an OAuth token, a `swanctl`
//! config carrying an EAP password and a group PSK, an `ssh` given the host's
//! private key. Every one of those is a file, and every one of them was
//! written with `fs::write`, which creates at `0666 & !umask` — **0644** in
//! practice. One of them then narrowed itself with a `set_permissions`
//! afterwards, which leaves the file readable for the length of the write.
//!
//! Those files lived in directories whose modes were the only thing keeping
//! them private. That is one `chmod`, one `create_dir_all` on a path someone
//! else already owns, or one distribution packaging decision away from being
//! a credential disclosure — and it is not a property anything checked.
//!
//! So the mode is set at creation, in the same syscall, and every path that
//! writes a secret goes through here rather than deciding for itself.
//!
//! # What the guarantees are
//!
//! - [`write_private`] — the file never exists at a mode other than 0600, and
//!   the open cannot follow a symlink planted at the path.
//! - [`ensure_private_dir`] — the directory is ours, is a real directory, and
//!   is not wider than asked for; a pre-existing one that fails any of those
//!   is refused rather than used.
//!
//! # Blocking I/O
//!
//! These are synchronous even though the callers are async. The files are a
//! few hundred bytes on `/run`, which is tmpfs — the write is microseconds,
//! and `spawn_blocking` for it would cost more than it saves. Do not reach
//! for these to write anything large.

use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Write `bytes` to `path` as a file only its owner can read.
///
/// Created with `O_CREAT | O_EXCL` at mode 0600 in one step, so it never
/// exists at a wider mode and the open refuses to follow a symlink someone
/// planted at the path. `owner`, when given, receives the file through the
/// open descriptor rather than the path, so nothing can be swapped underneath
/// in between; `None` leaves it owned by the daemon, which is right when the
/// reader is a subprocess the daemon spawns as itself.
///
/// An existing file at `path` is removed first. `O_EXCL` would otherwise
/// refuse to overwrite the one a previous connect left behind, and opening
/// without it would keep whatever mode that file already had — which is the
/// bug this function exists to prevent. The remove/create gap is only safe
/// because the directory is private; see [`ensure_private_dir`].
///
/// # Errors
///
/// Anything the open, write, or chown returns.
pub fn write_private(path: &Path, bytes: &[u8], owner: Option<u32>) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    create_private(path, bytes, owner)
}

/// Like [`write_private`], but fails rather than replacing an existing file.
///
/// The right choice when the path carries randomness and is therefore
/// expected not to exist: a collision means something is wrong, and refusing
/// says so instead of writing a credential over whatever was there. Callers
/// that rewrite a fixed path on every connect want [`write_private`].
///
/// # Errors
///
/// `AlreadyExists` if anything is at `path`, symlink included, plus whatever
/// the write or chown returns.
pub fn create_private(path: &Path, bytes: &[u8], owner: Option<u32>) -> io::Result<()> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;

    // Handed over through the descriptor, not the path, so nothing can be
    // swapped underneath in between — and while it is still 0600, so it goes
    // straight from daemon-only to caller-only.
    if let Some(uid) = owner {
        std::os::unix::fs::fchown(&file, Some(uid), None)?;
    }
    Ok(())
}

/// Create `dir` at `mode` owned by us, or verify that an existing one is.
///
/// `mode` is the caller's choice because the two uses differ: 0700 when only
/// the daemon and the subprocesses it spawns as itself need to get in, 0711
/// when an unprivileged caller has to traverse to a file it was told the path
/// of but must not be able to list.
///
/// A path that already exists is used only if it is a real directory — not a
/// symlink redirecting the writes elsewhere — owned by this process. Anything
/// else is refused. Writing a credential into a directory another account
/// controls is worse than failing the operation, and `create_dir_all` reports
/// success on exactly that case.
///
/// A directory that is ours but wider than `mode` is narrowed, so an install
/// carrying one from an earlier version does not keep it.
///
/// # Errors
///
/// `AlreadyExists` if the path is not a directory, `PermissionDenied` if it
/// belongs to another uid, or whatever the underlying calls return.
pub fn ensure_private_dir(dir: &Path, mode: u32) -> io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match std::fs::DirBuilder::new().mode(mode).create(dir) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }

    // `symlink_metadata`, not `metadata`: the question is what is at this
    // path, not what it points at.
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a directory", dir.display()),
        ));
    }
    if meta.uid() != nix::unistd::getuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {}, not by this daemon — refusing to write credentials into it",
                dir.display(),
                meta.uid()
            ),
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

    fn scratch() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    // --- write_private ------------------------------------------------

    #[test]
    fn a_secret_is_never_written_group_or_world_readable() {
        // `fs::write` creates at 0666 & !umask — 0644 on every system this
        // ships to. That is how an OpenVPN static key and a VPN password
        // ended up readable by every account on the machine.
        let dir = scratch();
        let path = dir.path().join("tls-auth.key");

        write_private(&path, b"static key material", None).unwrap();

        assert_eq!(mode_of(&path), 0o600, "at {:o}", mode_of(&path));
        assert_eq!(std::fs::read(&path).unwrap(), b"static key material");
    }

    #[test]
    fn rewriting_narrows_a_file_left_wide_by_an_older_version() {
        // Upgrades are the case that matters: the 0644 file from before this
        // existed is still on disk, and a reconnect must not inherit its
        // mode. Opening without O_EXCL would do exactly that, because
        // `.mode()` applies only at creation.
        let dir = scratch();
        let path = dir.path().join("auth.txt");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, b"new", None).unwrap();

        assert_eq!(mode_of(&path), 0o600, "inherited the old mode");
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn a_planted_symlink_is_not_written_through() {
        let dir = scratch();
        let victim = dir.path().join("victim");
        let planted = dir.path().join("client.ovpn");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        // The remove clears the symlink itself, not its target, and the
        // create then makes a real file. What must not happen is the secret
        // landing in `victim`.
        write_private(&planted, b"secret", None).unwrap();

        assert!(!victim.exists(), "written through the symlink");
        assert_eq!(std::fs::read(&planted).unwrap(), b"secret");
        assert_eq!(mode_of(&planted), 0o600);
    }

    #[test]
    fn an_owner_can_be_named_for_files_a_subprocess_reads_as_someone_else() {
        // As root any uid can be given the file; unprivileged, only our own.
        let dir = scratch();
        let me = nix::unistd::getuid().as_raw();
        let target = if nix::unistd::getuid().is_root() { 12345 } else { me };
        let path = dir.path().join("key");

        write_private(&path, b"k", Some(target)).unwrap();

        assert_eq!(std::fs::metadata(&path).unwrap().uid(), target);
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn no_owner_leaves_the_file_with_the_daemon() {
        let dir = scratch();
        let path = dir.path().join("key");

        write_private(&path, b"k", None).unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().uid(),
            nix::unistd::getuid().as_raw()
        );
    }

    // --- ensure_private_dir -------------------------------------------

    #[test]
    fn a_directory_is_born_at_the_mode_asked_for() {
        let dir = scratch();
        for (name, mode) in [("private", 0o700), ("traversable", 0o711)] {
            let path = dir.path().join(name);
            ensure_private_dir(&path, mode).unwrap();
            assert_eq!(mode_of(&path), mode, "{name} created at {:o}", mode_of(&path));
        }
    }

    #[test]
    fn a_directory_left_wide_by_an_older_version_is_narrowed() {
        let dir = scratch();
        let path = dir.path().join("run");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        ensure_private_dir(&path, 0o700).unwrap();

        assert_eq!(mode_of(&path), 0o700);
    }

    #[test]
    fn a_symlink_standing_in_for_the_directory_is_refused() {
        // Following it would let whoever planted it choose where a root
        // daemon writes — an arbitrary-write primitive, not just a leak.
        let dir = scratch();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let planted = dir.path().join("run");
        std::os::unix::fs::symlink(&elsewhere, &planted).unwrap();

        let err = ensure_private_dir(&planted, 0o700).expect_err("followed a symlink");

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn a_directory_owned_by_someone_else_is_refused() {
        // Needs a directory we do not own, which only root can arrange.
        if !nix::unistd::getuid().is_root() {
            return;
        }
        let dir = scratch();
        let planted = dir.path().join("run");
        std::fs::create_dir(&planted).unwrap();
        std::os::unix::fs::chown(&planted, Some(12345), None).unwrap();

        let err = ensure_private_dir(&planted, 0o700)
            .expect_err("used a directory belonging to another account");

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_file_standing_in_for_the_directory_is_refused() {
        let dir = scratch();
        let path = dir.path().join("run");
        std::fs::write(&path, b"not a directory").unwrap();

        let err = ensure_private_dir(&path, 0o700).expect_err("used a plain file as a directory");

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn missing_parents_are_created() {
        let dir = scratch();
        let path = dir.path().join("a/b/c/run");

        ensure_private_dir(&path, 0o700).unwrap();

        assert!(path.is_dir());
        assert_eq!(mode_of(&path), 0o700);
    }

    #[test]
    fn re_running_is_idempotent() {
        // Every connect calls this. It must not fail the second time.
        let dir = scratch();
        let path = dir.path().join("run");

        ensure_private_dir(&path, 0o700).unwrap();
        ensure_private_dir(&path, 0o700).unwrap();

        assert_eq!(mode_of(&path), 0o700);
    }

    // --- the call sites -----------------------------------------------

    /// Every VPN backend stages its credentials through this module.
    ///
    /// The functions above being correct is no use if a call site doesn't
    /// call them, which is the state all three backends were in: each wrote
    /// its own secrets with `fs::write` and got 0644. There is no way to
    /// exercise those paths in a test — they need an Entra tenant, an
    /// `OpenVPN` server, a `FortiGate` — so this reads the sources instead.
    ///
    /// A source-level check is a blunt instrument and it will annoy someone
    /// adding an unrelated write. That is the intended cost: the reviewer's
    /// question at that moment is "is this a secret?", and the answer for
    /// everything these files currently write is yes.
    #[test]
    fn no_vpn_backend_writes_a_file_without_going_through_this_module() {
        for (name, source) in [
            ("azure", include_str!("vpn/azure.rs")),
            ("openvpn", include_str!("vpn/openvpn.rs")),
            ("fortigate", include_str!("vpn/fortigate.rs")),
        ] {
            for (lineno, line) in source.lines().enumerate() {
                // Comments discuss the calls that used to be here.
                let code = line.split("//").next().unwrap_or("");
                for banned in ["fs::write(", "create_dir_all(", "set_permissions("] {
                    assert!(
                        !code.contains(banned),
                        "{name}.rs:{} calls {banned} directly — use \
                         secure_file::write_private / ensure_private_dir, or the \
                         file lands at the umask (0644):\n  {}",
                        lineno + 1,
                        line.trim()
                    );
                }
            }
        }
    }
}
