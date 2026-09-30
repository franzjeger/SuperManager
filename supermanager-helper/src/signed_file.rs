//! Installing a program the helper will run as root.
//!
//! The helper copies the file it is pointed at and checks the copy, in the
//! directory it installs to, before renaming it into place: the file that
//! runs is the file that passed. The source is read once, as a regular file
//! and not through a symlink. A copy that fails the check is removed and the
//! installed program, if any, is left as it was.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Install a copy of `source` at `target` if `check` passes it.
pub fn install(
    source: &Path,
    target: &Path,
    check: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut from = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)
        .with_context(|| format!("open {}", source.display()))?;
    if !from.metadata()?.is_file() {
        bail!("{} is not a regular file", source.display());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let staged = PathBuf::from(format!(
        "{}.{}.tmp",
        target.display(),
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| -> Result<()> {
        let mut to = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&staged)
            .with_context(|| format!("create {}", staged.display()))?;
        std::io::copy(&mut from, &mut to).context("copy")?;
        to.sync_all()?;
        drop(to);
        check(&staged)?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
        fs::rename(&staged, target).with_context(|| format!("install {}", target.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

/// `path` is signed by SuperManager with `identifier`: anchored at Apple,
/// SuperManager's team, every architecture valid.
#[cfg(target_os = "macos")]
pub fn signed_by_supermanager(path: &Path, identifier: &str) -> Result<()> {
    use core_foundation::url::CFURL;
    use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};
    let requirement: SecRequirement = format!(
        "anchor apple generic and certificate leaf[subject.OU] = \"{}\" \
         and identifier \"{identifier}\"",
        crate::client_auth::TEAM_ID
    )
    .parse()
    .context("code requirement")?;
    let url = CFURL::from_path(path, false).context("path")?;
    SecStaticCode::from_path(&url, Flags::NONE)
        .and_then(|code| {
            code.check_validity(
                Flags::CHECK_ALL_ARCHITECTURES | Flags::STRICT_VALIDATE,
                &requirement,
            )
        })
        .map_err(|e| anyhow::anyhow!("not {identifier} as SuperManager signs it ({e})"))
}

#[cfg(not(target_os = "macos"))]
pub fn signed_by_supermanager(_: &Path, _: &str) -> Result<()> {
    bail!("code signatures can only be checked on macOS")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("supermanager-signed-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        dir
    }

    /// Signed by Apple, but not SuperManager's: nothing is installed, and
    /// the staged copy is gone.
    #[test]
    fn a_program_supermanager_did_not_sign_is_not_installed() {
        let dir = scratch_dir();
        let target = dir.join("program");
        let err = install(Path::new("/usr/bin/true"), &target, |copy| {
            signed_by_supermanager(copy, "com.sybr.supermanager.test")
        })
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("not com.sybr.supermanager.test as SuperManager signs it")
        );
        assert!(!target.exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_source_is_not_read_through_a_symlink_or_as_a_directory() {
        let dir = scratch_dir();
        let link = dir.join("link");
        std::os::unix::fs::symlink("/usr/bin/true", &link).unwrap();
        assert!(install(&link, &dir.join("program"), |_| Ok(())).is_err());
        assert!(install(&dir, &dir.join("program"), |_| Ok(())).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    /// A copy that passes replaces the installed program whole.
    #[test]
    fn a_copy_that_passes_replaces_the_installed_program() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir();
        let source = dir.join("new");
        let target = dir.join("installed");
        fs::write(&source, "new").unwrap();
        fs::write(&target, "old").unwrap();
        install(&source, &target, |copy| {
            assert_eq!(fs::read_to_string(copy).unwrap(), "new");
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
