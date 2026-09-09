use anyhow::{bail, Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

/// Fail rather than chmod/chown an existing attacker-controlled tree.
pub fn ensure_root_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("Privileged directory must be absolute");
    }
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if !ancestor.exists() {
            fs::DirBuilder::new().mode(0o755).create(ancestor)?;
        }
        let meta = fs::symlink_metadata(ancestor)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            bail!("Privileged directory must be root-owned, non-symlink and not group/world writable: {}", ancestor.display());
        }
    }
    Ok(())
}

pub fn stage_file(
    source: &Path,
    directory: &Path,
    maximum: u64,
) -> Result<tempfile::NamedTempFile> {
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)
        .context("open source without following symlinks")?;
    if !source.metadata()?.is_file() {
        bail!("Source must be a regular file");
    }
    let mut staged = tempfile::NamedTempFile::new_in(directory)?;
    let count = std::io::copy(&mut source.take(maximum + 1), &mut staged)?;
    if count == 0 || count > maximum {
        bail!("Source is empty or exceeds size limit");
    }
    staged.as_file().sync_all()?;
    Ok(staged)
}

pub fn read_config(source: &Path, maximum: u64) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)?;
    if !file.metadata()?.is_file() {
        bail!("Configuration must be a regular file");
    }
    let mut content = String::new();
    file.take(maximum + 1).read_to_string(&mut content)?;
    if content.len() as u64 > maximum {
        bail!("Configuration exceeds size limit");
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staging_is_bounded_private_and_independent_of_later_source_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        fs::write(&path, b"reviewed").unwrap();
        let staged = stage_file(&path, dir.path(), 100).unwrap();
        fs::write(&path, b"replaced").unwrap();
        assert_eq!(fs::read(staged.path()).unwrap(), b"reviewed");
        assert_eq!(staged.as_file().metadata().unwrap().mode() & 0o777, 0o600);
        assert!(stage_file(&path, dir.path(), 1).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(stage_file(&link, dir.path(), 100).is_err());
        assert!(stage_file(dir.path(), dir.path(), 100).is_err());
        assert!(ensure_root_directory(dir.path()).is_err());
    }
}

/// Runtime deployment is a root-admin installation step, never an in-place
/// chmod/chown of Homebrew. Reject writable files, symlinks and special files.
pub fn check_root_ancestors(root: &Path) -> Result<()> {
    for parent in root.ancestors() {
        let meta = fs::symlink_metadata(parent).context("Managed VPN runtime is not installed")?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            bail!("VPN runtime requires a protected root-owned directory tree");
        }
    }
    Ok(())
}

pub fn check_runtime_tree(root: &Path) -> Result<()> {
    check_root_ancestors(root)?;
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0;
    while let Some(path) = pending.pop() {
        visited += 1;
        if visited > 10000 {
            bail!("VPN runtime tree is too large");
        }
        let meta = fs::symlink_metadata(&path)?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 || !(meta.is_file() || meta.is_dir()) {
            bail!("VPN runtime contains an unsafe file");
        }
        if meta.is_dir() {
            for child in fs::read_dir(path)? {
                pending.push(child?.path());
            }
        }
    }
    Ok(())
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("private file needs a directory")?;
    ensure_root_directory(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
