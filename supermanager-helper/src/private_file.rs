//! Files only root may read: connect arguments, VPN secrets, configs
//! with keys inline.
//!
//! `write` replaces the file whole. The new contents go to a fresh file
//! created with mode 0600, which is then renamed over the old one, so a
//! reader sees the old version or the new one, and the file is never
//! readable by anyone else, not even for a moment. The rename replaces a
//! symlink at `path` instead of writing through it, and a file that used
//! to have wider permissions ends up with 0600.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::write;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn replaces_a_permissive_file_and_does_not_follow_a_symlink() {
        let dir =
            std::env::temp_dir().join(format!("supermanager-private-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("secrets.conf");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write(&path, b"private").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "private");

        let target = dir.join("untouched");
        std::fs::write(&target, "original").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        write(&path, b"replacement").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "replacement");
        assert!(!std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        // No temporary file left behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
