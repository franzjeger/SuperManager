//! Private, atomic exports and read-only checks of portable backups.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::Path;

use anyhow::{bail, Context as _};
use base64::Engine as _;
use supermgr_core::backup::{PortableBackup, BACKUP_VERSION};

/// Replace an export atomically with a file created owner-only from the start.
/// The previous file survives a failed write. Symlinks and hard links at the
/// destination cannot redirect the write into another file.
pub fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent).context("create private export")?;
    file.write_all(bytes).context("write export")?;
    file.as_file().sync_all().context("flush export")?;
    file.persist(path)
        .map_err(|e| e.error)
        .context("save export")?;
    Ok(())
}

/// Check the file format and encoded contents without importing any records.
/// This is an integrity check, not a promise that remote services or external
/// OpenVPN files will be available when the backup is restored.
pub fn verify(bytes: &[u8]) -> anyhow::Result<String> {
    // Don't include serde's source snippet: malformed fields can be secrets.
    let backup: PortableBackup = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("The file is not a readable SuperManager portable backup."))?;
    if backup.version != BACKUP_VERSION {
        bail!(
            "Unsupported backup format {} (expected {}).",
            backup.version,
            BACKUP_VERSION
        );
    }
    let mut ids = HashSet::new();
    for id in backup
        .profiles
        .iter()
        .map(|p| p.id)
        .chain(backup.ssh_keys.iter().map(|k| k.id))
        .chain(backup.hosts.iter().map(|h| h.id))
    {
        if !ids.insert(id) {
            bail!("The backup contains duplicate record IDs.");
        }
    }
    for value in backup.secrets.values() {
        if base64::engine::general_purpose::STANDARD
            .decode(value)
            .is_err()
        {
            bail!("The backup contains an unreadable encoded credential.");
        }
    }
    for filename in backup.config_backups.keys() {
        if filename.is_empty()
            || filename == "."
            || filename == ".."
            || filename.contains(['/', '\\', '\0'])
        {
            bail!("The backup contains an unsafe configuration filename.");
        }
    }
    for customer in &backup.customers {
        customer
            .validate()
            .map_err(|_| anyhow::anyhow!("The backup contains an invalid customer record."))?;
    }
    let counts = backup.counts();
    Ok(format!(
        "Format and encoded data checked: {} VPN profiles, {} SSH keys, {} hosts, {} customers and {} credentials.\n\nNothing was imported. External VPN files and remote connectivity were not tested.",
        counts.profiles, counts.ssh_keys, counts.hosts, counts.customers, counts.secrets,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    #[test]
    fn replacing_a_public_export_makes_it_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.json");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, b"new secret").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new secret");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn export_does_not_write_through_links() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("untouched");
        std::fs::write(&target, "original").unwrap();
        for hard in [false, true] {
            let path = dir.path().join(if hard { "hard" } else { "symbolic" });
            if hard {
                std::fs::hard_link(&target, &path).unwrap();
            } else {
                symlink(&target, &path).unwrap();
            }
            write_private(&path, b"secret").unwrap();
            assert_eq!(std::fs::read(&target).unwrap(), b"original");
        }
    }

    #[test]
    fn verification_checks_data_without_exposing_credentials() {
        let mut backup = PortableBackup::new();
        backup.secrets.insert("password".into(), "c2VjcmV0".into());
        assert!(verify(&serde_json::to_vec(&backup).unwrap()).is_ok());
        backup
            .secrets
            .insert("password".into(), "PRIVATE BAD VALUE!".into());
        let error = verify(&serde_json::to_vec(&backup).unwrap())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("PRIVATE"));
        backup.secrets.clear();
        backup
            .config_backups
            .insert("../escape.conf".into(), String::new());
        assert!(verify(&serde_json::to_vec(&backup).unwrap()).is_err());
        assert!(verify(br#"{"version":999}"#).is_err());
        assert!(verify(b"not a backup").is_err());
    }
}
