//! Master-password storage, isolated from the rest of `AppSettings`.
//!
//! # Why a dedicated file
//!
//! The hash used to live inside `AppSettings` (the same struct as theme,
//! opacity, RDP-client preference, webhook config). Every time *any* of
//! those settings changed, the GUI called `AppSettings::save()` which
//! wrote the whole struct back — including the `password_hash` field
//! that had been loaded into memory at startup. That made the password
//! impossible to genuinely remove without quitting the GUI first: every
//! tweak silently re-saved it.
//!
//! Splitting the hash into its own file means:
//!
//! - The only writers are [`set`] and [`clear`] (explicit user actions
//!   from the lock screen or the change-password dialog).
//! - Editing or deleting the hash file from disk is permanent — there
//!   is no in-memory copy held by an unrelated struct that will quietly
//!   restore it.
//! - `AppSettings::save()` no longer touches the password at all.
//!
//! # On-disk layout
//!
//! `~/.config/supermgr/master-password.hash` (or
//! `$XDG_CONFIG_HOME/supermgr/master-password.hash`). The file contains
//! exactly the hash string with no surrounding JSON or markup, written
//! with `0600` permissions when possible.

use std::fs;
use std::io;
use std::path::PathBuf;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sha2::{Digest, Sha256};
use tracing::warn;

/// Resolve the path to the master-password hash file.
///
/// Mirrors `settings_path()` in `settings.rs`: prefer `XDG_CONFIG_HOME`
/// when set, fall back to `~/.config`, last-resort `./` for tests run
/// without a home directory.
fn hash_path() -> PathBuf {
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| {
                let mut p = PathBuf::from(h);
                p.push(".config");
                p
            })
        })
        .unwrap_or_else(|| PathBuf::from("."));
    config_dir.join("supermgr").join("master-password.hash")
}

/// Read the stored hash, if any.
///
/// Returns `None` when the file does not exist, is unreadable, or
/// contains only whitespace. Trailing newlines from a `printf '...' >`
/// invocation are stripped.
pub fn read() -> Option<String> {
    let path = hash_path();
    let raw = fs::read_to_string(&path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Persist `hash` to the hash file with `0600` permissions when supported.
fn write_raw(hash: &str) -> io::Result<()> {
    let path = hash_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, hash.as_bytes())?;

    // Best-effort permissions tightening — silently skipped on platforms
    // without Unix permission semantics.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Delete the hash file, if it exists. Idempotent — `NotFound` is treated
/// as success.
pub fn clear() {
    let path = hash_path();
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => warn!("master_password::clear: unlink {}: {e}", path.display()),
    }
}

/// Returns `true` when a master password is currently configured.
pub fn is_set() -> bool {
    read().is_some()
}

/// Hash `password` with Argon2id (OWASP defaults from the `argon2` crate)
/// and persist. Returns the resulting PHC string on success.
///
/// Argon2id failure is exceedingly rare (allocation failure inside the
/// hashing routine); the caller can choose how to surface it.
pub fn set(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
    if let Err(e) = write_raw(&phc) {
        warn!("master_password::set: write hash file: {e}");
    }
    Ok(phc)
}

/// Verify `password` against the stored hash, accepting both the modern
/// Argon2id PHC string and the legacy `<hex_salt>:<sha256_hex>` format
/// from pre-Argon2 builds.
///
/// Returns `false` when no hash is stored.
pub fn verify(password: &str) -> bool {
    let Some(stored) = read() else {
        return false;
    };
    if stored.starts_with("$argon2") {
        verify_argon2(password, &stored)
    } else if let Some((salt, expected)) = stored.split_once(':') {
        verify_legacy_sha256(password, salt, expected)
    } else {
        false
    }
}

/// `true` iff the stored hash is in the legacy SHA-256 format and should
/// be re-hashed at the next successful unlock.
pub fn needs_upgrade() -> bool {
    match read() {
        Some(s) => !s.starts_with("$argon2"),
        None => false,
    }
}

/// Re-hash `password` with Argon2id and overwrite the stored hash.
///
/// The caller must have just verified the password — this routine trusts
/// its argument and replaces the stored hash unconditionally.
pub fn upgrade_legacy(password: &str) {
    if let Ok(phc) = Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
    {
        if let Err(e) = write_raw(&phc.to_string()) {
            warn!("master_password::upgrade_legacy: write: {e}");
        }
    }
}

fn verify_argon2(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

fn verify_legacy_sha256(password: &str, salt_hex: &str, expected_hex: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(salt_hex.as_bytes());
    hasher.update(password.as_bytes());
    let computed = format!("{:x}", hasher.finalize());
    computed.len() == expected_hex.len()
        && computed
            .bytes()
            .zip(expected_hex.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// One-shot migration: if the legacy `password_hash` field carried a
/// non-empty value in `settings.json`, move it to the dedicated file.
///
/// Idempotent — calling on an empty input does nothing. Called from
/// `AppSettings::load` after deserialisation.
pub fn migrate_from_legacy_field(legacy_hash: &str) {
    if legacy_hash.trim().is_empty() {
        return;
    }
    if read().is_some() {
        // A dedicated-file hash already exists; the legacy field is
        // residual data we shouldn't touch. Just trust the dedicated file.
        return;
    }
    if let Err(e) = write_raw(legacy_hash) {
        warn!("master_password::migrate: write hash file: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a closure with a temporary $XDG_CONFIG_HOME so each test gets
    /// its own hash file and they don't stomp on each other.
    ///
    /// `XDG_CONFIG_HOME` is process-global env state; cargo runs tests
    /// concurrently by default, so we serialize via a Mutex to keep
    /// parallel tests from clobbering each other's env. The closure
    /// receives the lock guard and the env var stays redirected for the
    /// closure's whole duration.
    fn with_tmp_xdg<F: FnOnce()>(f: F) {
        use std::sync::{Mutex, OnceLock};
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        f();
        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[test]
    fn set_and_verify_round_trip() {
        with_tmp_xdg(|| {
            assert!(!is_set());
            set("correct horse battery staple").unwrap();
            assert!(is_set());
            assert!(verify("correct horse battery staple"));
            assert!(!verify("wrong"));
            assert!(!needs_upgrade());
        });
    }

    #[test]
    fn legacy_format_verifies_and_upgrades() {
        with_tmp_xdg(|| {
            let pw = "old-pass";
            let salt = "0123456789abcdef0123456789abcdef";
            let mut h = Sha256::new();
            h.update(salt.as_bytes());
            h.update(pw.as_bytes());
            let legacy = format!("{salt}:{:x}", h.finalize());

            // Simulate a freshly migrated legacy hash.
            migrate_from_legacy_field(&legacy);
            assert!(is_set());
            assert!(verify(pw));
            assert!(needs_upgrade());

            upgrade_legacy(pw);
            assert!(verify(pw));
            assert!(!needs_upgrade());
        });
    }

    #[test]
    fn clear_removes_hash() {
        with_tmp_xdg(|| {
            set("temp").unwrap();
            assert!(is_set());
            clear();
            assert!(!is_set());
            // Clearing a missing hash is silent.
            clear();
            assert!(!is_set());
        });
    }

    #[test]
    fn unset_state_rejects_everything() {
        with_tmp_xdg(|| {
            assert!(!is_set());
            assert!(!verify(""));
            assert!(!verify("anything"));
            assert!(!needs_upgrade());
        });
    }

    #[test]
    fn migrate_no_op_when_field_empty() {
        with_tmp_xdg(|| {
            assert!(!is_set());
            migrate_from_legacy_field("");
            migrate_from_legacy_field("   ");
            assert!(!is_set());
        });
    }

    #[test]
    fn migrate_does_not_clobber_dedicated_file() {
        with_tmp_xdg(|| {
            // Pre-existing dedicated hash takes precedence over a stale
            // legacy field still hanging around in settings.json.
            set("dedicated").unwrap();
            let before = read().unwrap();
            migrate_from_legacy_field("0123:abcd");
            let after = read().unwrap();
            assert_eq!(before, after, "dedicated file should be untouched");
        });
    }
}
