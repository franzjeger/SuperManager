//! The programs the helper runs WireGuard with, from a directory only root
//! can write.
//!
//! Homebrew's prefix belongs to the user, not to root, and the helper runs
//! programs as root only from where only root can write. The app bundles
//! its own `wg-quick`, the bash that runs it, `wg` and `wireguard-go`
//! (scripts/build-vpn-runtime.sh), and the helper installs each into
//! [`RUNTIME_DIR`] only after checking it: the Mach-O programs by
//! SuperManager's signature, `wg-quick` by a pinned SHA-256.
//!
//! A development build that bundles no runtime runs Homebrew's WireGuard as
//! before, and the log says so.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::client_auth::Policy;

pub const RUNTIME_DIR: &str = "/Library/PrivilegedHelperTools/SuperManagerVPN";

/// Process-wide policy set once at helper startup before watchdogs start.
/// Defaults to `Policy::Release` (fail-closed) when unset.
static RUNTIME_POLICY: OnceLock<Policy> = OnceLock::new();

pub fn init_policy(policy: Policy) {
    let _ = RUNTIME_POLICY.set(policy);
}

pub fn current_policy() -> Policy {
    RUNTIME_POLICY.get().copied().unwrap_or(Policy::Release)
}

/// The runtime's required WireGuard programs and the identifiers the app signs them with.
const SIGNED: [(&str, &str); 3] = [
    ("bash", "com.sybr.supermanager.vpn.bash"),
    ("wg", "com.sybr.supermanager.vpn.wg"),
    ("wireguard-go", "com.sybr.supermanager.vpn.wireguard-go"),
];

/// Optional VPN backend binaries installed into [`RUNTIME_DIR`] when bundled.
const OPTIONAL_SIGNED: [(&str, &str); 4] = [
    ("charon", "com.sybr.supermanager.vpn.charon"),
    ("swanctl", "com.sybr.supermanager.vpn.swanctl"),
    ("openvpn", "com.sybr.supermanager.vpn.openvpn"),
    ("openvpn3", "com.sybr.supermanager.vpn.openvpn3"),
];

/// The wg-quick the app bundles: wireguard-tools 1.0.20260223,
/// `src/wg-quick/darwin.bash`. The build refuses to bundle any other.
const WG_QUICK_SHA256: &str = include_str!("wg-quick.sha256");

const BREW_PREFIXES: &[&str] = &["/opt/homebrew", "/usr/local"];

#[derive(Debug, Deserialize)]
pub struct InstallArgs {
    /// `Contents/Resources/vpn-runtime` in the app bundle.
    pub bundled_dir: String,
}

#[derive(Debug, Serialize)]
pub struct InstallResult {
    /// Programs copied in by this call.
    pub installed: Vec<String>,
    /// Programs already installed as bundled.
    pub unchanged: Vec<String>,
}

/// Install the runtime the app bundles into [`RUNTIME_DIR`]. A program
/// already installed with the same content is left alone; one that fails
/// its check is not installed, and the one before it stays.
pub fn install(args: &InstallArgs) -> Result<InstallResult> {
    prepare_runtime_directory(Path::new(RUNTIME_DIR))?;
    let result = install_into(Path::new(&args.bundled_dir), Path::new(RUNTIME_DIR))
        .inspect_err(|e| tracing::warn!("VPN runtime not installed: {e:#}"))?;
    if !result.installed.is_empty() {
        tracing::info!(installed = ?result.installed, "VPN runtime installed in {RUNTIME_DIR}");
    }
    Ok(result)
}

/// Protect the destination before staging any executable in it. An old
/// manual installation may have left the runtime directory user-owned or
/// writable. Its parent must already be protected; a symlink is never a
/// runtime directory. Repair through the opened directory, not its path.
fn prepare_runtime_directory(dir: &Path) -> Result<()> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    if unsafe { libc::geteuid() } != 0 {
        bail!("the VPN runtime must be installed by the root helper");
    }
    let parent = dir
        .parent()
        .context("VPN runtime has no parent directory")?;
    ensure_root_owned(parent, "VPN runtime parent")?;
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
            bail!("VPN runtime {} is not a regular directory", dir.display());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(dir).context("create VPN runtime directory")?;
        }
        Err(error) => return Err(error).context("inspect VPN runtime directory"),
    }
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .context("open VPN runtime directory")?;
    let metadata = directory.metadata()?;
    if metadata.uid() != 0 || metadata.gid() != 0 || metadata.mode() & 0o7777 != 0o755 {
        let fd = directory.as_raw_fd();
        // Remove write access before changing ownership, then grant the
        // normal read/execute access after root owns the directory.
        if unsafe { libc::fchmod(fd, 0o700) } != 0
            || unsafe { libc::fchown(fd, 0, 0) } != 0
            || unsafe { libc::fchmod(fd, 0o755) } != 0
        {
            return Err(std::io::Error::last_os_error()).context("protect VPN runtime directory");
        }
    }
    ensure_root_owned(dir, "VPN runtime directory")
}

fn install_into(bundled: &Path, dir: &Path) -> Result<InstallResult> {
    let mut result = InstallResult {
        installed: Vec::new(),
        unchanged: Vec::new(),
    };
    let mut record = |name: &str, changed: bool| {
        let list = if changed {
            &mut result.installed
        } else {
            &mut result.unchanged
        };
        list.push(name.to_owned());
    };
    for (name, identifier) in SIGNED {
        let changed = install_one(bundled, dir, name, |copy| {
            crate::signed_file::signed_by_supermanager(copy, identifier)
        })?;
        record(name, changed);
    }
    let changed = install_one(bundled, dir, "wg-quick", check_wg_quick)?;
    record("wg-quick", changed);
    for (name, identifier) in OPTIONAL_SIGNED {
        if bundled.join(name).exists() {
            let changed = install_one(bundled, dir, name, |copy| {
                crate::signed_file::signed_by_supermanager(copy, identifier)
            })?;
            record(name, changed);
        }
    }
    Ok(result)
}

/// Install `name` unless the installed file has the same content: that
/// one passed its check when it was installed.
fn install_one(
    bundled: &Path,
    dir: &Path,
    name: &str,
    check: impl FnOnce(&Path) -> Result<()>,
) -> Result<bool> {
    let source = bundled.join(name);
    let target = dir.join(name);
    // Equal bytes are not enough: a user-owned/writable file or a symlink
    // would still be refused at execution time. Reinstall it through the
    // verified atomic-copy path so clicking Install can repair it.
    if installed_file_is_protected(&target, unsafe { libc::geteuid() })
        && same_content(&source, &target)
    {
        return Ok(false);
    }
    crate::signed_file::install(&source, &target, check)
        .with_context(|| format!("install {name}"))?;
    Ok(true)
}

fn installed_file_is_protected(path: &Path, expected_uid: u32) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_file() && metadata.uid() == expected_uid && metadata.mode() & 0o7777 == 0o755
    })
}

fn same_content(a: &Path, b: &Path) -> bool {
    matches!((std::fs::read(a), std::fs::read(b)), (Ok(a), Ok(b)) if a == b)
}

fn check_wg_quick(copy: &Path) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let hex = Sha256::digest(std::fs::read(copy)?).iter().fold(
        String::with_capacity(64),
        |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        },
    );
    if hex != WG_QUICK_SHA256.trim() {
        bail!("wg-quick is not the script SuperManager bundles");
    }
    Ok(())
}

/// How to run wg-quick.
pub struct WgQuick {
    program: PathBuf,
    script: Option<PathBuf>,
    path: String,
}

impl WgQuick {
    /// `wg-quick`, ready for its arguments.
    pub fn command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(&self.program);
        if let Some(script) = &self.script {
            command.arg(script);
        }
        // wg-quick puts the system directories first and its own after
        // them, where it finds `wg` and `wireguard-go`.
        command.env("PATH", &self.path);
        command
    }

    pub fn describe(&self) -> String {
        match &self.script {
            Some(script) => format!("{} {}", self.program.display(), script.display()),
            None => self.program.display().to_string(),
        }
    }
}

fn installed(dir: &Path) -> bool {
    SIGNED
        .iter()
        .map(|(name, _)| *name)
        .chain(["wg-quick"])
        .all(|name| dir.join(name).is_file())
}

/// Verify that `path`, its resolved target, and every ancestor directory are
/// owned by `root` (`uid == 0`) and are neither group- nor world-writable
/// (`mode & 0o022 == 0`). Under [`Policy::Release`], the root helper refuses
/// to execute any binary or load any daemon config from paths writable by an
/// unprivileged console user (such as `/opt/homebrew` or `/usr/local`).
pub fn ensure_root_owned(path: &Path, kind: &str) -> Result<()> {
    ensure_owned_by(path, 0, kind)
}

fn ensure_owned_by(path: &Path, expected_uid: u32, kind: &str) -> Result<()> {
    let sym = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {kind} {}", path.display()))?;
    if sym.uid() != expected_uid {
        bail!(
            "{kind} {} is owned by uid {} (expected uid {expected_uid}); \
             install the root-owned VPN runtime via `vpn_runtime_install`",
            path.display(),
            sym.uid()
        );
    }
    if !sym.file_type().is_symlink() && (sym.mode() & 0o022 != 0) {
        bail!(
            "{kind} {} is group- or world-writable (mode {:04o}); \
             install the root-owned VPN runtime via `vpn_runtime_install`",
            path.display(),
            sym.mode() & 0o777
        );
    }

    let meta =
        std::fs::metadata(path).with_context(|| format!("resolve {kind} {}", path.display()))?;
    if meta.uid() != expected_uid {
        bail!(
            "{kind} target {} is owned by uid {} (expected uid {expected_uid}); \
             install the root-owned VPN runtime via `vpn_runtime_install`",
            path.display(),
            meta.uid()
        );
    }
    if meta.mode() & 0o022 != 0 {
        bail!(
            "{kind} target {} is group- or world-writable (mode {:04o}); \
             install the root-owned VPN runtime via `vpn_runtime_install`",
            path.display(),
            meta.mode() & 0o777
        );
    }

    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("canonicalize {kind} {}", path.display()))?;
    for ancestor in canonical.ancestors() {
        let dir_meta = std::fs::metadata(ancestor)
            .with_context(|| format!("stat ancestor {}", ancestor.display()))?;
        if dir_meta.uid() != expected_uid {
            bail!(
                "{kind} {} resides under non-root directory {} (uid {}); \
                 install the root-owned VPN runtime via `vpn_runtime_install`",
                path.display(),
                ancestor.display(),
                dir_meta.uid()
            );
        }
        if dir_meta.mode() & 0o022 != 0 {
            bail!(
                "{kind} {} resides under group- or world-writable directory {} (mode {:04o}); \
                 install the root-owned VPN runtime via `vpn_runtime_install`",
                path.display(),
                ancestor.display(),
                dir_meta.mode() & 0o777
            );
        }
    }
    Ok(())
}

/// wg-quick from the runtime, run by the runtime's bash; Homebrew's only in
/// Development builds when no runtime is installed (or under Release only if
/// root-owned and non-writable by others).
pub fn wg_quick(policy: Policy) -> Result<WgQuick> {
    let dir = Path::new(RUNTIME_DIR);
    if installed(dir) {
        if policy == Policy::Release {
            for name in ["bash", "wg-quick", "wg", "wireguard-go"] {
                ensure_root_owned(&dir.join(name), "VPN runtime binary")?;
            }
        }
        return Ok(WgQuick {
            program: dir.join("bash"),
            script: Some(dir.join("wg-quick")),
            path: format!("{RUNTIME_DIR}:/usr/sbin:/sbin:/usr/bin:/bin"),
        });
    }
    let brew = homebrew("wg-quick", policy)?;
    let bin = brew
        .parent()
        .map(Path::display)
        .map(|d| d.to_string())
        .unwrap_or_default();
    let path = match policy {
        Policy::Release => format!("{bin}:/usr/sbin:/sbin:/usr/bin:/bin"),
        Policy::Development => format!("{bin}:/usr/local/sbin:/usr/sbin:/sbin:/usr/bin:/bin"),
    };
    Ok(WgQuick {
        program: brew,
        script: None,
        path,
    })
}

/// wireguard-go from the runtime, for the helper's own WireGuard setup
/// (`wg_native`), which has no Homebrew fallback.
pub fn wireguard_go(policy: Policy) -> Result<PathBuf> {
    let dir = Path::new(RUNTIME_DIR);
    if !installed(dir) {
        bail!(
            "SuperManager's own WireGuard setup needs the root-owned VPN runtime in \
             {RUNTIME_DIR}, and it is not installed (run `vpn_runtime_install`)"
        );
    }
    let bin = dir.join("wireguard-go");
    if policy == Policy::Release {
        ensure_root_owned(&bin, "wireguard-go binary")?;
    }
    Ok(bin)
}

/// `wg`, from the runtime or else Homebrew (in Development builds, or in
/// Release only if root-owned and not group/world-writable).
pub fn wg(policy: Policy) -> Result<PathBuf> {
    let dir = Path::new(RUNTIME_DIR);
    if installed(dir) {
        let bin = dir.join("wg");
        if policy == Policy::Release {
            ensure_root_owned(&bin, "wg binary")?;
        }
        return Ok(bin);
    }
    homebrew("wg", policy)
}

fn homebrew(name: &str, policy: Policy) -> Result<PathBuf> {
    static WARNED: AtomicBool = AtomicBool::new(false);
    let mut last_refusal: Option<anyhow::Error> = None;
    for prefix in BREW_PREFIXES {
        let candidate = Path::new(prefix).join("bin").join(name);
        if !candidate.exists() {
            continue;
        }
        if policy == Policy::Release {
            if let Err(e) = ensure_root_owned(&candidate, "WireGuard fallback binary") {
                last_refusal = Some(e);
                continue;
            }
        }
        if !WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "WireGuard uses Homebrew's tools: no VPN runtime is installed in {RUNTIME_DIR} \
                 (the app installs the one it bundles before a WireGuard connect)"
            );
        }
        return Ok(candidate);
    }
    if let Some(refusal) = last_refusal {
        return Err(refusal.context(format!(
            "refusing unprivileged `{name}` in Release mode; install the root-owned VPN runtime \
             in {RUNTIME_DIR} (`vpn_runtime_install`)"
        )));
    }
    match policy {
        Policy::Release => Err(anyhow!(
            "{name} not found in {RUNTIME_DIR}: Release builds require the root-owned VPN runtime \
             (run `vpn_runtime_install` from SuperManager)"
        )),
        Policy::Development => Err(anyhow!(
            "{name} not found: no VPN runtime is installed, and Homebrew's \
             wireguard-tools is not either"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin is a digest alone, as `shasum -a 256 | cut -d' ' -f1` writes
    /// it and the build script reads it.
    #[test]
    fn the_wg_quick_pin_is_a_sha256() {
        let pin = WG_QUICK_SHA256.trim();
        assert_eq!(pin.len(), 64, "{pin:?}");
        assert!(
            pin.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{pin:?}"
        );
    }

    fn scratch_dir() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("supermanager-runtime-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn identical_writable_files_are_verified_and_reinstalled() {
        use std::cell::Cell;
        use std::os::unix::fs::PermissionsExt as _;

        let bundled = scratch_dir();
        let dir = scratch_dir();
        let source = bundled.join("openvpn3");
        let target = dir.join("openvpn3");
        std::fs::write(&source, "same executable").unwrap();
        std::fs::write(&target, "same executable").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o775)).unwrap();

        // A repair must still verify the staged executable. Refusing it
        // leaves the installed file and its permissions untouched.
        assert!(install_one(&bundled, &dir, "openvpn3", |_| bail!("unsigned")).is_err());
        assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o7777, 0o775);
        let checked = Cell::new(false);
        assert!(install_one(&bundled, &dir, "openvpn3", |copy| {
            checked.set(true);
            assert_eq!(std::fs::read(copy)?, b"same executable");
            Ok(())
        })
        .unwrap());
        assert!(checked.get());
        assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o7777, 0o755);
        // Once repaired, another request is a true no-op.
        assert!(!install_one(&bundled, &dir, "openvpn3", |_| bail!(
            "must not verify again"
        ))
        .unwrap());
        std::fs::remove_dir_all(bundled).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn identical_symlink_targets_are_replaced_without_changing_the_link_destination() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let bundled = scratch_dir();
        let dir = scratch_dir();
        let source = bundled.join("openvpn3");
        let outside = bundled.join("other-program");
        let target = dir.join("openvpn3");
        std::fs::write(&source, "same executable").unwrap();
        std::fs::write(&outside, "same executable").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
        let original_inode = std::fs::metadata(&outside).unwrap().ino();
        symlink(&outside, &target).unwrap();

        assert!(install_one(&bundled, &dir, "openvpn3", |_| Ok(())).unwrap());
        assert!(std::fs::symlink_metadata(&target).unwrap().is_file());
        assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o7777, 0o755);
        assert_eq!(std::fs::metadata(&outside).unwrap().ino(), original_inode);
        assert_eq!(std::fs::read(&outside).unwrap(), b"same executable");
        std::fs::remove_dir_all(bundled).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_identical_file_with_the_wrong_owner_needs_reinstallation() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch_dir();
        let target = dir.join("openvpn3");
        std::fs::write(&target, "executable").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(installed_file_is_protected(&target, uid));
        assert!(!installed_file_is_protected(
            &target,
            if uid == 0 { 501 } else { 0 }
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_script_that_is_not_the_bundled_wg_quick_is_refused() {
        let dir = scratch_dir();
        let script = dir.join("wg-quick");
        std::fs::write(&script, "#!/usr/bin/env bash\necho hello\n").unwrap();
        assert!(check_wg_quick(&script).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Unsigned programs are not installed, and nothing is half-installed.
    #[test]
    fn an_unsigned_runtime_is_not_installed() {
        let bundled = scratch_dir();
        let dir = scratch_dir();
        for (name, _) in SIGNED {
            std::fs::copy("/usr/bin/true", bundled.join(name)).unwrap();
        }
        std::fs::write(bundled.join("wg-quick"), "#!/usr/bin/env bash\n").unwrap();
        assert!(install_into(&bundled, &dir).is_err());
        assert!(!installed(&dir));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir_all(bundled).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_unsigned_optional_openvpn3_does_not_replace_the_installed_runtime() {
        let bundled = scratch_dir();
        let dir = scratch_dir();
        let target = dir.join("openvpn3");
        std::fs::write(&target, b"previously installed runtime").unwrap();
        std::fs::copy("/usr/bin/true", bundled.join("openvpn3")).unwrap();
        let (_, identifier) = OPTIONAL_SIGNED
            .iter()
            .find(|(name, _)| *name == "openvpn3")
            .unwrap();

        let err = install_one(&bundled, &dir, "openvpn3", |copy| {
            crate::signed_file::signed_by_supermanager(copy, identifier)
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains(identifier), "{err:#}");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"previously installed runtime"
        );
        // No unverified program or staged file is left behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(bundled).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The runtime a signed build bundles installs. Run with the path of a
    /// signed build:
    ///
    /// ```text
    /// SUPERMANAGER_APP=/Applications/SuperManager.app \
    ///     cargo test -p supermanager-helper -- --ignored bundled_vpn_runtime
    /// ```
    #[test]
    #[ignore = "needs a signed SuperManager build, see the doc comment"]
    fn the_bundled_vpn_runtime_of_a_signed_build_installs() {
        let app = std::env::var("SUPERMANAGER_APP").unwrap();
        let bundled = Path::new(&app).join("Contents/Resources/vpn-runtime");
        let expected: Vec<String> = SIGNED
            .iter()
            .map(|(name, _)| *name)
            .chain(["wg-quick"])
            .chain(
                OPTIONAL_SIGNED
                    .iter()
                    .map(|(name, _)| *name)
                    .filter(|name| bundled.join(name).exists()),
            )
            .map(str::to_owned)
            .collect();
        let dir = scratch_dir();
        let first = install_into(&bundled, &dir).unwrap();
        assert_eq!(first.installed, expected, "{first:?}");
        assert!(first.unchanged.is_empty(), "{first:?}");
        assert!(installed(&dir));
        for name in &expected {
            assert!(same_content(&bundled.join(name), &dir.join(name)), "{name}");
        }
        // A second install finds everything in place.
        let again = install_into(&bundled, &dir).unwrap();
        assert_eq!(again.unchanged, expected, "{again:?}");
        assert!(again.installed.is_empty(), "{again:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Unlike the compatibility test above, this requires a build carrying
    /// OpenVPN 3 and verifies its signature through the real installer.
    #[test]
    #[ignore = "needs a signed SuperManager build with OpenVPN 3"]
    fn the_bundled_openvpn3_of_a_signed_build_installs_and_is_unchanged() {
        let app = std::env::var("SUPERMANAGER_APP").unwrap();
        let bundled = Path::new(&app).join("Contents/Resources/vpn-runtime");
        assert!(
            bundled.join("openvpn3").is_file(),
            "no bundled OpenVPN 3 in {app}"
        );
        let dir = scratch_dir();
        let first = install_into(&bundled, &dir).unwrap();
        assert!(first.installed.iter().any(|name| name == "openvpn3"));
        assert!(same_content(
            &bundled.join("openvpn3"),
            &dir.join("openvpn3")
        ));
        let again = install_into(&bundled, &dir).unwrap();
        assert!(again.unchanged.iter().any(|name| name == "openvpn3"));
        assert!(again.installed.is_empty(), "{again:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ownership_check_refuses_wrong_uid_and_writable_modes() {
        use std::os::unix::fs::PermissionsExt as _;

        let base = scratch_dir();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin = base.join("vpn-bin");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let my_uid = unsafe { libc::geteuid() };
        // Non-matching owner (e.g. unprivileged user when root uid=0 is required) is refused.
        let other_uid = if my_uid == 0 { 501 } else { 0 };
        let err = ensure_owned_by(&bin, other_uid, "VPN binary").unwrap_err();
        assert!(err.to_string().contains("vpn_runtime_install"), "{err:#}");

        // Group-writable binary is refused even when uid matches; note `/tmp` itself is
        // world-writable (01777), so even a 0755 file inside `/tmp` is refused via its
        // ancestor check!
        let ancestor_err = ensure_owned_by(&bin, my_uid, "VPN binary").unwrap_err();
        assert!(
            ancestor_err.to_string().contains("writable")
                || ancestor_err.to_string().contains("non-root"),
            "{ancestor_err:#}"
        );

        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).unwrap();
        let group_err = ensure_owned_by(&bin, my_uid, "VPN binary").unwrap_err();
        assert!(
            group_err.to_string().contains("group- or world-writable"),
            "{group_err:#}"
        );

        std::fs::remove_dir_all(base).unwrap();
    }
}
