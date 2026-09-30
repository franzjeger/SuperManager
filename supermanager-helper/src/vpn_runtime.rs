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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const RUNTIME_DIR: &str = "/Library/PrivilegedHelperTools/SuperManagerVPN";

/// The runtime's programs and the identifiers the app signs them with.
const SIGNED: [(&str, &str); 3] = [
    ("bash", "com.sybr.supermanager.vpn.bash"),
    ("wg", "com.sybr.supermanager.vpn.wg"),
    ("wireguard-go", "com.sybr.supermanager.vpn.wireguard-go"),
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
    let result = install_into(Path::new(&args.bundled_dir), Path::new(RUNTIME_DIR))
        .inspect_err(|e| tracing::warn!("VPN runtime not installed: {e:#}"))?;
    if !result.installed.is_empty() {
        tracing::info!(installed = ?result.installed, "VPN runtime installed in {RUNTIME_DIR}");
    }
    Ok(result)
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
    if same_content(&source, &target) {
        return Ok(false);
    }
    crate::signed_file::install(&source, &target, check)
        .with_context(|| format!("install {name}"))?;
    Ok(true)
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

/// wg-quick from the runtime, run by the runtime's bash; Homebrew's when
/// no runtime is installed.
pub fn wg_quick() -> Result<WgQuick> {
    let dir = Path::new(RUNTIME_DIR);
    if installed(dir) {
        return Ok(WgQuick {
            program: dir.join("bash"),
            script: Some(dir.join("wg-quick")),
            path: format!("{RUNTIME_DIR}:/usr/sbin:/sbin:/usr/bin:/bin"),
        });
    }
    let brew = homebrew("wg-quick")?;
    let bin = brew
        .parent()
        .map(Path::display)
        .map(|d| d.to_string())
        .unwrap_or_default();
    Ok(WgQuick {
        program: brew,
        script: None,
        path: format!("{bin}:/usr/local/sbin:/usr/sbin:/sbin:/usr/bin:/bin"),
    })
}

/// wireguard-go from the runtime, for the helper's own WireGuard setup
/// (`wg_native`), which has no Homebrew fallback.
pub fn wireguard_go() -> Result<PathBuf> {
    let dir = Path::new(RUNTIME_DIR);
    if !installed(dir) {
        bail!("SuperManager's own WireGuard setup needs the VPN runtime, and it is not installed");
    }
    Ok(dir.join("wireguard-go"))
}

/// `wg`, from the runtime or else Homebrew.
pub fn wg() -> Result<PathBuf> {
    let dir = Path::new(RUNTIME_DIR);
    if installed(dir) {
        return Ok(dir.join("wg"));
    }
    homebrew("wg")
}

fn homebrew(name: &str) -> Result<PathBuf> {
    static WARNED: AtomicBool = AtomicBool::new(false);
    let found = BREW_PREFIXES
        .iter()
        .map(|prefix| Path::new(prefix).join("bin").join(name))
        .find(|path| path.exists())
        .ok_or_else(|| {
            anyhow!(
                "{name} not found: no VPN runtime is installed, and Homebrew's \
                 wireguard-tools is not either"
            )
        })?;
    if !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "WireGuard uses Homebrew's tools: no VPN runtime is installed in {RUNTIME_DIR} \
             (the app installs the one it bundles before a WireGuard connect)"
        );
    }
    Ok(found)
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
        let dir = scratch_dir();
        let first = install_into(&bundled, &dir).unwrap();
        assert_eq!(first.installed.len(), 4, "{first:?}");
        assert!(installed(&dir));
        // A second install finds everything in place.
        let again = install_into(&bundled, &dir).unwrap();
        assert_eq!(again.unchanged.len(), 4, "{again:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
