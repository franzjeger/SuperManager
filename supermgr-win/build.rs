//! Compile the Slint `.slint` UI files into Rust at build time, and embed
//! the release version.
//!
//! Skipped on non-Windows hosts so the workspace `cargo metadata` step
//! works on a Linux/macOS box without slint-build installed (the
//! `cfg(target_os = "windows")` gate on the build-dependency is enough
//! at the manifest level, but build.rs runs on the host regardless of
//! target so we still need a runtime check).
//!
//! # Version
//!
//! Releases are versioned by git tag (v1.7.0), not by the crate version,
//! which stays at 1.0.0 — so release CI exports `SUPERMGR_RELEASE_VERSION`
//! from the tag and this script prefers it over `CARGO_PKG_VERSION`. It
//! flows into two places:
//!
//! - `env!("SUPERMGR_VERSION")` in the app, which the in-app update check
//!   compares against the newest GitHub release tag.
//! - The `.exe`'s numeric VS_FIXEDFILEINFO version, which the MSI's
//!   `!(bind.FileVersion.supermgrd_win.exe)` binding turns into the MSI
//!   ProductVersion — the value Windows Installer's MajorUpgrade logic
//!   compares. Before this, every release MSI carried 1.0.0 and only the
//!   *filename* knew the real version.

fn main() {
    let version = std::env::var("SUPERMGR_RELEASE_VERSION")
        .map(|v| v.trim().trim_start_matches('v').to_owned())
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
    println!("cargo:rustc-env=SUPERMGR_VERSION={version}");
    println!("cargo:rerun-if-env-changed=SUPERMGR_RELEASE_VERSION");

    #[cfg(target_os = "windows")]
    {
        slint_build::compile("ui/main.slint")
            .expect("slint UI compile failed");

        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "SuperManager");
        res.set("FileDescription", "SuperManager GUI");
        res.set("CompanyName", "Sybr");
        res.set("LegalCopyright", "GPL-3.0-or-later");
        res.set("ProductVersion", &version);
        res.set("FileVersion", &version);
        // The string table above is what File Explorer shows; the packed
        // numeric version below is what installers and APIs compare.
        // winres defaults the numeric fields to CARGO_PKG_VERSION, so
        // without this the release override never reaches them.
        if let Some(packed) = pack_version(&version) {
            res.set_version_info(winres::VersionInfo::FILEVERSION, packed);
            res.set_version_info(winres::VersionInfo::PRODUCTVERSION, packed);
        }
        if let Err(e) = res.compile() {
            println!("cargo:warning=failed to embed Windows version resource: {e}");
        }
    }
}

/// `"1.7.0"` → the four 16-bit fields of a VS_FIXEDFILEINFO version,
/// packed major.minor.patch.0. `None` when the string is not dotted
/// numbers, in which case winres keeps its CARGO_PKG_VERSION default.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn pack_version(v: &str) -> Option<u64> {
    let mut parts = v.split('.');
    let field = |p: Option<&str>| -> Option<u64> {
        p.map_or(Some(0), |p| p.parse::<u16>().ok().map(u64::from))
    };
    let major = field(parts.next())?;
    let minor = field(parts.next())?;
    let patch = field(parts.next())?;
    Some(major << 48 | minor << 32 | patch << 16)
}
