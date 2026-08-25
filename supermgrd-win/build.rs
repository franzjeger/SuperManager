//! Embed a Windows VS_FIXEDFILEINFO version resource into the daemon
//! `.exe`. The values appear in:
//!
//! - File Explorer's *Properties* dialog (Details tab).
//! - The MSI installer's `!(bind.FileVersion.supermgrd_win.exe)` binding.
//! - Windows Event Viewer's Source name when the service writes events.
//!
//! Skipped on non-Windows hosts so the crate still `cargo check`s on
//! Linux/macOS dev boxes for editor tooling (the binary itself is gated
//! on `cfg(target_os = "windows")` at `main.rs`).
//!
//! # Version
//!
//! Releases are versioned by git tag (v1.7.0) while the crate version
//! stays at 1.0.0, so release CI exports `SUPERMGR_RELEASE_VERSION` from
//! the tag and it wins over `CARGO_PKG_VERSION` here. The numeric
//! FILEVERSION matters beyond cosmetics: the MSI's ProductVersion binds to
//! it, and that is the value Windows Installer's MajorUpgrade compares —
//! before this override every release MSI carried 1.0.0 and only the
//! filename knew the real version.

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
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "SuperManager");
        res.set("FileDescription", "SuperManager Daemon");
        res.set("CompanyName", "Sybr");
        res.set("LegalCopyright", "GPL-3.0-or-later");
        res.set("ProductVersion", &version);
        res.set("FileVersion", &version);
        // winres defaults the packed numeric fields to CARGO_PKG_VERSION;
        // set them explicitly so the release override reaches the value
        // the MSI binding actually reads.
        if let Some(packed) = pack_version(&version) {
            res.set_version_info(winres::VersionInfo::FILEVERSION, packed);
            res.set_version_info(winres::VersionInfo::PRODUCTVERSION, packed);
        }
        if let Err(e) = res.compile() {
            // Don't fail the build on resource-compile errors — the
            // version-info is nice-to-have but not load-bearing. CI logs
            // get a clear warning instead.
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
