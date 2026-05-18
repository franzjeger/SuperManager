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

fn main() {
    #[cfg(target_os = "windows")]
    {
        let pkg_version = env!("CARGO_PKG_VERSION");
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "SuperManager");
        res.set("FileDescription", "SuperManager Daemon");
        res.set("CompanyName", "Sybr");
        res.set("LegalCopyright", "GPL-3.0-or-later");
        res.set("ProductVersion", pkg_version);
        res.set("FileVersion", pkg_version);
        if let Err(e) = res.compile() {
            // Don't fail the build on resource-compile errors — the
            // version-info is nice-to-have but not load-bearing. CI logs
            // get a clear warning instead.
            println!("cargo:warning=failed to embed Windows version resource: {e}");
        }
    }
}
