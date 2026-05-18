//! Compile the Slint `.slint` UI files into Rust at build time.
//!
//! Skipped on non-Windows hosts so the workspace `cargo metadata` step
//! works on a Linux/macOS box without slint-build installed (the
//! `cfg(target_os = "windows")` gate on the build-dependency is enough
//! at the manifest level, but build.rs runs on the host regardless of
//! target so we still need a runtime check).

fn main() {
    #[cfg(target_os = "windows")]
    {
        slint_build::compile("ui/main.slint")
            .expect("slint UI compile failed");

        let pkg_version = env!("CARGO_PKG_VERSION");
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "SuperManager");
        res.set("FileDescription", "SuperManager GUI");
        res.set("CompanyName", "Sybr");
        res.set("LegalCopyright", "GPL-3.0-or-later");
        res.set("ProductVersion", pkg_version);
        res.set("FileVersion", pkg_version);
        if let Err(e) = res.compile() {
            println!("cargo:warning=failed to embed Windows version resource: {e}");
        }
    }
}
