//! Embed a Windows VS_FIXEDFILEINFO version resource into
//! `supermgr-mcp.exe`. Skipped on non-Windows hosts.

fn main() {
    #[cfg(target_os = "windows")]
    {
        let pkg_version = env!("CARGO_PKG_VERSION");
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "SuperManager");
        res.set("FileDescription", "SuperManager MCP server");
        res.set("CompanyName", "Sybr");
        res.set("LegalCopyright", "GPL-3.0-or-later");
        res.set("ProductVersion", pkg_version);
        res.set("FileVersion", pkg_version);
        if let Err(e) = res.compile() {
            println!("cargo:warning=failed to embed Windows version resource: {e}");
        }
    }
}
