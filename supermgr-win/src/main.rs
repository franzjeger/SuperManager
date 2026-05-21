//! `supermgr-win` — SuperManager desktop GUI for Windows.
//!
//! Slint frontend that talks to `supermgrd-win` over the named pipe at
//! `\\.\pipe\supermgrd`. The GUI process runs as the interactive user;
//! all privileged operations (firewall rules, driver loading, secret
//! storage) happen on the daemon side.
//!
//! The whole UI lives in [`win`], gated to Windows so the workspace can
//! still `cargo metadata` on Linux/macOS without Slint's native deps.

// Suppress the console window in release builds — GUI-only process.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "windows")]
mod win;

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "windows")]
    {
        match win::run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("supermgr-win: {e:#}");
                std::process::ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!(
            "supermgr-win is a Windows-only build. \
             Use `supermgr` on Linux or open SuperManager.app on macOS."
        );
        std::process::ExitCode::from(2)
    }
}
