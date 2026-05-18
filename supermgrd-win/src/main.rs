//! `supermgrd-win` — SuperManager privileged daemon for Windows.
//!
//! Runs as a Windows Service (Local System by default), exposes the same
//! RPC contract as the Linux `supermgrd` D-Bus interface, but transports it
//! over a named pipe at `\\.\pipe\supermgrd`. The wire protocol is the
//! JSON-RPC envelope defined in [`supermgr_core::protocol`].
//!
//! The body of the daemon lives in [`win`], gated to `cfg(target_os = "windows")`
//! so the workspace can still `cargo check` this crate on Linux/macOS for
//! editor tooling — the `main` function on those platforms simply prints a
//! diagnostic and exits non-zero.

#[cfg(target_os = "windows")]
mod win;

fn main() {
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = win::run() {
            eprintln!("supermgrd-win: {e:#}");
            std::process::exit(1);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!(
            "supermgrd-win only builds on Windows. \
             Use supermgrd on Linux or SuperManagerMac on macOS."
        );
        std::process::exit(2);
    }
}
