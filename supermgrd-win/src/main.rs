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

#[cfg(any(target_os = "windows", test))]
mod rpc_args;

// Exercise the Windows trust-store implementation on every CI host too.
#[cfg(all(test, not(target_os = "windows")))]
#[path = "win/known_hosts.rs"]
mod windows_known_hosts;

// Likewise the VPN clients' output reader: plain tokio, no Win32. Only its
// tests run off Windows, so the reader itself is unused there.
#[cfg(all(test, not(target_os = "windows")))]
#[path = "win/vpn/output.rs"]
#[allow(dead_code)]
mod windows_vpn_output;

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
