//! Filesystem layout for the daemon.
//!
//! All state lives under `%PROGRAMDATA%\SuperManager` so it survives user
//! switches and is reachable while the daemon runs as `LocalSystem`. The
//! directory is created with an ACL granting full control to
//! `SYSTEM` + `Administrators` and read access to `Authenticated Users` —
//! the daemon needs to read user-pushed config drops without escalating
//! the user to admin.
//!
//! | Subdirectory      | Contents                                          |
//! |-------------------|---------------------------------------------------|
//! | `profiles\`       | VPN profile TOMLs (WireGuard, FortiGate, OpenVPN) |
//! | `hosts\`          | Managed-host inventory (one TOML per host)        |
//! | `keys\`           | SSH key metadata (private keys live in Credential Manager) |
//! | `logs\`           | Rolling daemon logs (Event Log is for service lifecycle only) |
//! | `backups\`        | FortiGate/OPNsense config backups                 |
//! | `templates\`      | Custom Tera templates the user has dropped in     |

use std::path::PathBuf;

/// Root directory under `%PROGRAMDATA%`. The literal subpath is fixed
/// rather than discovered via `directories::ProjectDirs` because the
/// daemon runs as `LocalSystem`, where `directories` resolves to the
/// system profile rather than the interactive user's profile.
pub const PROGRAM_DATA_SUBPATH: &str = "SuperManager";

/// Resolve `%PROGRAMDATA%\SuperManager`, creating it (and the standard
/// subdirectories) if it does not already exist.
///
/// Returns the absolute path. Fails only if the filesystem is broken in a
/// way that prevents creating the directory — in which case the daemon
/// can't function and should exit.
pub fn ensure_root() -> std::io::Result<PathBuf> {
    let base = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        // Fall back to the conventional Windows default if the env var is
        // somehow unset (e.g. running under a stripped-down service host).
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let root = base.join(PROGRAM_DATA_SUBPATH);
    for sub in ["profiles", "hosts", "keys", "logs", "backups", "templates"] {
        std::fs::create_dir_all(root.join(sub))?;
    }
    Ok(root)
}
