//! Where SuperManager keeps its data, per platform.
//!
//! Moved here from `supermgr-engine::secrets` because the engine is macOS-only
//! and this is not: the Linux daemon needs the same answer to write compliance
//! runs and user-supplied check libraries to the same place the GUI reads them
//! from. Two copies of this function would be two chances to disagree about
//! where a customer's scan history lives.
//!
//! The engine re-exports it, so `secrets::default_data_dir` still resolves.

use std::path::PathBuf;

/// Return the default data directory for the current platform.
///
/// On Linux the answer depends on *who is asking*: the daemon runs as root and
/// owns `/etc/supermgrd`, while an unprivileged GUI must not try to write
/// there and gets an XDG path instead. That branch is why this cannot be a
/// constant.
#[must_use]
pub fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
        PathBuf::from(home).join("Library/Application Support/SuperManager")
    }

    #[cfg(target_os = "linux")]
    {
        if nix::unistd::getuid().is_root() {
            PathBuf::from("/etc/supermgrd")
        } else {
            let base = std::env::var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
                    PathBuf::from(home).join(".local/share")
                });
            base.join("supermgrd")
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
        PathBuf::from(home).join(".supermanager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_is_absolute_and_named() {
        // A relative path here would put a customer's scan history wherever
        // the process happened to be started from.
        let p = default_data_dir();
        assert!(p.is_absolute(), "{p:?} is not absolute");
        assert!(
            p.to_string_lossy().to_lowercase().contains("superm"),
            "{p:?} does not look like ours"
        );
    }
}
