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
            let xdg = std::env::var("XDG_DATA_HOME").ok();
            let home = std::env::var("HOME").ok();
            xdg_data_base(xdg.as_deref(), home.as_deref()).join("supermgrd")
        }
    }

    // Windows was previously served by the generic fallback below, which reads
    // `HOME` — a variable Windows does not set — and lands on `/tmp`, which is
    // not even an absolute path there. Nothing noticed because the engine is
    // macOS-only and `supermgrd-win` has its own path module; moving this into
    // core put it on Windows for the first time, and the absolute-path test
    // caught it immediately.
    //
    // `PROGRAMDATA\SuperManager` matches `supermgrd_win::win::paths`, so the
    // GUI and the Windows daemon agree on where a customer's data lives rather
    // than each having a private answer.
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("SuperManager")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
        PathBuf::from(home).join(".supermanager")
    }
}

/// Resolve the XDG data base directory from the raw `XDG_DATA_HOME` and
/// `HOME` values, per the XDG Base Directory spec.
///
/// `$XDG_DATA_HOME` is honoured only when it is a non-empty, ABSOLUTE
/// path; otherwise the fallback is `$HOME/.local/share` (and `/tmp` when
/// even `HOME` is unset, matching the rest of this module).
///
/// The subtle part is the empty string. `std::env::var` returns `Ok("")`
/// for a set-but-empty variable, which several login/session setups
/// export. The old code did `var("XDG_DATA_HOME").map(PathBuf::from)`, so
/// an empty value skipped the fallback and produced a RELATIVE data dir —
/// and then the GUI and the daemon disagreed on where the data lived the
/// moment either was started from a different working directory, the
/// exact divergence this module exists to prevent. The spec says to
/// ignore a non-absolute value, so that is what restores an absolute path.
///
/// Pure and platform-independent so the rule is tested on every CI host,
/// not only a Linux one — the bug lived in a `cfg(target_os = "linux")`
/// block that a macOS test runner never compiled. Compiled where it is
/// used: the Linux data-dir branch, and the tests on any host.
#[cfg(any(target_os = "linux", test))]
fn xdg_data_base(xdg_data_home: Option<&str>, home: Option<&str>) -> PathBuf {
    if let Some(x) = xdg_data_home {
        // Unix-absolute, checked as `starts_with('/')` rather than
        // `Path::is_absolute()`. XDG is a Unix concept and an absolute XDG
        // path always starts with `/`; `Path::is_absolute()` would apply
        // the host's rules, so on a Windows test runner "/data" is not
        // absolute and this branch would wrongly fall through. The value
        // is only ever consumed on Linux, so Unix semantics are the
        // correct ones to apply on every platform that compiles this.
        if x.starts_with('/') {
            return PathBuf::from(x);
        }
    }
    let home = home.filter(|h| !h.is_empty()).unwrap_or("/tmp");
    PathBuf::from(home).join(".local/share")
}

#[cfg(test)]
mod tests {

    #[test]
    fn xdg_absolute_is_used() {
        assert_eq!(xdg_data_base(Some("/data"), Some("/home/x")),
                   PathBuf::from("/data"));
    }

    /// The bug: a set-but-empty XDG_DATA_HOME must fall back, not yield "".
    #[test]
    fn xdg_empty_falls_back_to_home() {
        assert_eq!(xdg_data_base(Some(""), Some("/home/x")),
                   PathBuf::from("/home/x/.local/share"));
    }

    #[test]
    fn xdg_unset_falls_back_to_home() {
        assert_eq!(xdg_data_base(None, Some("/home/x")),
                   PathBuf::from("/home/x/.local/share"));
    }

    /// XDG spec: a relative XDG_DATA_HOME is ignored — honouring it would
    /// reintroduce the relative-path divergence by another door.
    #[test]
    fn xdg_relative_is_ignored() {
        assert_eq!(xdg_data_base(Some("relative/share"), Some("/home/x")),
                   PathBuf::from("/home/x/.local/share"));
    }

    #[test]
    fn xdg_and_home_both_empty_is_still_absolute() {
        let p = xdg_data_base(Some(""), None);
        // Unix-absolute checked directly: `Path::is_absolute()` applies the
        // host's rules, and a Windows test runner does not consider a
        // drive-less `/tmp/...` absolute — but this value is only ever used
        // on Linux, where it is.
        assert!(p.to_string_lossy().starts_with('/'), "{p:?}");
        assert_eq!(p, PathBuf::from("/tmp/.local/share"));
    }

    #[test]
    fn xdg_home_empty_string_treated_as_unset() {
        assert_eq!(xdg_data_base(None, Some("")),
                   PathBuf::from("/tmp/.local/share"));
    }
    use super::*;

    #[test]
    fn the_path_is_absolute_and_named() {
        // A relative path here would put a customer's scan history wherever the
        // process happened to be started from. This is not hypothetical: the
        // Windows branch used to fall through to a `HOME`-based path, and since
        // Windows does not set `HOME` it produced `/tmp/.supermanager` — which
        // on Windows is not absolute. This assertion is what found it.
        let p = default_data_dir();
        assert!(p.is_absolute(), "{p:?} is not absolute");
        assert!(
            p.to_string_lossy().to_lowercase().contains("superm"),
            "{p:?} does not look like ours"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_agrees_with_the_windows_daemon() {
        // supermgrd-win keeps its state under PROGRAMDATA\SuperManager. If this
        // returned anything else, the GUI and the daemon would each have a
        // private idea of where a customer's data lives.
        let p = default_data_dir();
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("SuperManager"),
            "{p:?} does not end at the SuperManager root"
        );
        assert!(
            !s.contains("/tmp"),
            "{p:?} still uses the unix fallback"
        );
    }
}
