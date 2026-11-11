//! Where `SuperManager` keeps its data, per platform.
//!
//! Moved here from `supermgr-engine::secrets` because the engine is macOS-only
//! and this is not: the Linux daemon needs the same answer to write compliance
//! runs and user-supplied check libraries to the same place the GUI reads them
//! from. Two copies of this function would be two chances to disagree about
//! where a customer's scan history lives.
//!
//! The engine re-exports it, so `secrets::default_data_dir` still resolves.

use std::path::PathBuf;

/// Validate a Unix `HOME` value: must be present, non-empty, and start with `/`.
///
/// Pure and platform-independent so tests on every CI host exercise the exact
/// Unix rejection rules without mutating process-wide environment variables.
pub fn validate_unix_home(home: Option<&str>) -> Result<PathBuf, &'static str> {
    let h = home
        .filter(|s| !s.is_empty())
        .ok_or("HOME environment variable is not set")?;
    if !h.starts_with('/') {
        return Err("HOME environment variable must be an absolute path");
    }
    Ok(PathBuf::from(h))
}

/// Resolve the current user's `HOME` directory on Unix, refusing missing or
/// relative values instead of falling back to a world-writable directory.
pub fn unix_home_dir() -> Result<PathBuf, &'static str> {
    let home = std::env::var("HOME").ok();
    validate_unix_home(home.as_deref())
}

/// Fallible counterpart to [`default_data_dir`].
///
/// Refuses to fall back to `/tmp` when `HOME` (and, on non-root Linux,
/// `XDG_DATA_HOME`) is unset or relative. Callers at process startup or RPC
/// boundaries should prefer this so an invalid environment produces an explicit
/// error rather than placing sockets, state, or secrets in a shared directory.
pub fn try_default_data_dir() -> Result<PathBuf, &'static str> {
    #[cfg(target_os = "macos")]
    {
        Ok(unix_home_dir()?.join("Library/Application Support/SuperManager"))
    }

    #[cfg(target_os = "linux")]
    {
        if nix::unistd::getuid().is_root() {
            Ok(PathBuf::from("/etc/supermgrd"))
        } else {
            let xdg = std::env::var("XDG_DATA_HOME").ok();
            let home = std::env::var("HOME").ok();
            Ok(try_xdg_data_base(xdg.as_deref(), home.as_deref())?.join("supermgrd"))
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
        Ok(std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("SuperManager"))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok(unix_home_dir()?.join(".supermanager"))
    }
}

/// Return the default data directory for the current platform.
///
/// On Linux the answer depends on *who is asking*: the daemon runs as root and
/// owns `/etc/supermgrd`, while an unprivileged GUI must not try to write
/// there and gets an XDG path instead. That branch is why this cannot be a
/// constant.
///
/// # Panics
///
/// Panics on Unix when `HOME` (and, on non-root Linux, `XDG_DATA_HOME`) is
/// unset or not an absolute path. Never falls back to `/tmp`.
#[must_use]
pub fn default_data_dir() -> PathBuf {
    try_default_data_dir()
        .expect("cannot resolve SuperManager data directory: HOME must be set to an absolute path")
}

/// Resolve an XDG base directory (`XDG_DATA_HOME` or `XDG_STATE_HOME`) per the
/// XDG Base Directory spec, falling back to `$HOME/<fallback_rel>` when the XDG
/// variable is unset, empty, or relative, and failing if `HOME` is also unset
/// or relative.
pub fn try_xdg_base(
    xdg_var: Option<&str>,
    home: Option<&str>,
    fallback_rel: &str,
) -> Result<PathBuf, &'static str> {
    if let Some(x) = xdg_var {
        // Unix-absolute, checked as `starts_with('/')` rather than
        // `Path::is_absolute()`. XDG is a Unix concept and an absolute XDG
        // path always starts with `/`; `Path::is_absolute()` would apply
        // the host's rules, so on a Windows test runner "/data" is not
        // absolute and this branch would wrongly fall through.
        if x.starts_with('/') {
            return Ok(PathBuf::from(x));
        }
    }
    Ok(validate_unix_home(home)?.join(fallback_rel))
}

/// Resolve the XDG data base directory (`$XDG_DATA_HOME` or `$HOME/.local/share`).
pub fn try_xdg_data_base(
    xdg_data_home: Option<&str>,
    home: Option<&str>,
) -> Result<PathBuf, &'static str> {
    try_xdg_base(xdg_data_home, home, ".local/share")
}

/// Resolve the XDG state base directory (`$XDG_STATE_HOME` or `$HOME/.local/state`).
pub fn try_xdg_state_base(
    xdg_state_home: Option<&str>,
    home: Option<&str>,
) -> Result<PathBuf, &'static str> {
    try_xdg_base(xdg_state_home, home, ".local/state")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdg_absolute_is_used() {
        assert_eq!(
            try_xdg_data_base(Some("/data"), Some("/home/x")),
            Ok(PathBuf::from("/data"))
        );
        // Valid absolute XDG_DATA_HOME succeeds even when HOME is unset.
        assert_eq!(
            try_xdg_data_base(Some("/data"), None),
            Ok(PathBuf::from("/data"))
        );
    }

    /// A set-but-empty `XDG_DATA_HOME` must fall back to `$HOME/.local/share`.
    #[test]
    fn xdg_empty_falls_back_to_home() {
        assert_eq!(
            try_xdg_data_base(Some(""), Some("/home/x")),
            Ok(PathBuf::from("/home/x/.local/share"))
        );
    }

    #[test]
    fn xdg_unset_falls_back_to_home() {
        assert_eq!(
            try_xdg_data_base(None, Some("/home/x")),
            Ok(PathBuf::from("/home/x/.local/share"))
        );
    }

    /// XDG spec: a relative `XDG_DATA_HOME` is ignored.
    #[test]
    fn xdg_relative_is_ignored() {
        assert_eq!(
            try_xdg_data_base(Some("relative/share"), Some("/home/x")),
            Ok(PathBuf::from("/home/x/.local/share"))
        );
    }

    #[test]
    fn xdg_and_home_both_empty_or_relative_is_refused() {
        assert!(try_xdg_data_base(Some(""), None).is_err());
        assert!(try_xdg_data_base(None, Some("")).is_err());
        assert!(try_xdg_data_base(None, Some("relative/home")).is_err());
        assert!(try_xdg_state_base(Some("relative/state"), None).is_err());
        assert!(validate_unix_home(None).is_err());
        assert!(validate_unix_home(Some("")).is_err());
        assert!(validate_unix_home(Some("tmp/user")).is_err());
    }

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
        assert!(!s.contains("/tmp"), "{p:?} still uses the unix fallback");
    }
}
