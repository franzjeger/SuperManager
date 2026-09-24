//! The window's dealings with Windows itself: opening links, the light/dark
//! setting, and the one preference the window keeps.

use std::path::PathBuf;

use tracing::warn;

use crate::model;

/// Open `url` in the default browser — only if it is one the window has
/// reason to open.
///
/// `ShellExecuteW` with the URL as the file, never a command line: nothing
/// in it is parsed by a shell.
#[allow(unsafe_code)] // ShellExecuteW
pub fn open_url(url: &str) -> bool {
    const REPOSITORY: &str = "https://github.com/franzjeger/SuperManager";
    let allowed = model::is_sign_in_url(url)
        || url == REPOSITORY
        || url
            .strip_prefix(REPOSITORY)
            .is_some_and(|rest| rest.starts_with('/') && !rest.contains(char::is_whitespace));
    if !allowed {
        warn!("refused to open an unexpected URL");
        return false;
    }
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (verb, file) = (wide("open"), wide(url));
    // SAFETY: both strings are NUL-terminated UTF-16 that outlive the call;
    // the remaining pointers are documented as optional.
    let code = unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        )
    };
    // ShellExecute reports success as any value above 32.
    let opened = code as isize > 32;
    if !opened {
        warn!("ShellExecuteW failed to open a URL ({})", code as isize);
    }
    opened
}

/// Whether Windows is set to dark mode for apps.
///
/// Read once when the operator switches back to "Use Windows setting"
/// mid-session; at startup the fluent style follows Windows by itself.
#[allow(unsafe_code)] // RegGetValueW
pub fn windows_prefers_dark() -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
    let value = wide("AppsUseLightTheme");
    let mut data: u32 = 1;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: NUL-terminated strings, and a DWORD-sized buffer whose size
    // is passed alongside it.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            std::ptr::addr_of_mut!(data).cast(),
            &mut size,
        )
    };
    status == 0 && data == 0
}

/// The window's own settings, in `%APPDATA%\SuperManager\gui.json`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Prefs {
    /// 0 = follow Windows, 1 = light, 2 = dark.
    pub appearance: i32,
}

impl Prefs {
    fn path() -> Option<PathBuf> {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("SuperManager").join("gui.json"))
    }

    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        let appearance = v
            .get("appearance")
            .and_then(serde_json::Value::as_i64)
            .and_then(|a| i32::try_from(a).ok())
            .filter(|a| (0..=2).contains(a))
            .unwrap_or(0);
        Self { appearance }
    }

    pub fn save(self) {
        let Some(path) = Self::path() else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let body = serde_json::json!({ "appearance": self.appearance }).to_string();
        if let Err(e) = std::fs::write(&path, body) {
            warn!("could not save window settings to {}: {e}", path.display());
        }
    }
}
