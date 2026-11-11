//! Trusted binary & DLL resolution for `SYSTEM` VPN backends (`P0-32`).
//!
//! `supermgrd-win` runs as `NT AUTHORITY\SYSTEM`. Resolving helper executables
//! or native DLLs through `%PATH%`, `ProgramData`, or unprivileged environment
//! variables would let a local user plant an unsigned binary executed as
//! `SYSTEM`. Every helper binary/DLL must therefore:
//! 1. Reside inside a canonical `%ProgramFiles%` directory (`ProgramW6432` or
//!    `ProgramFiles`, owned by `TrustedInstaller` / `Administrators`), and
//! 2. Carry a valid Authenticode signature verified via `WinVerifyTrust`.

use std::{
    ffi::c_void,
    os::windows::ffi::OsStrExt as _,
    path::{Path, PathBuf},
    ptr,
};

use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    },
};

use super::VpnError;

fn program_files_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for var in ["ProgramW6432", "ProgramFiles"] {
        if let Some(val) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            let candidate = PathBuf::from(val);
            if let Ok(canon) = std::fs::canonicalize(&candidate) {
                if !roots.contains(&canon) {
                    roots.push(canon);
                }
            }
        }
    }
    if roots.is_empty() {
        if let Ok(canon) = std::fs::canonicalize(r"C:\Program Files") {
            roots.push(canon);
        }
    }
    roots
}

fn clean_windows_path(canon: &Path) -> PathBuf {
    let raw = canon.to_string_lossy();
    if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        canon.to_path_buf()
    }
}

/// Verify that `path` has a valid Authenticode signature chained to a trusted root.
pub fn verify_authenticode(path: &Path) -> Result<(), VpnError> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };

    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            std::ptr::from_mut(&mut data).cast::<c_void>(),
        )
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            std::ptr::from_mut(&mut data).cast::<c_void>(),
        );
    }

    if status == 0 {
        Ok(())
    } else {
        Err(VpnError::Win32(format!(
            "Authenticode signature verification failed for {} (0x{:08x})",
            path.display(),
            status as u32
        )))
    }
}

/// Locate a signed binary or DLL strictly inside `%ProgramFiles%`.
pub fn resolve_trusted_program_files_binary(
    bundled_filename: Option<&str>,
    program_files_relatives: &[&str],
    missing_message: &str,
) -> Result<PathBuf, VpnError> {
    let roots = program_files_roots();
    if roots.is_empty() {
        return Err(VpnError::MissingDependency(
            "could not resolve %ProgramFiles% root directory".into(),
        ));
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(name) = bundled_filename {
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
        {
            candidates.push(dir.join(name));
        }
    }
    for root in &roots {
        let clean_root = clean_windows_path(root);
        for rel in program_files_relatives {
            candidates.push(clean_root.join(rel));
        }
    }

    let mut last_trust_err: Option<VpnError> = None;
    for candidate in candidates {
        let Ok(canon) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if !roots.iter().any(|root| canon.starts_with(root)) {
            tracing::warn!(
                path = %canon.display(),
                "ignoring VPN helper candidate outside %ProgramFiles%"
            );
            continue;
        }
        let clean = clean_windows_path(&canon);
        match verify_authenticode(&clean) {
            Ok(()) => return Ok(clean),
            Err(e) => {
                tracing::warn!(path = %clean.display(), error = %e, "rejected unsigned/untrusted VPN binary");
                last_trust_err = Some(e);
            }
        }
    }

    if let Some(err) = last_trust_err {
        return Err(err);
    }
    Err(VpnError::MissingDependency(missing_message.to_owned()))
}
