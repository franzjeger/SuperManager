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

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};

/// DACL applied to the state root (and inherited by everything created
/// underneath it, via the `OICI` object+container-inherit flags):
/// - SY (SYSTEM)              → FA (File All) — the daemon process
/// - BA (Builtin Admins)      → FA — service control & maintenance
/// - AU (Authenticated Users) → FR (File Read) — the GUI reads config
///
/// `P` makes the DACL *protected*: it does NOT inherit the permissive
/// default ProgramData ACE (which grants Authenticated Users write), so
/// secrets written under this tree — Azure tokens, tls-auth keys — are
/// no longer world-writable, and only readable, never modifiable, by a
/// non-admin user.
const ROOT_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;AU)";

/// DACL for directories that hold actual secrets (OAuth access tokens,
/// tls-auth keys) rather than config the GUI must read. SYSTEM and
/// Administrators only — Authenticated Users get NOTHING, so a token
/// dropped here is not readable by other local users. Protected, same
/// rationale as [`ROOT_SDDL`].
const SECRET_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

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
    // Create and lock down the root FIRST, then create the subdirs so
    // they inherit the protected DACL rather than the permissive
    // ProgramData default. Applying the ACL is best-effort: a failure
    // here (e.g. the daemon is somehow not elevated) must not stop the
    // daemon from starting, but it is logged loudly because it means
    // secrets could be left readable.
    std::fs::create_dir_all(&root)?;
    if let Err(e) = apply_acl(&root, ROOT_SDDL) {
        log::error!(
            "failed to apply restrictive ACL to {} — secrets may be world-readable: {e}",
            root.display()
        );
    }
    for sub in ["profiles", "hosts", "keys", "logs", "backups", "templates"] {
        std::fs::create_dir_all(root.join(sub))?;
    }
    Ok(root)
}

/// Lock a directory holding secrets down to SYSTEM + Administrators
/// only (no read access for Authenticated Users), protected against
/// inheriting the permissive ProgramData default. Call this right
/// after creating a runtime dir that will hold tokens/keys.
pub fn lock_down_secret_dir(dir: &Path) -> std::io::Result<()> {
    apply_acl(dir, SECRET_SDDL)
}

/// Replace the DACL on `dir` with `sddl`, protected so it does not
/// merge the inherited ProgramData ACE. Parses the SDDL into a
/// security descriptor, lifts its DACL out, and hands it to
/// `SetNamedSecurityInfoW`.
fn apply_acl(dir: &Path, sddl: &str) -> std::io::Result<()> {
    // SDDL → security descriptor (OS-allocated; freed with LocalFree).
    let mut sddl_w: Vec<u16> = sddl.encode_utf16().collect();
    sddl_w.push(0);
    let mut descriptor: *mut c_void = ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Ensure the descriptor is always freed, even on an early return.
    let _guard = FreeOnDrop(descriptor);

    // Pull the DACL pointer out of the descriptor.
    let mut dacl_present: i32 = 0;
    let mut dacl_defaulted: i32 = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    let got = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    };
    if got == 0 || dacl_present == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Apply it to the directory, protected so the ProgramData default
    // ACE is not inherited in.
    let mut path_w: Vec<u16> = dir.as_os_str().encode_wide().collect();
    path_w.push(0);
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// RAII guard: `LocalFree` the security descriptor when it drops, so
/// every return path out of `apply_root_acl` releases it.
struct FreeOnDrop(*mut c_void);
impl Drop for FreeOnDrop {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0 as _) };
        }
    }
}
