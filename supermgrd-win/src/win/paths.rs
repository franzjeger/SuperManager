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
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;

/// Protected DACLs: no ProgramData write permissions may be inherited. Setting
/// the owner to Administrators also prevents a creating user's implicit right
/// to change the DACL. Creation is restricted to the elevated service/admins.
const ROOT_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;AU)";
const SECRET_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub const PROGRAM_DATA_SUBPATH: &str = "SuperManager";

/// Create and secure the state tree before loading any data. ACL failures,
/// reparse points and directories planted by an unprivileged owner stop startup.
pub fn ensure_root() -> io::Result<PathBuf> {
    ensure_root_at(&program_data_dir())
}

fn program_data_dir() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

fn root_path_at(base: &Path) -> io::Result<PathBuf> {
    if !base.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ProgramData must be absolute",
        ));
    }
    Ok(base.join(PROGRAM_DATA_SUBPATH))
}

fn ensure_root_at(base: &Path) -> io::Result<PathBuf> {
    let root = root_path_at(base)?;
    let _root_handle = secure_directory(&root, ROOT_SDDL, true)?;
    for sub in [
        "profiles",
        "hosts",
        "keys",
        "logs",
        "backups",
        "templates",
        "runtime",
    ] {
        let sddl = if sub == "runtime" {
            SECRET_SDDL
        } else {
            ROOT_SDDL
        };
        let dir = root.join(sub);
        let _handle = secure_directory(&dir, sddl, true)?;
    }
    // Include top-level state such as known_hosts.json and older/custom
    // directories. The private runtime subtree must never receive the
    // configuration tree's read permission for authenticated users.
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let sddl = if entry.file_name().to_string_lossy().eq_ignore_ascii_case("runtime") {
            SECRET_SDDL
        } else {
            ROOT_SDDL
        };
        let (handle, is_dir) = open_trusted_path(&entry.path())?;
        set_dacl(&handle, sddl)?;
        if is_dir {
            secure_existing_children(&entry.path(), sddl)?;
        }
    }
    Ok(root)
}

/// A new session never reuses stale files, explicit old ACLs, symlinks or file
/// handles left by an earlier client. The secret DACL is supplied to creation,
/// so there is no create-before-lock window. Retain the guard until teardown.
pub fn create_private_runtime_dir(profile_id: &uuid::Uuid) -> io::Result<PrivateRuntimeDir> {
    let root = root_path_at(&program_data_dir())?;
    create_private_runtime_dir_at(&root, profile_id)
}

fn create_private_runtime_dir_at(
    root: &Path,
    profile_id: &uuid::Uuid,
) -> io::Result<PrivateRuntimeDir> {
    // The full state-tree migration runs once, before daemon startup. Pin and
    // secure only the ancestors of this new session during a connection, so
    // legitimate writers elsewhere in the running service remain independent.
    let _root_handle = secure_directory(root, ROOT_SDDL, true)?;
    let runtime = root.join("runtime");
    let _runtime_handle = secure_directory(&runtime, SECRET_SDDL, true)?;
    let path = runtime.join(format!(
        "azure-{}-{}",
        profile_id.simple(),
        uuid::Uuid::new_v4().simple()
    ));
    drop(secure_directory(&path, SECRET_SDDL, false)?);
    Ok(PrivateRuntimeDir { path })
}

#[derive(Debug)]
pub struct PrivateRuntimeDir {
    path: PathBuf,
}

impl PrivateRuntimeDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateRuntimeDir {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            if error.kind() != io::ErrorKind::NotFound {
                tracing::warn!(path = %self.path.display(), %error, "remove private VPN runtime directory");
            }
        }
    }
}

/// Upgrade old explicitly permissive child ACLs too, not just inherited ACEs.
/// Handles deny write/delete sharing while each subtree is checked and secured;
/// a pre-existing writable handle therefore causes a fail-closed sharing error.
fn secure_existing_children(dir: &Path, sddl: &str) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let (handle, is_dir) = open_trusted_path(&path)?;
        set_dacl(&handle, sddl)?;
        if is_dir {
            secure_existing_children(&path, sddl)?;
        }
    }
    Ok(())
}

fn secure_directory(path: &Path, sddl: &str, allow_existing: bool) -> io::Result<OwnedHandle> {
    let descriptor = SecurityDescriptor::parse(sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide = wide_path(path)?;
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if !allow_existing || error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    let (handle, is_dir) = open_trusted_path(path)?;
    if !is_dir {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state path is not a directory",
        ));
    }
    set_dacl(&handle, sddl)?;
    Ok(handle)
}

/// Open the object itself, never the target of a junction/symlink, and keep its
/// directory entry pinned while inspecting it and replacing the DACL.
fn open_trusted_path(path: &Path) -> io::Result<(OwnedHandle, bool)> {
    let wide = wide_path(path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            // SetSecurityInfo must not recursively change an unchecked
            // child (including a planted hardlink) before we validate it.
            // MAXIMUM_ALLOWED disables that automatic propagation; the
            // explicit traversal below secures each trusted object itself.
            // https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
            MAXIMUM_ALLOWED,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.nNumberOfLinks > 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unsafe linked state path: {}", path.display()),
        ));
    }
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let rc = unsafe {
        GetSecurityInfo(
            raw,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = SecurityDescriptor(descriptor);
    win32_result(rc)?;
    if owner.is_null()
        || unsafe {
            IsWellKnownSid(owner, WinLocalSystemSid) == 0
                && IsWellKnownSid(owner, WinBuiltinAdministratorsSid) == 0
        }
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "state path must be owned by SYSTEM or Administrators: {}",
                path.display()
            ),
        ));
    }
    Ok((
        handle,
        info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
    ))
}

fn set_dacl(handle: &OwnedHandle, sddl: &str) -> io::Result<()> {
    let descriptor = SecurityDescriptor::parse(sddl)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing restrictive DACL",
        ));
    }
    win32_result(unsafe {
        SetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    })
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn win32_result(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

struct SecurityDescriptor(*mut c_void);
impl SecurityDescriptor {
    fn parse(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::{
        BuildTrusteeWithSidW, GetEffectiveRightsFromAclW, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, WinAuthenticatedUserSid, WELL_KNOWN_SID_TYPE,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_READ_DATA, FILE_WRITE_DATA};

    fn effective_rights(descriptor: &SecurityDescriptor, sid_type: WELL_KNOWN_SID_TYPE) -> u32 {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        let mut sid = [0u32; 17];
        let mut length = std::mem::size_of_val(&sid) as u32;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    sid_type,
                    ptr::null_mut(),
                    sid.as_mut_ptr().cast(),
                    &mut length,
                )
            },
            0
        );
        let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
        unsafe { BuildTrusteeWithSidW(&mut trustee, sid.as_mut_ptr().cast()) };
        let mut rights = 0;
        win32_result(unsafe { GetEffectiveRightsFromAclW(dacl, &trustee, &mut rights) }).unwrap();
        rights
    }

    fn file_descriptor(path: &Path) -> SecurityDescriptor {
        let (handle, _) = open_trusted_path(path).unwrap();
        let mut descriptor = ptr::null_mut();
        win32_result(unsafe {
            GetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        })
        .unwrap();
        SecurityDescriptor(descriptor)
    }

    #[test]
    fn acl_policies_allow_config_reads_but_keep_tokens_private() {
        let root = SecurityDescriptor::parse(ROOT_SDDL).unwrap();
        let secret = SecurityDescriptor::parse(SECRET_SDDL).unwrap();
        assert_ne!(
            effective_rights(&root, WinAuthenticatedUserSid) & FILE_READ_DATA,
            0
        );
        assert_eq!(
            effective_rights(&root, WinAuthenticatedUserSid) & FILE_WRITE_DATA,
            0
        );
        assert_eq!(effective_rights(&secret, WinAuthenticatedUserSid), 0);
        for descriptor in [&root, &secret] {
            for owner in [WinLocalSystemSid, WinBuiltinAdministratorsSid] {
                assert_ne!(effective_rights(descriptor, owner) & FILE_WRITE_DATA, 0);
            }
        }
    }

    #[test]
    fn temporary_runtime_files_inherit_private_acl_and_are_cleaned_on_drop() {
        // Service filesystem tests require an elevated runner and use only
        // temporary paths. No security setup error is accepted as a test pass.
        let mut admins_sid = [0u32; 17];
        let mut length = std::mem::size_of_val(&admins_sid) as u32;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinBuiltinAdministratorsSid,
                    ptr::null_mut(),
                    admins_sid.as_mut_ptr().cast(),
                    &mut length,
                )
            },
            0
        );
        let mut is_admin = 0;
        assert_ne!(
            unsafe {
                CheckTokenMembership(
                    ptr::null_mut(),
                    admins_sid.as_mut_ptr().cast(),
                    &mut is_admin,
                )
            },
            0
        );
        assert_ne!(
            is_admin, 0,
            "ACL filesystem tests require an elevated Windows runner"
        );
        let base = std::env::temp_dir().join(format!("supermanager-acl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&base).unwrap();
        let root = ensure_root_at(&base).expect("create secure temporary state tree");
        let profile = uuid::Uuid::new_v4();
        let first = create_private_runtime_dir_at(&root, &profile).unwrap();
        let second = create_private_runtime_dir_at(&root, &profile).unwrap();
        assert_ne!(first.path(), second.path());
        let token = first.path().join("auth.txt");
        std::fs::write(&token, "test-token").unwrap();
        assert_eq!(
            effective_rights(&file_descriptor(&token), WinAuthenticatedUserSid),
            0
        );
        assert_ne!(
            effective_rights(&file_descriptor(&root), WinAuthenticatedUserSid) & FILE_READ_DATA,
            0
        );
        drop(first);
        assert!(!token.exists());
        assert!(second.path().exists());
        drop(second);
        assert!(secure_directory(&root.join("profiles"), ROOT_SDDL, false).is_err());

        // An existing writable handle must not survive an ACL repair and keep
        // changing data after the service begins trusting it.
        let config = root.join("profiles").join("open.json");
        let writer = std::fs::File::create(&config).unwrap();
        assert!(ensure_root_at(&base).is_err());
        let unrelated_session = create_private_runtime_dir_at(&root, &profile)
            .expect("live profile writer must not block a new private VPN session");
        let unrelated_token = unrelated_session.path().join("auth.txt");
        std::fs::write(&unrelated_token, "test-token").unwrap();
        assert_eq!(
            effective_rights(&file_descriptor(&unrelated_token), WinAuthenticatedUserSid),
            0
        );
        drop(unrelated_session);
        drop(writer);
        ensure_root_at(&base).unwrap();

        // Do not change the ACL of an unrelated file through a planted link.
        let linked = root.join("profiles").join("linked.json");
        std::fs::hard_link(&config, &linked).unwrap();
        assert!(ensure_root_at(&base).is_err());
        std::fs::remove_file(linked).unwrap();
        ensure_root_at(&base).unwrap();

        let known_hosts = root.join("known_hosts.json");
        let writer = std::fs::File::create(&known_hosts).unwrap();
        assert!(ensure_root_at(&base).is_err(), "top-level writers must be rejected");
        drop(writer);
        ensure_root_at(&base).unwrap();
        std::fs::remove_file(&known_hosts).unwrap();

        // A hardlink in the state root must not cause automatic DACL
        // propagation to expose a private file outside the state tree.
        let external = base.join("private-external");
        drop(secure_directory(&external, SECRET_SDDL, false).unwrap());
        let external_token = external.join("token.txt");
        std::fs::write(&external_token, "fixture-secret").unwrap();
        std::fs::hard_link(&external_token, &known_hosts).unwrap();
        assert!(ensure_root_at(&base).is_err(), "top-level hardlinks must be rejected");
        std::fs::remove_file(&known_hosts).unwrap();
        assert_eq!(
            effective_rights(&file_descriptor(&external_token), WinAuthenticatedUserSid),
            0,
            "rejected linked file must retain its private ACL"
        );

        let active = create_private_runtime_dir_at(&root, &profile).unwrap();
        let active_token = active.path().join("auth.txt");
        std::fs::write(&active_token, "fixture-secret").unwrap();
        ensure_root_at(&base).unwrap();
        assert_eq!(
            effective_rights(&file_descriptor(&active_token), WinAuthenticatedUserSid),
            0,
            "startup migration must preserve private runtime ACLs"
        );
        drop(active);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rejects_relative_state_roots_and_nul_paths() {
        assert!(ensure_root_at(Path::new("relative")).is_err());
        assert!(wide_path(Path::new("bad\0path")).is_err());
    }
}
