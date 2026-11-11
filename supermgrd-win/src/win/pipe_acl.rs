//! SDDL-driven security descriptor and caller token verification for the daemon's named pipe.
//!
//! | Principal / Label | Permissions |
//! |-------------------|-------------|
//! | `NT AUTHORITY\SYSTEM` (`SY`)       | Generic All — the daemon process itself |
//! | `BUILTIN\Administrators` (`BA`)    | Generic All — service control, debug & elevated CI |
//! | `NT AUTHORITY\INTERACTIVE` (`IU`)  | `0x0012019B` — read + write pipe data only (`FILE_CREATE_PIPE_INSTANCE` withheld) |
//! | Mandatory Label Medium (`ME`)      | `No-Write-Up` (`NW`) — blocks Low/Untrusted-integrity sandboxed processes |
//!
//! Withholding `FILE_CREATE_PIPE_INSTANCE` (`0x0004`), `WRITE_DAC`, and `WRITE_OWNER`
//! from `IU` ensures an unprivileged interactive process can neither squat/create
//! secondary pipe instances nor re-permission the pipe handle.

use std::{ffi::c_void, io, ptr};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::{
    Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    },
    CheckTokenMembership, CreateWellKnownSid, DuplicateToken, GetTokenInformation,
    LookupAccountNameW, RevertToSelf, SecurityIdentification, TokenLinkedToken, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, PSID, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, SID_NAME_USE, TOKEN_DUPLICATE, TOKEN_LINKED_TOKEN, TOKEN_QUERY,
    TOKEN_USER, WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

/// `FILE_GENERIC_READ (0x00120089) | FILE_WRITE_DATA (0x0002) | FILE_WRITE_EA (0x0010) | FILE_WRITE_ATTRIBUTES (0x0100)`
/// = `0x0012019B`. Grants pipe read/write I/O to interactive callers WITHOUT
/// `FILE_CREATE_PIPE_INSTANCE` (`0x0004`), `WRITE_DAC`, or `WRITE_OWNER`.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)S:(ML;;NW;;;ME)";

/// Verified identity of a connected named-pipe client.
#[derive(Debug, Clone)]
pub struct CallerAuth {
    /// True when the caller is `SYSTEM`, a member of `BUILTIN\Administrators`
    /// (including UAC split-token administrators), or a member of the local
    /// `SuperManager Operators` group.
    pub is_admin_or_operator: bool,
    /// String SID (`S-1-5-...`) of the caller's user account for auditing/diagnostics.
    pub user_sid: String,
}

/// Owns the heap allocation behind a SECURITY_DESCRIPTOR + attributes pair.
pub struct PipeSecurity {
    descriptor: *mut c_void,
    attrs: Box<SECURITY_ATTRIBUTES>,
}

unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

impl PipeSecurity {
    /// Build a security descriptor from `PIPE_SDDL` and wrap it in `SECURITY_ATTRIBUTES`.
    pub fn restrictive() -> io::Result<Self> {
        let mut wide: Vec<u16> = PIPE_SDDL.encode_utf16().collect();
        wide.push(0);

        let mut descriptor: *mut c_void = ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let attrs = Box::new(SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        });
        Ok(Self { descriptor, attrs })
    }

    /// Pointer suitable for `create_with_security_attributes_raw`. Valid while `self` is alive.
    pub fn attrs_ptr(&mut self) -> *mut c_void {
        std::ptr::from_mut(&mut *self.attrs).cast::<c_void>()
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe {
                LocalFree(self.descriptor as _);
            }
            self.descriptor = ptr::null_mut();
        }
    }
}

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct RevertGuard;

impl Drop for RevertGuard {
    fn drop(&mut self) {
        let ok = unsafe { RevertToSelf() };
        assert!(
            ok != 0,
            "RevertToSelf failed after named-pipe impersonation"
        );
    }
}

/// Inspect the connected client's security token after at least one byte has
/// been read from `pipe_handle`.
pub fn caller_auth_from_pipe(pipe_handle: HANDLE) -> io::Result<CallerAuth> {
    let ok = unsafe { ImpersonateNamedPipeClient(pipe_handle) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let revert = RevertGuard;

    let mut raw_token: HANDLE = ptr::null_mut();
    let opened = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            1,
            &mut raw_token,
        )
    };
    drop(revert);
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = HandleGuard(raw_token);

    let user_sid = token_user_sid_string(token.0).unwrap_or_else(|_| "unknown-sid".to_owned());
    let is_admin_or_operator = token_is_authorized(token.0);

    Ok(CallerAuth {
        is_admin_or_operator,
        user_sid,
    })
}

fn token_user_sid_string(token: HANDLE) -> io::Result<String> {
    let mut needed: u32 = 0;
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let token_user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
    let mut str_ptr: *mut u16 = ptr::null_mut();
    let conv = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut str_ptr) };
    if conv == 0 || str_ptr.is_null() {
        return Err(io::Error::last_os_error());
    }
    let sid_string = unsafe {
        let mut len = 0usize;
        while *str_ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(str_ptr, len);
        let out = String::from_utf16_lossy(slice);
        LocalFree(str_ptr.cast::<c_void>());
        out
    };
    Ok(sid_string)
}

fn check_well_known_sid(imp_token: HANDLE, kind: WELL_KNOWN_SID_TYPE) -> bool {
    let mut sid_buf = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut cb = SECURITY_MAX_SID_SIZE;
    let created = unsafe {
        CreateWellKnownSid(
            kind,
            ptr::null_mut(),
            sid_buf.as_mut_ptr().cast::<c_void>(),
            &mut cb,
        )
    };
    if created == 0 {
        return false;
    }
    check_sid_membership(imp_token, sid_buf.as_mut_ptr().cast::<c_void>())
}

fn check_operators_group(imp_token: HANDLE) -> bool {
    let mut group_name: Vec<u16> = "SuperManager Operators".encode_utf16().collect();
    group_name.push(0);
    let mut sid_buf = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut cb_sid = SECURITY_MAX_SID_SIZE;
    let mut domain_buf = [0u16; 256];
    let mut cch_domain = domain_buf.len() as u32;
    let mut use_kind: SID_NAME_USE = 0;

    let found = unsafe {
        LookupAccountNameW(
            ptr::null(),
            group_name.as_ptr(),
            sid_buf.as_mut_ptr().cast::<c_void>(),
            &mut cb_sid,
            domain_buf.as_mut_ptr(),
            &mut cch_domain,
            &mut use_kind,
        )
    };
    if found == 0 {
        return false;
    }
    check_sid_membership(imp_token, sid_buf.as_mut_ptr().cast::<c_void>())
}

fn check_sid_membership(imp_token: HANDLE, sid: PSID) -> bool {
    let mut is_member: i32 = 0;
    let ok = unsafe { CheckTokenMembership(imp_token, sid, &mut is_member) };
    ok != 0 && is_member != 0
}

fn token_is_authorized(imp_token: HANDLE) -> bool {
    if check_well_known_sid(imp_token, WinLocalSystemSid)
        || check_well_known_sid(imp_token, WinBuiltinAdministratorsSid)
        || check_operators_group(imp_token)
    {
        return true;
    }

    // Under UAC, a local Administrator launching the desktop GUI without
    // "Run as administrator" holds a filtered split token whose linked token
    // carries the unfiltered Administrator group membership.
    let mut linked = TOKEN_LINKED_TOKEN::default();
    let mut ret_len: u32 = 0;
    let got_linked = unsafe {
        GetTokenInformation(
            imp_token,
            TokenLinkedToken,
            std::ptr::from_mut(&mut linked).cast::<c_void>(),
            std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut ret_len,
        )
    };
    if got_linked == 0 || linked.LinkedToken.is_null() {
        return false;
    }
    let linked_guard = HandleGuard(linked.LinkedToken);

    if check_well_known_sid(linked_guard.0, WinBuiltinAdministratorsSid) {
        return true;
    }

    // When queried as `LocalSystem` (`SeTcbPrivilege`), `TokenLinkedToken` is a
    // primary token; `CheckTokenMembership` requires an impersonation token.
    let mut dup_raw: HANDLE = ptr::null_mut();
    let duplicated =
        unsafe { DuplicateToken(linked_guard.0, SecurityIdentification, &mut dup_raw) };
    if duplicated == 0 || dup_raw.is_null() {
        return false;
    }
    let dup_guard = HandleGuard(dup_raw);
    check_well_known_sid(dup_guard.0, WinBuiltinAdministratorsSid)
}
