//! SDDL-driven security descriptor for the daemon's named pipe.
//!
//! The default ACL on a pipe created by a `LocalSystem` service is
//! restrictive enough that the interactive user can't even open it — and
//! conversely, in console-mode (developer) builds the default ACL permits
//! every authenticated user including non-elevated processes. Neither is
//! correct for production.
//!
//! This module builds an explicit security descriptor from an SDDL string
//! and hands it back as raw pointers suitable for
//! [`ServerOptions::create_with_security_attributes_raw`]. The string
//! grants:
//!
//! | SID | Permissions |
//! |-----|-------------|
//! | `NT AUTHORITY\SYSTEM`    | Generic All — the daemon process itself |
//! | `BUILTIN\Administrators` | Generic All — service control & debug |
//! | `NT AUTHORITY\Authenticated Users` | Generic Read + Generic Write — the GUI/MCP client |
//!
//! Anonymous/network-logon principals are excluded by omission — SDDL
//! deny-by-default for unenumerated SIDs.
//!
//! # Lifetime contract
//!
//! `PipeSecurity` owns the heap allocations the Win32 APIs hand back. It
//! must outlive the `NamedPipeServer` instance that references it.
//! Dropping it calls `LocalFree` on the security descriptor.

use std::{ffi::c_void, io, ptr};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::{
    Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    },
    SECURITY_ATTRIBUTES,
};

/// SDDL granting:
/// - SY (SYSTEM)             → GA (Generic All)
/// - BA (Builtin Admins)     → GA
/// - AU (Authenticated Users)→ GR | GW  (read + write data only)
///
/// We don't grant FILE_WRITE_DAC / FILE_WRITE_OWNER to AU so a logged-in
/// user can't re-permission the pipe after open.
const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

/// Owns the heap allocation behind a SECURITY_DESCRIPTOR + attributes
/// pair. Hand `attrs_ptr()` to tokio's pipe ServerOptions and keep the
/// struct alive until the listener is replaced.
pub struct PipeSecurity {
    /// Raw pointer returned by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    /// Allocated by the OS; freed via `LocalFree` in `Drop`.
    descriptor: *mut c_void,
    /// SECURITY_ATTRIBUTES owned by this struct. Heap-pinned via `Box` so
    /// taking `&mut` to its address stays valid for the lifetime of `Self`.
    attrs: Box<SECURITY_ATTRIBUTES>,
}

// The pointers here are not Send/Sync by default because they came from
// FFI, but the lifetime contract is "owned by this struct and read-only
// after construction" — exactly the conditions under which it is sound
// to mark this Send (which the tokio API requires when handing the
// pointer across an `await`).
unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

impl PipeSecurity {
    /// Build a security descriptor from the SDDL constant and wrap it in
    /// SECURITY_ATTRIBUTES.
    pub fn restrictive() -> io::Result<Self> {
        // Convert the SDDL string to a wide-string buffer.
        let mut wide: Vec<u16> = PIPE_SDDL.encode_utf16().collect();
        wide.push(0);

        let mut descriptor: *mut c_void = ptr::null_mut();
        // The Win32 entry point allocates the descriptor on the
        // process's local heap and stores the pointer in our out-arg.
        // Returns nonzero on success.
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

    /// Pointer suitable for `create_with_security_attributes_raw`. Valid
    /// while `self` is alive.
    pub fn attrs_ptr(&mut self) -> *mut c_void {
        std::ptr::from_mut(&mut *self.attrs).cast::<c_void>()
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: descriptor was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW, which
            // documents LocalFree as the matching deallocator.
            unsafe {
                LocalFree(self.descriptor as _);
            }
            self.descriptor = ptr::null_mut();
        }
    }
}
