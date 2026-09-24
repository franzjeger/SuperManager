//! The libc calls the helper makes, behind safe functions.
//!
//! Each is a single system call whose only preconditions are its
//! arguments, so `unsafe` lives here, once, instead of at every call site.
//! One place also gets the argument checks right: a PID from a pidfile is
//! refused unless it names exactly one process, because `kill(0, …)`
//! signals the helper's whole process group and `kill(-1, …)`, as root,
//! every process on the machine.
#![allow(unsafe_code)]

use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

/// The process's effective user ID.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// `pid` as a `pid_t` that names exactly one process: positive, and in range.
fn single_process(pid: u32) -> Option<libc::pid_t> {
    libc::pid_t::try_from(pid).ok().filter(|&pid| pid > 0)
}

/// Whether a process with this PID exists and may be signalled.
pub fn process_alive(pid: u32) -> bool {
    let Some(pid) = single_process(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks that the process exists, and `pid` is
    // one positive PID.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Ask a process to exit (SIGTERM). Whether the signal was sent.
pub fn terminate(pid: u32) -> bool {
    let Some(pid) = single_process(pid) else {
        return false;
    };
    // SAFETY: SIGTERM to one positive PID.
    unsafe { libc::kill(pid, libc::SIGTERM) == 0 }
}

/// The ID of the group called `name`, if there is one.
///
/// `getgrnam_r`, not `getgrnam`: the helper is multi-threaded, and
/// `getgrnam` returns a pointer into storage the next lookup on any thread
/// overwrites.
pub fn group_id(name: &str) -> io::Result<Option<u32>> {
    let name = std::ffi::CString::new(name)?;
    // SAFETY: `group` is plain data; all-zero is a valid value for it
    // (null pointers, zero ids), and getgrnam_r fills it in.
    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut buf: Vec<libc::c_char> = vec![0; 1024];
    let mut found: *mut libc::group = std::ptr::null_mut();
    loop {
        // SAFETY: every pointer is valid for the duration of the call and
        // `buf.len()` is the length of `buf`; getgrnam_r writes only into
        // `group`, `buf` and `found`.
        let rc = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &raw mut group,
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut found,
            )
        };
        match rc {
            0 => return Ok((!found.is_null()).then_some(group.gr_gid)),
            libc::ERANGE if buf.len() < 1 << 20 => buf.resize(buf.len() * 2, 0),
            _ => return Err(io::Error::from_raw_os_error(rc)),
        }
    }
}

/// Start `cmd`'s child in a session of its own, so it is not taken down
/// with the helper when the helper is replaced (`deploy_self`).
pub fn new_session(cmd: &mut Command) {
    // SAFETY: the closure runs in the child between fork and exec, where
    // only async-signal-safe calls are allowed; setsid is one. Its failure
    // (already a session leader) leaves the child where it was, which is
    // what it did before this was a function.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pid_that_is_not_one_process_is_never_signalled() {
        // 0 is the caller's process group; u32::MAX is -1 as a pid_t,
        // which as root is every process on the machine.
        for pid in [0, u32::MAX, u32::try_from(i32::MAX).unwrap() + 1] {
            assert!(single_process(pid).is_none(), "{pid}");
            assert!(!process_alive(pid));
            assert!(!terminate(pid));
        }
        assert!(process_alive(std::process::id()));
    }

    #[test]
    fn groups_are_found_by_name() {
        // Every Unix system has group 0 ("root" on Linux, "wheel" on macOS);
        // a name no system uses has none.
        let zero = if cfg!(target_os = "macos") {
            "wheel"
        } else {
            "root"
        };
        assert_eq!(group_id(zero).unwrap(), Some(0));
        assert_eq!(group_id("supermanager-no-such-group").unwrap(), None);
    }
}
