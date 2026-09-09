//! Kernel-bound client identity. No PID-only lookup, UID exemption or debug bypass.
use anyhow::{bail, Context, Result};
use std::{os::fd::AsRawFd, path::Path};
use tokio::net::UnixStream;

const TEAM: &str = "LY6LJ395B8";
const CLIENT_ID: &str = "com.sybr.supermanager";
const CLI_ID: &str = "com.sybr.supermanager.tailscale";
const DAEMON_ID: &str = "com.sybr.supermanager.tailscaled";

fn requirement(identifier: &str) -> String {
    format!("anchor apple generic and certificate leaf[subject.OU] = \"{TEAM}\" and identifier \"{identifier}\" and ! entitlement[\"com.apple.security.get-task-allow\"] exists and ! entitlement[\"com.apple.security.cs.disable-library-validation\"] exists and ! entitlement[\"com.apple.security.cs.allow-dyld-environment-variables\"] exists")
}

pub fn authorize(stream: &UnixStream) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use core_foundation::{base::TCFType, data::CFData};
        use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode};
        let mut token = [0u8; 32]; // Darwin audit_token_t: eight uint32_t values.
        let mut len = token.len() as libc::socklen_t;
        // SAFETY: token and len are valid writable buffers of the stated size.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                0,
                libc::LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if result != 0 || len as usize != token.len() {
            bail!("Client audit token unavailable");
        }
        let data = CFData::from_buffer(&token);
        let mut attributes = GuestAttributes::new();
        attributes.set_audit_token(data.as_concrete_TypeRef());
        let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .context("Client code identity unavailable")?;
        code.check_validity(Flags::STRICT_VALIDATE, &requirement(CLIENT_ID).parse()?)
            .context("Only the signed SuperManager application may use the root helper")?;
        check_runtime_flags(&code)?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = stream;
        bail!("Privileged helper requires macOS code identity verification")
    }
}

/// Verify only an immutable private staging file, never the caller's live path.
pub fn verify_tailscaled(path: &Path) -> Result<()> {
    verify_component(path, DAEMON_ID)
}
pub fn verify_tailscale_cli(path: &Path) -> Result<()> {
    verify_component(path, CLI_ID)
}
fn verify_component(path: &Path, identifier: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use core_foundation::url::CFURL;
        use security_framework::os::macos::code_signing::{Flags, SecStaticCode};
        let url =
            CFURL::from_path(path, false).ok_or_else(|| anyhow::anyhow!("Invalid staging path"))?;
        SecStaticCode::from_path(&url, Flags::NONE)?
            .check_validity(
                Flags::STRICT_VALIDATE | Flags::CHECK_ALL_ARCHITECTURES,
                &requirement(identifier).parse()?,
            )
            .context("Bundled tailscaled must have SuperManager's valid release signature")?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        bail!("Code signature verification is unavailable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    #[test]
    fn requirements_parse_and_reject_other_signed_programs_and_unsigned_payloads() {
        use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};
        let req: SecRequirement = requirement(CLIENT_ID).parse().unwrap();
        assert!(SecCode::for_self(Flags::NONE)
            .unwrap()
            .check_validity(Flags::NONE, &req)
            .is_err());
        let _: SecRequirement = requirement(DAEMON_ID).parse().unwrap();
        assert!(verify_tailscaled(Path::new("/usr/bin/true")).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload");
        std::fs::write(&path, "#!/bin/sh\necho untrusted\n").unwrap();
        assert!(verify_tailscaled(&path).is_err());
    }
    #[tokio::test]
    async fn unsigned_socket_peer_is_rejected() {
        let (one, _two) = UnixStream::pair().unwrap();
        assert!(authorize(&one).is_err());
    }
}

#[cfg(target_os = "macos")]
fn check_runtime_flags(code: &security_framework::os::macos::code_signing::SecCode) -> Result<()> {
    use core_foundation::{
        base::{CFType, TCFType},
        dictionary::{CFDictionary, CFDictionaryRef},
        number::CFNumber,
        string::{CFString, CFStringRef},
    };
    extern "C" {
        fn SecCodeCopySigningInformation(
            code: *const std::ffi::c_void,
            flags: u32,
            info: *mut CFDictionaryRef,
        ) -> i32;
        static kSecCodeInfoFlags: CFStringRef;
        static kSecCodeInfoStatus: CFStringRef;
    }
    let mut info = std::ptr::null();
    // SAFETY: valid SecCode object and output pointer, ownership follows Copy rule.
    let result = unsafe {
        SecCodeCopySigningInformation(code.as_CFTypeRef(), (1 << 1) | (1 << 3), &mut info)
    };
    if result != 0 || info.is_null() {
        bail!("Client signing flags unavailable");
    }
    let info: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    let flags_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoFlags) };
    let status_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoStatus) };
    let number = |key: &CFString| -> Result<i64> {
        info.find(key)
            .and_then(|value| value.downcast::<CFNumber>())
            .and_then(|n| n.to_i64())
            .ok_or_else(|| anyhow::anyhow!("Missing client signing state"))
    };
    let flags = number(&flags_key)?;
    let status = number(&status_key)?;
    // SDK CSCommon.h: runtime=0x10000, valid=1, debugged=0x10000000.
    if flags & 0x10000 == 0 || status & 1 == 0 || status & 0x10000000 != 0 {
        bail!("Client must use hardened runtime and must not be debugged");
    }
    Ok(())
}
