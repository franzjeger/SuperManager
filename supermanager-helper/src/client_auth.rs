//! Only SuperManager itself may use the root helper.
//!
//! The helper acts as root on behalf of whoever it answers, so it answers
//! only SuperManager. The socket's root:admin 0660 mode keeps other users
//! out; this check decides which program may talk to it.
//!
//! Before a request is read, the helper identifies the connecting process
//! by the kernel audit token of its socket, which names that exact process
//! image, unlike a pid, which the kernel reuses. It then checks the process's
//! code signature against a requirement: anchored at Apple, issued to
//! SuperManager's team, with the app's own identifier. A certificate made
//! locally cannot satisfy "anchor apple".
//!
//! A helper signed with Developer ID, which is what users run, also refuses
//! a client that could be debugged or have code injected into it: one with
//! the get-task-allow, disable-library-validation or DYLD-variables
//! entitlement, without the hardened runtime, or with a debugger attached. A
//! helper signed for development accepts Xcode's Debug builds, which carry
//! get-task-allow.

use std::fmt;
use std::os::fd::AsRawFd;

use tokio::net::UnixStream;

pub(crate) const TEAM_ID: &str = "LY6LJ395B8";
const APP_ID: &str = "com.sybr.supermanager";

/// Which clients this helper accepts, decided by how the helper itself is
/// signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Signed with Developer ID, as on users' machines: the app, in a build
    /// that can be neither debugged nor injected into.
    Release,
    /// Signed for development, ad hoc, or not at all, as on a developer's
    /// machine: the app, Debug builds included.
    Development,
}

impl Policy {
    /// The code requirement a client's signature must satisfy.
    fn requirement(self) -> String {
        let app = format!(
            "anchor apple generic and certificate leaf[subject.OU] = \"{TEAM_ID}\" \
             and identifier \"{APP_ID}\""
        );
        match self {
            Policy::Development => app,
            Policy::Release => format!(
                "{app} \
                 and !entitlement[\"com.apple.security.get-task-allow\"] exists \
                 and !entitlement[\"com.apple.security.cs.disable-library-validation\"] exists \
                 and !entitlement[\"com.apple.security.cs.allow-dyld-environment-variables\"] exists"
            ),
        }
    }
}

/// Why a client was turned away. Logged, and sent back to the client.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal(String);

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Check the process on the other end of `stream` before anything it sent
/// is read.
pub async fn authorize(stream: &UnixStream, policy: Policy) -> Result<(), Refusal> {
    let token = peer_audit_token(stream)?;
    // Signature checks may read the client's executable from disk; keep them
    // off the async workers that answer everyone else.
    tokio::task::spawn_blocking(move || verify(&token, policy))
        .await
        .map_err(|e| Refusal(format!("the check did not finish: {e}")))?
}

/// The peer's `audit_token_t`, eight `u32`s the kernel recorded when it
/// connected.
fn peer_audit_token(stream: &UnixStream) -> Result<[u8; 32], Refusal> {
    let mut token = [0u8; 32];
    let mut len = libc::socklen_t::try_from(token.len()).unwrap_or(0);
    // SAFETY: the fd is a live socket, and `token`/`len` describe a writable
    // buffer of exactly that many bytes.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if rc != 0 || usize::try_from(len).ok() != Some(token.len()) {
        return Err(Refusal(format!(
            "the kernel has no audit token for the peer: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(token)
}

#[cfg(target_os = "macos")]
fn verify(token: &[u8; 32], policy: Policy) -> Result<(), Refusal> {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };

    let token = CFData::from_buffer(token);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token.as_concrete_TypeRef());
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|e| Refusal(format!("no code identity for the peer: {e}")))?;
    let requirement: SecRequirement = policy
        .requirement()
        .parse()
        .map_err(|e| Refusal(format!("bad requirement: {e}")))?;
    code.check_validity(Flags::NONE, &requirement)
        .map_err(|e| Refusal(format!("the peer is not SuperManager: {e}")))?;
    if policy == Policy::Release {
        release_state_ok(signing_state(&code)?)?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn verify(_token: &[u8; 32], _policy: Policy) -> Result<(), Refusal> {
    Err(Refusal("client verification needs macOS".into()))
}

/// Code directory flags (static) and code status (dynamic) of a running
/// process, from `SecCodeCopySigningInformation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SigningState {
    flags: u64,
    status: u64,
}

/// `kSecCodeSignatureRuntime` in CSCommon.h: signed for the hardened runtime.
const SIGNATURE_RUNTIME: u64 = 0x1_0000;
/// `kSecCodeStatusValid`: the kernel still considers the process validly signed.
const STATUS_VALID: u64 = 0x1;
/// `kSecCodeStatusDebugged`: a debugger has been attached.
const STATUS_DEBUGGED: u64 = 0x1000_0000;

/// What a Release helper additionally requires of a running client.
fn release_state_ok(state: SigningState) -> Result<(), Refusal> {
    if state.flags & SIGNATURE_RUNTIME == 0 {
        return Err(Refusal(
            "the peer does not run with the hardened runtime".into(),
        ));
    }
    if state.status & STATUS_VALID == 0 {
        return Err(Refusal("the peer's signature is no longer valid".into()));
    }
    if state.status & STATUS_DEBUGGED != 0 {
        return Err(Refusal("the peer is being debugged".into()));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn signing_state(
    code: &security_framework::os::macos::code_signing::SecCode,
) -> Result<SigningState, Refusal> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};

    // Not wrapped by security-framework.
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecCodeCopySigningInformation(
            code: core_foundation::base::CFTypeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32;
        static kSecCodeInfoFlags: CFStringRef;
        static kSecCodeInfoStatus: CFStringRef;
    }
    // kSecCSSigningInformation | kSecCSDynamicInformation
    const WANTED: u32 = (1 << 1) | (1 << 3);

    let mut information: CFDictionaryRef = std::ptr::null();
    // SAFETY: `code` is a live SecCode, and `information` is a valid out
    // pointer that receives a +1 dictionary on success.
    let rc =
        unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), WANTED, &raw mut information) };
    if rc != 0 || information.is_null() {
        return Err(Refusal(format!(
            "no signing information for the peer ({rc})"
        )));
    }
    // SAFETY: returned by a Copy function, so we own this reference.
    let information: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(information) };
    let number = |key: CFStringRef| -> Result<u64, Refusal> {
        // SAFETY: the kSecCodeInfo* keys are constant strings owned by Security.
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        information
            .find(&key)
            .and_then(|value| value.downcast::<CFNumber>())
            .and_then(|number| number.to_i64())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| Refusal(format!("the peer's signing information has no {key}")))
    };
    // SAFETY: reading extern statics provided by the Security framework.
    let (flags_key, status_key) = unsafe { (kSecCodeInfoFlags, kSecCodeInfoStatus) };
    Ok(SigningState {
        flags: number(flags_key)?,
        status: number(status_key)?,
    })
}

/// This helper's own policy. Release only on a positive Developer ID match;
/// a signature that cannot be read at all also counts as Release, so a
/// failure here can never loosen the check.
#[cfg(target_os = "macos")]
pub fn own_policy() -> Policy {
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

    // A Developer ID Application leaf (1.2.840.113635.100.6.1.13) issued by
    // the Developer ID CA (1.2.840.113635.100.6.2.6).
    const DEVELOPER_ID: &str = "anchor apple generic \
        and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
        and certificate leaf[field.1.2.840.113635.100.6.1.13] exists";
    // errSecCSReqFailed: validly signed, but not with Developer ID.
    const REQUIREMENT_FAILED: i32 = -67050;
    // errSecCSUnsigned
    const UNSIGNED: i32 = -67062;

    let checked = DEVELOPER_ID
        .parse::<SecRequirement>()
        .and_then(|requirement| {
            SecCode::for_self(Flags::NONE)?.check_validity(Flags::NONE, &requirement)
        });
    match checked {
        Ok(()) => Policy::Release,
        Err(e) if matches!(e.code(), REQUIREMENT_FAILED | UNSIGNED) => Policy::Development,
        Err(e) => {
            tracing::warn!(
                "could not read the helper's own signature ({e}); treating it as a release build"
            );
            Policy::Release
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn own_policy() -> Policy {
    Policy::Release
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};

    fn satisfies_statically(path: &str, policy: Policy) -> bool {
        let is_bundle = std::path::Path::new(path).is_dir();
        let url = core_foundation::url::CFURL::from_path(path, is_bundle).unwrap();
        let requirement: SecRequirement = policy.requirement().parse().unwrap();
        SecStaticCode::from_path(&url, Flags::NONE)
            .and_then(|code| code.check_validity(Flags::NONE, &requirement))
            .is_ok()
    }

    #[test]
    fn both_requirements_parse() {
        for policy in [Policy::Release, Policy::Development] {
            policy
                .requirement()
                .parse::<SecRequirement>()
                .unwrap_or_else(|e| panic!("{policy:?}: {e}"));
        }
    }

    /// cargo's linker signature is ad hoc, which is what a helper deployed
    /// straight from `target/` would carry.
    #[test]
    fn an_ad_hoc_signed_helper_is_a_development_build() {
        assert_eq!(own_policy(), Policy::Development);
    }

    /// The test process connects to itself: not SuperManager, so refused
    /// under either policy, before anything is read.
    #[tokio::test]
    async fn a_peer_that_is_not_supermanager_is_refused() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        for policy in [Policy::Release, Policy::Development] {
            let refusal = authorize(&ours, policy).await.unwrap_err();
            assert!(refusal.0.contains("not SuperManager"), "{refusal}");
        }
    }

    /// Signed by Apple is not enough: the team and identifier must match.
    #[test]
    fn an_apple_signed_program_is_not_supermanager() {
        assert!(!satisfies_statically("/usr/bin/true", Policy::Development));
    }

    #[test]
    fn a_release_client_must_be_hardened_valid_and_undebugged() {
        let good = SigningState {
            flags: SIGNATURE_RUNTIME,
            status: STATUS_VALID,
        };
        assert_eq!(release_state_ok(good), Ok(()));
        for bad in [
            SigningState { flags: 0, ..good },
            SigningState { status: 0, ..good },
            SigningState {
                status: STATUS_VALID | STATUS_DEBUGGED,
                ..good
            },
        ] {
            assert!(release_state_ok(bad).is_err(), "{bad:?}");
        }
    }

    /// The installed release app must pass the Release requirement, and a
    /// Debug build must fail it but pass Development. Needs real signed
    /// builds, so only run on request:
    ///
    /// ```text
    /// SUPERMANAGER_RELEASE_APP=/Applications/SuperManager.app \
    /// SUPERMANAGER_DEBUG_APP=…/Debug/SuperManagerMac.app \
    /// cargo test -p supermanager-helper -- --ignored real_builds
    /// ```
    #[test]
    #[ignore = "needs signed SuperManager builds, see the doc comment"]
    fn real_builds_meet_their_policy() {
        let release = std::env::var("SUPERMANAGER_RELEASE_APP").unwrap();
        assert!(satisfies_statically(&release, Policy::Release), "{release}");
        let debug = std::env::var("SUPERMANAGER_DEBUG_APP").unwrap();
        assert!(!satisfies_statically(&debug, Policy::Release), "{debug}");
        assert!(satisfies_statically(&debug, Policy::Development), "{debug}");
    }
}
