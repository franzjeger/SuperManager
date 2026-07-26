//! Persistent known-hosts store for SSH host-key verification.
//!
//! The implementation moved to [`supermgr_core::ssh::known_hosts`] so the
//! Linux daemon (`supermgrd`) applies exactly the same policy as the macOS
//! engine — it previously had no host-key verification at all, which is the
//! kind of drift a single shared module prevents. This re-export keeps the
//! `crate::ssh::known_hosts::*` paths working for engine callers.

pub use supermgr_core::ssh::known_hosts::{
    HostKeyCheck, KnownHostsError, KnownHostsStore, Result,
};
