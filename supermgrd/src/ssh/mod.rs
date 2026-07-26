//! SSH transport for the daemon — connection setup and the audit log.
//!
//! Key generation, `~/.ssh` import scanning, and `authorized_keys`
//! push/revoke used to live here as byte-identical copies of the same
//! modules in `supermgr-engine`. They now live once in
//! [`supermgr_core::ssh`], driven through the
//! [`supermgr_core::ssh::remote::RemoteShell`] trait that
//! [`connection::SshSession`] implements.

pub mod audit;
pub mod connection;
