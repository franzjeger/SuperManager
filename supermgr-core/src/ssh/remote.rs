//! Transport abstraction for remote operations over an SSH session.
//!
//! # Why this exists
//!
//! [`crate::ssh::authorized_keys`] knows *what* to do to a remote
//! `authorized_keys` file — which shell commands to issue, when to prefer
//! SFTP, how to stay BusyBox-compatible. It has no business knowing *how*
//! the bytes get there.
//!
//! That split matters because the workspace has two SSH session types that
//! have deliberately diverged: `supermgrd`'s supports certificate auth,
//! keyboard-interactive and jump hosts, while `supermgr-engine`'s is
//! deliberately smaller. They cannot be merged, but the key-management
//! logic on top of them was identical — and was maintained as two copies
//! that had already begun to drift. Each crate now implements these two
//! traits over its own session in a few dozen lines, and shares one copy of
//! the logic.
//!
//! Keeping the traits here rather than in a session type also means the
//! shared logic is testable without a network: see the fake shell in
//! `authorized_keys`'s tests, which asserts the exact command strings sent
//! to a remote host.

use async_trait::async_trait;

use crate::error::SshError;

/// A remote shell that can run commands and may be able to transfer files.
#[async_trait]
pub trait RemoteShell: Sync {
    /// Run `command` on the remote host.
    ///
    /// Returns `(exit_status, stdout, stderr)`. A non-zero exit status is
    /// **not** an error — plenty of callers here use `grep`'s exit code as a
    /// predicate. Only a transport failure is an `Err`.
    async fn exec(&self, command: &str) -> Result<(u32, String, String), SshError>;

    /// Open a file-transfer session over this connection.
    ///
    /// An `Err` means the remote has no usable SFTP subsystem, which is
    /// common on embedded network gear (Dropbear without the sftp-server
    /// binary). Callers are expected to fall back to shell commands rather
    /// than give up.
    async fn files(&self) -> Result<Box<dyn RemoteFiles + Send + Sync + '_>, SshError>;
}

/// File operations over an established transfer session.
#[async_trait]
pub trait RemoteFiles {
    /// Read a file whole. `Err` covers "absent" as well as "unreadable" —
    /// callers here treat both the same way.
    async fn read(&self, path: &str) -> Result<Vec<u8>, SshError>;

    /// Write `contents` to `path`, replacing what was there.
    async fn write(&self, path: &str, contents: &[u8]) -> Result<(), SshError>;

    /// Create a directory. Not required to be recursive.
    async fn create_dir(&self, path: &str) -> Result<(), SshError>;

    /// Whether `path` exists.
    async fn exists(&self, path: &str) -> bool;
}
