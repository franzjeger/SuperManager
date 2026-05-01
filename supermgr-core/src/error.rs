//! Typed error hierarchy for supermgr-core.
//!
//! [`BackendError`] is the leaf-level error used inside every VPN backend
//! implementation. [`SshError`] covers SSH key and host operations.
//! [`CoreError`] wraps all subsystem errors in one place, so callers that
//! don't need to discriminate can use a single `?` chain.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Backend errors
// ---------------------------------------------------------------------------

/// Errors that can originate inside a VPN backend implementation.
#[derive(Debug, Error)]
pub enum BackendError {
    /// The connection attempt failed for a protocol-level reason.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// An operation that requires an active tunnel was called while disconnected.
    #[error("not connected")]
    NotConnected,

    /// A connect was requested while a tunnel is already active.
    #[error("already connected")]
    AlreadyConnected,

    /// A network interface operation (create/delete/configure) failed.
    #[error("interface error: {0}")]
    Interface(String),

    /// A cryptographic key could not be parsed or generated.
    #[error("key error: {0}")]
    Key(String),

    /// Profile configuration is invalid or incomplete.
    #[error("configuration error: {0}")]
    Config(String),

    /// A required helper subprocess (e.g. `ipsec`) failed.
    #[error("subprocess error: {message}")]
    Subprocess {
        /// The subprocess command that was invoked.
        command: String,
        /// The error message or stderr output.
        message: String,
    },

    /// A permission or privilege error (the daemon may not be running as root).
    #[error("permission denied: {0}")]
    Permission(String),

    /// A timeout waiting for a state transition.
    #[error("operation timed out after {seconds}s")]
    Timeout {
        /// Number of seconds elapsed before the operation was abandoned.
        seconds: u64,
    },

    /// Passthrough for OS / file-system errors.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl BackendError {
    /// Returns `true` when retrying the same operation has no chance of
    /// succeeding without operator intervention (bad config, invalid
    /// credentials, permission errors, gateway-side auth rejection).
    ///
    /// Callers (notably the connect-retry loop in the daemon) skip
    /// exponential backoff on terminal errors and surface them immediately,
    /// avoiding 30-second user-visible latency on a typo.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            BackendError::AlreadyConnected
            | BackendError::Config(_)
            | BackendError::Key(_)
            | BackendError::Permission(_) => true,
            // ConnectionFailed is overloaded — it covers both transient
            // network failures and authoritative gateway rejections.
            // Treat AAA failures (server-side auth) as terminal since the
            // same credentials will keep failing on retry.
            BackendError::ConnectionFailed(msg) => {
                let lower = msg.to_ascii_lowercase();
                lower.contains("auth_failed")
                    || lower.contains("auth-failure")
                    || lower.contains("authentication failed")
                    || lower.contains("authentication required")
                    || lower.contains("invalid credentials")
                    || lower.contains("token has expired")
                    || lower.contains("session may have expired")
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Profile / store errors
// ---------------------------------------------------------------------------

/// Errors related to profile storage and retrieval.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// No profile with the given ID exists.
    #[error("profile not found: {id}")]
    NotFound {
        /// The UUID that was looked up but not found.
        id: uuid::Uuid,
    },

    /// A profile with the same name already exists.
    #[error("duplicate profile name: {name}")]
    DuplicateName {
        /// The conflicting display name.
        name: String,
    },

    /// A WireGuard `.conf` or FortiGate `.mobileconfig` file could not be parsed.
    #[error("import failed for '{path}': {reason}")]
    ImportFailed {
        /// Path or label of the file that failed to import.
        path: String,
        /// Human-readable description of the parse or validation failure.
        reason: String,
    },

    /// Profile serialisation / deserialisation failure.
    #[error("serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),

    /// Profile file I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Secret-store errors
// ---------------------------------------------------------------------------

/// Errors raised when reading or writing credentials in the system secret store.
#[derive(Debug, Error)]
pub enum SecretError {
    /// The requested secret (private key, password, PSK) was not found.
    #[error("secret not found for key '{label}'")]
    NotFound {
        /// The keyring label that was looked up but had no stored value.
        label: String,
    },

    /// The secret service (GNOME Keyring / KWallet) is unavailable.
    #[error("secret service unavailable: {0}")]
    ServiceUnavailable(String),

    /// A secret could not be stored.
    #[error("failed to store secret '{label}': {reason}")]
    StoreFailed {
        /// The keyring label under which storage was attempted.
        label: String,
        /// The underlying error returned by the secret service.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// SSH errors
// ---------------------------------------------------------------------------

/// Errors specific to SSH key and host management operations.
#[derive(Debug, Error)]
pub enum SshError {
    /// SSH key generation failed (e.g. `ssh-keygen` returned an error).
    #[error("key generation failed: {0}")]
    KeyGenFailed(String),

    /// No SSH key with the given ID exists.
    #[error("SSH key not found: {id}")]
    KeyNotFound {
        /// The UUID that was looked up but not found.
        id: uuid::Uuid,
    },

    /// No SSH host with the given ID exists.
    #[error("SSH host not found: {id}")]
    HostNotFound {
        /// The UUID that was looked up but not found.
        id: uuid::Uuid,
    },

    /// An SSH connection attempt to a remote host failed.
    #[error("connection to '{host}' failed: {reason}")]
    ConnectionFailed {
        /// The hostname or IP address that was unreachable.
        host: String,
        /// Human-readable description of the failure.
        reason: String,
    },

    /// SSH authentication failed (wrong key, wrong password, etc.).
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Pushing a public key to one or more remote hosts failed.
    #[error("key push failed: {0}")]
    PushFailed(String),

    /// Revoking a public key from one or more remote hosts failed.
    #[error("key revocation failed: {0}")]
    RevokeFailed(String),

    /// Importing an existing SSH key from disk failed.
    #[error("key import failed: {0}")]
    ImportFailed(String),

    /// A key with the same fingerprint already exists in the store.
    #[error("duplicate fingerprint: {fingerprint}")]
    DuplicateFingerprint {
        /// The SSH key fingerprint that collided.
        fingerprint: String,
    },

    /// Passthrough for OS / file-system errors.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Top-level error
// ---------------------------------------------------------------------------

/// Unified error type for the `supermgr-core` crate.
///
/// Application code that does not need to distinguish error categories can use
/// `CoreError` as a single catch-all via `?` conversion.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Originates inside a VPN backend.
    #[error("backend: {0}")]
    Backend(#[from] BackendError),

    /// Originates in the profile store.
    #[error("profile: {0}")]
    Profile(#[from] ProfileError),

    /// Originates in the secret store.
    #[error("secret: {0}")]
    Secret(#[from] SecretError),

    /// Originates in the SSH subsystem.
    #[error("ssh: {0}")]
    Ssh(#[from] SshError),

    /// D-Bus communication error.
    #[error("D-Bus: {0}")]
    DBus(#[from] zbus::Error),

    /// D-Bus FDO error (returned by method handlers to callers).
    #[error("D-Bus FDO: {0}")]
    DBusFdo(#[from] zbus::fdo::Error),

    /// Unexpected internal invariant violation.
    #[error("internal error: {0}")]
    Internal(String),
}

impl CoreError {
    /// Convenience constructor for [`CoreError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}
