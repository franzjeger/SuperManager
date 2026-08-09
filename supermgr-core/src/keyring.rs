//! Keyring integration — secure storage for secrets.
//!
//! Provides [`SecretStore`], a thin async trait over the system secret store,
//! with platform-specific implementations:
//!
//! - **Linux**: [`LibsecretStore`] backed by the D-Bus Secret Service protocol
//!   (GNOME Keyring, KWallet).
//! - **macOS**: [`KeychainStore`] backed by the macOS Keychain via the
//!   `security-framework` crate.
//!
//! # Secret lifecycle
//!
//! 1. **Import** — the daemon calls [`SecretStore::store`] with the raw bytes
//!    of a private key, password, or PSK and a unique string label derived from
//!    the profile or key UUID (e.g. `"supermgr/wg/a1b2c3d4/privkey"` or
//!    `"supermgr/ssh/a1b2c3d4/privkey"`).
//! 2. **Connect** — the backend calls [`SecretStore::retrieve`] to get the bytes
//!    back as a [`ZeroizingSecret`], which zeroes its heap buffer on drop so the
//!    key material cannot linger in memory after use.

#[cfg(target_os = "linux")]
use std::collections::HashMap;

use async_trait::async_trait;
#[cfg(target_os = "linux")]
use secret_service::{EncryptionType, SecretService};
use zeroize::Zeroize;

use crate::error::SecretError;

#[cfg(target_os = "windows")]
use keyring::Entry as WinKeyringEntry;

// ---------------------------------------------------------------------------
// ZeroizingSecret
// ---------------------------------------------------------------------------

/// A heap-allocated secret buffer that is zeroed in place when dropped.
///
/// All secret bytes returned from [`SecretStore::retrieve`] are wrapped in
/// this type.  Callers should consume (e.g. parse) the contents and let the
/// wrapper drop naturally — no explicit scrubbing is needed.
pub struct ZeroizingSecret(Vec<u8>);

impl ZeroizingSecret {
    /// Wrap a raw byte vector, transferring ownership.
    ///
    /// The buffer will be zeroed when the returned `ZeroizingSecret` is dropped.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::ops::Deref for ZeroizingSecret {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ZeroizingSecret {
    /// Zero the secret bytes before the backing allocation is released.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for ZeroizingSecret {
    /// Prints only the byte length — never the contents — to prevent secret
    /// material from appearing in log output or panic messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZeroizingSecret({} bytes)", self.0.len())
    }
}

// ---------------------------------------------------------------------------
// SecretStore trait
// ---------------------------------------------------------------------------

/// Async abstraction over a system secret store.
///
/// Implementations are expected to be cheap to construct (no I/O at
/// construction time) and to open a fresh service connection on each operation.
/// This keeps the API simple: callers do not need to manage connection lifetimes.
///
/// The trait is object-safe via [`async_trait`] so it can be used as
/// `Box<dyn SecretStore>` when the concrete type needs to be erased.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Persist `secret` bytes under `label`, replacing any existing value.
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError>;

    /// Retrieve the bytes stored under `label`.
    async fn retrieve(&self, label: &str) -> Result<ZeroizingSecret, SecretError>;

    /// Delete the secret stored under `label`.
    async fn delete(&self, label: &str) -> Result<(), SecretError>;
}

// ---------------------------------------------------------------------------
// Linux: LibsecretStore
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
/// D-Bus attribute key that identifies supermgr items in the keyring.
const ATTR_KEY: &str = "supermgr_label";

/// Production [`SecretStore`] backed by the system Secret Service D-Bus API.
///
/// Works with any compliant service: GNOME Keyring, KWallet (via
/// `kwallet-secrets`), or any daemon that implements
/// `org.freedesktop.secrets`.
#[cfg(target_os = "linux")]
pub struct LibsecretStore;

#[cfg(target_os = "linux")]
impl LibsecretStore {
    /// Create a new `LibsecretStore`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "linux")]
impl Default for LibsecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl SecretStore for LibsecretStore {
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError> {
        let ss = SecretService::connect(EncryptionType::Dh)
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        let collection = ss
            .get_default_collection()
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        collection
            .unlock()
            .await
            .map_err(|e| {
                SecretError::ServiceUnavailable(format!("collection unlock failed: {e}"))
            })?;

        let mut attrs = HashMap::new();
        attrs.insert(ATTR_KEY, label);

        collection
            .create_item(
                label,
                attrs,
                secret,
                true,
                "application/octet-stream",
            )
            .await
            .map_err(|e| SecretError::StoreFailed {
                label: label.to_owned(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    async fn retrieve(&self, label: &str) -> Result<ZeroizingSecret, SecretError> {
        let ss = SecretService::connect(EncryptionType::Dh)
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        let collection = ss
            .get_default_collection()
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        collection
            .unlock()
            .await
            .map_err(|e| {
                SecretError::ServiceUnavailable(format!("collection unlock failed: {e}"))
            })?;

        let mut attrs = HashMap::new();
        attrs.insert(ATTR_KEY, label);

        let items = collection
            .search_items(attrs)
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        let item = items
            .into_iter()
            .next()
            .ok_or_else(|| SecretError::NotFound {
                label: label.to_owned(),
            })?;

        let bytes = item
            .get_secret()
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        Ok(ZeroizingSecret::from_vec(bytes))
    }

    async fn delete(&self, label: &str) -> Result<(), SecretError> {
        let ss = SecretService::connect(EncryptionType::Dh)
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        let collection = ss
            .get_default_collection()
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        collection
            .unlock()
            .await
            .map_err(|e| {
                SecretError::ServiceUnavailable(format!("collection unlock failed: {e}"))
            })?;

        let mut attrs = HashMap::new();
        attrs.insert(ATTR_KEY, label);

        let items = collection
            .search_items(attrs)
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        for item in items {
            item.delete()
                .await
                .map_err(|e| SecretError::StoreFailed {
                    label: label.to_owned(),
                    reason: e.to_string(),
                })?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// macOS: KeychainStore
// ---------------------------------------------------------------------------

/// Production [`SecretStore`] backed by the macOS Keychain.
///
/// Uses `security-framework` to store and retrieve generic password items.
/// Items are identified by service name `"com.sybr.supermanager"` and
/// account name set to the label.
#[cfg(target_os = "macos")]
pub struct KeychainStore;

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "com.sybr.supermanager";

#[cfg(target_os = "macos")]
impl KeychainStore {
    /// Create a new `KeychainStore`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl Default for KeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
#[async_trait]
impl SecretStore for KeychainStore {
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError> {
        use security_framework::passwords::{set_generic_password, delete_generic_password};

        // Delete existing item first (set_generic_password fails on duplicates)
        let _ = delete_generic_password(KEYCHAIN_SERVICE, label);

        set_generic_password(KEYCHAIN_SERVICE, label, secret)
            .map_err(|e| SecretError::StoreFailed {
                label: label.to_owned(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    async fn retrieve(&self, label: &str) -> Result<ZeroizingSecret, SecretError> {
        use security_framework::passwords::get_generic_password;

        let bytes = get_generic_password(KEYCHAIN_SERVICE, label)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("-25300") || msg.contains("ItemNotFound") {
                    SecretError::NotFound {
                        label: label.to_owned(),
                    }
                } else {
                    SecretError::ServiceUnavailable(msg)
                }
            })?;

        Ok(ZeroizingSecret::from_vec(bytes))
    }

    async fn delete(&self, label: &str) -> Result<(), SecretError> {
        use security_framework::passwords::delete_generic_password;

        delete_generic_password(KEYCHAIN_SERVICE, label)
            .map_err(|e| SecretError::StoreFailed {
                label: label.to_owned(),
                reason: e.to_string(),
            })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Windows: CredentialManagerStore
// ---------------------------------------------------------------------------

/// Production [`SecretStore`] backed by Windows Credential Manager.
///
/// Uses the `keyring` crate's `windows-native` backend, which wraps
/// `CredReadW` / `CredWriteW` / `CredDeleteW` from the Advapi32 Credential
/// Management API. Items are stored under the target name
/// `"com.sybr.supermanager:<label>"`, persisted at `LOCAL_MACHINE` scope so
/// the daemon (running as `LocalSystem`) and the interactive-user GUI can
/// both reach them. Persistence survives reboot but does not roam.
///
/// # Large-secret chunking
///
/// Windows Credential Manager limits `CredentialBlobSize` to 2 560 bytes
/// (`CRED_MAX_CREDENTIAL_BLOB_SIZE`).  RSA-4096 private keys in PEM format
/// are ~3 200 bytes and would overflow that limit.  When a secret exceeds
/// [`WIN_CRED_MAX_BLOB`] bytes this implementation transparently splits it
/// into numbered chunks stored at `{label}:chunk:{i}` and writes a compact
/// marker at the primary label so `retrieve` can reassemble them.  Callers
/// see a single opaque `store` / `retrieve` / `delete` interface regardless
/// of whether chunking was needed.
#[cfg(target_os = "windows")]
pub struct CredentialManagerStore;

/// Safe upper bound for a single Credential Manager blob (platform limit is
/// 2 560 bytes; we stay 160 bytes below to leave room for encoding overhead).
#[cfg(target_os = "windows")]
const WIN_CRED_MAX_BLOB: usize = 2400;

/// ASCII prefix written into the primary credential entry when a secret has
/// been split across multiple chunks.  Real secrets (PEM keys, passwords,
/// PSKs) never start with this string.
#[cfg(target_os = "windows")]
const CHUNK_PREFIX: &str = "SMCHNK:";

#[cfg(target_os = "windows")]
const WIN_KEYRING_SERVICE: &str = "com.sybr.supermanager";

#[cfg(target_os = "windows")]
impl CredentialManagerStore {
    /// Create a new `CredentialManagerStore`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Build a `keyring::Entry` for `label`. Credential Manager calls are
    /// cheap and stateless, so we open a fresh entry per operation rather
    /// than caching handles across awaits.
    fn entry(label: &str) -> Result<WinKeyringEntry, SecretError> {
        WinKeyringEntry::new(WIN_KEYRING_SERVICE, label).map_err(|e| {
            SecretError::ServiceUnavailable(format!("keyring entry construct: {e}"))
        })
    }

    // ------------------------------------------------------------------
    // Low-level single-entry helpers (no chunking logic)
    // ------------------------------------------------------------------

    /// Write `secret` bytes directly to one Credential Manager entry.
    async fn write_one(label: String, secret: Vec<u8>) -> Result<(), SecretError> {
        tokio::task::spawn_blocking(move || {
            let entry = Self::entry(&label)?;
            entry.set_secret(&secret).map_err(|e| SecretError::StoreFailed {
                label: label.clone(),
                reason: e.to_string(),
            })
        })
        .await
        .map_err(|e| SecretError::ServiceUnavailable(format!("spawn_blocking: {e}")))?
    }

    /// Read bytes from one Credential Manager entry.
    async fn read_one(label: String) -> Result<Vec<u8>, SecretError> {
        tokio::task::spawn_blocking(move || {
            let entry = Self::entry(&label)?;
            match entry.get_secret() {
                Ok(b) => Ok(b),
                Err(keyring::Error::NoEntry) => {
                    Err(SecretError::NotFound { label: label.clone() })
                }
                Err(e) => Err(SecretError::ServiceUnavailable(e.to_string())),
            }
        })
        .await
        .map_err(|e| SecretError::ServiceUnavailable(format!("spawn_blocking: {e}")))?
    }

    /// Delete one Credential Manager entry.  Returns `NotFound` if absent.
    async fn erase_one(label: String) -> Result<(), SecretError> {
        tokio::task::spawn_blocking(move || {
            let entry = Self::entry(&label)?;
            match entry.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => {
                    Err(SecretError::NotFound { label: label.clone() })
                }
                Err(e) => Err(SecretError::StoreFailed {
                    label: label.clone(),
                    reason: e.to_string(),
                }),
            }
        })
        .await
        .map_err(|e| SecretError::ServiceUnavailable(format!("spawn_blocking: {e}")))?
    }

    /// Delete one entry, silently ignoring `NotFound`.
    async fn erase_one_best_effort(label: String) {
        let _ = Self::erase_one(label).await;
    }
}

#[cfg(target_os = "windows")]
impl Default for CredentialManagerStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
#[async_trait]
impl SecretStore for CredentialManagerStore {
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError> {
        if secret.len() <= WIN_CRED_MAX_BLOB {
            // Fits in one entry — direct write.
            Self::write_one(label.to_owned(), secret.to_vec()).await
        } else {
            // Too large: split into chunks and write a marker at the
            // primary label so `retrieve` knows to reassemble.
            let chunks: Vec<Vec<u8>> = secret
                .chunks(WIN_CRED_MAX_BLOB)
                .map(|c| c.to_vec())
                .collect();
            let n = chunks.len();
            let marker = format!("{CHUNK_PREFIX}{n}").into_bytes();
            Self::write_one(label.to_owned(), marker).await?;
            for (i, chunk) in chunks.into_iter().enumerate() {
                Self::write_one(format!("{label}:chunk:{i}"), chunk).await?;
            }
            Ok(())
        }
    }

    async fn retrieve(&self, label: &str) -> Result<ZeroizingSecret, SecretError> {
        let primary = Self::read_one(label.to_owned()).await?;

        // Check whether this entry is a chunk manifest.
        if let Ok(s) = std::str::from_utf8(&primary) {
            if let Some(rest) = s.strip_prefix(CHUNK_PREFIX) {
                if let Ok(n) = rest.parse::<usize>() {
                    let mut assembled: Vec<u8> = Vec::new();
                    for i in 0..n {
                        let chunk =
                            Self::read_one(format!("{label}:chunk:{i}")).await?;
                        assembled.extend_from_slice(&chunk);
                    }
                    return Ok(ZeroizingSecret::from_vec(assembled));
                }
            }
        }

        Ok(ZeroizingSecret::from_vec(primary))
    }

    async fn delete(&self, label: &str) -> Result<(), SecretError> {
        // Peek at the primary entry to determine whether it is chunked.
        match Self::read_one(label.to_owned()).await {
            Ok(bytes) => {
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    if let Some(rest) = s.strip_prefix(CHUNK_PREFIX) {
                        if let Ok(n) = rest.parse::<usize>() {
                            for i in 0..n {
                                Self::erase_one_best_effort(
                                    format!("{label}:chunk:{i}"),
                                )
                                .await;
                            }
                        }
                    }
                }
            }
            Err(SecretError::NotFound { .. }) => {
                // Propagate NotFound — nothing to delete.
                return Err(SecretError::NotFound {
                    label: label.to_owned(),
                });
            }
            Err(_) => {
                // Unreadable but present — try to delete the primary anyway.
            }
        }
        Self::erase_one(label.to_owned()).await
    }
}
