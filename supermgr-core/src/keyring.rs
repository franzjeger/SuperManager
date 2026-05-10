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
