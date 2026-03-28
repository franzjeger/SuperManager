//! Keyring integration — secure storage for secrets.
//!
//! Provides [`SecretStore`], a thin async trait over the system
//! [Secret Service](https://specifications.freedesktop.org/secret-service/)
//! D-Bus protocol, and [`LibsecretStore`], its production implementation
//! backed by the `secret-service` crate (GNOME Keyring, KWallet, …).
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
//!
//! # Transport security
//!
//! [`LibsecretStore`] opens every D-Bus session with [`EncryptionType::Dh`] so
//! secret bytes are Diffie-Hellman-encrypted in transit over the session socket
//! and never transmitted in the clear.
//!
//! # Item identification
//!
//! Every keyring item written by supermgr carries the attribute
//! `supermgr_label = <label>` (see [`ATTR_KEY`]).  This allows exact lookups via
//! `search_items` even if the item's human-readable display name is changed by
//! an external tool.

use std::collections::HashMap;

use async_trait::async_trait;
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
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> Result<(), supermgr_core::SecretError> {
/// use supermgr_core::keyring::{LibsecretStore, SecretStore};
///
/// let store = LibsecretStore::new();
/// let secret = store.retrieve("supermgr/wg/abc/privkey").await?;
/// // Use the key bytes via Deref to [u8]:
/// println!("{} bytes", secret.len());
/// // Buffer is zeroed here when `secret` is dropped.
/// # Ok(())
/// # }
/// ```
pub struct ZeroizingSecret(Vec<u8>);

impl ZeroizingSecret {
    /// Wrap a raw byte vector, transferring ownership.
    ///
    /// The buffer will be zeroed when the returned `ZeroizingSecret` is dropped.
    #[must_use]
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
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
    ///
    /// The label is an opaque string used as a lookup key.  By convention
    /// supermgr uses slash-separated paths such as `"supermgr/wg/<uuid>/privkey"`
    /// or `"supermgr/ssh/<uuid>/privkey"`.
    ///
    /// # Errors
    ///
    /// - [`SecretError::ServiceUnavailable`] — the secret service is unreachable
    ///   or the default collection could not be unlocked.
    /// - [`SecretError::StoreFailed`] — the service rejected the write.
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError>;

    /// Retrieve the bytes stored under `label`.
    ///
    /// Returns the bytes wrapped in a [`ZeroizingSecret`] that zeroes its
    /// buffer on drop.
    ///
    /// # Errors
    ///
    /// - [`SecretError::NotFound`] — no item with this label exists in the
    ///   default collection.
    /// - [`SecretError::ServiceUnavailable`] — the service is unreachable or
    ///   the collection could not be unlocked.
    async fn retrieve(&self, label: &str) -> Result<ZeroizingSecret, SecretError>;
}

// ---------------------------------------------------------------------------
// LibsecretStore
// ---------------------------------------------------------------------------

/// D-Bus attribute key that identifies supermgr items in the keyring.
///
/// Every item stored by supermgr has the attribute `"supermgr_label" = <label>`
/// so that [`SecretStore::retrieve`] can find it with a targeted `search_items`
/// call without scanning all keyring items.
const ATTR_KEY: &str = "supermgr_label";

/// Production [`SecretStore`] backed by the system Secret Service D-Bus API.
///
/// Works with any compliant service: GNOME Keyring, KWallet (via
/// `kwallet-secrets`), or any daemon that implements
/// `org.freedesktop.secrets`.
///
/// DH-encrypted sessions (`EncryptionType::Dh`) are used for every operation
/// so secret bytes are never transmitted in the clear over the session bus,
/// even if the bus itself is unencrypted.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> Result<(), supermgr_core::SecretError> {
/// use supermgr_core::keyring::{LibsecretStore, SecretStore};
///
/// let store = LibsecretStore::new();
/// store.store("supermgr/wg/abc123/privkey", b"base64keyhere==").await?;
/// let secret = store.retrieve("supermgr/wg/abc123/privkey").await?;
/// // secret is zeroed automatically when dropped
/// # Ok(())
/// # }
/// ```
pub struct LibsecretStore;

impl LibsecretStore {
    /// Create a new `LibsecretStore`.
    ///
    /// No I/O is performed at construction time; a D-Bus connection is opened
    /// on the first call to [`store`](SecretStore::store) or
    /// [`retrieve`](SecretStore::retrieve).
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for LibsecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretStore for LibsecretStore {
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError> {
        // A new SecretService connection is created per operation.  Collection
        // and Item objects borrow from it via the 'ss lifetime, so all three
        // must live in the same stack frame.
        let ss = SecretService::connect(EncryptionType::Dh)
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        let collection = ss
            .get_default_collection()
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;

        // The default collection may be locked after a screen-lock event.
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
                label,                      // human-readable display name
                attrs,                      // searchable attributes
                secret,                     // the secret bytes
                true,                       // replace = overwrite any existing item
                "application/octet-stream", // content type
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

        // Take the first match; duplicate labels should not exist in practice
        // because store() always sets replace = true.
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
}
