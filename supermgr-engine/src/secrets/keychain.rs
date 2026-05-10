//! macOS Data-Protection-Keychain–backed [`SecretStore`].
//!
//! ## Why
//!
//! Up until now, every SSH password and every generated SSH private key
//! was stored as base64 in `~/Library/Application Support/SuperManager/secrets.json`
//! (mode 0o600). That's better than plaintext in /tmp, but it's not
//! what users expect from a Mac app: anyone with read access to the
//! user's home directory walks away with every server credential.
//!
//! This implementation moves them into macOS's *Data Protection
//! Keychain*. Items are stored with file-system encryption, scoped to
//! the binary's keychain access group (the implicit
//! `<TEAM_ID>.com.sybr.supermanager` group attached via the
//! `keychain-access-groups` entitlement) and — critically — accessed
//! *without* the cdhash pinning that the legacy file-based keychain
//! enforces. That means a freshly rebuilt binary can read its own
//! secrets without triggering the "Type your login password to allow
//! access" prompt every time the binary's hash changes.
//!
//! Mechanism: `kSecUseDataProtectionKeychain: true` on every SecItem
//! call.
//!
//! ## Entitlement requirement
//!
//! Per Apple DTS: DPK calls return `errSecMissingEntitlement` (-34018)
//! unless the binary is signed with an App ID and carries the
//! `keychain-access-groups` entitlement. Two ways to satisfy that:
//!
//! - **Paid Apple Developer Program** — full Developer ID. The
//!   long-term path; we use it once enrollment finishes verifying.
//! - **Free Apple ID via Xcode "Personal Team"** — Xcode synthesises
//!   an App ID and a provisioning profile when the target carries a
//!   capability that triggers it (Maps is the canonical one). That
//!   profile authorises `keychain-access-groups` for our bundle id.
//!
//! Either way, this Rust crate signs to the same App ID + access
//! group as the GUI app; both processes see the same items.
//!
//! We hand-roll the SecItemAdd/Update/Delete/CopyMatching calls
//! because the higher-level `set_generic_password` / `get_generic_password`
//! functions in `security-framework` do *not* expose the data-protection
//! keychain flag. The crate's `PasswordOptions` struct does expose its
//! query vector publicly, so we build on top of that to keep type/version
//! alignment with the rest of the crate.
//!
//! ## Migration
//!
//! `migrate_from_file` reads the existing `secrets.json`, writes every
//! entry into the data-protection keychain, then renames the file to
//! `secrets.json.migrated`. Idempotent. Failures are logged and do not
//! block the rest of the migration. The original file is renamed (not
//! deleted) so a recovery is always possible.

use anyhow::Context;
use async_trait::async_trait;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::CFTypeRef;
use security_framework::passwords_options::PasswordOptions;
use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound};
use security_framework_sys::item::{kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};

use supermgr_core::error::SecretError;
use supermgr_core::keyring::{SecretStore, ZeroizingSecret};

/// Service identifier used for every SuperManager keychain item.
/// Keychain `service` + `account` together uniquely identify an item;
/// we hold the service constant and let the SecretStore label become
/// the account name.
const KEYCHAIN_SERVICE: &str = "com.sybr.supermanager";

pub struct KeychainSecretStore;

impl KeychainSecretStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KeychainSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretStore for KeychainSecretStore {
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError> {
        let label_owned = label.to_owned();
        let secret_owned = secret.to_owned();
        tokio::task::spawn_blocking(move || dp_store(&label_owned, &secret_owned))
            .await
            .map_err(|e| SecretError::ServiceUnavailable(format!("join error: {e}")))?
    }

    async fn retrieve(&self, label: &str) -> Result<ZeroizingSecret, SecretError> {
        let label_owned = label.to_owned();
        let bytes = tokio::task::spawn_blocking(move || dp_retrieve(&label_owned))
            .await
            .map_err(|e| SecretError::ServiceUnavailable(format!("join error: {e}")))??;
        Ok(ZeroizingSecret::from_vec(bytes))
    }

    async fn delete(&self, label: &str) -> Result<(), SecretError> {
        let label_owned = label.to_owned();
        tokio::task::spawn_blocking(move || dp_delete(&label_owned))
            .await
            .map_err(|e| SecretError::ServiceUnavailable(format!("join error: {e}")))?
    }
}

/// Build a query vector for (service, account) pinned to the
/// data-protection keychain. Used by every operation below.
fn dp_query(label: &str) -> Vec<(CFString, CFType)> {
    let mut options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, label);
    options.query.push((
        unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) },
        CFBoolean::from(true).into_CFType(),
    ));
    options.query
}

/// SecItemAdd then, if the item already exists, fall back to update.
fn dp_store(label: &str, secret: &[u8]) -> Result<(), SecretError> {
    let mut query = dp_query(label);
    let value = CFData::from_buffer(secret);
    query.push((
        unsafe { CFString::wrap_under_get_rule(kSecValueData) },
        value.into_CFType(),
    ));
    let dict = CFDictionary::from_CFType_pairs(&query);

    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status == 0 {
        return Ok(());
    }
    if status == errSecDuplicateItem {
        // Item exists — fall back to SecItemUpdate.
        return dp_update(label, secret);
    }
    Err(SecretError::ServiceUnavailable(format!(
        "SecItemAdd {label}: status={status}"
    )))
}

/// SecItemUpdate the value of an existing entry.
fn dp_update(label: &str, secret: &[u8]) -> Result<(), SecretError> {
    let query_dict = CFDictionary::from_CFType_pairs(&dp_query(label));
    let value = CFData::from_buffer(secret);
    let attrs_pairs = vec![(
        unsafe { CFString::wrap_under_get_rule(kSecValueData) },
        value.into_CFType(),
    )];
    let attrs = CFDictionary::from_CFType_pairs(&attrs_pairs);

    let status = unsafe {
        SecItemUpdate(
            query_dict.as_concrete_TypeRef(),
            attrs.as_concrete_TypeRef(),
        )
    };
    if status == 0 {
        Ok(())
    } else if status == errSecItemNotFound {
        Err(SecretError::NotFound { label: label.to_owned() })
    } else {
        Err(SecretError::ServiceUnavailable(format!(
            "SecItemUpdate {label}: status={status}"
        )))
    }
}

/// SecItemCopyMatching, ask for the data, return the bytes.
fn dp_retrieve(label: &str) -> Result<Vec<u8>, SecretError> {
    let mut query = dp_query(label);
    query.push((
        unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
        CFBoolean::from(true).into_CFType(),
    ));
    let dict = CFDictionary::from_CFType_pairs(&query);
    let mut result: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result) };
    if status == errSecItemNotFound {
        return Err(SecretError::NotFound { label: label.to_owned() });
    }
    if status != 0 {
        return Err(SecretError::ServiceUnavailable(format!(
            "SecItemCopyMatching {label}: status={status}"
        )));
    }
    if result.is_null() {
        return Err(SecretError::NotFound { label: label.to_owned() });
    }
    // Wrap the returned CFData and copy its bytes out.
    let cf_data = unsafe { CFData::wrap_under_create_rule(result.cast()) };
    Ok(cf_data.bytes().to_vec())
}

/// SecItemDelete on the (service, account, data-protection) tuple.
fn dp_delete(label: &str) -> Result<(), SecretError> {
    let dict = CFDictionary::from_CFType_pairs(&dp_query(label));
    let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };
    if status == 0 || status == errSecItemNotFound {
        Ok(())
    } else {
        Err(SecretError::ServiceUnavailable(format!(
            "SecItemDelete {label}: status={status}"
        )))
    }
}

/// One-shot migration: copy every entry from `secrets.json` (the legacy
/// file-backed store) into the data-protection keychain, then rename
/// the file to `secrets.json.migrated` so we don't redo the work on
/// the next boot. Idempotent. If a single entry fails we log it and
/// keep going so a partial migration doesn't hold up the rest. The
/// original file is renamed (not deleted) so a recovery is always
/// possible.
pub async fn migrate_from_file(secrets_json_path: &std::path::Path) -> anyhow::Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    if !tokio::fs::try_exists(secrets_json_path).await.unwrap_or(false) {
        return Ok(());
    }

    let text = tokio::fs::read_to_string(secrets_json_path)
        .await
        .with_context(|| format!("read {}", secrets_json_path.display()))?;

    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&text).with_context(|| {
            format!("parse legacy secrets file {}", secrets_json_path.display())
        })?;

    let store = KeychainSecretStore::new();
    let mut migrated = 0usize;
    let mut failed = 0usize;
    for (label, encoded) in map {
        let bytes = match STANDARD.decode(&encoded) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(label = %label, error = %e, "skipping malformed base64");
                failed += 1;
                continue;
            }
        };
        match store.store(&label, &bytes).await {
            Ok(()) => migrated += 1,
            Err(e) => {
                tracing::warn!(label = %label, error = %e, "data-protection keychain store failed during migration");
                failed += 1;
            }
        }
    }
    tracing::info!(
        migrated,
        failed,
        path = %secrets_json_path.display(),
        "completed legacy secrets.json migration"
    );

    let dest = secrets_json_path.with_extension("json.migrated");
    if let Err(e) = tokio::fs::rename(secrets_json_path, &dest).await {
        tracing::warn!(error = %e, "could not rename legacy secrets.json after migration");
    }
    Ok(())
}
