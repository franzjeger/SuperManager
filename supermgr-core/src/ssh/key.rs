//! SSH key model and summary types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::vpn::profile::SecretRef;

/// The cryptographic algorithm used for an SSH key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum SshKeyType {
    /// Ed25519 — modern, fast, and recommended.
    Ed25519,
    /// RSA with a 2048-bit modulus.
    Rsa2048,
    /// RSA with a 4096-bit modulus.
    Rsa4096,
}

/// A managed SSH key pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    /// Unique identifier.
    pub id: Uuid,

    /// Human-readable name for this key.
    pub name: String,

    /// Optional description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Cryptographic algorithm.
    pub key_type: SshKeyType,

    /// Public key in OpenSSH authorized-keys format.
    pub public_key: String,

    /// Reference to the private key stored in the secret service.
    pub private_key_ref: SecretRef,

    /// Key fingerprint in `SHA256:<base64>` format.
    pub fingerprint: String,

    /// User-defined tags for grouping and filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// IDs of hosts this key has been deployed to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployed_to: Vec<Uuid>,

    /// When this key was created.
    pub created_at: DateTime<Utc>,

    /// When this key was last modified.
    pub updated_at: DateTime<Utc>,
}

/// Lightweight summary of an [`SshKey`] for list views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeySummary {
    /// Unique identifier.
    pub id: Uuid,

    /// Human-readable name.
    pub name: String,

    /// Cryptographic algorithm.
    pub key_type: SshKeyType,

    /// Key fingerprint in `SHA256:<base64>` format.
    pub fingerprint: String,

    /// User-defined tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Number of hosts this key is deployed to.
    pub deployed_count: usize,

    /// When this key was created.
    pub created_at: DateTime<Utc>,
}

impl From<&SshKey> for SshKeySummary {
    fn from(key: &SshKey) -> Self {
        Self {
            id: key.id,
            name: key.name.clone(),
            key_type: key.key_type,
            fingerprint: key.fingerprint.clone(),
            tags: key.tags.clone(),
            deployed_count: key.deployed_to.len(),
            created_at: key.created_at,
        }
    }
}
