//! SSH key pair generation and fingerprint computation.
//!
//! Uses the `ssh-key` crate (v0.6) for Ed25519 and RSA key generation.
//! RSA keys are generated via `ssh_key::private::RsaKeypair::random` which
//! allows specifying the bit size (2048 or 4096).

use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use supermgr_core::error::SshError;
use supermgr_core::ssh::key::SshKeyType;

/// Generated key material returned by [`generate_key`].
pub struct GeneratedKey {
    /// OpenSSH-format public key (e.g. `ssh-ed25519 AAAA... comment`).
    pub public_key: String,
    /// PEM-encoded private key (OpenSSH format, unencrypted).
    pub private_key_pem: String,
    /// SHA-256 fingerprint in `SHA256:<base64>` format.
    pub fingerprint: String,
}

/// Generate a new SSH key pair of the given type.
///
/// The `comment` is appended to the public key line and embedded in the
/// private key's metadata.
pub fn generate_key(key_type: SshKeyType, comment: &str) -> Result<GeneratedKey, SshError> {
    let mut rng = rand::rngs::OsRng;

    let private_key = match key_type {
        SshKeyType::Ed25519 => {
            PrivateKey::random(&mut rng, Algorithm::Ed25519)
                .map_err(|e| SshError::KeyGenFailed(format!("Ed25519: {e}")))?
        }
        SshKeyType::Rsa2048 => {
            let keypair = RsaKeypair::random(&mut rng, 2048)
                .map_err(|e| SshError::KeyGenFailed(format!("RSA-2048: {e}")))?;
            PrivateKey::new(KeypairData::from(keypair), comment)
                .map_err(|e| SshError::KeyGenFailed(format!("RSA-2048 wrapping: {e}")))?
        }
        SshKeyType::Rsa4096 => {
            let keypair = RsaKeypair::random(&mut rng, 4096)
                .map_err(|e| SshError::KeyGenFailed(format!("RSA-4096: {e}")))?;
            PrivateKey::new(KeypairData::from(keypair), comment)
                .map_err(|e| SshError::KeyGenFailed(format!("RSA-4096 wrapping: {e}")))?
        }
    };

    // For Ed25519 we need to set the comment separately since
    // `PrivateKey::random` doesn't accept one.
    let private_key = if matches!(key_type, SshKeyType::Ed25519) && !comment.is_empty() {
        let mut pk = private_key;
        pk.set_comment(comment);
        pk
    } else {
        private_key
    };

    let public_key = private_key.public_key();
    let fingerprint = public_key.fingerprint(HashAlg::Sha256);

    let public_key_str = public_key
        .to_openssh()
        .map_err(|e| SshError::KeyGenFailed(format!("public key serialisation: {e}")))?;

    let private_key_pem = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| SshError::KeyGenFailed(format!("private key serialisation: {e}")))?
        .to_string();

    Ok(GeneratedKey {
        public_key: public_key_str,
        private_key_pem,
        fingerprint: fingerprint.to_string(),
    })
}

/// Compute the SHA-256 fingerprint from an OpenSSH-format public key string.
///
/// Returns the fingerprint in `SHA256:<base64>` format.
pub fn compute_fingerprint(public_key_openssh: &str) -> Result<String, SshError> {
    let key = ssh_key::PublicKey::from_openssh(public_key_openssh)
        .map_err(|e| SshError::KeyGenFailed(format!("parse public key: {e}")))?;
    Ok(key.fingerprint(HashAlg::Sha256).to_string())
}
