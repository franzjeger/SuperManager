//! SSH key import — scan a directory for existing private keys.
//!
//! Iterates files in a directory (typically `~/.ssh`), attempts to parse each
//! as an OpenSSH private key, and returns metadata for importable candidates.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use supermgr_core::ssh::key::SshKeyType;

/// A candidate key found during a directory scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportCandidate {
    /// Filesystem path to the private key file.
    pub path: PathBuf,
    /// Human-readable display name derived from the filename.
    pub name: String,
    /// Detected cryptographic algorithm.
    pub key_type: SshKeyType,
    /// OpenSSH-format public key string.
    pub public_key: String,
    /// PEM-encoded private key (OpenSSH format, unencrypted).
    pub private_key_pem: String,
    /// SHA-256 fingerprint in `SHA256:<base64>` format.
    pub fingerprint: String,
    /// Whether the key is passphrase-protected (and thus not directly importable).
    pub has_passphrase: bool,
}

/// File names that are never private keys.
const SKIP_NAMES: &[&str] = &[
    "authorized_keys",
    "known_hosts",
    "known_hosts.old",
    "config",
    "environment",
    ".gitignore",
    "rc",
];

/// File extensions that are never private keys.
const SKIP_EXTENSIONS: &[&str] = &[".pub", ".txt", ".bak", ".old", ".orig", ".log"];

/// Scan a directory for SSH private keys.
///
/// Returns a list of [`ImportCandidate`] entries, sorted by filename.
/// Encrypted (passphrase-protected) keys are included with
/// `has_passphrase = true` if a corresponding `.pub` file provides
/// enough information to populate the public key and fingerprint fields.
/// Keys that cannot be parsed at all are silently skipped.
pub fn scan_ssh_directory(directory: &Path) -> Vec<ImportCandidate> {
    let entries = match std::fs::read_dir(directory) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };

    let skip_names: HashSet<&str> = SKIP_NAMES.iter().copied().collect();

    let mut candidates: Vec<ImportCandidate> = Vec::new();

    // Collect and sort entries by name for deterministic output.
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    paths.sort();

    for path in paths {
        if !path.is_file() {
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };

        // Skip well-known non-key files.
        if skip_names.contains(file_name.as_str()) {
            continue;
        }
        if file_name.starts_with('.') {
            continue;
        }
        if SKIP_EXTENSIONS
            .iter()
            .any(|ext| file_name.to_lowercase().ends_with(ext))
        {
            continue;
        }

        // Read file contents.
        let raw = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Quick sniff: must look like a PEM private key.
        if !raw.windows(11).any(|w| w == b"PRIVATE KEY") {
            continue;
        }

        // Try parsing as an unencrypted OpenSSH private key.
        match PrivateKey::from_openssh(&raw) {
            Ok(priv_key) => {
                if let Some(candidate) = build_candidate(&path, &file_name, &priv_key, false) {
                    candidates.push(candidate);
                }
            }
            Err(_) => {
                // Parsing failed — likely encrypted or unsupported format.
                // Try to extract info from the companion .pub file.
                if let Some(candidate) = build_from_pub_file(&path, &file_name) {
                    candidates.push(candidate);
                }
            }
        }
    }

    candidates
}

/// Build an [`ImportCandidate`] from a successfully parsed private key.
fn build_candidate(
    path: &Path,
    file_name: &str,
    priv_key: &PrivateKey,
    has_passphrase: bool,
) -> Option<ImportCandidate> {
    let public_key = priv_key.public_key();

    // Detect key type.
    let key_type = match public_key.algorithm() {
        ssh_key::Algorithm::Ed25519 => SshKeyType::Ed25519,
        ssh_key::Algorithm::Rsa { .. } => {
            // We cannot easily distinguish 2048 vs 4096 from the public key
            // alone, so default to Rsa4096 as the more common modern choice.
            // The actual bit size is encoded in the modulus length.
            SshKeyType::Rsa4096
        }
        _ => return None, // ECDSA, DSA, etc. — not supported by our model.
    };

    // Prefer the .pub file if it exists (it usually carries a useful comment).
    let pub_str = read_pub_file(path).unwrap_or_else(|| {
        public_key
            .to_openssh()
            .unwrap_or_default()
    });

    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();

    let private_key_pem = if has_passphrase {
        String::new()
    } else {
        priv_key
            .to_openssh(LineEnding::LF)
            .map(|z| z.to_string())
            .unwrap_or_default()
    };

    let display_name = derive_display_name(file_name);

    Some(ImportCandidate {
        path: path.to_owned(),
        name: display_name,
        key_type,
        public_key: pub_str,
        private_key_pem,
        fingerprint,
        has_passphrase,
    })
}

/// Attempt to build an [`ImportCandidate`] from just the `.pub` companion file
/// when the private key itself is encrypted or otherwise unparseable.
fn build_from_pub_file(private_key_path: &Path, file_name: &str) -> Option<ImportCandidate> {
    let pub_str = read_pub_file(private_key_path)?;

    // Parse the public key to extract type and fingerprint.
    let public_key = ssh_key::PublicKey::from_openssh(&pub_str).ok()?;

    let key_type = match public_key.algorithm() {
        ssh_key::Algorithm::Ed25519 => SshKeyType::Ed25519,
        ssh_key::Algorithm::Rsa { .. } => SshKeyType::Rsa4096,
        _ => return None,
    };

    let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
    let display_name = derive_display_name(file_name);

    Some(ImportCandidate {
        path: private_key_path.to_owned(),
        name: display_name,
        key_type,
        public_key: pub_str,
        private_key_pem: String::new(),
        fingerprint,
        has_passphrase: true,
    })
}

/// Read the companion `.pub` file for a private key path.
///
/// Tries `<path>.pub` first, then `<path_without_ext>.pub`.
fn read_pub_file(private_key_path: &Path) -> Option<String> {
    // Try appending .pub to the full path.
    let pub_path = private_key_path.with_extension(
        private_key_path
            .extension()
            .map(|ext| {
                let mut s = ext.to_os_string();
                s.push(".pub");
                s
            })
            .unwrap_or_else(|| "pub".into()),
    );

    // Simpler: just append ".pub" to the full filename.
    let pub_path_appended = PathBuf::from(format!("{}.pub", private_key_path.display()));

    for p in [&pub_path_appended, &pub_path] {
        if let Ok(text) = std::fs::read_to_string(p) {
            let trimmed = text.trim().to_owned();
            // Validate: must have at least "type base64".
            if trimmed.split_whitespace().count() >= 2 {
                return Some(trimmed);
            }
        }
    }

    None
}

/// Derive a human-readable display name from a private key filename.
///
/// `id_ed25519` -> `Ed25519`, `id_rsa_work` -> `Rsa Work`.
fn derive_display_name(file_name: &str) -> String {
    let stem = Path::new(file_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name);

    let display = stem
        .strip_prefix("id_")
        .unwrap_or(stem)
        .replace('_', " ");

    if display.is_empty() {
        file_name.to_owned()
    } else {
        // Title-case each word.
        display
            .split_whitespace()
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    Some(c) => {
                        let upper: String = c.to_uppercase().collect();
                        format!("{upper}{}", chars.as_str())
                    }
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}
