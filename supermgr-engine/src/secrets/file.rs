//! File-based secrets store.
//!
//! Credentials are stored as a JSON map of `label -> base64(bytes)` in a
//! permission-restricted file. Used on both Linux and macOS as a simple
//! alternative to system keyrings.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};

use supermgr_core::error::SecretError;
use supermgr_core::keyring::{SecretStore, ZeroizingSecret};

/// File-based [`SecretStore`] implementation.
pub struct FileSecretStore {
    path: PathBuf,
}

impl FileSecretStore {
    /// Create a new file-based store at the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Create with the default path for the current platform.
    pub fn default_path() -> Self {
        let dir = super::default_data_dir();
        Self::new(dir.join("secrets.json"))
    }

    async fn read_map(&self) -> Result<HashMap<String, String>> {
        let exists = tokio::fs::try_exists(&self.path)
            .await
            .with_context(|| format!("stat secrets file {}", self.path.display()))?;
        if !exists {
            return Ok(HashMap::new());
        }
        let text = tokio::fs::read_to_string(&self.path)
            .await
            .with_context(|| format!("read secrets file {}", self.path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("parse secrets file {}", self.path.display()))
    }

    async fn write_map(&self, map: &HashMap<String, String>) -> Result<()> {
        let dir = self
            .path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("create secrets directory {}", dir.display()))?;

        let text = serde_json::to_string_pretty(map).context("serialise secrets map")?;
        let tmp = dir.join(format!("secrets.{}.tmp", uuid::Uuid::new_v4()));

        // Create the temp file with O_EXCL and 0600 *at creation*, in the
        // same directory as the target (so the rename is atomic on the same
        // filesystem). O_EXCL refuses to follow a pre-existing symlink at
        // the temp path — closing the symlink-attack surface a predictable
        // `secrets.tmp` name had — and the file never exists at 0644.
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create_new(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(&tmp)
            .with_context(|| format!("create secrets tmp file {}", tmp.display()))?;
        let mut file = std::io::BufWriter::new(file);
        file.write_all(text.as_bytes())
            .with_context(|| format!("write secrets tmp file {}", tmp.display()))?;
        file.flush()
            .with_context(|| format!("flush secrets tmp file {}", tmp.display()))?;
        drop(file);

        std::fs::rename(&tmp, &self.path).with_context(|| {
            format!(
                "rename {} -> {}",
                tmp.display(),
                self.path.display()
            )
        })?;

        Ok(())
    }
}

#[async_trait]
impl SecretStore for FileSecretStore {
    async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError> {
        let mut map = self
            .read_map()
            .await
            .map_err(|e| SecretError::StoreFailed {
                label: label.to_owned(),
                reason: e.to_string(),
            })?;
        map.insert(label.to_owned(), STANDARD.encode(secret));
        self.write_map(&map)
            .await
            .map_err(|e| SecretError::StoreFailed {
                label: label.to_owned(),
                reason: e.to_string(),
            })
    }

    async fn retrieve(&self, label: &str) -> Result<ZeroizingSecret, SecretError> {
        let map = self
            .read_map()
            .await
            .map_err(|e| SecretError::ServiceUnavailable(e.to_string()))?;
        let encoded = map.get(label).ok_or_else(|| SecretError::NotFound {
            label: label.to_owned(),
        })?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|e| SecretError::ServiceUnavailable(format!("base64 decode: {e}")))?;
        Ok(ZeroizingSecret::from_vec(bytes))
    }

    async fn delete(&self, label: &str) -> Result<(), SecretError> {
        let mut map = self
            .read_map()
            .await
            .map_err(|e| SecretError::StoreFailed {
                label: label.to_owned(),
                reason: e.to_string(),
            })?;
        if map.remove(label).is_some() {
            self.write_map(&map)
                .await
                .map_err(|e| SecretError::StoreFailed {
                    label: label.to_owned(),
                    reason: e.to_string(),
                })?;
        }
        Ok(())
    }
}
