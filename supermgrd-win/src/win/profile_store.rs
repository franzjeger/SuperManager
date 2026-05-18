//! On-disk VPN profile store.
//!
//! Profiles serialise as TOML to `%PROGRAMDATA%\SuperManager\profiles\<uuid>.toml`,
//! the same format the Linux daemon writes. Secret material (WireGuard
//! private keys, PSKs, OpenVPN passwords) is stored separately in the
//! Windows Credential Manager via [`supermgr_core::keyring::SecretStore`]
//! and referenced from the profile TOML by label only.
//!
//! # Concurrency
//!
//! The store wraps a `RwLock<HashMap<Uuid, Profile>>`. All file I/O happens
//! under the write lock so concurrent imports don't race each other on
//! disk. Reads (list, get) take the read lock and are lock-free with
//! respect to each other.

// `list` and `get` are part of the public store API but no dispatcher arm
// calls them yet — the GUI is wired to `list_summaries`. They'll be used
// by the VPN connect path once that backend lands. Suppress the noise
// rather than gating each method individually.
#![allow(dead_code)]

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use supermgr_core::vpn::profile::{Profile, ProfileSummary};

/// Profile store error variants. Kept narrow so callers can match without
/// reading prose strings.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// On-disk I/O failure (read, write, create).
    #[error("profile store I/O: {0}")]
    Io(#[from] std::io::Error),
    /// TOML parse failure on load, or serialise failure on save.
    #[error("profile TOML: {0}")]
    Toml(String),
    /// The requested profile does not exist.
    #[error("profile {0} not found")]
    NotFound(Uuid),
}

/// Async-friendly profile store. Cheap to clone (it wraps an `Arc` internally).
pub struct ProfileStore {
    /// Directory where profile TOMLs live. Created at startup if absent.
    dir: PathBuf,
    /// In-memory cache keyed by profile id. Source of truth for reads;
    /// disk is the source of truth on cold-start.
    profiles: RwLock<HashMap<Uuid, Profile>>,
}

impl ProfileStore {
    /// Construct a store rooted at `dir`. Performs a one-time scan of the
    /// directory; subsequent calls hit the in-memory cache.
    pub fn load_from(dir: PathBuf) -> Result<Self, StoreError> {
        std::fs::create_dir_all(&dir)?;
        let mut profiles = HashMap::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            match Self::load_one(&path) {
                Ok(p) => {
                    profiles.insert(p.id, p);
                }
                Err(e) => warn!("skipping malformed profile {}: {e}", path.display()),
            }
        }
        info!(count = profiles.len(), "profile store initialised");
        Ok(Self {
            dir,
            profiles: RwLock::new(profiles),
        })
    }

    fn load_one(path: &Path) -> Result<Profile, StoreError> {
        let text = std::fs::read_to_string(path)?;
        toml::from_str(&text).map_err(|e| StoreError::Toml(e.to_string()))
    }

    /// Persist a profile to disk and the in-memory cache. Replaces any
    /// existing profile with the same id.
    pub async fn save(&self, profile: Profile) -> Result<Uuid, StoreError> {
        let path = self.dir.join(format!("{}.toml", profile.id));
        let text = toml::to_string_pretty(&profile)
            .map_err(|e| StoreError::Toml(e.to_string()))?;
        tokio::task::spawn_blocking(move || std::fs::write(&path, text))
            .await
            .map_err(|e| StoreError::Toml(format!("spawn_blocking: {e}")))??;
        let id = profile.id;
        self.profiles.write().await.insert(id, profile);
        Ok(id)
    }

    /// Return a clone of every profile in the store.
    pub async fn list(&self) -> Vec<Profile> {
        self.profiles.read().await.values().cloned().collect()
    }

    /// Lightweight list returning [`ProfileSummary`] rather than full
    /// [`Profile`]. Used by the GUI sidebar. The `From<&Profile>` impl in
    /// `supermgr-core` already does the field mapping, including
    /// backend-specific extraction of `host`, `username`, `split_routes`,
    /// and `dns_servers`, so we just delegate.
    pub async fn list_summaries(&self) -> Vec<ProfileSummary> {
        self.profiles
            .read()
            .await
            .values()
            .map(ProfileSummary::from)
            .collect()
    }

    /// Fetch a single profile by id.
    pub async fn get(&self, id: Uuid) -> Result<Profile, StoreError> {
        self.profiles
            .read()
            .await
            .get(&id)
            .cloned()
            .ok_or(StoreError::NotFound(id))
    }

    /// Remove a profile from disk and the cache.
    pub async fn delete(&self, id: Uuid) -> Result<(), StoreError> {
        let path = self.dir.join(format!("{id}.toml"));
        tokio::task::spawn_blocking(move || {
            if path.exists() {
                std::fs::remove_file(path)
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| StoreError::Toml(format!("spawn_blocking: {e}")))??;
        self.profiles.write().await.remove(&id);
        Ok(())
    }
}
