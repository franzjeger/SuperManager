//! Portable backup export/import for the macOS engine.
//!
//! Produces and consumes the same `PortableBackup` JSON the Linux daemon
//! does, so a backup taken on one platform restores on the other. This
//! half covers everything in the engine's own state and file-backed
//! secret store: profiles, SSH keys and hosts, and the WireGuard keys,
//! SSH material, API tokens and UniFi passwords the store holds.
//!
//! The IKEv2/OpenVPN login credentials that live in the macOS app
//! Keychain are NOT visible here — the Swift app merges them into the
//! exported JSON and splits them back out on import (see the app's
//! backup code). The `secrets` map is just `label -> base64`, so this
//! side neither knows nor cares which store a value ultimately belongs
//! to.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use supermgr_core::backup::PortableBackup;

use crate::protocol::{self, Response};
use crate::server::EngineServer;

impl EngineServer {
    /// Serialise the engine's state + file-store secrets into a
    /// `PortableBackup` JSON string, returned as `{ "backup": "<json>" }`.
    pub(crate) async fn handle_backup_export(&self, id: u64) -> Response {
        let mut backup = PortableBackup::new();
        {
            let state = self.state.lock().await;
            backup.profiles = state.profiles.values().cloned().collect();
            backup.ssh_keys = state.ssh_keys.values().cloned().collect();
            backup.hosts = state.ssh_hosts.values().cloned().collect();
        }
        match self.secrets.read_all().await {
            Ok(secrets) => backup.secrets = secrets,
            Err(e) => {
                return Response::err(id, protocol::INTERNAL_ERROR, format!("read secrets: {e}"))
            }
        }
        backup.exported_at = chrono::Utc::now().to_rfc3339();

        match serde_json::to_string(&backup) {
            Ok(json) => Response::ok(id, serde_json::json!({ "backup": json })),
            Err(e) => Response::err(id, protocol::INTERNAL_ERROR, e.to_string()),
        }
    }

    /// Restore a `PortableBackup` (passed as `{ "backup": "<json>" }`)
    /// into the engine's state + file store.
    ///
    /// Ids are PRESERVED, not regenerated. macOS's `VPNKeychain` derives
    /// its secret labels from `profile.id`, so re-iding a profile on
    /// import would orphan its Keychain-held IKEv2/OpenVPN credentials.
    /// Preserving ids also gives restore-shaped semantics: re-importing
    /// the same backup overwrites rather than duplicating. Secrets are
    /// written first so a profile is never briefly live with a missing
    /// key.
    pub(crate) async fn handle_backup_import(&self, id: u64, params: serde_json::Value) -> Response {
        let Some(data) = params.get("backup").and_then(|v| v.as_str()) else {
            return Response::err(id, protocol::INVALID_PARAMS, "missing backup".to_owned());
        };
        let backup: PortableBackup = match serde_json::from_str(data) {
            Ok(b) => b,
            Err(e) => {
                return Response::err(id, protocol::INVALID_PARAMS, format!("parse backup: {e}"))
            }
        };

        let mut imported_secrets = 0usize;
        for (label, b64) in &backup.secrets {
            match STANDARD.decode(b64) {
                Ok(bytes) => match self.secrets.store(label, &bytes).await {
                    Ok(()) => imported_secrets += 1,
                    Err(e) => tracing::warn!("backup import: store secret {label}: {e}"),
                },
                Err(e) => tracing::warn!("backup import: bad base64 for {label}: {e}"),
            }
        }

        let mut state = self.state.lock().await;
        let (mut profiles, mut ssh_keys, mut hosts) = (0usize, 0usize, 0usize);
        for p in backup.profiles {
            match state.save_profile(&p) {
                Ok(()) => {
                    state.profiles.insert(p.id, p);
                    profiles += 1;
                }
                Err(e) => tracing::warn!("backup import: save profile: {e}"),
            }
        }
        for k in backup.ssh_keys {
            match state.save_ssh_key(&k) {
                Ok(()) => {
                    state.ssh_keys.insert(k.id, k);
                    ssh_keys += 1;
                }
                Err(e) => tracing::warn!("backup import: save ssh key: {e}"),
            }
        }
        for h in backup.hosts {
            match state.save_ssh_host(&h) {
                Ok(()) => {
                    state.ssh_hosts.insert(h.id, h);
                    hosts += 1;
                }
                Err(e) => tracing::warn!("backup import: save ssh host: {e}"),
            }
        }

        Response::ok(
            id,
            serde_json::json!({
                "profiles": profiles,
                "ssh_keys": ssh_keys,
                "hosts": hosts,
                "secrets": imported_secrets,
            }),
        )
    }
}
