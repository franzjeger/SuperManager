//! Portable backup export/import for the macOS engine.
//!
//! Produces and consumes the same `PortableBackup` JSON the Linux daemon
//! does, so a backup taken on one platform restores on the other. This
//! half covers everything in the engine's own state and file-backed
//! secret store: profiles, SSH keys and hosts, and the `WireGuard` keys,
//! SSH material, API tokens and `UniFi` passwords the store holds.
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
        match crate::customer::list_all() {
            Ok(customers) => backup.customers = customers,
            Err(e) => tracing::warn!("backup export: read customers: {e:#}"),
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
    pub(crate) async fn handle_backup_import(
        &self,
        id: u64,
        params: serde_json::Value,
    ) -> Response {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BackupImportParams {
            backup: String,
        }

        let p: BackupImportParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return Response::err(id, protocol::INVALID_PARAMS, format!("bad params: {e}"))
            }
        };
        let backup: PortableBackup = match serde_json::from_str(&p.backup) {
            Ok(b) => b,
            Err(e) => {
                return Response::err(id, protocol::INVALID_PARAMS, format!("parse backup: {e}"))
            }
        };
        if let Err(msg) = backup.validate_version() {
            return Response::err(id, protocol::INVALID_PARAMS, msg);
        }

        // Decode all base64 secret values up front before mutating any state (`P2-24`).
        let mut decoded_secrets: Vec<(String, Vec<u8>)> = Vec::with_capacity(backup.secrets.len());
        for (label, b64) in &backup.secrets {
            match STANDARD.decode(b64) {
                Ok(bytes) => decoded_secrets.push((label.clone(), bytes)),
                Err(e) => {
                    return Response::err(
                        id,
                        protocol::INVALID_PARAMS,
                        format!("bad base64 for secret '{label}': {e}"),
                    )
                }
            }
        }

        let mut imported_secrets = 0usize;
        for (label, bytes) in &decoded_secrets {
            if let Err(e) = self.secrets.store(label, bytes).await {
                return Response::err(
                    id,
                    protocol::INTERNAL_ERROR,
                    format!("store secret '{label}': {e}"),
                );
            }
            imported_secrets += 1;
        }

        let mut state = self.state.lock().await;
        let (mut profiles, mut ssh_keys, mut hosts, mut customers) =
            (0usize, 0usize, 0usize, 0usize);
        for p in backup.profiles {
            if let Err(e) = state.save_profile(&p) {
                return Response::err(
                    id,
                    protocol::INTERNAL_ERROR,
                    format!("save profile '{}': {e}", p.name),
                );
            }
            state.profiles.insert(p.id, p);
            profiles += 1;
        }
        for k in backup.ssh_keys {
            if let Err(e) = state.save_ssh_key(&k) {
                return Response::err(
                    id,
                    protocol::INTERNAL_ERROR,
                    format!("save ssh key '{}': {e}", k.name),
                );
            }
            state.ssh_keys.insert(k.id, k);
            ssh_keys += 1;
        }
        for h in backup.hosts {
            if let Err(e) = state.save_ssh_host(&h) {
                return Response::err(
                    id,
                    protocol::INTERNAL_ERROR,
                    format!("save ssh host '{}': {e}", h.label),
                );
            }
            state.ssh_hosts.insert(h.id, h);
            hosts += 1;
        }
        for customer in backup.customers {
            if let Err(e) = crate::customer::save(&customer) {
                return Response::err(
                    id,
                    protocol::INTERNAL_ERROR,
                    format!("save customer '{}': {e:#}", customer.slug),
                );
            }
            customers += 1;
        }

        Response::ok(
            id,
            serde_json::json!({
                "profiles": profiles,
                "ssh_keys": ssh_keys,
                "hosts": hosts,
                "customers": customers,
                "secrets": imported_secrets,
            }),
        )
    }
}
