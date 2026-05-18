//! Top-level daemon orchestration.
//!
//! Owns the shared state (loaded profiles, hosts, keys) and spawns the
//! named-pipe listener. The dispatcher in [`crate::dispatch`] borrows this
//! state read-only or via fine-grained `Mutex`es; we do **not** hold the
//! whole state under one `Mutex` to keep concurrent reads cheap.

use std::sync::Arc;

use anyhow::Context as _;
use tokio::sync::Notify;
use tracing::{info, warn};

use super::{known_hosts::KnownHostsStore, paths, pipe_server, profile_store::ProfileStore, vpn};

/// Shared daemon state passed to the dispatcher for every request.
///
/// Concrete subsystems live behind narrow types so the dispatcher can
/// borrow them independently — keeping the secret store, profile store,
/// and the active-VPN handle on separate locks instead of one big
/// `Mutex` around all daemon state.
pub struct DaemonState {
    /// Resolved `%PROGRAMDATA%\SuperManager` root.
    pub root: std::path::PathBuf,
    /// Platform-appropriate secret store. The boxed trait object lets us
    /// swap in a mock for integration tests without dragging a generic
    /// parameter through every dispatch arm.
    pub secret_store: Arc<dyn supermgr_core::keyring::SecretStore>,
    /// VPN profile store. Loads existing `.toml`s from disk at startup
    /// and writes back through async-friendly `save`/`delete` methods.
    pub profile_store: Arc<ProfileStore>,
    /// Persistent SSH host-key store. Recorded fingerprints stop a
    /// changed key from silently going through trust-on-first-use a
    /// second time.
    pub known_hosts: KnownHostsStore,
    /// VPN backend instances. Each backend tracks its own
    /// `Option<active-tunnel>` state internally; the dispatcher routes
    /// connect/disconnect to the right backend based on the profile's
    /// `ProfileConfig` discriminator.
    pub vpn: VpnBackends,
}

/// Container for the four VPN backends. Concrete types (not `Arc<dyn ...>`)
/// because we want the dispatcher to dispatch statically and because each
/// backend exposes a couple of backend-specific methods (e.g. WireGuard's
/// `bring_up` takes a `Profile`, not a JSON string) that the trait can't
/// surface ergonomically.
pub struct VpnBackends {
    pub wireguard: Arc<vpn::wireguard::WireGuardBackend>,
    pub openvpn: Arc<vpn::openvpn::OpenVpnBackend>,
    pub ikev2: Arc<vpn::ikev2::Ikev2Backend>,
    pub fortigate: Arc<vpn::fortigate::FortiGateBackend>,
    pub forticlient: Arc<vpn::forticlient::ForticlientBackend>,
}

impl DaemonState {
    /// Build state from on-disk artefacts. Called once at daemon startup.
    pub fn load() -> anyhow::Result<Self> {
        let root = paths::ensure_root().context("create %PROGRAMDATA%\\SuperManager")?;
        let secret_store: Arc<dyn supermgr_core::keyring::SecretStore> =
            Arc::new(supermgr_core::keyring::CredentialManagerStore::new());
        let profile_store =
            Arc::new(ProfileStore::load_from(root.join("profiles"))
                .context("load profile store")?);
        let known_hosts = KnownHostsStore::load_from(&root)
            .context("load known_hosts store")?;
        let vpn_backends = VpnBackends {
            wireguard: Arc::new(vpn::wireguard::WireGuardBackend::new(
                secret_store.clone(),
            )),
            openvpn: Arc::new(vpn::openvpn::OpenVpnBackend::with_store(
                secret_store.clone(),
            )),
            ikev2: Arc::new(vpn::ikev2::Ikev2Backend::with_store(
                secret_store.clone(),
            )),
            fortigate: Arc::new(vpn::fortigate::FortiGateBackend::with_store(
                secret_store.clone(),
            )),
            forticlient: Arc::new(vpn::forticlient::ForticlientBackend::with_store(
                secret_store.clone(),
            )),
        };
        Ok(Self {
            root,
            secret_store,
            profile_store,
            known_hosts,
            vpn: vpn_backends,
        })
    }
}

/// Run the daemon until `shutdown` fires.
///
/// The function is `Send`-safe; it can be `block_on`'d from either the
/// console-mode runtime or the service runtime.
pub async fn run(shutdown: Arc<Notify>) -> anyhow::Result<()> {
    let state = Arc::new(DaemonState::load()?);
    info!(root = ?state.root, "supermgrd-win state loaded");

    let pipe_task = {
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = pipe_server::serve(state, shutdown).await {
                warn!("named-pipe server exited: {e:#}");
            }
        })
    };

    shutdown.notified().await;
    info!("shutdown signal received");

    // Give the pipe server a beat to finish in-flight requests before we
    // abort. In practice it observes the same Notify and exits cleanly.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), pipe_task).await;
    Ok(())
}
