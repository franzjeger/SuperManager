//! SuperManager daemon for macOS.
//!
//! Starts the JSON-RPC engine server on a Unix domain socket.
//! The SwiftUI app communicates with this daemon to perform SSH operations,
//! manage keys/hosts, and (eventually) VPN connections.

use std::sync::Arc;

use tracing::info;

use supermgr_engine::secrets::file::FileSecretStore;
use supermgr_engine::server::EngineServer;
use supermgr_engine::state::DaemonState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (logs to stderr).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    info!("supermgrd-mac starting");

    // Set up data directory (fails cleanly if HOME is unset or relative).
    let data_dir = supermgr_core::paths::try_default_data_dir().map_err(anyhow::Error::msg)?;
    std::fs::create_dir_all(&data_dir)?;
    info!("data directory: {}", data_dir.display());

    // Initialize state and load persisted data.
    let mut state = DaemonState::new(data_dir.clone())?;
    state.load_profiles()?;
    state.load_ssh_keys()?;
    state.load_ssh_hosts()?;
    state.load_unifi_controllers()?;

    info!(
        "loaded {} profiles, {} SSH keys, {} SSH hosts, {} UniFi controllers",
        state.profiles.len(),
        state.ssh_keys.len(),
        state.ssh_hosts.len(),
        state.unifi_controllers.len(),
    );

    // Set up secrets store.
    //
    // `SuperManager.app` owns a 256-bit wrapping key in the macOS Data
    // Protection Keychain (`com.sybr.supermanager.vpn` /
    // `engine/secrets-master-key-v1`) and passes it to `supermgrd-mac`
    // over a private `--key-stdin` pipe at spawn time. `FileSecretStore`
    // seals `secrets.json` at rest with `AES-256-GCM` (`version: 2`) and
    // transparently upgrades any existing v1 `secrets.json` in place on
    // startup without prompting or losing stored credentials.
    let secrets_path = data_dir.join("secrets.json");
    let store = if std::env::args().any(|a| a == "--key-stdin") {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let s = FileSecretStore::from_hex_key(secrets_path, &line)?;
        line.replace_range(.., "");
        s
    } else if let Ok(dpk_key) = supermgr_engine::secrets::keychain::try_load_or_create_dpk_master_key() {
        FileSecretStore::with_master_key(secrets_path, *dpk_key)
    } else {
        tracing::warn!(
            "running without Data Protection Keychain wrapping key (unsigned dev/CLI invocation)"
        );
        FileSecretStore::new(secrets_path)
    };
    store.migrate_to_encrypted_if_needed().await?;
    let secrets: Arc<dyn supermgr_core::keyring::SecretStore> = Arc::new(store);

    // Background recon scheduler is intentionally disabled while the Recon /
    // Engagement UI is inactive so the daemon never triggers unsolicited
    // active scans or background CVE-feed network requests.
    // supermgr_engine::scheduler::spawn();

    // Start the JSON-RPC server.
    let server = Arc::new(EngineServer::new(state, secrets));
    let sock = data_dir
        .join("supermgrd.sock")
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("data directory path is not valid UTF-8"))?
        .to_owned();
    info!("starting JSON-RPC server on {sock}");
    server.serve(&sock).await?;

    Ok(())
}
