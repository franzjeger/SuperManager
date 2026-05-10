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

/// Default socket path for the macOS daemon.
fn socket_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
    format!("{home}/Library/Application Support/SuperManager/supermgrd.sock")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (logs to stderr).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    info!("supermgrd-mac starting");

    // Set up data directory.
    let data_dir = supermgr_engine::secrets::default_data_dir();
    std::fs::create_dir_all(&data_dir)?;
    info!("data directory: {}", data_dir.display());

    // Initialize state and load persisted data.
    let mut state = DaemonState::new(data_dir.clone());
    state.load_profiles()?;
    state.load_ssh_keys()?;
    state.load_ssh_hosts()?;

    info!(
        "loaded {} profiles, {} SSH keys, {} SSH hosts",
        state.profiles.len(),
        state.ssh_keys.len(),
        state.ssh_hosts.len(),
    );

    // Set up secrets store.
    //
    // The architecturally correct macOS path is the Data Protection
    // Keychain, accessed via `kSecUseDataProtectionKeychain: true`.
    // DPK requires a `keychain-access-groups` entitlement, which in
    // turn requires the *binary* to be authorised by a provisioning
    // profile. The Personal Team profile we have only authorises
    // bundles that carry an `embedded.provisionprofile` — and a raw
    // CLI binary like this daemon, sitting in `Contents/MacOS/`
    // alongside the GUI but not wrapped in its own .app, has no way
    // to carry one. Signing it with the entitlement anyway makes
    // amfid kill the process on launch (SIGKILL within milliseconds
    // of fork — no log entries reach us, console barely registers
    // it).
    //
    // The architecturally correct fix is to have the GUI own all
    // user-facing secrets in DPK and ship them down to the daemon
    // over RPC on demand — that's the macOS-canonical "GUI owns
    // user data, headless helpers are stateless" pattern. We're
    // not there yet for SSH passwords (VPN already works that way),
    // so for now the daemon falls back to the file-based store
    // (mode 0600 JSON in the data dir). It's the same bytes as the
    // pre-DPK days; not encrypted at rest, but readable only by
    // the user. Once SSH password flow gets refactored to send the
    // secret as an RPC argument from the GUI (mirroring VPN), this
    // store becomes write-only and eventually unused.
    let secrets: Arc<dyn supermgr_core::keyring::SecretStore> =
        Arc::new(FileSecretStore::default_path());

    // Start background scheduler — fires recurring active scans
    // for engagements with a configured cadence.
    supermgr_engine::scheduler::spawn();

    // Start the JSON-RPC server.
    let server = Arc::new(EngineServer::new(state, secrets));
    let sock = socket_path();
    info!("starting JSON-RPC server on {sock}");
    server.serve(&sock).await?;

    Ok(())
}
