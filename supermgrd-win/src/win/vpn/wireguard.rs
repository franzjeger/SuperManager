//! WireGuard backend (Windows).
//!
//! Wraps **WireGuardNT**, the kernel-mode driver Microsoft and the WireGuard
//! project co-ship for Windows 10/11. The `wireguard-nt` crate dynamically
//! loads `wireguard.dll` and the kernel driver registered by the
//! WireGuardNT installer; we never link the SDK at build time, so the dev
//! environment doesn't need the WireGuard headers installed.
//!
//! # Lifecycle
//!
//! The backend keeps the live `Adapter` and bring-up metadata in
//! [`WgActive`]. Connect populates the slot; disconnect takes it back out
//! and tears it down (drops the Adapter → driver removes the interface,
//! kernel reaps routes, DNS reverts to the saved values).
//!
//! Only one WireGuard tunnel can be active at a time. A second `connect`
//! while a tunnel is up tears the old one down first — same semantics as
//! the Linux daemon.
//!
//! # Implemented
//!
//! - Translate a `WireGuardConfig` from `supermgr-core` into
//!   `wireguard-nt`'s `SetInterface` + `SetPeer` shapes (with secret
//!   resolution from Credential Manager).
//! - Create the adapter (named after the profile), apply the config, set
//!   the default route via `Adapter::set_default_route` (which assigns
//!   the local IP and installs `AllowedIPs` routes through the tunnel),
//!   bring the interface up.
//! - Push DNS servers via `Set-DnsClientServerAddress` PowerShell cmdlet.
//! - Override MTU via `Set-NetIPInterface -NlMtuBytes`.
//! - Tear down on disconnect (drop Adapter; PowerShell reverts DNS).
//!
//! # TODO
//!
//! - **DNS-revert race**: Set-DnsClientServerAddress with `-ResetServerAddresses`
//!   on the now-vanished interface ifindex prints a warning. Harmless but
//!   noisy; suppress by snapshotting+restoring instead.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use base64::Engine as _;
use ipnet::IpNet;
use tokio::sync::Mutex;
use tracing::{info, warn};

use supermgr_core::keyring::SecretStore;
use supermgr_core::vpn::profile::{Profile, ProfileConfig, WireGuardConfig};

use super::{VpnBackend, VpnError};

/// Singleton DLL handle. WireGuardNT requires that the library be loaded
/// exactly once per process — repeated `load()` calls leak resources and
/// can crash the driver. `OnceLock` gives us a thread-safe lazy init that
/// surfaces errors instead of panicking.
static WG_LIB: OnceLock<Arc<wireguard_nt::dll>> = OnceLock::new();

/// State of the currently-active WireGuard tunnel.
///
/// Stored inside the backend's `Mutex<Option<...>>` slot. Drop order
/// matters: `adapter.drop()` tears down the kernel-side interface
/// (removing routes the driver added), which must happen before we
/// revert DNS — otherwise the DNS-revert cmdlet hits a stale ifindex.
struct WgActive {
    /// Profile this tunnel was started from. Used by `status` to echo
    /// the active profile id back to the GUI.
    profile_id: uuid::Uuid,
    /// Adapter handle. Dropping it removes the interface.
    adapter: wireguard_nt::Adapter,
    /// Adapter name as we requested it (also the friendly name Windows
    /// shows in Get-NetAdapter output).
    adapter_name: String,
    /// Whether we installed a DNS override that needs reverting.
    dns_overridden: bool,
}

/// Windows-side WireGuard backend.
pub struct WireGuardBackend {
    secret_store: Arc<dyn SecretStore>,
    active: Mutex<Option<WgActive>>,
}

impl WireGuardBackend {
    /// Construct a backend bound to the given secret store.
    pub fn new(secret_store: Arc<dyn SecretStore>) -> Self {
        Self {
            secret_store,
            active: Mutex::new(None),
        }
    }

    /// Whether a tunnel is currently up.
    pub async fn is_active(&self) -> bool {
        self.active.lock().await.is_some()
    }

    /// Load `wireguard.dll`. Surfaces a typed [`VpnError::MissingDependency`]
    /// when the driver isn't installed so the GUI can prompt the user.
    fn ensure_lib() -> Result<Arc<wireguard_nt::dll>, VpnError> {
        if let Some(lib) = WG_LIB.get() {
            return Ok(lib.clone());
        }
        // Probe the DLL in order of preference:
        //  1. Same directory as the daemon binary (MSI install: bin\wireguard.dll)
        //  2. WIREGUARD_DLL env var override (developer/testing)
        //  3. System PATH (legacy: full WireGuard-for-Windows install)
        //
        // `unsafe` is unavoidable: dynamic library loading can never be
        // safe in the Rust sense. The MSI places the DLL inside a
        // system-protected directory (%ProgramFiles%\SuperManager\bin\).
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        let loaded: Arc<wireguard_nt::dll> = (|| {
            // 1. Bundled in the SuperManager bin\ directory.
            if let Some(ref dir) = exe_dir {
                let bundled = dir.join("wireguard.dll");
                if bundled.exists() {
                    // SAFETY: path points to our own install directory.
                    if let Ok(lib) = unsafe { wireguard_nt::load_from_path(&bundled) } {
                        return Ok(lib);
                    }
                }
            }
            // 2. Env var override.
            if let Ok(path) = std::env::var("WIREGUARD_DLL") {
                if let Ok(lib) = unsafe { wireguard_nt::load_from_path(path.as_str()) } {
                    return Ok(lib);
                }
            }
            // 3. Fallback to PATH / default search.
            unsafe { wireguard_nt::load() }
        })()
        .map_err(|e| VpnError::MissingDependency(format!(
            "wireguard.dll not found ({e}). \
             It should be bundled at %ProgramFiles%\\SuperManager\\bin\\wireguard.dll. \
             Re-run the SuperManager installer to restore it."
        )))?;

        match WG_LIB.set(loaded.clone()) {
            Ok(()) => Ok(loaded),
            Err(_) => Ok(WG_LIB.get().expect("OnceLock set then get").clone()),
        }
    }

    /// Decode a base64 WireGuard key into the 32-byte array the driver expects.
    fn decode_key(b64: &str, what: &'static str) -> Result<[u8; 32], VpnError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| VpnError::MissingDependency(format!("decode {what}: {e}")))?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            VpnError::MissingDependency(format!(
                "{what} has {} bytes after base64-decode; expected 32",
                v.len()
            ))
        })
    }

    /// Translate the core WireGuard config into wireguard-nt's struct,
    /// resolving secrets from Credential Manager along the way.
    async fn build_interface(
        &self,
        cfg: &WireGuardConfig,
    ) -> Result<wireguard_nt::SetInterface, VpnError> {
        let priv_secret = self
            .secret_store
            .retrieve(cfg.private_key.label())
            .await
            .map_err(|e| VpnError::MissingDependency(format!(
                "WireGuard private key not found in Credential Manager: {e}"
            )))?;
        let priv_b64 = std::str::from_utf8(&priv_secret).map_err(|_| {
            VpnError::MissingDependency("stored private key is not valid UTF-8".into())
        })?;
        let private_key = Self::decode_key(priv_b64, "private key")?;

        let mut peers = Vec::with_capacity(cfg.peers.len());
        for peer in &cfg.peers {
            let public_key = Self::decode_key(&peer.public_key, "peer public key")?;
            let preshared_key = if let Some(psk_ref) = &peer.preshared_key {
                let psk = self
                    .secret_store
                    .retrieve(psk_ref.label())
                    .await
                    .map_err(|e| VpnError::MissingDependency(format!(
                        "PSK lookup ({psk_ref}): {e}"
                    )))?;
                let psk_str = std::str::from_utf8(&psk).map_err(|_| {
                    VpnError::MissingDependency("stored PSK is not valid UTF-8".into())
                })?;
                Some(Self::decode_key(psk_str, "preshared key")?)
            } else {
                None
            };
            let endpoint_sockaddr = if let Some(ep) = &peer.endpoint {
                resolve_endpoint(ep)?
            } else {
                return Err(VpnError::MissingDependency(format!(
                    "peer {} has no Endpoint set — WireGuardNT requires one",
                    &peer.public_key[..8.min(peer.public_key.len())]
                )));
            };
            peers.push(wireguard_nt::SetPeer {
                public_key: Some(public_key),
                preshared_key,
                keep_alive: peer.persistent_keepalive,
                endpoint: endpoint_sockaddr,
                allowed_ips: peer.allowed_ips.clone(),
            });
        }

        Ok(wireguard_nt::SetInterface {
            listen_port: cfg.listen_port,
            public_key: None,
            private_key: Some(private_key),
            peers,
        })
    }

    /// Bring up a tunnel for `profile`. If another tunnel is already
    /// active it is torn down first (matches the Linux daemon's
    /// connect-while-connected semantics).
    pub async fn bring_up(&self, profile: &Profile) -> Result<(), VpnError> {
        // Tear down any pre-existing tunnel before starting a new one.
        // Using `take()` here so we drop the old `WgActive` while still
        // holding our own lock — the previous adapter's Drop runs synchronously.
        if let Some(prev) = self.active.lock().await.take() {
            tear_down(prev).await;
        }

        let wg_cfg = match &profile.config {
            ProfileConfig::WireGuard(c) => c.clone(),
            _ => {
                return Err(VpnError::MissingDependency(
                    "profile is not a WireGuard profile".into(),
                ));
            }
        };
        let interface = self.build_interface(&wg_cfg).await?;
        let local_addresses: Vec<IpNet> = wg_cfg.addresses.clone();

        let wg = Self::ensure_lib()?;
        let adapter_name = profile
            .wg_interface_name()
            .unwrap_or_else(|| format!("supermgr-{}", &profile.id.simple().to_string()[..8]));

        // Tear down any leftover same-named adapter from a previous crash.
        if let Ok(existing) = wireguard_nt::Adapter::open(wg.clone(), &adapter_name) {
            warn!(adapter_name, "tearing down stale WireGuard adapter from prior run");
            let _ = existing.down();
            drop(existing);
        }

        let adapter = wireguard_nt::Adapter::create(wg, "SuperManager", &adapter_name, None)
            .map_err(|(e, _wg)| VpnError::Win32(format!("create WireGuard adapter: {e}")))?;

        adapter
            .set_config(&interface)
            .map_err(|e| VpnError::Win32(format!("set WireGuard config: {e}")))?;

        adapter
            .set_default_route(&local_addresses, &interface)
            .map_err(|e| VpnError::Win32(format!("set default route: {e}")))?;

        if !adapter.up() {
            return Err(VpnError::Win32("adapter.up() returned false".into()));
        }

        info!(adapter_name, peers = wg_cfg.peers.len(), "WireGuard adapter up");

        // DNS + MTU happen after the adapter is up so the interface index
        // exists in the Get-NetAdapter table. Both are best-effort — if
        // the user didn't request DNS/MTU we skip the PowerShell call.
        let mut dns_overridden = false;
        if !wg_cfg.dns.is_empty() {
            match set_dns_servers(&adapter_name, &wg_cfg.dns).await {
                Ok(()) => dns_overridden = true,
                Err(e) => warn!("DNS push failed for {adapter_name}: {e:#}"),
            }
        }
        if let Some(mtu) = wg_cfg.mtu {
            if let Err(e) = set_mtu(&adapter_name, mtu).await {
                warn!("MTU override failed for {adapter_name}: {e:#}");
            }
        }

        *self.active.lock().await = Some(WgActive {
            profile_id: profile.id,
            adapter,
            adapter_name,
            dns_overridden,
        });
        Ok(())
    }

    /// Tear down the active tunnel. No-op if nothing is connected.
    pub async fn bring_down(&self) -> Result<(), VpnError> {
        let active = self.active.lock().await.take();
        match active {
            Some(a) => {
                tear_down(a).await;
                Ok(())
            }
            None => Err(VpnError::NotImplemented("no active WireGuard tunnel")),
        }
    }
}

/// Synchronous-ish teardown: drop the Adapter (kernel removes the
/// interface and its routes), then revert DNS if we set it. The
/// PowerShell cmdlet to revert DNS is fire-and-forget; failures are
/// logged but don't propagate (the tunnel is already gone).
async fn tear_down(active: WgActive) {
    let name = active.adapter_name.clone();
    let dns_overridden = active.dns_overridden;
    info!(adapter_name = %name, "tearing down WireGuard tunnel");
    // Explicit `down()` for symmetry; `drop` would do the same but
    // logs more clearly when each step happens.
    let _ = active.adapter.down();
    drop(active.adapter);
    if dns_overridden {
        if let Err(e) = reset_dns_servers(&name).await {
            warn!("DNS reset on {name} failed (interface may already be gone): {e:#}");
        }
    }
}

#[async_trait]
impl VpnBackend for WireGuardBackend {
    async fn connect(&self, profile_json: &str) -> Result<(), VpnError> {
        let profile: Profile = serde_json::from_str(profile_json).map_err(|e| {
            VpnError::MissingDependency(format!("parse WireGuard profile JSON: {e}"))
        })?;
        self.bring_up(&profile).await
    }

    async fn disconnect(&self) -> Result<(), VpnError> {
        self.bring_down().await
    }

    async fn status(&self) -> Result<String, VpnError> {
        let guard = self.active.lock().await;
        if let Some(a) = guard.as_ref() {
            Ok(serde_json::json!({
                "state": "Connected",
                "backend": "wireguard",
                "profile_id": a.profile_id.to_string(),
                "adapter": a.adapter_name,
            })
            .to_string())
        } else {
            Ok(r#"{"state":"Disconnected","backend":"wireguard"}"#.to_owned())
        }
    }
}

/// Resolve a `host:port` endpoint string to a single `SocketAddr`. We
/// pick the first result the OS returns; the kernel handles
/// re-resolution if the gateway moves.
fn resolve_endpoint(endpoint: &str) -> Result<std::net::SocketAddr, VpnError> {
    use std::net::ToSocketAddrs;
    endpoint
        .to_socket_addrs()
        .map_err(|e| VpnError::MissingDependency(format!("resolve endpoint {endpoint}: {e}")))?
        .next()
        .ok_or_else(|| {
            VpnError::MissingDependency(format!("endpoint {endpoint} resolved to no addresses"))
        })
}

/// Shell out to PowerShell to set DNS server addresses on the tunnel
/// interface. Uses `-InterfaceAlias` so we don't have to look up the
/// ifindex separately — Windows resolves the alias to the right adapter.
///
/// Quoting via single quotes everywhere; the adapter name and IPs are
/// validated upstream and we don't interpolate user-supplied text into a
/// shell command line beyond that.
async fn set_dns_servers(
    adapter_name: &str,
    dns: &[std::net::IpAddr],
) -> Result<(), VpnError> {
    if dns.is_empty() {
        return Ok(());
    }
    let servers = dns
        .iter()
        .map(|ip| format!("'{ip}'"))
        .collect::<Vec<_>>()
        .join(",");
    let cmd = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({})",
        adapter_name.replace('\'', "''"),
        servers,
    );
    run_powershell(&cmd).await
}

/// Revert DNS to DHCP for the given adapter.
async fn reset_dns_servers(adapter_name: &str) -> Result<(), VpnError> {
    let cmd = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
        adapter_name.replace('\'', "''"),
    );
    run_powershell(&cmd).await
}

/// Set the MTU on the tunnel interface. PowerShell's `Set-NetIPInterface`
/// requires an address family — we apply to both IPv4 and IPv6 so the
/// tunnel's payload MTU is consistent regardless of which family is
/// routing through it.
async fn set_mtu(adapter_name: &str, mtu: u16) -> Result<(), VpnError> {
    let name = adapter_name.replace('\'', "''");
    let cmd = format!(
        "Set-NetIPInterface -InterfaceAlias '{name}' -AddressFamily IPv4 -NlMtuBytes {mtu} ; \
         Set-NetIPInterface -InterfaceAlias '{name}' -AddressFamily IPv6 -NlMtuBytes {mtu}",
    );
    run_powershell(&cmd).await
}

/// Run a PowerShell command line. Stdout and stderr are captured; a
/// non-zero exit becomes [`VpnError::Subprocess`].
async fn run_powershell(cmd: &str) -> Result<(), VpnError> {
    let output = tokio::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(cmd)
        .output()
        .await
        .map_err(VpnError::Io)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(VpnError::Subprocess {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}
