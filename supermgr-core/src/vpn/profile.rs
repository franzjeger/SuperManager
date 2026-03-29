//! VPN profile types.
//!
//! A [`Profile`] is a named, persistent description of how to reach a VPN endpoint.
//! It is serialised to TOML on disk (without any secrets — those live in the
//! system keyring) and passed over D-Bus as a JSON string.
//!
//! # Secret references
//!
//! Keys and passwords are **never** stored inline.  Instead, a [`SecretRef`] is a
//! handle (a human-readable label) that the daemon resolves against the system
//! secret store (GNOME Keyring / KWallet) at connect time.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

// ---------------------------------------------------------------------------
// Secret reference
// ---------------------------------------------------------------------------

/// An opaque handle into the system secret store.
///
/// The daemon stores the actual secret bytes under this label in GNOME Keyring
/// or KWallet.  Config files only ever contain the label string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretRef(pub String);

impl SecretRef {
    /// Create a new secret reference with the given label.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    /// Returns the underlying label string.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<secret:{}>", self.0)
    }
}

// ---------------------------------------------------------------------------
// WireGuard config
// ---------------------------------------------------------------------------

/// Configuration for a single WireGuard peer (remote endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardPeer {
    /// Peer's static public key (base64-encoded).
    pub public_key: String,

    /// Optional UDP endpoint in `host:port` form.
    ///
    /// The host may be a hostname (`vpn.example.com`), an IPv4 address
    /// (`1.2.3.4`), or a bracketed IPv6 address (`[::1]`).  Resolution to a
    /// [`std::net::SocketAddr`] happens at connect time, not import time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// IP prefixes routed through this peer (allowed IPs).
    pub allowed_ips: Vec<IpNet>,

    /// Handle to the pre-shared key stored in the system keyring, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<SecretRef>,

    /// Keepalive interval in seconds.  `None` disables persistent keepalive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}

/// Configuration for the local WireGuard interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardConfig {
    /// Reference to the interface private key in the system keyring.
    pub private_key: SecretRef,

    /// IP addresses assigned to the local WireGuard interface.
    pub addresses: Vec<IpNet>,

    /// DNS servers to configure via `systemd-resolved` when the tunnel is up.
    #[serde(default)]
    pub dns: Vec<IpAddr>,

    /// Optional DNS search domains.
    #[serde(default)]
    pub dns_search: Vec<String>,

    /// MTU override.  `None` lets the kernel or WireGuard choose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Listen port for the local WireGuard socket.  `None` picks a random port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    /// One or more remote peers.
    pub peers: Vec<WireGuardPeer>,

    /// Name of the kernel interface to create (e.g. `wg0`).
    /// Defaults to `wg{id_prefix}` if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,

    /// Routes to push through the tunnel when `Profile.full_tunnel` is `false`.
    ///
    /// When split-tunnel mode is active these prefixes replace the catch-all
    /// `0.0.0.0/0` / `::/0` entries in each peer's AllowedIPs.  If this list
    /// is empty and the peer AllowedIPs contains no specific (non-catch-all)
    /// prefixes, connecting in split-tunnel mode will return an error.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub split_routes: Vec<IpNet>,
}

// ---------------------------------------------------------------------------
// FortiGate IPsec / IKEv2 config
// ---------------------------------------------------------------------------

/// Configuration for a FortiGate VPN connection driven via strongSwan.
///
/// IKEv2 with EAP-MSCHAPv2 user authentication and a group PSK for IKE SA
/// authentication, mode-config for virtual IP assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FortiGateConfig {
    /// Hostname or IP address of the FortiGate appliance.
    pub host: String,

    /// EAP username (sent in IKE_AUTH as the EAP identity).
    pub username: String,

    /// Keyring reference to the EAP password.
    pub password: SecretRef,

    /// Keyring reference to the group PSK for IKE SA authentication.
    pub psk: SecretRef,

    /// DNS servers to configure via `systemd-resolved` when the tunnel is up.
    /// Usually populated from the gateway's configuration payload.
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,

    /// Split-tunnel destination prefixes (`remote_ts` in strongSwan).
    /// Only used when the profile's `full_tunnel` flag is `false`.
    /// Empty means only the VPN-assigned subnet is reachable via the tunnel.
    #[serde(default)]
    pub routes: Vec<IpNet>,
}

// ---------------------------------------------------------------------------
// OpenVPN config
// ---------------------------------------------------------------------------

/// Configuration for an OpenVPN connection.
///
/// Managed via the `openvpn` v2 CLI tool.  The actual `.ovpn` config file is
/// stored in the daemon's data directory; only the path is kept here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenVpnConfig {
    /// Path to the stored `.ovpn` configuration file.
    pub config_file: String,

    /// Optional username for configurations that require authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Keyring reference to the password, if authentication is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretRef>,
}

// ---------------------------------------------------------------------------
// Azure Point-to-Site / Entra ID config
// ---------------------------------------------------------------------------

/// Configuration for an Azure Point-to-Site VPN connection that authenticates
/// via Microsoft Entra ID (formerly Azure AD) using the OAuth2 device-code
/// flow.
///
/// # Connection lifecycle (daemon side)
///
/// 1. POST device-code request to
///    `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode`.
/// 2. Emit `auth_challenge` D-Bus signal so the GUI can display the user code.
/// 3. Poll the token endpoint until the user completes browser authentication.
/// 4. Write temporary files: `.ovpn` config, TLS-crypt key, auth-user-pass.
/// 5. Spawn `openvpn --config <tmp.ovpn>` and wait for
///    "Initialization Sequence Completed".
/// 6. Configure `systemd-resolved` per-link DNS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureVpnConfig {
    /// VPN gateway FQDN (e.g. `azuregateway-xxx.vpn.azure.com`).
    pub gateway_fqdn: String,

    /// Entra ID tenant ID — UUID string extracted from the `<issuer>` or
    /// `<tenant>` field in `azurevpnconfig.xml`.
    pub tenant_id: String,

    /// OAuth2 client / audience ID (the well-known Azure VPN app ID
    /// `c632b3df-fb67-4d84-bdcf-b95ad541b5c8` unless overridden by the
    /// gateway administrator).
    pub client_id: String,

    /// 512-character hex string (256 bytes) used as the OpenVPN `tls-crypt`
    /// key.  Sourced from `<serversecret>` in `azurevpnconfig.xml`.
    pub server_secret_hex: String,

    /// PEM-encoded CA certificate for verifying the gateway's TLS certificate.
    /// Derived from the `<CaCerts>` base64 blob in `VpnSettings.xml`.
    pub ca_cert_pem: String,

    /// Split-tunnel routes.  Empty means full-tunnel (`redirect-gateway def1`).
    #[serde(default)]
    pub routes: Vec<IpNet>,

    /// DNS servers to push via `systemd-resolved` when the tunnel is up.
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
}

// ---------------------------------------------------------------------------
// Generic backend placeholder
// ---------------------------------------------------------------------------

/// Configuration for a backend that is not yet natively supported, stored as
/// an arbitrary key-value map (e.g. for future OpenVPN or AnyConnect profiles).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GenericConfig {
    /// Backend identifier string (e.g. `"openvpn"`, `"anyconnect"`).
    pub backend_id: String,

    /// Opaque configuration blob; interpretation is left to the plugin.
    pub config: std::collections::HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Top-level profile
// ---------------------------------------------------------------------------

/// Discriminated union of all supported VPN backend configurations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum ProfileConfig {
    /// WireGuard via the kernel netlink API.
    WireGuard(WireGuardConfig),
    /// FortiGate IPsec / IKEv2 via strongSwan.
    FortiGate(FortiGateConfig),
    /// OpenVPN session managed via the `openvpn` v2 CLI.
    OpenVpn(OpenVpnConfig),
    /// Azure Point-to-Site VPN with Entra ID (device-code) authentication.
    AzureVpn(AzureVpnConfig),
    /// Plugin / generic backend.
    Generic(GenericConfig),
}

impl ProfileConfig {
    /// Human-readable name of the backend.
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::WireGuard(_) => "WireGuard",
            Self::FortiGate(_) => "FortiGate (IPsec/IKEv2)",
            Self::OpenVpn(_) => "OpenVPN3",
            Self::AzureVpn(_) => "Azure VPN (Entra ID)",
            Self::Generic(_) => "Generic",
        }
    }
}

/// A complete, named VPN profile.
///
/// Profiles are stored as TOML files in the daemon's configuration directory
/// (`/etc/supermgrd/profiles/`).  Secret material is **never** written to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Stable identifier — generated at import time, never changes.
    pub id: Uuid,

    /// Display name shown in the GUI and tray menu.
    pub name: String,

    /// Connect automatically when the system starts or the network becomes
    /// available.
    #[serde(default)]
    pub auto_connect: bool,

    /// Route all traffic through this VPN when connected (`redirect-gateway`
    /// / `0.0.0.0/0`).  When `false`, only the backend-specific split-tunnel
    /// routes are installed.  Defaults to `true` for new profiles.
    #[serde(default = "default_true")]
    pub full_tunnel: bool,

    /// Timestamp of the most recent successful connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_connected_at: Option<DateTime<Utc>>,

    /// Block all non-VPN traffic while this profile is connected.
    #[serde(default)]
    pub kill_switch: bool,

    /// The backend-specific configuration.
    pub config: ProfileConfig,

    /// ISO-8601 timestamp at which this profile was imported or last modified.
    pub updated_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

impl Profile {
    /// Create a new profile with a freshly generated UUID.
    #[must_use]
    pub fn new(name: impl Into<String>, config: ProfileConfig) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            auto_connect: false,
            full_tunnel: true,
            last_connected_at: None,
            kill_switch: false,
            config,
            updated_at: Utc::now(),
        }
    }

    /// Returns the kernel interface name to use for this profile (WireGuard only).
    ///
    /// Uses the explicit name from the config if set; otherwise derives one
    /// from the first 8 hex digits of the UUID to avoid collisions.
    #[must_use]
    pub fn wg_interface_name(&self) -> Option<String> {
        match &self.config {
            ProfileConfig::WireGuard(wg) => Some(
                wg.interface_name
                    .clone()
                    .unwrap_or_else(|| format!("wg{}", &self.id.simple().to_string()[..8])),
            ),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Lightweight summary transferred over D-Bus
// ---------------------------------------------------------------------------

/// Compact summary of a [`Profile`] returned by `ListProfiles`.
///
/// Only non-secret, non-bulky fields are included so the GUI can populate a
/// list without deserialising full configs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSummary {
    /// Stable profile identifier.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Human-readable backend name.
    pub backend: String,
    /// Auto-connect flag.
    pub auto_connect: bool,
    /// Route all traffic through this VPN.
    #[serde(default = "default_true")]
    pub full_tunnel: bool,
    /// Split-tunnel routes (CIDR strings).  Only meaningful for WireGuard
    /// profiles with `full_tunnel = false`.  Empty for all other backends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub split_routes: Vec<String>,
    /// Unix epoch seconds of the most recent successful connection, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_connected_secs: Option<u64>,
    /// For FortiGate: the appliance hostname or IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// For FortiGate/OpenVPN: the authentication username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Kill-switch flag.
    #[serde(default)]
    pub kill_switch: bool,
}

impl From<&Profile> for ProfileSummary {
    fn from(p: &Profile) -> Self {
        let split_routes = match &p.config {
            ProfileConfig::WireGuard(wg) => {
                wg.split_routes.iter().map(|r| r.to_string()).collect()
            }
            ProfileConfig::FortiGate(fg) => {
                fg.routes.iter().map(|r| r.to_string()).collect()
            }
            _ => Vec::new(),
        };
        Self {
            id: p.id,
            name: p.name.clone(),
            backend: p.config.backend_name().to_owned(),
            auto_connect: p.auto_connect,
            full_tunnel: p.full_tunnel,
            split_routes,
            last_connected_secs: p.last_connected_at
                .map(|dt| dt.timestamp().max(0) as u64),
            host: match &p.config {
                ProfileConfig::FortiGate(fg) => Some(fg.host.clone()),
                _ => None,
            },
            username: match &p.config {
                ProfileConfig::FortiGate(fg) => Some(fg.username.clone()),
                ProfileConfig::OpenVpn(ov) => ov.username.clone(),
                _ => None,
            },
            kill_switch: p.kill_switch,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip an inline `# comment` (or `; comment`) from a `.conf` value.
///
/// WireGuard tools commonly emit lines like:
/// ```text
/// Address = 10.0.0.1/24 # tunnel address
/// DNS     = 1.1.1.1     ; Cloudflare
/// ```
/// Anything from the first ` #`, `\t#`, ` ;`, or `\t;` onwards is discarded.
fn strip_inline_comment(value: &str) -> &str {
    // Find the earliest inline comment marker that is preceded by whitespace.
    let mut earliest: Option<usize> = None;
    for marker in [" #", "\t#", " ;", "\t;"] {
        if let Some(pos) = value.find(marker) {
            earliest = Some(match earliest {
                Some(prev) => prev.min(pos),
                None => pos,
            });
        }
    }
    match earliest {
        Some(pos) => value[..pos].trim_end(),
        None => value,
    }
}

/// Validate and normalise a WireGuard `Endpoint` value.
///
/// Accepts all three forms that WireGuard tools emit:
///
/// | Form | Example |
/// |------|---------|
/// | `hostname:port` | `vpn.example.com:51820` |
/// | `IPv4:port`     | `1.2.3.4:51820` |
/// | `[IPv6]:port`   | `[2001:db8::1]:51820` |
///
/// The host portion is **not** resolved to an IP address here — resolution
/// happens at connect time so that hostnames with TTL-limited DNS records are
/// always freshly resolved.
///
/// Returns the original string unchanged if it is valid, or an error
/// description if the format is unrecognisable.
fn parse_endpoint(value: &str) -> Result<String, String> {
    // `rsplit_once` splits at the *last* colon, correctly handling both
    // `hostname:port` and `[IPv6]:port` (whose host contains colons).
    let (host, port_str) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("expected host:port, got {:?}", value))?;

    if host.is_empty() {
        return Err(format!("host part is empty in {:?}", value));
    }

    // Validate the port is a u16; reject garbage like "abc" or "99999".
    port_str
        .parse::<u16>()
        .map_err(|_| format!("port {:?} is not a valid u16 in {:?}", port_str, value))?;

    // The host is accepted as-is (hostname, bare IPv4, or `[IPv6]`).
    // We do not resolve or further validate hostnames at import time.
    Ok(value.to_owned())
}

// ---------------------------------------------------------------------------
// WireGuard .conf file importer
// ---------------------------------------------------------------------------

/// Parses a WireGuard `.conf` file (INI format) and returns a [`WireGuardConfig`].
///
/// The caller is responsible for storing the private key (returned separately
/// by [`import_wireguard_conf`]) in the system keyring.
///
/// # Errors
///
/// Returns a [`crate::error::ProfileError::ImportFailed`] if the file cannot be
/// parsed or required fields are missing.
pub fn parse_wireguard_conf(
    source: &str,
    secret_label: &str,
) -> Result<WireGuardConfig, crate::error::ProfileError> {
    use std::str::FromStr;

    let mut private_key: Option<String> = None;
    let mut addresses: Vec<IpNet> = Vec::new();
    let mut dns: Vec<IpAddr> = Vec::new();
    let mut dns_search: Vec<String> = Vec::new();
    let mut mtu: Option<u16> = None;
    let mut listen_port: Option<u16> = None;
    let mut peers: Vec<WireGuardPeer> = Vec::new();

    // Current peer being assembled (if inside a [Peer] section).
    let mut cur_peer: Option<WireGuardPeer> = None;

    let fail = |line: usize, msg: &str| crate::error::ProfileError::ImportFailed {
        path: "<wireguard conf>".into(),
        reason: format!("line {line}: {msg}"),
    };

    for (line_no, raw) in source.lines().enumerate() {
        let line = raw.trim();

        // Skip blank lines and comments.
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.eq_ignore_ascii_case("[Interface]") {
            // Flush any in-progress peer.
            if let Some(peer) = cur_peer.take() {
                peers.push(peer);
            }
            continue;
        }

        if line.eq_ignore_ascii_case("[Peer]") {
            if let Some(peer) = cur_peer.take() {
                peers.push(peer);
            }
            cur_peer = Some(WireGuardPeer {
                public_key: String::new(),
                endpoint: None,
                allowed_ips: Vec::new(),
                preshared_key: None,
                persistent_keepalive: None,
            });
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .map(|(k, v)| (k.trim(), strip_inline_comment(v.trim())))
            .ok_or_else(|| fail(line_no + 1, "expected key = value"))?;

        if let Some(peer) = cur_peer.as_mut() {
            // We are inside a [Peer] section.
            match key {
                "PublicKey" => peer.public_key = value.to_owned(),
                "PresharedKey" => {
                    let label = format!("{secret_label}/psk/{}", &value[..8.min(value.len())]);
                    peer.preshared_key = Some(SecretRef::new(label));
                }
                "Endpoint" => {
                    peer.endpoint = Some(
                        parse_endpoint(value)
                            .map_err(|e| fail(line_no + 1, &format!("invalid Endpoint: {e}")))?,
                    );
                }
                "AllowedIPs" => {
                    for part in value.split(',') {
                        peer.allowed_ips.push(
                            IpNet::from_str(part.trim())
                                .map_err(|_| fail(line_no + 1, "invalid AllowedIPs entry"))?,
                        );
                    }
                }
                "PersistentKeepalive" => {
                    peer.persistent_keepalive = Some(
                        value
                            .parse()
                            .map_err(|_| fail(line_no + 1, "invalid PersistentKeepalive"))?,
                    );
                }
                _ => {} // Ignore unknown keys.
            }
        } else {
            // We are inside the [Interface] section.
            match key {
                "PrivateKey" => private_key = Some(value.to_owned()),
                "Address" => {
                    for part in value.split(',') {
                        addresses.push(
                            IpNet::from_str(part.trim())
                                .map_err(|_| fail(line_no + 1, "invalid Address"))?,
                        );
                    }
                }
                "DNS" => {
                    for part in value.split(',') {
                        let part = part.trim();
                        // A DNS entry can be either an IP or a search domain.
                        if let Ok(ip) = part.parse::<IpAddr>() {
                            dns.push(ip);
                        } else {
                            dns_search.push(part.to_owned());
                        }
                    }
                }
                "MTU" => {
                    mtu = Some(
                        value
                            .parse()
                            .map_err(|_| fail(line_no + 1, "invalid MTU"))?,
                    );
                }
                "ListenPort" => {
                    listen_port = Some(
                        value
                            .parse()
                            .map_err(|_| fail(line_no + 1, "invalid ListenPort"))?,
                    );
                }
                _ => {}
            }
        }
    }

    // Flush the last peer.
    if let Some(peer) = cur_peer {
        peers.push(peer);
    }

    let private_key_raw = private_key.ok_or_else(|| crate::error::ProfileError::ImportFailed {
        path: "<wireguard conf>".into(),
        reason: "missing PrivateKey in [Interface]".into(),
    })?;

    // We don't store the raw key in the config — only the keyring label.
    // The daemon will store the actual bytes when it processes the import.
    let _ = private_key_raw;

    Ok(WireGuardConfig {
        private_key: SecretRef::new(secret_label),
        addresses,
        dns,
        dns_search,
        mtu,
        listen_port,
        peers,
        interface_name: None,
        split_routes: Vec::new(),
    })
}

/// Same as [`parse_wireguard_conf`] but also returns the raw private key bytes
/// so the caller can persist them to the keyring, and a list of
/// `(psk_label, raw_psk_value)` pairs for each peer that has a `PresharedKey`.
///
/// The returned [`ZeroingKey`] is the base64-encoded private key from the
/// `.conf` file and **must be zeroed after storage**.
#[allow(clippy::type_complexity)]
pub fn import_wireguard_conf(
    source: &str,
    secret_label: &str,
) -> Result<(WireGuardConfig, ZeroingKey, Vec<(String, String)>), crate::error::ProfileError> {
    use std::str::FromStr;

    let mut raw_private_key: Option<String> = None;
    let mut addresses: Vec<IpNet> = Vec::new();
    let mut dns: Vec<IpAddr> = Vec::new();
    let mut dns_search: Vec<String> = Vec::new();
    let mut mtu: Option<u16> = None;
    let mut listen_port: Option<u16> = None;
    let mut peers: Vec<WireGuardPeer> = Vec::new();
    let mut cur_peer: Option<WireGuardPeer> = None;
    let mut psks: Vec<(String, String)> = Vec::new();

    let fail = |line: usize, msg: &str| crate::error::ProfileError::ImportFailed {
        path: "<wireguard conf>".into(),
        reason: format!("line {line}: {msg}"),
    };

    for (line_no, raw) in source.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") {
            if let Some(p) = cur_peer.take() {
                peers.push(p);
            }
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            if let Some(p) = cur_peer.take() {
                peers.push(p);
            }
            cur_peer = Some(WireGuardPeer {
                public_key: String::new(),
                endpoint: None,
                allowed_ips: Vec::new(),
                preshared_key: None,
                persistent_keepalive: None,
            });
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .map(|(k, v)| (k.trim(), strip_inline_comment(v.trim())))
            .ok_or_else(|| fail(line_no + 1, "expected key = value"))?;

        if let Some(peer) = cur_peer.as_mut() {
            match key {
                "PublicKey" => peer.public_key = value.to_owned(),
                "PresharedKey" => {
                    let label =
                        format!("{secret_label}/psk/{}", &value[..8.min(value.len())]);
                    psks.push((label.clone(), value.to_owned()));
                    peer.preshared_key = Some(SecretRef::new(label));
                }
                "Endpoint" => {
                    peer.endpoint = Some(
                        parse_endpoint(value)
                            .map_err(|e| fail(line_no + 1, &format!("invalid Endpoint: {e}")))?,
                    );
                }
                "AllowedIPs" => {
                    for part in value.split(',') {
                        peer.allowed_ips.push(
                            IpNet::from_str(part.trim())
                                .map_err(|_| fail(line_no + 1, "invalid AllowedIPs"))?,
                        );
                    }
                }
                "PersistentKeepalive" => {
                    peer.persistent_keepalive = Some(
                        value
                            .parse()
                            .map_err(|_| fail(line_no + 1, "invalid PersistentKeepalive"))?,
                    );
                }
                _ => {}
            }
        } else {
            match key {
                "PrivateKey" => raw_private_key = Some(value.to_owned()),
                "Address" => {
                    for part in value.split(',') {
                        addresses.push(
                            IpNet::from_str(part.trim())
                                .map_err(|_| fail(line_no + 1, "invalid Address"))?,
                        );
                    }
                }
                "DNS" => {
                    for part in value.split(',') {
                        let part = part.trim();
                        if let Ok(ip) = part.parse::<IpAddr>() {
                            dns.push(ip);
                        } else {
                            dns_search.push(part.to_owned());
                        }
                    }
                }
                "MTU" => {
                    mtu = Some(
                        value
                            .parse()
                            .map_err(|_| fail(line_no + 1, "invalid MTU"))?,
                    );
                }
                "ListenPort" => {
                    listen_port = Some(
                        value
                            .parse()
                            .map_err(|_| fail(line_no + 1, "invalid ListenPort"))?,
                    );
                }
                _ => {}
            }
        }
    }

    if let Some(p) = cur_peer {
        peers.push(p);
    }

    let raw_private_key = raw_private_key.ok_or_else(|| {
        crate::error::ProfileError::ImportFailed {
            path: "<wireguard conf>".into(),
            reason: "missing PrivateKey in [Interface]".into(),
        }
    })?;

    let cfg = WireGuardConfig {
        private_key: SecretRef::new(secret_label),
        addresses,
        dns,
        dns_search,
        mtu,
        listen_port,
        peers,
        interface_name: None,
        split_routes: Vec::new(),
    };

    Ok((cfg, ZeroingKey(raw_private_key), psks))
}

/// A private key that zeroises its memory on drop.
///
/// Call [`.take()`](ZeroingKey::take) exactly once to move the bytes out for
/// keyring storage.
#[derive(ZeroizeOnDrop)]
pub struct ZeroingKey(String);

impl ZeroingKey {
    /// Move the key value out, consuming the wrapper.
    ///
    /// **You are responsible** for zeroing the returned `String` promptly after
    /// passing it to the keyring.
    #[must_use]
    pub fn take(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_config_backend_name() {
        let wg = ProfileConfig::WireGuard(WireGuardConfig {
            private_key: SecretRef::new("test/privkey"),
            addresses: vec![],
            dns: vec![],
            dns_search: vec![],
            mtu: None,
            listen_port: None,
            peers: vec![],
            interface_name: None,
            split_routes: vec![],
        });
        assert_eq!(wg.backend_name(), "WireGuard");

        let fg = ProfileConfig::FortiGate(FortiGateConfig {
            host: "fw.example.com".into(),
            username: "admin".into(),
            password: SecretRef::new("pw"),
            psk: SecretRef::new("psk"),
            dns_servers: vec![],
            routes: vec![],
        });
        assert_eq!(fg.backend_name(), "FortiGate (IPsec/IKEv2)");

        let ov = ProfileConfig::OpenVpn(OpenVpnConfig {
            config_file: "/etc/openvpn/client.ovpn".into(),
            username: None,
            password: None,
        });
        assert_eq!(ov.backend_name(), "OpenVPN3");

        let generic = ProfileConfig::Generic(GenericConfig::default());
        assert_eq!(generic.backend_name(), "Generic");
    }

    #[test]
    fn wireguard_config_roundtrip() {
        let conf = r#"[Interface]
PrivateKey = cGhvbnktcHJpdmF0ZS1rZXktYmFzZTY0LXRlc3Q=
Address = 10.0.0.2/24
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = cGVlci1wdWJsaWMta2V5LWJhc2U2NC10ZXN0AA==
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#;
        let (cfg, key, psks) =
            import_wireguard_conf(conf, "test/wg").expect("parse WireGuard conf");

        // Private key is extracted
        assert_eq!(
            key.take(),
            "cGhvbnktcHJpdmF0ZS1rZXktYmFzZTY0LXRlc3Q="
        );

        // Interface fields
        assert_eq!(cfg.private_key.label(), "test/wg");
        assert_eq!(cfg.addresses.len(), 1);
        assert_eq!(cfg.addresses[0].to_string(), "10.0.0.2/24");
        assert_eq!(cfg.dns.len(), 2);
        assert_eq!(cfg.mtu, Some(1420));

        // Peer fields
        assert_eq!(cfg.peers.len(), 1);
        let peer = &cfg.peers[0];
        assert_eq!(
            peer.public_key,
            "cGVlci1wdWJsaWMta2V5LWJhc2U2NC10ZXN0AA=="
        );
        assert_eq!(peer.endpoint.as_deref(), Some("vpn.example.com:51820"));
        assert_eq!(peer.allowed_ips.len(), 1);
        assert_eq!(peer.persistent_keepalive, Some(25));

        // No PSKs in this config
        assert!(psks.is_empty());

        // The parsed config should round-trip through JSON
        let json = serde_json::to_string(&cfg).expect("serialize WireGuardConfig");
        let back: WireGuardConfig =
            serde_json::from_str(&json).expect("deserialize WireGuardConfig");
        assert_eq!(back.addresses, cfg.addresses);
        assert_eq!(back.peers.len(), cfg.peers.len());
        assert_eq!(back.mtu, cfg.mtu);
    }

    #[test]
    fn secret_ref_display() {
        let sr = SecretRef::new("supermgr/wg/abc123/privkey");
        assert_eq!(format!("{sr}"), "<secret:supermgr/wg/abc123/privkey>");
    }
}
