//! D-Bus interface definitions for the `supermgrd` daemon.
//!
//! # Layout
//!
//! | Symbol | Purpose |
//! |--------|---------|
//! | [`DaemonInterface`] | Server-side impl trait — `supermgrd` implements this. |
//! | [`DaemonProxy`] | Client-side proxy — `supermgr` (GUI) uses this. |
//! | [`DBUS_SERVICE`] | Well-known D-Bus service name. |
//! | [`DBUS_OBJECT_PATH`] | Object path the daemon registers. |
//! | [`DBUS_INTERFACE`] | Interface name. |
//!
//! ## Wire format
//!
//! Complex types (profiles, states, stats, SSH keys/hosts) are JSON-serialised
//! and passed as `String` over D-Bus.  This sidesteps the need for complete
//! `zvariant::Type` implementations on every domain type and keeps the interface
//! straightforward to consume from other languages.  Future revisions may
//! migrate to typed D-Bus structs where performance demands it.
//!
//! ## Error handling
//!
//! Server-side methods return `zbus::fdo::Result<T>`.  A [`crate::error::CoreError`]
//! is mapped to a D-Bus FDO error by [`core_error_to_fdo`].

use zbus::fdo;

/// D-Bus well-known service name acquired by the daemon at startup.
pub const DBUS_SERVICE: &str = "org.supermgr.Daemon";

/// Object path at which the daemon exposes its interface.
pub const DBUS_OBJECT_PATH: &str = "/org/supermgr/Daemon";

/// D-Bus interface name.
pub const DBUS_INTERFACE: &str = "org.supermgr.Daemon1";

// ---------------------------------------------------------------------------
// Helper: map CoreError → D-Bus FDO error
// ---------------------------------------------------------------------------

/// Convert a [`crate::error::CoreError`] into a [`zbus::fdo::Error`] for
/// returning from D-Bus method implementations.
#[must_use]
pub fn core_error_to_fdo(err: crate::error::CoreError) -> fdo::Error {
    use crate::error::CoreError;
    match err {
        CoreError::Profile(crate::error::ProfileError::NotFound { id }) => {
            fdo::Error::UnknownObject(format!("profile {id} not found"))
        }
        CoreError::Secret(crate::error::SecretError::ServiceUnavailable(msg)) => {
            fdo::Error::ServiceUnknown(msg)
        }
        CoreError::Backend(crate::error::BackendError::AlreadyConnected) => {
            fdo::Error::Failed("already connected".into())
        }
        CoreError::Backend(crate::error::BackendError::NotConnected) => {
            fdo::Error::Failed("not connected".into())
        }
        CoreError::Ssh(ref e) => fdo::Error::Failed(e.to_string()),
        other => fdo::Error::Failed(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Server-side interface (implemented by the daemon)
// ---------------------------------------------------------------------------

// NOTE: The `#[zbus::interface]` macro is applied in `supermgrd` on the
// concrete daemon struct, not here, because the macro needs an `impl` block —
// it cannot be applied to a trait.  This module instead declares the *expected*
// method signatures via a Rust doc contract, and provides the proxy (client
// side).
//
// The daemon crate declares:
//
//   pub struct DaemonService { ... }
//
//   #[zbus::interface(name = "org.supermgr.Daemon1")]
//   impl DaemonService {
//       // --- VPN methods ---
//       async fn list_profiles(&self) -> fdo::Result<String> { ... }
//       async fn connect(&self, profile_id: &str) -> fdo::Result<()> { ... }
//       async fn disconnect(&self) -> fdo::Result<()> { ... }
//       async fn get_status(&self) -> fdo::Result<String> { ... }
//       async fn import_wireguard(&self, conf_text: &str, name: &str) -> fdo::Result<String> { ... }
//       async fn import_fortigate(&self, name: &str, host: &str, username: &str, password: &str, psk: &str) -> fdo::Result<String> { ... }
//       async fn import_openvpn(&self, conf_text: &str, name: &str, username: &str, password: &str) -> fdo::Result<String> { ... }
//       async fn import_azure_vpn(&self, azure_xml: &str, vpn_settings_xml: &str, name: &str) -> fdo::Result<String> { ... }
//       async fn import_toml(&self, toml_text: &str) -> fdo::Result<String> { ... }
//       async fn delete_profile(&self, profile_id: &str) -> fdo::Result<()> { ... }
//       async fn rename_profile(&self, profile_id: &str, new_name: &str) -> fdo::Result<()>;
//       async fn set_full_tunnel(&self, profile_id: &str, full_tunnel: bool) -> fdo::Result<()>;
//       async fn get_logs(&self) -> fdo::Result<Vec<String>> { ... }
//       async fn set_log_level(&self, level: &str) -> fdo::Result<()> { ... }
//
//       // --- SSH methods ---
//       async fn ssh_generate_key(&self, key_type: &str, name: &str, description: &str, tags_json: &str) -> fdo::Result<String> { ... }
//       async fn ssh_import_keys_scan(&self, directory: &str) -> fdo::Result<String> { ... }
//       async fn ssh_import_key(&self, name: &str, public_key: &str, private_key_pem: &str, key_type: &str) -> fdo::Result<String> { ... }
//       async fn ssh_delete_key(&self, key_id: &str) -> fdo::Result<()> { ... }
//       async fn ssh_list_keys(&self) -> fdo::Result<String> { ... }
//       async fn ssh_get_key(&self, key_id: &str) -> fdo::Result<String> { ... }
//       async fn ssh_export_public_key(&self, key_id: &str) -> fdo::Result<String> { ... }
//       async fn ssh_export_private_key(&self, key_id: &str) -> fdo::Result<String> { ... }
//       async fn add_host(&self, host_json: &str) -> fdo::Result<String> { ... }
//       async fn update_host(&self, host_id: &str, host_json: &str) -> fdo::Result<()> { ... }
//       async fn toggle_host_pin(&self, host_id: &str) -> fdo::Result<String> { ... }
//       async fn delete_host(&self, host_id: &str) -> fdo::Result<()> { ... }
//       async fn list_hosts(&self) -> fdo::Result<String> { ... }
//       async fn get_host(&self, host_id: &str) -> fdo::Result<String> { ... }
//       async fn ssh_push_key(&self, key_id: &str, host_ids_json: &str, use_sudo: bool) -> fdo::Result<String> { ... }
//       async fn ssh_revoke_key(&self, key_id: &str, host_ids_json: &str, use_sudo: bool) -> fdo::Result<String> { ... }
//       async fn ssh_get_audit_log(&self, max_lines: u32) -> fdo::Result<Vec<String>> { ... }
//       async fn ssh_connect_command(&self, host_id: &str) -> fdo::Result<String> { ... }
//       async fn test_host_connection(&self, host_id: &str) -> fdo::Result<String> { ... }
//       async fn fortigate_push_ssh_key(&self, host_id: &str, key_id: &str, admin_user: &str) -> fdo::Result<String> { ... }
//       async fn ssh_start_port_forward(&self, host_id: &str, local_port: u16, remote_host: &str, remote_port: u16) -> fdo::Result<String> { ... }
//       async fn ssh_stop_port_forward(&self, forward_id: &str) -> fdo::Result<()> { ... }
//       async fn ssh_list_port_forwards(&self) -> fdo::Result<String> { ... }
//
//       // --- UniFi methods ---
//       async fn unifi_set_inform(&self, host_id: &str, inform_url: &str) -> fdo::Result<String> { ... }
//       async fn unifi_api(&self, host_id: &str, method: &str, path: &str, body: &str) -> fdo::Result<String> { ... }
//       async fn unifi_set_controller(&self, host_id: &str, url: &str, username: &str, password: &str) -> fdo::Result<()> { ... }
//
//       #[zbus(signal)]
//       async fn state_changed(ctx: &zbus::SignalContext<'_>, state_json: String) -> zbus::Result<()>;
//
//       #[zbus(signal)]
//       async fn stats_updated(ctx: &zbus::SignalContext<'_>, stats_json: String) -> zbus::Result<()>;
//
//       #[zbus(signal)]
//       async fn auth_challenge(ctx: &zbus::SignalContext<'_>, user_code: String, verification_url: String) -> zbus::Result<()>;
//
//       #[zbus(signal)]
//       async fn ssh_operation_progress(ctx: &zbus::SignalContext<'_>, operation_id: String, host_label: String, message: String) -> zbus::Result<()>;
//
//       async fn ssh_host_health(&self) -> fdo::Result<String> { ... }
//
//       // --- Config backup & restore ---
//       async fn export_all(&self) -> fdo::Result<String> { ... }
//       async fn import_all(&self, data: &str) -> fdo::Result<String> { ... }
//
//       // --- Config versioning ---
//       async fn save_config_version(&self, customer: &str, device_type: &str, config: &str) -> fdo::Result<String> { ... }
//       async fn list_config_versions(&self, customer: &str) -> fdo::Result<String> { ... }
//       async fn get_config_version(&self, filename: &str) -> fdo::Result<String> { ... }
//
//       // --- FortiGate CIS compliance ---
//       async fn fortigate_compliance_check(&self, host_id: &str) -> fdo::Result<String> { ... }
//
//       #[zbus(signal)]
//       async fn host_health_changed(ctx: &zbus::SignalContext<'_>, host_id: String, reachable: bool) -> zbus::Result<()>;
//   }

// ---------------------------------------------------------------------------
// Client-side proxy (used by the GUI)
// ---------------------------------------------------------------------------

/// Async D-Bus proxy for the `org.supermgr.Daemon1` interface.
///
/// Instantiate with [`DaemonProxy::new`] (provided by `zbus`) and await
/// individual method calls.  The proxy owns a zbus `Connection` internally.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> zbus::Result<()> {
/// use supermgr_core::dbus::DaemonProxyBlocking;
/// let conn = zbus::blocking::Connection::session()?;
/// let proxy = DaemonProxyBlocking::new(&conn)?;
/// let json = proxy.get_status()?;
/// # Ok(())
/// # }
/// ```
// `#[allow(missing_docs)]` suppresses lint errors on the internal helper types
// and methods that `#[zbus::proxy]` generates and that we cannot doc-comment.
#[allow(missing_docs)]
#[zbus::proxy(
    interface = "org.supermgr.Daemon1",
    default_service = "org.supermgr.Daemon",
    default_path = "/org/supermgr/Daemon"
)]
pub trait Daemon {
    // =======================================================================
    // VPN methods
    // =======================================================================

    /// Return a JSON array of [`crate::vpn::profile::ProfileSummary`] objects.
    ///
    /// The GUI deserialises the string with [`crate::vpn::profile::ProfileSummary`].
    async fn list_profiles(&self) -> fdo::Result<String>;

    /// Initiate a connection for the profile identified by `profile_id` (UUID string).
    ///
    /// Returns immediately; the actual connection runs asynchronously in the
    /// daemon.  Listen for [`Self::receive_state_changed`] to track progress.
    async fn connect(&self, profile_id: &str) -> fdo::Result<()>;

    /// Tear down the active tunnel (no-op if already disconnected).
    async fn disconnect(&self) -> fdo::Result<()>;

    /// Return the current [`crate::vpn::state::VpnState`] serialised as JSON.
    async fn get_status(&self) -> fdo::Result<String>;

    /// Return recent daemon log lines from the in-memory ring buffer.
    ///
    /// Each element is a pre-formatted string `[HH:MM:SS] LEVEL target: message`.
    /// Returns up to 500 lines, oldest first.
    async fn get_logs(&self) -> fdo::Result<Vec<String>>;

    /// Clear the in-memory log buffer.
    async fn clear_logs(&self) -> fdo::Result<()>;

    /// Dynamically change the daemon's tracing log level at runtime.
    ///
    /// `level` is a tracing filter directive, e.g. `"error"`, `"warn"`,
    /// `"info"`, `"debug"`, or `"trace"`.
    async fn set_log_level(&self, level: &str) -> fdo::Result<()>;

    /// Return live tunnel statistics as a compact JSON object.
    ///
    /// JSON shape: `{"bytes_sent": u64, "bytes_received": u64, "last_handshake_secs": u64}`
    ///
    /// `last_handshake_secs` is a Unix epoch timestamp; `0` means no handshake
    /// has been observed yet or no tunnel is active.
    async fn get_stats(&self) -> fdo::Result<String>;

    /// Import a WireGuard `.conf` file.
    ///
    /// `conf_text` is the raw file contents; `name` is the desired display name.
    /// Returns the new profile's UUID string on success.
    ///
    /// The daemon will parse the config, store the private key in the system
    /// keyring, and persist the profile to disk.
    async fn import_wireguard(&self, conf_text: &str, name: &str) -> fdo::Result<String>;

    /// Delete a profile by UUID string.
    ///
    /// Fails with `org.freedesktop.DBus.Error.Failed` if the profile is
    /// currently connected.
    async fn delete_profile(&self, profile_id: &str) -> fdo::Result<()>;

    /// Rename a profile identified by `profile_id` to `new_name`.
    async fn rename_profile(&self, profile_id: &str, new_name: &str) -> fdo::Result<()>;

    /// Set the `auto_connect` flag on a profile.
    ///
    /// When `true` the daemon will automatically connect this profile when
    /// NetworkManager reports the network is available (e.g. after resume from
    /// suspend).  Only one profile should have `auto_connect = true` at a time;
    /// if multiple profiles have the flag set, the daemon picks the first one
    /// it finds.
    ///
    /// The change is persisted to the profile's TOML file immediately.
    async fn set_auto_connect(&self, profile_id: &str, auto_connect: bool) -> fdo::Result<()>;

    /// Update a FortiGate profile's connection settings.
    ///
    /// Non-empty `password` / `psk` overwrite the stored secret; empty strings
    /// leave the existing secret unchanged.
    ///
    /// `dns_servers` is a comma- or whitespace-separated list of IPv4/IPv6
    /// addresses that overrides the FortiGate's mode-config-pushed DNS.
    /// Pass an empty string to clear any previous override and revert to
    /// using mode-config DNS.
    async fn update_fortigate(
        &self,
        profile_id: &str,
        name: &str,
        host: &str,
        username: &str,
        password: &str,
        psk: &str,
        dns_servers: &str,
    ) -> fdo::Result<()>;

    /// Update an OpenVPN profile's credentials.
    ///
    /// A non-empty `password` overwrites the stored secret; an empty string
    /// leaves the existing secret unchanged.
    async fn update_openvpn_credentials(
        &self,
        profile_id: &str,
        username: &str,
        password: &str,
    ) -> fdo::Result<()>;

    /// Set the `full_tunnel` flag on a profile.
    ///
    /// `true`  → route all traffic through the VPN when connected.
    /// `false` → use only the backend-specific split-tunnel routes.
    ///
    /// The change is persisted to the profile's TOML file immediately.
    /// If the profile is currently connected the change takes effect on the
    /// next reconnect.
    async fn set_full_tunnel(&self, profile_id: &str, full_tunnel: bool) -> fdo::Result<()>;

    /// Set the kill-switch flag on a profile.
    ///
    /// When `true` all non-VPN traffic is blocked via nftables while this
    /// profile is connected.
    ///
    /// The change is persisted to the profile's TOML file immediately.
    async fn set_kill_switch(&self, profile_id: &str, enabled: bool) -> fdo::Result<()>;

    /// Set or clear the customer/tenant tag on a VPN profile.
    ///
    /// Pass an empty string to clear the tag (un-group the profile).
    /// The change is persisted to the profile's TOML file immediately.
    async fn set_profile_customer(
        &self,
        profile_id: &str,
        customer: &str,
    ) -> fdo::Result<()>;

    /// Set the split-tunnel route list for a WireGuard profile.
    ///
    /// `routes` is a list of CIDR strings (e.g. `["10.0.0.0/8", "192.168.1.0/24"]`).
    /// These replace the catch-all `0.0.0.0/0` when `full_tunnel = false` is active.
    /// Passing an empty list clears split routes (split-tunnel will then fall back
    /// to whatever explicit prefixes are in the peer's AllowedIPs after stripping
    /// catch-alls, which may cause a connect-time error if none remain).
    ///
    /// Only valid for WireGuard profiles; returns an error for other backends.
    async fn set_split_routes(
        &self,
        profile_id: &str,
        routes: Vec<String>,
    ) -> fdo::Result<()>;

    /// Create a new FortiGate IPsec/IKEv2 profile and persist it to disk.
    ///
    /// `name` is the display name; `host` is the appliance hostname or IP;
    /// `username` / `password` are the EAP-MSCHAPv2 credentials; `psk` is
    /// the group pre-shared key for IKE SA authentication.
    ///
    /// `dns_servers` is a comma- or whitespace-separated list of IPv4/IPv6
    /// addresses to push to systemd-resolved on connect. Pass an empty
    /// string to fall back to whatever DNS servers the FortiGate sends
    /// during IKE mode-config negotiation.
    ///
    /// Returns the new profile's UUID string on success.
    async fn import_fortigate(
        &self,
        name: &str,
        host: &str,
        username: &str,
        password: &str,
        psk: &str,
        dns_servers: &str,
    ) -> fdo::Result<String>;

    /// Import an OpenVPN `.ovpn` configuration file.
    ///
    /// `conf_text` is the raw `.ovpn` file contents; `name` is the desired
    /// display name.  `username` and `password` are optional credentials —
    /// pass empty strings to import without credentials.
    /// Returns the new profile's UUID string on success.
    async fn import_openvpn(
        &self,
        conf_text: &str,
        name: &str,
        username: &str,
        password: &str,
    ) -> fdo::Result<String>;

    /// Import an Azure Point-to-Site VPN profile from the XML config files
    /// that Azure downloads as a zip archive.
    ///
    /// `azure_xml` is the contents of `AzureVPN/azurevpnconfig.xml`;
    /// `vpn_settings_xml` is the contents of `Generic/VpnSettings.xml`.
    /// `name` is the desired display name (pre-filled from `<name>` in the XML
    /// is a sensible default).
    ///
    /// Returns the new profile's UUID string on success.
    async fn import_azure_vpn(
        &self,
        azure_xml: &str,
        vpn_settings_xml: &str,
        name: &str,
    ) -> fdo::Result<String>;

    /// Import a TOML configuration file (VPN profile, SSH key, or SSH host).
    ///
    /// Auto-detects the type based on TOML content.  Returns a JSON object
    /// with `{ "type": "vpn"|"ssh_key"|"ssh_host", "id": "<uuid>" }`.
    async fn import_toml(&self, toml_text: &str) -> fdo::Result<String>;

    /// Rotate the WireGuard private key for the given profile.
    ///
    /// Generates a new key pair, overwrites the stored private key in the
    /// secret service, and returns the new base64-encoded public key.
    async fn rotate_wireguard_key(&self, profile_id: &str) -> fdo::Result<String>;

    /// Export a profile as a TOML string (secrets replaced by their labels).
    ///
    /// Returns the serialised TOML text of the profile.  Secrets are stored
    /// as `SecretRef` labels (not raw values), so the output is safe to share.
    async fn export_profile(&self, profile_id: &str) -> fdo::Result<String>;

    // =======================================================================
    // SSH methods
    // =======================================================================

    /// Generate a new SSH key pair of the given type.
    ///
    /// `key_type` is one of `"ed25519"`, `"ecdsa"`, `"rsa"`.
    /// `tags_json` is a JSON array of tag strings (e.g. `["prod", "web"]`).
    /// Returns the new key's UUID string on success.
    async fn ssh_generate_key(
        &self,
        key_type: &str,
        name: &str,
        description: &str,
        tags_json: &str,
    ) -> fdo::Result<String>;

    /// Scan a directory for existing SSH key files and return a JSON array of
    /// discovered key metadata (paths, types, fingerprints).
    async fn ssh_import_keys_scan(&self, directory: &str) -> fdo::Result<String>;

    /// Import an existing SSH key pair into the managed store.
    ///
    /// `public_key` is the contents of the `.pub` file; `private_key_pem` is
    /// the PEM-encoded private key.  `key_type` is `"ed25519"`, `"ecdsa"`, or
    /// `"rsa"`.  Returns the new key's UUID string on success.
    async fn ssh_import_key(
        &self,
        name: &str,
        public_key: &str,
        private_key_pem: &str,
        key_type: &str,
    ) -> fdo::Result<String>;

    /// Delete an SSH key by UUID string.
    async fn ssh_delete_key(&self, key_id: &str) -> fdo::Result<()>;

    /// Return a JSON array of [`crate::ssh::key::SshKeySummary`] objects.
    async fn ssh_list_keys(&self) -> fdo::Result<String>;

    /// List nodes in the local tailnet via `tailscale status --json`.
    ///
    /// Returns a JSON array of TailscaleNode objects (defined in the
    /// daemon's `tailscale` module). Errors string-wise when the
    /// tailscale CLI isn't installed or tailscaled isn't running.
    async fn tailscale_list_nodes(&self) -> fdo::Result<String>;

    /// Return the full [`crate::ssh::key::SshKey`] serialised as JSON.
    async fn ssh_get_key(&self, key_id: &str) -> fdo::Result<String>;

    /// Return the public key in OpenSSH `authorized_keys` format.
    async fn ssh_export_public_key(&self, key_id: &str) -> fdo::Result<String>;

    /// Return the PEM-encoded private key (retrieved from the secret store).
    async fn ssh_export_private_key(&self, key_id: &str) -> fdo::Result<String>;

    /// Add a new SSH host from a JSON-serialised
    /// [`crate::host::Host`] object.
    ///
    /// Returns the new host's UUID string on success.
    async fn add_host(&self, host_json: &str) -> fdo::Result<String>;

    /// Update an existing SSH host.
    ///
    /// `host_json` is the full JSON-serialised host object with updated fields.
    async fn update_host(&self, host_id: &str, host_json: &str) -> fdo::Result<()>;

    /// Toggle the pinned/favourite state of an SSH host.
    ///
    /// Flips `pinned` and returns the refreshed host list as a JSON array of
    /// [`crate::host::HostSummary`] objects.
    async fn toggle_host_pin(&self, host_id: &str) -> fdo::Result<String>;

    /// Set or clear the customer/tenant tag on an SSH host.
    ///
    /// Pass an empty string to clear the tag.
    async fn ssh_set_host_customer(
        &self,
        host_id: &str,
        customer: &str,
    ) -> fdo::Result<()>;

    // =======================================================================
    // Per-customer documentation export
    // =======================================================================

    /// Return a JSON array of distinct customer tags currently in use across
    /// VPN profiles and SSH hosts. Sorted, case-insensitively deduplicated.
    async fn list_customers(&self) -> fdo::Result<String>;

    /// Render a Markdown documentation snapshot for `customer`.
    ///
    /// Matching is case-insensitive on the trimmed input. Pass an empty
    /// string to render an "Ungrouped" report covering every profile and
    /// host whose customer tag is empty.
    async fn export_customer_docs(&self, customer: &str) -> fdo::Result<String>;

    /// Delete an SSH host by UUID string.
    async fn delete_host(&self, host_id: &str) -> fdo::Result<()>;

    /// Return a JSON array of [`crate::host::HostSummary`] objects.
    async fn list_hosts(&self) -> fdo::Result<String>;

    /// Return the full [`crate::host::Host`] serialised as JSON.
    async fn get_host(&self, host_id: &str) -> fdo::Result<String>;

    /// Push a public key to one or more remote hosts' `authorized_keys`.
    ///
    /// `host_ids_json` is a JSON array of host UUID strings.
    /// `use_sudo` controls whether `sudo` is used on the remote side.
    /// Returns a JSON object with per-host results.
    async fn ssh_push_key(
        &self,
        key_id: &str,
        host_ids_json: &str,
        use_sudo: bool,
    ) -> fdo::Result<String>;

    /// Revoke (remove) a public key from one or more remote hosts'
    /// `authorized_keys`.
    ///
    /// `host_ids_json` is a JSON array of host UUID strings.
    /// `use_sudo` controls whether `sudo` is used on the remote side.
    /// Returns a JSON object with per-host results.
    async fn ssh_revoke_key(
        &self,
        key_id: &str,
        host_ids_json: &str,
        use_sudo: bool,
    ) -> fdo::Result<String>;

    /// Return recent SSH audit log entries.
    ///
    /// Each element is a pre-formatted log line.  Returns up to `max_lines`
    /// entries, newest first.
    async fn ssh_get_audit_log(&self, max_lines: u32) -> fdo::Result<Vec<String>>;

    /// Store an SSH password for the given host.
    async fn ssh_get_password(&self, host_id: &str) -> fdo::Result<String>;
    async fn ssh_set_password(&self, host_id: &str, password: &str) -> fdo::Result<()>;

    /// Store an OpenSSH certificate for the given host (certificate auth).
    async fn ssh_set_certificate(&self, host_id: &str, certificate: &str) -> fdo::Result<()>;

    /// Store a FortiGate REST API token and port for the given host.
    /// Pass `port = 0` to keep the existing port.
    async fn ssh_set_api_token(&self, host_id: &str, token: &str, port: u16) -> fdo::Result<()>;

    /// Call the FortiGate REST API on a host.
    ///
    /// `method` is GET, POST, PUT, or DELETE.  `path` is the API path
    /// (e.g. `/api/v2/cmdb/system/admin/admin`).  `body` is optional JSON.
    /// Returns the JSON response body.
    async fn fortigate_api(
        &self,
        host_id: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> fdo::Result<String>;

    /// Push an SSH public key to a FortiGate admin user via REST API.
    ///
    /// `host_id` is the UUID of the FortiGate host with an API token configured.
    /// `key_id` is the UUID of the SSH key whose public key will be pushed.
    /// `admin_user` is the FortiGate admin username (e.g. `"admin"`).
    ///
    /// The key is set as `ssh-public-key1` on the admin user via
    /// `PUT /api/v2/cmdb/system/admin/{admin_user}`.
    async fn fortigate_push_ssh_key(
        &self,
        host_id: &str,
        key_id: &str,
        admin_user: &str,
    ) -> fdo::Result<String>;

    /// Execute a shell command on a remote SSH host.
    ///
    /// Returns a JSON object with `stdout`, `stderr`, and `exit_code`.
    async fn ssh_execute_command(&self, host_id: &str, command: &str) -> fdo::Result<String>;

    // =======================================================================
    // UniFi methods
    // =======================================================================

    /// Execute `set-inform <url>` on a UniFi device via SSH.
    ///
    /// Returns a JSON object with `stdout`, `stderr`, and `exit_code`.
    async fn unifi_set_inform(&self, host_id: &str, inform_url: &str) -> fdo::Result<String>;

    /// Call the UniFi Controller REST API on a host.
    ///
    /// `method` is GET, POST, PUT, or DELETE.  `path` is the API path
    /// (e.g. `/proxy/network/api/s/default/stat/device`).  `body` is optional JSON.
    /// Returns the JSON response body.
    async fn unifi_api(
        &self,
        host_id: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> fdo::Result<String>;

    /// Store UniFi Controller URL and credentials for a host.
    ///
    /// Validates the credentials by attempting to log in, then stores the URL
    /// and credentials securely.
    async fn unifi_set_controller(
        &self,
        host_id: &str,
        url: &str,
        username: &str,
        password: &str,
    ) -> fdo::Result<()>;

    // =======================================================================
    // OPNsense REST API
    // =======================================================================

    /// Store OPNsense API credentials (key + secret) for an SSH host.
    ///
    /// `port` is the HTTPS port (defaults to 443 if 0). `api_key` and
    /// `api_secret` are the values from OPNsense → System → Access → Users
    /// → API keys.
    ///
    /// Validates the credentials by issuing an authenticated probe; on
    /// success the credentials are persisted as a JSON blob in the system
    /// secret service and the host's `api_token_ref` / `api_port` fields
    /// are updated.
    async fn opnsense_set_credentials(
        &self,
        host_id: &str,
        port: u16,
        api_key: &str,
        api_secret: &str,
    ) -> fdo::Result<()>;

    /// Issue a Basic-Auth REST API call to an OPNsense host and return the
    /// raw response body as text.
    ///
    /// `method` is one of `GET`, `POST`, `PUT`, `DELETE`. `path` is the
    /// URL path including the leading `/api/...`. `body` is sent as
    /// JSON for non-GET methods.
    async fn opnsense_api(
        &self,
        host_id: &str,
        method: &str,
        path: &str,
        body: &str,
    ) -> fdo::Result<String>;

    /// Composite "is this OPNsense alive" status snapshot for the dashboard.
    ///
    /// Returns the `OpnSenseStatus` struct (defined in the daemon's
    /// `opnsense` module) serialised as JSON. Each field is optional; an
    /// individual endpoint failure does not fail the whole call.
    async fn opnsense_get_status(&self, host_id: &str) -> fdo::Result<String>;

    /// Download the OPNsense running config and save it under
    /// `/etc/supermgrd/backups/<safe_host>_<ts>.opnsense.xml`.
    /// Returns the filename written.
    async fn opnsense_backup_config(&self, host_id: &str) -> fdo::Result<String>;

    // =======================================================================
    // Sophos XML Configuration API
    // =======================================================================

    /// Store Sophos WebAdmin credentials for an SSH host and validate them.
    ///
    /// Sophos has no token endpoint; the username and password are stored as
    /// a JSON blob in the system secret service and resent on every API call
    /// inside the `<Login>` block of the XML envelope.
    ///
    /// `port` defaults to 4444 (the conventional WebAdmin HTTPS port) if 0.
    async fn sophos_set_credentials(
        &self,
        host_id: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> fdo::Result<()>;

    /// Send a Sophos XML Configuration API operation.
    ///
    /// `inner_xml` is the operation body (`<Get>...</Get>`, `<Set>...</Set>`,
    /// `<Remove>...</Remove>`). The daemon adds the `<Request>` envelope and
    /// `<Login>` block. The caller is responsible for XML-escaping any
    /// user-supplied values inside `inner_xml`.
    ///
    /// Sophos always returns HTTP 200; success/failure is encoded in the
    /// `<Status code="N">` tag of the response body, which is returned
    /// verbatim.
    async fn sophos_xml_api(
        &self,
        host_id: &str,
        inner_xml: &str,
    ) -> fdo::Result<String>;

    // =======================================================================
    // SSH port forwarding
    // =======================================================================

    /// Start a local TCP port forward through an SSH tunnel.
    ///
    /// Binds `local_port` on localhost, and for each accepted connection opens
    /// an SSH direct-tcpip channel to `remote_host:remote_port`.
    /// Returns a unique forward ID string that can be passed to
    /// [`Self::ssh_stop_port_forward`] to tear it down.
    async fn ssh_start_port_forward(
        &self,
        host_id: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> fdo::Result<String>;

    /// Stop an active port forward by its forward ID.
    async fn ssh_stop_port_forward(&self, forward_id: &str) -> fdo::Result<()>;

    /// List all active port forwards as a JSON array.
    ///
    /// Each element: `{"forward_id":"...","host_id":"...","local_port":N,"remote_host":"...","remote_port":N}`
    async fn ssh_list_port_forwards(&self) -> fdo::Result<String>;

    /// Return the SSH command string for connecting to the given host.
    ///
    /// The returned string is suitable for `std::process::Command` or display
    /// to the user (e.g. `"ssh -i /path/to/key user@host -p 22"`).
    async fn ssh_connect_command(&self, host_id: &str) -> fdo::Result<String>;

    /// Test SSH and (optionally) FortiGate API connectivity for a host.
    ///
    /// Returns a JSON object like `{"ssh": "ok", "api": "ok"}` or
    /// `{"ssh": "timeout", "api": "auth_failed"}`.
    async fn test_host_connection(&self, host_id: &str) -> fdo::Result<String>;

    // =======================================================================
    // Config versioning
    // =======================================================================

    /// Save a generated config with a timestamp for later comparison.
    ///
    /// Returns the filename under which the config was stored.
    async fn save_config_version(
        &self,
        customer: &str,
        device_type: &str,
        config: &str,
    ) -> fdo::Result<String>;

    /// List saved config versions for a customer.
    ///
    /// Returns a JSON array of `{"filename": "...", "timestamp": "..."}` objects,
    /// newest first.
    async fn list_config_versions(&self, customer: &str) -> fdo::Result<String>;

    /// Retrieve a previously saved config version by filename.
    async fn get_config_version(&self, filename: &str) -> fdo::Result<String>;

    // =======================================================================
    // Signals
    // =======================================================================

    /// Emitted whenever the daemon transitions to a new [`crate::vpn::state::VpnState`].
    ///
    /// `state_json` is the new state serialised as JSON.
    #[zbus(signal)]
    fn state_changed(&self, state_json: String) -> fdo::Result<()>;

    /// Emitted periodically (every ~5 s) while a tunnel is active.
    ///
    /// `stats_json` is a [`crate::vpn::state::TunnelStats`] serialised as JSON.
    #[zbus(signal)]
    fn stats_updated(&self, stats_json: String) -> fdo::Result<()>;

    /// Emitted by the daemon during an Azure Entra ID connection when the
    /// user must complete a device-code authentication challenge.
    ///
    /// The GUI should display `user_code` prominently and tell the user to
    /// visit `verification_url` (typically `https://microsoft.com/devicelogin`)
    /// in a browser.  The code expires after ~15 minutes.
    #[zbus(signal)]
    fn auth_challenge(&self, user_code: String, verification_url: String) -> fdo::Result<()>;

    /// Emitted during multi-host SSH operations (push/revoke) to report
    /// per-host progress.
    ///
    /// `operation_id` is a unique identifier for the batch operation;
    /// `host_label` identifies which host this update concerns;
    /// `message` is a human-readable status string.
    #[zbus(signal)]
    fn ssh_operation_progress(
        &self,
        operation_id: String,
        host_label: String,
        message: String,
    ) -> fdo::Result<()>;

    // =======================================================================
    // SSH health check
    // =======================================================================

    /// Return a JSON map of `host_id → reachable(bool)` for all SSH hosts.
    async fn ssh_host_health(&self) -> fdo::Result<String>;

    // =======================================================================
    // Config backup & restore
    // =======================================================================

    /// Export all configuration (profiles, SSH keys, SSH hosts) as a single
    /// JSON string.  Secret values are not included -- only `SecretRef` labels.
    async fn export_all(&self) -> fdo::Result<String>;

    /// Import configuration from a JSON backup string produced by
    /// [`Self::export_all`].  Each imported item receives a new UUID.
    /// Returns a JSON summary `{"profiles": N, "ssh_keys": N, "hosts": N}`.
    async fn import_all(&self, data: &str) -> fdo::Result<String>;

    // =======================================================================
    // FortiGate config backup
    // =======================================================================

    /// Download the FortiGate running config and save it to disk.
    ///
    /// Calls `GET /api/v2/monitor/system/config/backup?scope=global` and writes
    /// the result to `/etc/supermgrd/backups/{hostname}_{timestamp}.conf`.
    /// Returns the filename on success.
    async fn fortigate_backup_config(&self, host_id: &str) -> fdo::Result<String>;

    /// Run CIS benchmark compliance checks against a FortiGate device via SSH.
    ///
    /// Returns a JSON object with individual check results and a summary score:
    /// `{ "checks": [...], "score": "8/10", "passed": 8, "failed": 2, "total": 10 }`.
    async fn fortigate_compliance_check(&self, host_id: &str) -> fdo::Result<String>;

    /// Generate a new FortiGate REST API token via SSH.
    ///
    /// Creates the API user if needed, generates a key, stores it in the
    /// secret store, and returns the token string.
    async fn fortigate_generate_api_token(
        &self,
        host_id: &str,
        api_user: &str,
        api_port: u16,
    ) -> fdo::Result<String>;

    /// Retrieve the stored FortiGate API token (for clipboard copy / docs).
    async fn fortigate_get_api_token(&self, host_id: &str) -> fdo::Result<String>;

    // =======================================================================
    // Webhook / notification methods
    // =======================================================================

    /// Configure outgoing webhook notifications.
    ///
    /// `url` is the incoming-webhook URL (empty string to disable).
    /// `on_host_down` and `on_vpn_disconnect` control which events fire.
    async fn set_webhook(
        &self,
        url: String,
        on_host_down: bool,
        on_vpn_disconnect: bool,
    ) -> fdo::Result<()>;

    /// Return the current webhook configuration as JSON.
    ///
    /// Shape: `{"url":"...","on_host_down":true,"on_vpn_disconnect":false}`
    async fn get_webhook_config(&self) -> fdo::Result<String>;

    /// Send a test message to the configured webhook URL.
    async fn test_webhook(&self) -> fdo::Result<String>;

    // =======================================================================
    // Signals
    // =======================================================================

    /// Emitted when the reachability of an SSH host changes.
    #[zbus(signal)]
    fn host_health_changed(
        &self,
        host_id: String,
        reachable: bool,
    ) -> fdo::Result<()>;
}
