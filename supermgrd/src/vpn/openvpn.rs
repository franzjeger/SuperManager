//! OpenVPN3 backend — manages sessions via the `openvpn3` CLI tool.
//!
//! # Lifecycle
//!
//! 1. `connect`:
//!    a. If credentials are configured, write a temporary `.ovpn` with an
//!       `<auth-user-pass>` inline block appended.
//!    b. Run `openvpn3 config-import --config <tmp> --name <uuid>` to load
//!       the configuration into the openvpn3 config manager.  The temp file
//!       is deleted immediately after import.
//!    c. Run `openvpn3 config-manage --config <uuid> --allow-compression asym`
//!       so the client accepts server-pushed compression (VORACLE-safe: only
//!       receives compressed, never sends).
//!    d. Run `openvpn3 session-start --config <uuid> --background`.
//!       Parse the session path from stdout.
//! 2. `disconnect`:
//!    a. `openvpn3 session-manage --session-path <path> --disconnect`
//!    b. `openvpn3 config-remove --config <uuid> --force`
//! 3. `status`: checks `openvpn3 sessions-list` for the stored session path.

use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use supermgr_core::{
    vpn::backend::{BackendStatus, Capabilities, VpnBackend},
    error::BackendError,
    vpn::profile::{Profile, ProfileConfig},
    vpn::state::TunnelStats,
};

use crate::secrets;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Base directory for temporary credential files.
fn runtime_dir() -> PathBuf {
    if nix::unistd::getuid().is_root() {
        PathBuf::from("/run/supermgrd")
    } else {
        std::env::temp_dir().join("supermgrd")
    }
}

/// Parse `openvpn3 session-stats --json` output into [`TunnelStats`].
///
/// The JSON is a flat object: `{ "TUN_BYTES_IN": 12345, "TUN_BYTES_OUT": 67890, ... }`.
/// Returns zeroed stats if parsing fails.
fn parse_session_stats(json: &str) -> TunnelStats {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return TunnelStats::default();
    };
    TunnelStats {
        bytes_sent: v["TUN_BYTES_OUT"].as_u64().unwrap_or(0),
        bytes_received: v["TUN_BYTES_IN"].as_u64().unwrap_or(0),
        ..TunnelStats::default()
    }
}

/// Return the first `inet` address assigned to `iface` (e.g. `10.1.2.3/24`),
/// or an empty string if the interface has no IP or `ip` is unavailable.
async fn iface_virtual_ip(iface: &str) -> String {
    if iface.is_empty() {
        return String::new();
    }
    let Ok(out) = tokio::process::Command::new("ip")
        .args(["addr", "show", "dev", iface])
        .output()
        .await
    else {
        return String::new();
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| {
            let l = l.trim();
            if l.starts_with("inet ") {
                l.split_whitespace().nth(1).map(str::to_owned)
            } else {
                None
            }
        })
        .unwrap_or_default()
}

/// Return all routes currently installed for `iface` as CIDR strings.
async fn iface_routes(iface: &str) -> Vec<String> {
    if iface.is_empty() {
        return Vec::new();
    }
    let Ok(out) = tokio::process::Command::new("ip")
        .args(["route", "show", "dev", iface])
        .output()
        .await
    else {
        return Vec::new();
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .filter(|s| !s.is_empty() && s != "default")
        .collect()
}

/// Run an `openvpn3` subcommand and return (stdout, stderr, success).
async fn run_openvpn3(args: &[&str]) -> Result<(String, String, bool), BackendError> {
    let out = tokio::process::Command::new("openvpn3")
        .args(args)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BackendError::Interface("openvpn3 not found — please install openvpn3".into())
            } else {
                BackendError::Io(e)
            }
        })?;
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    ))
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Ov3State {
    /// D-Bus session path returned by `openvpn3 session-start`.
    session_path: Option<String>,
    /// Configuration name used with `openvpn3 config-import --name`.
    /// Kept so we can remove it from the config manager on disconnect.
    config_name: Option<String>,
    /// Kernel tun interface name (e.g. `tun0`), set once the tunnel reaches
    /// CONNECTED state.  Cached here so `status()` can return it without
    /// re-parsing `sessions-list` on every poll tick.
    interface: Option<String>,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// OpenVPN3 backend — wraps the `openvpn3` CLI.
pub struct OpenVpnBackend {
    state: Arc<Mutex<Ov3State>>,
}

impl OpenVpnBackend {
    /// Create a new, idle OpenVPN3 backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(Ov3State::default())),
        }
    }
}

#[async_trait]
impl VpnBackend for OpenVpnBackend {
    async fn connect(&self, profile: &Profile) -> Result<(), BackendError> {
        let cfg = match &profile.config {
            ProfileConfig::OpenVpn(c) => c,
            _ => return Err(BackendError::Interface("wrong profile type".into())),
        };

        info!("OpenVPN3: starting session for '{}'", profile.name);

        let run_dir = runtime_dir();
        tokio::fs::create_dir_all(&run_dir)
            .await
            .map_err(BackendError::Io)?;

        // Build temp config file, applying full_tunnel override and credentials.
        //
        // full_tunnel=true  → ensure redirect-gateway def1 is present
        // full_tunnel=false → strip any redirect-gateway directives (split-tunnel;
        //                     routes defined in the .ovpn file are kept as-is)
        let apply_full_tunnel_override = |base: &str| -> String {
            let has_redirect = base.lines().any(|l| {
                let l = l.trim();
                l.starts_with("redirect-gateway") || l.starts_with("push redirect-gateway")
            });
            if profile.full_tunnel && !has_redirect {
                format!("{base}\nredirect-gateway def1\n")
            } else if !profile.full_tunnel {
                base.lines()
                    .filter(|l| !l.trim().starts_with("redirect-gateway"))
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n"
            } else {
                base.to_owned()
            }
        };

        let (temp_path, temp_file) = if let (Some(user), Some(pw_ref)) =
            (&cfg.username, &cfg.password)
        {
            match secrets::retrieve_secret(pw_ref.label()).await {
                Ok(pw_bytes) => {
                    let pw = String::from_utf8_lossy(&pw_bytes);
                    let base = tokio::fs::read_to_string(&cfg.config_file)
                        .await
                        .map_err(BackendError::Io)?;
                    let base = apply_full_tunnel_override(&base);
                    let with_creds = format!(
                        "{base}\n<auth-user-pass>\n{user}\n{pw}\n</auth-user-pass>\n"
                    );
                    let id_prefix = profile.id.simple().to_string();
                    let tmp = run_dir.join(format!("ovpn-{}.tmp.ovpn", &id_prefix[..8]));
                    tokio::fs::write(&tmp, with_creds.as_bytes())
                        .await
                        .map_err(BackendError::Io)?;
                    (tmp.to_string_lossy().into_owned(), Some(tmp))
                }
                Err(e) => {
                    warn!("OpenVPN3: could not retrieve password from keyring: {e}");
                    // Fall through to the no-credentials path for the override.
                    ("".to_owned(), None)
                }
            }
        } else {
            ("".to_owned(), None)
        };

        // If no temp file was created yet (no credentials or keyring error),
        // still write one if the full_tunnel override needs to change the config.
        let (temp_path, temp_file) = if temp_path.is_empty() {
            let base = tokio::fs::read_to_string(&cfg.config_file)
                .await
                .map_err(BackendError::Io)?;
            let modified = apply_full_tunnel_override(&base);
            if modified == base {
                // No change needed — use the original file path directly.
                (cfg.config_file.clone(), None)
            } else {
                let id_prefix = profile.id.simple().to_string();
                let tmp = run_dir.join(format!("ovpn-{}.tmp.ovpn", &id_prefix[..8]));
                tokio::fs::write(&tmp, modified.as_bytes())
                    .await
                    .map_err(BackendError::Io)?;
                (tmp.to_string_lossy().into_owned(), Some(tmp))
            }
        } else {
            (temp_path, temp_file)
        };

        // Unique name for the imported config (profile UUID prefix).
        let config_name = format!("supermgr-{}", &profile.id.simple().to_string()[..8]);

        // Step 1 — import config into openvpn3 config manager.
        let (stdout, stderr, ok) = run_openvpn3(&[
            "config-import",
            "--config",
            &temp_path,
            "--name",
            &config_name,
        ])
        .await?;

        // Delete temp file immediately after import regardless of outcome.
        if let Some(tmp) = temp_file {
            let _ = tokio::fs::remove_file(tmp).await;
        }

        if !ok {
            return Err(BackendError::Interface(format!(
                "openvpn3 config-import failed: {}",
                stderr.trim()
            )));
        }
        info!("OpenVPN3: config imported as '{}': {}", config_name, stdout.trim());

        // Step 2 — allow server-pushed compression (asym = safe, no VORACLE risk).
        let (_, stderr, ok) = run_openvpn3(&[
            "config-manage",
            "--config",
            &config_name,
            "--allow-compression",
            "asym",
        ])
        .await?;

        if !ok {
            warn!("OpenVPN3: config-manage --allow-compression asym failed: {}", stderr.trim());
            // Non-fatal — proceed; server may not use compression.
        } else {
            info!("OpenVPN3: allow-compression asym set for '{}'", config_name);
        }

        // Step 3 — start the session.
        let (stdout, stderr, ok) =
            run_openvpn3(&["session-start", "--config", &config_name, "--background"]).await?;

        if !ok {
            // Best-effort cleanup of the imported config.
            let _ =
                run_openvpn3(&["config-remove", "--config", &config_name, "--force"]).await;
            return Err(BackendError::Interface(format!(
                "openvpn3 session-start failed: {}",
                stderr.trim()
            )));
        }

        // Parse "Session path: /net/openvpn/v3/sessions/..." from stdout.
        let session_path = stdout
            .lines()
            .find_map(|line| {
                line.strip_prefix("Session path:")
                    .map(str::trim)
                    .map(str::to_owned)
            })
            .ok_or_else(|| {
                BackendError::Interface(format!(
                    "could not parse session path from openvpn3 output: {}",
                    stdout.trim()
                ))
            })?;

        info!("OpenVPN3: session started at {session_path}; waiting for tunnel device…");

        // Store session path immediately so disconnect() can abort if needed.
        {
            let mut st = self.state.lock().await;
            st.session_path = Some(session_path.clone());
            st.config_name = Some(config_name.clone());
        }

        // Poll sessions-list until the session reaches a connected state or a
        // terminal failure.  `--background` returns while the session is still
        // CONNECTING, so we must wait here.
        //
        // Two success conditions are accepted:
        //   1. "Tunnel Device: tunX" appears  → classical tun-device mode.
        //   2. Status contains "Client connected" but no tun device is visible
        //      → openvpn3 DCO (Data Channel Offload) mode, where the data
        //      channel is handled entirely in the kernel without a userspace
        //      tun interface.  The session IS up; the interface (if any) will
        //      be discovered later by status() polling.
        //
        // Failure conditions: AUTH_FAILED, DISCONNECTED, FAILED in the status
        // line, or the session disappearing from sessions-list, or a 60-second
        // timeout without ever reaching "Client connected".
        let (tunnel_iface, session_connected, poll_last_status) = {
            const POLL_INTERVAL_MS: u64 = 200;
            const TIMEOUT_SECS: u64 = 60;
            const MAX_POLLS: u64 = TIMEOUT_SECS * 1000 / POLL_INTERVAL_MS;

            let mut iface = String::new();
            let mut connected = false;
            let mut last_status = String::new();

            'poll: for _ in 0..MAX_POLLS {
                tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;

                let (list_out, _, _) = match run_openvpn3(&["sessions-list"]).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                // Find the block for our session.
                if !list_out.contains(session_path.as_str()) {
                    // Session disappeared from sessions-list — treat as failure.
                    break 'poll;
                }

                // Extract status line and tunnel device from our session's block.
                let mut in_block = false;
                let mut status_line = String::new();
                let mut found_iface = String::new();

                for line in list_out.lines() {
                    if line.contains(session_path.as_str()) {
                        in_block = true;
                    }
                    if in_block {
                        let trimmed = line.trim();
                        if let Some(s) = trimmed.strip_prefix("Status:") {
                            status_line = s.trim().to_owned();
                        }
                        // openvpn3 sessions-list shows the device in two formats:
                        //   "Tunnel Device: tun0"   (standalone line, older builds)
                        //   "Owner: root   Device: tun0"  (same line as Owner, newer builds)
                        // Handle both by searching for "Device:" anywhere in the line.
                        if found_iface.is_empty() {
                            if let Some(pos) = trimmed.find("Device:") {
                                let after = trimmed[pos + "Device:".len()..].trim();
                                if !after.is_empty() && !after.starts_with("(not") {
                                    if let Some(name) = after.split_whitespace().next() {
                                        found_iface = name.to_owned();
                                    }
                                }
                            }
                        }
                        // A new session block starts with a blank line or another path.
                        if trimmed.is_empty() && in_block && !status_line.is_empty() {
                            break;
                        }
                    }
                }

                last_status = status_line.clone();

                // Log every status change so the daemon log shows progression.
                debug!("OpenVPN3: session status = '{status_line}', device = '{found_iface}'");

                // Check for terminal failure states.
                if status_line.contains("AUTH_FAILED")
                    || status_line.contains("DISCONNECTED")
                    || status_line.contains("FAILED")
                {
                    info!("OpenVPN3: terminal status '{status_line}' — stopping poll");
                    break 'poll;
                }

                // Success condition 1: tun device visible.
                if !found_iface.is_empty() && found_iface != "(not set)" {
                    iface = found_iface;
                    connected = true;
                    break 'poll;
                }

                // Success condition 2: openvpn3 reports "Client connected" even
                // without a visible tun device (DCO mode or delayed assignment).
                // Trust the session status rather than requiring a tun interface.
                if status_line.contains("Client connected") {
                    // found_iface may be empty or "(not set)" here; that is fine.
                    info!("OpenVPN3: status '{status_line}' — session connected (device='{found_iface}')");
                    connected = true;
                    break 'poll;
                }
            }

            (iface, connected, last_status)
        };

        if !session_connected {
            warn!(
                "OpenVPN3: session did not reach 'Client connected' within 60 s \
                 (last status: '{poll_last_status}') — cleaning up"
            );
            let _ = self.disconnect().await;
            return Err(BackendError::Interface(format!(
                "OpenVPN3 session failed to connect within 60 s \
                 (last status: '{poll_last_status}')"
            )));
        }

        if tunnel_iface.is_empty() {
            info!(
                "OpenVPN3: session connected (status: '{poll_last_status}'); \
                 no tun device visible (DCO mode or not yet assigned)"
            );
        } else {
            info!("OpenVPN3: tunnel device is {tunnel_iface}");
        }

        // Store the resolved interface (may be empty for DCO mode).
        // status() will fall back to sessions-list on each poll to discover
        // the interface if it was not known at connect time.
        {
            let mut st = self.state.lock().await;
            st.interface = if tunnel_iface.is_empty() {
                None
            } else {
                Some(tunnel_iface)
            };
        }

        Ok(())
    }

    async fn disconnect(&self) -> Result<(), BackendError> {
        let (session_path, config_name) = {
            let mut st = self.state.lock().await;
            st.interface = None;
            (st.session_path.take(), st.config_name.take())
        };

        if let Some(ref path) = session_path {
            info!("OpenVPN3: disconnecting session {path}");

            // First try a clean disconnect.
            let (_, stderr, ok) = run_openvpn3(&[
                "session-manage",
                "--session-path",
                path,
                "--disconnect",
            ])
            .await?;
            if !ok {
                warn!("openvpn3 session-manage disconnect: {}", stderr.trim());
            }

            // Verify the session is gone.  If it's still present (e.g. stuck in
            // CONNECTING), escalate to --abort which works in any state.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let (list_out, _, _) = run_openvpn3(&["sessions-list"]).await.unwrap_or_default();
            if list_out.contains(path.as_str()) {
                info!("OpenVPN3: session still present after disconnect; sending --abort");
                let (_, stderr, ok) = run_openvpn3(&[
                    "session-manage",
                    "--session-path",
                    path,
                    "--abort",
                ])
                .await?;
                if !ok {
                    warn!("openvpn3 session-manage abort: {}", stderr.trim());
                }
            }
        } else {
            debug!("OpenVPN3: disconnect called but no session path stored");
        }

        // Remove the imported config profile from the openvpn3 config manager.
        if let Some(ref name) = config_name {
            info!("OpenVPN3: removing config '{name}'");
            let (_, stderr, ok) =
                run_openvpn3(&["config-remove", "--config", name, "--force"]).await?;
            if !ok {
                warn!("openvpn3 config-remove: {}", stderr.trim());
            }
        }

        Ok(())
    }

    async fn status(&self) -> Result<BackendStatus, BackendError> {
        let (session_path, cached_iface) = {
            let st = self.state.lock().await;
            (st.session_path.clone(), st.interface.clone())
        };

        let Some(ref path) = session_path else {
            return Ok(BackendStatus::Inactive);
        };

        // Verify the session still exists.
        let (list_out, _, _) = run_openvpn3(&["sessions-list"]).await?;
        if !list_out.contains(path.as_str()) {
            return Ok(BackendStatus::Inactive);
        }

        // Parse the tunnel device name from the block for our session.
        // openvpn3 uses two formats depending on build:
        //   "Tunnel Device: tun0"   (standalone line)
        //   "Owner: root   Device: tun0"  (multi-field line)
        // Search for "Device:" anywhere in any line within the session block.
        let iface = {
            let mut found: Option<String> = None;
            let mut in_block = false;
            for line in list_out.lines() {
                if line.contains(path.as_str()) {
                    in_block = true;
                }
                if in_block {
                    let trimmed = line.trim();
                    if let Some(pos) = trimmed.find("Device:") {
                        let after = trimmed[pos + "Device:".len()..].trim();
                        if !after.is_empty() && !after.starts_with("(not") {
                            if let Some(name) = after.split_whitespace().next() {
                                found = Some(name.to_owned());
                                break;
                            }
                        }
                    }
                    if trimmed.is_empty() && in_block {
                        break;
                    }
                }
            }
            found.or(cached_iface).unwrap_or_default()
        };

        // Fetch live byte counters via session-stats --json.
        // TUN_BYTES_* reflect actual data through the tunnel (not VPN overhead).
        let stats = match run_openvpn3(&["session-stats", "--path", path, "--json"]).await {
            Ok((json, _, true)) => parse_session_stats(&json),
            _ => super::read_iface_stats(&iface), // fallback to sysfs
        };

        let virtual_ip = iface_virtual_ip(&iface).await;
        let active_routes = iface_routes(&iface).await;

        Ok(BackendStatus::Active {
            interface: iface,
            stats,
            virtual_ip,
            active_routes,
        })
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            split_tunnel: true,
            full_tunnel: true,
            dns_push: false,
            persistent_keepalive: false,
            config_import: true,
        }
    }

    fn name(&self) -> &'static str {
        "OpenVPN3"
    }
}
