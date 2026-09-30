//! WireGuard tunnel control for SuperManager's privileged helper.
//!
//! ## Architecture
//!
//! macOS doesn't have a kernel-mode WireGuard. The supported user-mode
//! implementation is **`wireguard-go`**, driven by the **`wg-quick`**
//! script that ships with `wireguard-tools`. Both run from the VPN runtime
//! the helper installs where only root can write (`vpn_runtime`), with
//! wg-quick run by the runtime's own bash; a development build without
//! the runtime uses Homebrew's.
//!
//! `wg-quick up <name>` reads `/etc/wireguard/<name>.conf`, asks
//! `wireguard-go` to spin up a `utun` device, then plumbs routes / DNS
//! according to the directives in the file. We need root to write to
//! `/etc/wireguard/` and to create routes — that's what this helper
//! provides.
//!
//! ## What the GUI sends us
//!
//! A complete rendered `.conf` body. The daemon (user-space) is what
//! owns the profile + secret store; it materialises the private key
//! and any peer pre-shared keys from the keyring, splices them into
//! the `[Interface]` / `[Peer]` blocks, and ships the whole rendered
//! string here. We never see secrets in any other shape.
//!
//! ## What lives on disk
//!
//! `/etc/wireguard/supermgr-<sanitized-profile-id>.conf`, mode 0600,
//! root:wheel. The leading `supermgr-` prefix is so multiple
//! WireGuard sources (e.g. the user's own pre-existing `wg0.conf`)
//! coexist without collision. The conf file is removed on disconnect
//! so credentials don't linger.
//!
//! ## No hooks
//!
//! `wg-quick` runs a config's `PreUp` / `PostUp` / `PreDown` / `PostDown`
//! lines as shell commands, as root. SuperManager renders its configs from
//! profile fields and never writes those, so a config that has them is
//! refused (`refuse_hooks`).
//!
//! ## Without wg-quick
//!
//! With `WgConnectArgs::native` the helper sets the tunnel up itself
//! (`wg_native`) and writes no config file. A tunnel it set up that way is
//! taken down that way, whichever way the next connect asks for.

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// `wg-quick` is a bash script that resolves the endpoint, starts
/// wireguard-go and edits routes and DNS; slow is possible, never finishing
/// is not. Under the WireGuard mutex, an unbounded run held every later RPC.
const WG_QUICK_BUDGET: u64 = 30;

/// Configs we write live here. Created lazily with mode 0700 so a
/// non-root local user can't peek at the directory listing.
///
/// We deliberately *don't* use this path with `wg-quick`'s implicit
/// resolver (`wg-quick up <name>`); we always pass the absolute path
/// (`wg-quick up /etc/wireguard/<name>.conf`) instead. Reason: brew
/// builds `wg-quick` with `CONFIG_PATH=/opt/homebrew/etc/wireguard/`
/// baked in, and `wg-quick down <name>` looks there first. Different
/// dirs for up vs. down is a way to never tear the tunnel back down.
/// Absolute paths sidestep the resolver entirely.
const WG_CONF_DIR: &str = "/etc/wireguard";

/// Lifetime-of-process WireGuard controller. `wg-quick` tracks the
/// tunnels it set up itself; the ones the helper set up without it
/// (`wg_native`) have their supervisors here.
#[derive(Default)]
pub struct WireGuard {
    native: HashMap<String, crate::wg_native::Tunnel>,
}

/// Arguments for `wg_connect`. Mirrors what the daemon sends.
#[derive(Debug, Deserialize)]
pub struct WgConnectArgs {
    /// UUID of the profile from the user-space daemon. Used to derive
    /// the interface / config-file name (sanitised to be valid for
    /// `utun` and the filesystem).
    pub profile_id: String,

    /// Full rendered `.conf` body — `[Interface]` block with
    /// `PrivateKey`, `Address`, `DNS`; one `[Peer]` per peer with
    /// `PublicKey`, `Endpoint`, `AllowedIPs`, optional `PresharedKey`.
    /// Daemon constructs this from the stored profile + secret store.
    pub conf_content: String,

    #[serde(default)]
    pub dns_servers: Vec<String>,

    /// Set the tunnel up without wg-quick (`wg_native`). Off unless the
    /// app's setting asks for it, until it has carried every kind of
    /// profile.
    #[serde(default)]
    pub native: bool,
}

#[derive(Debug, Deserialize)]
pub struct WgDisconnectArgs {
    pub profile_id: String,
}

#[derive(Debug, Deserialize)]
pub struct WgStatusArgs {
    pub profile_id: String,
}

#[derive(Debug, Serialize)]
pub struct WgConnectResult {
    pub success: bool,
    pub message: String,
    /// `utun3`-style interface name `wireguard-go` chose. Useful for
    /// the GUI to show "tunnel is on utunN" without us having to
    /// re-shell-out to look it up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WgDisconnectResult {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct WgStatusResult {
    pub state: WgState,
    /// Last received-bytes counter from `wg show`. Useful as a "is
    /// the tunnel actually moving traffic" sanity check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bytes: Option<u64>,
    /// Unix timestamp of the most recent handshake across all peers.
    /// `None` when no peer has handshaken yet (tunnel is up but the
    /// initial handshake hasn't completed) or when `wg show` couldn't
    /// be queried this poll. The GUI converts this to "12s ago" so
    /// the operator can spot a stale tunnel without `wg show`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake_unix: Option<i64>,
    /// Endpoint string of the peer with the freshest handshake.
    /// Format `<host-or-ip>:<port>`. Useful for the "where am I
    /// actually connected to" question when a profile lists multiple
    /// peers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WgState {
    Connected,
    Disconnected,
}

impl WireGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Supervise the tunnels an earlier helper set up without wg-quick.
    pub async fn adopt_native(&mut self) {
        self.native = crate::wg_native::adopt().await;
    }

    /// Take the tunnel `name` down if the helper set it up without
    /// wg-quick; None if it did not.
    async fn native_down(&mut self, name: &str) -> Option<anyhow::Result<()>> {
        let tunnel = self.native.remove(name);
        if tunnel.is_none() && !crate::wg_native::exists(name) {
            return None;
        }
        Some(crate::wg_native::down(name, tunnel).await)
    }

    async fn native_connect(&mut self, name: &str, args: &WgConnectArgs) -> WgConnectResult {
        // One an earlier wg-quick connect left has the private key in it.
        let _ = std::fs::remove_file(conf_path_for(name));
        match crate::wg_native::up(name, &args.conf_content).await {
            Ok((interface, tunnel)) => {
                self.native.insert(name.to_owned(), tunnel);
                if !args.dns_servers.is_empty() {
                    crate::dns::set_vpn_dns(&args.dns_servers);
                }
                WgConnectResult {
                    success: true,
                    message: format!("WireGuard tunnel '{name}' up on {interface}"),
                    interface: Some(interface),
                }
            }
            Err(e) => WgConnectResult {
                success: false,
                message: format!("{e:#}"),
                interface: None,
            },
        }
    }

    /// Bring the tunnel up. Idempotent — if a tunnel with this name
    /// already exists (e.g. a previous Connect that the GUI lost
    /// track of, or a wg-quick session left behind across an app
    /// restart), we tear it down first and rebuild with the new
    /// config, rather than refusing with "already exists."
    ///
    ///   1. If `/var/run/wireguard/<name>.name` exists, bring the
    ///      old tunnel down (best effort, ignore failures — we'll
    ///      catch the real problem at the up step).
    ///   2. Render the .conf to `/etc/wireguard/<name>.conf` (0600).
    ///   3. `wg-quick up /etc/wireguard/<name>.conf`.
    ///   4. Inspect `/var/run/wireguard/<name>.name` to determine
    ///      which `utunN` `wireguard-go` actually picked.
    pub async fn connect(&mut self, args: &WgConnectArgs) -> anyhow::Result<WgConnectResult> {
        refuse_hooks(&args.conf_content)?;
        let name = interface_name(&args.profile_id);
        let conf_path = conf_path_for(&name);

        // Step 1: pre-emptive cleanup of any leftover tunnel with the
        // same name. We can't trust the GUI's "Disconnected" state
        // to match reality — a daemon restart, a force-quit, or a
        // wg-quick mid-failure can leave the utun up while our state
        // says it's down. Tear it down silently rather than greet
        // the user with "already exists."
        if let Some(Err(e)) = self.native_down(&name).await {
            tracing::warn!("leftover WireGuard tunnel {name}: {e:#}");
        } else if read_name_mapping(&name).is_some() {
            let wg_quick = crate::vpn_runtime::wg_quick()?;
            let _ = crate::proc::bounded_async(
                wg_quick.command().arg("down").arg(&conf_path),
                WG_QUICK_BUDGET,
            )
            .await;
            // Belt-and-braces: if there's a residual utunN, force-
            // destroy it. wg-quick down can leave the device when
            // its bash bits choke on missing utilities.
            if let Some(utun) = read_name_mapping(&name) {
                let _ = crate::proc::bounded_async(
                    Command::new("/sbin/ifconfig").args([&utun, "destroy"]),
                    crate::proc::MUTATE,
                )
                .await;
                let _ = std::fs::remove_file(format!("/var/run/wireguard/{name}.name"));
                let _ = std::fs::remove_file(format!("/var/run/wireguard/{utun}.sock"));
            }
        }

        if args.native {
            return Ok(self.native_connect(&name, args).await);
        }
        let wg_quick = crate::vpn_runtime::wg_quick()?;

        // Make sure the parent dir exists with restrictive mode.
        std::fs::create_dir_all(WG_CONF_DIR).with_context(|| format!("create {WG_CONF_DIR}"))?;
        std::fs::set_permissions(
            WG_CONF_DIR,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .with_context(|| format!("chmod 700 {WG_CONF_DIR}"))?;

        // Write the conf with mode 0600 + root:wheel ownership.
        std::fs::write(&conf_path, &args.conf_content)
            .with_context(|| format!("write {}", conf_path.display()))?;
        std::fs::set_permissions(
            &conf_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .with_context(|| format!("chmod 600 {}", conf_path.display()))?;

        // Run `wg-quick up /etc/wireguard/<name>.conf` — absolute path,
        // not `wg-quick up <name>`. wg-quick on Mac (brew build) has
        // `CONFIG_PATH=/opt/homebrew/etc/wireguard` baked in, so the
        // bare-name path resolves there, not in `/etc/wireguard`.
        // Passing the absolute path bypasses the search.
        let output = crate::proc::bounded_async(
            wg_quick.command().arg("up").arg(&conf_path),
            WG_QUICK_BUDGET,
        )
        .await
        .with_context(|| format!("run {}", wg_quick.describe()))?;

        if !output.status.success() {
            // Best-effort cleanup so the next attempt isn't poisoned
            // by a half-up state.
            let _ = std::fs::remove_file(&conf_path);
            return Ok(WgConnectResult {
                success: false,
                message: format!(
                    "wg-quick up failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                interface: None,
            });
        }

        let interface = detect_interface(&name).await.ok();

        if !args.dns_servers.is_empty() {
            crate::dns::set_vpn_dns(&args.dns_servers);
        }

        Ok(WgConnectResult {
            success: true,
            message: format!("WireGuard tunnel '{name}' up"),
            interface,
        })
    }

    /// Bring the tunnel down + delete the conf.
    ///
    /// We try `wg-quick down <name>` first — that's the clean path
    /// (clears routes, restores DNS, drops the utun device). If
    /// `wg-quick` fails or refuses (bash version, missing utility,
    /// stale state), we fall back to manually destroying the
    /// matching `utunN` device + cleaning up the mapping files.
    /// Either way, the conf file is unlinked at the end so a
    /// half-failed teardown doesn't leave the private key on disk.
    pub async fn disconnect(
        &mut self,
        args: &WgDisconnectArgs,
    ) -> anyhow::Result<WgDisconnectResult> {
        let name = interface_name(&args.profile_id);
        if let Some(result) = self.native_down(&name).await {
            let _ = std::fs::remove_file(conf_path_for(&name));
            crate::dns::clear_vpn_dns();
            return Ok(match result {
                Ok(()) => WgDisconnectResult {
                    success: true,
                    message: format!("WireGuard tunnel '{name}' down"),
                },
                Err(e) => WgDisconnectResult {
                    success: false,
                    message: format!("Tunnel still up despite teardown: {e:#}"),
                },
            });
        }
        let wg_quick = crate::vpn_runtime::wg_quick()?;

        // 1. Capture the utun mapping before wg-quick deletes the
        //    `.name` file so we can still tear the interface down by
        //    its real name if wg-quick fails.
        let utun_name_before = read_name_mapping(&name);

        // 2. Try the clean path. Pass the absolute conf path for the
        //    same reason as in `connect` — bypass wg-quick's
        //    brew-baked-in CONFIG_PATH.
        let conf_path = conf_path_for(&name);
        let output = crate::proc::bounded_async(
            wg_quick.command().arg("down").arg(&conf_path),
            WG_QUICK_BUDGET,
        )
        .await
        .with_context(|| format!("run {} down", wg_quick.describe()))?;

        let mut messages: Vec<String> = Vec::new();
        let wg_quick_ok = output.status.success();
        if wg_quick_ok {
            messages.push(format!("wg-quick down '{name}' succeeded"));
        } else {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            messages.push(format!("wg-quick down failed ({err})"));
        }

        // 3. Always verify the interface is actually gone. Some
        //    wg-quick failure modes (bash version mismatch, missing
        //    `route` in PATH) report success but leave the utun up;
        //    others report failure but already torn things down.
        //    Source of truth is `ifconfig`.
        if let Some(ref utun) = utun_name_before {
            if interface_exists(utun) {
                // Force-destroy via ifconfig — root, no shell.
                match crate::proc::bounded_async(
                    Command::new("/sbin/ifconfig").args([utun, "destroy"]),
                    crate::proc::MUTATE,
                )
                .await
                {
                    Ok(out) if out.status.success() => {
                        messages.push(format!("force-destroyed {utun}"));
                    }
                    Ok(out) => {
                        messages.push(format!(
                            "ifconfig {utun} destroy failed: {}",
                            String::from_utf8_lossy(&out.stderr).trim()
                        ));
                    }
                    Err(e) => {
                        messages.push(format!("ifconfig {utun} destroy: {e}"));
                    }
                }
            }
        }

        // 4. Clean up wg-quick's `/var/run/wireguard/*` cookies if
        //    they're still there. wg-quick removes them on a clean
        //    `down`, but a fallback path leaves them and confuses a
        //    later `up`.
        let _ = std::fs::remove_file(format!("/var/run/wireguard/{name}.name"));
        if let Some(ref utun) = utun_name_before {
            let _ = std::fs::remove_file(format!("/var/run/wireguard/{utun}.sock"));
        }

        // 5. Always remove the conf file. Leaving a private key on
        //    disk is worse than a dangling interface.
        let _ = std::fs::remove_file(conf_path_for(&name));

        // 6. Always restore DNS — unconditionally, regardless of
        //    whether wg-quick down succeeded or the fallback ran.
        //    wg-quick sets DNS via `networksetup` (Setup store) when
        //    it brings the tunnel up; its `down` path clears it, but
        //    the `ifconfig destroy` fallback above does not. Calling
        //    `clear_vpn_dns` here covers both paths and also removes
        //    any State-store entries, matching macOS best-practice.
        crate::dns::clear_vpn_dns();

        // Final verdict: success iff the interface is gone now.
        let final_alive = utun_name_before
            .as_deref()
            .map(interface_exists)
            .unwrap_or(false);
        Ok(WgDisconnectResult {
            success: !final_alive,
            message: if final_alive {
                format!(
                    "Tunnel still up despite teardown attempts: {}",
                    messages.join("; ")
                )
            } else {
                messages.join("; ")
            },
        })
    }

    /// Probe `wg show <utun>` for tunnel state + byte counters.
    ///
    /// On macOS `wg-quick` doesn't get to choose the interface name
    /// (the kernel allocates `utunN` automatically), so it stores the
    /// human-readable name → `utunN` mapping in
    /// `/var/run/wireguard/<name>.name`. `wg` doesn't follow that
    /// mapping; we have to read the file ourselves and use the real
    /// `utunN` name on the CLI.
    ///
    /// "Tunnel up" = the `.name` file exists. "Tunnel down" = it
    /// doesn't. Byte counters come from `wg show <utun> transfer`,
    /// which sums per-peer.
    pub async fn status(&mut self, args: &WgStatusArgs) -> anyhow::Result<WgStatusResult> {
        let name = interface_name(&args.profile_id);

        let utun_name = match read_name_mapping(&name) {
            Some(u) => u,
            None => {
                // No mapping file → tunnel was never up, or it was
                // brought down (wg-quick removes the file on `down`).
                return Ok(WgStatusResult {
                    state: WgState::Disconnected,
                    rx_bytes: None,
                    tx_bytes: None,
                    last_handshake_unix: None,
                    peer_endpoint: None,
                });
            }
        };

        let wg_bin = crate::vpn_runtime::wg()?;
        // `wg show <if> dump` is the machine-readable kitchen sink:
        // one tab-separated line per peer with endpoint, allowed IPs,
        // last handshake (unix ts), rx/tx bytes, and keepalive.
        // The interface line precedes the peers.
        let output = crate::proc::bounded_async(
            Command::new(&wg_bin).args(["show", &utun_name, "dump"]),
            crate::proc::PROBE,
        )
        .await
        .context("run wg show dump")?;

        if !output.status.success() {
            // `wg show dump` failed despite the mapping existing.
            // Most likely cause is a transient permission glitch or
            // a race with the userland daemon — NOT "tunnel is
            // gone." Trust the mapping file as ground truth: if
            // it's there, we're connected, just without traffic
            // counters this poll. The next poll will (probably)
            // succeed and re-populate the byte counts.
            //
            // Reporting "disconnected" here was the bug that made
            // the UI flicker mid-connection.
            if interface_exists(&utun_name) {
                return Ok(WgStatusResult {
                    state: WgState::Connected,
                    rx_bytes: None,
                    tx_bytes: None,
                    last_handshake_unix: None,
                    peer_endpoint: None,
                });
            }
            return Ok(WgStatusResult {
                state: WgState::Disconnected,
                rx_bytes: None,
                tx_bytes: None,
                last_handshake_unix: None,
                peer_endpoint: None,
            });
        }

        // `wg show <if> dump` per-peer line layout:
        //   pubkey \t psk \t endpoint \t allowed_ips \t handshake_unix \t rx \t tx \t keepalive
        // The first line is the interface (no endpoint) — skip it.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut total_rx: u64 = 0;
        let mut total_tx: u64 = 0;
        let mut freshest_handshake: i64 = 0;
        let mut freshest_endpoint: Option<String> = None;
        for (idx, line) in stdout.lines().enumerate() {
            if idx == 0 {
                // Interface line: pubkey \t psk \t listen_port \t fwmark — skip.
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 8 {
                continue;
            }
            let endpoint = parts[2];
            let handshake = parts[4].parse::<i64>().unwrap_or(0);
            let rx = parts[5].parse::<u64>().unwrap_or(0);
            let tx = parts[6].parse::<u64>().unwrap_or(0);
            total_rx = total_rx.saturating_add(rx);
            total_tx = total_tx.saturating_add(tx);
            if handshake > freshest_handshake {
                freshest_handshake = handshake;
                if endpoint != "(none)" && !endpoint.is_empty() {
                    freshest_endpoint = Some(endpoint.to_owned());
                }
            }
        }

        Ok(WgStatusResult {
            state: WgState::Connected,
            rx_bytes: Some(total_rx),
            tx_bytes: Some(total_tx),
            // 0 from the dump means "no handshake yet" — keep it None
            // so the GUI can render "establishing…" rather than
            // "1970-01-01".
            last_handshake_unix: if freshest_handshake > 0 {
                Some(freshest_handshake)
            } else {
                None
            },
            peer_endpoint: freshest_endpoint,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sanitize a UUID-shaped profile id into a name that's both
/// filesystem-safe and accepted by `utun`. The kernel's interface
/// name limit is 15 chars (IFNAMSIZ-1). UUIDs are way over that, so
/// we hash to 8 hex chars and prefix with "smwg" (sm = SuperManager,
/// wg = WireGuard) for a tight, human-readable interface name.
fn interface_name(profile_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(profile_id.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("smwg{hex}")
}

fn conf_path_for(name: &str) -> PathBuf {
    Path::new(WG_CONF_DIR).join(format!("{name}.conf"))
}

/// `wg-quick` on macOS lands the tunnel on a kernel-allocated
/// `utunN` device, then writes the wg-quick-config-name → `utunN`
/// mapping to `/var/run/wireguard/<name>.name`. The file's body is
/// just the literal interface name with a trailing newline. Reading
/// it is how everything else on the system finds the tunnel.
fn read_name_mapping(name: &str) -> Option<String> {
    let path = format!("/var/run/wireguard/{name}.name");
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim().to_owned();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Check whether a network interface exists by name. Used to verify
/// `wg-quick down` actually tore the utun down; if it didn't, the
/// fallback path force-destroys it via `ifconfig`.
fn interface_exists(name: &str) -> bool {
    // `ifconfig <name>` exits 0 if the interface exists, non-zero
    // otherwise. Synchronous on purpose — threading async through a single
    // existence check buys nothing — but BOUNDED, because "brief blocking
    // shell-out" is exactly the assumption that wedged the helper: this runs on
    // a tokio worker, and ifconfig on a half-torn-down interface does not
    // always return.
    crate::proc::Bounded::new("/sbin/ifconfig")
        .arg(name)
        .budget(crate::proc::PROBE)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `wg-quick` wraps the real device name (`utunN`) — read it from
/// the mapping file rather than re-deriving it via `wg show`.
async fn detect_interface(name: &str) -> anyhow::Result<String> {
    read_name_mapping(name)
        .ok_or_else(|| anyhow!("no /var/run/wireguard/{name}.name mapping — tunnel didn't come up"))
}

/// `wg-quick` runs these as shell commands, as root.
const HOOK_KEYS: [&str; 4] = ["PreUp", "PostUp", "PreDown", "PostDown"];

/// Refuse a config with `wg-quick` hooks. SuperManager renders its configs
/// from profile fields and never writes one, so a config that has them did
/// not come from SuperManager.
fn refuse_hooks(conf: &str) -> anyhow::Result<()> {
    for line in conf.lines() {
        // wg-quick drops everything after a `#`.
        let setting = line.split('#').next().unwrap_or_default();
        let Some((key, _)) = setting.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if let Some(hook) = HOOK_KEYS.iter().find(|hook| key.eq_ignore_ascii_case(hook)) {
            return Err(anyhow!(
                "refusing a WireGuard config with {hook}: wg-quick would run it as root"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RENDERED: &str =
        "[Interface]\nPrivateKey = aaaa\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n\n\
                            [Peer]\nPublicKey = bbbb\nEndpoint = vpn.example.com:51820\n\
                            AllowedIPs = 0.0.0.0/0\n";

    #[test]
    fn a_config_as_supermanager_renders_it_is_accepted() {
        refuse_hooks(RENDERED).unwrap();
        // A hook named in a comment runs nothing.
        refuse_hooks(&format!("# PostUp = never\n{RENDERED}")).unwrap();
    }

    #[test]
    fn a_config_that_would_run_commands_as_root_is_refused() {
        for hook in [
            "PostUp = echo hook",
            "PreUp=echo hook",
            "  postdown = echo hook",
            "PreDown = echo hook # cleanup",
        ] {
            let conf = RENDERED.replace("[Peer]", &format!("{hook}\n[Peer]"));
            let err = refuse_hooks(&conf).unwrap_err();
            assert!(err.to_string().contains("run it as root"), "{hook}: {err}");
        }
    }

    #[test]
    fn interface_name_is_short_and_stable() {
        let id = "26b4fcc6-097a-41e7-932e-9a6d2a4663e5";
        let n = interface_name(id);
        assert_eq!(n.len(), 12);
        assert!(n.starts_with("smwg"));
        // Stability across repeated calls on the same input.
        assert_eq!(n, interface_name(id));
    }

    #[test]
    fn conf_path_is_under_wg_dir() {
        let p = conf_path_for("smwg12345678");
        assert!(p.starts_with("/etc/wireguard"));
        assert!(p.to_string_lossy().ends_with(".conf"));
    }
}
