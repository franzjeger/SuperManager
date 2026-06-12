//! Thin wrapper around the strongSwan binaries (`charon`, `swanctl`)
//! that brew installs at `/opt/homebrew/sbin/`.
//!
//! Connect flow per VPN profile:
//! 1. Make sure the strongSwan service is running. We launch `charon-systemd`
//!    out-of-process if needed; on macOS there's no systemd but the binary
//!    still works as a foreground daemon. We supervise it with a child
//!    process handle held in this struct.
//! 2. Generate a swanctl config file under
//!    `/etc/swanctl/conf.d/supermanager-<profile_id>.conf` that declares one
//!    `connections.<profile_id>` block with FortiGate-friendly IKEv2 +
//!    EAP-MSCHAPv2 + group PSK proposals.
//! 3. Generate a secrets file under
//!    `/etc/swanctl/swanctl.d/supermanager-<profile_id>.secrets` (mode 0600)
//!    with the EAP password and IKE PSK.
//! 4. `swanctl --load-all` to pick them up.
//! 5. `swanctl --initiate --child <profile_id>` to bring the tunnel up.
//!
//! Disconnect: `swanctl --terminate --ike <profile_id>`. Status:
//! `swanctl --list-sas` and grep for our connection name.

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// Best-effort cleanup of `supermanager-*` swanctl configs and secrets
/// left behind by a previous helper crash. Called once on helper startup.
/// Failures are silent — if strongSwan isn't installed, there's nothing
/// to sweep, and if a directory is missing the glob just yields nothing.
///
/// Also sweeps stale kernel host routes for any VPN server address found
/// in the leftover config files. When charon is killed without a clean
/// disconnect it leaves a host route like:
///
///   193.213.13.22  192.168.200.1  UGHS  en0
///
/// pointing at the old gateway. A fresh connect attempt fails with
/// "unable to determine source address" because charon tries to reach
/// the server via the stale route (wrong gateway, wrong network).
pub async fn sweep_stale_configs() {
    // Wake-sweep race guard. This runs at startup AND on system_wake. If a
    // strongSwan tunnel is ESTABLISHED right now, this is almost certainly a
    // post-wake sweep racing auto_reconnect's replay: the tunnel was just
    // re-established and its conf + 0/1+128/1 routes are legitimate. Deleting
    // them here would strip a live tunnel's default routes (a cleartext leak)
    // and remove the conf charon is actively using. Skip the whole sweep — at
    // startup (the other caller) charon isn't running yet, so no SA is
    // ESTABLISHED and the sweep runs normally to clean genuine leftovers.
    if has_established_strongswan_sa() {
        tracing::info!("sweep_stale_configs: live strongSwan SA present — skipping sweep to avoid racing auto_reconnect");
        return;
    }
    for prefix in BREW_PATHS {
        for subdir in ["etc/swanctl/conf.d", "etc/swanctl/swanctl.d"] {
            let dir = std::path::Path::new(prefix).join(subdir);
            let Ok(mut entries) = tokio::fs::read_dir(&dir).await else { continue };
            while let Ok(Some(entry)) = entries.next_entry().await {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if name.starts_with("supermanager-") {
                    // Extract server host before deleting the file so we
                    // can also sweep the kernel host route.
                    if let Ok(host) = extract_remote_addr(entry.path()).await {
                        delete_server_host_route(&host);
                    }
                    let _ = tokio::fs::remove_file(entry.path()).await;
                    tracing::debug!(path = %entry.path().display(), "swept stale config");
                }
            }
        }
    }
    // On wake (the primary caller of this function) any full-tunnel routes
    // from a pre-sleep session may have survived. Remove them so the first
    // post-wake ping doesn't black-hole into a dead tunnel.
    delete_full_tunnel_routes();
}

/// Where brew puts the strongSwan install root on Apple Silicon Macs.
/// On Intel Macs Homebrew lives at `/usr/local`. We probe both.
/// brew layout for strongswan 6.x:
///   `<prefix>/bin/swanctl`      — vici client we drive for connect/disconnect
///   `<prefix>/libexec/ipsec/charon` — the actual IKE daemon we supervise
///   `<prefix>/etc/strongswan.conf` — main config (we override via env)
///   `<prefix>/etc/swanctl/`     — per-connection conf.d / swanctl.d files
const BREW_PATHS: &[&str] = &["/opt/homebrew", "/usr/local"];

#[derive(Debug, Deserialize)]
pub struct ConnectArgs {
    /// Stable profile identifier — used as the swanctl `connections.<id>`
    /// name so multiple profiles can coexist without name collisions.
    pub profile_id: String,
    /// Display name (informational only — surfaced in `swanctl --list-sas`).
    pub name: String,
    /// VPN gateway hostname or IP.
    pub host: String,
    /// EAP username.
    pub username: String,
    /// EAP password.
    pub password: String,
    /// IKEv2 group PSK. Empty means certificate-only.
    pub shared_secret: String,
    /// If true, ask for `0.0.0.0/0,::/0` as `remote_ts` (catch-all
    /// — every packet goes through the tunnel). If false, use the
    /// `routes` field below to scope which destinations the kernel
    /// installs for the tunnel. Empty `routes` with `full_tunnel=false`
    /// produces a tunnel that can't reach anything; the GUI's
    /// validation should prevent that, and we fail closed if it gets
    /// here anyway.
    #[serde(default = "default_full_tunnel")]
    pub full_tunnel: bool,
    /// Split-tunnel destinations as CIDR strings. Only consulted
    /// when `full_tunnel=false`. Each entry becomes a `remote_ts`
    /// selector in the strongSwan child config.
    #[serde(default)]
    pub routes: Vec<String>,
}

fn default_full_tunnel() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct DisconnectArgs {
    pub profile_id: String,
}

#[derive(Debug, Deserialize)]
pub struct StatusArgs {
    pub profile_id: String,
}

#[derive(Debug, Serialize)]
pub struct ConnectResult {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct DisconnectResult {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct StatusResult {
    /// "connected", "connecting", or "disconnected".
    pub state: String,
    /// Optional human-readable detail (e.g. ESP rekey time).
    pub detail: String,
}

/// Holds onto the strongSwan install paths and the supervised charon
/// process. `&mut self` is required for connect/disconnect because they
/// may need to (re)launch charon.
pub struct Strongswan {
    /// `<brew>/sbin/charon-systemd` — the daemon we launch as a child.
    /// Resolved lazily on first use because the user might not have
    /// installed strongSwan yet at helper start time.
    charon: Option<PathBuf>,
    /// `<brew>/sbin/swanctl` — the CLI we drive for config + control.
    swanctl: Option<PathBuf>,
    /// `<brew>/etc` — strongSwan's config root.
    etc: Option<PathBuf>,
    /// Handle to the charon daemon we launched. None until first connect.
    charon_child: Option<tokio::process::Child>,
}

impl Strongswan {
    pub fn new() -> Self {
        Self { charon: None, swanctl: None, etc: None, charon_child: None }
    }

    /// Resolve the strongSwan install location lazily. Cached on success.
    /// brew doesn't symlink the strongSwan-private `libexec/ipsec/` tree
    /// into `<prefix>/libexec/`, so we probe the formula's `opt/strongswan/`
    /// path which IS the canonical brew "give me the current version of
    /// this formula" location.
    fn resolve(&mut self) -> anyhow::Result<()> {
        if self.swanctl.is_some() {
            return Ok(());
        }
        for prefix in BREW_PATHS {
            let swanctl = Path::new(prefix).join("bin/swanctl");
            // Try the canonical brew path first; fall back to a generic
            // libexec path for non-brew installs (e.g. strongSwan compiled
            // from source by the user).
            let charon_candidates = [
                Path::new(prefix).join("opt/strongswan/libexec/ipsec/charon"),
                Path::new(prefix).join("libexec/ipsec/charon"),
            ];
            let charon = charon_candidates.iter().find(|p| p.exists()).cloned();

            // Prefer the brew-shared `/opt/homebrew/etc` path; that's where
            // swanctl reads from by default and where multiple strongSwan
            // installs (or upgrades) write to. The formula-private
            // `<prefix>/opt/strongswan/etc` is bottled and not what swanctl
            // looks at.
            let etc_candidates = [
                Path::new(prefix).join("etc"),
                Path::new(prefix).join("opt/strongswan/etc"),
            ];
            let etc = etc_candidates.iter().find(|p| p.exists()).cloned();

            if swanctl.exists() {
                if let (Some(charon), Some(etc)) = (charon, etc) {
                    self.charon = Some(charon);
                    self.swanctl = Some(swanctl);
                    self.etc = Some(etc);
                    return Ok(());
                }
            }
        }
        Err(anyhow!(
            "strongSwan not found. Install it with `brew install strongswan` \
             (we probe /opt/homebrew and /usr/local)."
        ))
    }

    /// Launch charon as a child process if it's not already running.
    /// We supervise it ourselves rather than relying on a separate
    /// LaunchDaemon so a SuperManager uninstall doesn't leave charon
    /// hanging around as a system service.
    async fn ensure_charon(&mut self) -> anyhow::Result<()> {
        if let Some(child) = &mut self.charon_child {
            // try_wait returns Ok(None) while still running.
            match child.try_wait() {
                Ok(None) => return Ok(()),
                Ok(Some(status)) => {
                    tracing::warn!("charon previously exited: {status:?}");
                    self.charon_child = None;
                }
                Err(e) => {
                    tracing::warn!("charon try_wait error: {e}");
                    self.charon_child = None;
                }
            }
        }

        let charon = self.charon.as_ref().expect("resolve() must run first").clone();
        let etc = self.etc.as_ref().expect("resolve() must run first").clone();

        // charon-systemd reads /etc/strongswan.conf and the swanctl plugin
        // talks to /var/run/charon.vici. Set STRONGSWAN_CONF to point at
        // the brew prefix so we don't depend on /etc/strongswan.conf.
        let mut cmd = Command::new(&charon);
        cmd.env("STRONGSWAN_CONF", etc.join("strongswan.conf"))
            .env("SWANCTL_DIR", etc.join("swanctl"))
            .kill_on_drop(true);

        let child = cmd
            .spawn()
            .with_context(|| format!("spawn {}", charon.display()))?;
        self.charon_child = Some(child);

        // charon needs a moment to bind its vici socket. swanctl will spin
        // briefly and reconnect if it fails, but giving it ~500ms here makes
        // the first --load-all reliable.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        Ok(())
    }

    pub async fn connect(&mut self, args: &ConnectArgs) -> anyhow::Result<ConnectResult> {
        self.resolve()?;
        // Force a fresh charon on every connect. strongSwan caches secrets
        // and connections on the IKE-SA level; re-initiating against an
        // existing charon that was started with stale config can produce
        // hard-to-diagnose "no shared key found" errors. Killing and
        // re-spawning is cheap (~500 ms) and guarantees clean state.
        if let Some(mut child) = self.charon_child.take() {
            let _ = child.kill().await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        self.ensure_charon().await?;

        let etc = self.etc.as_ref().unwrap().clone();
        let swanctl_dir = etc.join("swanctl");
        tokio::fs::create_dir_all(swanctl_dir.join("conf.d")).await.ok();
        tokio::fs::create_dir_all(swanctl_dir.join("swanctl.d")).await.ok();

        let conf_path = swanctl_dir.join(format!("conf.d/supermanager-{}.conf", args.profile_id));
        let secrets_path = swanctl_dir.join(format!("conf.d/supermanager-{}-secrets.conf", args.profile_id));

        let conf = build_swanctl_conf(args);
        // `build_swanctl_conf` returns an empty string when split-tunnel
        // mode is requested without any routes — that's a misconfig
        // we'd rather fail closed on than silently let through.
        if conf.is_empty() {
            return Err(anyhow::anyhow!(
                "split-tunnel mode requires at least one route — got an empty list"
            ));
        }
        tokio::fs::write(&conf_path, conf)
            .await
            .with_context(|| format!("write {}", conf_path.display()))?;

        let secrets = build_swanctl_secrets(args);
        tokio::fs::write(&secrets_path, secrets)
            .await
            .with_context(|| format!("write {}", secrets_path.display()))?;
        // Keep credentials private even though we are root.
        tokio::fs::set_permissions(&secrets_path, std::fs::Permissions::from_mode(0o600)).await.ok();

        run(self.swanctl.as_ref().unwrap(), &["--load-all"]).await?;

        // --initiate is async — the call returns once the IKE handshake has
        // either succeeded or failed, but for fast networks ~1s is enough.
        // We give it 30s to allow for slow gateways.
        let out = run_with_timeout(
            self.swanctl.as_ref().unwrap(),
            &["--initiate", "--child", &args.profile_id],
            std::time::Duration::from_secs(30),
        )
        .await?;

        // swanctl prints "initiate completed successfully" on the happy path.
        let ok = out.contains("completed successfully") || out.contains("CHILD_SA");

        // IPv6 leak protection. Our full-tunnel config is IPv4-only
        // (vips = 0.0.0.0, remote_ts = 0.0.0.0/0) — charon installs the
        // 0/1 + 128/1 split-defaults for IPv4 but nothing for IPv6, so
        // every IPv6 packet keeps routing out the physical `default
        // ...%en0` gateway in cleartext while the user believes ALL their
        // traffic is tunnelled. Since the FortiGate side doesn't carry v6,
        // we fail closed: blackhole all IPv6 for the duration of the
        // tunnel. Torn down by delete_full_tunnel_routes() on disconnect.
        if ok && args.full_tunnel {
            install_ipv6_leak_block();
        }

        Ok(ConnectResult {
            ok,
            message: out.lines().last().unwrap_or("").to_owned(),
        })
    }

    pub async fn disconnect(&mut self, args: &DisconnectArgs) -> anyhow::Result<DisconnectResult> {
        self.resolve()?;
        let swanctl = self.swanctl.as_ref().unwrap();
        // best-effort: terminate the IKE SA. Even if it fails, also remove
        // the loaded config so a subsequent --load-all doesn't try to
        // re-initiate.
        let out = run(swanctl, &["--terminate", "--ike", &args.profile_id])
            .await
            .unwrap_or_default();

        let etc = self.etc.as_ref().unwrap().clone();
        let conf_path = etc.join(format!("swanctl/conf.d/supermanager-{}.conf", args.profile_id));
        let secrets_path = etc.join(format!("swanctl/conf.d/supermanager-{}-secrets.conf", args.profile_id));

        // Extract the server host BEFORE removing the config file — we need
        // it to clean up the kernel host route that charon installed.
        // IKEv2 full-tunnel adds: `<server_ip>  <original_gw>  UGHS  en0`
        // so that control traffic bypasses the tunnel. After disconnect the
        // route must be removed; if the user changes networks before the
        // next connect, the stale route points at the old gateway and charon
        // can't determine a source address → "unable to determine source
        // address, faking NAT situation" → every packet fails with EADDRNOTAVAIL.
        let server_host = extract_remote_addr(&conf_path).await.ok();

        tokio::fs::remove_file(&conf_path).await.ok();
        tokio::fs::remove_file(&secrets_path).await.ok();
        let _ = run(swanctl, &["--load-all"]).await;

        if let Some(host) = server_host {
            delete_server_host_route(&host);
        }
        // Belt-and-braces: charon removes the full-tunnel split-default routes
        // (0/1 + 128/1) when it terminates the SA cleanly. But if the SA was
        // already gone before --terminate ran (server timeout, network change,
        // unexpected drop), charon has nothing to clean up and the routes stay
        // in the kernel — routing ALL subsequent traffic into a dead tunnel and
        // breaking internet access until the next VPN connect or reboot.
        // Deleting them here is idempotent: `route delete` ignores missing routes.
        delete_full_tunnel_routes();

        Ok(DisconnectResult { ok: true, message: out.lines().last().unwrap_or("").to_owned() })
    }

    pub async fn status(&mut self, args: &StatusArgs) -> anyhow::Result<StatusResult> {
        // Run path resolution lazily so the GUI's first poll-tick after
        // helper install still reports the right state. resolve() is cheap
        // and idempotent.
        if self.resolve().is_err() {
            return Ok(StatusResult {
                state: "disconnected".to_owned(),
                detail: "strongSwan not installed".to_owned(),
            });
        }
        let swanctl = self.swanctl.as_ref().expect("just resolved");
        // Bound the swanctl call. Without a timeout a wedged charon (vici
        // socket unresponsive) makes `--list-sas` hang FOREVER — and because
        // status() holds the strongSwan controller lock, that wedges EVERY
        // VPN operation (connect, disconnect, and all subsequent status
        // polls), freezing the GUI on "Connecting…" for a tunnel that is
        // actually up. On timeout we report the interim "connecting" state
        // and return, releasing the lock so the next poll retries and other
        // RPCs proceed.
        // Distinguish a genuine TIMEOUT (charon's vici wedged → report the
        // interim "connecting" so the lock releases) from swanctl simply
        // exiting non-zero (e.g. charon not running → no SA → that's just
        // "disconnected", the original behaviour). Conflating the two would
        // wrongly show "Connecting…" for a tunnel that is plainly down.
        let out = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run(swanctl, &["--list-sas"]),
        )
        .await
        {
            // swanctl finished in time: use its output, or empty on a
            // non-zero exit (no charon / no SAs) → resolves to "disconnected".
            Ok(result) => result.unwrap_or_default(),
            // genuinely hung past the deadline.
            Err(_) => {
                return Ok(StatusResult {
                    state: "connecting".to_owned(),
                    detail: "status query timed out (charon busy)".to_owned(),
                });
            }
        };
        let block_marker = format!("{}: ", args.profile_id);
        let block = out
            .lines()
            .skip_while(|l| !l.starts_with(&block_marker))
            .take(8)
            .collect::<Vec<_>>()
            .join("\n");
        let state = if block.is_empty() {
            "disconnected"
        } else if block.contains("ESTABLISHED") {
            "connected"
        } else {
            "connecting"
        };
        Ok(StatusResult { state: state.to_owned(), detail: block })
    }
}

use std::os::unix::fs::PermissionsExt;

async fn run(bin: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(bin).args(args).output().await?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(anyhow!(
            "{} {:?} exited {}: {}{}",
            bin.display(),
            args,
            output.status,
            stderr,
            stdout
        ));
    }
    Ok([stdout, stderr].concat())
}

async fn run_with_timeout(
    bin: &Path,
    args: &[&str],
    timeout: std::time::Duration,
) -> anyhow::Result<String> {
    match tokio::time::timeout(timeout, run(bin, args)).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("{} {:?} timed out", bin.display(), args)),
    }
}

/// Build a swanctl config snippet for a FortiGate dial-up IKEv2 + EAP +
/// optional group-PSK setup. Strings come from typed `ConnectArgs` fields,
/// not from the wire — no shell quoting concerns.
fn build_swanctl_conf(args: &ConnectArgs) -> String {
    // FortiGate's defaults are surprisingly liberal so we don't pin a
    // specific proposal. If a particular gateway needs something narrower
    // we can add a `proposals = aes256-sha256-modp1024` line later.
    //
    // Local TS: the IPs WE source as. `0.0.0.0/0` says "any source IP
    // we have can be tunnelled" — strongSwan installs kernel routes
    // accordingly. We don't tighten this; FortiGate doesn't care, and
    // the `remote_ts` is what actually scopes traffic.
    let local_ts = "0.0.0.0/0";
    // Remote TS: the destination scope. Full tunnel → catch-all.
    // Split tunnel → comma-joined CIDR list from `routes`. Empty
    // routes in split mode produces a tunnel that can't reach
    // anything; we fail closed by emitting a deliberately-invalid
    // selector so the daemon refuses the child SA rather than
    // silently establishing a useless tunnel.
    let remote_ts: String = if args.full_tunnel {
        "0.0.0.0/0".to_owned()
    } else if args.routes.is_empty() {
        // No routes + split mode = misconfiguration. Better to
        // surface as a connect error than to install a tunnel that
        // pretends to work.
        return String::new();
    } else {
        args.routes.join(",")
    };
    let id = sanitize_name(&args.profile_id);
    // FortiGate dial-up IKEv2 + EAP-MSCHAPv2 expects:
    //   - Local (us): authenticate with EAP-MSCHAPv2 only — no IKE-level
    //     PSK from us. When we tried to send PSK + EAP combined, FortiGate
    //     silently dropped IKE_AUTH (5x retransmits, then giving up).
    //   - Remote (server): authenticates to us with PSK over IKE.
    // The empirical signal that this is right: with `local.auth =
    // eap-mschapv2` alone, FortiGate responded with `IDr AUTH EAP/REQ/ID`
    // (it sent its server cert/PSK auth and started the EAP exchange).
    // With `local-1.auth = psk + local-2.auth = eap`, FortiGate stopped
    // responding entirely.
    format!(
        r#"connections {{
    {id} {{
        version = 2
        remote_addrs = {host}
        vips = 0.0.0.0
        local {{
            auth = eap-mschapv2
            eap_id = {username}
        }}
        remote {{
            auth = psk
            id = {host}
        }}
        children {{
            {id} {{
                local_ts = {local_ts}
                remote_ts = {remote_ts}
                start_action = none
                close_action = none
            }}
        }}
    }}
}}
"#,
        id = id,
        host = args.host,
        username = args.username,
        local_ts = local_ts,
        remote_ts = remote_ts,
    )
}

/// `connections.<name>` keys must be ident-like. We only accept hex digits,
/// dashes, and underscores; anything else gets stripped. Profile UUIDs are
/// already in this set.
fn sanitize_name(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_hexdigit() || *c == '-' || *c == '_').collect()
}

/// Secrets file format per
/// https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html#_secrets
///
/// strongSwan matches `ike` secrets to peers by ID. We pin the local IKE
/// identity to a stable `supermgr-<profile_id>` FQDN-style value in
/// `build_swanctl_conf`, then list it here as `id-1`. We also list `%any`
/// as `id-2` so a server-initiated lookup against any other identity
/// still finds the secret. The remote ID isn't enumerated because we
/// configure the connection with `remote.id = %any` — the FortiGate's
/// IKE identity is not what authenticates us; the EAP exchange does.
fn build_swanctl_secrets(args: &ConnectArgs) -> String {
    let id = sanitize_name(&args.profile_id);
    let mut s = String::new();
    s.push_str("secrets {\n");
    if !args.shared_secret.is_empty() {
        // strongSwan needs the PSK to verify the SERVER's IKE auth payload.
        // The server presents its IDr as the host IP, so we list it as id-1.
        // We also include `%any` as id-2 so the lookup succeeds regardless
        // of how charon formats the local IDi (IP, FQDN, etc.).
        s.push_str(&format!(
            "    ike-{id} {{\n\
             \x20       id-1 = {host}\n\
             \x20       id-2 = %any\n\
             \x20       secret = \"{secret}\"\n\
             \x20   }}\n",
            id = id,
            host = args.host,
            secret = escape_swanctl(&args.shared_secret),
        ));
    }
    if !args.password.is_empty() {
        s.push_str(&format!(
            "    eap-{id} {{\n\
             \x20       id = {username}\n\
             \x20       secret = \"{secret}\"\n\
             \x20   }}\n",
            id = id,
            username = args.username,
            secret = escape_swanctl(&args.password),
        ));
    }
    s.push_str("}\n");
    s
}

/// Delete the VPN-server host route that charon installs during an
/// IKEv2 full-tunnel connect.
///
/// When charon brings up a full tunnel it adds a host route so that
/// IKE keep-alives and rekeying reach the peer directly instead of
/// looping back through the tunnel:
///
///   `<server>  <original-gw>  UGHS  en0`
///
/// On a clean disconnect charon removes this route. When charon is
/// killed (helper crash, SIGKILL, machine sleep mid-connect), the
/// route persists. On the next connect attempt — especially after a
/// network change — charon can't determine a source address because
/// the route still points at the old gateway on the old network →
/// "unable to determine source address, faking NAT situation" →
/// every IKE_SA_INIT packet fails with EADDRNOTAVAIL.
///
/// This function is called from `disconnect()` (before cleaning up
/// the config file) and from `sweep_stale_configs()` (at startup).
/// Safe to call unconditionally — `route delete` is a no-op if the
/// route doesn't exist.
fn delete_server_host_route(host: &str) {
    let out = std::process::Command::new("/sbin/route")
        .args(["-q", "delete", host])
        .output();
    match out {
        Ok(o) if o.status.success() =>
            tracing::info!("route_cleanup: deleted host route for {host}"),
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stderr);
            // "not in table" is expected when the route was already gone.
            if !msg.contains("not in table") && !msg.contains("No such process") {
                tracing::debug!("route_cleanup: route delete {host}: {msg}");
            }
        }
        Err(e) => tracing::warn!("route_cleanup: route delete {host}: {e}"),
    }
}

/// Remove the split-default routes that strongSwan installs for full-tunnel
/// IKEv2 connections. These two routes redirect ALL IPv4 traffic through the
/// VPN tunnel — if they linger after a disconnect (e.g., because the SA was
/// already gone when `swanctl --terminate` ran), the entire machine loses
/// internet access until a reboot or another VPN connect.
///
/// CRITICAL: `0/1` + `128.0/1` are a SHARED kernel resource. WireGuard
/// (wg-quick) and OpenVPN (`redirect-gateway def1`) install the exact same
/// pair for their own full tunnels. `route delete -net 0/1` matches purely on
/// destination, so a blind delete would strip a live WireGuard/OpenVPN
/// tunnel's routes and silently leak all traffic in cleartext via en0 while
/// the GUI still shows "Connected".
///
/// We therefore gate the deletion on OWNERSHIP: look up the interface backing
/// each route and skip the delete when that interface belongs to a live
/// non-strongSwan tunnel. We only delete routes that point at a dead/charon
/// interface — exactly the stale-route case this function exists to fix.
///
/// Safe to call unconditionally: `/sbin/route delete` returns "not in table"
/// if the route doesn't exist, which we treat as success.
fn delete_full_tunnel_routes() {
    // Interfaces owned by a live WireGuard or OpenVPN tunnel. Never delete a
    // split-default that points at one of these.
    let foreign = foreign_tunnel_ifaces();
    // Is a strongSwan tunnel ESTABLISHED right now? If so, a utun-backed /1
    // route belongs to it (e.g. auto_reconnect re-established the tunnel after
    // wake, or another IKEv2 profile is up while this one disconnects). We must
    // not delete a live IKEv2 tunnel's default routes.
    let live_sa = has_established_strongswan_sa();

    // IPv4 split-defaults charon installs for a full tunnel. (get-spec,
    // delete-spec, family-flag): `route get` wants a full address, `route
    // delete` accepts the short CIDR form charon/wg-quick install.
    let v4 = [("0.0.0.0/1", "0/1"), ("128.0.0.0/1", "128.0/1")];
    for (get_spec, del_spec) in &v4 {
        delete_split_default(get_spec, del_spec, "-inet", &foreign, live_sa);
    }
    // IPv6 split-defaults: charon never installs these (our conf is v4-only),
    // but install_ipv6_leak_block() does — as blackhole routes via lo0 — to
    // stop v6 leaking past the tunnel. wg-quick installs the same ::/1 +
    // 8000::/1 pair for its own v6 full tunnel, so the ownership gate
    // (skip if backed by a live foreign utun) protects those too; our
    // blackhole routes resolve to lo0, which is never foreign, so they delete.
    let v6 = [("::/1", "::/1"), ("8000::/1", "8000::/1")];
    for (get_spec, del_spec) in &v6 {
        delete_split_default(get_spec, del_spec, "-inet6", &foreign, live_sa);
    }
}

/// True if the IPv4 full-tunnel split-default (`0/1`) is currently installed
/// on a utun interface — i.e. a full tunnel's routes are actually present, not
/// merely its SA. auto_reconnect uses this to detect an ESTABLISHED-but-
/// routeless tunnel (e.g. the split-defaults were externally flushed) so it
/// can replay the connect and re-install them instead of reporting "connected"
/// for a tunnel that is silently leaking.
pub(crate) fn full_tunnel_routes_present() -> bool {
    route_iface_family("0.0.0.0/1", "-inet")
        .map(|i| i.starts_with("utun"))
        .unwrap_or(false)
}

/// True if `swanctl --list-sas` shows any ESTABLISHED IKE SA — i.e. a live
/// strongSwan tunnel exists right now. Used to keep route/config cleanup from
/// stripping a tunnel that auto_reconnect (or always-on) re-established before
/// a wake sweep ran, and to protect one IKEv2 profile while another disconnects.
fn has_established_strongswan_sa() -> bool {
    let Some(swanctl) = BREW_PATHS
        .iter()
        .map(|p| std::path::Path::new(p).join("bin/swanctl"))
        .find(|p| p.exists())
    else {
        return false;
    };
    std::process::Command::new(&swanctl)
        .arg("--list-sas")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("ESTABLISHED"))
        .unwrap_or(false)
}

/// Delete one split-default route unless it belongs to a live tunnel.
/// `family` is `-inet` or `-inet6`. Skips the delete when the route is owned by
/// a live WireGuard/OpenVPN interface (`foreign`) or, when `live_sa` is set, by
/// any utun (a live strongSwan tunnel's route). Idempotent: a missing route is
/// success. Our own IPv6 blackhole routes resolve to lo0, not a utun, so the
/// `live_sa` guard never blocks their cleanup.
fn delete_split_default(
    get_spec: &str,
    del_spec: &str,
    family: &str,
    foreign: &std::collections::HashSet<String>,
    live_sa: bool,
) {
    if let Some(iface) = route_iface_family(get_spec, family) {
        if foreign.contains(&iface) {
            tracing::info!("route_cleanup: keeping {del_spec} — owned by live tunnel {iface}");
            return;
        }
        if live_sa && iface.starts_with("utun") {
            tracing::info!("route_cleanup: keeping {del_spec} — live strongSwan SA on {iface}");
            return;
        }
    }
    let out = std::process::Command::new("/sbin/route")
        .args(["-q", "delete", family, "-net", del_spec])
        .output();
    match out {
        Ok(o) if o.status.success() =>
            tracing::info!("route_cleanup: deleted full-tunnel route {del_spec}"),
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stderr);
            if !msg.contains("not in table") && !msg.contains("No such process") {
                tracing::debug!("route_cleanup: route delete {del_spec}: {msg}");
            }
        }
        Err(e) => tracing::warn!("route_cleanup: route delete {del_spec}: {e}"),
    }
}

/// Install IPv6 leak protection for an IPv4-only full tunnel: blackhole the
/// two IPv6 split-defaults (`::/1` + `8000::/1`) so they take precedence over
/// the physical `::/0` default and the kernel silently drops all IPv6. Routed
/// via `::1`/lo0 with `-blackhole` (RTF_BLACKHOLE). Idempotent: we delete any
/// prior copy first so a reconnect doesn't error on "route already in table".
fn install_ipv6_leak_block() {
    for net in &["::/1", "8000::/1"] {
        // Don't clobber a real v6 tunnel route if one somehow points here.
        if let Some(iface) = route_iface_family(net, "-inet6") {
            if iface != "lo0" && iface.starts_with("utun") {
                let foreign = foreign_tunnel_ifaces();
                if foreign.contains(&iface) {
                    tracing::warn!(
                        "ipv6_leak_block: {net} already owned by live tunnel {iface}, skipping"
                    );
                    continue;
                }
            }
        }
        let _ = std::process::Command::new("/sbin/route")
            .args(["-q", "delete", "-inet6", "-net", net])
            .output();
        let out = std::process::Command::new("/sbin/route")
            .args(["-q", "add", "-inet6", "-net", net, "::1", "-blackhole"])
            .output();
        match out {
            Ok(o) if o.status.success() =>
                tracing::info!("ipv6_leak_block: blackholed {net}"),
            Ok(o) => tracing::warn!(
                "ipv6_leak_block: add {net} failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => tracing::warn!("ipv6_leak_block: add {net}: {e}"),
        }
    }
}

/// Resolve the kernel interface that a packet to `dest` would use, by parsing
/// `route -n get <family> <dest>` (family = `-inet` or `-inet6`). Returns
/// `None` if the lookup fails or prints no `interface:` line. Used to identify
/// which backend owns a full-tunnel split-default route before we delete it.
pub(crate) fn route_iface_family(dest: &str, family: &str) -> Option<String> {
    let out = std::process::Command::new("/sbin/route")
        .args(["-n", "get", family, dest])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out.stdout);
    for line in body.lines() {
        if let Some(rest) = line.trim().strip_prefix("interface:") {
            let name = rest.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Set of kernel interfaces currently owned by a live non-strongSwan VPN
/// tunnel — WireGuard (`wg show interfaces`) and OpenVPN
/// (`openvpn::live_tunnel_interfaces`). The strongSwan route cleanup must
/// never delete a split-default route pointing at one of these.
pub(crate) fn foreign_tunnel_ifaces() -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    // WireGuard: `wg show interfaces` prints a space-separated list of the
    // utun devices wireguard-go currently owns.
    for prefix in BREW_PATHS {
        let wg = std::path::Path::new(prefix).join("bin/wg");
        if !wg.exists() {
            continue;
        }
        if let Ok(out) = std::process::Command::new(&wg)
            .args(["show", "interfaces"])
            .output()
        {
            if out.status.success() {
                for name in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                    set.insert(name.to_string());
                }
            }
        }
        break;
    }
    // OpenVPN: live tunnels expose their utun via the helper's log parse.
    for iface in crate::openvpn::live_tunnel_interfaces() {
        set.insert(iface);
    }
    set
}

/// Extract the `remote_addrs` value from a swanctl conf file.
///
/// Config format:
/// ```
/// connections {
///     <id> {
///         remote_addrs = 79.161.11.170
///         ...
///     }
/// }
/// ```
///
/// Returns the first `remote_addrs` value found, trimmed. Returns
/// `Err` if the file can't be read or the key is absent (e.g.
/// secrets-only file).
async fn extract_remote_addr(path: impl AsRef<std::path::Path>) -> anyhow::Result<String> {
    let content = tokio::fs::read_to_string(path.as_ref()).await?;
    for line in content.lines() {
        if let Some(rest) = line.trim().strip_prefix("remote_addrs") {
            // Matches both `remote_addrs = host` and `remote_addrs=host`
            let host = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim();
            if !host.is_empty() {
                return Ok(host.to_string());
            }
        }
    }
    anyhow::bail!("remote_addrs not found in {}", path.as_ref().display())
}

/// Terminate all active supermanager IKE SAs and sweep their config files.
///
/// Called on system-sleep notification (belt-and-braces after the Swift
/// layer has already fired per-profile disconnect RPCs) and can also be
/// called stand-alone. Safe to call when no VPNs are active — every
/// underlying command is idempotent.
///
/// Steps:
///   1. For each `supermanager-<id>.conf` in swanctl's conf.d:
///      a. Run `swanctl --terminate --ike <id>` (best-effort).
///      b. Extract `remote_addrs` and delete the kernel host route.
///      c. Remove the conf file.
///   2. Sweep `supermanager-*-secrets.conf` files (belt-and-braces).
///   3. Run `swanctl --load-all` so charon sees the empty namespace.
pub async fn terminate_and_sweep() {
    // Find the first working swanctl binary. Return early if strongSwan
    // isn't installed — nothing to clean up.
    let swanctl_path = BREW_PATHS
        .iter()
        .map(|p| std::path::Path::new(p).join("bin/swanctl"))
        .find(|p| p.exists());
    let Some(swanctl) = swanctl_path else {
        tracing::debug!("terminate_and_sweep: swanctl not found, skipping");
        return;
    };

    for prefix in BREW_PATHS {
        let conf_dir = std::path::Path::new(prefix).join("etc/swanctl/conf.d");
        let Ok(mut entries) = tokio::fs::read_dir(&conf_dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let fname = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Only touch our namespace; leave other strongSwan configs alone.
            if !fname.starts_with("supermanager-") || !fname.ends_with(".conf") {
                continue;
            }
            // Secrets files (supermanager-<id>-secrets.conf) — remove but
            // don't try to terminate an IKE SA named "<id>-secrets".
            if fname.ends_with("-secrets.conf") {
                let _ = tokio::fs::remove_file(entry.path()).await;
                tracing::debug!(file = %fname, "terminate_and_sweep: removed secrets file");
                continue;
            }
            // Derive the connection name: `supermanager-<id>.conf` → `<id>`
            let conn_name = fname
                .strip_prefix("supermanager-")
                .and_then(|s| s.strip_suffix(".conf"))
                .unwrap_or("");
            if conn_name.is_empty() {
                continue;
            }
            // Terminate the IKE SA (best-effort — it may already be gone).
            let _ = run(&swanctl, &["--terminate", "--ike", conn_name]).await;
            tracing::info!(conn = %conn_name, "terminate_and_sweep: terminated IKE SA");

            // Sweep the kernel host route charon installed.
            if let Ok(host) = extract_remote_addr(entry.path()).await {
                delete_server_host_route(&host);
            }
            // Remove the config file.
            let _ = tokio::fs::remove_file(entry.path()).await;
            tracing::debug!(file = %fname, "terminate_and_sweep: removed conf");
        }
        // Reload so charon sees the now-empty supermanager namespace.
        let _ = run(&swanctl, &["--load-all"]).await;
        // Explicitly remove full-tunnel split-default routes. charon removes
        // these when --terminate succeeds, but if a SA was already gone they
        // linger in the kernel and black-hole all internet traffic.
        delete_full_tunnel_routes();
        break; // Found a valid brew prefix; done.
    }
}

/// swanctl uses double-quoted strings; we need to escape `"` and `\`.
/// Newlines aren't valid inside a swanctl secret so we drop them defensively.
fn escape_swanctl(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '\n' && *c != '\r')
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '"' => vec!['\\', '"'],
            other => vec![other],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(host: &str, username: &str, password: &str, psk: &str) -> ConnectArgs {
        ConnectArgs {
            profile_id: "abcd1234-5678-9012-3456-7890abcdef00".to_owned(),
            name: "test profile".to_owned(),
            host: host.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
            shared_secret: psk.to_owned(),
            full_tunnel: true,
            routes: Vec::new(),
        }
    }

    #[test]
    fn conf_carries_eap_only_local_auth_and_psk_remote_auth() {
        // FortiGate dial-up is happy when the client only does EAP and the
        // server does PSK. We tested this against a live FortiGate; this
        // test pins the regression so the failing-but-recovering "send
        // PSK from us" detour we burned a day on can't sneak back in.
        let conf = build_swanctl_conf(&args("79.160.91.22", "alice", "pw", "secret"));
        assert!(
            conf.contains("auth = eap-mschapv2"),
            "EAP-MSCHAPv2 must be the local auth method:\n{conf}"
        );
        assert!(
            conf.contains("auth = psk"),
            "remote PSK verification must remain in the config:\n{conf}"
        );
        // Reject the previously-broken combined "PSK + EAP" client config.
        assert!(
            !conf.contains("local-1"),
            "local-N split was the wrong shape; FortiGate dropped IKE_AUTH:\n{conf}"
        );
    }

    #[test]
    fn conf_remote_id_pins_to_host() {
        // The remote PSK lookup needs an explicit id so charon knows what
        // to look up; %any matched too loosely on macOS strongSwan 6.x.
        let conf = build_swanctl_conf(&args("vpn.example.com", "u", "p", "s"));
        assert!(conf.contains("id = vpn.example.com"));
    }

    #[test]
    fn secrets_file_pins_remote_psk_lookup_against_host() {
        // The bug we shipped TWICE: secrets file with id=%any only
        // matches identities of "any" type, not IP-form IDr. We hardcode
        // the host as id-1 so charon's PSK lookup finds our entry when
        // it parses the FortiGate's IDr.
        let s = build_swanctl_secrets(&args("79.160.91.22", "alice", "pw", "psk-secret"));
        assert!(s.contains("id-1 = 79.160.91.22"));
        assert!(s.contains("id-2 = %any"));
        assert!(s.contains(r#"secret = "psk-secret""#));
        // EAP secret entry binds to the username
        assert!(s.contains("id = alice"));
        assert!(s.contains(r#"secret = "pw""#));
    }

    #[test]
    fn secrets_strip_newlines_and_escape_quotes() {
        // Defense-in-depth: a credential with a trailing newline (paste
        // accident) or an embedded `"` (configurations seen in the wild)
        // must not corrupt the secrets file. Newlines get filtered, `"`
        // and `\` get escaped.
        let s = build_swanctl_secrets(&args("h", "u", "pw\nbad", r#"a"b\c"#));
        assert!(!s.contains("pw\nbad"), "newline in password leaked into config:\n{s}");
        assert!(s.contains(r#"\"b\\c"#), "PSK quote/backslash not escaped:\n{s}");
    }

    #[test]
    fn no_psk_means_no_ike_secret_block() {
        // Cert-only / pure-EAP profiles should not emit an `ike-` secrets
        // entry — strongSwan would treat an empty secret as a literal
        // empty PSK, which then mismatches the server's auth payload.
        let s = build_swanctl_secrets(&args("h", "u", "pw", ""));
        assert!(!s.contains("ike-"), "empty PSK still emitted ike- entry:\n{s}");
        assert!(s.contains("eap-"), "EAP entry still required:\n{s}");
    }

    #[test]
    fn sanitize_name_strips_unsafe_chars() {
        // swanctl connection names are restricted; non-hex/dash/underscore
        // chars get stripped so we never try to write a name with a
        // newline or quote in it. Only [0-9a-fA-F-_] survives — even
        // letters like v/i/l/n/m get dropped because UUIDs are our
        // canonical input. (Profile UUIDs already only contain hex+dash.)
        assert_eq!(sanitize_name("abc-def_012"), "abc-def_012");
        assert_eq!(sanitize_name("evil\"name"), "eae"); // e + a + e survive hex test
        assert_eq!(sanitize_name("with space"), "ace");
        assert_eq!(
            sanitize_name("abcd1234-5678-9012-3456-7890abcdef00"),
            "abcd1234-5678-9012-3456-7890abcdef00",
            "real profile UUIDs must round-trip unchanged"
        );
    }

    #[test]
    fn escape_swanctl_handles_special_chars() {
        // Pin the escaping rules; if they ever weaken, the secrets file
        // can be misparsed.
        assert_eq!(escape_swanctl("plain"), "plain");
        assert_eq!(escape_swanctl(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_swanctl(r"a\b"), r"a\\b");
        assert_eq!(escape_swanctl("line1\nline2"), "line1line2");
        assert_eq!(escape_swanctl("with\rcarriage"), "withcarriage");
    }
}
