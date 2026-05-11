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
pub async fn sweep_stale_configs() {
    for prefix in BREW_PATHS {
        for subdir in ["etc/swanctl/conf.d", "etc/swanctl/swanctl.d"] {
            let dir = std::path::Path::new(prefix).join(subdir);
            let Ok(mut entries) = tokio::fs::read_dir(&dir).await else { continue };
            while let Ok(Some(entry)) = entries.next_entry().await {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if name.starts_with("supermanager-") {
                    let _ = tokio::fs::remove_file(entry.path()).await;
                    tracing::debug!(path = %entry.path().display(), "swept stale config");
                }
            }
        }
    }
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
        tokio::fs::remove_file(&conf_path).await.ok();
        tokio::fs::remove_file(&secrets_path).await.ok();
        let _ = run(swanctl, &["--load-all"]).await;

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
        let out = run(swanctl, &["--list-sas"]).await.unwrap_or_default();
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
