//! Bounded, typed access to Tailscale settings and saved accounts.
use std::time::Duration;
use supermgr_core::tailscale::{
    TailscaleManagement, TailscalePreferences, TailscalePreferencesPatch, TailscaleProfile,
};

pub static CONTROL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) async fn cli(args: &[String]) -> Result<String, String> {
    run_cli(
        std::path::Path::new("tailscale"),
        args,
        Duration::from_secs(20),
    )
    .await
}

async fn run_cli(
    binary: &std::path::Path,
    args: &[String],
    timeout: Duration,
) -> Result<String, String> {
    let output = run_cli_output(binary, args, timeout).await?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub(crate) async fn mutate(args: &[String]) -> Result<String, String> {
    let output = run_cli_output(
        std::path::Path::new("tailscale"),
        args,
        Duration::from_secs(20),
    )
    .await?;
    Ok(format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .trim()
    .to_owned())
}

pub(crate) async fn run_cli_output(
    binary: &std::path::Path,
    args: &[String],
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let output = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(binary)
            .args(args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "Tailscale command timed out".to_owned())?
    .map_err(|e| format!("Could not run Tailscale: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Tailscale command failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(4096)
                .collect::<String>()
                .trim()
        ));
    }
    Ok(output)
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

pub(crate) async fn profiles() -> Result<Vec<TailscaleProfile>, String> {
    let raw = cli(&args(&["switch", "--list", "--json"])).await?;
    serde_json::from_str(&raw).map_err(|_| "Tailscale returned an unsupported account list".into())
}

fn parse_preferences(raw: &str) -> Result<TailscalePreferences, String> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| "Tailscale returned invalid preferences")?;
    if !v.is_object() {
        return Err("Tailscale returned an unsupported preferences format".into());
    }
    let advertised = match v.get("AdvertiseRoutes") {
        Some(serde_json::Value::Null) => Some(vec![]),
        Some(serde_json::Value::Array(routes)) => routes
            .iter()
            .map(|r| r.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>(),
        _ => None,
    };
    Ok(TailscalePreferences {
        profile_id: None,
        want_running: v["WantRunning"].as_bool(),
        accept_dns: v["CorpDNS"].as_bool(),
        accept_routes: v["RouteAll"].as_bool(),
        shields_up: v["ShieldsUp"].as_bool(),
        run_ssh: v["RunSSH"].as_bool(),
        exit_node_allow_lan: v["ExitNodeAllowLANAccess"].as_bool(),
        advertise_exit_node: advertised
            .as_ref()
            .map(|routes| routes.iter().any(|r| r == "0.0.0.0/0" || r == "::/0")),
        advertise_routes: advertised.map(|routes| {
            routes
                .into_iter()
                .filter(|r| r != "0.0.0.0/0" && r != "::/0")
                .collect()
        }),
        hostname: v["Hostname"].as_str().map(str::to_owned),
        auto_update: v["AutoUpdate"]["Apply"].as_bool(),
    })
}

pub async fn snapshot() -> TailscaleManagement {
    let _guard = CONTROL_LOCK.lock().await;
    let read_prefs = args(&["debug", "prefs"]);
    let (prefs, profiles) = tokio::join!(cli(&read_prefs), profiles());
    let mut out = TailscaleManagement::default();
    match profiles {
        Ok(p) => out.profiles = p,
        Err(e) => out.warnings.push(format!("Accounts unavailable: {e}")),
    }
    match prefs.and_then(|raw| parse_preferences(&raw)) {
        Ok(mut p) => {
            p.profile_id = out
                .profiles
                .iter()
                .find(|p| p.selected)
                .map(|p| p.id.clone());
            out.preferences = Some(p);
        }
        Err(e) => out.warnings.push(format!("Settings unavailable: {e}")),
    }
    out
}

fn patch_args(p: &TailscalePreferencesPatch) -> Result<Vec<String>, String> {
    let mut out = args(&["set"]);
    for (flag, value) in [
        ("accept-dns", p.accept_dns),
        ("accept-routes", p.accept_routes),
        ("shields-up", p.shields_up),
        ("ssh", p.run_ssh),
        ("exit-node-allow-lan-access", p.exit_node_allow_lan),
        ("advertise-exit-node", p.advertise_exit_node),
        ("auto-update", p.auto_update),
    ] {
        if let Some(value) = value {
            out.push(format!("--{flag}={value}"));
        }
    }
    if let Some(hostname) = &p.hostname {
        if !hostname.is_empty()
            && (hostname.len() > 63
                || hostname.starts_with('-')
                || hostname.ends_with('-')
                || !hostname
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-'))
        {
            return Err("Hostname must be a DNS label of at most 63 letters, digits or hyphens, or empty to use the OS name".into());
        }
        out.push(format!("--hostname={hostname}"));
    }
    if let Some(routes) = &p.advertise_routes {
        if routes.len() > 64 {
            return Err("At most 64 advertised subnet routes are supported".into());
        }
        let mut normalized = Vec::new();
        for route in routes {
            let network: ipnet::IpNet = route
                .trim()
                .parse()
                .map_err(|_| format!("Invalid subnet route: {route}"))?;
            if network.prefix_len() == 0 {
                return Err("Use Advertise as exit node for default routes".into());
            }
            let cidr = network.trunc().to_string();
            if !normalized.contains(&cidr) {
                normalized.push(cidr);
            }
        }
        out.push(format!("--advertise-routes={}", normalized.join(",")));
    }
    if out.len() == 1 {
        return Err("No settings have changed".into());
    }
    Ok(out)
}

pub(crate) async fn require_profile(expected: &str) -> Result<(), String> {
    crate::tailscale_accounts::ensure_idle()?;
    if expected.is_empty()
        || !profiles()
            .await?
            .iter()
            .any(|p| p.selected && p.id == expected)
    {
        return Err(
            "The active Tailscale account changed. Refresh before applying this action.".into(),
        );
    }
    Ok(())
}

pub async fn apply(patch: &TailscalePreferencesPatch) -> Result<String, String> {
    let command = patch_args(patch)?;
    let _guard = CONTROL_LOCK.lock().await;
    require_profile(&patch.profile_id).await?;
    mutate(&command).await
}

pub async fn set_running(profile_id: &str, running: bool) -> Result<String, String> {
    let _guard = CONTROL_LOCK.lock().await;
    require_profile(profile_id).await?;
    mutate(&if running {
        args(&["up", "--timeout=15s"])
    } else {
        args(&["down"])
    })
    .await
}

pub async fn switch_profile(id: &str) -> Result<String, String> {
    let _guard = CONTROL_LOCK.lock().await;
    crate::tailscale_accounts::ensure_idle()?;
    if id.starts_with('-') || id.is_empty() || !profiles().await?.iter().any(|p| p.id == id) {
        return Err("Select an existing saved Tailscale account".into());
    }
    mutate(&args(&["switch", id])).await
}

pub async fn logout(profile_id: &str) -> Result<String, String> {
    let _guard = CONTROL_LOCK.lock().await;
    require_profile(profile_id).await?;
    mutate(&args(&["logout"])).await
}

pub async fn ping(node_id: &str) -> Result<String, String> {
    let nodes = crate::tailscale::list_nodes().await?;
    let node = nodes
        .iter()
        .find(|n| n.id == node_id && !n.is_self)
        .ok_or("Peer is no longer in the active tailnet")?;
    let ip: std::net::IpAddr = node
        .primary_ip()
        .ok_or("Peer has no address")?
        .parse()
        .map_err(|_| "Peer address is invalid")?;
    cli(&args(&["ping", "--c=3", "--timeout=3s", &ip.to_string()])).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_are_projected_without_secrets_or_invented_defaults() {
        let prefs = parse_preferences(r#"{"CorpDNS":true,"RouteAll":false,"AdvertiseRoutes":["0.0.0.0/0","::/0","192.168.3.0/24"],"AutoUpdate":{"Apply":null},"Persist":{"PrivateNodeKey":"do-not-expose"}}"#).unwrap();
        assert_eq!(prefs.accept_dns, Some(true));
        assert_eq!(prefs.run_ssh, None);
        assert_eq!(prefs.auto_update, None);
        assert_eq!(prefs.advertise_exit_node, Some(true));
        assert_eq!(prefs.advertise_routes, Some(vec!["192.168.3.0/24".into()]));
        assert!(!serde_json::to_string(&prefs)
            .unwrap()
            .contains("do-not-expose"));
        assert_eq!(
            parse_preferences(r#"{"AdvertiseRoutes":null}"#)
                .unwrap()
                .advertise_routes,
            Some(vec![])
        );
        assert!(parse_preferences("[]").is_err());
    }

    #[test]
    fn patches_modify_only_explicit_fields_and_validate_routes_and_names() {
        let patch = TailscalePreferencesPatch {
            profile_id: "fixture".into(),
            accept_dns: Some(false),
            ..Default::default()
        };
        assert_eq!(patch_args(&patch).unwrap(), ["set", "--accept-dns=false"]);
        for hostname in [
            "--operator=root",
            "a b",
            "a;reboot",
            "-host",
            "host-",
            "a/b",
        ] {
            assert!(patch_args(&TailscalePreferencesPatch {
                hostname: Some(hostname.into()),
                ..patch.clone()
            })
            .is_err());
        }
        let routes = TailscalePreferencesPatch {
            advertise_routes: Some(vec!["192.168.4.9/24".into(), "fd00:1::/64".into()]),
            ..Default::default()
        };
        assert_eq!(
            patch_args(&routes).unwrap(),
            ["set", "--advertise-routes=192.168.4.0/24,fd00:1::/64"]
        );
        for route in ["0.0.0.0/0", "::/0", "--hostname=bad", "10.0.0.1/99"] {
            assert!(patch_args(&TailscalePreferencesPatch {
                advertise_routes: Some(vec![route.into()]),
                ..Default::default()
            })
            .is_err());
        }
        assert_eq!(
            patch_args(&TailscalePreferencesPatch {
                advertise_routes: Some(vec![]),
                ..Default::default()
            })
            .unwrap(),
            ["set", "--advertise-routes="]
        );
        assert!(serde_json::from_str::<TailscalePreferencesPatch>(
            r#"{"profile_id":"fixture","operator":"root"}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn cli_errors_and_timeouts_are_not_successful_changes() {
        let sh = std::path::Path::new("/bin/sh");
        assert_eq!(
            run_cli(sh, &args(&["-c", "printf fixture"]), Duration::from_secs(1))
                .await
                .unwrap(),
            "fixture"
        );
        assert!(run_cli(
            sh,
            &args(&["-c", "echo denied >&2; exit 1"]),
            Duration::from_secs(1)
        )
        .await
        .unwrap_err()
        .contains("denied"));
        assert!(run_cli(
            sh,
            &args(&["-c", "exec sleep 5"]),
            Duration::from_millis(30)
        )
        .await
        .unwrap_err()
        .contains("timed out"));
    }
}
