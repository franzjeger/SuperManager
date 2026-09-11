//! Exit-node changes with a baseline, verification and conditional rollback.
use crate::tailscale_management::{profiles, run_cli_output, CONTROL_LOCK};
use std::{net::SocketAddr, time::Duration};
use supermgr_core::tailscale::TailscaleNode;

#[derive(Clone)]
struct State {
    profile: String,
    exit_id: String,
    exit_ip: String,
    running: bool,
    nodes: Vec<TailscaleNode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Selection {
    id: String,
    ip: String,
}

impl State {
    fn selection(&self) -> Result<Selection, String> {
        if self.exit_id.is_empty() && self.exit_ip.is_empty() {
            return Ok(Selection {
                id: String::new(),
                ip: String::new(),
            });
        }
        let node = self.nodes.iter().find(|n| {
            (!self.exit_id.is_empty() && n.id == self.exit_id)
                || (!self.exit_ip.is_empty() && n.tailscale_ips.contains(&self.exit_ip))
        });
        if let Some(node) = node {
            return selected(node);
        }
        // Refuse to lose an old selection we cannot restore faithfully.
        Err("The previous exit node is no longer in the device list. Stop using it before choosing another.".into())
    }
    fn matches(&self, selection: &Selection) -> bool {
        if selection.id.is_empty() {
            self.exit_id.is_empty() && self.exit_ip.is_empty()
        } else {
            self.exit_id == selection.id
                || (self.exit_id.is_empty() && self.exit_ip == selection.ip)
        }
    }
}

fn selected(node: &TailscaleNode) -> Result<Selection, String> {
    let ip = node.primary_ip().ok_or("Exit node has no address")?;
    let _: std::net::IpAddr = ip.parse().map_err(|_| "Exit node address is invalid")?;
    if node.id.is_empty() {
        return Err("Exit node has no stable identity".into());
    }
    Ok(Selection {
        id: node.id.clone(),
        ip: ip.into(),
    })
}

#[async_trait::async_trait]
trait Network: Send + Sync {
    async fn state(&self) -> Result<State, String>;
    async fn apply(&self, selection: &Selection) -> Result<(), String>;
    async fn probe(&self, targets: &[SocketAddr]) -> Vec<SocketAddr>;
    async fn settle(&self);
}

struct Live;
async fn command(args: &[String]) -> Result<String, String> {
    let output = run_cli_output(
        std::path::Path::new("tailscale"),
        args,
        Duration::from_secs(5),
    )
    .await?;
    Ok(String::from_utf8_lossy(&output.stdout).into())
}

#[async_trait::async_trait]
impl Network for Live {
    async fn state(&self) -> Result<State, String> {
        let prefs_args = vec!["debug".into(), "prefs".into()];
        let (accounts, prefs, nodes) = tokio::join!(
            profiles(),
            command(&prefs_args),
            crate::tailscale::list_nodes()
        );
        let accounts = accounts?;
        let profile = accounts
            .iter()
            .find(|p| p.selected)
            .map(|p| p.id.clone())
            .ok_or("No active Tailscale account")?;
        let raw: serde_json::Value =
            serde_json::from_str(&prefs?).map_err(|_| "Invalid Tailscale preferences")?;
        let text = |key: &str| {
            raw[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("Tailscale did not report {key}; no routes were changed"))
        };
        Ok(State {
            profile,
            exit_id: text("ExitNodeID")?,
            exit_ip: text("ExitNodeIP")?,
            running: raw["WantRunning"]
                .as_bool()
                .ok_or("Tailscale running preference unknown")?,
            nodes: nodes?,
        })
    }
    async fn apply(&self, selection: &Selection) -> Result<(), String> {
        command(&["set".into(), format!("--exit-node={}", selection.ip)])
            .await
            .map(|_| ())
    }
    async fn probe(&self, targets: &[SocketAddr]) -> Vec<SocketAddr> {
        let probes = targets.iter().map(|address| async move {
            tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(address),
            )
            .await
            .is_ok_and(|result| result.is_ok())
            .then_some(*address)
        });
        futures_util::future::join_all(probes)
            .await
            .into_iter()
            .flatten()
            .collect()
    }
    async fn settle(&self) {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn rollback(
    network: &impl Network,
    profile: &str,
    previous: &Selection,
    applied: &Selection,
    cause: &str,
) -> Result<String, String> {
    let current = network.state().await.map_err(|e| format!("{cause} Could not inspect the current selection: {e}. Refresh Exit node before making another change."))?;
    if current.profile != profile || (!current.matches(applied) && !current.matches(previous)) {
        return Err(format!(
            "{cause} Account or exit-node selection changed meanwhile; the newer choice was kept."
        ));
    }
    if !current.matches(previous) {
        network.apply(previous).await.map_err(|e| format!("{cause} Restoring the previous exit node failed: {e}. Use Stop using to clear the selection."))?;
    }
    let restored = network.state().await?;
    if restored.profile != profile || !restored.matches(previous) {
        return Err(format!(
            "{cause} The previous selection could not be verified. Refresh Exit node."
        ));
    }
    Err(format!("{cause} Previous exit-node selection restored."))
}

async fn change_with(
    network: &impl Network,
    expected: &str,
    target: &str,
) -> Result<String, String> {
    let before = network.state().await?;
    if expected.is_empty() || before.profile != expected {
        return Err(
            "The active Tailscale account changed. Refresh before choosing an exit node.".into(),
        );
    }
    if target.is_empty() {
        let empty = Selection {
            id: String::new(),
            ip: String::new(),
        };
        network.apply(&empty).await?;
        let after = network.state().await?;
        return if after.profile == expected && after.matches(&empty) {
            Ok("Exit node cleared.".into())
        } else {
            Err("Account or selection changed while clearing the exit node. Refresh to inspect the current selection.".into())
        };
    }
    if !before.running {
        return Err("Connect Tailscale before selecting an exit node.".into());
    }
    let node = before
        .nodes
        .iter()
        .find(|n| {
            n.id == target || n.tailscale_ips.iter().any(|ip| ip == target) || n.dns_name == target
        })
        .filter(|n| n.online && n.exit_node_option && !n.is_self)
        .ok_or("Select an online exit node in the current tailnet")?;
    let desired = selected(node)?;
    let previous = before.selection()?;
    if before.matches(&desired) {
        return Ok("This exit node is already selected.".into());
    }
    let probes: [SocketAddr; 2] = [
        "1.1.1.1:443".parse().unwrap(),
        "8.8.8.8:443".parse().unwrap(),
    ];
    let baseline = network.probe(&probes).await;
    if baseline.is_empty() {
        return Err("Internet connectivity could not be established before switching. No settings changed. Run DNS diagnostics or try again when connected.".into());
    }
    let fresh = network.state().await?;
    if fresh.profile != expected || !fresh.matches(&previous) || !fresh.running {
        return Err("Account, connection or exit-node selection changed before applying. No settings changed.".into());
    }
    if let Err(error) = network.apply(&desired).await {
        return rollback(
            network,
            expected,
            &previous,
            &desired,
            &format!("Exit-node change failed: {error}."),
        )
        .await;
    }
    let mut consecutive = 0;
    for _ in 0..4 {
        network.settle().await;
        let current = network.state().await.map_err(|e| format!("The exit-node change could not be verified: {e}. The current selection is unverified; refresh Exit node or use Stop using."))?;
        if !current.running {
            return Err("Tailscale was disconnected during verification. The current selection was kept; connect and retry.".into());
        }
        if current.profile != expected || !current.matches(&desired) {
            return Err("Account or exit-node selection changed during verification; the newer choice was kept.".into());
        }
        if !network.probe(&baseline).await.is_empty() {
            consecutive += 1;
        } else {
            consecutive = 0;
        }
        if consecutive >= 2 {
            let final_state = network.state().await?;
            if final_state.profile == expected
                && final_state.matches(&desired)
                && final_state.running
            {
                return Ok("Exit node selected. Internet TCP connectivity verified twice; DNS can be checked separately in Diagnostics.".into());
            }
            return Err(
                "Selection changed after the connectivity check. Refresh the device list.".into(),
            );
        }
    }
    rollback(
        network,
        expected,
        &previous,
        &desired,
        "Connectivity did not recover reliably after switching.",
    )
    .await
}

pub async fn change(profile: &str, target: &str) -> Result<String, String> {
    let profile = profile.to_owned();
    let target = target.to_owned();
    // Keep verification/rollback alive if a GUI connection closes mid-call.
    tokio::spawn(async move {
        let _guard = CONTROL_LOCK.lock().await;
        crate::tailscale_accounts::ensure_idle()?;
        change_with(&Live, &profile, &target).await
    })
    .await
    .map_err(|e| format!("Exit-node task stopped: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};
    struct Fake {
        state: Mutex<State>,
        probes: Mutex<VecDeque<bool>>,
        applied: Mutex<Vec<String>>,
        external: Option<(usize, String, String)>,
        rounds: Mutex<usize>,
        fail_apply: bool,
        pause_at: Option<usize>,
    }
    fn fixture(probes: &[bool]) -> Fake {
        let nodes: Vec<TailscaleNode> = ["old", "new"].into_iter().enumerate().map(|(i, id)| serde_json::from_value(serde_json::json!({
            "id":id,"hostname":id,"dns_name":format!("{id}.test.ts.net"),"os":"linux","tailscale_ips":[format!("100.64.0.{}",i+1)],"online":true,"is_self":false,"exit_node":false,"exit_node_option":true,"last_seen":"","rx_bytes":0,"tx_bytes":0
        })).unwrap()).collect();
        Fake {
            state: Mutex::new(State {
                profile: "account".into(),
                exit_id: "old".into(),
                exit_ip: String::new(),
                running: true,
                nodes,
            }),
            probes: Mutex::new(probes.iter().copied().collect()),
            applied: Mutex::new(vec![]),
            external: None,
            rounds: Mutex::new(0),
            fail_apply: false,
            pause_at: None,
        }
    }
    #[async_trait::async_trait]
    impl Network for Fake {
        async fn state(&self) -> Result<State, String> {
            Ok(self.state.lock().unwrap().clone())
        }
        async fn apply(&self, selection: &Selection) -> Result<(), String> {
            self.applied.lock().unwrap().push(selection.id.clone());
            self.state.lock().unwrap().exit_id = selection.id.clone();
            if self.fail_apply && selection.id == "new" {
                Err("partial CLI failure".into())
            } else {
                Ok(())
            }
        }
        async fn probe(&self, targets: &[SocketAddr]) -> Vec<SocketAddr> {
            let mut round = self.rounds.lock().unwrap();
            *round += 1;
            if self.pause_at == Some(*round) {
                self.state.lock().unwrap().running = false;
            }
            if let Some((at, profile, node)) = &self.external {
                if *round == *at {
                    let mut state = self.state.lock().unwrap();
                    state.profile = profile.clone();
                    state.exit_id = node.clone();
                }
            }
            if self.probes.lock().unwrap().pop_front().unwrap_or(false) {
                targets.to_vec()
            } else {
                vec![]
            }
        }
        async fn settle(&self) {}
    }
    #[tokio::test]
    async fn failed_switch_restores_the_previous_exit_node() {
        let f = fixture(&[true, false, false, false, false]);
        assert!(change_with(&f, "account", "new")
            .await
            .unwrap_err()
            .contains("restored"));
        assert_eq!(*f.applied.lock().unwrap(), ["new", "old"]);
    }
    #[tokio::test]
    async fn successful_switch_requires_two_consecutive_successes() {
        let f = fixture(&[true, true, false, true, true]);
        assert!(change_with(&f, "account", "new").await.is_ok());
        assert_eq!(*f.rounds.lock().unwrap(), 5);
        assert_eq!(*f.applied.lock().unwrap(), ["new"]);
    }
    #[tokio::test]
    async fn missing_baseline_or_stale_account_never_changes_settings() {
        for (profile, target) in [("account", "new"), ("stale", "new"), ("account", "deleted")] {
            let f = fixture(&[false]);
            assert!(change_with(&f, profile, target).await.is_err());
            assert!(f.applied.lock().unwrap().is_empty());
        }
    }
    #[tokio::test]
    async fn external_changes_including_network_recovery_are_not_rolled_back() {
        for (profile, node) in [("other-account", "new"), ("account", "another-node")] {
            let mut f = fixture(&[true, false, false, false, false]);
            f.external = Some((2, profile.into(), node.into()));
            assert!(change_with(&f, "account", "new")
                .await
                .unwrap_err()
                .contains("newer choice"));
            assert_eq!(*f.applied.lock().unwrap(), ["new"]);
        }
    }
    #[tokio::test]
    async fn partial_cli_failure_also_restores_the_old_selection() {
        let mut f = fixture(&[true]);
        f.fail_apply = true;
        assert!(change_with(&f, "account", "new")
            .await
            .unwrap_err()
            .contains("restored"));
        assert_eq!(*f.applied.lock().unwrap(), ["new", "old"]);
    }
    #[tokio::test]
    async fn clearing_an_exit_node_does_not_require_working_internet() {
        let f = fixture(&[]);
        assert!(change_with(&f, "account", "").await.is_ok());
        assert_eq!(*f.applied.lock().unwrap(), [""]);
        assert_eq!(*f.rounds.lock().unwrap(), 0);
    }
    #[tokio::test]
    async fn disconnecting_during_a_switch_never_reports_verified_connectivity() {
        for round in [1, 2] {
            let mut f = fixture(&[true, true, true]);
            f.pause_at = Some(round);
            assert!(change_with(&f, "account", "new").await.is_err());
            assert!(!f.state.lock().unwrap().running);
            assert_eq!(
                f.applied.lock().unwrap().len(),
                if round == 1 { 0 } else { 1 }
            );
        }
    }
}
