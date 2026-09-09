//! Fixed-service Tailscale handoff for the signed Dev helper only.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{os::unix::fs::MetadataExt, path::Path, time::Duration};
use tokio::process::Command;

pub static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[derive(Clone, Copy, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Target { Stable, Dev }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchArgs { pub target: Target }
impl Target {
    fn label(self) -> &'static str { match self {
        Self::Stable => "com.sybr.tailscaled", Self::Dev => "com.sybr.supermanager.dev.tailscaled",
    }}
    fn socket(self) -> &'static str { match self {
        Self::Stable => "/var/run/tailscaled.socket", Self::Dev => "/var/run/supermanager-dev-tailscaled.socket",
    }}
    fn other(self) -> Self { if self == Self::Stable { Self::Dev } else { Self::Stable } }
    fn plist(self) -> String { format!("/Library/LaunchDaemons/{}.plist", self.label()) }
    fn service(self) -> String { format!("system/{}", self.label()) }
}
#[derive(Serialize)]
pub struct State { stable_running: bool, dev_running: bool, both_running: bool }
async fn command(program: &str, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new(program);
    cmd.args(args).env_clear().env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(8), cmd.output()).await.context("Service command timed out")?.context("Service command failed")
}
async fn loaded(target: Target) -> Result<bool> {
    Ok(command("/bin/launchctl", &["print", &target.service()]).await?.status.success())
}
async fn ready(target: Target) -> Result<bool> {
    let output = command("/bin/launchctl", &["print", &target.service()]).await?;
    if !output.status.success() || !String::from_utf8_lossy(&output.stdout).contains("state = running") { return Ok(false); }
    Ok(tokio::time::timeout(Duration::from_millis(300), tokio::net::UnixStream::connect(target.socket())).await.is_ok_and(|r| r.is_ok()))
}
pub async fn status() -> Result<State> {
    let stable_running = ready(Target::Stable).await?;
    let dev_running = ready(Target::Dev).await?;
    Ok(State { stable_running, dev_running, both_running: stable_running && dev_running })
}
fn protected_file(path: &Path) -> Result<()> {
    crate::secure_files::check_root_ancestors(path.parent().context("Missing parent")?)?;
    let m = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0, "Service file must be root-owned, regular and protected");
    Ok(())
}
fn valid_binary(target: Target, binary: &str) -> bool {
    match target {
        Target::Stable => matches!(binary, "/usr/local/sbin/supermanager-tailscaled" | "/Library/PrivilegedHelperTools/com.sybr.supermanager.tailscaled"),
        Target::Dev => binary == "/Library/PrivilegedHelperTools/com.sybr.supermanager.dev.tailscaled",
    }
}
async fn validate(target: Target) -> Result<()> {
    let plist = target.plist(); protected_file(Path::new(&plist))?;
    let out = command("/usr/bin/plutil", &["-convert", "json", "-o", "-", &plist]).await?;
    anyhow::ensure!(out.status.success(), "Invalid service plist");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    anyhow::ensure!(value["Label"].as_str() == Some(target.label()), "Service label mismatch");
    let binary = value["ProgramArguments"][0].as_str().context("Missing daemon program")?;
    anyhow::ensure!(valid_binary(target, binary), "Unexpected daemon path");
    anyhow::ensure!(value.get("Program").is_none(), "Separate launchd Program override is not supported");
    protected_file(Path::new(binary))?;
    let identity = match target { Target::Stable => "com.sybr.supermanager.tailscaled", Target::Dev => "com.sybr.supermanager.dev.tailscaled" };
    crate::authorization::verify_component(Path::new(binary), identity)?;
    Ok(())
}
fn owned_process_alive(target: Target, pid: i32) -> bool {
    let mut bytes = [0u8; 4096];
    let size = unsafe { libc::proc_pidpath(pid, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    size > 0 && valid_binary(target, std::str::from_utf8(&bytes[..size as usize]).unwrap_or("").trim_end_matches('\0'))
}
async fn stop(target: Target) -> Result<()> {
    let before = command("/bin/launchctl", &["print", &target.service()]).await?;
    let pid: Option<i32> = String::from_utf8_lossy(&before.stdout).lines()
        .find_map(|line| line.trim().strip_prefix("pid = ").and_then(|v| v.parse().ok()));
    let _ = command("/bin/launchctl", &["bootout", &target.service()]).await?;
    for _ in 0..60 {
        if !loaded(target).await? && !pid.is_some_and(|p| owned_process_alive(target, p)) { return Ok(()); }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("Timed out stopping {}; no other node was started", target.label())
}
async fn set_enabled(target: Target, enabled: bool) -> Result<()> {
    let action = if enabled { "enable" } else { "disable" };
    let out = command("/bin/launchctl", &[action, &target.service()]).await?;
    anyhow::ensure!(out.status.success(), "Could not {action} {}", target.label());
    Ok(())
}
async fn is_disabled(target: Target) -> Result<bool> {
    let out = command("/bin/launchctl", &["print-disabled", "system"]).await?;
    anyhow::ensure!(out.status.success(), "Cannot read launchd enablement");
    Ok(String::from_utf8_lossy(&out.stdout).lines().any(|l| l.trim() == format!("\"{}\" => disabled", target.label())))
}
async fn start(target: Target) -> Result<()> {
    if ready(target).await? { return Ok(()); }
    if loaded(target).await? { stop(target).await?; }
    for _ in 0..5 {
        let out = command("/bin/launchctl", &["bootstrap", "system", &target.plist()]).await?;
        if out.status.success() { break; }
        if loaded(target).await? { break; }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    for _ in 0..40 {
        if ready(target).await? { return Ok(()); }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("{} did not become ready", target.label())
}
/// Caller holds LOCK, also shared with daemon installation/uninstallation.
pub async fn switch(args: SwitchArgs) -> Result<State> {
    let target = args.target; let source = target.other();
    validate(target).await?;
    let source_loaded = loaded(source).await?;
    if source_loaded { validate(source).await?; }
    let source_disabled = is_disabled(source).await?;
    let target_disabled = is_disabled(target).await?;
    let target_loaded = loaded(target).await?;
    let result: Result<()> = async {
        set_enabled(source, false).await?;
        stop(source).await?;
        set_enabled(target, true).await?;
        start(target).await?;
        anyhow::ensure!(!loaded(source).await?, "Other Tailscale service restarted during handoff");
        Ok(())
    }.await;
    if let Err(error) = result {
        // Do not restore the old node while a newly started target is still live.
        let recovery: Result<()> = async {
            if !target_loaded { stop(target).await?; }
            set_enabled(target, !target_disabled).await?;
            set_enabled(source, !source_disabled).await?;
            if source_loaded { start(source).await?; }
            Ok(())
        }.await;
        return match recovery {
            Ok(()) => Err(error.context("Switch failed; previous service state restored")),
            Err(recovery) => Err(anyhow::anyhow!("Switch failed: {error:#}. Recovery incomplete: {recovery:#}. Check service status before connecting.")),
        };
    }
    tracing::info!(target = target.label(), "Tailscale service handoff completed");
    status().await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn targets_cannot_name_arbitrary_services_or_programs() {
        assert!(serde_json::from_str::<SwitchArgs>(r#"{"target":"system/com.apple.sshd"}"#).is_err());
        assert!(serde_json::from_str::<SwitchArgs>(r#"{"target":"dev","path":"/tmp/evil"}"#).is_err());
        assert!(!valid_binary(Target::Stable, "/tmp/tailscaled"));
        assert!(!valid_binary(Target::Dev, "/usr/local/sbin/supermanager-tailscaled"));
        assert_ne!(Target::Stable.socket(), Target::Dev.socket());
    }
}
