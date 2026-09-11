//! Bounded browser login, cancellation and recovery of the previous account.
use crate::tailscale_management::{mutate, profiles, CONTROL_LOCK};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use supermgr_core::tailscale::TailscaleLoginAttempt;
use supermgr_core::tailscale::TailscaleProfile;

const JOURNAL: &str = "/etc/supermgrd/tailscale-login-recovery.json";
struct Attempt {
    owner: u32,
    view: TailscaleLoginAttempt,
    cancel: Arc<tokio::sync::Notify>,
}
impl Attempt {
    fn belongs_to(&self, id: &str, uid: u32) -> bool {
        self.owner == uid && self.view.id == id
    }
}
static ATTEMPT: Mutex<Option<Attempt>> = Mutex::new(None);

pub fn ensure_idle() -> Result<(), String> {
    if ATTEMPT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|a| a.view.state == "waiting")
    {
        Err(
            "Finish or cancel the pending Tailscale sign-in before changing accounts or settings."
                .into(),
        )
    } else {
        Ok(())
    }
}

pub fn status(id: &str, uid: u32) -> Result<TailscaleLoginAttempt, String> {
    ATTEMPT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .filter(|a| a.belongs_to(id, uid))
        .map(|a| a.view.clone())
        .ok_or_else(|| "This sign-in attempt is no longer available for this user.".into())
}

pub fn cancel(id: &str, uid: u32) -> Result<(), String> {
    let guard = ATTEMPT.lock().unwrap_or_else(|e| e.into_inner());
    let attempt = guard
        .as_ref()
        .filter(|a| a.belongs_to(id, uid))
        .ok_or("This sign-in attempt is no longer available for this user.")?;
    if attempt.view.state == "waiting" {
        attempt.cancel.notify_one();
    }
    Ok(())
}

fn update(id: &str, state: &str, message: &str, url: &str) {
    if let Some(attempt) = ATTEMPT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .filter(|a| a.view.id == id)
    {
        attempt.view.state = state.into();
        attempt.view.message = message.into();
        attempt.view.auth_url = url.into();
    }
}

fn browser_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(parsed)
            if parsed.scheme() == "https"
                && parsed.host_str().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none() =>
        {
            url.into()
        }
        _ => String::new(),
    }
}

fn should_restore(previous: &str, active: Option<&str>, available: &[String]) -> bool {
    !previous.is_empty() && active.is_none() && available.iter().any(|id| id == previous)
}

#[async_trait::async_trait]
trait AccountStore: Send + Sync {
    async fn profiles(&self) -> Result<Vec<TailscaleProfile>, String>;
    async fn select(&self, id: &str) -> Result<(), String>;
}
struct Live;
#[async_trait::async_trait]
impl AccountStore for Live {
    async fn profiles(&self) -> Result<Vec<TailscaleProfile>, String> {
        profiles().await
    }
    async fn select(&self, id: &str) -> Result<(), String> {
        mutate(&["switch".into(), id.into()]).await.map(|_| ())
    }
}

async fn restore_with(store: &impl AccountStore, previous: &str) -> Result<String, String> {
    let current = store.profiles().await?;
    let active = current.iter().find(|p| p.selected).map(|p| p.id.as_str());
    if should_restore(
        previous,
        active,
        &current.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
    ) {
        store.select(previous).await?;
        if !store
            .profiles()
            .await?
            .iter()
            .any(|p| p.selected && p.id == previous)
        {
            return Err("The previous account could not be verified after switching back. Select it in Accounts.".into());
        }
        Ok("Previous account restored.".into())
    } else if active == Some(previous) {
        Ok("Previous account is still selected.".into())
    } else if active.is_some() {
        Ok("Another account is now selected; its settings were kept.".into())
    } else if previous.is_empty() {
        Ok("No previous account to restore.".into())
    } else {
        Err("The previous saved account no longer exists. Select an account manually.".into())
    }
}

/// Called after a daemon restart; never replaces an already selected account.
pub async fn recover() -> Result<(), String> {
    let _guard = CONTROL_LOCK.lock().await;
    recover_locked().await
}

async fn recover_locked() -> Result<(), String> {
    let path = std::path::Path::new(JOURNAL);
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let previous: String = serde_json::from_slice(&raw)
        .map_err(|e| format!("Cannot read sign-in recovery record: {e}"))?;
    let result = restore_with(&Live, &previous).await?;
    tracing::info!("Tailscale sign-in recovery: {result}");
    std::fs::remove_file(path).map_err(|e| e.to_string())
}

pub async fn start(expected: &str, uid: u32) -> Result<TailscaleLoginAttempt, String> {
    let _guard = CONTROL_LOCK.lock().await;
    ensure_idle()?;
    // Preserve an unresolved recovery record instead of overwriting it.
    recover_locked().await?;
    let before = profiles().await?;
    let previous = before
        .iter()
        .find(|p| p.selected)
        .map(|p| p.id.clone())
        .unwrap_or_default();
    if previous != expected {
        return Err("The active account changed. Refresh before starting sign-in.".into());
    }
    let health = crate::tailscale::health().await;
    if !health.cli_present || !health.daemon_running {
        return Err("Start tailscaled before signing in.".into());
    }
    crate::secure_file::write_private(
        std::path::Path::new(JOURNAL),
        &serde_json::to_vec(&previous).map_err(|e| e.to_string())?,
        None,
    )
    .map_err(|e| format!("Cannot save previous account for recovery: {e}"))?;
    let mut child = match tokio::process::Command::new("tailscale")
        .args(["login", "--timeout=180s"])
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            let _ = std::fs::remove_file(JOURNAL);
            return Err(format!("Cannot start Tailscale sign-in: {e}"));
        }
    };
    let view = TailscaleLoginAttempt {
        id: uuid::Uuid::new_v4().to_string(),
        state: "waiting".into(),
        auth_url: String::new(),
        message: "Waiting for a browser sign-in link…".into(),
    };
    let cancel = Arc::new(tokio::sync::Notify::new());
    *ATTEMPT.lock().unwrap_or_else(|e| e.into_inner()) = Some(Attempt {
        owner: uid,
        view: view.clone(),
        cancel: Arc::clone(&cancel),
    });
    let id = view.id.clone();
    tokio::spawn(async move {
        let deadline = tokio::time::sleep(Duration::from_secs(180));
        tokio::pin!(deadline);
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let (mut state, mut message) = loop {
            tokio::select! {
                _ = cancel.notified() => break ("cancelled", "Sign-in cancelled.".to_owned()),
                _ = &mut deadline => break ("failed", "Sign-in timed out after three minutes.".to_owned()),
                result = child.wait() => match result {
                    Ok(exit) if exit.success() => break ("complete", "Tailscale account signed in.".to_owned()),
                    Ok(exit) => break ("failed", format!("Tailscale sign-in ended with {exit}. Try signing in again.")),
                    Err(e) => break ("failed", format!("Tailscale sign-in stopped: {e}")),
                },
                _ = tick.tick() => {
                    let health = crate::tailscale::health().await;
                    let url = browser_url(&health.auth_url);
                    update(&id, "waiting", if url.is_empty() { "Waiting for Tailscale to prepare sign-in…" } else { "Complete sign-in in your browser. Use Cancel to stop this sign-in attempt." }, &url);
                    if let Ok(current) = profiles().await {
                        if current.iter().any(|p| p.selected && p.id != previous && before.iter().any(|old| old.id == p.id)) {
                            break ("cancelled", "Account changed outside this sign-in; kept the newer selection.".into());
                        }
                    }
                }
            }
        };
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _guard = CONTROL_LOCK.lock().await;
        if state == "complete" {
            match profiles().await {
                Ok(current) if current.iter().any(|p| p.selected && !p.id.is_empty()) => {}
                Ok(_) => {
                    state = "failed";
                    message = "Sign-in exited without a selected account.".into();
                }
                Err(error) => {
                    state = "failed";
                    message = format!("Could not verify the signed-in account: {error}");
                }
            }
        }
        let message = if state != "complete" {
            match restore_with(&Live, &previous).await {
                Ok(result) => {
                    let _ = std::fs::remove_file(JOURNAL);
                    format!("{message} {result}")
                }
                Err(error) => format!("{message} Recovery failed: {error}"),
            }
        } else {
            let _ = std::fs::remove_file(JOURNAL);
            message
        };
        update(&id, state, &message, "");
    });
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_login_only_restores_an_empty_profile_and_never_overwrites_new_choices() {
        let saved = vec!["old".into(), "other".into()];
        assert!(should_restore("old", None, &saved));
        assert!(!should_restore("old", Some("other"), &saved));
        assert!(!should_restore("old", Some("newly-authenticated"), &saved));
        assert!(!should_restore("old", Some("old"), &saved));
        assert!(!should_restore("deleted", None, &saved));
        assert!(!should_restore("", None, &saved));
    }
    #[test]
    fn browser_links_cannot_launch_local_programs_or_embed_credentials() {
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user:pass@example.com/",
            "ssh://host",
            "invalid",
        ] {
            assert!(browser_url(url).is_empty());
        }
        assert_eq!(
            browser_url("https://login.tailscale.com/a/test"),
            "https://login.tailscale.com/a/test"
        );
    }
    struct Fake {
        profiles: Mutex<Vec<TailscaleProfile>>,
        selected: Mutex<Vec<String>>,
        fail_switch: bool,
        ignore_switch: bool,
    }
    fn fixture(active: Option<&str>) -> Fake {
        Fake {
            profiles: Mutex::new(
                ["old", "new"]
                    .into_iter()
                    .map(|id| TailscaleProfile {
                        id: id.into(),
                        selected: active == Some(id),
                        ..Default::default()
                    })
                    .collect(),
            ),
            selected: Mutex::new(vec![]),
            fail_switch: false,
            ignore_switch: false,
        }
    }
    #[async_trait::async_trait]
    impl AccountStore for Fake {
        async fn profiles(&self) -> Result<Vec<TailscaleProfile>, String> {
            Ok(self.profiles.lock().unwrap().clone())
        }
        async fn select(&self, id: &str) -> Result<(), String> {
            self.selected.lock().unwrap().push(id.into());
            if self.fail_switch {
                return Err("switch failed".into());
            }
            if !self.ignore_switch {
                for p in self.profiles.lock().unwrap().iter_mut() {
                    p.selected = p.id == id;
                }
            }
            Ok(())
        }
    }
    #[tokio::test]
    async fn recovery_switches_only_an_empty_account_and_verifies_the_result() {
        let f = fixture(None);
        assert!(restore_with(&f, "old").await.unwrap().contains("restored"));
        assert_eq!(*f.selected.lock().unwrap(), ["old"]);
        assert!(f
            .profiles
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.id == "old" && p.selected));
        for active in ["old", "new"] {
            let f = fixture(Some(active));
            restore_with(&f, "old").await.unwrap();
            assert!(f.selected.lock().unwrap().is_empty());
        }
        let f = fixture(None);
        assert!(restore_with(&f, "deleted").await.is_err());
        assert!(f.selected.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn recovery_does_not_report_success_after_a_failed_or_ineffective_switch() {
        let mut f = fixture(None);
        f.fail_switch = true;
        assert!(restore_with(&f, "old")
            .await
            .unwrap_err()
            .contains("switch failed"));
        let mut f = fixture(None);
        f.ignore_switch = true;
        assert!(restore_with(&f, "old")
            .await
            .unwrap_err()
            .contains("could not be verified"));
    }
    #[test]
    fn only_the_owning_user_can_poll_or_cancel_their_specific_attempt() {
        let a = Attempt {
            owner: 1000,
            view: TailscaleLoginAttempt {
                id: "opaque-attempt".into(),
                state: "waiting".into(),
                auth_url: String::new(),
                message: String::new(),
            },
            cancel: Arc::new(tokio::sync::Notify::new()),
        };
        assert!(a.belongs_to("opaque-attempt", 1000));
        assert!(!a.belongs_to("opaque-attempt", 1001));
        assert!(!a.belongs_to("another-attempt", 1000));
    }
}
