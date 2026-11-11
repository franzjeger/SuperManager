//! Notification configuration persistence (`notify.toml`).
//!
//! Stores per-customer webhook URLs and `PagerDuty` / `OpsGenie` escalation keys
//! managed by the Mac app's Settings → Integrations panel.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyConfig {
    /// Per-customer-slug → Slack/Mattermost incoming webhook URL.
    #[serde(default)]
    pub webhooks: std::collections::HashMap<String, String>,
    /// Per-customer-slug → `PagerDuty` Events API v2 routing key.
    #[serde(default)]
    pub pagerduty_keys: std::collections::HashMap<String, String>,
    /// Per-customer-slug → `OpsGenie` Genie API key.
    #[serde(default)]
    pub opsgenie_keys: std::collections::HashMap<String, String>,
}

fn config_path() -> PathBuf {
    let mut p = crate::secrets::default_data_dir();
    p.push("notify.toml");
    p
}

pub fn try_load_config() -> Result<NotifyConfig> {
    try_load_config_at(&config_path())
}

fn try_load_config_at(path: &std::path::Path) -> Result<NotifyConfig> {
    match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).with_context(|| format!("parse {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(NotifyConfig::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

pub fn save_config(cfg: &NotifyConfig) -> Result<()> {
    save_config_at(&config_path(), cfg)
}

fn save_config_at(path: &std::path::Path, cfg: &NotifyConfig) -> Result<()> {
    // Refuse to clobber an unreadable/corrupt file on disk.
    if path.exists() {
        try_load_config_at(path)
            .context("refusing to overwrite corrupt notify.toml; repair or remove it first")?;
    }
    let s = toml::to_string_pretty(cfg).context("serialize notify config")?;
    crate::state::write_private_atomic(path, s.as_bytes())
        .with_context(|| format!("write {path:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_config_writes_private_file_and_refuses_corrupt_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.toml");
        let mut cfg = NotifyConfig::default();
        cfg.pagerduty_keys
            .insert("acme".into(), "pd-routing-secret".into());
        save_config_at(&path, &cfg).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let loaded = try_load_config_at(&path).unwrap();
        assert_eq!(
            loaded.pagerduty_keys.get("acme").map(String::as_str),
            Some("pd-routing-secret")
        );

        std::fs::write(&path, "broken = [toml").unwrap();
        assert!(try_load_config_at(&path).is_err());
        assert!(save_config_at(&path, &cfg).is_err());
    }
}
