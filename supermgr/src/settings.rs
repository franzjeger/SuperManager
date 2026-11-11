//! Persistent per-user appearance settings for supermgr.
//!
//! Settings are stored as JSON at `$XDG_CONFIG_HOME/supermgr/settings.json`
//! (falling back to `~/.config/supermgr/settings.json`). All fields are
//! optional in the file; missing fields use their defaults so that older
//! settings files remain valid after an upgrade.
//!
//! # Credentials and master password are NOT persisted in `settings.json`
//!
//! - The Argon2id master-password hash lives in `master-password.hash`
//!   handled by [`crate::master_password`].
//! - API keys and webhook URLs (`openai_api_key`, `anthropic_api_key`,
//!   `unifi_cloud_api_key`, `webhook_url`) live in the system secret store
//!   (`org.freedesktop.secrets` via [`supermgr_core::keyring::LibsecretStore`]).
//!   Legacy `settings.json` files that still carry those fields migrate them
//!   into the secret store on load and scrub them on the subsequent save.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use serde::{Deserialize, Serialize};
use supermgr_core::error::SecretError;
use supermgr_core::keyring::SecretStore;

const LABEL_OPENAI_API_KEY: &str = "supermgr/ui/openai_api_key";
const LABEL_ANTHROPIC_API_KEY: &str = "supermgr/ui/anthropic_api_key";
const LABEL_UNIFI_CLOUD_API_KEY: &str = "supermgr/ui/unifi_cloud_api_key";
const LABEL_WEBHOOK_URL: &str = "supermgr/ui/webhook_url";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The colour scheme to request from libadwaita.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColorScheme {
    /// Follow the system / desktop preference.
    #[default]
    Default,
    /// Force a light appearance regardless of the system setting.
    Light,
    /// Force a dark appearance regardless of the system setting.
    Dark,
}

/// AI provider selected in the console. Existing installations retain Claude.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProvider {
    /// Anthropic API or the Claude Code subscription.
    #[default]
    Claude,
    /// Codex CLI with the operator's existing ChatGPT/Codex login.
    Codex,
    /// OpenAI Responses API with a separately configured API key.
    OpenAi,
}

/// Default Anthropic model, overridable in Settings.
pub fn default_anthropic_model() -> String {
    anthropic_model_id("").into()
}

/// Recover the retired original default, including old saved settings.
/// Preserve other explicit model IDs instead of guessing from a 404.
pub fn anthropic_model_id(configured: &str) -> &str {
    match configured.trim() {
        "" | "claude-sonnet-4-20250514" | "claude-sonnet-4-0" => "claude-sonnet-5",
        model => model,
    }
}

fn deserialize_anthropic_model<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let model = String::deserialize(deserializer)?;
    Ok(anthropic_model_id(&model).to_owned())
}

/// Default OpenAI API model, overridable in Settings.
pub fn default_openai_model() -> String {
    "gpt-6-astra".into()
}

/// Serialisable application settings.
#[derive(Clone, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(default)]
    pub layout: LayoutSettings,
    /// AI backend used for new console requests.
    #[serde(default)]
    pub ai_provider: AiProvider,
    /// OpenAI API credential; stored in the system secret store, never serialised to JSON.
    #[serde(default, skip_serializing)]
    pub openai_api_key: String,
    /// OpenAI Responses model ID.
    #[serde(default = "default_openai_model")]
    pub openai_model: String,
    /// Claude model ID, shared by the API and subscription CLI.
    #[serde(
        default = "default_anthropic_model",
        deserialize_with = "deserialize_anthropic_model"
    )]
    pub anthropic_model: String,
    /// Which colour scheme to use.
    #[serde(default)]
    pub color_scheme: ColorScheme,
    /// Window opacity in the range `[0.1, 1.0]`.
    #[serde(default = "default_opacity")]
    pub opacity: f64,
    /// Anthropic API key for the built-in Claude console; stored in the system secret store.
    #[serde(default, skip_serializing)]
    pub anthropic_api_key: String,
    /// Whether to use Claude Code CLI (subscription) instead of API key.
    #[serde(default)]
    pub use_claude_subscription: bool,
    /// Migration-only: legacy settings.json files written by builds before
    /// the master-password split contained a `password_hash` field here.
    #[serde(default, skip_serializing, rename = "password_hash")]
    legacy_password_hash: String,
    /// Minutes of inactivity before the session auto-locks.
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u64,

    // ---- Webhook / notification settings ----
    /// Webhook URL for outgoing notifications (Slack, Teams, Discord); stored in the secret store.
    #[serde(default, skip_serializing)]
    pub webhook_url: String,
    /// Send a webhook notification when an SSH host goes down.
    #[serde(default = "default_true")]
    pub webhook_on_host_down: bool,
    /// Send a webhook notification when a VPN tunnel disconnects unexpectedly.
    #[serde(default)]
    pub webhook_on_vpn_disconnect: bool,

    // ---- UniFi Cloud (ui.com Site Manager) ----
    /// API key for the UI.com Site Manager API; stored in the system secret store.
    #[serde(default, skip_serializing)]
    pub unifi_cloud_api_key: String,

    // ---- Remote Desktop ----
    /// Preferred RDP client: "auto", "remmina", "xfreerdp3", "xfreerdp".
    #[serde(default = "default_rdp_client")]
    pub rdp_client: String,

    /// Set when `settings.json` existed on disk but could not be read or parsed,
    /// preventing subsequent `save()` calls from silently clobbering the file.
    #[serde(skip)]
    load_failed: bool,
}

fn redact_secret(value: &str) -> &'static str {
    if value.is_empty() {
        ""
    } else {
        "[REDACTED]"
    }
}

impl std::fmt::Debug for AppSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppSettings")
            .field("layout", &self.layout)
            .field("ai_provider", &self.ai_provider)
            .field("openai_api_key", &redact_secret(&self.openai_api_key))
            .field("openai_model", &self.openai_model)
            .field("anthropic_model", &self.anthropic_model)
            .field("color_scheme", &self.color_scheme)
            .field("opacity", &self.opacity)
            .field("anthropic_api_key", &redact_secret(&self.anthropic_api_key))
            .field("use_claude_subscription", &self.use_claude_subscription)
            .field(
                "legacy_password_hash",
                &redact_secret(&self.legacy_password_hash),
            )
            .field("auto_lock_minutes", &self.auto_lock_minutes)
            .field("webhook_url", &redact_secret(&self.webhook_url))
            .field("webhook_on_host_down", &self.webhook_on_host_down)
            .field("webhook_on_vpn_disconnect", &self.webhook_on_vpn_disconnect)
            .field(
                "unifi_cloud_api_key",
                &redact_secret(&self.unifi_cloud_api_key),
            )
            .field("rdp_client", &self.rdp_client)
            .finish()
    }
}

fn default_rdp_client() -> String {
    "auto".into()
}

fn default_opacity() -> f64 {
    1.0
}

fn default_auto_lock_minutes() -> u64 {
    15
}

fn default_true() -> bool {
    true
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            layout: LayoutSettings::default(),
            ai_provider: AiProvider::default(),
            openai_api_key: String::new(),
            openai_model: default_openai_model(),
            anthropic_model: default_anthropic_model(),
            color_scheme: ColorScheme::default(),
            opacity: 1.0,
            anthropic_api_key: String::new(),
            use_claude_subscription: false,
            legacy_password_hash: String::new(),
            auto_lock_minutes: 15,
            webhook_url: String::new(),
            webhook_on_host_down: true,
            webhook_on_vpn_disconnect: false,
            unifi_cloud_api_key: String::new(),
            rdp_client: "auto".into(),
            load_failed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LayoutSettings {
    pub window_width: i32,
    pub window_height: i32,
    pub maximized: bool,
    pub sidebar_widths: std::collections::BTreeMap<String, i32>,
}

impl Default for LayoutSettings {
    fn default() -> Self {
        Self {
            window_width: 1280,
            window_height: 800,
            maximized: false,
            sidebar_widths: Default::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Persistence & Secret Store Bridge
// ---------------------------------------------------------------------------

fn settings_path() -> anyhow::Result<PathBuf> {
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        })
        .ok_or_else(|| {
            anyhow!("neither XDG_CONFIG_HOME nor HOME is set; refusing relative settings path")
        })?;
    if !config_dir.is_absolute() {
        return Err(anyhow!(
            "refusing non-absolute config directory {}",
            config_dir.display()
        ));
    }
    Ok(config_dir.join("supermgr").join("settings.json"))
}

fn run_secret_op<F, T>(f: F) -> anyhow::Result<T>
where
    F: FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<T>> + Send>>
        + Send
        + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("create secret-store runtime")?;
        rt.block_on(f())
    })
    .join()
    .map_err(|_| anyhow!("secret-store worker thread panicked"))?
}

#[cfg(target_os = "linux")]
fn default_secret_store() -> std::sync::Arc<dyn SecretStore> {
    std::sync::Arc::new(supermgr_core::keyring::LibsecretStore::new())
}

#[cfg(not(target_os = "linux"))]
struct UnsupportedStore;

#[cfg(not(target_os = "linux"))]
#[async_trait::async_trait]
impl SecretStore for UnsupportedStore {
    async fn store(&self, _label: &str, _secret: &[u8]) -> Result<(), SecretError> {
        Err(SecretError::ServiceUnavailable(
            "Linux Secret Service unavailable on this platform".into(),
        ))
    }
    async fn retrieve(&self, label: &str) -> Result<supermgr_core::keyring::ZeroizingSecret, SecretError> {
        Err(SecretError::NotFound {
            label: label.to_owned(),
        })
    }
    async fn delete(&self, label: &str) -> Result<(), SecretError> {
        Err(SecretError::NotFound {
            label: label.to_owned(),
        })
    }
}

#[cfg(not(target_os = "linux"))]
fn default_secret_store() -> std::sync::Arc<dyn SecretStore> {
    std::sync::Arc::new(UnsupportedStore)
}

async fn load_or_migrate_secret(
    store: &dyn SecretStore,
    label: &str,
    legacy_value: &mut String,
) -> anyhow::Result<bool> {
    if !legacy_value.is_empty() {
        store
            .store(label, legacy_value.as_bytes())
            .await
            .map_err(|e| anyhow!("migrate {label} to secret store: {e}"))?;
        return Ok(true);
    }
    match store.retrieve(label).await {
        Ok(bytes) => {
            *legacy_value = String::from_utf8(bytes.to_vec())
                .with_context(|| format!("secret {label} is not valid UTF-8"))?;
            Ok(false)
        }
        Err(SecretError::NotFound { .. }) => Ok(false),
        Err(e) => Err(anyhow!("retrieve {label} from secret store: {e}")),
    }
}

async fn sync_secret(store: &dyn SecretStore, label: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        match store.delete(label).await {
            Ok(()) | Err(SecretError::NotFound { .. }) => Ok(()),
            Err(e) => Err(anyhow!("delete {label} from secret store: {e}")),
        }
    } else {
        store
            .store(label, value.as_bytes())
            .await
            .map_err(|e| anyhow!("store {label} in secret store: {e}"))
    }
}

impl AppSettings {
    /// Load settings from `path` and synchronise secret-backed fields against `store`.
    ///
    /// Fails with a descriptive error if `path` exists and cannot be read or parsed;
    /// a missing `settings.json` yields [`Self::default`] hydrated from `store`.
    pub async fn try_load_from_with_store(
        path: &Path,
        store: &dyn SecretStore,
    ) -> anyhow::Result<Self> {
        let mut s: Self = match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|_| {
                anyhow!(
                    "settings file {} is not valid JSON; refusing to reset to defaults",
                    path.display()
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                return Err(e).with_context(|| format!("read settings file {}", path.display()));
            }
        };

        let mut needs_resave = false;
        if !s.legacy_password_hash.is_empty() {
            crate::master_password::migrate_from_legacy_field(&s.legacy_password_hash);
            s.legacy_password_hash.clear();
            needs_resave = true;
        }

        for (label, field) in [
            (LABEL_OPENAI_API_KEY, &mut s.openai_api_key),
            (LABEL_ANTHROPIC_API_KEY, &mut s.anthropic_api_key),
            (LABEL_UNIFI_CLOUD_API_KEY, &mut s.unifi_cloud_api_key),
            (LABEL_WEBHOOK_URL, &mut s.webhook_url),
        ] {
            match load_or_migrate_secret(store, label, field).await {
                Ok(migrated) => needs_resave |= migrated,
                Err(e) => {
                    tracing::warn!(%label, error = %e, "settings secret-store sync warning");
                }
            }
        }

        if needs_resave {
            s.try_save_to_with_store(path, store).await?;
        }
        Ok(s)
    }

    /// Persist settings to `path` (`0600` atomic write) and sync secret fields to `store`.
    pub async fn try_save_to_with_store(
        &self,
        path: &Path,
        store: &dyn SecretStore,
    ) -> anyhow::Result<()> {
        if self.load_failed {
            anyhow::bail!(
                "refusing to overwrite {} because loading it failed earlier",
                path.display()
            );
        }
        for (label, value) in [
            (LABEL_OPENAI_API_KEY, self.openai_api_key.as_str()),
            (LABEL_ANTHROPIC_API_KEY, self.anthropic_api_key.as_str()),
            (LABEL_UNIFI_CLOUD_API_KEY, self.unifi_cloud_api_key.as_str()),
            (LABEL_WEBHOOK_URL, self.webhook_url.as_str()),
        ] {
            sync_secret(store, label, value).await?;
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create settings directory {}", parent.display()))?;
        }
        let text = serde_json::to_string_pretty(self).context("serialise settings JSON")?;
        crate::backup::write_private(path, text.as_bytes())
            .with_context(|| format!("write settings file {}", path.display()))
    }

    /// Load settings from disk, logging and preserving corrupt files rather than
    /// silently clobbering them on a later save.
    pub fn load() -> Self {
        let path = match settings_path() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "cannot resolve settings path");
                return Self {
                    load_failed: true,
                    ..Self::default()
                };
            }
        };
        let store = default_secret_store();
        let path_clone = path.clone();
        match run_secret_op(move || {
            Box::pin(async move {
                Self::try_load_from_with_store(&path_clone, store.as_ref()).await
            })
        }) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "failed to load settings.json; preserving file");
                let backup = path.with_extension("json.corrupt");
                if path.exists() && !backup.exists() {
                    if let Ok(bytes) = std::fs::read(&path) {
                        let _ = crate::backup::write_private(&backup, &bytes);
                    }
                }
                Self {
                    load_failed: true,
                    ..Self::default()
                }
            }
        }
    }

    /// Persist settings to disk and to the system secret store, logging any error.
    pub fn save(&self) {
        let path = match settings_path() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "cannot resolve settings path for save");
                return;
            }
        };
        let cloned = self.clone();
        let store = default_secret_store();
        if let Err(e) = run_secret_op(move || {
            Box::pin(async move { cloned.try_save_to_with_store(&path, store.as_ref()).await })
        }) {
            tracing::error!(error = %e, "failed to save settings");
        }
    }

    /// Convert the stored colour-scheme variant into a libadwaita value.
    pub fn adw_color_scheme(&self) -> libadwaita::ColorScheme {
        match self.color_scheme {
            ColorScheme::Default => libadwaita::ColorScheme::Default,
            ColorScheme::Light => libadwaita::ColorScheme::ForceLight,
            ColorScheme::Dark => libadwaita::ColorScheme::ForceDark,
        }
    }
}

#[cfg(test)]
mod model_tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use supermgr_core::keyring::ZeroizingSecret;

    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, Vec<u8>>>);

    #[async_trait::async_trait]
    impl SecretStore for MemStore {
        async fn store(&self, label: &str, secret: &[u8]) -> Result<(), SecretError> {
            self.0
                .lock()
                .unwrap()
                .insert(label.to_owned(), secret.to_vec());
            Ok(())
        }
        async fn retrieve(&self, label: &str) -> Result<ZeroizingSecret, SecretError> {
            self.0
                .lock()
                .unwrap()
                .get(label)
                .cloned()
                .map(ZeroizingSecret::from_vec)
                .ok_or_else(|| SecretError::NotFound {
                    label: label.to_owned(),
                })
        }
        async fn delete(&self, label: &str) -> Result<(), SecretError> {
            self.0
                .lock()
                .unwrap()
                .remove(label)
                .map(|_| ())
                .ok_or_else(|| SecretError::NotFound {
                    label: label.to_owned(),
                })
        }
    }

    #[test]
    fn debug_impl_redacts_all_secret_fields() {
        let settings = AppSettings {
            openai_api_key: "sk-openai-super-secret".into(),
            anthropic_api_key: "sk-ant-super-secret".into(),
            webhook_url: "https://hooks.slack.com/services/SECRET".into(),
            unifi_cloud_api_key: "unifi-secret-token".into(),
            legacy_password_hash: "$argon2id$secret".into(),
            ..AppSettings::default()
        };
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("sk-openai-super-secret"));
        assert!(!rendered.contains("sk-ant-super-secret"));
        assert!(!rendered.contains("hooks.slack.com"));
        assert!(!rendered.contains("unifi-secret-token"));
        assert!(!rendered.contains("$argon2id$secret"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn legacy_settings_recover_retired_or_empty_models_without_losing_other_settings() {
        for model in ["", "  ", "claude-sonnet-4-20250514", " claude-sonnet-4-0 "] {
            let saved =
                serde_json::json!({"anthropic_model":model,"use_claude_subscription":true,"opacity":0.8});
            let settings: AppSettings = serde_json::from_value(saved).unwrap();
            assert_eq!(settings.anthropic_model, "claude-sonnet-5");
            assert!(settings.use_claude_subscription);
            assert_eq!(settings.opacity, 0.8);
        }
        let settings: AppSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(settings.anthropic_model, "claude-sonnet-5");
    }

    #[test]
    fn explicit_custom_models_survive_loading_and_saving() {
        let saved = serde_json::json!({"anthropic_model":"  custom-accessible-model  "});
        let settings: AppSettings = serde_json::from_value(saved).unwrap();
        assert_eq!(settings.anthropic_model, "custom-accessible-model");
        assert_eq!(
            serde_json::to_value(settings).unwrap()["anthropic_model"],
            "custom-accessible-model"
        );
    }

    #[tokio::test]
    async fn legacy_api_keys_migrate_into_secret_store_and_disappear_from_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{
                "anthropic_api_key": "sk-ant-legacy",
                "openai_api_key": "sk-openai-legacy",
                "unifi_cloud_api_key": "unifi-legacy",
                "webhook_url": "https://hooks.example.test/abc",
                "opacity": 0.9
            }"#,
        )
        .unwrap();

        let store = MemStore::default();
        let loaded = AppSettings::try_load_from_with_store(&path, &store)
            .await
            .unwrap();
        assert_eq!(loaded.anthropic_api_key, "sk-ant-legacy");
        assert_eq!(loaded.openai_api_key, "sk-openai-legacy");
        assert_eq!(loaded.unifi_cloud_api_key, "unifi-legacy");
        assert_eq!(loaded.webhook_url, "https://hooks.example.test/abc");
        assert_eq!(loaded.opacity, 0.9);

        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(!rewritten.contains("sk-ant-legacy"), "{rewritten}");
        assert!(!rewritten.contains("sk-openai-legacy"), "{rewritten}");
        assert!(!rewritten.contains("unifi-legacy"), "{rewritten}");
        assert!(!rewritten.contains("hooks.example.test"), "{rewritten}");

        let reloaded = AppSettings::try_load_from_with_store(&path, &store)
            .await
            .unwrap();
        assert_eq!(reloaded.anthropic_api_key, "sk-ant-legacy");
        assert_eq!(reloaded.openai_api_key, "sk-openai-legacy");
    }

    #[tokio::test]
    async fn corrupt_settings_fail_loudly_and_are_not_clobbered_by_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "{ invalid json").unwrap();

        let store = MemStore::default();
        let err = AppSettings::try_load_from_with_store(&path, &store)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not valid JSON"), "{err}");

        let guarded = AppSettings {
            load_failed: true,
            ..AppSettings::default()
        };
        assert!(guarded.try_save_to_with_store(&path, &store).await.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ invalid json");
    }
}
