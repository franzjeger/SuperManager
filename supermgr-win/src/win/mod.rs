//! Windows GUI body. Gated on `cfg(target_os = "windows")` by the parent
//! `main.rs` so off-Windows builds skip Slint entirely.

mod tray;

use std::sync::Arc;

use anyhow::Context as _;
use slint::{ComponentHandle as _, ModelRc, SharedString, VecModel};
use supermgr_core::client;
use tracing::{error, info, warn};

// Slint generates `AppWindow`, `KeyRow`, and `HostRow` from `ui/main.slint`.
slint::include_modules!();

/// Entry point for the GUI. Owns the Slint event loop and the Tokio
/// runtime that drives daemon RPC; the two are bridged by `slint::spawn_local`
/// for UI-thread callbacks and `slint::Weak::upgrade_in_event_loop` for
/// pushing async results back to the UI from arbitrary tasks.
pub fn run() -> anyhow::Result<()> {
    init_tracing();
    info!("supermgr-win starting");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    let rt_handle = rt.handle().clone();

    let window = AppWindow::new().context("create main window")?;

    // Connect to the daemon eagerly. If the connection fails the GUI still
    // opens with an error banner — the user can install the service and
    // hit Refresh without restarting the app.
    let client = match rt_handle.block_on(client::connect()) {
        Ok(c) => {
            window.set_daemon_status("Connected".into());
            Some(Arc::new(c))
        }
        Err(e) => {
            warn!("daemon connect failed at startup: {e}");
            window.set_daemon_status("Disconnected".into());
            window.set_last_error(SharedString::from(format!(
                "Could not reach supermgrd: {e}. Start the service from services.msc, then click Refresh."
            )));
            None
        }
    };

    // Tray icon. Holds a Weak to the window so the "Show" menu item can
    // bring the GUI back from a minimised state.
    let _tray = tray::spawn(window.as_weak());

    bind_callbacks(&window, client.clone(), rt_handle.clone());

    // Initial data load, fire-and-forget. The async closure pushes results
    // back via `upgrade_in_event_loop` so we don't touch Slint state from
    // a Tokio worker thread.
    if let Some(c) = client.clone() {
        let weak = window.as_weak();
        rt_handle.spawn(async move {
            refresh_all(&c, weak).await;
        });
    }

    window.run().context("Slint event loop")?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let _ = fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}

/// Wire all UI callbacks to async daemon calls.
fn bind_callbacks(
    window: &AppWindow,
    client: Option<Arc<client::DaemonClient>>,
    rt: tokio::runtime::Handle,
) {
    // ----- Refresh -----
    {
        let weak = window.as_weak();
        let client = client.clone();
        let rt = rt.clone();
        window.on_refresh(move || {
            let Some(c) = client.clone() else {
                set_error(&weak, "Not connected to daemon.");
                return;
            };
            let weak = weak.clone();
            rt.spawn(async move { refresh_all(&c, weak).await });
        });
    }

    // ----- Generate key -----
    {
        let weak = window.as_weak();
        let client = client.clone();
        let rt = rt.clone();
        window.on_generate_key(move |name, description, key_type| {
            let Some(c) = client.clone() else {
                set_error(&weak, "Not connected to daemon.");
                return;
            };
            let name = name.to_string();
            let description = description.to_string();
            let key_type = key_type.to_string();
            let weak = weak.clone();
            rt.spawn(async move {
                if let Err(e) = c
                    .ssh_generate_key(&key_type, &name, &description, "[]")
                    .await
                {
                    push_error(&weak, format!("Generate key failed: {e}"));
                    return;
                }
                refresh_all(&c, weak).await;
            });
        });
    }

    // ----- Delete key -----
    {
        let weak = window.as_weak();
        let client = client.clone();
        let rt = rt.clone();
        window.on_delete_key(move |key_id| {
            let Some(c) = client.clone() else {
                set_error(&weak, "Not connected to daemon.");
                return;
            };
            let key_id = key_id.to_string();
            let weak = weak.clone();
            rt.spawn(async move {
                if let Err(e) = c.ssh_delete_key(&key_id).await {
                    push_error(&weak, format!("Delete key failed: {e}"));
                    return;
                }
                refresh_all(&c, weak).await;
            });
        });
    }

    // ----- Export key (copies the public OpenSSH line to the clipboard) -----
    {
        let weak = window.as_weak();
        let client = client.clone();
        let rt = rt.clone();
        window.on_export_key(move |key_id| {
            let Some(c) = client.clone() else {
                set_error(&weak, "Not connected to daemon.");
                return;
            };
            let key_id = key_id.to_string();
            let weak = weak.clone();
            rt.spawn(async move {
                match c.ssh_export_public_key(&key_id).await {
                    Ok(pubkey) => {
                        if let Err(e) = copy_to_clipboard(&pubkey) {
                            push_error(&weak, format!("Clipboard copy failed: {e}"));
                        } else {
                            push_status(&weak, "Public key copied to clipboard");
                        }
                    }
                    Err(e) => push_error(&weak, format!("Export failed: {e}")),
                }
            });
        });
    }

    // ----- Delete host -----
    {
        let weak = window.as_weak();
        let client = client.clone();
        let rt = rt.clone();
        window.on_delete_host(move |host_id| {
            let Some(c) = client.clone() else {
                set_error(&weak, "Not connected to daemon.");
                return;
            };
            let host_id = host_id.to_string();
            let weak = weak.clone();
            rt.spawn(async move {
                if let Err(e) = c.delete_host(&host_id).await {
                    push_error(&weak, format!("Delete host failed: {e}"));
                    return;
                }
                refresh_all(&c, weak).await;
            });
        });
    }
}

/// Pull keys + hosts from the daemon and push them into the UI model.
async fn refresh_all(client: &client::DaemonClient, weak: slint::Weak<AppWindow>) {
    let keys_result = client.ssh_list_keys().await;
    let hosts_result = client.list_hosts().await;

    let keys = match keys_result {
        Ok(j) => parse_keys(&j),
        Err(e) => {
            push_error(&weak, format!("List keys failed: {e}"));
            Vec::new()
        }
    };
    let hosts = match hosts_result {
        Ok(j) => parse_hosts(&j),
        Err(e) => {
            push_error(&weak, format!("List hosts failed: {e}"));
            Vec::new()
        }
    };

    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_keys(ModelRc::new(VecModel::from(keys)));
        w.set_hosts(ModelRc::new(VecModel::from(hosts)));
        w.set_last_error("".into());
    });
}

fn parse_keys(j: &str) -> Vec<KeyRow> {
    let arr: serde_json::Value = match serde_json::from_str(j) {
        Ok(v) => v,
        Err(e) => {
            warn!("parse keys json: {e}");
            return Vec::new();
        }
    };
    arr.as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| KeyRow {
                    id: item.get("id").and_then(|v| v.as_str()).unwrap_or("").into(),
                    name: item.get("name").and_then(|v| v.as_str()).unwrap_or("").into(),
                    key_type: item
                        .get("key_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    fingerprint: item
                        .get("fingerprint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    created_at: item
                        .get("created_at")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_hosts(j: &str) -> Vec<HostRow> {
    let arr: serde_json::Value = match serde_json::from_str(j) {
        Ok(v) => v,
        Err(e) => {
            warn!("parse hosts json: {e}");
            return Vec::new();
        }
    };
    arr.as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| HostRow {
                    id: item.get("id").and_then(|v| v.as_str()).unwrap_or("").into(),
                    label: item
                        .get("label")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    hostname: item
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    username: item
                        .get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    device_type: item
                        .get("device_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    pinned: item.get("pinned").and_then(|v| v.as_bool()).unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn push_error(weak: &slint::Weak<AppWindow>, msg: String) {
    error!("{msg}");
    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_last_error(SharedString::from(msg));
    });
}

fn push_status(weak: &slint::Weak<AppWindow>, msg: &'static str) {
    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_daemon_status(SharedString::from(msg));
    });
}

fn set_error(weak: &slint::Weak<AppWindow>, msg: &'static str) {
    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_last_error(SharedString::from(msg));
    });
}

/// Copy a string to the Windows clipboard via `arboard`, which on Windows
/// wraps `OpenClipboard` / `SetClipboardData` via the `clipboard-win` crate.
/// A fresh [`arboard::Clipboard`] per call is cheap and side-steps the
/// "clipboard handle must live on the UI thread" subtlety — we're already
/// on the Tokio worker that handled the export RPC.
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut cb = arboard::Clipboard::new()
        .map_err(|e| format!("clipboard init: {e}"))?;
    cb.set_text(text.to_owned())
        .map_err(|e| format!("clipboard set: {e}"))
}

