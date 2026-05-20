//! Windows GUI body. Gated on `cfg(target_os = "windows")` by the parent
//! `main.rs` so off-Windows builds skip Slint entirely.

mod tray;

use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use slint::{ComponentHandle as _, Model as _, ModelRc, SharedString, VecModel};
use supermgr_core::client;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

slint::include_modules!();

/// How often the status poller wakes up.
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// How often we re-pull the full key/host/profile lists.
const LIST_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Shared connection handle. Wrapped in a `Mutex<Option<...>>` so the
/// poller can swap in a fresh handle if the daemon restarts mid-session
/// without forcing the user to relaunch the GUI.
type ConnectionSlot = Arc<Mutex<Option<Arc<client::DaemonClient>>>>;

/// Cached unfiltered host list. The Hosts tab renders `set_hosts(...)`
/// which is the *filtered* view; keeping the full list separately
/// lets the host-search callback rebuild the filtered view client-side
/// without round-tripping the daemon.
type HostCache = Arc<Mutex<Vec<HostRow>>>;

pub fn run() -> anyhow::Result<()> {
    init_tracing();
    info!("supermgr-win starting");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    let rt_handle = rt.handle().clone();

    let window = AppWindow::new().context("create main window")?;

    let connection: ConnectionSlot = Arc::new(Mutex::new(None));
    let host_cache: HostCache = Arc::new(Mutex::new(Vec::new()));

    // Eager first connect. If it fails we surface the error in the
    // sidebar banner but still bring the window up — the poller will
    // retry every POLL_INTERVAL.
    {
        let conn = connection.clone();
        rt_handle.block_on(async move {
            match client::connect().await {
                Ok(c) => {
                    *conn.lock().await = Some(Arc::new(c));
                }
                Err(e) => {
                    warn!("initial daemon connect failed: {e}");
                }
            }
        });
    }

    // Hand the connection slot to the tray so it can disconnect on
    // the "Quick disconnect" menu item.
    let _tray = tray::spawn(window.as_weak(), connection.clone(), rt_handle.clone());

    bind_callbacks(&window, connection.clone(), host_cache.clone(), rt_handle.clone());

    // Initial full refresh fire-and-forget.
    {
        let conn = connection.clone();
        let host_cache = host_cache.clone();
        let weak = window.as_weak();
        rt_handle.spawn(async move { refresh_all(&conn, &host_cache, weak).await });
    }

    // Periodic status poller (every POLL_INTERVAL) + full list
    // refresh on a longer cadence. One task drives both so we don't
    // race two polls into the daemon at once.
    {
        let conn = connection.clone();
        let host_cache = host_cache.clone();
        let weak = window.as_weak();
        rt_handle.spawn(async move {
            let mut ticks: u32 = 0;
            loop {
                tokio::time::sleep(POLL_INTERVAL).await;
                ticks = ticks.wrapping_add(1);
                ensure_connection(&conn).await;
                poll_status(&conn, weak.clone()).await;
                // Pull the heavy lists every 6 ticks = 30 s.
                if ticks % (LIST_REFRESH_INTERVAL.as_secs() / POLL_INTERVAL.as_secs()) as u32 == 0 {
                    refresh_all(&conn, &host_cache, weak.clone()).await;
                }
            }
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

/// If the connection slot is empty, try to fill it. Best-effort: a
/// failure here just leaves the slot empty for the next tick.
async fn ensure_connection(conn: &ConnectionSlot) {
    let guard = conn.lock().await;
    if guard.is_some() {
        return;
    }
    drop(guard);
    if let Ok(c) = client::connect().await {
        *conn.lock().await = Some(Arc::new(c));
        info!("daemon connection (re)established");
    }
}

/// Pull `get_status` and push the result into the UI's status fields.
async fn poll_status(conn: &ConnectionSlot, weak: slint::Weak<AppWindow>) {
    let client = {
        let guard = conn.lock().await;
        guard.clone()
    };

    let (connected, vpn_state, vpn_profile, vpn_backend) = match &client {
        Some(c) => match c.get_status().await {
            Ok(json) => {
                let v: serde_json::Value =
                    serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
                let state = v
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("Disconnected")
                    .to_owned();
                let backend = v
                    .get("backend")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                // The backend doesn't echo the profile *name*, just the
                // id. We resolve the name from the cached profile list
                // on the UI thread.
                let profile_id = v
                    .get("profile_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                (true, state, profile_id, backend)
            }
            Err(e) => {
                warn!("get_status RPC failed: {e}");
                // Drop the connection so ensure_connection retries.
                *conn.lock().await = None;
                (false, "Disconnected".into(), String::new(), String::new())
            }
        },
        None => (false, "Disconnected".into(), String::new(), String::new()),
    };

    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_daemon_connected(connected);
        w.set_daemon_status(SharedString::from(if connected {
            "Connected"
        } else {
            "Daemon offline (retrying…)"
        }));
        w.set_vpn_state(SharedString::from(vpn_state.clone()));
        w.set_vpn_backend(SharedString::from(vpn_backend));
        // Resolve profile-id to name from the cached list.
        let profile_name = if vpn_profile.is_empty() {
            String::new()
        } else {
            let profiles = w.get_profiles();
            let mut found = String::new();
            for i in 0..profiles.row_count() {
                if let Some(p) = profiles.row_data(i) {
                    if p.id.as_str() == vpn_profile {
                        found = p.name.to_string();
                        break;
                    }
                }
            }
            found
        };
        w.set_vpn_profile_name(SharedString::from(profile_name));
        w.set_last_refresh(SharedString::from(ts));
    });
}

/// Pull keys + hosts + profiles from the daemon and push them into the UI.
/// Caches the full host list so the search callback can filter without
/// hitting the daemon again.
async fn refresh_all(
    conn: &ConnectionSlot,
    host_cache: &HostCache,
    weak: slint::Weak<AppWindow>,
) {
    let client = {
        let guard = conn.lock().await;
        guard.clone()
    };
    let Some(client) = client else {
        return;
    };

    let keys = match client.ssh_list_keys().await {
        Ok(j) => parse_keys(&j),
        Err(e) => {
            push_error(&weak, format!("List keys failed: {e}"));
            Vec::new()
        }
    };
    let hosts = match client.list_hosts().await {
        Ok(j) => parse_hosts(&j),
        Err(e) => {
            push_error(&weak, format!("List hosts failed: {e}"));
            Vec::new()
        }
    };
    let profiles = match client.list_profiles().await {
        Ok(j) => parse_profiles(&j),
        Err(e) => {
            push_error(&weak, format!("List profiles failed: {e}"));
            Vec::new()
        }
    };

    *host_cache.lock().await = hosts.clone();

    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
    let _ = weak.upgrade_in_event_loop(move |w| {
        let query = w.get_host_search().to_string();
        let filtered = if query.is_empty() {
            hosts.clone()
        } else {
            filter_hosts(&hosts, &query)
        };
        w.set_keys(ModelRc::new(VecModel::from(keys)));
        w.set_hosts(ModelRc::new(VecModel::from(filtered)));
        w.set_profiles(ModelRc::new(VecModel::from(profiles)));
        w.set_last_refresh(SharedString::from(ts));
    });
}

/// Case-insensitive substring match on label + hostname.
fn filter_hosts(hosts: &[HostRow], query: &str) -> Vec<HostRow> {
    let needle = query.to_ascii_lowercase();
    hosts
        .iter()
        .filter(|h| {
            h.label.to_ascii_lowercase().contains(&needle)
                || h.hostname.to_ascii_lowercase().contains(&needle)
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Callback wiring
// ---------------------------------------------------------------------------

fn bind_callbacks(
    window: &AppWindow,
    conn: ConnectionSlot,
    host_cache: HostCache,
    rt: tokio::runtime::Handle,
) {
    macro_rules! with_client {
        ($conn:expr, $weak:expr, $body:expr) => {{
            let client = {
                let guard = $conn.lock().await;
                guard.clone()
            };
            match client {
                Some(c) => $body(c).await,
                None => push_error(&$weak, "Not connected to daemon.".into()),
            }
        }};
    }

    // Refresh
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        let host_cache = host_cache.clone();
        window.on_refresh(move || {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_cache = host_cache.clone();
            rt.spawn(async move {
                ensure_connection(&conn).await;
                refresh_all(&conn, &host_cache, weak.clone()).await;
                poll_status(&conn, weak).await;
            });
        });
    }

    // Generate key
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        let host_cache = host_cache.clone();
        window.on_generate_key(move |name, description, key_type| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_cache = host_cache.clone();
            let name = name.to_string();
            let description = description.to_string();
            let key_type = key_type.to_string();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.ssh_generate_key(&key_type, &name, &description, "[]").await {
                        Ok(_) => {
                            push_status(&weak, "SSH key generated.");
                            refresh_all(&conn, &host_cache, weak.clone()).await;
                        }
                        Err(e) => push_error(&weak, format!("Generate key failed: {e}")),
                    }
                });
            });
        });
    }

    // Delete key
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        let host_cache = host_cache.clone();
        window.on_delete_key(move |key_id| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_cache = host_cache.clone();
            let key_id = key_id.to_string();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.ssh_delete_key(&key_id).await {
                        Ok(()) => {
                            push_status(&weak, "Key deleted.");
                            refresh_all(&conn, &host_cache, weak.clone()).await;
                        }
                        Err(e) => push_error(&weak, format!("Delete key failed: {e}")),
                    }
                });
            });
        });
    }

    // Export key — copies the OpenSSH public line to the clipboard.
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        window.on_export_key(move |key_id| {
            let weak = weak.clone();
            let conn = conn.clone();
            let key_id = key_id.to_string();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.ssh_export_public_key(&key_id).await {
                        Ok(pubkey) => match copy_to_clipboard(&pubkey) {
                            Ok(()) => push_status(&weak, "Public key copied to clipboard."),
                            Err(e) => push_error(&weak, format!("Clipboard copy failed: {e}")),
                        },
                        Err(e) => push_error(&weak, format!("Export failed: {e}")),
                    }
                });
            });
        });
    }

    // Add host
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        let host_cache = host_cache.clone();
        window.on_add_host(
            move |label, hostname, port, username, group, device_type, auth_method| {
                let weak = weak.clone();
                let conn = conn.clone();
                let host_cache = host_cache.clone();
                let label = label.to_string();
                let hostname = hostname.to_string();
                let username = username.to_string();
                let group = group.to_string();
                let device_type = device_type.to_string();
                let auth_method = auth_method.to_string();
                let port_u16: u16 = if port > 0 && port < 65536 { port as u16 } else { 22 };
                rt.spawn(async move {
                    if hostname.is_empty() || label.is_empty() {
                        push_error(&weak, "Label and hostname are required.".into());
                        return;
                    }
                    with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                        let host_json = serde_json::json!({
                            "label": label,
                            "hostname": hostname,
                            "port": port_u16,
                            "username": username,
                            "group": group,
                            "device_type": device_type,
                            "auth_method": auth_method,
                        });
                        match c.add_host(&host_json.to_string()).await {
                            Ok(_) => {
                                push_status(&weak, "Host added.");
                                refresh_all(&conn, &host_cache, weak.clone()).await;
                            }
                            Err(e) => push_error(&weak, format!("Add host failed: {e}")),
                        }
                    });
                });
            },
        );
    }

    // Delete host
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        let host_cache = host_cache.clone();
        window.on_delete_host(move |host_id| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_cache = host_cache.clone();
            let host_id = host_id.to_string();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.delete_host(&host_id).await {
                        Ok(()) => {
                            push_status(&weak, "Host deleted.");
                            refresh_all(&conn, &host_cache, weak.clone()).await;
                        }
                        Err(e) => push_error(&weak, format!("Delete host failed: {e}")),
                    }
                });
            });
        });
    }

    // Toggle host pin
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        let host_cache = host_cache.clone();
        window.on_toggle_host_pin(move |host_id| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_cache = host_cache.clone();
            let host_id = host_id.to_string();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.toggle_host_pin(&host_id).await {
                        Ok(_) => refresh_all(&conn, &host_cache, weak).await,
                        Err(e) => push_error(&weak, format!("Toggle pin failed: {e}")),
                    }
                });
            });
        });
    }

    // Import WireGuard
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        let host_cache = host_cache.clone();
        window.on_import_wireguard(move |name, conf_text| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_cache = host_cache.clone();
            let name = name.to_string();
            let conf_text = conf_text.to_string();
            rt.spawn(async move {
                if name.is_empty() || conf_text.is_empty() {
                    push_error(&weak, "Name and .conf body are required.".into());
                    return;
                }
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.import_wireguard(&conf_text, &name).await {
                        Ok(_) => {
                            push_status(&weak, "WireGuard profile imported.");
                            refresh_all(&conn, &host_cache, weak.clone()).await;
                        }
                        Err(e) => push_error(&weak, format!("Import WireGuard failed: {e}")),
                    }
                });
            });
        });
    }

    // Import FortiClient SSL VPN
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        let host_cache = host_cache.clone();
        window.on_import_forticlient(move |name, host, port, username, password| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_cache = host_cache.clone();
            let name = name.to_string();
            let host = host.to_string();
            let username = username.to_string();
            let password = password.to_string();
            let port_u16: u16 = if port > 0 && port < 65536 { port as u16 } else { 443 };
            rt.spawn(async move {
                if name.is_empty() || host.is_empty() || username.is_empty() || password.is_empty() {
                    push_error(
                        &weak,
                        "Name, host, username, and password are required.".into(),
                    );
                    return;
                }
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c
                        .import_forticlient_sslvpn(
                            &name, &host, port_u16, &username, &password, None, "[]", "[]",
                        )
                        .await
                    {
                        Ok(_) => {
                            push_status(&weak, "FortiClient SSL VPN profile imported.");
                            refresh_all(&conn, &host_cache, weak.clone()).await;
                        }
                        Err(e) => push_error(&weak, format!("Import FortiClient failed: {e}")),
                    }
                });
            });
        });
    }

    // Connect profile
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        window.on_connect_profile(move |profile_id| {
            let weak = weak.clone();
            let conn = conn.clone();
            let profile_id = profile_id.to_string();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.connect(&profile_id).await {
                        Ok(()) => {
                            push_status(&weak, "Connect requested.");
                            poll_status(&conn, weak).await;
                        }
                        Err(e) => push_error(&weak, format!("Connect failed: {e}")),
                    }
                });
            });
        });
    }

    // Disconnect VPN
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        window.on_disconnect_vpn(move || {
            let weak = weak.clone();
            let conn = conn.clone();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.disconnect().await {
                        Ok(()) => {
                            push_status(&weak, "Disconnected.");
                            poll_status(&conn, weak).await;
                        }
                        Err(e) => push_error(&weak, format!("Disconnect failed: {e}")),
                    }
                });
            });
        });
    }

    // Delete profile
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        let host_cache = host_cache.clone();
        window.on_delete_profile(move |profile_id| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_cache = host_cache.clone();
            let profile_id = profile_id.to_string();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.delete_profile(&profile_id).await {
                        Ok(()) => {
                            push_status(&weak, "Profile deleted.");
                            refresh_all(&conn, &host_cache, weak.clone()).await;
                        }
                        Err(e) => push_error(&weak, format!("Delete profile failed: {e}")),
                    }
                });
            });
        });
    }

    // Open host - fetches detail via get_host, populates selected-host,
    // switches to the detail view.
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        window.on_open_host(move |host_id| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_id = host_id.to_string();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.get_host(&host_id).await {
                        Ok(json) => {
                            let detail = parse_host_detail(&json);
                            let _ = weak.upgrade_in_event_loop(move |w| {
                                w.set_selected_host(detail);
                                w.set_host_cmd("".into());
                                w.set_host_cmd_stdout("".into());
                                w.set_host_cmd_stderr("".into());
                                w.set_host_cmd_exit_code(0);
                                w.set_host_test_result("".into());
                                w.set_current_view(5);
                            });
                        }
                        Err(e) => push_error(&weak, format!("Open host failed: {e}")),
                    }
                });
            });
        });
    }

    // Close host detail - go back to the Hosts list.
    {
        let weak = window.as_weak();
        window.on_close_host_detail(move || {
            if let Some(w) = weak.upgrade() {
                w.set_current_view(2);
            }
        });
    }

    // Test host connection
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        window.on_test_host_connection(move |host_id| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_id = host_id.to_string();
            let weak_pending = weak.clone();
            let _ = weak_pending.upgrade_in_event_loop(|w| {
                w.set_host_test_result("Probing…".into());
            });
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.test_host_connection(&host_id).await {
                        Ok(json) => {
                            let label = summarise_test_result(&json);
                            let _ = weak.upgrade_in_event_loop(move |w| {
                                w.set_host_test_result(SharedString::from(label));
                            });
                        }
                        Err(e) => {
                            let msg = format!("Probe failed: {e}");
                            let _ = weak.upgrade_in_event_loop(move |w| {
                                w.set_host_test_result(SharedString::from(msg));
                            });
                        }
                    }
                });
            });
        });
    }

    // SSH execute command
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        window.on_ssh_execute(move |host_id, command| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_id = host_id.to_string();
            let command = command.to_string();
            if command.is_empty() {
                return;
            }
            // Flip the running flag + clear previous output before kicking off.
            let weak_pending = weak.clone();
            let _ = weak_pending.upgrade_in_event_loop(|w| {
                w.set_host_cmd_running(true);
                w.set_host_cmd_stdout("".into());
                w.set_host_cmd_stderr("".into());
                w.set_host_cmd_exit_code(0);
            });
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    let result = c.ssh_execute_command(&host_id, &command).await;
                    let _ = weak.upgrade_in_event_loop(|w| { w.set_host_cmd_running(false); });
                    match result {
                        Ok(json) => {
                            let (stdout, stderr, exit) = parse_exec_result(&json);
                            let _ = weak.upgrade_in_event_loop(move |w| {
                                w.set_host_cmd_stdout(SharedString::from(stdout));
                                w.set_host_cmd_stderr(SharedString::from(stderr));
                                w.set_host_cmd_exit_code(exit);
                            });
                        }
                        Err(e) => push_error(&weak, format!("SSH execute failed: {e}")),
                    }
                });
            });
        });
    }

    // Set host password
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        window.on_set_host_password(move |host_id, password| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_id = host_id.to_string();
            let password = password.to_string();
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.ssh_set_password(&host_id, &password).await {
                        Ok(()) => push_status(&weak, "Password saved to Credential Manager."),
                        Err(e) => push_error(&weak, format!("Set password failed: {e}")),
                    }
                });
            });
        });
    }

    // Set host API token
    {
        let weak = window.as_weak();
        let conn = conn.clone();
        let rt = rt.clone();
        window.on_set_host_api_token(move |host_id, token, port| {
            let weak = weak.clone();
            let conn = conn.clone();
            let host_id = host_id.to_string();
            let token = token.to_string();
            let port_u16: u16 = if port > 0 && port < 65536 { port as u16 } else { 443 };
            rt.spawn(async move {
                with_client!(conn, weak, |c: Arc<client::DaemonClient>| async move {
                    match c.ssh_set_api_token(&host_id, &token, port_u16).await {
                        Ok(()) => push_status(&weak, "API token saved to Credential Manager."),
                        Err(e) => push_error(&weak, format!("Set API token failed: {e}")),
                    }
                });
            });
        });
    }

    // Host search - filters the cached host list client-side.
    {
        let weak = window.as_weak();
        let host_cache = host_cache.clone();
        let rt = rt.clone();
        window.on_host_search_changed(move |query| {
            let weak = weak.clone();
            let host_cache = host_cache.clone();
            let query = query.to_string();
            rt.spawn(async move {
                let hosts = host_cache.lock().await.clone();
                let filtered = if query.is_empty() {
                    hosts
                } else {
                    filter_hosts(&hosts, &query)
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_hosts(ModelRc::new(VecModel::from(filtered)));
                });
            });
        });
    }

    // Dismiss banners
    {
        let weak = window.as_weak();
        window.on_dismiss_error(move || {
            if let Some(w) = weak.upgrade() {
                w.set_last_error("".into());
                w.set_last_status_message("".into());
            }
        });
    }
}

// ---------------------------------------------------------------------------
// JSON → Slint-model helpers
// ---------------------------------------------------------------------------

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
                    customer: item
                        .get("customer")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    pinned: item.get("pinned").and_then(|v| v.as_bool()).unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_host_detail(j: &str) -> HostDetail {
    let v: serde_json::Value = serde_json::from_str(j).unwrap_or(serde_json::Value::Null);
    HostDetail {
        id: v.get("id").and_then(|x| x.as_str()).unwrap_or("").into(),
        label: v.get("label").and_then(|x| x.as_str()).unwrap_or("").into(),
        hostname: v.get("hostname").and_then(|x| x.as_str()).unwrap_or("").into(),
        port: v.get("port").and_then(|x| x.as_i64()).unwrap_or(22) as i32,
        username: v.get("username").and_then(|x| x.as_str()).unwrap_or("").into(),
        group: v.get("group").and_then(|x| x.as_str()).unwrap_or("").into(),
        customer: v.get("customer").and_then(|x| x.as_str()).unwrap_or("").into(),
        device_type: v
            .get("device_type")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into(),
        auth_method: v
            .get("auth_method")
            .and_then(|x| x.as_str())
            .unwrap_or("password")
            .into(),
        pinned: v.get("pinned").and_then(|x| x.as_bool()).unwrap_or(false),
        created_at: v
            .get("created_at")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .into(),
    }
}

/// Parse the `ssh_execute_command` RPC result into (stdout, stderr,
/// exit_code). The daemon wraps the JSON one extra level deep when it
/// returns from `Value::String` so we unwrap that here.
fn parse_exec_result(raw: &str) -> (String, String, i32) {
    // The dispatcher returns the JSON-as-string; unwrap one level.
    let inner: serde_json::Value = serde_json::from_str(raw).unwrap_or(serde_json::Value::Null);
    let parsed = if let Some(s) = inner.as_str() {
        serde_json::from_str::<serde_json::Value>(s).unwrap_or(inner.clone())
    } else {
        inner
    };
    let stdout = parsed
        .get("stdout")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_owned();
    let stderr = parsed
        .get("stderr")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_owned();
    let exit = parsed
        .get("exit_code")
        .and_then(|x| x.as_i64())
        .unwrap_or(-1) as i32;
    (stdout, stderr, exit)
}

/// Render the `test_host_connection` JSON ({ssh: "...", api: "..."})
/// as one human-readable summary line for the detail view.
fn summarise_test_result(j: &str) -> String {
    let inner: serde_json::Value = serde_json::from_str(j).unwrap_or(serde_json::Value::Null);
    // The daemon wraps in a string for D-Bus parity; unwrap if needed.
    let parsed = if let Some(s) = inner.as_str() {
        serde_json::from_str::<serde_json::Value>(s).unwrap_or(inner.clone())
    } else {
        inner
    };
    let ssh = parsed
        .get("ssh")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown");
    let api = parsed.get("api").and_then(|x| x.as_str());
    match api {
        Some(api) => format!("SSH: {ssh}  ·  API: {api}"),
        None => format!("SSH: {ssh}"),
    }
}

fn parse_profiles(j: &str) -> Vec<ProfileRow> {
    let arr: serde_json::Value = match serde_json::from_str(j) {
        Ok(v) => v,
        Err(e) => {
            warn!("parse profiles json: {e}");
            return Vec::new();
        }
    };
    arr.as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| ProfileRow {
                    id: item.get("id").and_then(|v| v.as_str()).unwrap_or("").into(),
                    name: item.get("name").and_then(|v| v.as_str()).unwrap_or("").into(),
                    backend: item
                        .get("backend")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    host: item.get("host").and_then(|v| v.as_str()).unwrap_or("").into(),
                    username: item
                        .get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .into(),
                    full_tunnel: item
                        .get("full_tunnel")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    auto_connect: item
                        .get("auto_connect")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// UI thread helpers
// ---------------------------------------------------------------------------

fn push_error(weak: &slint::Weak<AppWindow>, msg: String) {
    error!("{msg}");
    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_last_error(SharedString::from(msg));
        w.set_last_status_message("".into());
    });
}

fn push_status(weak: &slint::Weak<AppWindow>, msg: &'static str) {
    let _ = weak.upgrade_in_event_loop(move |w| {
        w.set_last_status_message(SharedString::from(msg));
        w.set_last_error("".into());
    });
}

/// Copy a string to the Windows clipboard via `arboard`.
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("clipboard init: {e}"))?;
    cb.set_text(text.to_owned())
        .map_err(|e| format!("clipboard set: {e}"))
}
