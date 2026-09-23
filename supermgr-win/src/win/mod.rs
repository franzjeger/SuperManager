//! Windows GUI body. Gated on `cfg(target_os = "windows")` by the parent
//! `main.rs` so off-Windows builds skip Slint entirely.
//!
//! # Shape
//!
//! The UI (ui/*.slint) reads a handful of Slint globals — `App`, `Vpn`,
//! `Hosts`, `Keys`, `Updates` — and calls their callbacks. This module
//! fills the globals and answers the callbacks, one submodule per page.
//!
//! Two pipe connections to the service. `reads` carries the status poll and
//! the list refreshes; `actions` carries what the operator asks for. A
//! thirty-second SSH command on `actions` no longer stops the VPN status
//! from updating — the service handles one request at a time per
//! connection, and with one connection the poll queued behind everything.
//!
//! The status poll runs every five seconds, and every second while a
//! connect or disconnect is in flight, so the window follows a tunnel
//! coming up as it happens.

mod hosts;
mod import;
mod keys;
mod shell;
mod tray;
mod update;
mod vpn;

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use slint::ComponentHandle as _;
use supermgr_core::client::{self, DaemonClient};
use supermgr_core::pipe::PipeError;
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

use crate::model;

slint::include_modules!();

/// Status poll interval while nothing is happening.
const IDLE_POLL: Duration = Duration::from_secs(5);
/// Status poll interval while a connect or disconnect is in flight.
const BUSY_POLL: Duration = Duration::from_secs(1);
/// How often the profile, host and key lists are re-read unprompted.
const LIST_REFRESH: Duration = Duration::from_secs(30);
/// How long a success message stays up. Errors stay until dismissed.
const TOAST_TIME: Duration = Duration::from_secs(4);

const SERVICE_DOWN: &str = "The SuperManager service isn't running.";

type Slot = Arc<Mutex<Option<Arc<DaemonClient>>>>;

/// What every callback needs. Cheap to clone into one.
#[derive(Clone)]
pub(crate) struct Ctx {
    weak: slint::Weak<AppWindow>,
    rt: tokio::runtime::Handle,
    actions: Slot,
    reads: Slot,
    /// Wakes the poller early: after an action, the operator should not
    /// wait out the interval to see its effect.
    wake: Arc<Notify>,
    /// Set when the lists should be re-read on the next poll.
    lists_stale: Arc<AtomicBool>,
    /// Numbers toasts, so an old toast's timer does not hide a newer one.
    toast_seq: Arc<AtomicU64>,
    /// The last sign-in URL opened in the browser, so each opens once.
    opened_sign_in: Arc<std::sync::Mutex<String>>,
    /// The unfiltered host list; the search box filters it locally.
    host_cache: Arc<std::sync::Mutex<Vec<model::Host>>>,
    /// A profile or host to select once the next list refresh has it —
    /// the one just added.
    select_profile: Arc<std::sync::Mutex<Option<String>>>,
    select_host: Arc<std::sync::Mutex<Option<String>>>,
}

impl Ctx {
    fn new(weak: slint::Weak<AppWindow>, rt: tokio::runtime::Handle) -> Self {
        Self {
            weak,
            rt,
            actions: Arc::default(),
            reads: Arc::default(),
            wake: Arc::default(),
            lists_stale: Arc::new(AtomicBool::new(true)),
            toast_seq: Arc::default(),
            opened_sign_in: Arc::default(),
            host_cache: Arc::default(),
            select_profile: Arc::default(),
            select_host: Arc::default(),
        }
    }

    fn spawn(&self, f: impl Future<Output = ()> + Send + 'static) {
        self.rt.spawn(f);
    }

    /// Run `f` on the UI thread.
    fn ui(&self, f: impl FnOnce(&AppWindow) + Send + 'static) {
        let _ = self.weak.upgrade_in_event_loop(move |w| f(&w));
    }

    /// Re-read the status now.
    fn refresh_status(&self) {
        self.wake.notify_one();
    }

    /// Re-read the status and the lists now.
    fn refresh_all(&self) {
        self.lists_stale.store(true, Ordering::SeqCst);
        self.wake.notify_one();
    }

    fn toast_ok(&self, msg: impl Into<String>) {
        self.toast(msg.into(), ToastKind::Success);
    }

    fn toast_err(&self, msg: impl Into<String>) {
        let msg = msg.into();
        warn!("{msg}");
        self.toast(msg, ToastKind::Error);
    }

    fn toast(&self, msg: String, kind: ToastKind) {
        let seq = self.toast_seq.fetch_add(1, Ordering::SeqCst) + 1;
        self.ui(move |w| {
            let app = w.global::<App>();
            app.set_toast_text(msg.into());
            app.set_toast_kind(kind);
            app.set_toast_visible(true);
        });
        if kind == ToastKind::Success {
            let ctx = self.clone();
            self.spawn(async move {
                tokio::time::sleep(TOAST_TIME).await;
                if ctx.toast_seq.load(Ordering::SeqCst) == seq {
                    ctx.ui(|w| w.global::<App>().set_toast_visible(false));
                }
            });
        }
    }

    /// Call the service on the actions connection. Errors come back as a
    /// sentence for the operator; a connection that broke is dropped so the
    /// next call opens a fresh one.
    async fn call<T, F, Fut>(&self, f: F) -> Result<T, String>
    where
        F: FnOnce(Arc<DaemonClient>) -> Fut,
        Fut: Future<Output = Result<T, PipeError>>,
    {
        call_on(&self.actions, f).await
    }

    /// Same, on the reads connection.
    async fn read<T, F, Fut>(&self, f: F) -> Result<T, String>
    where
        F: FnOnce(Arc<DaemonClient>) -> Fut,
        Fut: Future<Output = Result<T, PipeError>>,
    {
        call_on(&self.reads, f).await
    }
}

async fn call_on<T, F, Fut>(slot: &Slot, f: F) -> Result<T, String>
where
    F: FnOnce(Arc<DaemonClient>) -> Fut,
    Fut: Future<Output = Result<T, PipeError>>,
{
    let client = {
        let mut guard = slot.lock().await;
        match guard.as_ref() {
            Some(c) => c.clone(),
            None => match client::connect().await {
                Ok(c) => {
                    let c = Arc::new(c);
                    *guard = Some(c.clone());
                    c
                }
                Err(e) => {
                    info!("service not reachable: {e}");
                    return Err(SERVICE_DOWN.into());
                }
            },
        }
    };
    match f(client).await {
        Ok(v) => Ok(v),
        Err(e) => {
            if matches!(
                e,
                PipeError::Connect(_)
                    | PipeError::Io(_)
                    | PipeError::Disconnected
                    | PipeError::Protocol(_)
                    | PipeError::Timeout(_)
            ) {
                *slot.lock().await = None;
            }
            Err(describe(&e))
        }
    }
}

/// A pipe error, for the operator.
fn describe(e: &PipeError) -> String {
    match e {
        PipeError::Connect(_) => SERVICE_DOWN.into(),
        PipeError::Io(_) | PipeError::Disconnected => {
            "Lost the connection to the SuperManager service. Try again in a moment.".into()
        }
        PipeError::Timeout(_) => "The SuperManager service didn't answer in time.".into(),
        PipeError::Protocol(m) => format!(
            "The service sent an answer this app can't read ({m}). The app and the service may be different versions — reinstalling updates both."
        ),
        PipeError::Rpc(e) => model::describe_rpc_error(e),
    }
}

pub fn run() -> anyhow::Result<()> {
    init_tracing();
    info!("supermgr-win starting");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    let window = AppWindow::new().context("create main window")?;
    let app = window.global::<App>();
    // Real version, not a placeholder: from the release tag in CI builds,
    // the crate version in dev builds (see build.rs).
    app.set_version(update::CURRENT_VERSION.into());
    app.set_data_root(program_data().into());

    let prefs = shell::Prefs::load();
    app.set_appearance(prefs.appearance);
    // "Use Windows setting" is the fluent style's own default and follows
    // Windows live; only an explicit choice overrides it.
    if prefs.appearance != 0 {
        window.invoke_set_color_scheme(prefs.appearance == 2);
    }

    let ctx = Ctx::new(window.as_weak(), rt.handle().clone());

    tray::install(&ctx);
    bind_app(&window, &ctx);
    vpn::bind(&window, &ctx);
    hosts::bind(&window, &ctx);
    keys::bind(&window, &ctx);
    update::bind(&window, &ctx);

    rt.spawn(poll(ctx.clone()));

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

fn program_data() -> String {
    let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into());
    format!(r"{}\SuperManager", base.trim_end_matches('\\'))
}

fn bind_app(window: &AppWindow, ctx: &Ctx) {
    let app = window.global::<App>();

    app.on_dismiss_toast({
        let ctx = ctx.clone();
        move || {
            ctx.toast_seq.fetch_add(1, Ordering::SeqCst);
            ctx.ui(|w| w.global::<App>().set_toast_visible(false));
        }
    });

    app.on_open_url(move |url| {
        shell::open_url(&url);
    });

    app.on_copy_text({
        let ctx = ctx.clone();
        move |text| match copy_to_clipboard(&text) {
            Ok(()) => ctx.toast_ok("Copied to the clipboard."),
            Err(e) => ctx.toast_err(format!("Couldn't copy: {e}")),
        }
    });

    app.on_appearance_changed({
        let weak = window.as_weak();
        move |mode| {
            shell::Prefs { appearance: mode }.save();
            if let Some(w) = weak.upgrade() {
                let dark = match mode {
                    1 => false,
                    2 => true,
                    // Back to following Windows: take its current setting.
                    // The style's live binding was replaced by the explicit
                    // choice and does not come back until the next start.
                    _ => shell::windows_prefers_dark(),
                };
                w.invoke_set_color_scheme(dark);
            }
        }
    });
}

/// The status poll, and the list refresh riding on it.
async fn poll(ctx: Ctx) {
    let mut last_lists: Option<Instant> = None;
    let mut online: Option<bool> = None;
    loop {
        let status = ctx.read(|c| async move { c.get_status().await }).await;
        let is_online = status.is_ok();
        if online != Some(is_online) {
            online = Some(is_online);
            ctx.ui(move |w| w.global::<App>().set_daemon_online(is_online));
            if is_online {
                info!("connected to the SuperManager service");
                ctx.lists_stale.store(true, Ordering::SeqCst);
            }
        }
        let status = status
            .map(|json| model::parse_status(&json))
            .unwrap_or_else(|_| model::Status::disconnected());
        let busy = status.is_busy();
        vpn::show_status(&ctx, status);

        let due = last_lists.map_or(true, |t| t.elapsed() >= LIST_REFRESH);
        if is_online && (due || ctx.lists_stale.swap(false, Ordering::SeqCst)) {
            refresh_lists(&ctx).await;
            last_lists = Some(Instant::now());
        }

        let delay = if busy { BUSY_POLL } else { IDLE_POLL };
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = ctx.wake.notified() => {}
        }
    }
}

async fn refresh_lists(ctx: &Ctx) {
    match ctx.read(|c| async move { c.list_profiles().await }).await {
        Ok(json) => vpn::show_profiles(ctx, model::parse_profiles(&json)),
        Err(e) => warn!("list profiles: {e}"),
    }
    // A service from before capabilities existed answers "unknown method";
    // the defaults describe what it could always do.
    let caps = ctx
        .read(|c| async move { c.vpn_capabilities().await })
        .await
        .map(|json| model::parse_capabilities(&json))
        .unwrap_or_default();
    vpn::show_capabilities(ctx, caps);
    match ctx.read(|c| async move { c.list_hosts().await }).await {
        Ok(json) => hosts::show_hosts(ctx, model::parse_hosts(&json)),
        Err(e) => warn!("list hosts: {e}"),
    }
    match ctx.read(|c| async move { c.ssh_list_keys().await }).await {
        Ok(json) => keys::show_keys(ctx, model::parse_keys(&json)),
        Err(e) => warn!("list keys: {e}"),
    }
}

/// Copy a string to the Windows clipboard.
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("clipboard: {e}"))?;
    cb.set_text(text.to_owned())
        .map_err(|e| format!("clipboard: {e}"))
}

/// A time for display, in local time.
fn local(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Local> {
    t.with_timezone(&chrono::Local)
}
