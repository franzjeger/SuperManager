//! The VPN page: profiles, the tunnel's state, and adding profiles.

use slint::{ComponentHandle as _, Model as _, ModelRc, SharedString, VecModel};
use tracing::info;

use super::{
    import, local, shell, tray, App, AppWindow, ConnState, Ctx, Overlay, ProfileItem, ProfileKind,
    Vpn,
};
use crate::model;

pub(super) fn bind(window: &AppWindow, ctx: &Ctx) {
    let vpn = window.global::<Vpn>();

    vpn.on_connect({
        let ctx = ctx.clone();
        move |id| connect(&ctx, id.to_string())
    });

    vpn.on_retry({
        let ctx = ctx.clone();
        move || {
            if let Some(w) = ctx.weak.upgrade() {
                let id = w.global::<Vpn>().get_state_profile_id().to_string();
                if !id.is_empty() {
                    connect(&ctx, id);
                }
            }
        }
    });

    vpn.on_disconnect({
        let ctx = ctx.clone();
        move || disconnect(&ctx, false)
    });

    // An error is cleared the way the service clears it: a disconnect.
    vpn.on_dismiss_error({
        let ctx = ctx.clone();
        move || disconnect(&ctx, true)
    });

    vpn.on_set_push_dns({
        let ctx = ctx.clone();
        move |id, enabled| {
            let (ctx2, id) = (ctx.clone(), id.to_string());
            ctx.spawn(async move {
                let id2 = id.clone();
                if let Err(e) = ctx2
                    .call(|c| async move { c.set_push_dns(&id2, enabled).await })
                    .await
                {
                    ctx2.toast_err(format!("Couldn't change the DNS setting: {e}"));
                }
                ctx2.refresh_all();
            });
        }
    });

    vpn.on_set_full_tunnel({
        let ctx = ctx.clone();
        move |id, enabled| {
            let (ctx2, id) = (ctx.clone(), id.to_string());
            ctx.spawn(async move {
                let id2 = id.clone();
                if let Err(e) = ctx2
                    .call(|c| async move { c.set_full_tunnel(&id2, enabled).await })
                    .await
                {
                    ctx2.toast_err(format!("Couldn't change the routing setting: {e}"));
                }
                ctx2.refresh_all();
            });
        }
    });

    vpn.on_submit_rename({
        let ctx = ctx.clone();
        move |id, name| {
            let (ctx2, id, name) = (ctx.clone(), id.to_string(), name.trim().to_owned());
            if name.is_empty() {
                return;
            }
            ctx.spawn(async move {
                let (id2, name2) = (id.clone(), name.clone());
                match ctx2
                    .call(|c| async move { c.rename_profile(&id2, &name2).await })
                    .await
                {
                    Ok(()) => {
                        ctx2.ui(|w| w.global::<App>().invoke_close_overlay());
                        ctx2.toast_ok(format!("Renamed to {name}."));
                    }
                    Err(e) => ctx2.toast_err(format!("Couldn't rename the profile: {e}")),
                }
                ctx2.refresh_all();
            });
        }
    });

    vpn.on_delete({
        let ctx = ctx.clone();
        move |id| {
            let ctx2 = ctx.clone();
            let id = id.to_string();
            let name = ctx
                .weak
                .upgrade()
                .map(|w| profile_name(&w.global::<Vpn>(), &id))
                .unwrap_or_default();
            ctx.spawn(async move {
                let id2 = id.clone();
                match ctx2
                    .call(|c| async move { c.delete_profile(&id2).await })
                    .await
                {
                    Ok(()) => ctx2.toast_ok(format!("Deleted {name}.")),
                    Err(e) => ctx2.toast_err(format!("Couldn't delete {name}: {e}")),
                }
                ctx2.refresh_all();
            });
        }
    });

    vpn.on_choose_file({
        let ctx = ctx.clone();
        move |kind| choose_file(&ctx, kind)
    });

    vpn.on_submit_add({
        let ctx = ctx.clone();
        move || submit_add(&ctx)
    });
}

fn connect(ctx: &Ctx, id: String) {
    // Say so at once. The poll a moment later has the service's own word.
    if let Some(w) = ctx.weak.upgrade() {
        let v = w.global::<Vpn>();
        let name = profile_name(&v, &id);
        v.set_state(ConnState::Connecting);
        v.set_state_profile_id(id.clone().into());
        v.set_state_profile_name(name.into());
        v.set_phase("Starting".into());
        v.set_error_message(SharedString::default());
        v.set_auth_url(SharedString::default());
    }
    let ctx2 = ctx.clone();
    ctx.spawn(async move {
        info!(profile = %id, "connect requested");
        if let Err(e) = ctx2.call(|c| async move { c.connect(&id).await }).await {
            ctx2.toast_err(format!("Couldn't start the connection: {e}"));
        }
        ctx2.refresh_status();
    });
}

/// Disconnect, cancel a connect, or — `quiet` — clear an error, which
/// has nothing to report if it fails.
fn disconnect(ctx: &Ctx, quiet: bool) {
    let ctx2 = ctx.clone();
    ctx.spawn(async move {
        if let Err(e) = ctx2.call(|c| async move { c.disconnect().await }).await {
            if !quiet {
                ctx2.toast_err(format!("Couldn't disconnect: {e}"));
            }
        }
        ctx2.refresh_status();
    });
}

/// The name of profile `id`, from the list the window has.
fn profile_name(v: &Vpn<'_>, id: &str) -> String {
    let profiles = v.get_profiles();
    (0..profiles.row_count())
        .filter_map(|i| profiles.row_data(i))
        .find(|p| p.id == id)
        .map(|p| p.name.to_string())
        .unwrap_or_default()
}

/// Put the service's status on the page, and open a sign-in page the
/// first time the service offers one.
pub(super) fn show_status(ctx: &Ctx, s: model::Status) {
    if model::is_sign_in_url(&s.auth_url) {
        let fresh = {
            let mut opened = ctx
                .opened_sign_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let fresh = *opened != s.auth_url;
            if fresh {
                opened.clone_from(&s.auth_url);
            }
            fresh
        };
        if fresh {
            info!("opening the Microsoft sign-in page");
            shell::open_url(&s.auth_url);
        }
    }

    ctx.ui(move |w| {
        let v = w.global::<Vpn>();
        let name = profile_name(&v, &s.profile_id);
        let backend = model::kind_label(model::kind_of(&s.backend), &s.backend);
        let state = match s.phase {
            model::Phase::Disconnected => ConnState::Disconnected,
            model::Phase::Connecting => ConnState::Connecting,
            model::Phase::Connected => ConnState::Connected,
            model::Phase::Disconnecting => ConnState::Disconnecting,
            model::Phase::Failed => ConnState::Failed,
        };
        v.set_state(state);
        v.set_state_profile_id(s.profile_id.clone().into());
        v.set_state_profile_name(name.clone().into());
        v.set_state_backend(backend.into());
        v.set_phase(s.step.clone().into());
        v.set_interface(s.interface.clone().into());
        v.set_since(
            s.since
                .map(|t| model::describe_since(local(t), chrono::Local::now()))
                .unwrap_or_default()
                .into(),
        );
        v.set_error_message(s.message.clone().into());
        let url = if model::is_sign_in_url(&s.auth_url) {
            s.auth_url.as_str()
        } else {
            ""
        };
        v.set_auth_url(url.into());

        let named = if name.is_empty() {
            "VPN".to_owned()
        } else {
            name
        };
        tray::set_tooltip(&match s.phase {
            model::Phase::Connected => format!("SuperManager — connected to {named}"),
            model::Phase::Connecting => format!("SuperManager — connecting to {named}…"),
            model::Phase::Disconnecting => format!("SuperManager — disconnecting…"),
            model::Phase::Failed => format!("SuperManager — couldn't connect to {named}"),
            model::Phase::Disconnected => "SuperManager — not connected".to_owned(),
        });
    });
}

fn to_item(p: &model::Profile) -> ProfileItem {
    ProfileItem {
        id: p.id.clone().into(),
        name: p.name.clone().into(),
        kind: match p.kind {
            model::Kind::WireGuard => ProfileKind::Wireguard,
            model::Kind::OpenVpn => ProfileKind::Openvpn,
            model::Kind::Azure => ProfileKind::Azure,
            model::Kind::FortiGate => ProfileKind::Fortigate,
            model::Kind::SslVpn => ProfileKind::Sslvpn,
            model::Kind::Other => ProfileKind::Other,
        },
        kind_label: p.kind_label.clone().into(),
        host: p.host.clone().into(),
        username: p.username.clone().into(),
        full_tunnel: p.full_tunnel,
        push_dns: p.push_dns,
        last_connected: p
            .last_connected
            .map(|t| model::describe_time(local(t), chrono::Local::now()))
            .unwrap_or_default()
            .into(),
    }
}

/// Put the profile list on the page, keeping the selection where it was —
/// or moving it to a profile just added.
pub(super) fn show_profiles(ctx: &Ctx, profiles: Vec<model::Profile>) {
    let want = ctx
        .select_profile
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    ctx.ui(move |w| {
        let v = w.global::<Vpn>();
        let items: Vec<ProfileItem> = profiles.iter().map(to_item).collect();
        let current = v
            .get_has_selection()
            .then(|| v.get_selected().id.to_string());
        let active = v.get_state_profile_id().to_string();
        let pick = want
            .and_then(|id| items.iter().find(|p| p.id == id.as_str()))
            .or_else(|| current.and_then(|id| items.iter().find(|p| p.id == id.as_str())))
            .or_else(|| items.iter().find(|p| p.id == active.as_str()))
            .or_else(|| items.first())
            .cloned();
        v.set_profiles(ModelRc::new(VecModel::from(items)));
        match pick {
            Some(p) => v.invoke_select(p),
            None => v.set_has_selection(false),
        }
    });
}

pub(super) fn show_capabilities(ctx: &Ctx, caps: model::Capabilities) {
    ctx.ui(move |w| {
        let v = w.global::<Vpn>();
        v.set_wireguard_available(caps.wireguard.is_ok());
        v.set_wireguard_reason(caps.wireguard.err().unwrap_or_default().into());
        v.set_openvpn_available(caps.openvpn.is_ok());
        v.set_openvpn_reason(caps.openvpn.err().unwrap_or_default().into());
        v.set_sslvpn_available(caps.sslvpn.is_ok());
        v.set_sslvpn_reason(caps.sslvpn.err().unwrap_or_default().into());
    });
}

/// Pick a config file, read it, and fill the form with it.
fn choose_file(ctx: &Ctx, kind: ProfileKind) {
    let Some(w) = ctx.weak.upgrade() else {
        return;
    };
    let dialog = rfd::AsyncFileDialog::new().set_parent(&w.window().window_handle());
    let dialog = match kind {
        ProfileKind::Wireguard => dialog
            .set_title("Choose a WireGuard configuration")
            .add_filter("WireGuard configuration", &["conf"]),
        ProfileKind::Openvpn => dialog
            .set_title("Choose an OpenVPN configuration")
            .add_filter("OpenVPN configuration", &["ovpn", "conf"]),
        ProfileKind::Azure => dialog
            .set_title("Choose the Azure VPN profile package")
            .add_filter("Azure VPN profile", &["zip", "xml"]),
        _ => dialog,
    }
    .add_filter("All files", &["*"]);

    let pick = dialog.pick_file();
    let weak = ctx.weak.clone();
    // On the UI thread: the dialog is modal to this window, and the file
    // is small enough to read without leaving it.
    let _ = slint::spawn_local(async move {
        let Some(file) = pick.await else {
            return;
        };
        let loaded = import::load(kind, file.path());
        let Some(w) = weak.upgrade() else {
            return;
        };
        let v = w.global::<Vpn>();
        match loaded {
            Ok(l) => {
                v.set_add_text(l.text.into());
                v.set_add_text_2(l.text_2.into());
                v.set_add_file(l.label.into());
                if v.get_add_name().trim().is_empty() {
                    v.set_add_name(l.suggested_name.into());
                }
                v.set_add_error(SharedString::default());
            }
            Err(e) => v.set_add_error(e.into()),
        }
    });
}

/// What the add-profile form holds when Add is pressed.
struct NewProfile {
    kind: ProfileKind,
    name: String,
    text: String,
    text_2: String,
    host: String,
    port: String,
    username: String,
    password: String,
}

fn submit_add(ctx: &Ctx) {
    let Some(w) = ctx.weak.upgrade() else {
        return;
    };
    let v = w.global::<Vpn>();
    let form = NewProfile {
        kind: v.get_add_kind(),
        name: v.get_add_name().trim().to_owned(),
        text: v.get_add_text().to_string(),
        text_2: v.get_add_text_2().to_string(),
        host: v.get_add_host().trim().to_owned(),
        port: v.get_add_port().trim().to_owned(),
        username: v.get_add_username().trim().to_owned(),
        password: v.get_add_password().to_string(),
    };
    v.set_add_busy(true);
    v.set_add_error(SharedString::default());

    let ctx2 = ctx.clone();
    ctx.spawn(async move {
        let name = form.name.clone();
        match add_profile(&ctx2, form).await {
            Ok(id) => {
                *ctx2
                    .select_profile
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(id);
                ctx2.ui(|w| {
                    w.global::<Vpn>().set_add_busy(false);
                    let app = w.global::<App>();
                    if app.get_overlay() == Overlay::AddProfile {
                        app.invoke_close_overlay();
                    }
                });
                ctx2.toast_ok(format!("Added {name}."));
                ctx2.refresh_all();
            }
            Err(e) => ctx2.ui(move |w| {
                let v = w.global::<Vpn>();
                v.set_add_busy(false);
                v.set_add_error(e.into());
            }),
        }
    });
}

async fn add_profile(ctx: &Ctx, f: NewProfile) -> Result<String, String> {
    let NewProfile {
        kind,
        name,
        text,
        text_2,
        host,
        port,
        username,
        password,
    } = f;
    match kind {
        ProfileKind::Wireguard => {
            ctx.call(|c| async move { c.import_wireguard(&text, &name).await })
                .await
        }
        ProfileKind::Openvpn => {
            ctx.call(|c| async move { c.import_openvpn(&text, &name, &username, &password).await })
                .await
        }
        ProfileKind::Azure => {
            ctx.call(|c| async move { c.import_azure_vpn(&text, &text_2, &name).await })
                .await
        }
        ProfileKind::Fortigate => {
            ctx.call(|c| async move {
                c.import_fortigate(&name, &host, &username, &password, "")
                    .await
            })
            .await
        }
        ProfileKind::Sslvpn => {
            let port: u16 = match port.parse() {
                Ok(p) if p > 0 => p,
                _ => return Err("The port must be a number from 1 to 65535.".into()),
            };
            ctx.call(|c| async move {
                c.import_forticlient_sslvpn(
                    &name, &host, port, &username, &password, None, "[]", "[]",
                )
                .await
            })
            .await
        }
        ProfileKind::Other => Err("Choose what kind of profile to add.".into()),
    }
}
