//! The Hosts page.

use slint::{ComponentHandle as _, ModelRc, SharedString, VecModel};

use super::{local, App, AppWindow, Ctx, HostInfo, HostItem, Hosts, Overlay};
use crate::model;

/// The device types and sign-in methods the add form offers, in the order
/// of its combo boxes (hosts.slint, `HostChoices`).
const DEVICE_TYPES: [&str; 7] = [
    "linux",
    "fortigate",
    "unifi",
    "opnsense",
    "sophos",
    "openwrt",
    "pfsense",
];
const AUTH_METHODS: [&str; 4] = ["password", "key", "api-token", "none"];

pub(super) fn bind(window: &AppWindow, ctx: &Ctx) {
    let hosts = window.global::<Hosts>();

    hosts.on_search_changed({
        let ctx = ctx.clone();
        move |query| {
            let all = ctx
                .host_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let shown = model::filter_hosts(&all, &query);
            ctx.ui(move |w| {
                w.global::<Hosts>().set_items(ModelRc::new(VecModel::from(
                    shown.iter().map(to_item).collect::<Vec<_>>(),
                )));
            });
        }
    });

    hosts.on_select({
        let ctx = ctx.clone();
        move |id| open(&ctx, id.to_string())
    });

    hosts.on_test({
        let ctx = ctx.clone();
        move |id| {
            let ctx2 = ctx.clone();
            let id = id.to_string();
            let port = ctx.weak.upgrade().map_or(22, |w| {
                u16::try_from(w.global::<Hosts>().get_detail().port).unwrap_or(22)
            });
            ctx.ui(|w| {
                let h = w.global::<Hosts>();
                h.set_testing(true);
                h.set_test_result(SharedString::default());
            });
            ctx.spawn(async move {
                let result = ctx2
                    .call(|c| async move { c.test_host_connection(&id).await })
                    .await
                    .map_or_else(|e| e, |json| model::describe_test(&json, port));
                ctx2.ui(move |w| {
                    let h = w.global::<Hosts>();
                    h.set_testing(false);
                    h.set_test_result(result.into());
                });
            });
        }
    });

    hosts.on_run({
        let ctx = ctx.clone();
        move |id, command| {
            let (ctx2, id, command) = (ctx.clone(), id.to_string(), command.to_string());
            if command.trim().is_empty() {
                return;
            }
            ctx.ui(|w| {
                let h = w.global::<Hosts>();
                h.set_running(true);
                h.set_has_output(false);
            });
            ctx.spawn(async move {
                let result = ctx2
                    .call(|c| async move { c.ssh_execute_command(&id, &command).await })
                    .await;
                ctx2.ui(move |w| {
                    let h = w.global::<Hosts>();
                    h.set_running(false);
                    match result {
                        Ok(json) => {
                            let (stdout, stderr, code) = model::parse_exec(&json);
                            h.set_stdout(stdout.into());
                            h.set_stderr(stderr.into());
                            h.set_exit_code(code);
                        }
                        Err(e) => {
                            h.set_stdout(SharedString::default());
                            h.set_stderr(e.into());
                            h.set_exit_code(-1);
                        }
                    }
                    h.set_has_output(true);
                });
            });
        }
    });

    hosts.on_save_password({
        let ctx = ctx.clone();
        move |id, password| {
            let (ctx2, id, password) = (ctx.clone(), id.to_string(), password.to_string());
            ctx.spawn(async move {
                match ctx2
                    .call(|c| async move { c.ssh_set_password(&id, &password).await })
                    .await
                {
                    Ok(()) => {
                        ctx2.ui(|w| {
                            w.global::<Hosts>()
                                .set_new_password(SharedString::default())
                        });
                        ctx2.toast_ok("Password saved to Windows Credential Manager.");
                    }
                    Err(e) => ctx2.toast_err(format!("Couldn't save the password: {e}")),
                }
            });
        }
    });

    hosts.on_save_token({
        let ctx = ctx.clone();
        move |id, token, port| {
            let (ctx2, id, token) = (ctx.clone(), id.to_string(), token.to_string());
            let port: u16 = match port.trim().parse() {
                Ok(p) if p > 0 => p,
                _ => {
                    ctx.toast_err("The API port must be a number from 1 to 65535.");
                    return;
                }
            };
            ctx.spawn(async move {
                match ctx2
                    .call(|c| async move { c.ssh_set_api_token(&id, &token, port).await })
                    .await
                {
                    Ok(()) => {
                        ctx2.ui(|w| w.global::<Hosts>().set_new_token(SharedString::default()));
                        ctx2.toast_ok("API token saved to Windows Credential Manager.");
                    }
                    Err(e) => ctx2.toast_err(format!("Couldn't save the API token: {e}")),
                }
            });
        }
    });

    hosts.on_toggle_pin({
        let ctx = ctx.clone();
        move |id| {
            let (ctx2, id) = (ctx.clone(), id.to_string());
            ctx.spawn(async move {
                let id2 = id.clone();
                if let Err(e) = ctx2
                    .call(|c| async move { c.toggle_host_pin(&id2).await })
                    .await
                {
                    ctx2.toast_err(format!("Couldn't change the pin: {e}"));
                }
                ctx2.refresh_all();
                open(&ctx2, id);
            });
        }
    });

    hosts.on_delete({
        let ctx = ctx.clone();
        move |id| {
            let (ctx2, id) = (ctx.clone(), id.to_string());
            let label = ctx
                .weak
                .upgrade()
                .map(|w| w.global::<Hosts>().get_detail().label.to_string())
                .unwrap_or_default();
            ctx.spawn(async move {
                let id2 = id.clone();
                match ctx2
                    .call(|c| async move { c.delete_host(&id2).await })
                    .await
                {
                    Ok(()) => {
                        ctx2.ui(move |w| {
                            let h = w.global::<Hosts>();
                            if h.get_selected_id() == id.as_str() {
                                h.set_selected_id(SharedString::default());
                                h.set_has_detail(false);
                            }
                        });
                        ctx2.toast_ok(format!("Deleted {label}."));
                    }
                    Err(e) => ctx2.toast_err(format!("Couldn't delete {label}: {e}")),
                }
                ctx2.refresh_all();
            });
        }
    });

    hosts.on_submit_add({
        let ctx = ctx.clone();
        move || submit_add(&ctx)
    });
}

/// Show host `id` in the detail pane, fresh from the service.
fn open(ctx: &Ctx, id: String) {
    let ctx2 = ctx.clone();
    ctx.spawn(async move {
        let id2 = id.clone();
        match ctx2.read(|c| async move { c.get_host(&id2).await }).await {
            Ok(json) => {
                let Some(d) = model::parse_host_detail(&json) else {
                    ctx2.toast_err("The service sent a host this app can't read.");
                    return;
                };
                ctx2.ui(move |w| {
                    let h = w.global::<Hosts>();
                    let same = h.get_has_detail() && h.get_detail().id == id.as_str();
                    h.set_detail(to_info(&d));
                    h.set_has_detail(true);
                    h.set_selected_id(id.into());
                    // A different host: the last one's output and test
                    // result say nothing about this one.
                    if !same {
                        h.set_test_result(SharedString::default());
                        h.set_has_output(false);
                        h.set_command(SharedString::default());
                        h.set_new_password(SharedString::default());
                        h.set_new_token(SharedString::default());
                    }
                });
            }
            Err(e) => ctx2.toast_err(format!("Couldn't open the host: {e}")),
        }
    });
}

fn to_item(h: &model::Host) -> HostItem {
    HostItem {
        id: h.id.clone().into(),
        label: h.label.clone().into(),
        address: h.address().into(),
        device_type: h.device_type.clone().into(),
        customer: h.customer.clone().into(),
        pinned: h.pinned,
    }
}

fn to_info(d: &model::HostDetail) -> HostInfo {
    HostInfo {
        id: d.host.id.clone().into(),
        label: d.host.label.clone().into(),
        hostname: d.host.hostname.clone().into(),
        port: i32::from(d.host.port),
        username: d.host.username.clone().into(),
        group: d.group.clone().into(),
        customer: d.host.customer.clone().into(),
        device_type: d.host.device_type.clone().into(),
        auth_method: model::auth_method_label(&d.auth_method).into(),
        pinned: d.host.pinned,
        created_at: d
            .created_at
            .map(|t| model::describe_time(local(t), chrono::Local::now()))
            .unwrap_or_default()
            .into(),
    }
}

/// Put the host list on the page, filtered by what is in the search box.
pub(super) fn show_hosts(ctx: &Ctx, hosts: Vec<model::Host>) {
    *ctx.host_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = hosts.clone();
    let want = ctx
        .select_host
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let ctx2 = ctx.clone();
    ctx.ui(move |w| {
        let h = w.global::<Hosts>();
        let shown = model::filter_hosts(&hosts, &h.get_search());
        h.set_items(ModelRc::new(VecModel::from(
            shown.iter().map(to_item).collect::<Vec<_>>(),
        )));
        h.set_total(i32::try_from(hosts.len()).unwrap_or(i32::MAX));
        let selected = h.get_selected_id().to_string();
        if let Some(id) = want {
            open(&ctx2, id);
        } else if !selected.is_empty() && !hosts.iter().any(|x| x.id == selected) {
            h.set_selected_id(SharedString::default());
            h.set_has_detail(false);
        }
    });
}

fn submit_add(ctx: &Ctx) {
    let Some(w) = ctx.weak.upgrade() else {
        return;
    };
    let h = w.global::<Hosts>();
    let port: u16 = match h.get_add_port().trim().parse() {
        Ok(p) if p > 0 => p,
        _ => {
            h.set_add_error("The SSH port must be a number from 1 to 65535.".into());
            return;
        }
    };
    let pick = |list: &[&str], i: i32| {
        usize::try_from(i)
            .ok()
            .and_then(|i| list.get(i))
            .copied()
            .unwrap_or(list[0])
            .to_owned()
    };
    let label = h.get_add_label().trim().to_owned();
    let host_json = serde_json::json!({
        "label": label,
        "hostname": h.get_add_hostname().trim(),
        "port": port,
        "username": h.get_add_username().trim(),
        "group": h.get_add_group().trim(),
        "device_type": pick(&DEVICE_TYPES, h.get_add_device_index()),
        "auth_method": pick(&AUTH_METHODS, h.get_add_auth_index()),
    })
    .to_string();
    h.set_add_busy(true);
    h.set_add_error(SharedString::default());

    let ctx2 = ctx.clone();
    ctx.spawn(async move {
        match ctx2
            .call(|c| async move { c.add_host(&host_json).await })
            .await
        {
            Ok(id) => {
                *ctx2
                    .select_host
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(id);
                ctx2.ui(|w| {
                    w.global::<Hosts>().set_add_busy(false);
                    let app = w.global::<App>();
                    if app.get_overlay() == Overlay::AddHost {
                        app.invoke_close_overlay();
                    }
                });
                ctx2.toast_ok(format!(
                    "Added {label}. Save its password or token under Credentials."
                ));
                ctx2.refresh_all();
            }
            Err(e) => ctx2.ui(move |w| {
                let h = w.global::<Hosts>();
                h.set_add_busy(false);
                h.set_add_error(e.into());
            }),
        }
    });
}
