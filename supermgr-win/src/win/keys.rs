//! The SSH keys page.

use slint::{ComponentHandle as _, Model as _, ModelRc, SharedString, VecModel};

use super::{copy_to_clipboard, local, App, AppWindow, Ctx, KeyItem, Keys, Overlay};
use crate::model;

/// The key types the generate form offers, in the order of its combo box.
const KEY_TYPES: [&str; 3] = ["ed25519", "rsa4096", "rsa2048"];

pub(super) fn bind(window: &AppWindow, ctx: &Ctx) {
    let keys = window.global::<Keys>();

    keys.on_copy_public({
        let ctx = ctx.clone();
        move |id| {
            let (ctx2, id) = (ctx.clone(), id.to_string());
            ctx.spawn(async move {
                match ctx2
                    .call(|c| async move { c.ssh_export_public_key(&id).await })
                    .await
                {
                    Ok(public) => match copy_to_clipboard(public.trim()) {
                        Ok(()) => ctx2.toast_ok("Public key copied to the clipboard."),
                        Err(e) => ctx2.toast_err(format!("Couldn't copy the public key: {e}")),
                    },
                    Err(e) => ctx2.toast_err(format!("Couldn't read the public key: {e}")),
                }
            });
        }
    });

    keys.on_delete({
        let ctx = ctx.clone();
        move |id| {
            let (ctx2, id) = (ctx.clone(), id.to_string());
            let name = ctx
                .weak
                .upgrade()
                .map(|w| {
                    let items = w.global::<Keys>().get_items();
                    (0..items.row_count())
                        .filter_map(|i| items.row_data(i))
                        .find(|k| k.id == id.as_str())
                        .map(|k| k.name.to_string())
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            ctx.spawn(async move {
                match ctx2
                    .call(|c| async move { c.ssh_delete_key(&id).await })
                    .await
                {
                    Ok(()) => ctx2.toast_ok(format!("Deleted {name}.")),
                    Err(e) => ctx2.toast_err(format!("Couldn't delete {name}: {e}")),
                }
                ctx2.refresh_all();
            });
        }
    });

    keys.on_submit_add({
        let ctx = ctx.clone();
        move || {
            let Some(w) = ctx.weak.upgrade() else {
                return;
            };
            let k = w.global::<Keys>();
            let name = k.get_add_name().trim().to_owned();
            let description = k.get_add_description().trim().to_owned();
            let key_type = usize::try_from(k.get_add_type_index())
                .ok()
                .and_then(|i| KEY_TYPES.get(i))
                .copied()
                .unwrap_or(KEY_TYPES[0]);
            k.set_add_busy(true);
            k.set_add_error(SharedString::default());
            let ctx2 = ctx.clone();
            ctx.spawn(async move {
                let label = name.clone();
                match ctx2
                    .call(|c| async move {
                        c.ssh_generate_key(key_type, &name, &description, "[]")
                            .await
                    })
                    .await
                {
                    Ok(_) => {
                        ctx2.ui(|w| {
                            w.global::<Keys>().set_add_busy(false);
                            let app = w.global::<App>();
                            if app.get_overlay() == Overlay::GenerateKey {
                                app.invoke_close_overlay();
                            }
                        });
                        ctx2.toast_ok(format!("Generated {label}."));
                        ctx2.refresh_all();
                    }
                    Err(e) => ctx2.ui(move |w| {
                        let k = w.global::<Keys>();
                        k.set_add_busy(false);
                        k.set_add_error(e.into());
                    }),
                }
            });
        }
    });
}

pub(super) fn show_keys(ctx: &Ctx, keys: Vec<model::Key>) {
    ctx.ui(move |w| {
        let now = chrono::Local::now();
        let items: Vec<KeyItem> = keys
            .iter()
            .map(|k| KeyItem {
                id: k.id.clone().into(),
                name: k.name.clone().into(),
                key_type: k.key_type.clone().into(),
                fingerprint: k.fingerprint.clone().into(),
                created_at: k
                    .created_at
                    .map(|t| model::describe_time(local(t), now))
                    .unwrap_or_default()
                    .into(),
            })
            .collect();
        w.global::<Keys>()
            .set_items(ModelRc::new(VecModel::from(items)));
    });
}
