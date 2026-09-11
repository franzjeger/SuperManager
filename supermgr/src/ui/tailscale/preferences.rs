use super::*;
use supermgr_core::tailscale::{TailscalePreferences, TailscalePreferencesPatch};

pub(super) fn show(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
    prefs: &TailscalePreferences,
) {
    let dialog = adw::Dialog::builder()
        .title("Tailscale settings")
        .content_width(660)
        .content_height(700)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let (scroll, body) = design::detail_body();
    body.set_spacing(20);
    toolbar.set_content(Some(&scroll));
    let group = design::card("Network and access");
    let mut toggles = Vec::new();
    for (title, subtitle, value) in [
        (
            "Use Tailscale DNS",
            "Use MagicDNS and the nameservers configured for this tailnet.",
            prefs.accept_dns,
        ),
        (
            "Accept subnet routes",
            "Reach networks advertised by other devices.",
            prefs.accept_routes,
        ),
        (
            "Block incoming connections",
            "Shields up blocks incoming tailnet connections; outgoing access remains available.",
            prefs.shields_up,
        ),
        (
            "Tailscale SSH server",
            "Allow SSH access to this machine according to tailnet policy.",
            prefs.run_ssh,
        ),
        (
            "Allow LAN access with an exit node",
            "Keep access to local devices while routing internet traffic through an exit node.",
            prefs.exit_node_allow_lan,
        ),
        (
            "Advertise as an exit node",
            "Requires IP forwarding and approval in the Tailscale admin console.",
            prefs.advertise_exit_node,
        ),
        (
            "Automatic updates",
            "Availability depends on how Tailscale is installed.",
            prefs.auto_update,
        ),
    ] {
        let toggle = adw::SwitchRow::builder()
            .title(title)
            .subtitle(if value.is_none() {
                "Not reported by this Tailscale installation"
            } else {
                subtitle
            })
            .active(value.unwrap_or(false))
            .sensitive(value.is_some())
            .build();
        group.add(&toggle);
        toggles.push((toggle, value));
    }
    body.append(&group);
    let identity = design::card("Hostname and subnet routing");
    let hostname = adw::EntryRow::builder()
        .title("Hostname override (empty uses OS name)")
        .text(prefs.hostname.as_deref().unwrap_or(""))
        .sensitive(prefs.hostname.is_some())
        .build();
    let routes = adw::EntryRow::builder()
        .title("Advertised subnet CIDRs, comma-separated")
        .text(
            prefs
                .advertise_routes
                .as_ref()
                .map(|v| v.join(", "))
                .unwrap_or_default(),
        )
        .sensitive(prefs.advertise_routes.is_some())
        .build();
    identity.add(&hostname);
    identity.add(&routes);
    identity.set_description(Some("Subnet edits replace the advertised subnet list. IP forwarding and tailnet approval are managed separately."));
    body.append(&identity);
    let result = gtk4::Label::builder()
        .wrap(true)
        .lines(4)
        .ellipsize(gtk4::pango::EllipsizeMode::End)
        .xalign(0.0)
        .visible(false)
        .build();
    result.bind_property("label", &result, "tooltip-text").sync_create().build();
    let footer = gtk4::Box::builder().orientation(gtk4::Orientation::Vertical).spacing(10)
        .margin_start(24).margin_end(24).margin_top(12).margin_bottom(16).build();
    footer.append(&result);
    let apply = gtk4::Button::builder()
        .label("Apply changes")
        .halign(gtk4::Align::End)
        .css_classes(["suggested-action"])
        .build();
    footer.append(&apply);
    toolbar.add_bottom_bar(&footer);
    let original = prefs.clone();
    let rt = rt.clone();
    let tx = tx.clone();
    let weak_dialog = dialog.downgrade();
    apply.connect_clicked(move |button| {
        let changed = |index: usize| {
            let (row, previous) = &toggles[index];
            previous.and_then(|value| (value != row.is_active()).then_some(row.is_active()))
        };
        let route_values: Vec<String> = routes
            .text()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let hostname_value = hostname.text().trim().to_owned();
        let patch = TailscalePreferencesPatch {
            profile_id: original.profile_id.clone().unwrap_or_default(),
            accept_dns: changed(0),
            accept_routes: changed(1),
            shields_up: changed(2),
            run_ssh: changed(3),
            exit_node_allow_lan: changed(4),
            advertise_exit_node: changed(5),
            auto_update: changed(6),
            hostname: original
                .hostname
                .as_ref()
                .and_then(|v| (v != &hostname_value).then_some(hostname_value)),
            advertise_routes: original
                .advertise_routes
                .as_ref()
                .and_then(|v| (v != &route_values).then_some(route_values)),
        };
        button.set_sensitive(false);
        result.set_visible(true);
        result.set_label("Applying changes…");
        let task =
            rt.spawn(
                async move { crate::dbus_client::dbus_tailscale_apply_preferences(&patch).await },
            );
        let button = button.clone();
        let result = result.clone();
        let dialog = weak_dialog.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        gtk4::glib::spawn_future_local(async move {
            button.set_sensitive(true);
            match task.await {
                Ok(Ok(output)) => {
                    if output.is_empty() {
                        if let Some(dialog) = dialog.upgrade() {
                            dialog.close();
                        }
                    } else {
                        result
                            .set_label(&format!("Settings applied. Tailscale reported:\n{output}"));
                        button.set_sensitive(false);
                    }
                    tx.send(AppMsg::ShowToast("Tailscale settings applied".into()))
                        .ok();
                    rt.spawn(async move {
                        refresh(&tx).await;
                    });
                }
                Ok(Err(e)) => result.set_label(&format!("Could not apply settings: {e:#}")),
                Err(e) => result.set_label(&format!("Settings task failed: {e}")),
            }
        });
    });
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(window));
}
