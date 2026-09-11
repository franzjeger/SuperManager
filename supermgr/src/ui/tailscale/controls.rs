use super::*;
use supermgr_core::tailscale::TailscaleManagement;

pub(super) fn render_management(
    view: &TailscaleView,
    result: &Result<TailscaleManagement, String>,
) {
    while let Some(child) = view.controls.first_child() {
        view.controls.remove(&child);
    }
    let data = match result {
        Ok(data) => data,
        Err(e) => {
            view.controls.append(&notice(&format!(
                "Account and settings controls unavailable: {e}"
            )));
            return;
        }
    };
    for warning in &data.warnings {
        view.controls.append(&notice(warning));
    }
    let active = data.profiles.iter().find(|p| p.selected);
    if let Some(prefs) = &data.preferences {
        let card = design::card("This machine");
        if let Some(profile) = &prefs.profile_id {
            let diagnose = button("DNS diagnostics");
            let profile = profile.clone(); let window = view.window.clone(); let rt = view.rt.clone();
            diagnose.connect_clicked(move |_| super::diagnostics::show(&window, &rt, &profile));
            card.set_header_suffix(Some(&diagnose));
        }
        let row = adw::ActionRow::builder()
            .title(match prefs.want_running {
                Some(true) => "Tailscale enabled",
                Some(false) => "Tailscale paused",
                None => "Local settings",
            })
            .subtitle(
                &active
                    .map(|p| format!("{} · {}", p.account, p.tailnet))
                    .unwrap_or_else(|| "No active account reported".into()),
            )
            .title_lines(1)
            .subtitle_lines(2)
            .build();
        if let (Some(profile), Some(running)) = (&prefs.profile_id, prefs.want_running) {
            let toggle = button(if running { "Disconnect" } else { "Connect" });
            let profile = profile.clone();
            let rt = view.rt.clone();
            let tx = view.tx.clone();
            toggle.connect_clicked(move |button| {
                let profile = profile.clone();
                run_action(
                    &rt,
                    &tx,
                    button,
                    "Tailscale connection updated",
                    async move {
                        crate::dbus_client::dbus_tailscale_set_running(&profile, !running).await
                    },
                );
            });
            row.add_suffix(&toggle);
        }
        let settings = button("Settings");
        settings.set_sensitive(prefs.profile_id.is_some());
        let prefs = prefs.clone();
        let rt = view.rt.clone();
        let tx = view.tx.clone();
        let window = view.window.clone();
        settings.connect_clicked(move |_| super::preferences::show(&window, &rt, &tx, &prefs));
        row.add_suffix(&settings);
        card.add(&row);
        view.controls.append(&card);
    }
    if !data.profiles.is_empty() {
        let card = design::card("Accounts");
        let add = button("Add account…");
        let previous = active.map(|p| p.id.clone()).unwrap_or_default();
        let window = view.window.clone(); let rt = view.rt.clone(); let tx = view.tx.clone();
        add.connect_clicked(move |_| super::accounts::show(&window, &rt, &tx, &previous));
        card.set_header_suffix(Some(&add));
        let labels = data
            .profiles
            .iter()
            .map(|p| {
                format!(
                    "{} · {}{}",
                    if p.nickname.is_empty() {
                        &p.account
                    } else {
                        &p.nickname
                    },
                    p.tailnet,
                    if p.selected { " (current)" } else { "" }
                )
            })
            .collect::<Vec<_>>();
        let model = gtk4::StringList::new(&labels.iter().map(String::as_str).collect::<Vec<_>>());
        let selected = data.profiles.iter().position(|p| p.selected).unwrap_or(0) as u32;
        let picker = adw::ComboRow::builder()
            .title("Saved account")
            .model(&model)
            .selected(selected)
            .build();
        let switch = button("Switch");
        switch.set_sensitive(false);
        {
            let switch = switch.clone();
            picker.connect_selected_notify(move |p| switch.set_sensitive(p.selected() != selected));
        }
        let choices = data.profiles.clone();
        let choice = picker.clone();
        let rt = view.rt.clone();
        let tx = view.tx.clone();
        switch.connect_clicked(move |button| {
            if let Some(profile) = choices.get(choice.selected() as usize) {
                let id = profile.id.clone();
                run_action(&rt, &tx, button, "Tailscale account switched", async move {
                    crate::dbus_client::dbus_tailscale_switch_profile(&id).await
                });
            }
        });
        picker.add_suffix(&switch);
        card.add(&picker);
        if let Some(active) = active {
            let logout = button("Log out…");
            let menu = gtk4::MenuButton::builder().icon_name("view-more-symbolic")
                .tooltip_text("Account actions").valign(gtk4::Align::Center).css_classes(["flat"]).build();
            let popover = gtk4::Popover::new(); popover.set_child(Some(&logout));
            menu.set_popover(Some(&popover)); picker.add_suffix(&menu);
            logout.connect_clicked(move |_| popover.popdown());
            let id = active.id.clone();
            let window = view.window.clone();
            let rt = view.rt.clone();
            let tx = view.tx.clone();
            logout.connect_clicked(move |button| {
                let dialog = adw::AlertDialog::new(Some("Log out of Tailscale?"), Some("This disconnects the active account. You will need to sign in again to use it."));
                dialog.add_response("cancel","Cancel"); dialog.add_response("logout","Log out");
                dialog.set_response_appearance("logout", adw::ResponseAppearance::Destructive);
                dialog.set_default_response(Some("cancel")); dialog.set_close_response("cancel");
                let id = id.clone(); let rt = rt.clone(); let tx = tx.clone(); let button = button.clone();
                dialog.connect_response(Some("logout"), move |_,_| {
                    let id = id.clone(); run_action(&rt, &tx, &button, "Logged out of Tailscale", async move { crate::dbus_client::dbus_tailscale_logout(&id).await });
                });
                dialog.present(Some(&window));
            });
        }
        view.controls.append(&card);
    }
}

fn button(label: &str) -> gtk4::Button {
    gtk4::Button::builder()
        .label(label)
        .valign(gtk4::Align::Center)
        .build()
}

fn notice(text: &str) -> gtk4::Label {
    gtk4::Label::builder()
        .label(text)
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build()
}

fn run_action(
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
    button: &gtk4::Button,
    success: &'static str,
    action: impl std::future::Future<Output = anyhow::Result<String>> + Send + 'static,
) {
    button.set_sensitive(false);
    let button = button.clone();
    let tx = tx.clone();
    let refresh_tx = tx.clone();
    let task = rt.spawn(async move {
        let result = action.await;
        refresh(&refresh_tx).await;
        result
    });
    gtk4::glib::spawn_future_local(async move {
        let result = task.await;
        button.set_sensitive(true);
        match result {
            Ok(Ok(output)) => {
                tx.send(AppMsg::ShowToast(if output.is_empty() {
                    success.into()
                } else {
                    format!("{success}: {output}")
                }))
                .ok();
            }
            Ok(Err(e)) => {
                tx.send(AppMsg::OperationFailed(format!("Tailscale: {e:#}")))
                    .ok();
            }
            Err(e) => {
                tx.send(AppMsg::OperationFailed(format!(
                    "Tailscale task failed: {e}"
                )))
                .ok();
            }
        }
    });
}

pub(super) fn matches_node(node: &TailscaleNode, query: &str, filter: u32) -> bool {
    (match filter {
        1 => node.online,
        2 => !node.online,
        3 => node.exit_node_option || node.exit_node,
        _ => true,
    }) && format!(
        "{} {} {} {}",
        node.display_name(),
        node.dns_name,
        node.os,
        node.tailscale_ips.join(" ")
    )
    .to_lowercase()
    .contains(&query.trim().to_lowercase())
}

pub(super) fn node_row(view: &TailscaleView, node: &TailscaleNode) -> adw::ExpanderRow {
    let row = adw::ExpanderRow::builder()
        .title(node.display_name())
        .subtitle(&format!(
            "{} · {}{}",
            node.primary_ip().unwrap_or("No address"),
            node.os,
            if node.is_self { " · This device" } else { "" }
        ))
        .title_lines(1)
        .subtitle_lines(1)
        .build();
    row.add_suffix(&design::status_pill(
        if node.online {
            Status::Connected
        } else {
            Status::Disconnected
        },
        if node.online { "Online" } else { "Offline" },
    ));
    if !node.dns_name.is_empty() {
        row.add_row(&copy_row("MagicDNS", &node.dns_name));
    }
    for ip in &node.tailscale_ips {
        row.add_row(&copy_row(
            if ip.contains(':') { "IPv6" } else { "IPv4" },
            ip,
        ));
    }
    let traffic = adw::ActionRow::builder()
        .title("Traffic since Tailscale started")
        .subtitle(format!(
            "Received {} · Sent {}",
            gtk4::glib::format_size(node.rx_bytes),
            gtk4::glib::format_size(node.tx_bytes)
        ))
        .build();
    row.add_row(&traffic);
    if !node.last_seen.is_empty() {
        row.add_row(
            &adw::ActionRow::builder()
                .title("Last seen")
                .subtitle(&node.last_seen)
                .build(),
        );
    }
    if !node.current_address.is_empty() {
        row.add_row(&copy_row("Reported direct endpoint", &node.current_address));
    }
    if !node.relay.is_empty() {
        row.add_row(
            &adw::ActionRow::builder()
                .title("Reported DERP region")
                .subtitle(&node.relay)
                .build(),
        );
    }
    if !node.is_self {
        let actions = gtk4::FlowBox::builder()
            .selection_mode(gtk4::SelectionMode::None)
            .min_children_per_line(1)
            .max_children_per_line(3)
            .column_spacing(8)
            .row_spacing(8)
            .margin_start(12)
            .margin_end(12)
            .margin_top(8)
            .margin_bottom(8)
            .build();
        let ping = button("Ping / connection path");
        let id = node.id.clone();
        let window = view.window.clone();
        let rt = view.rt.clone();
        ping.connect_clicked(move |button| {
            button.set_sensitive(false);
            let button = button.clone();
            let id = id.clone();
            let window = window.clone();
            let task = rt.spawn(async move { crate::dbus_client::dbus_tailscale_ping(&id).await });
            gtk4::glib::spawn_future_local(async move {
                let message = match task.await {
                    Ok(Ok(text)) => text,
                    Ok(Err(e)) => format!("{e:#}"),
                    Err(e) => e.to_string(),
                };
                button.set_sensitive(true);
                let dialog = adw::AlertDialog::new(Some("Tailscale ping"), Some(&message));
                dialog.add_response("close", "Close");
                dialog.present(Some(&window));
            });
        });
        actions.append(&ping);
        if let Some(ip) = node.primary_ip() {
            let ssh = button("Add SSH host…");
            let name = node.display_name().to_owned();
            let ip = ip.to_owned();
            let state = Arc::clone(&view.app_state);
            let window = view.window.clone();
            let rt = view.rt.clone();
            let tx = view.tx.clone();
            ssh.connect_clicked(move |_| {
                let keys = state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .ssh_keys
                    .clone();
                super::super::ssh::dialogs::show_add_host_dialog_prefilled(
                    &window, &keys, &rt, &tx, &name, &ip, 22,
                );
            });
            actions.append(&ssh);
        }
        row.add_row(&actions);
    }
    row
}

fn copy_row(title: &str, value: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(value)
        .subtitle_selectable(true)
        .subtitle_lines(2)
        .build();
    let copy = gtk4::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text(format!("Copy {title}"))
        .valign(gtk4::Align::Center)
        .css_classes(["flat"])
        .build();
    let value = value.to_owned();
    copy.connect_clicked(move |_| {
        if let Some(display) = gtk4::gdk::Display::default() {
            display.clipboard().set_text(&value);
        }
    });
    row.add_suffix(&copy);
    row
}
