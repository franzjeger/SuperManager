use super::*;

pub(super) fn show(window: &adw::ApplicationWindow, rt: &tokio::runtime::Handle, profile: &str) {
    let dialog = adw::Dialog::builder()
        .title("Tailscale DNS diagnostics")
        .content_width(660)
        .content_height(640)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let body = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(16)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    let status = gtk4::Label::builder()
        .label("Checking this device's MagicDNS name using Tailscale and the system resolver…")
        .wrap(true)
        .xalign(0.0)
        .build();
    body.append(&status);
    let spinner = gtk4::Spinner::builder().spinning(true).build();
    body.append(&spinner);
    let list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    body.append(&list);
    let details = gtk4::TextView::builder()
        .editable(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::WordChar)
        .left_margin(12)
        .right_margin(12)
        .top_margin(12)
        .bottom_margin(12)
        .build();
    let expander = gtk4::Expander::builder()
        .label("Resolver details")
        .child(&details)
        .build();
    expander.set_visible(false);
    body.append(&expander);
    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .child(&body)
        .build();
    toolbar.set_content(Some(&scroll));
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(window));
    let profile = profile.to_owned();
    let task =
        rt.spawn(async move { crate::dbus_client::dbus_tailscale_dns_diagnostics(&profile).await });
    gtk4::glib::spawn_future_local(async move {
        let outcome = task.await;
        spinner.stop();
        spinner.set_visible(false);
        match outcome {
            Ok(Ok(report)) => render(&status, &list, &details, &expander, &report),
            Ok(Err(e)) => status.set_label(&format!("Diagnostics failed: {e}")),
            Err(e) => status.set_label(&format!("Diagnostics task stopped: {e}")),
        }
    });
}

fn render(
    status: &gtk4::Label,
    list: &gtk4::ListBox,
    details: &gtk4::TextView,
    expander: &gtk4::Expander,
    report: &supermgr_core::tailscale::TailscaleDnsReport,
) {
    status.set_label(&format!(
        "Checked {}. No network settings were changed.",
        report.checked_at
    ));
    for check in &report.checks {
        let row = adw::ActionRow::builder()
            .title(&check.name)
            .subtitle(&check.detail)
            .subtitle_lines(5)
            .build();
        row.add_prefix(&design::status_pill(
            match check.status.as_str() {
                "pass" => Status::Connected,
                "fail" => Status::Error,
                "warning" => Status::Degraded,
                _ => Status::Unknown,
            },
            &check.status,
        ));
        list.append(&row);
    }
    details.buffer().set_text(&report.details);
    expander.set_visible(true);
}
