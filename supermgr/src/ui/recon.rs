//! Explicit, bounded private-network reconnaissance page.

use std::{
    rc::Rc,
    sync::{mpsc, Arc, Mutex},
};

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use supermgr_core::recon::ReconScanResult;

use crate::{
    app::{AppMsg, AppState},
    dbus_client::dbus_recon_scan,
};

use super::design;

/// Stateful handles for scan progress and results.
pub struct ReconView {
    /// Top-level page.
    pub widget: gtk4::Widget,
    body: gtk4::Box,
    scan_button: gtk4::Button,
    target: adw::EntryRow,
    ports: adw::EntryRow,
    app_state: Arc<Mutex<AppState>>,
    window: adw::ApplicationWindow,
    rt: tokio::runtime::Handle,
    tx: mpsc::Sender<AppMsg>,
}

#[must_use]
pub fn build_recon_page(
    app_state: &Arc<Mutex<AppState>>,
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) -> Rc<ReconView> {
    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
    let header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(2)
        .margin_top(18)
        .margin_bottom(12)
        .margin_start(24)
        .margin_end(24)
        .build();
    header.append(
        &gtk4::Label::builder()
            .label("Recon")
            .xalign(0.0)
            .css_classes(["title-1"])
            .build(),
    );
    header.append(
        &gtk4::Label::builder()
            .label("Discover unmanaged services on an explicitly selected private IPv4 range")
            .xalign(0.0)
            .wrap(true)
            .css_classes(["dim-label"])
            .build(),
    );
    page.append(&header);

    let body = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(18)
        .margin_start(24)
        .margin_end(24)
        .margin_bottom(32)
        .build();
    let scope = adw::PreferencesGroup::builder()
        .title("Scan scope")
        .description("Only private/link-local IPv4 ranges of /24 or smaller are accepted")
        .build();
    let target = adw::EntryRow::builder()
        .title("Target CIDR")
        .text("192.168.1.0/24")
        .build();
    let ports = adw::EntryRow::builder()
        .title("TCP ports")
        .text("22, 80, 443, 445, 3389, 5900, 8080, 8443")
        .build();
    scope.add(&target);
    scope.add(&ports);
    let scan_button = gtk4::Button::builder()
        .label("Start scan")
        .icon_name(design::icon_name(design::icons::SEARCH))
        .halign(gtk4::Align::Start)
        .css_classes(["suggested-action"])
        .build();
    body.append(&scope);
    body.append(&scan_button);
    body.append(&design::empty_state(
        design::icon_name(design::icons::SEARCH),
        "No scan run yet",
        "Choose a private subnet and start a bounded TCP discovery scan.",
    ));
    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&body)
        .build();
    page.append(&scroll);

    let view = Rc::new(ReconView {
        widget: page.upcast(),
        body,
        scan_button,
        target,
        ports,
        app_state: Arc::clone(app_state),
        window: window.clone(),
        rt: rt.clone(),
        tx: tx.clone(),
    });
    {
        let view = Rc::clone(&view);
        let button = view.scan_button.clone();
        button.connect_clicked(move |_| view.start_scan());
    }
    view
}

impl ReconView {
    fn start_scan(&self) {
        let ports = match parse_ports(&self.ports.text()) {
            Ok(ports) => ports,
            Err(error) => {
                self.tx.send(AppMsg::OperationFailed(error)).ok();
                return;
            }
        };
        self.scan_button.set_sensitive(false);
        self.scan_button.set_label("Scanning…");
        let target = self.target.text().trim().to_owned();
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let result = dbus_recon_scan(&target, &ports)
                .await
                .map_err(|e| e.to_string());
            tx.send(AppMsg::ReconScanFinished(result)).ok();
        });
    }

    pub fn show_result(&self, result: &ReconScanResult) {
        self.scan_button.set_sensitive(true);
        self.scan_button.set_label("Scan again");
        // Keep scope form + button; replace only everything following them.
        while self.body.last_child().is_some_and(|child| {
            child != self.scan_button && child != self.body.first_child().unwrap()
        }) {
            let child = self.body.last_child().unwrap();
            self.body.remove(&child);
        }

        let elapsed = (result.finished_at - result.started_at)
            .num_milliseconds()
            .max(0);
        let summary = adw::PreferencesGroup::builder()
            .title("Results")
            .description(format!(
                "{} responding host{} in {} ms · {}",
                result.hosts.len(),
                if result.hosts.len() == 1 { "" } else { "s" },
                elapsed,
                result.target
            ))
            .build();
        if result.hosts.is_empty() {
            summary.add(
                &adw::ActionRow::builder()
                    .title("No responding services")
                    .subtitle("No selected TCP port accepted a connection in this range.")
                    .build(),
            );
        }
        for host in &result.hosts {
            let ports = if host.open_ports.is_empty() {
                "Known inventory host; no selected port answered".to_owned()
            } else {
                format!(
                    "Open TCP: {}",
                    host.open_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let row = adw::ActionRow::builder()
                .title(host.managed_label.as_deref().unwrap_or(&host.ip))
                .subtitle(if let Some(customer) = &host.customer {
                    format!("{} · {ports}", customer)
                } else {
                    ports
                })
                .build();
            if host.managed_host_id.is_some() {
                row.add_suffix(&design::badge("Managed"));
            } else {
                let add = gtk4::Button::builder()
                    .label("Add host")
                    .valign(gtk4::Align::Center)
                    .build();
                let ip = host.ip.clone();
                let port = if host.open_ports.contains(&22) {
                    22
                } else {
                    host.open_ports.first().copied().unwrap_or(22)
                };
                let app_state = Arc::clone(&self.app_state);
                let window = self.window.clone();
                let rt = self.rt.clone();
                let tx = self.tx.clone();
                add.connect_clicked(move |_| {
                    let keys = app_state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .ssh_keys
                        .clone();
                    super::ssh::dialogs::show_add_host_dialog_prefilled(
                        &window, &keys, &rt, &tx, &ip, &ip, port,
                    );
                });
                row.add_suffix(&add);
            }
            summary.add(&row);
        }
        self.body.append(&summary);
    }

    pub fn show_error(&self, message: &str) {
        self.scan_button.set_sensitive(true);
        self.scan_button.set_label("Start scan");
        self.tx
            .send(AppMsg::OperationFailed(format!(
                "Recon scan failed: {message}"
            )))
            .ok();
    }
}

fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    let mut ports = text
        .split([',', ' ', ';'])
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            part.trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid TCP port: {part}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() || ports.len() > 32 || ports.contains(&0) {
        return Err("Enter between 1 and 32 valid TCP ports".into());
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_parser_deduplicates_and_sorts() {
        assert_eq!(parse_ports("443, 22 443").unwrap(), vec![22, 443]);
    }
}
