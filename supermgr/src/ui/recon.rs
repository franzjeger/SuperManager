//! Explicit, bounded private-network reconnaissance page.

use std::cell::RefCell;
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
    previous: RefCell<Option<ReconScanResult>>,
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
    let (page, body) = design::workspace_body(
        "Recon",
        "Find services, match inventory and compare changes on your private network.",
    );
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
    let view = Rc::new(ReconView {
        widget: page.upcast(),
        body,
        previous: RefCell::new(None),
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
        let responding = result
            .hosts
            .iter()
            .filter(|h| !h.open_ports.is_empty())
            .count();
        let managed = result
            .hosts
            .iter()
            .filter(|h| h.managed_host_id.is_some())
            .count();
        let services = result
            .hosts
            .iter()
            .map(|h| h.open_ports.len())
            .sum::<usize>();
        let summary = adw::PreferencesGroup::builder().title("Discovered services")
            .description(format!("{responding} responding · {managed} matched to inventory · {services} open ports · {elapsed} ms\n{} · {}", result.target, result.finished_at.format("%Y-%m-%d %H:%M UTC")))
            .build();
        if let Some(previous) = self.previous.borrow().as_ref() {
            if let Some((added, missing)) = supermgr_core::recon::service_changes(previous, result)
            {
                let changes = gtk4::Label::builder().label(format!("Since the previous scan: {added} newly responding services · {missing} no longer responding"))
                    .xalign(0.0).wrap(true).css_classes(["supermgr-notice"]).build();
                self.body.append(&changes);
            }
        }
        *self.previous.borrow_mut() = Some(result.clone());
        let export = gtk4::Button::with_label("Export JSON");
        export.set_valign(gtk4::Align::Center);
        let data = serde_json::to_value(result).unwrap_or_default();
        let window = self.window.clone();
        let tx = self.tx.clone();
        export.connect_clicked(move |_| {
            design::export_json(Some(window.upcast_ref()), "recon-scan.json", &data, &tx)
        });
        summary.set_header_suffix(Some(&export));
        for warning in &result.warnings {
            self.body.append(
                &gtk4::Label::builder()
                    .label(warning)
                    .xalign(0.0)
                    .wrap(true)
                    .css_classes(["warning"])
                    .build(),
            );
        }
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
                    "{} · TCP {}",
                    host.ip,
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
            row.set_subtitle_lines(2);
            if !host.services.is_empty() {
                let hints = host
                    .services
                    .iter()
                    .map(|s| match &s.banner {
                        Some(banner) => format!("{}: {banner} (observed)", s.port),
                        None => format!("{}: {} (port-based hint)", s.port, s.name),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                row.set_tooltip_text(Some(&hints));
                let services = host
                    .services
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" · ");
                row.add_suffix(&design::badge(&services));
            }
            if host.managed_host_id.is_some() {
                row.add_suffix(&design::badge("Managed"));
            } else {
                let add = gtk4::Button::builder()
                    .label("Add host")
                    .valign(gtk4::Align::Center)
                    .build();
                let ip = host.ip.clone();
                // An HTTP port is not an SSH connection port.
                let port = 22;
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
