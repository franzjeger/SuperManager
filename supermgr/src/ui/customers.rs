//! Customer/site catalog and asset assignment page.

use std::{cell::RefCell, rc::Rc, sync::mpsc};

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use supermgr_core::{
    customer::{slugify, Customer, Site},
    host::HostSummary,
    vpn::profile::ProfileSummary,
};

use crate::{
    app::AppMsg,
    dbus_client::{
        dbus_customer_assign_host, dbus_customer_assign_profile, dbus_customer_data,
        dbus_customer_delete, dbus_customer_save, dbus_export_customer_docs,
    },
};

use super::design;

/// Handles needed to repaint the catalog after daemon writes.
pub struct CustomerView {
    /// Top-level page widget.
    pub widget: gtk4::Widget,
    body: gtk4::Box,
    window: adw::ApplicationWindow,
    rt: tokio::runtime::Handle,
    tx: mpsc::Sender<AppMsg>,
}

#[derive(Clone)]
struct SiteEditor {
    original: Site,
    id: adw::EntryRow,
    name: adw::EntryRow,
    address: adw::EntryRow,
    lan: adw::EntryRow,
}

/// Build the customer workspace. Data is supplied later by [`CustomerView::render`].
#[must_use]
pub fn build_customer_page(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
) -> Rc<CustomerView> {
    let page = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();

    let header = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_top(18)
        .margin_bottom(12)
        .margin_start(24)
        .margin_end(24)
        .build();
    let title_box = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
    title_box.set_hexpand(true);
    let title = gtk4::Label::builder()
        .label("Customers & Sites")
        .xalign(0.0)
        .css_classes(["title-1"])
        .build();
    let subtitle = gtk4::Label::builder()
        .label("One source of truth for sites, managed devices and VPN connections")
        .xalign(0.0)
        .wrap(true)
        .css_classes(["dim-label"])
        .build();
    title_box.append(&title);
    title_box.append(&subtitle);
    header.append(&title_box);

    let refresh = gtk4::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Refresh customers and assignments")
        .build();
    header.append(&refresh);
    let add = gtk4::Button::builder()
        .label("Add customer")
        .icon_name("list-add-symbolic")
        .css_classes(["suggested-action"])
        .build();
    header.append(&add);
    page.append(&header);

    let body = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(18)
        .margin_bottom(32)
        .margin_start(24)
        .margin_end(24)
        .build();
    body.append(&design::empty_state(
        "view-refresh-symbolic",
        "Loading customer catalog",
        "Reading customers, sites and asset assignments from the daemon.",
    ));
    let scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&body)
        .build();
    page.append(&scroll);

    let view = Rc::new(CustomerView {
        widget: page.upcast(),
        body,
        window: window.clone(),
        rt: rt.clone(),
        tx: tx.clone(),
    });

    {
        let view = Rc::clone(&view);
        refresh.connect_clicked(move |_| view.refresh(None));
    }
    {
        let view = Rc::clone(&view);
        add.connect_clicked(move |_| view.show_editor(None));
    }
    view
}

impl CustomerView {
    /// Fetch a fresh coherent customer/asset snapshot.
    pub fn refresh(&self, toast: Option<String>) {
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            let result = dbus_customer_data().await.map_err(|e| e.to_string());
            tx.send(AppMsg::CustomerDataRefreshed { result, toast })
                .ok();
        });
    }

    /// Render a daemon snapshot and install assignment actions.
    pub fn render(
        &self,
        customers: &[Customer],
        hosts: &[HostSummary],
        profiles: &[ProfileSummary],
    ) {
        clear_box(&self.body);

        let catalog = adw::PreferencesGroup::builder().css_classes(["supermgr-card"])
            .title("Customer catalog")
            .description("Stable customer and site records used by every operational view")
            .build();
        if customers.is_empty() {
            let row = adw::ActionRow::builder()
                .title("No customers yet")
                .subtitle("Add the first customer, then assign hosts and VPN profiles below.")
                .build();
            catalog.add(&row);
        } else {
            for customer in customers {
                let site_count = customer.sites.len();
                let host_count = hosts.iter().filter(|h| h.customer == customer.slug).count();
                let vpn_count = profiles
                    .iter()
                    .filter(|p| p.customer == customer.slug)
                    .count();
                let subtitle = format!(
                    "{site_count} site{} · {host_count} device{} · {vpn_count} VPN profile{}",
                    plural(site_count),
                    plural(host_count),
                    plural(vpn_count)
                );
                let row = adw::ExpanderRow::builder()
                    .title(&customer.display_name)
                    .subtitle(&subtitle)
                    .build();

                let docs = gtk4::Button::builder()
                    .icon_name("edit-copy-symbolic")
                    .tooltip_text("Copy customer documentation as Markdown")
                    .valign(gtk4::Align::Center)
                    .css_classes(["flat"])
                    .build();
                {
                    let slug = customer.slug.clone();
                    let tx = self.tx.clone();
                    let rt = self.rt.clone();
                    docs.connect_clicked(move |_| {
                        let slug = slug.clone();
                        let tx = tx.clone();
                        rt.spawn(async move {
                            match dbus_export_customer_docs(&slug).await {
                                Ok(markdown) => {
                                    tx.send(AppMsg::CopyToClipboard(markdown)).ok();
                                    tx.send(AppMsg::ShowToast(
                                        "Customer documentation copied".into(),
                                    ))
                                    .ok();
                                }
                                Err(e) => {
                                    tx.send(AppMsg::OperationFailed(format!(
                                        "Documentation export failed: {e}"
                                    )))
                                    .ok();
                                }
                            }
                        });
                    });
                }
                row.add_suffix(&docs);

                let edit = gtk4::Button::builder()
                    .icon_name("document-edit-symbolic")
                    .tooltip_text("Edit customer and sites")
                    .valign(gtk4::Align::Center)
                    .css_classes(["flat"])
                    .build();
                {
                    let view = self.clone_handles();
                    let customer = customer.clone();
                    edit.connect_clicked(move |_| view.show_editor(Some(customer.clone())));
                }
                row.add_suffix(&edit);

                if !customer.contact_name.is_empty()
                    || !customer.contact_email.is_empty()
                    || !customer.primary_domain.is_empty()
                {
                    let details = adw::ActionRow::builder()
                        .title("Contact and domain")
                        .subtitle(
                            [
                                customer.contact_name.as_str(),
                                customer.contact_email.as_str(),
                                customer.primary_domain.as_str(),
                            ]
                            .into_iter()
                            .filter(|v| !v.is_empty())
                            .collect::<Vec<_>>()
                            .join(" · "),
                        )
                        .build();
                    row.add_row(&details);
                }
                for site in &customer.sites {
                    let linked = site.host_ids.len();
                    let subtitle = [site.address.as_str(), site.lan_base.as_str()]
                        .into_iter()
                        .filter(|v| !v.is_empty())
                        .collect::<Vec<_>>()
                        .join(" · ");
                    let site_row = adw::ActionRow::builder()
                        .title(&site.display_name)
                        .subtitle(if subtitle.is_empty() {
                            format!("{linked} linked device{}", plural(linked))
                        } else {
                            format!("{subtitle} · {linked} linked device{}", plural(linked))
                        })
                        .build();
                    site_row.add_prefix(&design::icon(&[
                        "mark-location-symbolic",
                        "folder-symbolic",
                    ]));
                    row.add_row(&site_row);
                }
                catalog.add(&row);
            }
        }
        self.body.append(&catalog);

        self.body.append(&self.host_assignments(customers, hosts));
        self.body
            .append(&self.profile_assignments(customers, profiles));
    }

    /// Render a persistent page-level load error.
    pub fn render_error(&self, message: &str) {
        clear_box(&self.body);
        self.body.append(&design::empty_state(
            "dialog-error-symbolic",
            "Customer catalog unavailable",
            message,
        ));
    }

    fn host_assignments(
        &self,
        customers: &[Customer],
        hosts: &[HostSummary],
    ) -> adw::PreferencesGroup {
        let group = adw::PreferencesGroup::builder().css_classes(["supermgr-card"])
            .title("Device assignments")
            .description("A device can belong to exactly one customer and one site")
            .build();
        if hosts.is_empty() {
            group.add(
                &adw::ActionRow::builder()
                    .title("No SSH hosts available")
                    .build(),
            );
            return group;
        }

        let mut choices = vec![(String::new(), String::new(), "Unassigned".to_owned())];
        for customer in customers {
            choices.push((
                customer.slug.clone(),
                String::new(),
                format!("{} · no site", customer.display_name),
            ));
            for site in &customer.sites {
                choices.push((
                    customer.slug.clone(),
                    site.id.clone(),
                    format!("{} — {}", customer.display_name, site.display_name),
                ));
            }
        }
        let labels: Vec<&str> = choices.iter().map(|(_, _, label)| label.as_str()).collect();

        for host in hosts {
            let row = adw::ActionRow::builder()
                .title(&host.label)
                .subtitle(format!("{} · {}", host.hostname, host.device_type))
                .build();
            let model = gtk4::StringList::new(&labels);
            let dropdown = gtk4::DropDown::builder()
                .model(&model)
                .valign(gtk4::Align::Center)
                .width_request(230)
                .build();
            let current = choices
                .iter()
                .position(|(customer, site, _)| {
                    if customer != &host.customer {
                        return false;
                    }
                    if customer.is_empty() {
                        return true;
                    }
                    if site.is_empty() {
                        return !customers.iter().any(|c| {
                            c.slug == *customer
                                && c.sites
                                    .iter()
                                    .any(|s| s.host_ids.iter().any(|id| id == &host.id.to_string()))
                        });
                    }
                    customers.iter().any(|c| {
                        c.slug == *customer
                            && c.sites.iter().any(|s| {
                                s.id == *site
                                    && s.host_ids.iter().any(|id| id == &host.id.to_string())
                            })
                    })
                })
                .unwrap_or(0);
            dropdown.set_selected(current as u32);
            {
                let choices = choices.clone();
                let host_id = host.id.to_string();
                let tx = self.tx.clone();
                let rt = self.rt.clone();
                dropdown.connect_selected_notify(move |dropdown| {
                    let Some((customer, site, _)) = choices.get(dropdown.selected() as usize)
                    else {
                        return;
                    };
                    let customer = customer.clone();
                    let site = site.clone();
                    let host_id = host_id.clone();
                    let tx = tx.clone();
                    rt.spawn(async move {
                        let result = async {
                            dbus_customer_assign_host(&customer, &site, &host_id).await?;
                            dbus_customer_data().await
                        }
                        .await
                        .map_err(|e| e.to_string());
                        tx.send(AppMsg::CustomerDataRefreshed {
                            result,
                            toast: Some("Device assignment saved".into()),
                        })
                        .ok();
                    });
                });
            }
            row.add_suffix(&dropdown);
            group.add(&row);
        }
        group
    }

    fn profile_assignments(
        &self,
        customers: &[Customer],
        profiles: &[ProfileSummary],
    ) -> adw::PreferencesGroup {
        let group = adw::PreferencesGroup::builder().css_classes(["supermgr-card"])
            .title("VPN assignments")
            .description("Customer ownership shared by VPN, Fleet, Compliance and Security")
            .build();
        if profiles.is_empty() {
            group.add(
                &adw::ActionRow::builder()
                    .title("No VPN profiles available")
                    .build(),
            );
            return group;
        }
        let choices: Vec<(String, String)> = std::iter::once((String::new(), "Unassigned".into()))
            .chain(
                customers
                    .iter()
                    .map(|c| (c.slug.clone(), c.display_name.clone())),
            )
            .collect();
        let labels: Vec<&str> = choices.iter().map(|(_, label)| label.as_str()).collect();

        for profile in profiles {
            let row = adw::ActionRow::builder()
                .title(&profile.name)
                .subtitle(&profile.backend)
                .build();
            let model = gtk4::StringList::new(&labels);
            let dropdown = gtk4::DropDown::builder()
                .model(&model)
                .valign(gtk4::Align::Center)
                .width_request(230)
                .build();
            let current = choices
                .iter()
                .position(|(slug, _)| slug == &profile.customer)
                .unwrap_or(0);
            dropdown.set_selected(current as u32);
            {
                let choices = choices.clone();
                let profile_id = profile.id.to_string();
                let tx = self.tx.clone();
                let rt = self.rt.clone();
                dropdown.connect_selected_notify(move |dropdown| {
                    let Some((customer, _)) = choices.get(dropdown.selected() as usize) else {
                        return;
                    };
                    let customer = customer.clone();
                    let profile_id = profile_id.clone();
                    let tx = tx.clone();
                    rt.spawn(async move {
                        let result = async {
                            dbus_customer_assign_profile(&customer, &profile_id).await?;
                            dbus_customer_data().await
                        }
                        .await
                        .map_err(|e| e.to_string());
                        tx.send(AppMsg::CustomerDataRefreshed {
                            result,
                            toast: Some("VPN assignment saved".into()),
                        })
                        .ok();
                    });
                });
            }
            row.add_suffix(&dropdown);
            group.add(&row);
        }
        group
    }

    fn show_editor(&self, existing: Option<Customer>) {
        let editing = existing.is_some();
        let customer = existing.unwrap_or_default();
        let dialog = adw::Dialog::builder()
            .title(if editing {
                "Edit customer"
            } else {
                "Add customer"
            })
            .content_width(620)
            .content_height(720)
            .build();
        let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        content.append(&adw::HeaderBar::new());

        let form = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(18)
            .margin_top(18)
            .margin_bottom(18)
            .margin_start(18)
            .margin_end(18)
            .build();
        let identity = adw::PreferencesGroup::builder().css_classes(["supermgr-card"]).title("Customer").build();
        let name = adw::EntryRow::builder()
            .title("Display name")
            .text(&customer.display_name)
            .build();
        let slug = adw::EntryRow::builder()
            .title("Stable ID")
            .text(&customer.slug)
            .build();
        slug.set_editable(!editing);
        let contact = adw::EntryRow::builder()
            .title("Contact name")
            .text(&customer.contact_name)
            .build();
        let email = adw::EntryRow::builder()
            .title("Contact email")
            .text(&customer.contact_email)
            .build();
        let domain = adw::EntryRow::builder()
            .title("Primary domain")
            .text(&customer.primary_domain)
            .build();
        let notes = adw::EntryRow::builder()
            .title("Operational notes")
            .text(&customer.notes)
            .build();
        for row in [&name, &slug, &contact, &email, &domain, &notes] {
            identity.add(row);
        }
        form.append(&identity);

        let sites_group = adw::PreferencesGroup::builder().css_classes(["supermgr-card"])
            .title("Sites")
            .description("Site IDs remain stable when a site is renamed")
            .build();
        let editors: Rc<RefCell<Vec<SiteEditor>>> = Rc::new(RefCell::new(Vec::new()));
        for site in customer.sites.clone() {
            add_site_editor(&sites_group, &editors, site, editing);
        }
        let add_site = gtk4::Button::builder()
            .label("Add site")
            .icon_name("list-add-symbolic")
            .halign(gtk4::Align::Start)
            .build();
        {
            let sites_group = sites_group.clone();
            let editors = Rc::clone(&editors);
            add_site.connect_clicked(move |_| {
                add_site_editor(&sites_group, &editors, Site::default(), false)
            });
        }
        form.append(&sites_group);
        form.append(&add_site);

        let buttons = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .halign(gtk4::Align::End)
            .build();
        if editing {
            let delete = gtk4::Button::builder()
                .label("Delete customer")
                .css_classes(["destructive-action"])
                .build();
            {
                let slug = customer.slug.clone();
                let dialog = dialog.clone();
                let tx = self.tx.clone();
                let rt = self.rt.clone();
                delete.connect_clicked(move |_| {
                    let confirm = adw::AlertDialog::builder()
                        .heading("Delete this customer?")
                        .body("The daemon will refuse deletion while any device or VPN profile is still assigned.")
                        .close_response("cancel")
                        .build();
                    confirm.add_response("cancel", "Cancel");
                    confirm.add_response("delete", "Delete");
                    confirm.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
                    let slug = slug.clone();
                    let tx = tx.clone();
                    let rt = rt.clone();
                    let editor = dialog.clone();
                    confirm.connect_response(None, move |_, response| {
                        if response != "delete" {
                            return;
                        }
                        editor.close();
                        let slug = slug.clone();
                        let tx = tx.clone();
                        rt.spawn(async move {
                            let result = async {
                                dbus_customer_delete(&slug).await?;
                                dbus_customer_data().await
                            }
                            .await
                            .map_err(|e| e.to_string());
                            tx.send(AppMsg::CustomerDataRefreshed {
                                result,
                                toast: Some("Customer deleted".into()),
                            })
                            .ok();
                        });
                    });
                    confirm.present(Some(&dialog));
                });
            }
            buttons.append(&delete);
        }
        let cancel = gtk4::Button::builder().label("Cancel").build();
        {
            let dialog = dialog.clone();
            cancel.connect_clicked(move |_| {
                dialog.close();
            });
        }
        buttons.append(&cancel);
        let save = gtk4::Button::builder()
            .label("Save")
            .css_classes(["suggested-action"])
            .build();
        {
            let dialog = dialog.clone();
            let tx = self.tx.clone();
            let rt = self.rt.clone();
            let editors = Rc::clone(&editors);
            save.connect_clicked(move |_| {
                let display_name = name.text().trim().to_owned();
                if display_name.is_empty() {
                    tx.send(AppMsg::OperationFailed("Customer name is required".into()))
                        .ok();
                    return;
                }
                let mut value = customer.clone();
                value.display_name = display_name;
                value.slug = if slug.text().trim().is_empty() {
                    slugify(&value.display_name)
                } else {
                    slug.text().trim().to_owned()
                };
                value.contact_name = contact.text().trim().to_owned();
                value.contact_email = email.text().trim().to_owned();
                value.primary_domain = domain.text().trim().to_owned();
                value.notes = notes.text().trim().to_owned();
                value.sites = editors
                    .borrow()
                    .iter()
                    .map(|editor| {
                        let mut site = editor.original.clone();
                        site.display_name = editor.name.text().trim().to_owned();
                        site.id = if editor.id.text().trim().is_empty() {
                            slugify(&site.display_name)
                        } else {
                            editor.id.text().trim().to_owned()
                        };
                        site.address = editor.address.text().trim().to_owned();
                        site.lan_base = editor.lan.text().trim().to_owned();
                        site
                    })
                    .collect();
                if let Err(error) = value.validate() {
                    tx.send(AppMsg::OperationFailed(error)).ok();
                    return;
                }
                dialog.close();
                let tx = tx.clone();
                rt.spawn(async move {
                    let result = async {
                        dbus_customer_save(&value).await?;
                        dbus_customer_data().await
                    }
                    .await
                    .map_err(|e| e.to_string());
                    tx.send(AppMsg::CustomerDataRefreshed {
                        result,
                        toast: Some("Customer saved".into()),
                    })
                    .ok();
                });
            });
        }
        buttons.append(&save);
        form.append(&buttons);

        let scroll = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .vexpand(true)
            .child(&form)
            .build();
        content.append(&scroll);
        dialog.set_child(Some(&content));
        dialog.present(Some(&self.window));
    }

    fn clone_handles(&self) -> Self {
        Self {
            widget: self.widget.clone(),
            body: self.body.clone(),
            window: self.window.clone(),
            rt: self.rt.clone(),
            tx: self.tx.clone(),
        }
    }
}

fn add_site_editor(
    group: &adw::PreferencesGroup,
    editors: &Rc<RefCell<Vec<SiteEditor>>>,
    site: Site,
    lock_id: bool,
) {
    let row = adw::ExpanderRow::builder()
        .title(if site.display_name.is_empty() {
            "New site"
        } else {
            &site.display_name
        })
        .expanded(true)
        .build();
    let id = adw::EntryRow::builder()
        .title("Stable site ID")
        .text(&site.id)
        .build();
    id.set_editable(!lock_id);
    let name = adw::EntryRow::builder()
        .title("Site name")
        .text(&site.display_name)
        .build();
    let address = adw::EntryRow::builder()
        .title("Address / location")
        .text(&site.address)
        .build();
    let lan = adw::EntryRow::builder()
        .title("LAN subnet")
        .text(&site.lan_base)
        .build();
    row.add_row(&id);
    row.add_row(&name);
    row.add_row(&address);
    row.add_row(&lan);
    group.add(&row);
    editors.borrow_mut().push(SiteEditor {
        original: site,
        id,
        name,
        address,
        lan,
    });
}

fn clear_box(container: &gtk4::Box) {
    while let Some(child) = container.first_child() {
        container.remove(&child);
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}
