use super::*;
use std::cell::Cell;
use std::time::Duration;

pub(super) fn show(
    window: &adw::ApplicationWindow,
    rt: &tokio::runtime::Handle,
    tx: &mpsc::Sender<AppMsg>,
    profile: &str,
) {
    let dialog = adw::Dialog::builder()
        .title("Add Tailscale account")
        .content_width(510)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let body = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(18)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    let icon = design::icon(design::icons::MESH);
    icon.set_pixel_size(40);
    body.append(&icon);
    let message = gtk4::Label::builder().label("Sign in to another account in your browser. Tailscale temporarily leaves the current account during sign-in. Cancel or timeout restores the previous saved account when no newer account has been selected.")
        .wrap(true).xalign(0.0).build();
    body.append(&message);
    let spinner = gtk4::Spinner::new();
    spinner.set_visible(false);
    body.append(&spinner);
    let browser = gtk4::Button::with_label("Open sign-in page");
    browser.set_visible(false);
    body.append(&browser);
    let buttons = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
    buttons.set_halign(gtk4::Align::End);
    let cancel = gtk4::Button::with_label("Cancel");
    let start = gtk4::Button::with_label("Continue to sign in");
    start.add_css_class("suggested-action");
    buttons.append(&cancel);
    buttons.append(&start);
    body.append(&buttons);
    toolbar.set_content(Some(&body));
    dialog.set_child(Some(&toolbar));
    let active = Rc::new(Cell::new(false));
    let cancelling = Rc::new(Cell::new(false));
    let url = Rc::new(RefCell::new(String::new()));
    {
        let dialog = dialog.clone();
        let active = Rc::clone(&active);
        let cancelling = Rc::clone(&cancelling);
        cancel.connect_clicked(move |button| {
            if active.get() {
                cancelling.set(true);
                button.set_sensitive(false);
                button.set_label("Cancelling…");
            } else {
                dialog.close();
            }
        });
    }
    {
        let url = Rc::clone(&url);
        let window = window.clone();
        browser.connect_clicked(move |_| {
            let link = url.borrow().clone();
            if !link.is_empty() {
                gtk4::UriLauncher::new(&link).launch(
                    Some(&window),
                    gtk4::gio::Cancellable::NONE,
                    |_| {},
                );
            }
        });
    }
    let profile = profile.to_owned();
    let rt = rt.clone();
    let tx = tx.clone();
    let dialog_for_start = dialog.clone();
    start.connect_clicked(move |start| {
        start.set_visible(false); active.set(true); cancelling.set(false); dialog_for_start.set_can_close(false);
        spinner.set_visible(true); spinner.start(); message.set_label("Preparing browser sign-in…");
        let profile = profile.clone(); let rt = rt.clone(); let tx = tx.clone(); let dialog = dialog_for_start.clone();
        let active = Rc::clone(&active); let cancelling = Rc::clone(&cancelling); let url = Rc::clone(&url);
        let message = message.clone(); let spinner = spinner.clone(); let cancel = cancel.clone(); let browser = browser.clone();
        gtk4::glib::spawn_future_local(async move {
            let initial = rt.spawn(async move { crate::dbus_client::dbus_tailscale_begin_login(&profile).await }).await;
            let outcome = async {
                let mut attempt = initial.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
                let mut opened = false; let mut cancel_sent = false;
                loop {
                    message.set_label(&attempt.message);
                    *url.borrow_mut() = attempt.auth_url.clone(); browser.set_visible(!attempt.auth_url.is_empty());
                    if !attempt.auth_url.is_empty() && !opened && !cancelling.get() { browser.emit_clicked(); opened = true; }
                    if attempt.state != "waiting" { return Ok::<(), String>(()); }
                    if cancelling.get() && !cancel_sent {
                        let id = attempt.id.clone();
                        rt.spawn(async move { crate::dbus_client::dbus_tailscale_cancel_login(&id).await }).await
                            .map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
                        cancel_sent = true;
                    }
                    gtk4::glib::timeout_future(Duration::from_secs(1)).await;
                    let id = attempt.id.clone();
                    attempt = rt.spawn(async move { crate::dbus_client::dbus_tailscale_login_status(&id).await }).await
                        .map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
                }
            }.await;
            if let Err(error) = outcome { message.set_label(&format!("Sign-in status unavailable: {error}. The daemon cancels unfinished sign-in after three minutes. Refresh Accounts to inspect the result.")); }
            active.set(false); dialog.set_can_close(true); spinner.stop(); spinner.set_visible(false); browser.set_visible(false);
            cancel.set_label("Close"); cancel.set_sensitive(true);
            rt.spawn(async move { refresh(&tx).await; });
        });
    });
    dialog.present(Some(window));
}
