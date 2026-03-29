//! Console panel — GTK4 chat interface for Claude.

use std::sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc, Mutex};

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use supermgr_core::vpn::state::VpnState;

use crate::app::{AppMsg, AppState};

const API_KEY_URL: &str = "https://console.anthropic.com/settings/keys";

/// Widget bundle for the console panel.
#[derive(Clone)]
pub struct ConsolePanel {
    pub chat_view: gtk4::TextView,
    pub chat_buffer: gtk4::TextBuffer,
    pub input_view: gtk4::TextView,
    pub send_btn: gtk4::Button,
    pub stop_btn: gtk4::Button,
    pub clear_btn: gtk4::Button,
    pub spinner: gtk4::Spinner,
    pub api_key_banner: adw::Banner,
    pub setup_stack: gtk4::Stack,
}

/// Build the console page content.
pub fn build_console_page(
    app_state: &Arc<Mutex<AppState>>,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
) -> (ConsolePanel, gtk4::Widget) {
    // =====================================================================
    // Setup page (shown when no API key)
    // =====================================================================
    let setup_page = build_setup_page();

    // =====================================================================
    // Chat page (shown when API key is configured)
    // =====================================================================
    let chat_buffer = gtk4::TextBuffer::new(None::<&gtk4::TextTagTable>);
    init_tags(&chat_buffer);

    let chat_view = gtk4::TextView::builder()
        .buffer(&chat_buffer)
        .editable(false)
        .cursor_visible(false)
        .wrap_mode(gtk4::WrapMode::Word)
        .vexpand(true)
        .hexpand(true)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(16)
        .right_margin(16)
        .build();

    let chat_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vexpand(true)
        .child(&chat_view)
        .build();

    // --- Input area (larger) ---
    let input_view = gtk4::TextView::builder()
        .wrap_mode(gtk4::WrapMode::Word)
        .accepts_tab(false)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(12)
        .right_margin(12)
        .build();

    let input_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .min_content_height(80)
        .max_content_height(200)
        .propagate_natural_height(true)
        .hexpand(true)
        .child(&input_view)
        .build();
    input_scroll.add_css_class("card");

    let send_btn = gtk4::Button::builder()
        .icon_name("go-next-symbolic")
        .tooltip_text("Send (Ctrl+Enter)")
        .css_classes(["suggested-action", "circular"])
        .valign(gtk4::Align::End)
        .build();

    let spinner = gtk4::Spinner::builder()
        .visible(false)
        .valign(gtk4::Align::End)
        .build();

    let stop_btn = gtk4::Button::builder()
        .icon_name("process-stop-symbolic")
        .tooltip_text("Stop current request")
        .css_classes(["destructive-action", "circular"])
        .valign(gtk4::Align::End)
        .visible(false)
        .build();

    let clear_btn = gtk4::Button::builder()
        .icon_name("edit-clear-all-symbolic")
        .tooltip_text("Clear conversation")
        .css_classes(["flat", "circular"])
        .valign(gtk4::Align::End)
        .build();

    let input_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_start(16)
        .margin_end(16)
        .margin_bottom(12)
        .margin_top(4)
        .build();
    input_row.append(&input_scroll);
    input_row.append(&spinner);
    input_row.append(&stop_btn);
    input_row.append(&send_btn);
    input_row.append(&clear_btn);

    let api_key_banner = adw::Banner::builder()
        .title("API key configured")
        .revealed(false)
        .build();

    let chat_page = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .vexpand(true)
        .hexpand(true)
        .build();
    chat_page.append(&api_key_banner);
    chat_page.append(&chat_scroll);
    chat_page.append(&input_row);

    // =====================================================================
    // Stack: setup vs chat
    // =====================================================================
    let setup_stack = gtk4::Stack::new();
    setup_stack.add_named(&setup_page, Some("setup"));
    setup_stack.add_named(&chat_page, Some("chat"));

    // Show correct page based on auth state.
    let use_sub = super::claude::use_subscription();
    let has_key = super::claude::has_api_key();
    if use_sub || has_key {
        setup_stack.set_visible_child_name("chat");
        let mode = if use_sub { "subscription (Claude Code CLI)" } else { "API key" };
        append_system_msg(
            &chat_buffer,
            &format!(
                "Claude Console — connected to SuperManager.\n\
                 Mode: {mode}\n\n\
                 I can manage your SSH connections and VPN profiles.\n\
                 Try: \"list my SSH hosts\" or \"connect to VPN\".\n",
            ),
        );
    } else {
        setup_stack.set_visible_child_name("setup");
    }

    // =====================================================================
    // Wire up send + stop
    // =====================================================================
    let cancel_flag = Arc::new(AtomicBool::new(false));

    // Stop button — kills running claude subprocess and resets UI.
    {
        let cancel_flag = Arc::clone(&cancel_flag);
        let tx = tx.clone();
        stop_btn.connect_clicked(move |_| {
            cancel_flag.store(true, Ordering::Relaxed);
            // Kill any running claude --print subprocess.
            let _ = std::process::Command::new("pkill")
                .args(["-f", "claude --print"])
                .status();
            let _ = tx.send(AppMsg::ConsoleResponse("\n[Stopped]\n".into()));
            let _ = tx.send(AppMsg::ConsoleThinking(false));
        });
    }

    {
        let input_view_for_ctrl = input_view.clone();
        let input_view = input_view.clone();
        let chat_buffer = chat_buffer.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        let app_state = Arc::clone(app_state);
        let cancel_flag = Arc::clone(&cancel_flag);
        let send = move || {
            let buf = input_view.buffer();
            let text = buf
                .text(&buf.start_iter(), &buf.end_iter(), false)
                .to_string();
            if text.trim().is_empty() {
                return;
            }
            buf.set_text("");

            cancel_flag.store(false, Ordering::Relaxed);
            append_tagged(&chat_buffer, &format!("\nYou: {text}\n"), "user");

            let tx = tx.clone();
            let text = text.clone();
            let app_state = Arc::clone(&app_state);
            let (messages, context) = {
                let s = app_state.lock().expect("lock app_state");
                let vpn = match &s.vpn_state {
                    VpnState::Connected { .. } => "VPN: connected",
                    VpnState::Disconnected => "VPN: disconnected",
                    _ => "VPN: transitioning",
                };
                let hosts: Vec<String> = s.ssh_hosts.iter()
                    .map(|h| format!("- {} ({}@{}:{}, {}, id={})", h.label, h.username, h.hostname, h.port, h.device_type, h.id))
                    .collect();
                let keys: Vec<String> = s.ssh_keys.iter()
                    .map(|k| format!("- {} ({:?}, {})", k.name, k.key_type, k.fingerprint))
                    .collect();
                let ctx = format!("{vpn}\n\nSSH Hosts:\n{}\n\nSSH Keys:\n{}", hosts.join("\n"), keys.join("\n"));
                (s.console_messages.clone(), ctx)
            };
            rt.spawn(async move {
                let _ = tx.send(AppMsg::ConsoleThinking(true));

                let use_sub = super::claude::use_subscription();

                if use_sub {
                    // Use Claude Code CLI (subscription — no API tokens).
                    match super::claude::send_message_subscription(&text, &tx, &context).await {
                        Ok(()) => {}
                        Err(e) => {
                            let _ = tx.send(AppMsg::ConsoleResponse(format!("\nError: {e}\n")));
                        }
                    }
                } else {
                    // Use API key (pay-per-token).
                    let api_key = super::claude::load_api_key();
                    let Some(api_key) = api_key else {
                        let _ = tx.send(AppMsg::ConsoleResponse(
                            "\nNo API key configured. Go to Settings to add one, or enable 'Use Claude subscription'.\n".into(),
                        ));
                        let _ = tx.send(AppMsg::ConsoleThinking(false));
                        return;
                    };

                    match super::claude::send_message(&api_key, &text, &tx, messages, &context).await {
                        Ok(updated_messages) => {
                            app_state.lock().expect("lock app_state").console_messages = updated_messages;
                        }
                        Err(e) => {
                            let _ = tx.send(AppMsg::ConsoleResponse(format!("\nError: {e}\n")));
                        }
                    }
                }
                let _ = tx.send(AppMsg::ConsoleThinking(false));
            });
        };

        let send = std::rc::Rc::new(send);
        let send_clone = std::rc::Rc::clone(&send);
        send_btn.connect_clicked(move |_| send_clone());

        // Enter sends, Shift+Enter adds newline.
        let key_ctrl = gtk4::EventControllerKey::builder()
            .propagation_phase(gtk4::PropagationPhase::Capture)
            .build();
        let send_clone2 = std::rc::Rc::clone(&send);
        key_ctrl.connect_key_pressed(move |_, key, _, modifier| {
            if (key == gtk4::gdk::Key::Return || key == gtk4::gdk::Key::KP_Enter)
                && !modifier.contains(gtk4::gdk::ModifierType::SHIFT_MASK)
            {
                send_clone2();
                return gtk4::glib::Propagation::Stop;
            }
            gtk4::glib::Propagation::Proceed
        });
        input_view_for_ctrl.add_controller(key_ctrl);
    }

    // Clear button
    {
        let chat_buffer = chat_buffer.clone();
        let app_state = Arc::clone(app_state);
        clear_btn.connect_clicked(move |_| {
            chat_buffer.set_text("");
            app_state.lock().expect("lock app_state").console_messages.clear();
            super::claude::reset_session();
            append_system_msg(&chat_buffer, "Conversation cleared.\n");
        });
    }

    let panel = ConsolePanel {
        chat_view,
        chat_buffer,
        input_view,
        send_btn,
        stop_btn,
        clear_btn,
        spinner,
        api_key_banner,
        setup_stack: setup_stack.clone(),
    };

    (panel, setup_stack.upcast())
}

// ---------------------------------------------------------------------------
// Setup page — API key entry with "Get API Key" browser button
// ---------------------------------------------------------------------------

fn build_setup_page() -> gtk4::Widget {
    let status = adw::StatusPage::builder()
        .title("Claude Console")
        .description("Connect an Anthropic API key to use the AI assistant.")
        .icon_name("utilities-terminal-symbolic")
        .build();

    let group = adw::PreferencesGroup::builder()
        .margin_start(48)
        .margin_end(48)
        .build();

    let key_row = adw::PasswordEntryRow::builder()
        .title("Anthropic API Key")
        .build();
    group.add(&key_row);

    let btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .halign(gtk4::Align::Center)
        .spacing(12)
        .margin_top(16)
        .build();

    let get_key_btn = gtk4::Button::builder()
        .label("Get API Key")
        .tooltip_text("Opens console.anthropic.com in your browser")
        .css_classes(["flat"])
        .build();
    get_key_btn.connect_clicked(|_| {
        let _ = std::process::Command::new("xdg-open")
            .arg(API_KEY_URL)
            .spawn();
    });

    let save_btn = gtk4::Button::builder()
        .label("Save & Continue")
        .css_classes(["suggested-action", "pill"])
        .sensitive(false)
        .build();

    btn_box.append(&get_key_btn);
    btn_box.append(&save_btn);

    // Enable save only when key looks valid (sk-ant-...)
    {
        let save_btn = save_btn.clone();
        key_row.connect_changed(move |row| {
            let text = row.text();
            save_btn.set_sensitive(text.starts_with("sk-ant-"));
        });
    }

    // Save button stores key and switches to chat
    {
        let key_row = key_row.clone();
        save_btn.connect_clicked(move |btn| {
            let key = key_row.text().to_string();
            if key.is_empty() {
                return;
            }
            let mut settings = crate::settings::AppSettings::load();
            settings.anthropic_api_key = key;
            settings.save();

            // Walk up to find the Stack and switch to "chat"
            if let Some(stack) = btn
                .ancestor(gtk4::Stack::static_type())
                .and_then(|w| w.downcast::<gtk4::Stack>().ok())
            {
                stack.set_visible_child_name("chat");
            }
        });
    }

    let vbox = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .valign(gtk4::Align::Center)
        .vexpand(true)
        .build();
    vbox.append(&status);
    vbox.append(&group);
    vbox.append(&btn_box);

    vbox.upcast()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tags(buffer: &gtk4::TextBuffer) {
    let tt = buffer.tag_table();

    // Use weight/style distinctions instead of hardcoded colors so the
    // console looks correct on both dark and light Adwaita themes.
    tt.add(
        &gtk4::TextTag::builder()
            .name("user")
            .weight(700)
            .build(),
    );
    tt.add(
        &gtk4::TextTag::builder()
            .name("assistant")
            .build(),
    );

    // "tool" — italic monospace, dimmed via half-opacity foreground so it
    // adapts to whatever the current text colour is.
    let tool_tag = gtk4::TextTag::builder()
        .name("tool")
        .style(gtk4::pango::Style::Italic)
        .family("monospace")
        .scale(0.9)
        .build();
    let dim = gtk4::gdk::RGBA::new(0.5, 0.5, 0.5, 0.7);
    tool_tag.set_foreground_rgba(Some(&dim));
    tt.add(&tool_tag);

    tt.add(
        &gtk4::TextTag::builder()
            .name("system")
            .style(gtk4::pango::Style::Italic)
            .build(),
    );
}

pub fn append_tagged(buffer: &gtk4::TextBuffer, text: &str, tag_name: &str) {
    let mut end = buffer.end_iter();
    buffer.insert(&mut end, text);
    let start = buffer.iter_at_offset(end.offset() - text.len() as i32);
    if let Some(tag) = buffer.tag_table().lookup(tag_name) {
        buffer.apply_tag(&tag, &start, &end);
    }
}

fn append_system_msg(buffer: &gtk4::TextBuffer, text: &str) {
    append_tagged(buffer, text, "system");
}
