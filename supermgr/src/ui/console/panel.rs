//! Console panel — GTK4 chat interface for Claude, Codex and OpenAI.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use supermgr_core::vpn::state::VpnState;

use crate::app::{AppMsg, AppState};

/// Widget bundle for the console panel.
#[derive(Clone)]
#[allow(dead_code)]
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
    app_settings: &Arc<Mutex<crate::settings::AppSettings>>,
    tx: &mpsc::Sender<AppMsg>,
    rt: &tokio::runtime::Handle,
) -> (ConsolePanel, gtk4::Widget) {
    // =====================================================================
    // Setup page (shown when no API key)
    // =====================================================================

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
        .tooltip_text("Send (Enter; Shift+Enter for a new line)")
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
    let provider = adw::ComboRow::builder()
        .title("Provider")
        .model(&gtk4::StringList::new(&[
            "Claude",
            "Codex · ChatGPT login",
            "OpenAI API",
        ]))
        .build();
    let settings = app_settings.lock().unwrap_or_else(|e| e.into_inner());
    provider.set_selected(match settings.ai_provider {
        crate::settings::AiProvider::Claude => 0,
        crate::settings::AiProvider::Codex => 1,
        crate::settings::AiProvider::OpenAi => 2,
    });
    drop(settings);
    let allow_changes = gtk4::CheckButton::with_label("Allow changes for this conversation");
    allow_changes.set_tooltip_text(Some("Enables remote commands and configuration changes you request. Read-only data access is the default."));
    let controls = adw::PreferencesGroup::new();
    controls.set_margin_start(20);
    controls.set_margin_end(20);
    controls.set_margin_top(16);
    controls.set_margin_bottom(10);
    controls.add(&provider);
    controls.add(&allow_changes);
    let heading = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(6)
        .margin_start(20)
        .margin_end(20)
        .margin_top(28)
        .margin_bottom(8)
        .build();
    heading.append(
        &gtk4::Label::builder()
            .label("Assistant")
            .xalign(0.0)
            .css_classes(["supermgr-page-title"])
            .build(),
    );
    heading.append(
        &gtk4::Label::builder()
            .label("Explore your fleet and turn findings into a clear next step.")
            .xalign(0.0)
            .wrap(true)
            .css_classes(["dim-label"])
            .build(),
    );
    chat_page.append(&heading);
    chat_page.append(&controls);
    let suggestions = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_start(20)
        .margin_end(20)
        .margin_bottom(12)
        .build();
    for (label, prompt) in [
        ("Fleet overview", "Summarize my managed hosts and their last known health. Call the relevant read-only tools and distinguish stale or missing data."),
        ("Security findings", "List the saved findings scopes, then summarize open high and critical findings. Do not run scans or make changes."),
        ("Compliance coverage", "Which compliance checks are available, and what do they actually cover?"),
    ] {
        let button = gtk4::Button::with_label(label);
        let input = input_view.clone();
        button.connect_clicked(move |_| { input.buffer().set_text(prompt); input.grab_focus(); });
        suggestions.append(&button);
    }
    chat_page.append(&suggestions);
    chat_scroll.add_css_class("supermgr-chat-surface");
    chat_scroll.set_margin_start(20);
    chat_scroll.set_margin_end(20);
    chat_scroll.set_margin_bottom(12);
    chat_view.add_css_class("supermgr-chat-text");
    input_view.add_css_class("supermgr-chat-text");
    chat_page.append(&api_key_banner);
    chat_page.append(&chat_scroll);
    chat_page.append(&input_row);

    // =====================================================================
    // Stack: setup vs chat
    // =====================================================================
    let setup_stack = gtk4::Stack::new();
    let clamp = adw::Clamp::builder()
        .maximum_size(1120)
        .tightening_threshold(880)
        .child(&chat_page)
        .build();
    setup_stack.add_named(&clamp, Some("chat"));
    setup_stack.set_visible_child_name("chat");
    append_system_msg(&chat_buffer,
        "Ask about your fleet, customers, compliance results or security findings.\nChoose an assistant above. Configure API keys and models in Settings → AI; Codex uses your existing CLI login.\nRead-only until you enable changes.\n");

    let busy = Arc::new(AtomicBool::new(false));
    let generation = Arc::new(AtomicU64::new(0));
    let running: Arc<Mutex<Option<tokio::task::AbortHandle>>> = Arc::new(Mutex::new(None));
    {
        let busy = Arc::clone(&busy);
        let running = Arc::clone(&running);
        let tx = tx.clone();
        let generation = Arc::clone(&generation);
        let provider = provider.clone();
        let allow_changes = allow_changes.clone();
        stop_btn.connect_clicked(move |_| {
            generation.fetch_add(1, Ordering::AcqRel);
            provider.set_sensitive(true);
            allow_changes.set_sensitive(true);
            if let Some(task) = running.lock().unwrap_or_else(|e| e.into_inner()).take() {
                task.abort();
            }
            busy.store(false, Ordering::Release);
            super::claude::reset_session();
            let _ = tx.send(AppMsg::ConsoleResponse("\n[Stopped]\n".into()));
            let _ = tx.send(AppMsg::ConsoleThinking(false));
        });
    }
    {
        let app_state = Arc::clone(app_state);
        let app_settings = Arc::clone(app_settings);
        let chat_buffer = chat_buffer.clone();
        let busy = Arc::clone(&busy);
        provider.connect_selected_notify(move |row| {
            if busy.load(Ordering::Acquire) {
                return;
            }
            let chosen = match row.selected() {
                1 => crate::settings::AiProvider::Codex,
                2 => crate::settings::AiProvider::OpenAi,
                _ => crate::settings::AiProvider::Claude,
            };
            let mut settings = app_settings.lock().unwrap_or_else(|e| e.into_inner());
            if settings.ai_provider == chosen {
                return;
            }
            settings.ai_provider = chosen;
            settings.save();
            app_state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .console_messages
                .clear();
            super::claude::reset_session();
            chat_buffer.set_text("");
            append_system_msg(
                &chat_buffer,
                &format!(
                    "{} selected. New conversation.\n",
                    super::provider_name(chosen)
                ),
            );
        });
    }
    {
        let app_state = Arc::clone(app_state);
        let chat_buffer = chat_buffer.clone();
        allow_changes.connect_toggled(move |_| {
            append_system_msg(
                &chat_buffer,
                "Access changed. Starting a new conversation context.\n",
            );
            app_state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .console_messages
                .clear();
            super::claude::reset_session();
        });
    }

    {
        let input_view_for_ctrl = input_view.clone();
        let input_view = input_view.clone();
        let chat_buffer = chat_buffer.clone();
        let tx = tx.clone();
        let rt = rt.clone();
        let app_state = Arc::clone(app_state);
        let busy = Arc::clone(&busy);
        let running = Arc::clone(&running);
        let app_settings = Arc::clone(app_settings);
        let provider = provider.clone();
        let allow_changes = allow_changes.clone();
        let generation = Arc::clone(&generation);
        let send = move || {
            let buf = input_view.buffer();
            let text = buf
                .text(&buf.start_iter(), &buf.end_iter(), false)
                .to_string();
            if text.trim().is_empty() || busy.load(Ordering::Acquire) {
                return;
            }
            buf.set_text("");

            let request_id = generation.fetch_add(1, Ordering::AcqRel) + 1;
            busy.store(true, Ordering::Release);
            provider.set_sensitive(false);
            allow_changes.set_sensitive(false);
            let settings = app_settings
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let actions_allowed = allow_changes.is_active();
            append_tagged(&chat_buffer, &format!("\nYou: {text}\n"), "user");

            let tx = tx.clone();
            let text = text.clone();
            let app_state = Arc::clone(&app_state);
            let (messages, context) = {
                let s = app_state.lock().unwrap_or_else(|e| e.into_inner());
                let vpn = match &s.vpn_state {
                    VpnState::Connected { profile_id, .. } => {
                        let name = s
                            .profiles
                            .iter()
                            .find(|p| p.id == *profile_id)
                            .map(|p| p.name.as_str())
                            .unwrap_or("unknown");
                        format!("VPN: connected to '{name}'")
                    }
                    VpnState::Disconnected => "VPN: disconnected".into(),
                    _ => "VPN: transitioning".into(),
                };
                let hosts: Vec<String> = s
                    .hosts
                    .iter()
                    .map(|h| {
                        let mut info = format!(
                            "- {} ({}@{}:{}, {}, auth={:?}, id={})",
                            h.label,
                            h.username,
                            h.hostname,
                            h.port,
                            h.device_type,
                            h.auth_method,
                            h.id
                        );
                        if h.has_api {
                            info.push_str(&format!(", api_port={}", h.api_port.unwrap_or(443)));
                        }
                        if let Some(ref vpn_id) = h.vpn_profile_id {
                            if let Some(p) = s
                                .profiles
                                .iter()
                                .find(|p| p.id.to_string() == vpn_id.to_string())
                            {
                                info.push_str(&format!(", auto_vpn='{}'", p.name));
                            }
                        }
                        if h.pinned {
                            info.push_str(", pinned");
                        }
                        info
                    })
                    .collect();
                let keys: Vec<String> = s
                    .ssh_keys
                    .iter()
                    .map(|k| {
                        format!(
                            "- {} ({:?}, {}, deployed_to={})",
                            k.name, k.key_type, k.fingerprint, k.deployed_count
                        )
                    })
                    .collect();
                let profiles: Vec<String> = s
                    .profiles
                    .iter()
                    .map(|p| format!("- {} ({}, id={})", p.name, p.backend, p.id))
                    .collect();
                let health: Vec<String> = s
                    .host_health
                    .iter()
                    .map(|(id, ok)| {
                        let label = s
                            .hosts
                            .iter()
                            .find(|h| h.id.to_string() == *id)
                            .map(|h| h.label.as_str())
                            .unwrap_or(id);
                        format!(
                            "- {}: {}",
                            label,
                            if *ok { "reachable" } else { "UNREACHABLE" }
                        )
                    })
                    .collect();
                let ctx = format!(
                    "{vpn}\n\n\
                     ## VPN Profiles\n{}\n\n\
                     ## SSH Hosts\n{}\n\n\
                     ## SSH Keys\n{}\n\n\
                     ## Host Health\n{}",
                    profiles.join("\n"),
                    hosts.join("\n"),
                    keys.join("\n"),
                    if health.is_empty() {
                        "No health data yet".into()
                    } else {
                        health.join("\n")
                    },
                );
                (s.console_messages.clone(), ctx)
            };
            // Per-request channels keep a cancelled request from writing into a
            // newer conversation. Only the GTK thread commits history/UI state.
            let (events_tx, events_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let _ = tx.send(AppMsg::ConsoleThinking(true));
            let task = rt.spawn(async move {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(300),
                    super::send(
                        &settings,
                        &text,
                        &events_tx,
                        messages,
                        &context,
                        actions_allowed,
                    ),
                )
                .await;
                let result = match result {
                    Ok(result) => result.map_err(|e| e.to_string()),
                    Err(_) => Err("Request timed out after five minutes.".into()),
                };
                let _ = done_tx.send(result);
            });
            *running.lock().unwrap_or_else(|e| e.into_inner()) = Some(task.abort_handle());
            let provider = provider.clone();
            let allow_changes = allow_changes.clone();
            let generation = Arc::clone(&generation);
            let busy = Arc::clone(&busy);
            let running = Arc::clone(&running);
            gtk4::glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
                if generation.load(Ordering::Acquire) != request_id {
                    return gtk4::glib::ControlFlow::Break;
                }
                for event in events_rx.try_iter() {
                    let _ = tx.send(event);
                }
                let result = match done_rx.try_recv() {
                    Err(mpsc::TryRecvError::Empty) => return gtk4::glib::ControlFlow::Continue,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        Err("Assistant request stopped unexpectedly.".into())
                    }
                    Ok(result) => result,
                };
                // Completion may arrive between the first event drain and the
                // result read; preserve the final answer before clearing busy.
                for event in events_rx.try_iter() {
                    let _ = tx.send(event);
                }
                match result {
                    Ok(messages) => {
                        app_state
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .console_messages = messages
                    }
                    Err(e) => {
                        let _ = tx.send(AppMsg::ConsoleResponse(format!("\nError: {e}\n")));
                    }
                }
                busy.store(false, Ordering::Release);
                running.lock().unwrap_or_else(|e| e.into_inner()).take();
                let _ = tx.send(AppMsg::ConsoleThinking(false));
                provider.set_sensitive(true);
                allow_changes.set_sensitive(true);
                gtk4::glib::ControlFlow::Break
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
        let running = Arc::clone(&running);
        let busy = Arc::clone(&busy);
        let tx = tx.clone();
        let generation = Arc::clone(&generation);
        let provider = provider.clone();
        let allow_changes = allow_changes.clone();
        clear_btn.connect_clicked(move |_| {
            generation.fetch_add(1, Ordering::AcqRel);
            provider.set_sensitive(true);
            allow_changes.set_sensitive(true);
            if let Some(task) = running.lock().unwrap_or_else(|e| e.into_inner()).take() {
                task.abort();
            }
            busy.store(false, Ordering::Release);
            let _ = tx.send(AppMsg::ConsoleThinking(false));
            chat_buffer.set_text("");
            app_state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .console_messages
                .clear();
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

fn init_tags(buffer: &gtk4::TextBuffer) {
    let tt = buffer.tag_table();

    // Use weight/style distinctions instead of hardcoded colors so the
    // console looks correct on both dark and light Adwaita themes.
    tt.add(&gtk4::TextTag::builder().name("user").weight(700).build());
    tt.add(&gtk4::TextTag::builder().name("assistant").build());

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
    let start = buffer.iter_at_offset(end.offset() - text.chars().count() as i32);
    if let Some(tag) = buffer.tag_table().lookup(tag_name) {
        buffer.apply_tag(&tag, &start, &end);
    }
}

fn append_system_msg(buffer: &gtk4::TextBuffer, text: &str) {
    append_tagged(buffer, text, "system");
}
