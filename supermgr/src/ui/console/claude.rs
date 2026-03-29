//! Claude API client with tool use for SuperManager operations.

use std::sync::mpsc;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde_json::{json, Value};
use tracing::{debug, info, warn};

use supermgr_core::dbus::DaemonProxy;

use crate::app::AppMsg;

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const MODEL: &str = "claude-sonnet-4-20250514";
const MAX_TOKENS: u64 = 4096;
/// Check if an API key is configured in settings.
pub fn has_api_key() -> bool {
    let s = crate::settings::AppSettings::load();
    !s.anthropic_api_key.is_empty()
}

/// Load the API key from settings.
pub fn load_api_key() -> Option<String> {
    let s = crate::settings::AppSettings::load();
    if s.anthropic_api_key.is_empty() { None } else { Some(s.anthropic_api_key) }
}

/// Check if subscription mode is enabled.
pub fn use_subscription() -> bool {
    crate::settings::AppSettings::load().use_claude_subscription
}

/// Check if Claude Code CLI is available.
pub fn has_claude_cli() -> bool {
    std::process::Command::new("claude")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Path to the MCP server binary (next to the GUI binary, or in /usr/bin).
fn mcp_binary_path() -> String {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("supermgr-mcp");
        if sibling.exists() {
            return sibling.to_string_lossy().to_string();
        }
    }
    "/usr/bin/supermgr-mcp".to_owned()
}

/// Shared session ID for the subscription CLI — reused across messages
/// for faster responses (warm cache) and conversation memory.
static SESSION_ID: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Reset the Claude CLI session (e.g. on "Clear conversation").
pub fn reset_session() {
    *SESSION_ID.lock().unwrap() = None;
}

/// Send a message using Claude Code CLI (subscription-based, no API tokens).
///
/// Uses `claude --print --output-format stream-json` for streaming output.
/// Reuses the session ID for faster follow-up messages.
pub async fn send_message_subscription(
    user_text: &str,
    tx: &mpsc::Sender<AppMsg>,
    context: &str,
) -> Result<()> {
    let mcp_path = mcp_binary_path();

    let mcp_config = json!({
        "mcpServers": {
            "supermgr": {
                "command": mcp_path
            }
        }
    });

    let allowed_tools = [
        "mcp__supermgr__ssh_list_hosts",
        "mcp__supermgr__ssh_list_keys",
        "mcp__supermgr__ssh_execute",
        "mcp__supermgr__vpn_status",
        "mcp__supermgr__vpn_list_profiles",
        "mcp__supermgr__vpn_connect",
        "mcp__supermgr__vpn_disconnect",
        "mcp__supermgr__ssh_add_host",
        "mcp__supermgr__fortigate_api",
        "mcp__supermgr__fortigate_set_api_token",
        "mcp__supermgr__fortigate_push_ssh_key",
        "mcp__supermgr__unifi_set_inform",
        "mcp__supermgr__unifi_api",
        "mcp__supermgr__fortigate_compliance_check",
    ].join(",");

    let system_with_context = format!(
        "{SYSTEM_PROMPT}\n\n## Current State\n{context}"
    );

    let session_id = SESSION_ID.lock().unwrap().clone();

    let mut cmd = tokio::process::Command::new("claude");
    cmd.args([
        "--print",
        "--output-format", "stream-json",
        "--verbose",
        "--mcp-config", &mcp_config.to_string(),
        "--allowedTools", &allowed_tools,
        "--system-prompt", &system_with_context,
    ]);

    // Resume existing session for speed + memory.
    if let Some(ref sid) = session_id {
        info!("resuming Claude CLI session {sid}");
        cmd.args(["--resume", sid]);
    }

    cmd.arg(user_text);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    info!("sending via Claude Code CLI (subscription)");

    let mut child = cmd.spawn()
        .context("failed to start `claude` CLI — is it installed?")?;

    let stdout = child.stdout.take()
        .context("failed to capture claude stdout")?;

    // Read streaming JSON lines from stdout.
    let tx_stream = tx.clone();
    let reader_handle = tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut new_session_id: Option<String> = None;
        let mut sent_text = false;

        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            let parsed: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            match parsed.get("type").and_then(|t| t.as_str()) {
                Some("system") => {
                    // Capture session_id from init message.
                    if let Some(sid) = parsed.get("session_id").and_then(|s| s.as_str()) {
                        new_session_id = Some(sid.to_owned());
                    }
                }
                Some("assistant") => {
                    // Extract text content from assistant message.
                    if let Some(msg) = parsed.get("message") {
                        if let Some(content) = msg.get("content").and_then(|c| c.as_array()) {
                            for block in content {
                                if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                                    if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                                        if !sent_text {
                                            let _ = tx_stream.send(AppMsg::ConsoleResponse(
                                                "\nClaude: ".into(),
                                            ));
                                            sent_text = true;
                                        }
                                        let _ = tx_stream.send(AppMsg::ConsoleStreamChunk(
                                            text.to_owned(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                Some("result") => {
                    // Final result — extract text if we haven't streamed yet.
                    if !sent_text {
                        if let Some(result) = parsed.get("result").and_then(|r| r.as_str()) {
                            let _ = tx_stream.send(AppMsg::ConsoleResponse(
                                format!("\nClaude: {result}\n"),
                            ));
                        }
                    } else {
                        let _ = tx_stream.send(AppMsg::ConsoleResponse("\n".into()));
                    }
                    // Capture session_id from result.
                    if let Some(sid) = parsed.get("session_id").and_then(|s| s.as_str()) {
                        new_session_id = Some(sid.to_owned());
                    }
                }
                _ => {} // ignore rate_limit_event etc.
            }
        }
        new_session_id
    });

    // Wait with timeout.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        child.wait(),
    ).await;

    match result {
        Ok(Ok(status)) => {
            if !status.success() {
                warn!("claude CLI exited with {status}");
            }
        }
        Ok(Err(e)) => {
            warn!("claude CLI wait error: {e}");
        }
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("claude CLI timed out after 5 minutes");
        }
    }

    // Save session ID for next message.
    if let Ok(Some(sid)) = reader_handle.await {
        info!("Claude CLI session: {sid}");
        *SESSION_ID.lock().unwrap() = Some(sid);
    }

    Ok(())
}

/// Tool definitions sent to the Claude API.
fn tools() -> Value {
    json!([
        {
            "name": "ssh_list_hosts",
            "description": "List all configured SSH hosts with their connection details.",
            "input_schema": { "type": "object", "properties": {}, "required": [] }
        },
        {
            "name": "ssh_list_keys",
            "description": "List all managed SSH keys.",
            "input_schema": { "type": "object", "properties": {}, "required": [] }
        },
        {
            "name": "ssh_execute",
            "description": "Execute a shell command on a remote SSH host. The host must be reachable (VPN active if needed).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host_id": { "type": "string", "description": "UUID of the target SSH host" },
                    "command": { "type": "string", "description": "Shell command to execute" }
                },
                "required": ["host_id", "command"]
            }
        },
        {
            "name": "vpn_status",
            "description": "Get current VPN connection status.",
            "input_schema": { "type": "object", "properties": {}, "required": [] }
        },
        {
            "name": "vpn_list_profiles",
            "description": "List all VPN profiles.",
            "input_schema": { "type": "object", "properties": {}, "required": [] }
        },
        {
            "name": "vpn_connect",
            "description": "Connect to a VPN profile.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string", "description": "UUID of the VPN profile" }
                },
                "required": ["profile_id"]
            }
        },
        {
            "name": "vpn_disconnect",
            "description": "Disconnect the active VPN.",
            "input_schema": { "type": "object", "properties": {}, "required": [] }
        },
        {
            "name": "ssh_add_host",
            "description": "Add a new SSH host.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "label": { "type": "string" },
                    "hostname": { "type": "string" },
                    "port": { "type": "integer" },
                    "username": { "type": "string" },
                    "group": { "type": "string" },
                    "device_type": { "type": "string", "description": "linux, uni_fi, pf_sense, open_wrt, fortigate, windows" },
                    "auth_method": { "type": "string", "description": "key or password" },
                    "auth_key_id": { "type": "string" }
                },
                "required": ["label", "hostname", "username", "auth_method"]
            }
        },
        {
            "name": "fortigate_api",
            "description": "Call the FortiGate REST API on a host that has an API token configured. Use this for FortiGate management tasks like reading config, pushing SSH keys, managing firewall policies, etc. Common paths: /api/v2/cmdb/system/admin (admin users), /api/v2/monitor/system/status (system status), /api/v2/cmdb/firewall/policy (firewall policies).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host_id": { "type": "string", "description": "UUID of the FortiGate host" },
                    "method": { "type": "string", "description": "HTTP method: GET, POST, PUT, DELETE" },
                    "path": { "type": "string", "description": "API path, e.g. /api/v2/cmdb/system/admin/admin" },
                    "body": { "type": "string", "description": "Optional JSON request body (for POST/PUT)" }
                },
                "required": ["host_id", "method", "path"]
            }
        },
        {
            "name": "fortigate_set_api_token",
            "description": "Store a FortiGate REST API token and HTTPS port for a host. The token is stored securely.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host_id": { "type": "string", "description": "UUID of the FortiGate host" },
                    "token": { "type": "string", "description": "FortiGate REST API token" },
                    "port": { "type": "integer", "description": "HTTPS admin port (default 443, common: 8443, 10000)" }
                },
                "required": ["host_id", "token"]
            }
        },
        {
            "name": "fortigate_push_ssh_key",
            "description": "Push an SSH public key to a FortiGate admin user via REST API. Sets ssh-public-key1 on the admin user. Requires an API token to be configured on the host.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host_id": { "type": "string", "description": "UUID of the FortiGate host" },
                    "key_id": { "type": "string", "description": "UUID of the SSH key to push" },
                    "admin_user": { "type": "string", "description": "FortiGate admin username (e.g. 'admin')" }
                },
                "required": ["host_id", "key_id", "admin_user"]
            }
        },
        {
            "name": "unifi_set_inform",
            "description": "Execute set-inform on a UniFi device via SSH to adopt it to a controller. The host must be a UniFi device type.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host_id": { "type": "string", "description": "UUID of the UniFi device host" },
                    "inform_url": { "type": "string", "description": "Controller inform URL (e.g. https://unifi.example.com:8443/inform)" }
                },
                "required": ["host_id", "inform_url"]
            }
        },
        {
            "name": "unifi_api",
            "description": "Call the UniFi Controller REST API on a host that has controller credentials configured. Authenticates automatically. Common paths: /proxy/network/api/s/default/stat/device (list devices), /proxy/network/api/s/default/stat/sta (list clients), /proxy/network/api/s/default/rest/setting (settings).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host_id": { "type": "string", "description": "UUID of the UniFi host with controller configured" },
                    "method": { "type": "string", "description": "HTTP method: GET, POST, PUT, DELETE" },
                    "path": { "type": "string", "description": "API path, e.g. /proxy/network/api/s/default/stat/device" },
                    "body": { "type": "string", "description": "Optional JSON request body (for POST/PUT)" }
                },
                "required": ["host_id", "method", "path"]
            }
        },
        {
            "name": "fortigate_compliance_check",
            "description": "Run CIS benchmark compliance checks against a FortiGate device via SSH. Checks admin port, strong crypto, telnet, password policy, logging, WAN interface access, DoS policy, and admin-maintainer settings. Returns a JSON report with pass/fail for each check and an overall score.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host_id": { "type": "string", "description": "UUID of the FortiGate host to check" }
                },
                "required": ["host_id"]
            }
        }
    ])
}

const SYSTEM_PROMPT: &str = "\
You are an AI assistant integrated into SuperManager, a unified SSH + VPN management application. \
You have access to tools that let you manage SSH connections, execute commands on remote hosts, \
control VPN connections, and interact with FortiGate firewalls via their REST API. \
The user is a system administrator managing network infrastructure. \
Be concise and action-oriented. When executing commands, show the results clearly. \
For FortiGate devices, you can use both SSH and REST API — prefer REST API when an API token is configured.";

/// Send a user message to Claude and handle the response (including tool use loops).
///
/// Accepts the existing conversation history and returns the updated history
/// after appending the new user message and all assistant/tool exchanges.
///
/// `context` is a snapshot of the current app state (VPN status, hosts, keys)
/// that is injected into the system prompt so Claude has immediate awareness
/// without needing to call tools first.
pub async fn send_message(
    api_key: &str,
    user_text: &str,
    tx: &mpsc::Sender<AppMsg>,
    mut messages: Vec<Value>,
    context: &str,
) -> Result<Vec<Value>> {
    // Try D-Bus connection; if it fails (daemon restarted), notify the user
    // and retry once after a short delay.
    let conn = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(_) => {
            let _ = tx.send(AppMsg::ConsoleResponse(
                "\nDaemon connection lost — reconnecting...\n".into(),
            ));
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            zbus::Connection::system()
                .await
                .context("D-Bus reconnect failed — is the daemon running?")?
        }
    };
    let proxy = DaemonProxy::new(&conn).await.context("DaemonProxy")?;

    let client = reqwest::Client::new();

    // Build the full system prompt with injected state context.
    let full_system = format!("{SYSTEM_PROMPT}\n\n## Current State\n{context}");

    // Append the new user message to the conversation history.
    messages.push(json!({ "role": "user", "content": user_text }));

    // Tool use loop — Claude may call tools and we feed results back.
    loop {
        let body = json!({
            "model": MODEL,
            "max_tokens": MAX_TOKENS,
            "system": full_system,
            "tools": tools(),
            "messages": messages,
            "stream": true,
        });

        debug!("Claude API request (streaming): {} messages", messages.len());

        let resp = client
            .post(API_URL)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("API request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error {status}: {body}");
        }

        // --- Stream SSE events ---
        let (content, stop_reason, tool_calls) =
            parse_stream(resp, tx).await?;

        // Always record the assistant response in history.
        if stop_reason != "tool_use" || tool_calls.is_empty() {
            messages.push(json!({ "role": "assistant", "content": content }));
            break;
        }

        // Execute tools and build tool_result messages.
        messages.push(json!({ "role": "assistant", "content": content }));

        let mut tool_results: Vec<Value> = Vec::new();
        for (id, name, input) in &tool_calls {
            let result = execute_tool(&proxy, name, input).await;
            let (result_text, is_error) = match result {
                Ok(v) => (serde_json::to_string_pretty(&v).unwrap_or_default(), false),
                Err(e) => (format!("Error: {e}"), true),
            };

            // Show tool result in console (truncated).
            let preview = if result_text.len() > 500 {
                format!("{}...", &result_text[..500])
            } else {
                result_text.clone()
            };
            let _ = tx.send(AppMsg::ConsoleResponse(format!("  {preview}\n")));

            tool_results.push(json!({
                "type": "tool_result",
                "tool_use_id": id,
                "content": result_text,
                "is_error": is_error,
            }));
        }

        messages.push(json!({ "role": "user", "content": tool_results }));
    }

    Ok(messages)
}

/// Parse an SSE stream from the Claude API, sending text chunks to the UI
/// as they arrive and accumulating content blocks for conversation history.
///
/// Returns `(content_blocks, stop_reason, tool_calls)`.
async fn parse_stream(
    resp: reqwest::Response,
    tx: &mpsc::Sender<AppMsg>,
) -> Result<(Vec<Value>, String, Vec<(String, String, Value)>)> {
    let mut stream = resp.bytes_stream();

    // Accumulated SSE line buffer (handles partial lines across chunks).
    let mut line_buf = String::new();
    // Current SSE event type and data lines.
    let mut event_type = String::new();
    let mut data_buf = String::new();

    // Accumulated content blocks for conversation history.
    let mut content_blocks: Vec<Value> = Vec::new();
    // Current text block being streamed.
    let mut current_text = String::new();
    let mut has_open_text_block = false;
    // Tool use accumulation.
    let mut tool_id = String::new();
    let mut tool_name = String::new();
    let mut tool_input_json = String::new();
    let mut in_tool_block = false;
    // Stop reason from message_delta.
    let mut stop_reason = String::new();
    // Prefix sent for the first text chunk.
    let mut sent_prefix = false;

    // Collected tool calls to execute.
    let mut tool_calls: Vec<(String, String, Value)> = Vec::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.context("stream read error")?;
        line_buf.push_str(&String::from_utf8_lossy(&chunk));

        // Process complete lines.
        while let Some(newline_pos) = line_buf.find('\n') {
            let line = line_buf[..newline_pos].trim_end_matches('\r').to_owned();
            line_buf = line_buf[newline_pos + 1..].to_owned();

            if line.is_empty() {
                // Empty line = end of SSE event; dispatch it.
                if !data_buf.is_empty() {
                    dispatch_sse_event(
                        &event_type,
                        &data_buf,
                        tx,
                        &mut content_blocks,
                        &mut current_text,
                        &mut has_open_text_block,
                        &mut tool_id,
                        &mut tool_name,
                        &mut tool_input_json,
                        &mut in_tool_block,
                        &mut stop_reason,
                        &mut sent_prefix,
                        &mut tool_calls,
                    );
                }
                event_type.clear();
                data_buf.clear();
            } else if let Some(rest) = line.strip_prefix("event: ") {
                event_type = rest.to_owned();
            } else if let Some(rest) = line.strip_prefix("data: ") {
                if !data_buf.is_empty() {
                    data_buf.push('\n');
                }
                data_buf.push_str(rest);
            } else if line.starts_with(':') {
                // SSE comment, ignore.
            }
        }
    }

    // Finalize any open text block.
    if has_open_text_block && !current_text.is_empty() {
        content_blocks.push(json!({ "type": "text", "text": current_text }));
        // Trailing newline for readability.
        let _ = tx.send(AppMsg::ConsoleStreamChunk("\n".to_owned()));
    }

    Ok((content_blocks, stop_reason, tool_calls))
}

/// Dispatch a single SSE event parsed from the stream.
#[allow(clippy::too_many_arguments)]
fn dispatch_sse_event(
    event_type: &str,
    data: &str,
    tx: &mpsc::Sender<AppMsg>,
    content_blocks: &mut Vec<Value>,
    current_text: &mut String,
    has_open_text_block: &mut bool,
    tool_id: &mut String,
    tool_name: &mut String,
    tool_input_json: &mut String,
    in_tool_block: &mut bool,
    stop_reason: &mut String,
    sent_prefix: &mut bool,
    tool_calls: &mut Vec<(String, String, Value)>,
) {
    let parsed: Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(e) => {
            warn!("SSE data parse error: {e}");
            return;
        }
    };

    match event_type {
        "content_block_start" => {
            let block_type = parsed["content_block"]["type"].as_str().unwrap_or("");
            if block_type == "text" {
                // Close any previous tool block.
                if *in_tool_block {
                    finalize_tool_block(
                        content_blocks, tool_id, tool_name, tool_input_json, tool_calls,
                    );
                    *in_tool_block = false;
                }
                *has_open_text_block = true;
                *current_text = String::new();
                if !*sent_prefix {
                    let _ = tx.send(AppMsg::ConsoleStreamChunk("\nClaude: ".to_owned()));
                    *sent_prefix = true;
                }
            } else if block_type == "tool_use" {
                // Close any previous text block.
                if *has_open_text_block && !current_text.is_empty() {
                    content_blocks.push(json!({ "type": "text", "text": *current_text }));
                    let _ = tx.send(AppMsg::ConsoleStreamChunk("\n".to_owned()));
                    *current_text = String::new();
                    *has_open_text_block = false;
                }
                *tool_id = parsed["content_block"]["id"]
                    .as_str().unwrap_or("").to_owned();
                *tool_name = parsed["content_block"]["name"]
                    .as_str().unwrap_or("").to_owned();
                *tool_input_json = String::new();
                *in_tool_block = true;
                let _ = tx.send(AppMsg::ConsoleResponse(
                    format!("\n[tool: {}]\n", tool_name),
                ));
            }
        }
        "content_block_delta" => {
            let delta_type = parsed["delta"]["type"].as_str().unwrap_or("");
            if delta_type == "text_delta" {
                let text = parsed["delta"]["text"].as_str().unwrap_or("");
                if !text.is_empty() {
                    current_text.push_str(text);
                    let _ = tx.send(AppMsg::ConsoleStreamChunk(text.to_owned()));
                }
            } else if delta_type == "input_json_delta" {
                let partial = parsed["delta"]["partial_json"].as_str().unwrap_or("");
                tool_input_json.push_str(partial);
            }
        }
        "content_block_stop" => {
            if *in_tool_block {
                finalize_tool_block(
                    content_blocks, tool_id, tool_name, tool_input_json, tool_calls,
                );
                *in_tool_block = false;
            }
            // Text blocks stay open until the next block or stream end.
        }
        "message_delta" => {
            if let Some(sr) = parsed["delta"]["stop_reason"].as_str() {
                *stop_reason = sr.to_owned();
            }
        }
        "message_stop" | "message_start" | "ping" => {
            // No action needed.
        }
        other => {
            debug!("unhandled SSE event type: {other}");
        }
    }
}

/// Finalize a tool_use content block and record it for execution.
fn finalize_tool_block(
    content_blocks: &mut Vec<Value>,
    tool_id: &mut String,
    tool_name: &mut String,
    tool_input_json: &mut String,
    tool_calls: &mut Vec<(String, String, Value)>,
) {
    let input: Value = serde_json::from_str(tool_input_json).unwrap_or(json!({}));
    tool_calls.push((tool_id.clone(), tool_name.clone(), input.clone()));
    content_blocks.push(json!({
        "type": "tool_use",
        "id": *tool_id,
        "name": *tool_name,
        "input": input,
    }));
    tool_id.clear();
    tool_name.clear();
    tool_input_json.clear();
}

/// Execute a single tool call against the daemon via D-Bus.
async fn execute_tool(proxy: &DaemonProxy<'_>, name: &str, args: &Value) -> Result<Value> {
    match name {
        "ssh_list_hosts" => {
            let j = proxy.ssh_list_hosts().await?;
            Ok(serde_json::from_str(&j)?)
        }
        "ssh_list_keys" => {
            let j = proxy.ssh_list_keys().await?;
            Ok(serde_json::from_str(&j)?)
        }
        "ssh_execute" => {
            let host_id = args["host_id"].as_str().context("missing host_id")?;
            let command = args["command"].as_str().context("missing command")?;
            info!("tool ssh_execute: host={host_id} cmd={command}");
            let j = proxy.ssh_execute_command(host_id, command).await?;
            Ok(serde_json::from_str(&j)?)
        }
        "vpn_status" => {
            let j = proxy.get_status().await?;
            Ok(serde_json::from_str(&j)?)
        }
        "vpn_list_profiles" => {
            let j = proxy.list_profiles().await?;
            Ok(serde_json::from_str(&j)?)
        }
        "vpn_connect" => {
            let id = args["profile_id"].as_str().context("missing profile_id")?;
            proxy.connect(id).await?;
            Ok(json!({ "status": "connecting", "profile_id": id }))
        }
        "vpn_disconnect" => {
            proxy.disconnect().await?;
            Ok(json!({ "status": "disconnecting" }))
        }
        "ssh_add_host" => {
            let host = json!({
                "label": args["label"].as_str().unwrap_or(""),
                "hostname": args["hostname"].as_str().unwrap_or(""),
                "port": args["port"].as_u64().unwrap_or(22),
                "username": args["username"].as_str().unwrap_or("root"),
                "group": args["group"].as_str().unwrap_or(""),
                "device_type": args["device_type"].as_str().unwrap_or("linux"),
                "auth_method": args["auth_method"].as_str().unwrap_or("password"),
                "auth_key_id": args.get("auth_key_id"),
            });
            let id = proxy.ssh_add_host(&host.to_string()).await?;
            Ok(json!({ "id": id, "status": "created" }))
        }
        "fortigate_api" => {
            let host_id = args["host_id"].as_str().context("missing host_id")?;
            let method = args["method"].as_str().context("missing method")?;
            let path = args["path"].as_str().context("missing path")?;
            let body = args["body"].as_str().unwrap_or("");
            info!("tool fortigate_api: {method} {path} on {host_id}");
            let resp = proxy.fortigate_api(host_id, method, path, body).await?;
            Ok(serde_json::from_str(&resp).unwrap_or(json!({ "raw": resp })))
        }
        "fortigate_set_api_token" => {
            let host_id = args["host_id"].as_str().context("missing host_id")?;
            let token = args["token"].as_str().context("missing token")?;
            let port = args["port"].as_u64().unwrap_or(443) as u16;
            proxy.ssh_set_api_token(host_id, token, port).await?;
            Ok(json!({ "status": "stored", "host_id": host_id, "port": port }))
        }
        "fortigate_push_ssh_key" => {
            let host_id = args["host_id"].as_str().context("missing host_id")?;
            let key_id = args["key_id"].as_str().context("missing key_id")?;
            let admin_user = args["admin_user"].as_str().context("missing admin_user")?;
            info!("tool fortigate_push_ssh_key: key={key_id} admin={admin_user} host={host_id}");
            let resp = proxy.fortigate_push_ssh_key(host_id, key_id, admin_user).await?;
            Ok(serde_json::from_str(&resp).unwrap_or(json!({ "raw": resp })))
        }
        "unifi_set_inform" => {
            let host_id = args["host_id"].as_str().context("missing host_id")?;
            let inform_url = args["inform_url"].as_str().context("missing inform_url")?;
            info!("tool unifi_set_inform: host={host_id} url={inform_url}");
            let resp = proxy.unifi_set_inform(host_id, inform_url).await?;
            Ok(serde_json::from_str(&resp).unwrap_or(json!({ "raw": resp })))
        }
        "unifi_api" => {
            let host_id = args["host_id"].as_str().context("missing host_id")?;
            let method = args["method"].as_str().context("missing method")?;
            let path = args["path"].as_str().context("missing path")?;
            let body = args["body"].as_str().unwrap_or("");
            info!("tool unifi_api: {method} {path} on {host_id}");
            let resp = proxy.unifi_api(host_id, method, path, body).await?;
            Ok(serde_json::from_str(&resp).unwrap_or(json!({ "raw": resp })))
        }
        "fortigate_compliance_check" => {
            let host_id = args["host_id"].as_str().context("missing host_id")?;
            info!("tool fortigate_compliance_check: host={host_id}");
            let resp = proxy.fortigate_compliance_check(host_id).await?;
            Ok(serde_json::from_str(&resp).unwrap_or(json!({ "raw": resp })))
        }
        _ => anyhow::bail!("unknown tool: {name}"),
    }
}
