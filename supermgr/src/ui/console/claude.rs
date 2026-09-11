//! Claude API client with tool use for SuperManager operations.

use std::sync::mpsc;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde_json::{json, Value};
use tracing::{debug, info};


use crate::app::AppMsg;

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const MAX_TOKENS: u64 = 4096;

/// Both console and provisioning use the operator's model selection.
/// An explicit --model also overrides inherited CLI defaults or old sessions.
pub fn subscription_command(model: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("claude");
    command.args([
        "--print", "--model", crate::settings::anthropic_model_id(model),
        "--tools", "", "--strict-mcp-config", "--setting-sources", "",
        "--disable-slash-commands", "--permission-prompts", "none",
    ]).kill_on_drop(true).stdin(std::process::Stdio::null());
    command
}

pub fn api_error(status: reqwest::StatusCode, body: &str, model: &str) -> String {
    if status == reqwest::StatusCode::NOT_FOUND {
        format!("Claude model '{model}' is unavailable for this account. Select an accessible model in Settings → AI → Claude model. {body}")
    } else {
        format!("Anthropic API error {status} (model '{model}'): {body}")
    }
}
/// Check if Claude Code CLI is available.
#[allow(dead_code)]
pub fn has_claude_cli() -> bool {
    std::process::Command::new("claude")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Path to the MCP server binary (next to the GUI binary, or in /usr/bin).
pub(super) fn mcp_binary_path() -> String {
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
    *SESSION_ID.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Send a message using Claude Code CLI (subscription-based, no API tokens).
///
/// Uses `claude --print --output-format stream-json` for streaming output.
/// Reuses the session ID for faster follow-up messages.
pub async fn send_message_subscription(
    user_text: &str,
    tx: &mpsc::Sender<AppMsg>,
    context: &str,
    allow_changes: bool,
    model: &str,
) -> Result<()> {
    let mcp_path = mcp_binary_path();

    let mcp_config = json!({
        "mcpServers": {
            "supermgr": {
                "command": mcp_path,
                "env": if allow_changes { json!({}) } else { json!({"SUPERMGR_MCP_READ_ONLY":"1"}) }
            }
        }
    });

    let allowed_tools = supermgr_mcp::available_tools(allow_changes).as_array().unwrap().iter()
        .filter_map(|tool| tool["name"].as_str().map(|name| format!("mcp__supermgr__{name}")))
        .collect::<Vec<_>>().join(",");

    let system_with_context = format!(
        "{SYSTEM_PROMPT}\n\n## Current State\n{context}"
    );

    let session_id = SESSION_ID.lock().unwrap_or_else(|e| e.into_inner()).clone();

    let mut cmd = subscription_command(model);
    cmd.args([
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

    if !allow_changes { cmd.env("SUPERMGR_MCP_READ_ONLY", "1"); }
    else { cmd.env_remove("SUPERMGR_MCP_READ_ONLY"); }
    cmd.kill_on_drop(true);
    cmd.arg(user_text);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    info!(model = crate::settings::anthropic_model_id(model), "sending via Claude Code CLI (subscription)");

    let mut child = cmd.spawn()
        .context("failed to start `claude` CLI — is it installed?")?;

    let stdout = child.stdout.take()
        .context("failed to capture claude stdout")?;

    // Read streaming JSON lines from stdout.
    let tx_stream = tx.clone();
    let reader = async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut new_session_id: Option<String> = None;
        let mut sent_text = false;
        let mut failure = None;

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
                    if parsed["is_error"] == true {
                        failure = Some(parsed["result"].as_str().unwrap_or("Claude CLI request failed").to_owned());
                    }
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
        (new_session_id, failure)
    };

    // Both futures belong to this request. Cancelling it drops the child and
    // its reader, so no detached task can append to the next conversation.
    let (session, status) = tokio::join!(reader, child.wait());
    let status = status.context("Claude CLI exited unexpectedly")?;
    if let Some(failure) = session.1 { anyhow::bail!("{failure}"); }
    anyhow::ensure!(status.success(), "Claude CLI exited with {status}. Check 'claude auth status'.");
    if let Some(sid) = session.0 {
        *SESSION_ID.lock().unwrap_or_else(|e| e.into_inner()) = Some(sid);
    }

    Ok(())
}

const SYSTEM_PROMPT: &str = super::SYSTEM;

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
    model: &str,
    allow_changes: bool,
) -> Result<Vec<Value>> {
    let client = reqwest::Client::new();
    let model = crate::settings::anthropic_model_id(model);

    // Build the full system prompt with injected state context.
    let full_system = format!("{SYSTEM_PROMPT}\n\n## Current State\n{context}");

    // Append the new user message to the conversation history.
    messages.push(json!({ "role": "user", "content": user_text }));

    // Tool use loop — Claude may call tools and we feed results back.
    for _ in 0..12 {
        let body = json!({
            "model": model,
            "thinking": {"type": "disabled"},
            "max_tokens": MAX_TOKENS,
            "system": full_system,
            "tools": super::anthropic_tools(allow_changes),
            "messages": messages,
            "stream": true,
        });

        debug!(model, "Claude API request (streaming): {} messages", messages.len());

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
            anyhow::bail!("{}", api_error(status, &body, model));
        }

        // --- Stream SSE events ---
        let (content, stop_reason, tool_calls) =
            parse_stream(resp, tx).await?;

        // Always record the assistant response in history.
        if stop_reason != "tool_use" || tool_calls.is_empty() {
            messages.push(json!({ "role": "assistant", "content": content }));
            return Ok(messages);
        }

        // Execute tools and build tool_result messages.
        messages.push(json!({ "role": "assistant", "content": content }));

        let mut tool_results: Vec<Value> = Vec::new();
        for (id, name, input) in &tool_calls {
            let result = super::execute_tool(name, input, allow_changes).await;
            let (result_text, is_error) = match result {
                Ok(v) => (serde_json::to_string_pretty(&v).unwrap_or_default(), false),
                Err(e) => (format!("Error: {e}"), true),
            };

            // Show tool result in console (truncated).
            let preview = if result_text.len() > 500 {
                format!("{}…", result_text.chars().take(500).collect::<String>())
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

    anyhow::bail!("Tool limit reached. Review the results and send a follow-up to continue.")
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

    let mut parser = super::openai::Events::default();
    let mut completed = false;

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
        for event in parser.push(&chunk_result.context("stream read error")?)? {
            let event_type = event["type"].as_str().unwrap_or("");
            if event_type == "error" {
                anyhow::bail!("Anthropic stream error: {}", event["error"]["message"].as_str().unwrap_or("request failed"));
            }
            if event_type == "message_stop" { completed = true; }
            dispatch_sse_event(event_type, &event.to_string(), tx,
                &mut content_blocks, &mut current_text, &mut has_open_text_block,
                &mut tool_id, &mut tool_name, &mut tool_input_json, &mut in_tool_block,
                &mut stop_reason, &mut sent_prefix, &mut tool_calls)?;
        }
        if completed { break; }
    }
    anyhow::ensure!(completed && matches!(stop_reason.as_str(), "end_turn" | "tool_use" | "stop_sequence"),
        "Claude response was incomplete ({}). Retry or narrow the request.",
        if stop_reason.is_empty() { "stream ended early" } else { &stop_reason });
    anyhow::ensure!(!in_tool_block, "Claude tool arguments were incomplete; no commands were executed.");

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
) -> Result<()> {
    let parsed: Value = serde_json::from_str(data)?;

    match event_type {
        "content_block_start" => {
            let block_type = parsed["content_block"]["type"].as_str().unwrap_or("");
            if block_type == "text" {
                // Close any previous tool block.
                if *in_tool_block {
                    finalize_tool_block(
                        content_blocks, tool_id, tool_name, tool_input_json, tool_calls,
                    )?;
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
                )?;
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
    Ok(())
}

/// Finalize a tool_use content block and record it for execution.
fn finalize_tool_block(
    content_blocks: &mut Vec<Value>,
    tool_id: &mut String,
    tool_name: &mut String,
    tool_input_json: &mut String,
    tool_calls: &mut Vec<(String, String, Value)>,
) -> Result<()> {
    let input: Value = if tool_input_json.is_empty() { json!({}) }
        else { serde_json::from_str(tool_input_json).context("Invalid Claude tool arguments; no command was executed")? };
    anyhow::ensure!(input.is_object(), "Tool arguments must be a JSON object");
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_overrides_old_cli_models_and_respects_explicit_model_choices() {
        for (configured, expected) in [("claude-sonnet-4-20250514", "claude-sonnet-5"), ("", "claude-sonnet-5"), (" custom-model ", "custom-model")] {
            let command = subscription_command(configured);
            let args: Vec<_> = command.as_std().get_args().map(|a| a.to_str().unwrap()).collect();
            let models: Vec<_> = args.windows(2).filter(|a| a[0] == "--model").map(|a| a[1]).collect();
            assert_eq!(models, [expected]);
            assert!(args.windows(2).any(|a| a == ["--tools", ""]));
            assert!(args.windows(2).any(|a| a == ["--permission-prompts", "none"]));
        }
    }

    #[tokio::test]
    async fn incomplete_and_failed_streams_are_not_successful_answers() {
        let (tx, _rx) = mpsc::channel();
        for body in [
            "data: {\"type\":\"message_start\"}\n\n",
            "data: {\"type\":\"error\",\"error\":{\"message\":\"overloaded\"}}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            assert!(parse_stream(super::super::tests::response(body).await, &tx).await.is_err());
        }
    }

    #[tokio::test]
    async fn complete_tool_stream_preserves_arguments_and_stop_reason() {
        let events = [
            json!({"type":"content_block_start","content_block":{"type":"tool_use","id":"call1","name":"findings_list"}}),
            json!({"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"{\"scope\":\"Blåbær\"}"}}),
            json!({"type":"content_block_stop"}),
            json!({"type":"message_delta","delta":{"stop_reason":"tool_use"}}),
            json!({"type":"message_stop"}),
        ];
        let body = events.iter().map(|e|format!("data: {e}\n\n")).collect::<String>();
        let (tx, _rx) = mpsc::channel();
        let (_, reason, calls) = parse_stream(super::super::tests::response(&body).await, &tx).await.unwrap();
        assert_eq!(reason, "tool_use");
        assert_eq!(calls, vec![("call1".into(), "findings_list".into(), json!({"scope":"Blåbær"}))]);
    }
}
