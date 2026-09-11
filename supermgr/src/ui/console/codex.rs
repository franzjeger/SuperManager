//! Codex CLI adapter. Reuses CLI login; never reads or copies auth tokens.

use crate::app::AppMsg;
use anyhow::{bail, Context as _};
use serde_json::{json, Value};
use std::sync::mpsc;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

pub async fn send(
    text: &str,
    tx: &mpsc::Sender<AppMsg>,
    mut history: Vec<Value>,
    context: &str,
    allow_changes: bool,
) -> anyhow::Result<Vec<Value>> {
    run(text, tx, &mut history, context, allow_changes, true).await?;
    Ok(history)
}

pub async fn generate(prompt: &str, system: &str) -> anyhow::Result<String> {
    let (tx, _rx) = mpsc::channel();
    let mut history = Vec::new();
    run(prompt, &tx, &mut history, system, false, false).await?;
    history
        .last()
        .and_then(|m| m["content"].as_str())
        .map(str::to_owned)
        .context("Codex returned no configuration")
}

async fn run(
    text: &str,
    tx: &mpsc::Sender<AppMsg>,
    history: &mut Vec<Value>,
    context: &str,
    allow_changes: bool,
    with_tools: bool,
) -> anyhow::Result<()> {
    let workspace = tempfile::tempdir().context("Create console workspace")?;
    let mut prompt = format!("{context}\n\nConversation:\n");
    for message in history.iter() {
        if let (Some(role), Some(content)) = (message["role"].as_str(), message["content"].as_str())
        {
            prompt.push_str(&format!("{role}: {content}\n"));
        }
    }
    prompt.push_str(&format!("user: {text}"));
    let mut command = tokio::process::Command::new("codex");
    command.args([
        "exec",
        "--json",
        "--ephemeral",
        "--skip-git-repo-check",
        "--ignore-user-config",
        "--ignore-rules",
        "--sandbox",
        "read-only",
        "--disable",
        "shell_tool",
        "--disable",
        "plugins",
        "-c",
        "approval_policy=\"never\"",
        "--color",
        "never",
    ]);
    if with_tools {
        command
            .arg("-c")
            .arg(format!(
                "mcp_servers.supermgr.command={}",
                json!(super::claude::mcp_binary_path())
            ))
            .arg("-c")
            .arg("mcp_servers.supermgr.required=true")
            .arg("-c")
            .arg("mcp_servers.supermgr.default_tools_approval_mode=\"approve\"")
            .arg("-c")
            .arg(format!(
                "mcp_servers.supermgr.enabled_tools={}",
                json!(supermgr_mcp::available_tools(allow_changes)
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| t["name"].clone())
                    .collect::<Vec<_>>())
            ));
        if !allow_changes {
            command.arg("-c")
                .arg("mcp_servers.supermgr.env.SUPERMGR_MCP_READ_ONLY=\"1\"");
        }
    }
    command
        .arg("-")
        .current_dir(workspace.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    if !allow_changes {
        command.env("SUPERMGR_MCP_READ_ONLY", "1");
    } else {
        command.env_remove("SUPERMGR_MCP_READ_ONLY");
    }
    let mut child = command.spawn().context("Could not start Codex. Install the Codex CLI and run 'codex login' with your ChatGPT account.")?;
    let mut stdin = child.stdin.take().context("Codex input unavailable")?;
    stdin.write_all(prompt.as_bytes()).await?;
    drop(stdin);
    let mut lines =
        BufReader::new(child.stdout.take().context("Codex output unavailable")?).lines();
    let mut answer = String::new();
    while let Some(line) = lines.next_line().await? {
        let Ok(event) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        match event["type"].as_str() {
            Some("item.completed") if event["item"]["type"] == "agent_message" => {
                if let Some(text) = event["item"]["text"].as_str() {
                    let _ = tx.send(AppMsg::ConsoleResponse(format!("\nCodex: {text}\n")));
                    answer.push_str(text);
                    answer.push('\n');
                }
            }
            Some("item.started") if event["item"]["type"] == "mcp_tool_call" => {
                let name = event["item"]["tool"].as_str().unwrap_or("SuperManager");
                let _ = tx.send(AppMsg::ConsoleResponse(format!("\nUsing {name}…\n")));
            }
            Some("turn.failed" | "error") => {
                bail!(
                    "Codex: {}",
                    event["error"]["message"]
                        .as_str()
                        .or_else(|| event["message"].as_str())
                        .unwrap_or("request failed; check 'codex login status'")
                );
            }
            _ => {}
        }
    }
    let status = child.wait().await?;
    anyhow::ensure!(status.success(), "Codex exited with {status}. Check 'codex login status' and update the CLI if its flags are unsupported.");
    anyhow::ensure!(!answer.trim().is_empty(), "Codex returned no answer.");
    history.push(json!({"role":"user","content":text}));
    history.push(json!({"role":"assistant","content":answer}));
    Ok(())
}
