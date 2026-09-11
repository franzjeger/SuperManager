//! OpenAI Responses streaming and local function-call dispatch.

use crate::{app::AppMsg, settings::AppSettings};
use anyhow::{bail, Context as _};
use futures_util::StreamExt as _;
use serde_json::{json, Value};
use std::sync::mpsc;

fn tools(allow_changes: bool) -> Vec<Value> {
    supermgr_mcp::available_tools(allow_changes)
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| {
            json!({
                "type":"function", "name":tool["name"], "description":tool["description"],
                "parameters":tool["inputSchema"], "strict":false,
            })
        })
        .collect()
}

pub async fn send(
    settings: &AppSettings,
    text: &str,
    tx: &mpsc::Sender<AppMsg>,
    mut history: Vec<Value>,
    context: &str,
    allow_changes: bool,
) -> anyhow::Result<Vec<Value>> {
    history.push(json!({"role":"user","content":text}));
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()?;
    for _ in 0..12 {
        let response = client
            .post("https://api.openai.com/v1/responses")
            .bearer_auth(&settings.openai_api_key)
            .json(&json!({
                "model":settings.openai_model, "instructions":context, "input":history,
                "tools":tools(allow_changes), "stream":true, "store":false,
                "include":["reasoning.encrypted_content"], "max_output_tokens":8192,
            }))
            .send()
            .await
            .context("OpenAI request failed")?;
        if !response.status().is_success() {
            let status = response.status();
            let body: Value = response.json().await.unwrap_or(Value::Null);
            let message = body["error"]["message"]
                .as_str()
                .unwrap_or("Request rejected");
            if status == reqwest::StatusCode::NOT_FOUND {
                bail!("OpenAI model '{}' is unavailable. Choose an accessible model in Settings → AI. {message}", settings.openai_model);
            }
            bail!("OpenAI API error {status}: {message}");
        }
        let _ = tx.send(AppMsg::ConsoleStreamChunk("\nOpenAI: ".into()));
        let output = read_response(response, tx).await?;
        history.extend(output.iter().cloned());
        let calls: Vec<_> = output
            .iter()
            .filter(|item| item["type"] == "function_call")
            .collect();
        if calls.is_empty() {
            return Ok(history);
        }
        for call in calls {
            let name = call["name"].as_str().context("Tool call has no name")?;
            let call_id = call["call_id"].as_str().context("Tool call has no ID")?;
            let args: Value = serde_json::from_str(call["arguments"].as_str().unwrap_or("{}"))
                .context("Invalid tool arguments")?;
            let _ = tx.send(AppMsg::ConsoleResponse(format!("\nUsing {name}…\n")));
            let result = super::execute_tool(name, &args, allow_changes).await;
            let output = match result {
                Ok(value) => serde_json::to_string(&value)?,
                Err(e) => json!({"error":e.to_string()}).to_string(),
            };
            history.push(json!({"type":"function_call_output","call_id":call_id,"output":output}));
        }
    }
    bail!("Tool limit reached. Review the results and send a follow-up to continue.")
}

/// Buffer raw bytes until a complete SSE line exists, so network packets can
/// split UTF-8 characters, JSON values and CRLF endings without corrupting them.
#[derive(Default)]
pub(super) struct Events {
    pending: Vec<u8>,
    data: Vec<String>,
}

impl Events {
    pub(super) fn push(&mut self, bytes: &[u8]) -> anyhow::Result<Vec<Value>> {
        self.pending.extend_from_slice(bytes);
        anyhow::ensure!(
            self.pending.len() < 16 * 1024 * 1024,
            "Response event exceeded 16 MB"
        );
        let mut events = Vec::new();
        while let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
            let line = self.pending.drain(..=end).collect::<Vec<_>>();
            let line = std::str::from_utf8(&line)?.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                if !self.data.is_empty() {
                    let data = self.data.join("\n");
                    self.data.clear();
                    if data != "[DONE]" {
                        events.push(serde_json::from_str(&data)?);
                    }
                }
            } else if let Some(data) = line.strip_prefix("data:") {
                self.data
                    .push(data.strip_prefix(' ').unwrap_or(data).into());
            }
        }
        Ok(events)
    }
}

async fn read_response(
    response: reqwest::Response,
    tx: &mpsc::Sender<AppMsg>,
) -> anyhow::Result<Vec<Value>> {
    let mut stream = response.bytes_stream();
    let mut parser = Events::default();
    while let Some(bytes) = stream.next().await {
        for event in parser.push(&bytes?)? {
            match event["type"].as_str() {
                Some("response.output_text.delta" | "response.refusal.delta") => {
                    if let Some(text) = event["delta"].as_str() {
                        let _ = tx.send(AppMsg::ConsoleStreamChunk(text.into()));
                    }
                }
                Some("response.completed") => {
                    return event["response"]["output"]
                        .as_array()
                        .cloned()
                        .context("OpenAI completed without response output")
                }
                Some("response.failed" | "response.incomplete" | "error") => {
                    bail!(
                        "OpenAI could not complete the response: {}",
                        event["response"]["error"]["message"]
                            .as_str()
                            .or_else(|| event["message"].as_str())
                            .or_else(|| event["response"]["incomplete_details"]["reason"].as_str())
                            .unwrap_or("response failed")
                    );
                }
                _ => {}
            }
        }
    }
    bail!("The OpenAI stream ended before completion. Retry the request.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_survives_every_byte_boundary_including_unicode() {
        let wire = "event: response.output_text.delta\r\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Blåbær 🌍\"}\r\n\r\ndata: [DONE]\n\n";
        let mut parser = Events::default();
        let mut events = Vec::new();
        for byte in wire.bytes() {
            events.extend(parser.push(&[byte]).unwrap());
        }
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["delta"], "Blåbær 🌍");
    }

    #[test]
    fn api_tool_names_match_the_mcp_catalog() {
        assert_eq!(
            tools(true).len(),
            supermgr_mcp::tool_definitions().as_array().unwrap().len()
        );
        assert!(tools(false)
            .iter()
            .all(|t| supermgr_mcp::is_read_only(t["name"].as_str().unwrap())));
    }

    #[tokio::test]
    async fn incomplete_streams_fail_and_complete_streams_retain_tool_calls() {
        let (tx, _rx) = mpsc::channel();
        for body in ["", "data: {\"type\":\"response.incomplete\"}\n\n"] {
            assert!(
                read_response(super::super::tests::response(body).await, &tx)
                    .await
                    .is_err()
            );
        }
        let output = json!([
            {"type":"reasoning","id":"r1","encrypted_content":"opaque","summary":[]},
            {"type":"function_call","call_id":"c1","name":"findings_list","arguments":"{\"scope\":\"Oslo\"}"}
        ]);
        let body = format!(
            "data: {}\n\n",
            json!({"type":"response.completed","response":{"output":output}})
        );
        assert_eq!(
            read_response(super::super::tests::response(&body).await, &tx)
                .await
                .unwrap(),
            output.as_array().unwrap().clone()
        );
    }
}

/// Generate an editable draft without giving the model any operational tools.
pub async fn generate(
    settings: &AppSettings,
    prompt: &str,
    system: &str,
) -> anyhow::Result<String> {
    anyhow::ensure!(
        !settings.openai_api_key.trim().is_empty(),
        "Add an OpenAI API key in Settings → AI."
    );
    let response = reqwest::Client::new().post("https://api.openai.com/v1/responses")
        .bearer_auth(&settings.openai_api_key)
        .json(&json!({"model":settings.openai_model,"instructions":system,"input":prompt,"store":false,"max_output_tokens":16384}))
        .send().await?;
    let status = response.status();
    let body: Value = response.json().await?;
    anyhow::ensure!(
        status.is_success(),
        "OpenAI API error {status}: {}",
        body["error"]["message"]
            .as_str()
            .unwrap_or("request rejected")
    );
    anyhow::ensure!(
        body["status"] == "completed",
        "OpenAI draft was incomplete; no deployable configuration was produced."
    );
    let text = body["output"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| item["type"] == "message")
        .flat_map(|item| item["content"].as_array().into_iter().flatten())
        .filter_map(|part| part["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    anyhow::ensure!(!text.trim().is_empty(), "OpenAI returned no configuration.");
    Ok(text)
}
