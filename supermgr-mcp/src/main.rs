//! `supermgr-mcp` — MCP (Model Context Protocol) server for SuperManager.
//!
//! Exposes SSH and VPN operations as tools that Claude Code can invoke.
//! Communicates with the local daemon over the platform-appropriate
//! transport: D-Bus on Linux (`supermgrd`), named pipes on Windows
//! (`supermgrd-win`). Both transports are reached via the
//! [`supermgr_core::client::DaemonClient`] alias.
//!
//! # Transport
//!
//! JSON-RPC 2.0 over stdin/stdout (MCP stdio transport).

use std::io::{self, BufRead, Write as _};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, error, info};

use supermgr_core::client::{self, DaemonClient};
use supermgr_mcp::execute_tool;
#[cfg(test)]
use supermgr_mcp::tool_definitions;

// ---------------------------------------------------------------------------
// JSON-RPC types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// MCP message handlers
// ---------------------------------------------------------------------------

fn handle_initialize(id: &Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: id.clone(),
        result: Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "supermgr-mcp",
                "version": env!("CARGO_PKG_VERSION")
            }
        })),
        error: None,
    }
}

fn handle_tools_list(id: &Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: id.clone(),
        result: Some(json!({ "tools": supermgr_mcp::available_tools(std::env::var_os("SUPERMGR_MCP_READ_ONLY").is_none()) })),
        error: None,
    }
}

async fn handle_tools_call(
    proxy: &DaemonClient,
    id: &Value,
    params: &Value,
) -> JsonRpcResponse {
    let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    debug!("tool call: {tool_name}");

    let result = if std::env::var_os("SUPERMGR_MCP_READ_ONLY").is_some()
        && !supermgr_mcp::is_read_only(tool_name)
    {
        Err("This console session is read-only. Enable Allow changes to use this tool.".into())
    } else {
        execute_tool(proxy, tool_name, &arguments).await
    };
    match result {
        Ok(result) => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: id.clone(),
            result: Some(json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                }]
            })),
            error: None,
        },
        Err(e) => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: id.clone(),
            result: Some(json!({
                "content": [{
                    "type": "text",
                    "text": format!("Error: {e}")
                }],
                "isError": true
            })),
            error: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Log to stderr so stdout stays clean for JSON-RPC.
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("supermgr-mcp starting");

    let proxy = client::connect()
        .await
        .map_err(anyhow::Error::msg)?;

    info!("connected to supermgrd");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => l,
            Err(e) => {
                error!("stdin read error: {e}");
                break;
            }
        };

        let req: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                error!("invalid JSON-RPC: {e}");
                continue;
            }
        };

        let id = req.id.clone().unwrap_or(Value::Null);

        let response = match req.method.as_str() {
            "initialize" => handle_initialize(&id),
            "notifications/initialized" => continue, // notification, no response
            "tools/list" => handle_tools_list(&id),
            "tools/call" => handle_tools_call(&proxy, &id, &req.params).await,
            "ping" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(json!({})),
                error: None,
            },
            method => {
                debug!("unhandled method: {method}");
                // Notifications (no id) don't get responses.
                if req.id.is_none() {
                    continue;
                }
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32601,
                        message: format!("method not found: {method}"),
                    }),
                }
            }
        };

        let out = serde_json::to_string(&response).unwrap();
        writeln!(stdout, "{out}")?;
        stdout.flush()?;
    }

    info!("supermgr-mcp shutting down");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Every tool this server advertises, by name.
    fn advertised_tool_names() -> Vec<String> {
        tool_definitions()
            .as_array()
            .expect("tool_definitions is a JSON array")
            .iter()
            .map(|t| {
                t.get("name")
                    .and_then(Value::as_str)
                    .expect("every tool has a name")
                    .to_owned()
            })
            .collect()
    }

    // -- the contract a client relies on ------------------------------------

    #[test]
    fn every_tool_carries_what_a_client_needs_to_call_it() {
        // A tool missing any of these is advertised but unusable: the
        // client has nothing to render and no schema to validate against.
        for tool in tool_definitions().as_array().expect("array") {
            let name = tool.get("name").and_then(Value::as_str);
            assert!(name.is_some_and(|n| !n.is_empty()), "tool without a name: {tool}");
            let name = name.unwrap();

            let description = tool.get("description").and_then(Value::as_str);
            assert!(
                description.is_some_and(|d| !d.is_empty()),
                "{name} has no description — the model picks tools by reading these"
            );

            assert!(
                tool.get("inputSchema").is_some_and(Value::is_object),
                "{name} has no inputSchema object"
            );
        }
    }

    #[test]
    fn tool_names_are_unique() {
        // Duplicates mean one silently shadows the other in dispatch.
        let mut names = advertised_tool_names();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate tool name in tool_definitions");
    }

    #[test]
    fn input_schemas_are_json_schema_objects() {
        for tool in tool_definitions().as_array().expect("array") {
            let name = tool["name"].as_str().unwrap_or("<unnamed>");
            let schema = &tool["inputSchema"];
            assert_eq!(
                schema.get("type").and_then(Value::as_str),
                Some("object"),
                "{name}: inputSchema must be type=object"
            );
            assert!(
                schema.get("properties").is_some_and(Value::is_object),
                "{name}: inputSchema needs a properties object, even when empty"
            );
        }
    }

    #[test]
    fn every_required_parameter_is_actually_declared() {
        // Naming a required parameter that isn't in `properties` gives the
        // model a field it cannot see how to fill — it will either omit it
        // and fail validation, or invent a shape.
        for tool in tool_definitions().as_array().expect("array") {
            let name = tool["name"].as_str().unwrap_or("<unnamed>");
            let schema = &tool["inputSchema"];
            let properties = schema["properties"].as_object().expect("properties object");

            let Some(required) = schema.get("required").and_then(Value::as_array) else {
                continue;
            };
            for entry in required {
                let field = entry.as_str().expect("required entries are strings");
                assert!(
                    properties.contains_key(field),
                    "{name}: '{field}' is required but not declared in properties"
                );
            }
        }
    }

    #[test]
    fn every_property_describes_itself() {
        for tool in tool_definitions().as_array().expect("array") {
            let name = tool["name"].as_str().unwrap_or("<unnamed>");
            for (field, spec) in tool["inputSchema"]["properties"]
                .as_object()
                .expect("properties object")
            {
                assert!(
                    spec.get("type").is_some(),
                    "{name}.{field} has no type — nothing tells the model what to send"
                );
                assert!(
                    spec.get("description").and_then(Value::as_str).is_some_and(|d| !d.is_empty()),
                    "{name}.{field} has no description"
                );
            }
        }
    }

    /// Advertising a tool the dispatcher doesn't handle is a call that fails
    /// at use; handling one that isn't advertised makes it unreachable. The
    /// two lists are written far apart in this file and nothing but this
    /// test keeps them together.
    #[test]
    fn advertised_tools_and_dispatched_tools_are_the_same_set() {
        let source = include_str!("lib.rs");
        // Bound this to `execute_tool` itself. Taking everything after it
        // also picks up the main loop's `"initialize" =>` method dispatch,
        // which is a different match on a different string.
        let dispatch_body = source
            .split("async fn execute_tool")
            .nth(1)
            .expect("execute_tool present")
            .split("\nfn handle_initialize")
            .next()
            .expect("execute_tool is followed by handle_initialize");

        for name in advertised_tool_names() {
            assert!(
                dispatch_body.contains(&format!("\"{name}\" =>")),
                "'{name}' is advertised by tool_definitions but has no arm in execute_tool"
            );
        }

        // And the other direction: every arm corresponds to something we
        // advertise. The catch-all `unknown` arm is excluded by construction
        // since it doesn't match the `"name" =>` shape.
        let advertised = advertised_tool_names();
        let mut linux_only = false;
        for line in dispatch_body.lines() {
            if line.trim() == "#[cfg(target_os = \"linux\")]" { linux_only = true; continue; }
            if linux_only && !cfg!(target_os = "linux") { linux_only = false; continue; }
            linux_only = false;
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix('"') else {
                continue;
            };
            let Some((name, tail)) = rest.split_once('"') else {
                continue;
            };
            if !tail.trim_start().starts_with("=>") {
                continue;
            }
            assert!(
                advertised.contains(&name.to_owned()),
                "execute_tool handles '{name}' but tool_definitions never advertises it"
            );
        }
    }

    // -- MCP handshake ------------------------------------------------------

    #[test]
    fn initialize_reports_a_protocol_version_and_identifies_the_server() {
        let response = handle_initialize(&json!(1));
        let result = response.result.expect("initialize returns a result");
        assert!(response.error.is_none());
        assert_eq!(response.id, json!(1), "the request id must come back unchanged");
        assert!(
            result["protocolVersion"].as_str().is_some_and(|v| !v.is_empty()),
            "a client with no protocolVersion cannot negotiate"
        );
        assert_eq!(result["serverInfo"]["name"], json!("supermgr-mcp"));
        assert_eq!(
            result["serverInfo"]["version"],
            json!(env!("CARGO_PKG_VERSION")),
            "serverInfo should report the crate version, not a literal"
        );
        assert!(
            result["capabilities"].get("tools").is_some(),
            "tools capability must be declared or the client won't call tools/list"
        );
    }

    #[test]
    fn tools_list_returns_every_advertised_tool() {
        let response = handle_tools_list(&json!("abc"));
        assert_eq!(response.id, json!("abc"), "string ids round-trip too");
        let tools = response.result.expect("result")["tools"]
            .as_array()
            .expect("tools array")
            .len();
        assert_eq!(tools, advertised_tool_names().len());
    }

    // -- JSON-RPC framing ---------------------------------------------------

    #[test]
    fn responses_serialise_without_null_result_or_error_fields() {
        // `result: null` alongside an error is a protocol violation; the
        // skip_serializing_if attributes are what prevent it, and they are
        // easy to drop in a refactor.
        let ok = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: json!(7),
            result: Some(json!({"ok": true})),
            error: None,
        };
        let encoded = serde_json::to_value(&ok).expect("serialise");
        assert_eq!(encoded["jsonrpc"], json!("2.0"));
        assert!(encoded.get("error").is_none(), "no error key on a success");

        let err = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: json!(7),
            result: None,
            error: Some(JsonRpcError { code: -32601, message: "nope".into() }),
        };
        let encoded = serde_json::to_value(&err).expect("serialise");
        assert!(encoded.get("result").is_none(), "no result key on a failure");
        assert_eq!(encoded["error"]["code"], json!(-32601));
    }

    #[test]
    fn a_request_without_params_parses_with_an_empty_value() {
        // `params` is optional in JSON-RPC and MCP clients omit it for
        // initialize; without the serde default this fails to parse and the
        // handshake never completes.
        let request: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#)
                .expect("parses without params");
        assert_eq!(request.method, "initialize");
        assert!(request.params.is_null());
    }

    #[test]
    fn a_notification_has_no_id() {
        // Notifications carry no id and must not be answered. The type has
        // to model that rather than failing to parse.
        let request: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .expect("notifications parse");
        assert!(request.id.is_none());
    }
}
