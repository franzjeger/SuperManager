//! `supermgr-mcp` — MCP (Model Context Protocol) server for SuperManager.
//!
//! Exposes SSH and VPN operations as tools that Claude Code can invoke.
//! Communicates with the `supermgrd` daemon via D-Bus on the system bus.
//!
//! # Transport
//!
//! JSON-RPC 2.0 over stdin/stdout (MCP stdio transport).

use std::io::{self, BufRead, Write as _};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, error, info};

use supermgr_core::dbus::DaemonProxy;

// ---------------------------------------------------------------------------
// JSON-RPC types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct JsonRpcRequest {
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

fn tool_definitions() -> Value {
    json!([
        {
            "name": "ssh_list_hosts",
            "description": "List all configured SSH hosts with their connection details (hostname, port, username, device type, auth method).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "ssh_list_keys",
            "description": "List all managed SSH keys with their type, fingerprint, and deployment status.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "ssh_execute",
            "description": "Execute a shell command on a remote SSH host managed by SuperManager. The host must be configured and reachable (VPN must be active if the host is behind one). Returns stdout, stderr, and exit code.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "UUID of the target SSH host (from ssh_list_hosts)"
                    },
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute on the remote host"
                    }
                },
                "required": ["host_id", "command"]
            }
        },
        {
            "name": "vpn_status",
            "description": "Get the current VPN connection status (connected/disconnected, active profile, tunnel stats).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "vpn_list_profiles",
            "description": "List all configured VPN profiles with their backend type and connection state.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "vpn_connect",
            "description": "Connect to a VPN profile by UUID. Returns immediately; the connection is established asynchronously.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "profile_id": {
                        "type": "string",
                        "description": "UUID of the VPN profile to connect"
                    }
                },
                "required": ["profile_id"]
            }
        },
        {
            "name": "vpn_disconnect",
            "description": "Disconnect the currently active VPN connection.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "ssh_add_host",
            "description": "Add a new SSH host configuration.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "label": { "type": "string", "description": "Display name" },
                    "hostname": { "type": "string", "description": "Hostname or IP" },
                    "port": { "type": "integer", "description": "SSH port (default 22)" },
                    "username": { "type": "string", "description": "Login username" },
                    "group": { "type": "string", "description": "Logical group (optional)" },
                    "device_type": { "type": "string", "description": "linux, uni_fi, pf_sense, open_wrt, fortigate, windows" },
                    "auth_method": { "type": "string", "description": "key or password" },
                    "auth_key_id": { "type": "string", "description": "UUID of SSH key (for key auth)" }
                },
                "required": ["label", "hostname", "username", "auth_method"]
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

async fn execute_tool(proxy: &DaemonProxy<'_>, name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "ssh_list_hosts" => {
            let json_str = proxy.ssh_list_hosts().await.map_err(|e| e.to_string())?;
            let hosts: Value = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
            Ok(hosts)
        }
        "ssh_list_keys" => {
            let json_str = proxy.ssh_list_keys().await.map_err(|e| e.to_string())?;
            let keys: Value = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
            Ok(keys)
        }
        "ssh_execute" => {
            let host_id = args.get("host_id").and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let command = args.get("command").and_then(|v| v.as_str())
                .ok_or("missing command")?;
            let result = proxy.ssh_execute_command(host_id, command).await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "vpn_status" => {
            let json_str = proxy.get_status().await.map_err(|e| e.to_string())?;
            let status: Value = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
            Ok(status)
        }
        "vpn_list_profiles" => {
            let json_str = proxy.list_profiles().await.map_err(|e| e.to_string())?;
            let profiles: Value = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
            Ok(profiles)
        }
        "vpn_connect" => {
            let profile_id = args.get("profile_id").and_then(|v| v.as_str())
                .ok_or("missing profile_id")?;
            proxy.connect(profile_id).await.map_err(|e| e.to_string())?;
            Ok(json!({ "status": "connecting", "profile_id": profile_id }))
        }
        "vpn_disconnect" => {
            proxy.disconnect().await.map_err(|e| e.to_string())?;
            Ok(json!({ "status": "disconnecting" }))
        }
        "ssh_add_host" => {
            let host_json = json!({
                "label": args.get("label").and_then(|v| v.as_str()).unwrap_or(""),
                "hostname": args.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
                "port": args.get("port").and_then(|v| v.as_u64()).unwrap_or(22),
                "username": args.get("username").and_then(|v| v.as_str()).unwrap_or("root"),
                "group": args.get("group").and_then(|v| v.as_str()).unwrap_or(""),
                "device_type": args.get("device_type").and_then(|v| v.as_str()).unwrap_or("linux"),
                "auth_method": args.get("auth_method").and_then(|v| v.as_str()).unwrap_or("password"),
                "auth_key_id": args.get("auth_key_id"),
            });
            let id = proxy.ssh_add_host(&host_json.to_string()).await
                .map_err(|e| e.to_string())?;
            Ok(json!({ "id": id, "status": "created" }))
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

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
        result: Some(json!({ "tools": tool_definitions() })),
        error: None,
    }
}

async fn handle_tools_call(
    proxy: &DaemonProxy<'_>,
    id: &Value,
    params: &Value,
) -> JsonRpcResponse {
    let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    debug!("tool call: {tool_name} args={arguments}");

    match execute_tool(proxy, tool_name, &arguments).await {
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

    let conn = zbus::Connection::system()
        .await
        .context("D-Bus system connection failed — is supermgrd running?")?;
    let proxy = DaemonProxy::new(&conn)
        .await
        .context("failed to create DaemonProxy")?;

    info!("connected to supermgrd via D-Bus");

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
