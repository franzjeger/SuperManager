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
        },
        {
            "name": "ssh_test_connection",
            "description": "Test SSH and (optionally) FortiGate API connectivity for a host. Returns a JSON object like {\"ssh\": \"ok\", \"api\": \"ok\"} or {\"ssh\": \"timeout\", \"api\": \"auth_failed\"}.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "UUID of the SSH host to test"
                    }
                },
                "required": ["host_id"]
            }
        },
        {
            "name": "ssh_toggle_pin",
            "description": "Pin or unpin an SSH host (toggle its favourite/pinned state). Returns the refreshed host list.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "UUID of the SSH host to pin/unpin"
                    }
                },
                "required": ["host_id"]
            }
        },
        {
            "name": "ssh_set_password",
            "description": "Store an SSH password for a host in the secret store. Used for password-based authentication.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "UUID of the SSH host"
                    },
                    "password": {
                        "type": "string",
                        "description": "SSH password to store"
                    }
                },
                "required": ["host_id", "password"]
            }
        },
        {
            "name": "ssh_set_api_token",
            "description": "Store a FortiGate REST API token and optional port for a host. Pass port 0 to keep the existing port.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "UUID of the FortiGate host"
                    },
                    "token": {
                        "type": "string",
                        "description": "FortiGate REST API token"
                    },
                    "port": {
                        "type": "integer",
                        "description": "API port (default 0 to keep existing)"
                    }
                },
                "required": ["host_id", "token"]
            }
        },
        {
            "name": "unifi_set_inform",
            "description": "Execute set-inform on a UniFi device via SSH. Tells the device to adopt to the given controller URL.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "UUID of the UniFi device host"
                    },
                    "inform_url": {
                        "type": "string",
                        "description": "Controller inform URL (e.g. http://controller:8080/inform)"
                    }
                },
                "required": ["host_id", "inform_url"]
            }
        },
        {
            "name": "unifi_api",
            "description": "Call the UniFi Controller REST API on a host. Requires controller credentials to be configured via unifi_set_controller first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "UUID of the UniFi host with controller credentials"
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method: GET, POST, PUT, or DELETE"
                    },
                    "path": {
                        "type": "string",
                        "description": "API path (e.g. /proxy/network/api/s/default/stat/device)"
                    },
                    "body": {
                        "type": "string",
                        "description": "Optional JSON request body (empty string for none)"
                    }
                },
                "required": ["host_id", "method", "path"]
            }
        },
        {
            "name": "fortigate_push_ssh_key",
            "description": "Push an SSH public key to a FortiGate admin user via REST API. The host must have an API token configured.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "UUID of the FortiGate host with API token configured"
                    },
                    "key_id": {
                        "type": "string",
                        "description": "UUID of the SSH key whose public key will be pushed"
                    },
                    "admin_user": {
                        "type": "string",
                        "description": "FortiGate admin username (e.g. admin)"
                    }
                },
                "required": ["host_id", "key_id", "admin_user"]
            }
        },
        {
            "name": "fortigate_backup_config",
            "description": "Download the FortiGate running configuration and save it to disk. Returns the backup filename on success.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "UUID of the FortiGate host with API token configured"
                    }
                },
                "required": ["host_id"]
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
        "ssh_test_connection" => {
            let host_id = args.get("host_id").and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let result = proxy.ssh_test_connection(host_id).await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "ssh_toggle_pin" => {
            let host_id = args.get("host_id").and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let result = proxy.ssh_toggle_pin(host_id).await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "ssh_set_password" => {
            let host_id = args.get("host_id").and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let password = args.get("password").and_then(|v| v.as_str())
                .ok_or("missing password")?;
            proxy.ssh_set_password(host_id, password).await
                .map_err(|e| e.to_string())?;
            Ok(json!({ "status": "ok", "host_id": host_id }))
        }
        "ssh_set_api_token" => {
            let host_id = args.get("host_id").and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let token = args.get("token").and_then(|v| v.as_str())
                .ok_or("missing token")?;
            let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            proxy.ssh_set_api_token(host_id, token, port).await
                .map_err(|e| e.to_string())?;
            Ok(json!({ "status": "ok", "host_id": host_id }))
        }
        "unifi_set_inform" => {
            let host_id = args.get("host_id").and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let inform_url = args.get("inform_url").and_then(|v| v.as_str())
                .ok_or("missing inform_url")?;
            let result = proxy.unifi_set_inform(host_id, inform_url).await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "unifi_api" => {
            let host_id = args.get("host_id").and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let method = args.get("method").and_then(|v| v.as_str())
                .ok_or("missing method")?;
            let path = args.get("path").and_then(|v| v.as_str())
                .ok_or("missing path")?;
            let body = args.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let result = proxy.unifi_api(host_id, method, path, body).await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "fortigate_push_ssh_key" => {
            let host_id = args.get("host_id").and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let key_id = args.get("key_id").and_then(|v| v.as_str())
                .ok_or("missing key_id")?;
            let admin_user = args.get("admin_user").and_then(|v| v.as_str())
                .ok_or("missing admin_user")?;
            let result = proxy.fortigate_push_ssh_key(host_id, key_id, admin_user).await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "fortigate_backup_config" => {
            let host_id = args.get("host_id").and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let filename = proxy.fortigate_backup_config(host_id).await
                .map_err(|e| e.to_string())?;
            Ok(json!({ "status": "ok", "filename": filename }))
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
