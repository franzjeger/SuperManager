//! Shared AI tools. Names and dispatch stay identical across providers.

use serde_json::{json, Value};
use supermgr_core::client::DaemonClient;

/// The canonical tool catalog used by MCP and both API providers.
pub fn tool_definitions() -> Value {
    let mut catalog = json!([
        {
            "name": "list_hosts",
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
                        "description": "UUID of the target SSH host (from list_hosts)"
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
            "name": "add_host",
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
            "name": "test_host_connection",
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
            "name": "toggle_host_pin",
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
    ]);
    #[cfg(target_os = "linux")]
    {
        let definitions = catalog.as_array_mut().expect("tool array");
        for (name, description, properties, required) in [
            ("customer_catalog", "Read the customer/site catalog and managed asset links.", json!({}), json!([])),
            ("host_health", "Read the daemon's last reachability result for managed hosts; this is not a new scan.", json!({}), json!([])),
            ("tailscale_health", "Read local Tailscale installation, service and login status.", json!({}), json!([])),
            ("tailscale_devices", "Read devices, IPs, traffic counters and reported connection metadata in the active tailnet. This does not ping peers.", json!({}), json!([])),
            ("tailscale_management", "Read saved Tailscale accounts and a safe projection of current network preferences. Missing preference values are unknown; no credentials are returned.", json!({}), json!([])),
            ("findings_scopes", "List exact identifiers of persisted findings scopes, including archived hosts and customers.", json!({}), json!([])),
            ("findings_summary", "Summarize stored security findings for one customer or host scope.", json!({"scope":{"type":"string","minLength":1,"description":"Exact scope identifier from findings_scopes. There is no all-scopes wildcard."}}), json!(["scope"])),
            ("findings_list", "Read stored security findings and dispositions. Does not discover new vulnerabilities.", json!({"scope":{"type":"string","minLength":1,"description":"Exact scope identifier from findings_scopes. There is no all-scopes wildcard."}}), json!(["scope"])),
            ("compliance_history", "Read previous Linux compliance runs for a managed host.", json!({"host_id":{"type":"string","description":"UUID of the managed host from list_hosts"}}), json!(["host_id"])),
            ("compliance_get_run", "Read checks and evidence from a stored compliance run.", json!({"host_id":{"type":"string","description":"UUID of the managed host from list_hosts"},"run_id":{"type":"string","description":"Stored run identifier from compliance_history"}}), json!(["host_id","run_id"])),
            ("compliance_list_checks", "List available Linux and FortiGate baseline checks, their scope and remediation.", json!({}), json!([])),
            ("fortigate_compliance_check", "Run the FortiGate configuration baseline over its API and store the findings. Requires operator-enabled actions.", json!({"host_id":{"type":"string","description":"UUID of the managed host from list_hosts"}}), json!(["host_id"])),
        ] {
            definitions.push(json!({"name":name,"description":description,"inputSchema":{
                "type":"object","properties":properties,"required":required
            }}));
        }
    }
    // This API is available on both Linux and Windows.
    catalog.as_array_mut().expect("tool array").push(json!({
        "name":"fortigate_api", "description":"Call a managed FortiGate REST API. Requires operator-enabled actions.",
        "inputSchema":{"type":"object","properties":{
            "host_id":{"type":"string","description":"UUID of the managed host from list_hosts"},"method":{"type":"string","description":"HTTP method to send","enum":["GET","POST","PUT","DELETE"]},
            "path":{"type":"string","description":"FortiGate REST API path, including query parameters if needed"},"body":{"type":"string","description":"Optional JSON-encoded request body"}
        },"required":["host_id","method","path"]}
    }));
    catalog
}

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

/// Execute a catalog tool through the platform daemon.
pub async fn execute_tool(proxy: &DaemonClient, name: &str, args: &Value) -> Result<Value, String> {
    match name {
        #[cfg(target_os = "linux")]
        "customer_catalog" => {
            parse_response(proxy.customer_catalog().await.map_err(|e| e.to_string())?)
        }
        #[cfg(target_os = "linux")]
        "host_health" => parse_response(proxy.ssh_host_health().await.map_err(|e| e.to_string())?),
        #[cfg(target_os = "linux")]
        "tailscale_health" => {
            let mut value =
                parse_response(proxy.tailscale_health().await.map_err(|e| e.to_string())?)?;
            if let Some(object) = value.as_object_mut() {
                object.remove("auth_url");
            }
            Ok(value)
        }
        #[cfg(target_os = "linux")]
        "tailscale_devices" => parse_response(proxy.tailscale_list_nodes().await.map_err(|e| e.to_string())?),
        #[cfg(target_os = "linux")]
        "tailscale_management" => parse_response(proxy.tailscale_management().await.map_err(|e| e.to_string())?),
        #[cfg(target_os = "linux")]
        "findings_scopes" => Ok(json!(proxy.findings_scopes().await.map_err(|e| e.to_string())?)),
        #[cfg(target_os = "linux")]
        "findings_summary" => parse_response(
            proxy
                .findings_summary(required_str(args, "scope")?)
                .await
                .map_err(|e| e.to_string())?,
        ),
        #[cfg(target_os = "linux")]
        "findings_list" => parse_response(
            proxy
                .findings_list(required_str(args, "scope")?)
                .await
                .map_err(|e| e.to_string())?,
        ),
        #[cfg(target_os = "linux")]
        "compliance_history" => parse_response(
            proxy
                .compliance_history(required_str(args, "host_id")?, 20)
                .await
                .map_err(|e| e.to_string())?,
        ),
        #[cfg(target_os = "linux")]
        "compliance_get_run" => parse_response(
            proxy
                .compliance_get_run(
                    required_str(args, "host_id")?,
                    required_str(args, "run_id")?,
                )
                .await
                .map_err(|e| e.to_string())?,
        ),
        #[cfg(target_os = "linux")]
        "compliance_list_checks" => parse_response(
            proxy
                .compliance_list_checks()
                .await
                .map_err(|e| e.to_string())?,
        ),
        #[cfg(target_os = "linux")]
        "fortigate_compliance_check" => parse_response(
            proxy
                .fortigate_compliance_check(required_str(args, "host_id")?)
                .await
                .map_err(|e| e.to_string())?,
        ),
        "fortigate_api" => parse_response(
            proxy
                .fortigate_api(
                    required_str(args, "host_id")?,
                    required_str(args, "method")?,
                    required_str(args, "path")?,
                    args["body"].as_str().unwrap_or(""),
                )
                .await
                .map_err(|e| e.to_string())?,
        ),

        "list_hosts" => {
            let json_str = proxy.list_hosts().await.map_err(|e| e.to_string())?;
            let hosts: Value = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
            Ok(hosts)
        }
        "ssh_list_keys" => {
            let json_str = proxy.ssh_list_keys().await.map_err(|e| e.to_string())?;
            let keys: Value = serde_json::from_str(&json_str).map_err(|e| e.to_string())?;
            Ok(keys)
        }
        "ssh_execute" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let command = args
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or("missing command")?;
            let result = proxy
                .ssh_execute_command(host_id, command)
                .await
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
            let profile_id = args
                .get("profile_id")
                .and_then(|v| v.as_str())
                .ok_or("missing profile_id")?;
            proxy.connect(profile_id).await.map_err(|e| e.to_string())?;
            Ok(json!({ "status": "connecting", "profile_id": profile_id }))
        }
        "vpn_disconnect" => {
            proxy.disconnect().await.map_err(|e| e.to_string())?;
            Ok(json!({ "status": "disconnecting" }))
        }
        "add_host" => {
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
            let id = proxy
                .add_host(&host_json.to_string())
                .await
                .map_err(|e| e.to_string())?;
            Ok(json!({ "id": id, "status": "created" }))
        }
        "test_host_connection" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let result = proxy
                .test_host_connection(host_id)
                .await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "toggle_host_pin" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let result = proxy
                .toggle_host_pin(host_id)
                .await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "ssh_set_password" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let password = args
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or("missing password")?;
            proxy
                .ssh_set_password(host_id, password)
                .await
                .map_err(|e| e.to_string())?;
            Ok(json!({ "status": "ok", "host_id": host_id }))
        }
        "ssh_set_api_token" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let token = args
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or("missing token")?;
            let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            proxy
                .ssh_set_api_token(host_id, token, port)
                .await
                .map_err(|e| e.to_string())?;
            Ok(json!({ "status": "ok", "host_id": host_id }))
        }
        "unifi_set_inform" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let inform_url = args
                .get("inform_url")
                .and_then(|v| v.as_str())
                .ok_or("missing inform_url")?;
            let result = proxy
                .unifi_set_inform(host_id, inform_url)
                .await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "unifi_api" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let method = args
                .get("method")
                .and_then(|v| v.as_str())
                .ok_or("missing method")?;
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or("missing path")?;
            let body = args.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let result = proxy
                .unifi_api(host_id, method, path, body)
                .await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "fortigate_push_ssh_key" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let key_id = args
                .get("key_id")
                .and_then(|v| v.as_str())
                .ok_or("missing key_id")?;
            let admin_user = args
                .get("admin_user")
                .and_then(|v| v.as_str())
                .ok_or("missing admin_user")?;
            let result = proxy
                .fortigate_push_ssh_key(host_id, key_id, admin_user)
                .await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        "fortigate_backup_config" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let filename = proxy
                .fortigate_backup_config(host_id)
                .await
                .map_err(|e| e.to_string())?;
            Ok(json!({ "status": "ok", "filename": filename }))
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn parse_response(value: String) -> Result<Value, String> {
    serde_json::from_str(&value).map_err(|e| format!("Unreadable daemon response: {e}"))
}

fn required_str<'a>(args: &'a Value, name: &str) -> Result<&'a str, String> {
    args[name].as_str().ok_or_else(|| format!("missing {name}"))
}

/// Only named, non-mutating data queries are available in read-only mode.
/// Raw API and shell tools are never classified by inspecting their arguments.
pub fn is_read_only(name: &str) -> bool {
    matches!(
        name,
        "list_hosts"
            | "ssh_list_keys"
            | "vpn_status"
            | "vpn_list_profiles"
            | "customer_catalog"
            | "host_health"
            | "tailscale_health"
            | "tailscale_devices" | "tailscale_management"
            | "findings_scopes" | "findings_summary"
            | "findings_list"
            | "compliance_history"
            | "compliance_get_run"
            | "compliance_list_checks"
    )
}

/// Catalog restricted to the operator's choice for this session.
pub fn available_tools(allow_changes: bool) -> Value {
    Value::Array(
        tool_definitions()
            .as_array()
            .expect("catalog array")
            .iter()
            .filter(|t| allow_changes || is_read_only(t["name"].as_str().unwrap_or("")))
            .cloned()
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_only_mode_excludes_shell_and_raw_api_access() {
        for name in [
            "ssh_execute",
            "unifi_api",
            "fortigate_api",
            "vpn_connect",
            "ssh_set_password",
            "unknown",
        ] {
            assert!(!is_read_only(name));
        }
        assert!(is_read_only("findings_list"));
        let filtered = available_tools(false);
        assert!(!filtered
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "ssh_execute"));
    }
}
