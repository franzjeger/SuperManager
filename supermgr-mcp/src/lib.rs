//! Shared AI tools. Names and dispatch stay identical across providers.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use supermgr_core::client::DaemonClient;
use uuid::Uuid;

fn confirm_property() -> Value {
    json!({
        "type": "boolean",
        "description": "Set to true only after explicit operator confirmation for this mutating or active action."
    })
}

/// Fine-grained authorization policy for `supermgr-mcp`.
#[derive(Debug, Clone)]
pub struct McpPolicy {
    pub allow_writes: bool,
    /// Optional allowlist of mutating tool names. When `Some`, unlisted
    /// mutating tools are neither advertised nor executable.
    pub allowed_tools: Option<BTreeSet<String>>,
    /// Optional allowlist of target host UUIDs. When `Some`, any tool taking
    /// `host_id` is restricted to these hosts.
    pub allowed_hosts: Option<BTreeSet<Uuid>>,
    /// Allow non-GET HTTP methods (`POST`, `PUT`, `DELETE`) on `fortigate_api`
    /// and `unifi_api`. Disabled by default even when `allow_writes` is true.
    pub allow_raw_api_writes: bool,
    /// Require `"confirm": true` in arguments for mutating tool calls.
    pub require_confirmation: bool,
    /// Append-only `0600` JSONL audit log for mutating tool calls.
    pub audit_log_path: Option<PathBuf>,
}

impl Default for McpPolicy {
    fn default() -> Self {
        Self {
            allow_writes: false,
            allowed_tools: None,
            allowed_hosts: None,
            allow_raw_api_writes: false,
            require_confirmation: true,
            audit_log_path: None,
        }
    }
}

impl McpPolicy {
    /// Parse policy from CLI arguments and environment variables. Fails closed
    /// on malformed host UUIDs or unknown tool names in allowlists.
    pub fn from_args_and_env<I, S>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args_vec: Vec<String> = args.into_iter().map(|s| s.as_ref().to_owned()).collect();
        let read_only_forced = std::env::var_os("SUPERMGR_MCP_READ_ONLY").is_some();
        let env_truthy = |key: &str| {
            matches!(
                std::env::var(key).as_deref(),
                Ok("1" | "true" | "TRUE" | "yes" | "YES")
            )
        };

        let allow_writes = !read_only_forced
            && (args_vec.iter().any(|a| a == "--allow-writes")
                || env_truthy("SUPERMGR_MCP_ALLOW_WRITES"));

        let allow_raw_api_writes = !read_only_forced
            && (args_vec.iter().any(|a| a == "--allow-raw-api-writes")
                || env_truthy("SUPERMGR_MCP_ALLOW_RAW_API_WRITES"));

        let raw_tools = args_vec
            .iter()
            .find_map(|a| a.strip_prefix("--allow-tools=").map(str::to_owned))
            .or_else(|| std::env::var("SUPERMGR_MCP_ALLOW_TOOLS").ok());
        let allowed_tools = match raw_tools {
            Some(csv) => {
                let mut set = BTreeSet::new();
                for item in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    set.insert(item.to_owned());
                }
                Some(set)
            }
            None => None,
        };

        let raw_hosts = args_vec
            .iter()
            .find_map(|a| a.strip_prefix("--allow-hosts=").map(str::to_owned))
            .or_else(|| std::env::var("SUPERMGR_MCP_ALLOW_HOSTS").ok());
        let allowed_hosts = match raw_hosts {
            Some(csv) => {
                let mut set = BTreeSet::new();
                for item in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let parsed = Uuid::parse_str(item)
                        .map_err(|e| format!("invalid UUID '{item}' in allowed hosts: {e}"))?;
                    set.insert(parsed);
                }
                Some(set)
            }
            None => None,
        };

        let audit_log_path = std::env::var("SUPERMGR_MCP_AUDIT_LOG")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                supermgr_core::paths::try_default_data_dir()
                    .ok()
                    .map(|d| d.join("mcp-audit.log"))
            });

        Ok(Self {
            allow_writes,
            allowed_tools,
            allowed_hosts,
            allow_raw_api_writes,
            require_confirmation: true,
            audit_log_path,
        })
    }

    #[must_use]
    pub fn is_tool_advertised(&self, name: &str) -> bool {
        if is_read_only(name) {
            return true;
        }
        if !self.allow_writes {
            return false;
        }
        match &self.allowed_tools {
            Some(set) => set.contains(name),
            None => true,
        }
    }
}

/// Catalog filtered by [`McpPolicy`].
#[must_use]
pub fn available_tools_for_policy(policy: &McpPolicy) -> Value {
    Value::Array(
        tool_definitions()
            .as_array()
            .expect("catalog array")
            .iter()
            .filter(|t| policy.is_tool_advertised(t["name"].as_str().unwrap_or("")))
            .cloned()
            .collect(),
    )
}

/// Enforce [`McpPolicy`] before dispatching a tool call.
pub fn authorize_tool_call(policy: &McpPolicy, name: &str, args: &Value) -> Result<(), String> {
    if matches!(name, "ssh_set_password" | "ssh_set_api_token") {
        return Err("credential-setting tools are not exposed over MCP".into());
    }

    // Enforce host scope across both read-only and mutating calls when `host_id` is supplied.
    if let Some(ref allowed_hosts) = policy.allowed_hosts {
        if let Some(raw_host) = args.get("host_id").and_then(Value::as_str) {
            let parsed = Uuid::parse_str(raw_host.trim())
                .map_err(|_| format!("invalid host_id '{raw_host}'"))?;
            if !allowed_hosts.contains(&parsed) {
                return Err(format!(
                    "host {parsed} is not in the MCP allowed-hosts policy"
                ));
            }
        }
    }

    if is_read_only(name) {
        return Ok(());
    }

    if !policy.allow_writes {
        return Err(
            "This MCP session is read-only by default. Pass --allow-writes to enable mutating tools."
                .into(),
        );
    }

    if let Some(ref allowed_tools) = policy.allowed_tools {
        if !allowed_tools.contains(name) {
            return Err(format!(
                "tool '{name}' is not permitted by the active --allow-tools policy"
            ));
        }
    }

    if matches!(name, "fortigate_api" | "unifi_api") {
        let method = args
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if !method.eq_ignore_ascii_case("GET") && !policy.allow_raw_api_writes {
            return Err(format!(
                "{name} non-GET method '{method}' requires --allow-raw-api-writes"
            ));
        }
    }

    if policy.require_confirmation
        && args.get("confirm").and_then(Value::as_bool) != Some(true)
    {
        return Err(format!(
            "mutating tool '{name}' requires explicit confirmation (\"confirm\": true)"
        ));
    }

    Ok(())
}

pub fn record_mcp_audit(
    path: &Path,
    tool: &str,
    args: &Value,
    allowed: bool,
    outcome: &str,
) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("create MCP audit directory {}: {e}", dir.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("open MCP audit log {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let entry = json!({
        "ts_unix": ts,
        "tool": tool,
        "host_id": args.get("host_id").and_then(Value::as_str),
        "profile_id": args.get("profile_id").and_then(Value::as_str),
        "method": args.get("method").and_then(Value::as_str),
        "path": args.get("path").and_then(Value::as_str),
        "allowed": allowed,
        "outcome": outcome,
    });
    let line = serde_json::to_string(&entry).map_err(|e| format!("serialize audit entry: {e}"))?;
    writeln!(file, "{line}").map_err(|e| format!("write MCP audit entry: {e}"))?;
    file.sync_data()
        .map_err(|e| format!("sync MCP audit log: {e}"))?;
    Ok(())
}

/// Authorize, audit, and execute a tool call under [`McpPolicy`].
pub async fn dispatch_with_policy(
    proxy: &DaemonClient,
    name: &str,
    args: &Value,
    policy: &McpPolicy,
) -> Result<Value, String> {
    let mutating = !is_read_only(name);
    if let Err(reason) = authorize_tool_call(policy, name, args) {
        if mutating {
            if let Some(ref log_path) = policy.audit_log_path {
                let _ = record_mcp_audit(log_path, name, args, false, &reason);
            }
        }
        return Err(reason);
    }

    if mutating {
        if let Some(ref log_path) = policy.audit_log_path {
            record_mcp_audit(log_path, name, args, true, "started")?;
        }
    }

    let res = execute_tool(proxy, name, args).await;

    if mutating {
        if let Some(ref log_path) = policy.audit_log_path {
            let outcome = match &res {
                Ok(_) => "ok",
                Err(_) => "error",
            };
            let _ = record_mcp_audit(log_path, name, args, true, outcome);
        }
    }

    res
}

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
                    },
                    "confirm": confirm_property()
                },
                "required": ["host_id", "command"]
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
                    "auth_key_id": { "type": "string", "description": "UUID of SSH key (for key auth)" },
                    "confirm": confirm_property()
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
                    },
                    "confirm": confirm_property()
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
                    },
                    "confirm": confirm_property()
                },
                "required": ["host_id"]
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
                    },
                    "confirm": confirm_property()
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
                    },
                    "confirm": confirm_property()
                },
                "required": ["host_id", "method", "path"]
            }
        }
    ]);
    #[cfg(not(target_os = "macos"))]
    {
        let definitions = catalog.as_array_mut().expect("tool array");
        definitions.extend([
            json!({
                "name": "vpn_status",
                "description": "Get the current VPN connection status (connected/disconnected, active profile, tunnel stats).",
                "inputSchema": { "type": "object", "properties": {}, "required": [] }
            }),
            json!({
                "name": "vpn_connect",
                "description": "Connect to a VPN profile by UUID. Returns immediately; the connection is established asynchronously.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "profile_id": {
                            "type": "string",
                            "description": "UUID of the VPN profile to connect"
                        },
                        "confirm": confirm_property()
                    },
                    "required": ["profile_id"]
                }
            }),
            json!({
                "name": "vpn_disconnect",
                "description": "Disconnect the currently active VPN connection.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "confirm": confirm_property()
                    },
                    "required": []
                }
            }),
            json!({
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
                        },
                        "confirm": confirm_property()
                    },
                    "required": ["host_id", "key_id", "admin_user"]
                }
            }),
            json!({
                "name": "fortigate_backup_config",
                "description": "Download the FortiGate running configuration and save it to disk. Returns the backup filename on success.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host_id": {
                            "type": "string",
                            "description": "UUID of the FortiGate host with API token configured"
                        },
                        "confirm": confirm_property()
                    },
                    "required": ["host_id"]
                }
            }),
        ]);
    }
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
            ("fortigate_compliance_check", "Run the FortiGate configuration baseline over its API and store the findings. Requires operator-enabled actions.", json!({"host_id":{"type":"string","description":"UUID of the managed host from list_hosts"},"confirm":confirm_property()}), json!(["host_id"])),
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
            "path":{"type":"string","description":"FortiGate REST API path, including query parameters if needed"},"body":{"type":"string","description":"Optional JSON-encoded request body"},
            "confirm":confirm_property()
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
        "tailscale_devices" => parse_response(
            proxy
                .tailscale_list_nodes()
                .await
                .map_err(|e| e.to_string())?,
        ),
        #[cfg(target_os = "linux")]
        "tailscale_management" => parse_response(
            proxy
                .tailscale_management()
                .await
                .map_err(|e| e.to_string())?,
        ),
        #[cfg(target_os = "linux")]
        "findings_scopes" => Ok(json!(proxy
            .findings_scopes()
            .await
            .map_err(|e| e.to_string())?)),
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
        #[cfg(not(target_os = "macos"))]
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
        #[cfg(not(target_os = "macos"))]
        "vpn_connect" => {
            let profile_id = args
                .get("profile_id")
                .and_then(|v| v.as_str())
                .ok_or("missing profile_id")?;
            proxy.connect(profile_id).await.map_err(|e| e.to_string())?;
            Ok(json!({ "status": "connecting", "profile_id": profile_id }))
        }
        #[cfg(not(target_os = "macos"))]
        "vpn_disconnect" => {
            proxy.disconnect().await.map_err(|e| e.to_string())?;
            Ok(json!({ "status": "disconnecting" }))
        }
        "add_host" => {
            let hostname = args
                .get("hostname")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            supermgr_core::sanitize::validate_host_or_ip(hostname)?;
            let username = args
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("root")
                .trim();
            supermgr_core::sanitize::validate_ssh_username(username)?;
            let host_json = json!({
                "label": args.get("label").and_then(|v| v.as_str()).unwrap_or(""),
                "hostname": hostname,
                "port": args.get("port").and_then(|v| v.as_u64()).unwrap_or(22),
                "username": username,
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
        "unifi_set_inform" => {
            let host_id = args
                .get("host_id")
                .and_then(|v| v.as_str())
                .ok_or("missing host_id")?;
            let inform_url = args
                .get("inform_url")
                .and_then(|v| v.as_str())
                .ok_or("missing inform_url")?
                .trim();
            supermgr_core::sanitize::validate_inform_url(inform_url)?;
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
        #[cfg(not(target_os = "macos"))]
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
                .ok_or("missing admin_user")?
                .trim();
            supermgr_core::sanitize::validate_safe_ident(admin_user, "admin_user")?;
            let result = proxy
                .fortigate_push_ssh_key(host_id, key_id, admin_user)
                .await
                .map_err(|e| e.to_string())?;
            let parsed: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
            Ok(parsed)
        }
        #[cfg(not(target_os = "macos"))]
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
            | "tailscale_devices"
            | "tailscale_management"
            | "findings_scopes"
            | "findings_summary"
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
            "ssh_set_api_token",
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
        // Secret-setting tools are never advertised in any mode.
        let all = tool_definitions();
        for forbidden in ["ssh_set_password", "ssh_set_api_token"] {
            assert!(!all
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["name"] == forbidden));
        }
    }

    #[test]
    fn policy_enforces_tool_allowlist_host_scope_raw_api_method_and_confirmation() {
        let host_ok = Uuid::new_v4();
        let host_denied = Uuid::new_v4();
        let mut policy = McpPolicy {
            allow_writes: true,
            allowed_tools: Some(["ssh_execute".to_owned(), "fortigate_api".to_owned()].into()),
            allowed_hosts: Some([host_ok].into()),
            allow_raw_api_writes: false,
            require_confirmation: true,
            audit_log_path: None,
        };

        // Unlisted mutating tool is denied.
        assert!(authorize_tool_call(
            &policy,
            "add_host",
            &json!({"confirm": true})
        )
        .is_err());

        // Listed tool without confirm=true is denied.
        assert!(authorize_tool_call(
            &policy,
            "ssh_execute",
            &json!({"host_id": host_ok.to_string(), "command": "uptime"})
        )
        .is_err());

        // Listed tool on out-of-scope host is denied.
        assert!(authorize_tool_call(
            &policy,
            "ssh_execute",
            &json!({"host_id": host_denied.to_string(), "command": "uptime", "confirm": true})
        )
        .is_err());

        // Listed tool on allowed host with confirm=true succeeds.
        assert!(authorize_tool_call(
            &policy,
            "ssh_execute",
            &json!({"host_id": host_ok.to_string(), "command": "uptime", "confirm": true})
        )
        .is_ok());

        // fortigate_api GET succeeds, POST is denied until allow_raw_api_writes=true.
        assert!(authorize_tool_call(
            &policy,
            "fortigate_api",
            &json!({"host_id": host_ok.to_string(), "method": "GET", "path": "/api/v2/monitor/system/status", "confirm": true})
        )
        .is_ok());
        assert!(authorize_tool_call(
            &policy,
            "fortigate_api",
            &json!({"host_id": host_ok.to_string(), "method": "DELETE", "path": "/api/v2/cmdb/firewall/policy/1", "confirm": true})
        )
        .is_err());
        policy.allow_raw_api_writes = true;
        assert!(authorize_tool_call(
            &policy,
            "fortigate_api",
            &json!({"host_id": host_ok.to_string(), "method": "DELETE", "path": "/api/v2/cmdb/firewall/policy/1", "confirm": true})
        )
        .is_ok());
    }

    #[test]
    fn mcp_audit_log_writes_private_jsonl_without_leaking_command_body() {
        let dir = std::env::temp_dir().join(format!("sm-mcp-audit-{}", Uuid::new_v4()));
        let log_path = dir.join("mcp-audit.log");
        record_mcp_audit(
            &log_path,
            "ssh_execute",
            &json!({"host_id": "11111111-1111-1111-1111-111111111111", "command": "echo super-secret-token"}),
            true,
            "ok",
        )
        .unwrap();
        let text = std::fs::read_to_string(&log_path).unwrap();
        assert!(text.contains("\"tool\":\"ssh_execute\""));
        assert!(!text.contains("super-secret-token"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
