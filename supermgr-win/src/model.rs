//! What the window makes of the service's answers.
//!
//! Pure functions over the JSON the named pipe returns, kept apart from the
//! Slint code so they build and are tested on every host — the window
//! itself only exists on Windows.

use chrono::{DateTime, Datelike as _, Local, Utc};
use serde_json::Value;

use supermgr_core::protocol::RpcError;

// ---------------------------------------------------------------------------
// VPN status
// ---------------------------------------------------------------------------

/// Where the tunnel stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

/// `get_status`, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub profile_id: String,
    /// The service's backend label, e.g. `"WireGuard"`.
    pub backend: String,
    /// What a connect is doing right now.
    pub step: String,
    pub interface: String,
    pub since: Option<DateTime<Utc>>,
    /// Why a connect failed, or why the tunnel dropped.
    pub message: String,
    /// Set while an Azure connect waits for a sign-in.
    pub auth_url: String,
}

impl Status {
    pub fn disconnected() -> Self {
        Self {
            phase: Phase::Disconnected,
            profile_id: String::new(),
            backend: String::new(),
            step: String::new(),
            interface: String::new(),
            since: None,
            message: String::new(),
            auth_url: String::new(),
        }
    }

    /// Whether something is happening that the window should watch
    /// closely.
    pub fn is_busy(&self) -> bool {
        matches!(self.phase, Phase::Connecting | Phase::Disconnecting)
    }
}

/// Read `get_status`.
///
/// The service reports the Linux daemon's `VpnState` (`"state":
/// "connected"`). Services from before that reported `"Connected"` with a
/// capital, which is read the same way, so a window upgraded before its
/// service still shows the tunnel. Anything unreadable is "disconnected":
/// this runs every second while a connect is in flight, and a garbled
/// answer is not worth an error box.
pub fn parse_status(json: &str) -> Status {
    let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    let text = |key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let phase = match text("state").to_ascii_lowercase().as_str() {
        "connecting" => Phase::Connecting,
        "connected" => Phase::Connected,
        "disconnecting" => Phase::Disconnecting,
        "error" => Phase::Failed,
        _ => Phase::Disconnected,
    };
    Status {
        phase,
        profile_id: text("profile_id"),
        backend: text("backend"),
        step: text("phase"),
        interface: text("interface").trim().to_owned(),
        since: v
            .get("since")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc)),
        message: text("message"),
        auth_url: text("auth_url"),
    }
}

/// Whether a sign-in URL from the service is one the window may open.
///
/// Only the service publishes these, but the window opens what it is given
/// in the operator's browser, so it holds the line itself: Microsoft's sign-in
/// endpoint, over HTTPS, and nothing a shell could read as more than one
/// argument.
pub fn is_sign_in_url(url: &str) -> bool {
    url.starts_with("https://login.microsoftonline.com/")
        && url.len() < 4096
        && !url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '<' || c == '>')
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

/// The kind of a profile, as the window groups them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    WireGuard,
    OpenVpn,
    Azure,
    FortiGate,
    SslVpn,
    Other,
}

/// The kind a service backend label stands for. Covers both the profile
/// summaries' labels ("FortiGate (IPsec/IKEv2)", "OpenVPN3") and the short
/// ones older services put in their status ("fortigate-ikev2").
pub fn kind_of(backend: &str) -> Kind {
    let b = backend.to_ascii_lowercase();
    if b.starts_with("wireguard") {
        Kind::WireGuard
    } else if b.contains("ssl") {
        Kind::SslVpn
    } else if b.starts_with("fortigate") {
        Kind::FortiGate
    } else if b.starts_with("openvpn") {
        Kind::OpenVpn
    } else if b.starts_with("azure") {
        Kind::Azure
    } else {
        Kind::Other
    }
}

/// What the window calls a kind.
pub fn kind_label(kind: Kind, backend: &str) -> String {
    match kind {
        Kind::WireGuard => "WireGuard",
        Kind::OpenVpn => "OpenVPN",
        Kind::Azure => "Azure VPN (Entra ID)",
        Kind::FortiGate => "FortiGate IPsec (IKEv2)",
        Kind::SslVpn => "FortiGate SSL VPN",
        Kind::Other => backend,
    }
    .to_owned()
}

/// A profile as the list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub kind_label: String,
    pub host: String,
    pub username: String,
    pub full_tunnel: bool,
    pub push_dns: bool,
    pub last_connected: Option<DateTime<Utc>>,
}

/// Read `list_profiles`, sorted by name.
pub fn parse_profiles(json: &str) -> Vec<Profile> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut profiles: Vec<Profile> = items
        .iter()
        .filter_map(|item| {
            let text = |key: &str| {
                item.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let id = text("id");
            if id.is_empty() {
                return None;
            }
            let backend = text("backend");
            let kind = kind_of(&backend);
            Some(Profile {
                id,
                name: text("name"),
                kind,
                kind_label: kind_label(kind, &backend),
                host: text("host"),
                username: text("username"),
                full_tunnel: item
                    .get("full_tunnel")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
                push_dns: item
                    .get("push_dns")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                last_connected: item
                    .get("last_connected_secs")
                    .and_then(Value::as_i64)
                    .and_then(|s| DateTime::from_timestamp(s, 0)),
            })
        })
        .collect();
    profiles.sort_by_key(|p| p.name.to_lowercase());
    profiles
}

/// Which profile kinds this PC can run, from `vpn_capabilities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub wireguard: Result<(), String>,
    pub openvpn: Result<(), String>,
    pub sslvpn: Result<(), String>,
}

impl Default for Capabilities {
    /// What to assume of a service too old to say: the kinds it has always
    /// run, and not the SSL VPN client it has never shipped.
    fn default() -> Self {
        Self {
            wireguard: Ok(()),
            openvpn: Ok(()),
            sslvpn: Err("Needs an SSL VPN client that isn't included in the Windows build.".into()),
        }
    }
}

pub fn parse_capabilities(json: &str) -> Capabilities {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return Capabilities::default();
    };
    let read = |key: &str, fallback: &Result<(), String>| -> Result<(), String> {
        let Some(entry) = v.get(key) else {
            return fallback.clone();
        };
        if entry.get("available").and_then(Value::as_bool) == Some(true) {
            Ok(())
        } else {
            Err(entry
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("Not available on this PC.")
                .to_owned())
        }
    };
    let fallback = Capabilities::default();
    Capabilities {
        wireguard: read("wireguard", &fallback.wireguard),
        openvpn: read("openvpn", &fallback.openvpn),
        sslvpn: read("forticlient", &fallback.sslvpn),
    }
}

// ---------------------------------------------------------------------------
// Hosts and keys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub id: String,
    pub label: String,
    pub hostname: String,
    pub username: String,
    pub port: u16,
    pub device_type: String,
    pub customer: String,
    pub pinned: bool,
}

impl Host {
    /// `user@host`, with the port only when it is not SSH's own.
    pub fn address(&self) -> String {
        let user = if self.username.is_empty() {
            String::new()
        } else {
            format!("{}@", self.username)
        };
        if self.port == 22 {
            format!("{user}{}", self.hostname)
        } else {
            format!("{user}{}:{}", self.hostname, self.port)
        }
    }
}

/// Read `list_hosts`: pinned first, then by name.
pub fn parse_hosts(json: &str) -> Vec<Host> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut hosts: Vec<Host> = items
        .iter()
        .filter_map(|item| {
            let text = |key: &str| {
                item.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let id = text("id");
            if id.is_empty() {
                return None;
            }
            Some(Host {
                id,
                label: text("label"),
                hostname: text("hostname"),
                username: text("username"),
                port: item
                    .get("port")
                    .and_then(Value::as_u64)
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(22),
                device_type: text("device_type"),
                customer: text("customer"),
                pinned: item.get("pinned").and_then(Value::as_bool).unwrap_or(false),
            })
        })
        .collect();
    hosts.sort_by_key(|h| (!h.pinned, h.label.to_lowercase()));
    hosts
}

/// Hosts whose name, address or customer contains `query`, ignoring case.
pub fn filter_hosts(hosts: &[Host], query: &str) -> Vec<Host> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return hosts.to_vec();
    }
    hosts
        .iter()
        .filter(|h| {
            h.label.to_lowercase().contains(&needle)
                || h.hostname.to_lowercase().contains(&needle)
                || h.customer.to_lowercase().contains(&needle)
        })
        .cloned()
        .collect()
}

/// One host in full, from `get_host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDetail {
    pub host: Host,
    pub group: String,
    pub auth_method: String,
    pub created_at: Option<DateTime<Utc>>,
}

pub fn parse_host_detail(json: &str) -> Option<HostDetail> {
    let v: Value = serde_json::from_str(json).ok()?;
    let host = parse_hosts(&Value::Array(vec![v.clone()]).to_string()).pop()?;
    let text = |key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    Some(HostDetail {
        host,
        group: text("group"),
        auth_method: text("auth_method"),
        created_at: v
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc)),
    })
}

/// How a host signs in, in words.
pub fn auth_method_label(method: &str) -> String {
    match method {
        "password" => "Password".into(),
        "key" => "SSH key".into(),
        "api-token" => "API token".into(),
        "none" => "Nothing stored".into(),
        other => other.to_owned(),
    }
}

/// The outcome of `test_host_connection`, as a sentence.
pub fn describe_test(json: &str, port: u16) -> String {
    let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    let ssh = v.get("ssh").and_then(Value::as_str).unwrap_or("");
    let mut out = match ssh {
        "ok" => "Reachable, and the stored credentials were accepted.".to_owned(),
        "auth_failed" => "Reachable, but the stored credentials were rejected.".to_owned(),
        "connection_refused" => format!("The host refused the connection on port {port}."),
        "timeout" => "No answer from the host. Check the address, and that this PC can reach it — over the VPN, if it is behind one.".to_owned(),
        "host_key_changed" => "The host presented a different SSH key from the one on file, so SuperManager did not connect.".to_owned(),
        "" => "The service gave no result.".to_owned(),
        other => other.strip_prefix("error: ").unwrap_or(other).to_owned(),
    };
    if let Some(api) = v.get("api").and_then(Value::as_str) {
        let api = match api {
            "ok" => "the API token works",
            "auth_failed" => "the API token was rejected",
            "timeout" => "the API did not answer",
            other => other,
        };
        out.push_str(&format!(" As for the API: {api}."));
    }
    out
}

/// A host presenting a different SSH key from the one on file, as
/// `test_host_connection` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChange {
    /// The key on file, `SHA256:…`.
    pub stored: String,
    /// When the key on file was first recorded.
    pub stored_since: Option<DateTime<Utc>>,
    /// The key presented this time, `SHA256:…`.
    pub presented: String,
    /// Its type, e.g. `ssh-ed25519`: trusting it records both.
    pub presented_algorithm: String,
}

/// Read a changed key out of a `test_host_connection` result; `None` for
/// every other outcome.
pub fn parse_key_change(json: &str) -> Option<KeyChange> {
    let v: Value = serde_json::from_str(json).ok()?;
    if v.get("ssh").and_then(Value::as_str) != Some("host_key_changed") {
        return None;
    }
    let text = |key: &str| v.get(key).and_then(Value::as_str).unwrap_or_default();
    Some(KeyChange {
        stored: fingerprint(text("stored")),
        stored_since: DateTime::parse_from_rfc3339(text("stored_since"))
            .ok()
            .map(|t| t.with_timezone(&Utc)),
        presented: fingerprint(text("presented")),
        presented_algorithm: text("presented_algorithm").to_owned(),
    })
}

/// The key on file for `hostname:port`, from `ssh_list_known_hosts`.
pub fn known_key(json: &str, hostname: &str, port: u16) -> Option<String> {
    let v: Value = serde_json::from_str(json).ok()?;
    v.get(format!("{hostname}:{port}"))
        .and_then(Value::as_str)
        .filter(|fp| !fp.is_empty())
        .map(fingerprint)
}

/// A host-key fingerprint the way OpenSSH prints it (`ssh-keygen -lf`), so
/// it can be compared with the host's own at a glance.
pub fn fingerprint(raw: &str) -> String {
    if raw.is_empty() || raw.starts_with("SHA256:") {
        raw.to_owned()
    } else {
        format!("SHA256:{raw}")
    }
}

/// The output of `ssh_execute_command`.
pub fn parse_exec(json: &str) -> (String, String, i32) {
    let v: Value = serde_json::from_str(json).unwrap_or(Value::Null);
    let text = |key: &str| {
        v.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim_end()
            .to_owned()
    };
    let exit = v
        .get("exit_code")
        .and_then(Value::as_i64)
        .and_then(|c| i32::try_from(c).ok())
        .unwrap_or(-1);
    (text("stdout"), text("stderr"), exit)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "`key_type` is the daemon's name for it, and the UI's"
)]
pub struct Key {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub fingerprint: String,
    pub created_at: Option<DateTime<Utc>>,
}

/// Read `ssh_list_keys`, newest first.
pub fn parse_keys(json: &str) -> Vec<Key> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut keys: Vec<Key> = items
        .iter()
        .filter_map(|item| {
            let text = |key: &str| {
                item.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let id = text("id");
            if id.is_empty() {
                return None;
            }
            Some(Key {
                id,
                name: text("name"),
                key_type: text("key_type"),
                fingerprint: text("fingerprint"),
                created_at: item
                    .get("created_at")
                    .and_then(Value::as_str)
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&Utc)),
            })
        })
        .collect();
    keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    keys
}

// ---------------------------------------------------------------------------
// Words
// ---------------------------------------------------------------------------

/// A past moment the way a person says it: "Today 08:14", "Yesterday
/// 16:02", "12 Sep 10:31", or "12 Sep 2024" once it is from another year.
pub fn describe_time(t: DateTime<Local>, now: DateTime<Local>) -> String {
    let (day, today) = (t.date_naive(), now.date_naive());
    if day == today {
        format!("Today {}", t.format("%H:%M"))
    } else if today.pred_opt() == Some(day) {
        format!("Yesterday {}", t.format("%H:%M"))
    } else if t.year() == now.year() {
        t.format("%-d %b %H:%M").to_string()
    } else {
        t.format("%-d %b %Y").to_string()
    }
}

/// When a tunnel came up: just the time today, the day as well before.
pub fn describe_since(t: DateTime<Local>, now: DateTime<Local>) -> String {
    if t.date_naive() == now.date_naive() {
        t.format("%H:%M").to_string()
    } else {
        t.format("%-d %b %H:%M").to_string()
    }
}

/// A service error, for a person to read. The transport's own prefixes
/// ("backend failure: ") are for logs.
pub fn describe_rpc_error(e: &RpcError) -> String {
    match e {
        RpcError::Backend(m) | RpcError::Other(m) | RpcError::PermissionDenied(m) => {
            capitalise(m)
        }
        RpcError::NotFound(m) => format!("{} no longer exists.", capitalise(m)),
        RpcError::Secret(m) => format!("Windows Credential Manager refused: {m}"),
        RpcError::Protocol(m) => format!(
            "The service did not understand the request ({m}). The app and the service may be different versions — reinstalling updates both."
        ),
    }
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// A profile name from a config file's name: `office-vpn.conf` → `office-vpn`.
pub fn name_from_file(file_name: &str) -> String {
    let stem = file_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(file_name)
        .rsplit_once('.')
        .map_or(file_name, |(stem, _)| stem);
    stem.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn a_connected_status_is_read_whole() {
        let s = parse_status(
            r#"{"state":"connected","profile_id":"p1","since":"2026-09-23T06:14:00Z","interface":"wg-office","backend":"WireGuard"}"#,
        );
        assert_eq!(s.phase, Phase::Connected);
        assert_eq!(s.profile_id, "p1");
        assert_eq!(s.interface, "wg-office");
        assert_eq!(s.backend, "WireGuard");
        assert!(s.since.is_some());
    }

    #[test]
    fn a_failure_keeps_its_reason_and_a_connect_its_step() {
        let s = parse_status(
            r#"{"state":"error","profile_id":"p1","code":"AUTH_FAILED","message":"The server rejected the username or password"}"#,
        );
        assert_eq!(s.phase, Phase::Failed);
        assert_eq!(s.message, "The server rejected the username or password");
        let s = parse_status(
            r#"{"state":"connecting","profile_id":"p1","since":"2026-09-23T06:14:00Z","phase":"Signing in to Microsoft Entra ID","auth_url":"https://login.microsoftonline.com/t/oauth2"}"#,
        );
        assert_eq!(s.phase, Phase::Connecting);
        assert!(s.is_busy());
        assert_eq!(s.step, "Signing in to Microsoft Entra ID");
    }

    #[test]
    fn an_older_services_status_still_reads() {
        // Capitalised, and no profile name: what services before this
        // change sent. A window upgraded first must still show the tunnel.
        let s = parse_status(
            r#"{"state":"Connected","backend":"wireguard","profile_id":"p1","adapter":"x"}"#,
        );
        assert_eq!(s.phase, Phase::Connected);
        assert_eq!(parse_status("not json").phase, Phase::Disconnected);
    }

    #[test]
    fn only_microsofts_sign_in_page_is_opened() {
        assert!(is_sign_in_url(
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=x&state=y"
        ));
        assert!(!is_sign_in_url("http://login.microsoftonline.com/tenant"));
        assert!(!is_sign_in_url(
            "https://login.microsoftonline.com.evil.example/tenant"
        ));
        assert!(!is_sign_in_url(
            "https://evil.example/?https://login.microsoftonline.com/"
        ));
        assert!(!is_sign_in_url(
            "https://login.microsoftonline.com/x\" --new-window file:///c:/"
        ));
        assert!(!is_sign_in_url(""));
    }

    #[test]
    fn backend_labels_old_and_new_map_to_one_kind() {
        assert_eq!(kind_of("WireGuard"), Kind::WireGuard);
        assert_eq!(kind_of("FortiGate (IPsec/IKEv2)"), Kind::FortiGate);
        assert_eq!(kind_of("fortigate-ikev2"), Kind::FortiGate);
        assert_eq!(kind_of("FortiGate SSL VPN"), Kind::SslVpn);
        assert_eq!(kind_of("forticlient-sslvpn"), Kind::SslVpn);
        assert_eq!(kind_of("OpenVPN3"), Kind::OpenVpn);
        assert_eq!(kind_of("Azure VPN (Entra ID)"), Kind::Azure);
        assert_eq!(kind_of("Generic"), Kind::Other);
        assert_eq!(kind_label(Kind::OpenVpn, "OpenVPN3"), "OpenVPN");
        assert_eq!(kind_label(Kind::Other, "Generic"), "Generic");
    }

    #[test]
    fn profiles_are_read_and_sorted_by_name() {
        let p = parse_profiles(
            r#"[{"id":"b","name":"zeta","backend":"WireGuard","auto_connect":false,"push_dns":true,"last_connected_secs":1700000000},
                {"id":"a","name":"Alpha","backend":"FortiGate (IPsec/IKEv2)","host":"fw.example","username":"frank","full_tunnel":true},
                {"name":"no id is skipped","backend":"WireGuard"}]"#,
        );
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "Alpha");
        assert_eq!(p[0].kind, Kind::FortiGate);
        assert_eq!(p[0].host, "fw.example");
        assert!(!p[0].push_dns);
        assert!(p[1].push_dns);
        assert!(p[1].last_connected.is_some());
    }

    #[test]
    fn capabilities_name_what_is_missing() {
        let c = parse_capabilities(
            r#"{"wireguard":{"available":true},"openvpn":{"available":false,"reason":"openvpn.exe not found"},"forticlient":{"available":false,"reason":"not shipped"}}"#,
        );
        assert_eq!(c.wireguard, Ok(()));
        assert_eq!(c.openvpn, Err("openvpn.exe not found".into()));
        assert_eq!(c.sslvpn, Err("not shipped".into()));
        // A service too old to answer: assume what it always had.
        assert_eq!(parse_capabilities("").openvpn, Ok(()));
        assert!(parse_capabilities("").sslvpn.is_err());
    }

    #[test]
    fn hosts_put_pinned_first_and_hide_the_default_port() {
        let h = parse_hosts(
            r#"[{"id":"1","label":"web","hostname":"web.example","username":"root","port":22},
                {"id":"2","label":"fw","hostname":"10.0.0.1","username":"admin","port":2222,"pinned":true}]"#,
        );
        assert_eq!(h[0].label, "fw");
        assert_eq!(h[0].address(), "admin@10.0.0.1:2222");
        assert_eq!(h[1].address(), "root@web.example");
        assert_eq!(filter_hosts(&h, "WEB").len(), 1);
        assert_eq!(filter_hosts(&h, "  ").len(), 2);
    }

    #[test]
    fn a_host_in_full_keeps_what_the_list_drops() {
        let d = parse_host_detail(
            r#"{"id":"1","label":"web","hostname":"web.example","username":"root","port":22,"group":"prod","auth_method":"key","created_at":"2025-02-11T10:00:00+00:00"}"#,
        )
        .unwrap();
        assert_eq!(d.host.label, "web");
        assert_eq!(d.group, "prod");
        assert_eq!(auth_method_label(&d.auth_method), "SSH key");
        assert!(d.created_at.is_some());
        assert!(parse_host_detail("[]").is_none());
    }

    #[test]
    fn a_test_result_reads_as_a_sentence() {
        assert!(describe_test(r#"{"ssh":"ok"}"#, 22).starts_with("Reachable"));
        assert!(describe_test(r#"{"ssh":"connection_refused"}"#, 2222).contains("2222"));
        assert_eq!(
            describe_test(r#"{"ssh":"error: no route to host"}"#, 22),
            "no route to host"
        );
    }

    #[test]
    fn a_changed_key_is_read_with_both_fingerprints() {
        let json = r#"{"ssh":"host_key_changed","stored":"b2xk","stored_algorithm":"ssh-ed25519","stored_since":"2026-09-01T10:00:00.5+00:00","presented":"bmV3","presented_algorithm":"ssh-rsa"}"#;
        let change = parse_key_change(json).unwrap();
        assert_eq!(change.stored, "SHA256:b2xk");
        assert_eq!(change.presented, "SHA256:bmV3");
        assert_eq!(change.presented_algorithm, "ssh-rsa");
        assert_eq!(
            change.stored_since,
            Some(
                Utc.with_ymd_and_hms(2026, 9, 1, 10, 0, 0).unwrap()
                    + chrono::Duration::milliseconds(500)
            )
        );
        assert!(describe_test(json, 22).contains("different SSH key"));

        assert_eq!(parse_key_change(r#"{"ssh":"ok"}"#), None);
        assert_eq!(parse_key_change("not json"), None);
    }

    #[test]
    fn the_key_on_file_is_found_by_address_and_port() {
        let json = r#"{"10.0.0.1:22":"YQ","10.0.0.1:2222":"Yg"}"#;
        assert_eq!(
            known_key(json, "10.0.0.1", 22).as_deref(),
            Some("SHA256:YQ")
        );
        assert_eq!(
            known_key(json, "10.0.0.1", 2222).as_deref(),
            Some("SHA256:Yg")
        );
        assert_eq!(known_key(json, "10.0.0.2", 22), None);
        assert_eq!(known_key("[]", "10.0.0.1", 22), None);
        assert_eq!(fingerprint("SHA256:YQ"), "SHA256:YQ");
        assert_eq!(fingerprint(""), "");
    }

    #[test]
    fn command_output_is_read_with_its_exit_code() {
        let (out, err, code) = parse_exec(r#"{"stdout":"up 3 days\n","stderr":"","exit_code":0}"#);
        assert_eq!((out.as_str(), err.as_str(), code), ("up 3 days", "", 0));
        assert_eq!(parse_exec("garbage").2, -1);
    }

    #[test]
    fn times_read_the_way_people_say_them() {
        let now = Local.with_ymd_and_hms(2026, 9, 23, 12, 0, 0).unwrap();
        let at = |d, h, m| Local.with_ymd_and_hms(2026, 9, d, h, m, 0).unwrap();
        assert_eq!(describe_time(at(23, 8, 14), now), "Today 08:14");
        assert_eq!(describe_time(at(22, 16, 2), now), "Yesterday 16:02");
        assert_eq!(describe_time(at(12, 10, 31), now), "12 Sep 10:31");
        let last_year = Local.with_ymd_and_hms(2025, 3, 2, 9, 0, 0).unwrap();
        assert_eq!(describe_time(last_year, now), "2 Mar 2025");
        assert_eq!(describe_since(at(23, 8, 14), now), "08:14");
    }

    #[test]
    fn service_errors_lose_their_transport_prefix() {
        let e = RpcError::Backend("a connection is already in progress".into());
        assert_eq!(
            describe_rpc_error(&e),
            "A connection is already in progress"
        );
        assert!(
            describe_rpc_error(&RpcError::Protocol("unknown method: x".into()))
                .contains("versions")
        );
    }

    #[test]
    fn a_file_name_makes_a_profile_name() {
        assert_eq!(name_from_file("office-vpn.conf"), "office-vpn");
        assert_eq!(
            name_from_file(r"C:\Users\f\Downloads\nordvik.ovpn"),
            "nordvik"
        );
        assert_eq!(name_from_file("noext"), "noext");
    }
}
