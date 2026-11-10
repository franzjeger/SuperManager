//! Validation and persistence helpers shared by Windows RPC handlers; portable
//! so they can be verified on every host without a running Windows service.

use serde_json::{json, Value};
use supermgr_core::host::{Host, HostSummary};
use supermgr_core::protocol::RpcError;
use supermgr_core::sanitize::{validate_host_or_ip, validate_safe_ident, validate_ssh_username};
use supermgr_core::secret_lifecycle::SecretOwner;
use supermgr_core::ssh::key::SshKey;
use supermgr_core::vpn::profile::{AzureVpnConfig, SecretRef};

/// Host JSON keys that hold Credential Manager labels and must never be
/// accepted from untrusted RPC callers or leaked in summary listings.
const HOST_SECRET_REF_KEYS: [&str; 4] = [
    "auth_password_ref",
    "auth_cert_ref",
    "api_token_ref",
    "unifi_api_token_ref",
];

/// Outcome of reading a single newline-delimited RPC frame with an upper bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BoundedLine {
    /// Peer closed the stream cleanly (`0` bytes read).
    Eof,
    /// Stream exceeded `max_frame_bytes` before or including `\n`.
    Oversized,
    /// Valid bounded line now buffered in `line`.
    Frame,
}

/// Read a single line from `reader`, bounding memory allocation BEFORE reading
/// via `AsyncReadExt::take(max_frame_bytes + 1)`.
pub(crate) async fn read_bounded_line<R>(
    reader: &mut R,
    line: &mut String,
    max_frame_bytes: usize,
) -> std::io::Result<BoundedLine>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};

    let max_read = (max_frame_bytes as u64).saturating_add(1);
    let n = (&mut *reader).take(max_read).read_line(line).await?;
    if n == 0 {
        return Ok(BoundedLine::Eof);
    }
    if n > max_frame_bytes || (!line.ends_with('\n') && n == max_read as usize) {
        return Ok(BoundedLine::Oversized);
    }
    Ok(BoundedLine::Frame)
}

/// Accept only UUID filename components, preserving the existing simple or
/// hyphenated spelling used by stored records and credential labels.
pub(crate) fn arg_id<'a>(args: &'a Value, name: &str) -> Result<&'a str, RpcError> {
    let value = args
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Protocol(format!("missing string arg: {name}")))?;
    validate_uuid_id(value, name)
}

/// Verify `value` is a filename-safe simple or hyphenated UUID.
pub(crate) fn validate_uuid_id<'a>(value: &'a str, name: &str) -> Result<&'a str, RpcError> {
    if !matches!(value.len(), 32 | 36) || uuid::Uuid::parse_str(value).is_err() {
        return Err(RpcError::Protocol(format!("invalid UUID arg: {name}")));
    }
    Ok(value)
}

/// Validate Azure VPN profile fields before using them in Entra OAuth URLs or
/// rendering `client.ovpn`.
pub(crate) fn validate_azure_ovpn_inputs(cfg: &AzureVpnConfig) -> Result<(), String> {
    validate_host_or_ip(&cfg.gateway_fqdn)?;
    validate_safe_ident(&cfg.tenant_id, "tenant_id")?;
    validate_safe_ident(&cfg.client_id, "client_id")?;
    if cfg.ca_cert_pem.contains('\0') || cfg.ca_cert_pem.to_ascii_lowercase().contains("</ca>") {
        return Err("Azure VPN CA certificate contains invalid '</ca>' breakout or NUL".into());
    }
    Ok(())
}

/// Deterministic Credential Manager label for a host's SSH password.
pub(crate) fn host_password_label(host_id: &str) -> String {
    format!("supermgr/host/{host_id}/password")
}

/// Deterministic Credential Manager label for a host's firewall API token.
pub(crate) fn host_api_token_label(host_id: &str) -> String {
    format!("supermgr/host/{host_id}/api-token")
}

/// Deterministic Credential Manager label for a host's UniFi controller credentials.
pub(crate) fn host_unifi_creds_label(host_id: &str) -> String {
    format!("supermgr/host/{host_id}/unifi-credentials")
}

/// Deterministic Credential Manager label for an SSH private key.
pub(crate) fn ssh_key_privkey_label(key_id: &str) -> String {
    format!("supermgr/ssh/{key_id}/privkey")
}

/// Validate and normalize caller-supplied `host_json` for `add_host`.
///
/// Enforces `validate_host_or_ip` on `hostname`, `validate_ssh_username` on
/// `username`, strips caller-supplied `*_ref` secret pointers, stamps `id`,
/// `created_at`, and `updated_at`, and verifies the resulting record parses
/// cleanly as [`Host`].
pub(crate) fn prepare_new_host(host_json: &str) -> Result<(String, Value), RpcError> {
    let mut value: Value = serde_json::from_str(host_json)
        .map_err(|e| RpcError::Other(format!("parse host_json: {e}")))?;
    let Some(obj) = value.as_object_mut() else {
        return Err(RpcError::Other("host_json must be an object".into()));
    };

    for secret_key in HOST_SECRET_REF_KEYS {
        obj.remove(secret_key);
    }

    let hostname = obj
        .get("hostname")
        .and_then(Value::as_str)
        .map(str::trim)
        .ok_or_else(|| RpcError::Protocol("host missing 'hostname'".into()))?
        .to_owned();
    validate_host_or_ip(&hostname).map_err(RpcError::Protocol)?;

    let username = obj
        .get("username")
        .and_then(Value::as_str)
        .map(str::trim)
        .ok_or_else(|| RpcError::Protocol("host missing 'username'".into()))?
        .to_owned();
    validate_ssh_username(&username).map_err(RpcError::Protocol)?;

    if let Some(raw_key_id) = obj.get("auth_key_id").cloned() {
        match raw_key_id.as_str() {
            None => {
                obj.remove("auth_key_id");
            }
            Some(s) if s.trim().is_empty() => {
                obj.remove("auth_key_id");
            }
            Some(s) => {
                let trimmed = validate_uuid_id(s.trim(), "auth_key_id")?;
                obj.insert("auth_key_id".into(), Value::String(trimmed.to_owned()));
            }
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    obj.insert("hostname".into(), Value::String(hostname));
    obj.insert("username".into(), Value::String(username));
    obj.insert("id".into(), Value::String(id.clone()));
    obj.insert("created_at".into(), Value::String(now.clone()));
    obj.insert("updated_at".into(), Value::String(now));

    // Verify the record satisfies the canonical Host schema.
    serde_json::from_value::<Host>(value.clone())
        .map_err(|e| RpcError::Protocol(format!("invalid host definition: {e}")))?;

    Ok((id, value))
}

/// Apply a metadata mutation to an on-disk host JSON blob and stamp `updated_at`.
pub(crate) fn mutate_host_json(
    bytes: &[u8],
    mutate: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> Result<Vec<u8>, RpcError> {
    let mut v: Value =
        serde_json::from_slice(bytes).map_err(|e| RpcError::Other(format!("parse host: {e}")))?;
    let Some(obj) = v.as_object_mut() else {
        return Err(RpcError::Other("stored host JSON is not an object".into()));
    };
    mutate(obj);
    obj.insert(
        "updated_at".into(),
        Value::String(chrono::Utc::now().to_rfc3339()),
    );
    serde_json::to_vec(&v).map_err(|e| RpcError::Other(format!("serialise host: {e}")))
}

/// Convert stored `hosts/<id>.json` bytes into a [`HostSummary`] JSON value
/// with accurate `has_password` and `has_api` flags.
///
/// Falls back gracefully if an older hand-edited record cannot parse into
/// [`Host`], computing boolean capability flags while stripping raw `*_ref`
/// labels.
pub(crate) fn summarize_host_json(bytes: &[u8]) -> Option<Value> {
    if let Ok(host) = serde_json::from_slice::<Host>(bytes) {
        let summary = HostSummary::from(&host);
        return serde_json::to_value(summary).ok();
    }
    let mut v: Value = serde_json::from_slice(bytes).ok()?;
    let obj = v.as_object_mut()?;
    let has_ref = |key: &str| {
        obj.get(key)
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    };
    let has_password = has_ref("auth_password_ref");
    let has_api = has_ref("api_token_ref");
    let has_cert = has_ref("auth_cert_ref");
    let has_unifi = has_ref("unifi_api_token_ref")
        && obj
            .get("unifi_controller_url")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
    for secret_key in HOST_SECRET_REF_KEYS {
        obj.remove(secret_key);
    }
    obj.insert("has_password".into(), Value::Bool(has_password));
    obj.insert("has_api".into(), Value::Bool(has_api));
    obj.insert("has_certificate".into(), Value::Bool(has_cert));
    obj.insert("has_unifi_controller".into(), Value::Bool(has_unifi));
    Some(v)
}

/// Collect Credential Manager labels to purge when deleting `host_id`.
///
/// Returns `(owned_labels, legacy_fallback_labels)`:
/// - `owned_labels` come from [`Host::secret_labels`] (or raw `*_ref` strings
///   if the JSON was partially malformed) and warrant a warning if deletion fails.
/// - `legacy_fallback_labels` cover deterministic labels written by older
///   daemons that omitted `SecretRef` fields from `hosts/<id>.json`.
pub(crate) fn host_secret_labels_for_delete(
    host_id: &str,
    bytes: Option<&[u8]>,
) -> (Vec<String>, Vec<String>) {
    let mut owned = Vec::new();
    if let Some(bytes) = bytes {
        if let Ok(host) = serde_json::from_slice::<Host>(bytes) {
            owned = host.secret_labels();
        } else if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
            for key in HOST_SECRET_REF_KEYS {
                if let Some(label) = v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()) {
                    if !owned.iter().any(|existing| existing == label) {
                        owned.push(label.to_owned());
                    }
                }
            }
        }
    }

    let deterministic = [
        host_password_label(host_id),
        format!("supermgr/ssh/{host_id}/password"),
        host_api_token_label(host_id),
        host_unifi_creds_label(host_id),
        format!("supermgr/host/{host_id}/opnsense-credentials"),
        format!("supermgr/host/{host_id}/sophos-credentials"),
    ];
    let mut fallbacks = Vec::new();
    for label in deterministic {
        if !owned.contains(&label) && !fallbacks.contains(&label) {
            fallbacks.push(label);
        }
    }
    (owned, fallbacks)
}

/// Canonical `SshKeyType` wire discriminant (`"ED25519"`, `"RSA2048"`, `"RSA4096"`).
pub(crate) fn canonical_ssh_key_type(raw: &str) -> Result<&'static str, RpcError> {
    match raw.to_ascii_lowercase().as_str() {
        "ed25519" => Ok("ED25519"),
        "rsa" | "rsa4096" | "rsa-4096" => Ok("RSA4096"),
        "rsa2048" | "rsa-2048" => Ok("RSA2048"),
        other => Err(RpcError::Other(format!(
            "unsupported key_type {other:?} (supported: ed25519, rsa2048, rsa4096)"
        ))),
    }
}

/// Build a canonical [`SshKey`] metadata JSON record (including `private_key_ref`
/// and `updated_at`) that round-trips cleanly through `serde_json::from_slice::<SshKey>`.
pub(crate) fn build_ssh_key_record(
    key_id: uuid::Uuid,
    name: &str,
    description: &str,
    key_type_raw: &str,
    fingerprint: &str,
    public_openssh: &str,
    tags_json: &str,
    secret_label: &str,
) -> Result<String, RpcError> {
    let canonical_type = canonical_ssh_key_type(key_type_raw)?;
    let tags: Vec<String> = serde_json::from_str::<Vec<String>>(tags_json).unwrap_or_default();
    let now = chrono::Utc::now().to_rfc3339();
    let raw = json!({
        "id": key_id.to_string(),
        "name": name,
        "description": description,
        "key_type": canonical_type,
        "fingerprint": fingerprint,
        "public_key": public_openssh,
        "private_key_ref": SecretRef::new(secret_label),
        "tags": tags,
        "created_at": now,
        "updated_at": now,
    });
    let typed: SshKey = serde_json::from_value(raw)
        .map_err(|e| RpcError::Other(format!("construct SshKey record: {e}")))?;
    serde_json::to_string(&typed)
        .map_err(|e| RpcError::Other(format!("serialise SshKey record: {e}")))
}

/// Collect Credential Manager labels to purge when deleting SSH key `key_id`.
pub(crate) fn key_secret_labels_for_delete(
    key_id: &str,
    bytes: Option<&[u8]>,
) -> (Vec<String>, Vec<String>) {
    let mut owned = Vec::new();
    if let Some(bytes) = bytes {
        if let Ok(key) = serde_json::from_slice::<SshKey>(bytes) {
            owned = key.secret_labels();
        } else if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
            if let Some(label) = v
                .get("private_key_ref")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                owned.push(label.to_owned());
            }
        }
    }
    let default_label = ssh_key_privkey_label(key_id);
    let fallbacks = if owned.contains(&default_label) {
        Vec::new()
    } else {
        vec![default_label]
    };
    (owned, fallbacks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn accepts_existing_uuid_spellings_without_changing_secret_labels() {
        for id in [
            "0123456789abcdef0123456789abcdef",
            "01234567-89ab-cdef-0123-456789abcdef",
            "01234567-89AB-CDEF-0123-456789ABCDEF",
        ] {
            let args = json!({"host_id": id});
            assert_eq!(arg_id(&args, "host_id").unwrap(), id);
        }
    }

    #[test]
    fn rejects_paths_and_non_filename_uuid_formats() {
        for id in [
            "",
            "..",
            "../outside",
            "..\\outside",
            "/etc/outside",
            "C:\\ProgramData\\outside",
            "C:outside",
            "\\outside",
            "\\\\server\\share\\outside",
            "\\\\?\\C:\\outside",
            "01234567-89ab-cdef-0123-456789abcdef:stream",
            "{01234567-89ab-cdef-0123-456789abcdef}",
            "urn:uuid:01234567-89ab-cdef-0123-456789abcdef",
            "01234567-89ab-cdef-0123-456789abcdef\0",
        ] {
            for name in ["host_id", "key_id"] {
                assert!(arg_id(&json!({name: id}), name).is_err(), "accepted {id:?}");
            }
        }
        assert!(arg_id(&json!({}), "host_id").is_err());
        assert!(arg_id(&json!({"host_id": 1}), "host_id").is_err());
    }

    #[tokio::test]
    async fn bounded_line_reader_caps_newline_less_streams_before_oom() {
        let huge = vec![b'a'; 4096];
        let mut reader = BufReader::new(huge.as_slice());
        let mut line = String::new();
        let res = read_bounded_line(&mut reader, &mut line, 128)
            .await
            .unwrap();
        assert_eq!(res, BoundedLine::Oversized);
        assert_eq!(line.len(), 129);

        // Oversized line WITH newline at byte 129 (total 129 > 128) is also rejected.
        let mut with_nl = vec![b'x'; 128];
        with_nl.push(b'\n');
        let mut reader = BufReader::new(with_nl.as_slice());
        line.clear();
        assert_eq!(
            read_bounded_line(&mut reader, &mut line, 128)
                .await
                .unwrap(),
            BoundedLine::Oversized
        );

        // Exact limit WITH newline (total 128 == max) succeeds.
        let mut exact = vec![b'y'; 127];
        exact.push(b'\n');
        let mut reader = BufReader::new(exact.as_slice());
        line.clear();
        assert_eq!(
            read_bounded_line(&mut reader, &mut line, 128)
                .await
                .unwrap(),
            BoundedLine::Frame
        );
        assert_eq!(line.len(), 128);

        // Clean EOF returns Eof.
        line.clear();
        assert_eq!(
            read_bounded_line(&mut reader, &mut line, 128)
                .await
                .unwrap(),
            BoundedLine::Eof
        );
    }

    #[test]
    fn azure_ovpn_validation_rejects_injection_and_ca_breakout() {
        let base = AzureVpnConfig {
            gateway_fqdn: "azuregateway-1.vpn.azure.com".into(),
            tenant_id: "11111111-2222-3333-4444-555555555555".into(),
            client_id: "41b23e61-6c1e-4545-b367-cd054e0ed4b4".into(),
            server_secret_hex: "00".repeat(32),
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into(),
            dns_servers: Vec::new(),
            routes: Vec::new(),
        };
        assert!(validate_azure_ovpn_inputs(&base).is_ok());

        let mut bad_gw = base.clone();
        bad_gw.gateway_fqdn = "gw.example.com\nscript-security 2\nup cmd.exe".into();
        assert!(validate_azure_ovpn_inputs(&bad_gw).is_err());

        let mut bad_tenant = base.clone();
        bad_tenant.tenant_id = "../evil".into();
        assert!(validate_azure_ovpn_inputs(&bad_tenant).is_err());

        let mut bad_client = base.clone();
        bad_client.client_id = "id?evil=1".into();
        assert!(validate_azure_ovpn_inputs(&bad_client).is_err());

        let mut bad_ca = base;
        bad_ca.ca_cert_pem = "MIIB\n</Ca>\nup C:\\evil.exe\n<ca>\n".into();
        assert!(validate_azure_ovpn_inputs(&bad_ca).is_err());
    }

    #[test]
    fn prepare_new_host_validates_inputs_and_strips_secret_refs() {
        let raw = json!({
            "label": "fw-01",
            "hostname": "10.0.1.1",
            "port": 22,
            "username": "admin",
            "group": "edge",
            "device_type": "fortigate",
            "auth_method": "password",
            "auth_password_ref": "supermgr/wg/stolen-secret",
            "auth_cert_ref": "supermgr/other/cert",
            "api_token_ref": "supermgr/other/token",
            "unifi_api_token_ref": "supermgr/other/unifi",
        })
        .to_string();

        let (id, cleaned) = prepare_new_host(&raw).unwrap();
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        for forbidden in HOST_SECRET_REF_KEYS {
            assert!(
                cleaned.get(forbidden).is_none(),
                "{forbidden} was not stripped"
            );
        }

        // Round-trips cleanly as Host and summarizes with accurate flags.
        let mut bytes = serde_json::to_vec(&cleaned).unwrap();
        let summary = summarize_host_json(&bytes).unwrap();
        assert_eq!(summary["has_password"], false);
        assert_eq!(summary["has_api"], false);

        // Recording password and API token updates HostSummary and SecretOwner labels.
        let pw_label = host_password_label(&id);
        let api_label = host_api_token_label(&id);
        let unifi_label = host_unifi_creds_label(&id);
        bytes = mutate_host_json(&bytes, |obj| {
            obj.insert("auth_password_ref".into(), Value::String(pw_label.clone()));
            obj.insert("api_port".into(), Value::from(8443u16));
            obj.insert("api_token_ref".into(), Value::String(api_label.clone()));
            obj.insert(
                "unifi_controller_url".into(),
                Value::String("https://unifi.example.com:8443".into()),
            );
            obj.insert(
                "unifi_api_token_ref".into(),
                Value::String(unifi_label.clone()),
            );
        })
        .unwrap();

        let summary = summarize_host_json(&bytes).unwrap();
        assert_eq!(summary["has_password"], true);
        assert_eq!(summary["has_api"], true);
        assert_eq!(summary["has_unifi_controller"], true);
        assert!(summary.get("auth_password_ref").is_none());

        let (owned, fallbacks) = host_secret_labels_for_delete(&id, Some(&bytes));
        assert!(owned.contains(&pw_label));
        assert!(owned.contains(&api_label));
        assert!(owned.contains(&unifi_label));
        assert!(fallbacks.contains(&format!("supermgr/ssh/{id}/password")));

        // Reject shell/option injection in hostname or username.
        let bad_host = json!({
            "label": "bad",
            "hostname": "-oProxyCommand=calc.exe",
            "port": 22,
            "username": "root",
            "device_type": "linux",
            "auth_method": "password",
        })
        .to_string();
        assert!(prepare_new_host(&bad_host).is_err());

        let bad_user = json!({
            "label": "bad",
            "hostname": "10.0.0.1",
            "port": 22,
            "username": "root;id",
            "device_type": "linux",
            "auth_method": "password",
        })
        .to_string();
        assert!(prepare_new_host(&bad_user).is_err());
    }

    #[test]
    fn legacy_host_without_secret_refs_still_cleans_deterministic_labels() {
        let host_id = "01234567-89ab-cdef-0123-456789abcdef";
        let legacy = json!({
            "id": host_id,
            "label": "legacy",
            "hostname": "10.0.0.5",
            "port": 22,
            "username": "admin",
            "device_type": "linux",
            "auth_method": "password",
            "created_at": "2026-01-01T00:00:00Z",
        });
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let (owned, fallbacks) = host_secret_labels_for_delete(host_id, Some(&bytes));
        assert!(owned.is_empty());
        assert!(fallbacks.contains(&format!("supermgr/host/{host_id}/password")));
        assert!(fallbacks.contains(&format!("supermgr/ssh/{host_id}/password")));
        assert!(fallbacks.contains(&format!("supermgr/host/{host_id}/api-token")));
        assert!(fallbacks.contains(&format!("supermgr/host/{host_id}/unifi-credentials")));
    }

    #[test]
    fn ssh_key_record_round_trips_and_legacy_keys_still_clean_up() {
        let key_id = uuid::Uuid::new_v4();
        let label = ssh_key_privkey_label(&key_id.to_string());
        let json_str = build_ssh_key_record(
            key_id,
            "deploy",
            "prod deploy key",
            "ed25519",
            "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI deploy",
            r#"["prod"]"#,
            &label,
        )
        .unwrap();

        let parsed: SshKey = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.id, key_id);
        assert_eq!(parsed.secret_labels(), vec![label.clone()]);

        let (owned, fallbacks) =
            key_secret_labels_for_delete(&key_id.to_string(), Some(json_str.as_bytes()));
        assert_eq!(owned, vec![label]);
        assert!(fallbacks.is_empty());

        // Legacy key record missing private_key_ref and updated_at with lowercase key_type:
        let legacy_key = json!({
            "id": key_id.to_string(),
            "name": "old-key",
            "key_type": "ed25519",
            "fingerprint": "SHA256:abc",
            "public_key": "ssh-ed25519 AAA",
            "created_at": "2026-01-01T00:00:00Z",
        });
        let legacy_bytes = serde_json::to_vec(&legacy_key).unwrap();
        let (owned, fallbacks) =
            key_secret_labels_for_delete(&key_id.to_string(), Some(&legacy_bytes));
        assert!(owned.is_empty());
        assert_eq!(fallbacks, vec![format!("supermgr/ssh/{key_id}/privkey")]);
    }
}
