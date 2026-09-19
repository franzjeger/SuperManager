//! Validation shared by Windows RPC handlers; portable so it can be tested
//! without a running privileged Windows service.

use serde_json::Value;
use supermgr_core::protocol::RpcError;

/// Accept only UUID filename components, preserving the existing simple or
/// hyphenated spelling used by stored records and credential labels.
pub(crate) fn arg_id<'a>(args: &'a Value, name: &str) -> Result<&'a str, RpcError> {
    let value = args
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Protocol(format!("missing string arg: {name}")))?;
    if !matches!(value.len(), 32 | 36) || uuid::Uuid::parse_str(value).is_err() {
        return Err(RpcError::Protocol(format!("invalid UUID arg: {name}")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
                assert_eq!(
                    json!({name: id}).get(name).and_then(Value::as_str),
                    Some(id)
                );
                assert!(arg_id(&json!({name: id}), name).is_err(), "accepted {id:?}");
            }
        }
        assert!(arg_id(&json!({}), "host_id").is_err());
        assert!(arg_id(&json!({"host_id": 1}), "host_id").is_err());
    }
}
