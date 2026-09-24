//! TCP and UDP port numbers from untrusted input.
//!
//! Ports arrive as JSON numbers — from the GUI, the MCP server, host files
//! on disk — and `as u16` on one wraps silently: 65558 becomes 22, 65536
//! becomes 0. These take only what is a port, 1 to 65535, and leave the
//! caller to say what anything else means.

use serde_json::Value;

/// `value` as a port, if it is one: an integer from 1 to 65535.
#[must_use]
pub fn from_json(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .filter(|&port| port != 0)
}

/// `value`, given as `key`, which must be a port.
pub fn parse(key: &str, value: &Value) -> Result<u16, InvalidPort> {
    from_json(value).ok_or_else(|| InvalidPort::new(key, value))
}

/// `value`, given as `key`, for a port that may be left unset: `null` and 0
/// mean none, anything else must be a port.
pub fn parse_optional(key: &str, value: &Value) -> Result<Option<u16>, InvalidPort> {
    match value {
        Value::Null => Ok(None),
        v if v.as_u64() == Some(0) => Ok(None),
        v => parse(key, v).map(Some),
    }
}

/// The port at `key` in `object`, if one is given: `None` when the key is
/// missing or `null`, and an error naming the key when there is something
/// that is not a port.
pub fn field(object: &Value, key: &str) -> Result<Option<u16>, InvalidPort> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse(key, value).map(Some),
    }
}

/// The port at `key` in `object`, or `default` when none is given.
pub fn field_or(object: &Value, key: &str, default: u16) -> Result<u16, InvalidPort> {
    field(object, key).map(|port| port.unwrap_or(default))
}

/// The port at `key` in `object`, where 0 is a way to give none, as it is
/// for "keep the port the host has".
pub fn optional_field(object: &Value, key: &str) -> Result<Option<u16>, InvalidPort> {
    object
        .get(key)
        .map_or(Ok(None), |value| parse_optional(key, value))
}

/// Something given as a port that is not one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{key} must be a port from 1 to 65535, not {value}")]
pub struct InvalidPort {
    /// Where it was given.
    pub key: String,
    /// What was given, as JSON.
    pub value: String,
}

impl InvalidPort {
    fn new(key: &str, value: &Value) -> Self {
        Self {
            key: key.to_owned(),
            value: value.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_1_to_65535_is_a_port() {
        assert_eq!(from_json(&json!(22)), Some(22));
        assert_eq!(from_json(&json!(65535)), Some(65535));
        // What `as u16` made of these: 22 and 0.
        assert_eq!(from_json(&json!(65558)), None);
        assert_eq!(from_json(&json!(65536)), None);
        assert_eq!(from_json(&json!(0)), None);
        assert_eq!(from_json(&json!(-1)), None);
        assert_eq!(from_json(&json!(22.5)), None);
        assert_eq!(from_json(&json!("22")), None);
    }

    #[test]
    fn a_wrong_port_is_an_error_that_names_it() {
        assert_eq!(parse("port", &json!(2222)), Ok(2222));
        assert_eq!(
            parse("api_port", &json!(70000)).unwrap_err().to_string(),
            "api_port must be a port from 1 to 65535, not 70000"
        );
        assert!(parse("port", &Value::Null).is_err());
    }

    #[test]
    fn an_unset_port_is_null_or_zero() {
        assert_eq!(parse_optional("rdp_port", &Value::Null), Ok(None));
        assert_eq!(parse_optional("rdp_port", &json!(0)), Ok(None));
        assert_eq!(parse_optional("rdp_port", &json!(3389)), Ok(Some(3389)));
        assert!(parse_optional("rdp_port", &json!(70000)).is_err());
        assert!(parse_optional("rdp_port", &json!("x")).is_err());
    }

    #[test]
    fn a_missing_port_takes_the_default() {
        let host = json!({ "port": 2222, "api_port": 70000, "rdp_port": null });
        assert_eq!(field(&host, "port"), Ok(Some(2222)));
        assert_eq!(field(&host, "rdp_port"), Ok(None));
        assert_eq!(field_or(&host, "port", 22), Ok(2222));
        assert_eq!(field_or(&host, "ssh_port", 22), Ok(22));
        assert_eq!(field_or(&host, "rdp_port", 3389), Ok(3389));
        assert!(field(&host, "api_port").is_err());
        assert!(field_or(&host, "api_port", 443).is_err());
        // Given, 0 is not a port; only an optional field reads it as none.
        assert!(field(&json!({ "port": 0 }), "port").is_err());
        assert_eq!(optional_field(&json!({ "port": 0 }), "port"), Ok(None));
        assert_eq!(optional_field(&json!({}), "port"), Ok(None));
        assert_eq!(
            optional_field(&json!({ "port": 8443 }), "port"),
            Ok(Some(8443))
        );
        assert!(optional_field(&json!({ "port": 65536 }), "port").is_err());
    }
}
