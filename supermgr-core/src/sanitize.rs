//! Shared input-validation and safe string-slicing primitives.
//!
//! Centralises trust-boundary checks (hostnames, SSH usernames, identifiers,
//! URLs, and UTF-8 byte truncation) so all platform daemons and clients enforce
//! identical rules without drifting.

use std::net::IpAddr;

/// Truncate `s` to at most `max_bytes` UTF-8 bytes without ever splitting a
/// multi-byte codepoint.
#[must_use]
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    &s[..s.floor_char_boundary(max_bytes)]
}

/// Validate a network target as either a literal IPv4/IPv6 address (with
/// optional surrounding `[...]` stripped if IPv6) or an RFC-1123 hostname.
///
/// Rejects empty strings, leading dashes (CLI option injection), whitespace,
/// control characters, quotes, braces, and shell metacharacters.
pub fn validate_host_or_ip(raw: &str) -> Result<(), String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("hostname or IP address must not be empty".into());
    }
    if s.len() > 253 {
        return Err("hostname exceeds 253 characters".into());
    }
    if s.starts_with('-') {
        return Err("hostname must not start with '-'".into());
    }
    let bracket_stripped = s
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(s);
    if bracket_stripped.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid hostname label in '{s}'"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("hostname label in '{s}' starts or ends with '-'"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "hostname '{s}' contains invalid characters (expected hostname or IP)"
            ));
        }
    }
    Ok(())
}

/// Validate an SSH / appliance username against shell and CLI option injection.
///
/// Permits standard POSIX, email-style (`user@domain`), and AD (`DOMAIN\user` is
/// disallowed for OpenSSH `-l` / `user@host` shell safety unless simple) tokens:
/// ASCII `[A-Za-z0-9._@-]+`, non-empty, not starting with `-`.
pub fn validate_ssh_username(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err("username must not be empty".into());
    }
    if raw.len() > 128 {
        return Err("username exceeds 128 characters".into());
    }
    if raw.starts_with('-') {
        return Err("username must not start with '-'".into());
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@' | b'+'))
    {
        return Err("username contains disallowed characters".into());
    }
    Ok(())
}

/// Validate a safe single-segment identifier (e.g. template ID, admin user,
/// path-embedded slug): `[A-Za-z0-9._-]+`, non-empty, not `.` or `..`, and not
/// starting with `-`.
pub fn validate_safe_ident(raw: &str, field: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if raw.len() > 128 {
        return Err(format!("{field} exceeds 128 characters"));
    }
    if raw == "." || raw == ".." || raw.starts_with('-') {
        return Err(format!("invalid {field}"));
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!("{field} contains disallowed characters"));
    }
    Ok(())
}

/// Validate an HTTP(S) inform URL so it is safe to pass to UniFi `set-inform`
/// over SSH without shell metacharacter injection.
pub fn validate_inform_url(raw: &str) -> Result<(), String> {
    let s = raw.trim();
    if !(s.starts_with("http://") || s.starts_with("https://")) {
        return Err("inform URL must start with http:// or https://".into());
    }
    if s.len() > 512 {
        return Err("inform URL exceeds 512 characters".into());
    }
    // Only allow safe URI characters that have zero shell interpretation.
    if !s.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b':' | b'/' | b'.' | b'-' | b'_' | b'[' | b']' | b'~')
    }) {
        return Err("inform URL contains disallowed or shell-unsafe characters".into());
    }
    Ok(())
}

/// POSIX single-quote shell escaping (`'foo'\''bar'`).
#[must_use]
pub fn posix_shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_utf8_never_panics_mid_codepoint() {
        let s = "Blåbær"; // 'å' is bytes 2..4, 'æ' is bytes 5..7
        assert_eq!(truncate_utf8(s, 3), "Bl");
        assert_eq!(truncate_utf8(s, 4), "Blå");
        assert_eq!(truncate_utf8(s, 100), "Blåbær");
    }

    #[test]
    fn validate_host_or_ip_blocks_injection_and_accepts_valid_targets() {
        assert!(validate_host_or_ip("192.168.1.1").is_ok());
        assert!(validate_host_or_ip("2001:db8::1").is_ok());
        assert!(validate_host_or_ip("[2001:db8::1]").is_ok());
        assert!(validate_host_or_ip("fw-01.corp.example.com").is_ok());

        assert!(validate_host_or_ip("-oProxyCommand=id").is_err());
        assert!(validate_host_or_ip("host; id").is_err());
        assert!(validate_host_or_ip("host\nupdown = /bin/sh").is_err());
        assert!(validate_host_or_ip("host$(whoami)").is_err());
        assert!(validate_host_or_ip("").is_err());
    }

    #[test]
    fn validate_ssh_username_blocks_options_and_shell_chars() {
        assert!(validate_ssh_username("admin").is_ok());
        assert!(validate_ssh_username("svc.ops@corp.local").is_ok());
        assert!(validate_ssh_username("-oProxyCommand=sh").is_err());
        assert!(validate_ssh_username("root;id").is_err());
        assert!(validate_ssh_username("user name").is_err());
    }

    #[test]
    fn validate_inform_url_blocks_metacharacters() {
        assert!(validate_inform_url("http://10.0.0.5:8080/inform").is_ok());
        assert!(validate_inform_url("https://unifi.example.com:8443/inform").is_ok());
        assert!(validate_inform_url("http://10.0.0.5:8080/inform;reboot").is_err());
        assert!(validate_inform_url("http://10.0.0.5:8080/inform?$(id)").is_err());
        assert!(validate_inform_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn posix_shell_quote_escapes_single_quotes() {
        assert_eq!(posix_shell_quote("abc"), "'abc'");
        assert_eq!(posix_shell_quote("a'b"), "'a'\\''b'");
    }
}
