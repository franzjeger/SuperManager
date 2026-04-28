//! Sophos Firewall (XG / SFOS) XML Configuration API client.
//!
//! # State of the world (2026-04, SFOS 21.5)
//!
//! Sophos exposes **only** the legacy XML Configuration API at
//! `https://<host>:<admin_port>/webconsole/APIController`. There is no
//! modern JSON REST surface as of SFOS 22.0. Auth is per-request: the
//! caller embeds `<Login><Username>...</Username><Password>...</Password></Login>`
//! in every XML payload — no token, no session cookie.
//!
//! # What this module *can* do
//!
//! - Send arbitrary `<Get>`, `<Set>`, `<Remove>` operations on configuration
//!   entities (firewall rules, IP host objects, services, NAT, VPN, etc.)
//!   and return the XML response body.
//! - Wrap the caller's payload in `<Request>` envelope + the `<Login>` block,
//!   URL-encode for `application/x-www-form-urlencoded`, send, return.
//!
//! # What this module *cannot* do
//!
//! These are limits of the upstream API, not of this code:
//!
//! - No firmware version query — Sophos has not exposed it through the
//!   Configuration API as of this writing. The community workaround is
//!   SNMP or `system diagnostics show version` over SSH.
//! - No uptime / CPU load / memory metrics — same gap as firmware.
//! - No HA status query.
//! - No config-backup download endpoint — backups go through the
//!   *Backup and Firmware → Import/Export* WebAdmin page only.
//!
//! Until Sophos ships a real REST API or documents missing entity tags,
//! a "dashboard card" comparable to FortiGate/OPNsense is not possible
//! from the API alone. SNMP integration is a viable follow-up.
//!
//! # Sources
//!
//! - <https://docs.sophos.com/nsg/sophos-firewall/22.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Administration/API/APIConfiguration/index.html>
//! - <https://docs.sophos.com/nsg/sophos-firewall/21.5/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/APIXMLTags/index.html>

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::debug;

/// Stored credential blob for one Sophos host.
///
/// Sent as `<Login>` on every API call — Sophos does not issue tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// WebAdmin username (typically `admin` or a service account).
    pub username: String,
    /// WebAdmin password.
    pub password: String,
}

/// Outcome of an XML API request.
#[derive(Debug)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Raw XML response body.
    pub body: String,
}

/// XML-escape a value before embedding it in the request envelope.
///
/// Sophos rejects any payload that isn't well-formed XML; a stray
/// `&` or `<` in a password silently breaks login with no diagnostic.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Wrap a caller-supplied operation fragment in the Sophos request envelope.
///
/// `inner_xml` is everything that goes between the `<Login>...</Login>` block
/// and the closing `</Request>` — typically one or more `<Get>`, `<Set>`, or
/// `<Remove>` blocks. Whitespace and indentation are not significant to
/// the API.
pub fn wrap_request(creds: &Credentials, inner_xml: &str) -> String {
    format!(
        "<Request>\
            <Login>\
                <Username>{user}</Username>\
                <Password>{pass}</Password>\
            </Login>\
            {inner}\
         </Request>",
        user = xml_escape(&creds.username),
        pass = xml_escape(&creds.password),
        inner = inner_xml,
    )
}

/// Build a reqwest client suitable for talking to a Sophos firewall.
///
/// Self-signed certs on Sophos appliances are the norm, so verification is
/// disabled. 30 s combined connect+read timeout matches the OPNsense client.
fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .build()
}

/// Send an XML Configuration API request.
///
/// `inner_xml` is the operation body (already escaped — caller is responsible
/// for XML-encoding any user-supplied values inside it). The login block is
/// added by this function.
///
/// Returns the response body as text; the caller parses it. The Sophos API
/// always replies with `HTTP 200` regardless of operation success — actual
/// success/failure is in the `<Status>` tag of the XML body.
pub async fn xml_request(
    hostname: &str,
    port: u16,
    creds: &Credentials,
    inner_xml: &str,
) -> Result<Response, String> {
    let url = format!("https://{hostname}:{port}/webconsole/APIController");
    let envelope = wrap_request(creds, inner_xml);
    debug!("sophos::xml_request -> {url}");

    let client = http_client().map_err(|e| format!("HTTP client build failed: {e}"))?;

    // Sophos accepts the payload via `reqxml` form parameter on POST.
    let resp = client
        .post(&url)
        .form(&[("reqxml", envelope.as_str())])
        .send()
        .await
        .map_err(|e| {
            let msg = e.to_string().replace(&creds.password, "***");
            if e.is_timeout() {
                format!("Sophos API request timed out at {hostname}:{port}: {msg}")
            } else if e.is_connect() {
                format!("cannot connect to Sophos at {hostname}:{port}: {msg}")
            } else {
                format!("Sophos API request failed: {msg}")
            }
        })?;

    let status = resp.status().as_u16();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("read response body: {e}"))?;
    Ok(Response { status, body })
}

/// Whether a Sophos response body indicates a successful operation.
///
/// The XML wraps each operation in `<Status code="N" .../>`. Codes documented
/// as success: 200, 216 (configuration applied), 250 (no change). Anything
/// else — most importantly 500 and 530 (auth failure) — is an error.
///
/// This is a coarse helper; for production use you'll want to extract the
/// human-readable text after the status code too.
pub fn looks_successful(body: &str) -> bool {
    // The XML may or may not have whitespace between attributes; do a
    // simple substring check on the documented success codes. For a real
    // parser, swap in `quick-xml`.
    body.contains("code=\"200\"")
        || body.contains("code=\"216\"")
        || body.contains("code=\"250\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_handles_all_five_predefined_entities() {
        let raw = r#"<a&b>"c'd""#;
        let escaped = xml_escape(raw);
        // None of the literal special chars should remain.
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        // & is replaced by entities, but the escape sequences themselves contain &.
        assert_eq!(escaped, "&lt;a&amp;b&gt;&quot;c&apos;d&quot;");
    }

    #[test]
    fn wrap_request_escapes_credentials() {
        let creds = Credentials {
            username: "ad<min".into(),
            password: "p&s>s".into(),
        };
        let env = wrap_request(&creds, "<Get><Status/></Get>");
        // Raw <, >, & from creds must not appear unescaped.
        assert!(env.contains("<Username>ad&lt;min</Username>"));
        assert!(env.contains("<Password>p&amp;s&gt;s</Password>"));
        // Inner XML passes through verbatim — caller's responsibility to escape it.
        assert!(env.contains("<Get><Status/></Get>"));
    }

    #[test]
    fn looks_successful_recognises_documented_codes() {
        assert!(looks_successful(r#"<Status code="200">OK</Status>"#));
        assert!(looks_successful(r#"<Status code="216">Configuration applied</Status>"#));
        assert!(looks_successful(r#"<Status code="250">No change</Status>"#));
    }

    #[test]
    fn looks_successful_rejects_auth_failure() {
        assert!(!looks_successful(
            r#"<Login status="Authentication Failure"></Login>"#
        ));
        assert!(!looks_successful(r#"<Status code="500">Operation failed</Status>"#));
        assert!(!looks_successful(r#"<Status code="530">Authentication failure</Status>"#));
    }

    #[test]
    fn credentials_round_trip_json() {
        let c = Credentials {
            username: "u".into(),
            password: "p".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        let parsed: Credentials = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.username, "u");
        assert_eq!(parsed.password, "p");
    }
}
