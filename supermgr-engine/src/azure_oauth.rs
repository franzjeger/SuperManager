//! Microsoft Entra ID OAuth2 device-code flow + runtime detection
//! for Azure VPN.
//!
//! The Azure VPN gateway authenticates clients with an Entra ID
//! access token in the OpenVPN `auth-user-pass` password slot.
//! For a desktop client to obtain that token without an embedded
//! webview, Microsoft uses the **device code flow** (RFC 8628):
//!
//!   1. Client POSTs to `/oauth2/v2.0/devicecode` and receives a
//!      short user-readable `user_code` plus a long-lived
//!      `device_code` and a `verification_uri`.
//!   2. The user opens the URI in any browser, signs in, and
//!      enters the `user_code`. Browser stays out-of-band — the
//!      app never sees the user's password.
//!   3. Client polls `/oauth2/v2.0/token` with the device_code.
//!      Returns `authorization_pending` until the user completes
//!      the browser flow, then returns an `access_token`.
//!
//! We split the flow into two RPCs (`vpn_azure_device_code_start`
//! and `vpn_azure_device_code_poll`) so the GUI can drive the
//! polling loop with its own UI state. The daemon stays
//! stateless — it doesn't track which device codes are in flight,
//! the GUI hands the device_code back on every poll.
//!
//! # Client app ID
//!
//! Microsoft's Azure VPN Client uses public app id
//! `41b23e61-6c1e-4545-b367-cd054e0ed4b4`. We piggyback on that
//! registration so users don't need a custom AAD app. The
//! `client_id` from the imported `.azurevpnconfig` is the
//! *audience* — what the gateway expects to see in the token —
//! and is requested as the OAuth `scope`.

use serde::{Deserialize, Serialize};

/// Microsoft's public client-app ID for the Azure VPN Client.
/// Documented at <https://learn.microsoft.com/azure/vpn-gateway/openvpn-azure-ad-tenant>.
const AZURE_VPN_CLIENT_APP_ID: &str = "41b23e61-6c1e-4545-b367-cd054e0ed4b4";

/// Endpoints under <https://login.microsoftonline.com/{tenant}>.
fn devicecode_url(tenant: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode")
}
fn token_url(tenant: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
}

/// Server response from `/oauth2/v2.0/devicecode`. We re-export
/// the user-facing fields — the GUI displays `user_code` + opens
/// `verification_uri` and discards the rest. `device_code` is
/// echoed straight back to us on the next poll RPC; we don't
/// store it.
#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceCodeStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /// How long the device_code stays valid, in seconds. Microsoft
    /// usually returns 900 (15 min); the GUI uses this to size the
    /// "code expires in…" countdown.
    pub expires_in: i64,
    /// Recommended poll interval. Microsoft returns 5 (seconds).
    /// Honour this — `slow_down` errors mean we polled too fast.
    pub interval: i64,
}

/// Polling result. Three terminal states + one transient.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeviceCodePoll {
    /// Token issued. `access_token` becomes the OpenVPN password;
    /// `username` is what we'll send in the `auth-user-pass` user
    /// slot (preferred_username from the id_token if present, else
    /// a placeholder).
    Authorized {
        access_token: String,
        username: String,
        /// Seconds until the access_token expires. The GUI surfaces
        /// this so the user knows roughly how long the VPN session
        /// is good for before re-authentication.
        expires_in: i64,
    },
    /// User hasn't completed the browser flow yet — keep polling.
    Pending,
    /// User code expired (~15 min default). Restart the flow.
    Expired,
    /// User cancelled the auth, or AAD denied (consent declined,
    /// tenant guest restrictions, etc.). `description` is
    /// Microsoft's human-readable reason — show it as-is.
    Denied { description: String },
}

/// Kick off the device-code flow against the given tenant. The
/// client_id is the gateway's expected audience (from the
/// `.azurevpnconfig`); we wrap it as a `.default` scope.
pub async fn start_device_flow(
    tenant: &str,
    audience: &str,
) -> anyhow::Result<DeviceCodeStart> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let scope = format!("{audience}/.default offline_access openid profile");
    let body = format!(
        "client_id={}&scope={}",
        AZURE_VPN_CLIENT_APP_ID,
        urlencoding(&scope),
    );

    let resp = client
        .post(devicecode_url(tenant))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Microsoft devicecode endpoint returned {status}: {text}"
        ));
    }

    serde_json::from_str(&text).map_err(|e| {
        anyhow::anyhow!("couldn't parse devicecode response: {e}\n\nbody: {text}")
    })
}

/// One poll against the token endpoint. The caller is responsible
/// for spacing polls at `interval` seconds (we don't sleep here).
pub async fn poll_token(
    tenant: &str,
    device_code: &str,
) -> anyhow::Result<DeviceCodePoll> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let body = format!(
        "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={}&device_code={}",
        AZURE_VPN_CLIENT_APP_ID,
        urlencoding(device_code),
    );

    let resp = client
        .post(token_url(tenant))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;

    // Successful auth: 200 + access_token. Pending / errors:
    // non-2xx with an `error` field. Both paths come through
    // here and we discriminate on the parsed body.
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        anyhow::anyhow!("couldn't parse token-endpoint response (status {status}): {e}\n\nbody: {text}")
    })?;

    if status.is_success() {
        let access_token = json
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("token response missing access_token: {text}"))?
            .to_owned();
        let expires_in = json
            .get("expires_in")
            .and_then(|v| v.as_i64())
            .unwrap_or(3600);
        // Lift `preferred_username` from the id_token JWT payload
        // for use as the OpenVPN auth-user-pass username. The
        // gateway extracts identity from the access_token regardless,
        // but a real UPN in the username slot is what shows up in
        // the OpenVPN log so it's worth pulling.
        let username = json
            .get("id_token")
            .and_then(|v| v.as_str())
            .and_then(decode_id_token_username)
            .unwrap_or_else(|| "azure_vpn".to_owned());

        return Ok(DeviceCodePoll::Authorized {
            access_token,
            username,
            expires_in,
        });
    }

    let err = json.get("error").and_then(|v| v.as_str()).unwrap_or("");
    let desc = json
        .get("error_description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    Ok(match err {
        "authorization_pending" | "slow_down" => DeviceCodePoll::Pending,
        "expired_token" | "code_expired" => DeviceCodePoll::Expired,
        // Everything else (access_denied, invalid_grant, …) we
        // surface as Denied with the AAD-supplied description.
        // The strings are admin-meaningful — consent issues,
        // conditional access policies, etc.
        _ => DeviceCodePoll::Denied {
            description: if desc.is_empty() {
                format!("Microsoft returned status {status}: {text}")
            } else {
                desc
            },
        },
    })
}

/// Lift the `preferred_username` claim from a JWT id_token. We
/// don't validate the signature — this is just for display; the
/// gateway is what verifies the access_token cryptographically.
fn decode_id_token_username(jwt: &str) -> Option<String> {
    use base64::Engine as _;
    let payload_b64 = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("preferred_username")
        .and_then(|s| s.as_str())
        .map(|s| s.to_owned())
}

/// Cheap percent-encoder — just the chars we actually emit (`/`,
/// `:`, `+`, `=` in scopes / device codes). Avoids pulling in
/// a full url-crate dep when reqwest's form helper would also
/// add overhead.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Runtime detection
// ---------------------------------------------------------------------------

/// What's installed on this Mac that can carry an Azure-AAD VPN
/// session. Azure's Entra ID flow puts an OAuth2 access token in
/// the OpenVPN `auth-user-pass` password slot — vanilla OpenVPN
/// 2.x doesn't speak this dialect reliably (it doesn't refresh
/// the token, doesn't handle the SAML push, can fail mid-handshake
/// on some gateway versions). The fix is OpenVPN 3.x or one of
/// the Mac apps that wraps it.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AzureRuntime {
    /// `openvpn3` CLI (from `openvpn3-linux` / `openvpn3-aircrack`
    /// or a similar port). We can spawn this directly from the
    /// helper. This is the cleanest path because it gives us
    /// session lifetime control.
    Openvpn3Cli { path: String },
    /// Microsoft's "Azure VPN Client" (App Store). Wraps openvpn3
    /// internally. We hand the imported `.azurevpnconfig` to it
    /// via `open -a` and lose direct lifetime control, but the
    /// user gets a working tunnel without any extra setup.
    AzureVpnClientApp { path: String },
    /// "OpenVPN Connect" (App Store). Also wraps openvpn3, but
    /// is generic — the user has to wire up the .ovpn manually
    /// the first time, and we can't drive it programmatically
    /// from the helper. Listed as a discoverable option so the
    /// UI can suggest it.
    OpenvpnConnectApp { path: String },
    /// **Only OpenVPN 2.x** is installed. We refuse to launch
    /// Azure connections on this stack — past the import step
    /// the user gets a guided "install one of the above" message.
    Only2x { path: String },
    /// No OpenVPN-family runtime detected at all. Same UX as
    /// `Only2x`, just with a different lead message.
    None,
}

impl AzureRuntime {
    /// True iff we can drive the connection from the privileged
    /// helper — i.e. the runtime is a CLI we can spawn, not a
    /// .app we'd need to hand off to.
    pub fn is_helper_driveable(&self) -> bool {
        matches!(self, AzureRuntime::Openvpn3Cli { .. })
    }

    /// True iff *some* macOS app exists that can complete an
    /// Azure-AAD VPN session, even if we can't drive it from the
    /// helper. Drives the GUI's "Open in Azure VPN Client" button.
    pub fn is_app_handoff(&self) -> bool {
        matches!(
            self,
            AzureRuntime::AzureVpnClientApp { .. } | AzureRuntime::OpenvpnConnectApp { .. }
        )
    }
}

/// Detect what's available, in preference order:
///   1. `openvpn3` CLI binary (we own the session lifetime)
///   2. Microsoft's Azure VPN Client (handoff, but Azure-specific
///      and most reliable for AAD)
///   3. OpenVPN Connect (handoff, generic)
///   4. OpenVPN 2.x (refused — token-as-password handshake is too
///      flaky to ship as a default)
///   5. Nothing
pub fn detect_azure_runtime() -> AzureRuntime {
    // Brew prefixes + a few known custom-port locations. The
    // openvpn3-aircrack port lands the binary at `/usr/local/sbin`
    // by default; macports puts it under `/opt/local/bin`.
    const OVPN3_CLI_PATHS: &[&str] = &[
        "/opt/homebrew/bin/openvpn3",
        "/opt/homebrew/sbin/openvpn3",
        "/usr/local/bin/openvpn3",
        "/usr/local/sbin/openvpn3",
        "/opt/local/bin/openvpn3",
    ];
    for p in OVPN3_CLI_PATHS {
        if std::path::Path::new(p).exists() {
            return AzureRuntime::Openvpn3Cli { path: (*p).to_owned() };
        }
    }

    let azure_app = "/Applications/Azure VPN Client.app";
    if std::path::Path::new(azure_app).exists() {
        return AzureRuntime::AzureVpnClientApp { path: azure_app.to_owned() };
    }

    let connect_app = "/Applications/OpenVPN Connect.app";
    if std::path::Path::new(connect_app).exists() {
        return AzureRuntime::OpenvpnConnectApp { path: connect_app.to_owned() };
    }

    // Last-resort 2.x detection. We DON'T return this as "good
    // to go" — the GUI surfaces it as `unsupported` so the user
    // gets actionable install instructions instead of a confusing
    // mid-handshake failure later.
    const OVPN2_PATHS: &[&str] = &[
        "/opt/homebrew/sbin/openvpn",
        "/opt/homebrew/bin/openvpn",
        "/usr/local/sbin/openvpn",
        "/usr/local/bin/openvpn",
    ];
    for p in OVPN2_PATHS {
        if std::path::Path::new(p).exists() {
            return AzureRuntime::Only2x { path: (*p).to_owned() };
        }
    }

    AzureRuntime::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_handles_special_chars() {
        assert_eq!(urlencoding("hello"), "hello");
        assert_eq!(urlencoding("a/b"), "a%2Fb");
        assert_eq!(urlencoding("api://x"), "api%3A%2F%2Fx");
        assert_eq!(urlencoding("a+b=c"), "a%2Bb%3Dc");
    }

    #[test]
    fn decode_id_token_username_pulls_preferred_username() {
        // Hand-rolled JWT: header.payload.sig where payload has
        // `preferred_username = alice@example.com`. Header and sig
        // are placeholders — we don't validate them.
        let payload = r#"{"preferred_username":"alice@example.com","name":"Alice"}"#;
        use base64::Engine as _;
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        let jwt = format!("aaa.{payload_b64}.bbb");
        let upn = decode_id_token_username(&jwt);
        assert_eq!(upn.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn decode_id_token_username_returns_none_on_garbage() {
        assert_eq!(decode_id_token_username("not.a.jwt"), None);
        assert_eq!(decode_id_token_username(""), None);
        assert_eq!(decode_id_token_username("only_one_segment"), None);
    }

    #[test]
    fn runtime_helper_classifiers() {
        // Smoke-tests for the boolean predicates. Build dummy
        // variants without touching the filesystem.
        let cli = AzureRuntime::Openvpn3Cli { path: "/usr/bin/openvpn3".into() };
        assert!(cli.is_helper_driveable());
        assert!(!cli.is_app_handoff());

        let azure_app = AzureRuntime::AzureVpnClientApp { path: "/Applications/X.app".into() };
        assert!(!azure_app.is_helper_driveable());
        assert!(azure_app.is_app_handoff());

        let connect_app = AzureRuntime::OpenvpnConnectApp { path: "/Applications/Y.app".into() };
        assert!(connect_app.is_app_handoff());

        let only2x = AzureRuntime::Only2x { path: "/usr/sbin/openvpn".into() };
        assert!(!only2x.is_helper_driveable());
        assert!(!only2x.is_app_handoff(), "2.x can't carry AAD reliably — refuse, don't pretend");

        let none = AzureRuntime::None;
        assert!(!none.is_helper_driveable());
        assert!(!none.is_app_handoff());
    }

    #[test]
    fn detect_returns_some_variant() {
        // We can't assert which specific variant — depends on
        // whatever's installed on the test box — but it must
        // never panic, and it must return *some* variant.
        let _ = detect_azure_runtime();
    }
}
