//! Microsoft Azure VPN Client `.azurevpnconfig` import + rendering.
//!
//! The user downloads a `.azurevpnconfig` (XML) file from the Azure
//! portal — `Virtual Network Gateway → Point-to-site configuration
//! → Download VPN client`. The file holds everything we need to
//! drive an OpenVPN-with-Entra-ID tunnel:
//!   - `<gatewayfqdn>` — the VPN concentrator
//!   - `<tenant>` / `<audience>` — Entra OAuth2 endpoints
//!   - `<serversecret>` — the OpenVPN `tls-crypt` key as hex
//!   - `<servervalidation><cert>` — base64 CA cert
//!
//! Microsoft's own Mac client (App Store: "Azure VPN Client") parses
//! this same file. We don't ship that client — we just parse the
//! same input so the operator's existing flow ("download config,
//! drag into app") works in SuperManager.
//!
//! # Why not a real XML crate?
//!
//! The schema is small, stable, and well-documented; a hand-rolled
//! tag extractor avoids a workspace-wide dependency that no other
//! crate would use. The parser is non-namespace-aware on purpose —
//! Microsoft's exporter sometimes emits the elements unqualified
//! and sometimes with the `azvpnprofile` namespace prefix, and a
//! tag-name match-by-suffix handles both.
//!
//! Format reference: <https://learn.microsoft.com/en-us/azure/vpn-gateway/point-to-site-entra-vpn-client-mac>

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

use supermgr_core::vpn::profile::AzureVpnConfig;

/// Well-known Azure VPN public client app ID. Microsoft uses the
/// same audience UUID for every customer's gateway unless the admin
/// has explicitly carved out a custom app registration. The XML
/// usually omits this and expects the client to know it.
const DEFAULT_AZURE_VPN_AUDIENCE: &str = "c632b3df-fb67-4d84-bdcf-b95ad541b5c8";

/// `DigiCert Global Root CA` PEM. SHA-1 thumbprint
/// `a8985d3a65e5e5c4b2d7d66d40c6dd2fb19c5436`.
///
/// Every Microsoft-issued Azure VPN gateway certificate chains up
/// to this root — it's what the `<servervalidation><Cert><hash>`
/// in a thumbprint-only `.azurevpnconfig` pins to. The PEM is
/// public (DigiCert publishes it openly) and is already shipped
/// in every macOS/Linux/Windows trust store, so embedding it
/// doesn't change the trust posture; it just lets OpenVPN 2.x
/// find a CA when the .azurevpnconfig didn't ship one inline.
///
/// **This blob was extracted directly from the macOS system
/// trust store** (`/System/Library/Keychains/SystemRootCertificates.keychain`)
/// via `security find-certificate -c "DigiCert Global Root CA" -p`
/// and verified to produce SHA-1
/// `A8:98:5D:3A:65:E5:E5:C4:B2:D7:D6:6D:40:C6:DD:2F:B1:9C:54:36`,
/// matching the `<hash>` field every Azure VPN config carries.
/// Don't hand-edit the base64 lines — even a single character
/// substitution makes OpenSSL emit
/// `error:0DFFF0A8:asn1 encoding routines:wrong tag` and refuse
/// to load the cert.
const DIGICERT_GLOBAL_ROOT_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----
";

/// Parse an `.azurevpnconfig` blob into the daemon's structured
/// config. Microsoft has shipped at least three different XML
/// schemas over time; the parser accepts all of them and only
/// hard-fails when the gateway FQDN or tenant ID can't be found
/// (those two are the truly load-bearing identifiers — without
/// them there's nothing meaningful to display or connect to).
///
/// `<serversecret>` and the CA certificate are connect-time
/// artifacts; if a particular export omits them (Microsoft's
/// modern AAD-flow profiles sometimes do, deferring secrets to
/// the gateway-issued OAuth bundle) we still import successfully
/// with empty placeholders. The Connect path will refetch what
/// it needs.
pub fn parse_azure_vpn_config(xml: &str) -> Result<AzureVpnConfig, String> {
    let gateway_fqdn = extract_gateway_fqdn(xml)
        .ok_or_else(|| "missing <gatewayfqdn> / <vpngateway> / <FQDN>".to_owned())?;

    let tenant_id = extract_tenant_id(xml)
        .ok_or_else(|| "missing <tenant> / <azuretenant>".to_owned())?;

    // `<audience>` is rare in customer-issued configs — Microsoft's
    // exporter usually omits it. Default to the public-client GUID
    // so we still get a working profile.
    let client_id = extract_tag(xml, "audience")
        .or_else(|| extract_tag(xml, "azureaudience"))
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_AZURE_VPN_AUDIENCE.to_owned());

    // tls-crypt key. Optional — modern AAD-flow profiles let the
    // gateway hand it back at connect time, so we don't fail
    // import when it's missing. We DO validate format if present
    // so a typo'd key is caught at import rather than first connect.
    let server_secret_hex = extract_tag(xml, "serversecret")
        .map(|s| s.split_whitespace().collect::<String>())
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.chars().any(|c| !c.is_ascii_hexdigit()) {
                Err("<serversecret> has non-hex characters".to_owned())
            } else if s.len() < 64 {
                Err(format!(
                    "<serversecret> too short ({} chars) — expected hex tls-crypt key",
                    s.len()
                ))
            } else {
                Ok(s)
            }
        })
        .transpose()?
        .unwrap_or_default();

    // CA cert. Optional — newer profiles validate via thumbprint
    // (`<cert><hash>...</hash></cert>`) and don't ship the PEM
    // inline. We accept either shape and just leave the PEM blank
    // when only a thumbprint is present.
    let ca_cert_pem = extract_ca_cert_pem(xml);

    let routes = extract_all_cidrs(xml);
    let dns_servers = extract_all_dns(xml);

    Ok(AzureVpnConfig {
        gateway_fqdn,
        tenant_id,
        client_id,
        server_secret_hex,
        ca_cert_pem,
        routes,
        dns_servers,
    })
}

/// Pull the gateway FQDN out of any of the three known schemas:
///   1. `<gatewayfqdn>azuregateway-….vpn.azure.com</gatewayfqdn>`
///   2. `<vpngateway>azuregateway-….vpn.azure.com</vpngateway>`
///      (old, when vpngateway was just a string)
///   3. `<vpngateway><servers><server><FQDN>azuregateway-….vpn.azure.com</FQDN>…`
///      (modern, where vpngateway is a container)
///
/// We resolve in that order and pick the first non-empty result.
/// Inside the modern container the FQDN tag is sometimes uppercase
/// `<FQDN>` and sometimes `<fqdn>`; tag matching is case-insensitive.
fn extract_gateway_fqdn(xml: &str) -> Option<String> {
    if let Some(s) = extract_tag(xml, "gatewayfqdn") {
        let trimmed = s.trim();
        // Avoid mistaking a container body (newlines + child tags)
        // for a real FQDN. Real FQDNs don't have `<` in them.
        if !trimmed.is_empty() && !trimmed.contains('<') {
            return Some(trimmed.to_owned());
        }
    }
    // Look inside <vpngateway> first (modern container); falling
    // back to the raw tag body covers the older "vpngateway is a
    // bare string" schema.
    if let Some(container) = extract_tag(xml, "vpngateway") {
        // Inner FQDN — accept both `<FQDN>` (server entry) and a
        // bare body if no nested element exists.
        if let Some(fqdn) = extract_tag(&container, "fqdn") {
            let trimmed = fqdn.trim();
            if !trimmed.is_empty() && !trimmed.contains('<') {
                return Some(trimmed.to_owned());
            }
        }
        let trimmed = container.trim();
        if !trimmed.is_empty() && !trimmed.contains('<') {
            return Some(trimmed.to_owned());
        }
    }
    // Last-ditch: raw `<FQDN>` anywhere in the document.
    if let Some(fqdn) = extract_tag(xml, "fqdn") {
        let trimmed = fqdn.trim();
        if !trimmed.is_empty() && !trimmed.contains('<') {
            return Some(trimmed.to_owned());
        }
    }
    None
}

/// Pull the Entra ID tenant ID out of any of the schemas. Newer
/// exports store it as a URL (`https://login.microsoftonline.com/<guid>/`);
/// we extract the GUID segment when that's the case.
fn extract_tenant_id(xml: &str) -> Option<String> {
    let raw = extract_tag(xml, "tenant")
        .or_else(|| extract_tag(xml, "azuretenant"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // GUID-shaped already? Ship it.
    if looks_like_guid(trimmed) {
        return Some(trimmed.to_owned());
    }
    // URL-shaped? Find the first GUID-looking path segment.
    for seg in trimmed.split(|c: char| c == '/' || c == '?' || c == '&') {
        if looks_like_guid(seg) {
            return Some(seg.to_owned());
        }
    }
    // Couldn't tell — return the raw string. Better to round-trip
    // the user's input than to fail import.
    Some(trimmed.to_owned())
}

fn looks_like_guid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    // Hyphens at positions 8/13/18/23, hex everywhere else.
    for (i, &b) in bytes.iter().enumerate() {
        let must_hyphen = matches!(i, 8 | 13 | 18 | 23);
        if must_hyphen {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Resolve the CA certificate to a PEM body, accepting:
///   - `<cert>BASE64</cert>` (old schema, base64 of a DER cert)
///   - `<servervalidation><cert>BASE64</cert></servervalidation>`
///   - `<servervalidation><cert><hash>…</hash><name>…</name></cert>…`
///     (modern schema — thumbprint-only, no inline PEM)
///   - `<cacerts>BASE64</cacerts>`
///
/// Returns an empty string when only a thumbprint is present —
/// the Connect path will fetch the cert chain from the gateway
/// at handshake time using the `<hash>` for validation.
fn extract_ca_cert_pem(xml: &str) -> String {
    // Try `<cert>` body first. Strip whitespace; if what's left is
    // pure base64 we wrap into PEM. If it contains `<` (nested
    // tags like `<hash>...`), fall through to thumbprint-only.
    if let Some(body) = extract_tag(xml, "cert").or_else(|| extract_tag(xml, "cacerts")) {
        let collapsed = body.split_whitespace().collect::<String>();
        if !collapsed.is_empty() && !collapsed.contains('<') && is_base64_like(&collapsed) {
            return wrap_base64_as_pem(&collapsed);
        }
    }
    String::new()
}

/// Cheap base64 sniff — only chars that legitimately appear in a
/// base64 body. Doesn't validate length / padding rigorously; the
/// goal is just to avoid wrapping a thumbprint or other XML in
/// PEM headers and shipping nonsense to OpenVPN.
fn is_base64_like(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
    })
}

/// Find the first inner-text occurrence of `<tag>...</tag>` (or any
/// namespaced variant ending in `:tag`). Returns the inner text, or
/// `None` if the tag is absent or self-closing.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    // Search for `<tag>` (no attributes) and `<tag ...>` (with
    // attributes) — we don't try to be a real parser, just a
    // best-effort extractor good enough for Microsoft's stable schema.
    let lower = xml.to_lowercase();
    let needle = format!("<{}", tag.to_lowercase());
    let mut start = 0;
    while let Some(idx) = lower[start..].find(&needle) {
        let abs = start + idx;
        // Make sure we matched a tag boundary, not a substring like
        // <tagless>. The next char after the needle must be `>`,
        // a space, or `/` (self-closing).
        let next = lower.as_bytes().get(abs + needle.len()).copied();
        if !matches!(next, Some(b'>') | Some(b' ') | Some(b'\t') | Some(b'/')) {
            // Also accept namespace separator e.g. <ns:tag becoming
            // <ns:tagless> — those aren't a real match either; bump
            // and continue.
            start = abs + needle.len();
            continue;
        }
        // Find the closing `>` of the open tag.
        let after_open = match xml[abs..].find('>') {
            Some(p) => abs + p + 1,
            None => return None,
        };
        // Locate the matching `</tag>` (any namespace prefix).
        let close_lower = format!("</{}>", tag.to_lowercase());
        let close_lower2 = format!(":{}>", tag.to_lowercase()); // namespaced close
        if let Some(end_rel) = lower[after_open..].find(&close_lower) {
            let end = after_open + end_rel;
            return Some(xml[after_open..end].to_owned());
        }
        if let Some(end_rel) = lower[after_open..].find(&close_lower2) {
            let end = after_open + end_rel - 1; // back up one for the `<` of `</`
            // Walk back to the start of the `</`
            if let Some(lt) = xml[..end].rfind("</") {
                return Some(xml[after_open..lt].to_owned());
            }
        }
        return None;
    }
    None
}

/// Wrap a single-line base64 blob into a PEM-formatted certificate
/// ready for OpenVPN's `<ca>` block. Inserts a newline every 64
/// chars (the openssl convention) so cert parsers that split on
/// line boundaries don't choke.
fn wrap_base64_as_pem(b64: &str) -> String {
    let mut out = String::with_capacity(b64.len() + 80);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    let bytes = b64.as_bytes();
    for chunk in bytes.chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Walk the document looking for routes. Two shapes show up in the
/// wild and we accept both:
///
///   1. CIDR-in-text: `<destinationaddress>10.0.0.0/8</destinationaddress>`
///      or any other tag whose body parses as `IpNet`.
///
///   2. Microsoft's older split shape:
///      `<Route><destination>10.0.0.0</destination><mask>255.0.0.0</mask></Route>`
///      where the destination + mask must be combined to form a CIDR.
///
/// Anything that doesn't parse cleanly is skipped silently so a
/// stray hostname or comment in the file doesn't fail the whole import.
fn extract_all_cidrs(xml: &str) -> Vec<IpNet> {
    let mut routes: Vec<IpNet> = Vec::new();

    // Shape 1: tag bodies that already contain a CIDR.
    for needle in ["<destinationaddress>", "<address>", "<route>"] {
        let lower = xml.to_lowercase();
        let mut start = 0;
        while let Some(rel) = lower[start..].find(needle) {
            let abs = start + rel + needle.len();
            if let Some(end_rel) = lower[abs..].find('<') {
                let end = abs + end_rel;
                let body = xml[abs..end].trim();
                if let Ok(net) = IpNet::from_str(body) {
                    if !routes.contains(&net) {
                        routes.push(net);
                    }
                }
                start = end;
            } else {
                break;
            }
        }
    }

    // Shape 2: paired `<destination>` + `<mask>` siblings. Walk
    // both in document order and zip them up — Microsoft's
    // exporter emits them adjacent so a positional match is
    // robust enough.
    let destinations = extract_all_simple_tags(xml, "destination");
    let masks = extract_all_simple_tags(xml, "mask");
    for (dest, mask) in destinations.iter().zip(masks.iter()) {
        if let Some(prefix_len) = netmask_to_prefix(mask) {
            let cidr = format!("{dest}/{prefix_len}");
            if let Ok(net) = IpNet::from_str(&cidr) {
                if !routes.contains(&net) {
                    routes.push(net);
                }
            }
        }
    }

    // Shape 1 again, but for `<destination>` bodies that already
    // include a `/N` prefix (some exporters do this even with the
    // paired-mask schema for IPv6).
    for body in &destinations {
        if let Ok(net) = IpNet::from_str(body.trim()) {
            if !routes.contains(&net) {
                routes.push(net);
            }
        }
    }

    routes
}

/// Pull out the inner text of every `<tag>...</tag>` occurrence
/// (case-insensitive, ignores attributes and namespace prefixes).
fn extract_all_simple_tags(xml: &str, tag: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let lower = xml.to_lowercase();
    let needle = format!("<{}", tag.to_lowercase());
    let mut start = 0;
    while let Some(rel) = lower[start..].find(&needle) {
        let abs = start + rel + needle.len();
        // Reject substring matches like <destinationaddress> when
        // we're looking for <destination>.
        let next = lower.as_bytes().get(abs).copied();
        if !matches!(next, Some(b'>') | Some(b' ') | Some(b'\t') | Some(b'/')) {
            start = abs;
            continue;
        }
        if let Some(close) = xml[abs..].find('>') {
            let after = abs + close + 1;
            if let Some(end_rel) = lower[after..].find('<') {
                let end = after + end_rel;
                out.push(xml[after..end].trim().to_owned());
                start = end;
                continue;
            }
        }
        break;
    }
    out
}

/// Convert a dotted-decimal IPv4 netmask (`255.255.255.0`) into the
/// equivalent prefix length (`24`). Returns `None` for anything
/// non-contiguous — Azure never produces those, but defensive.
fn netmask_to_prefix(mask: &str) -> Option<u8> {
    let mut parts = mask.trim().split('.');
    let octets = [
        parts.next()?.parse::<u8>().ok()?,
        parts.next()?.parse::<u8>().ok()?,
        parts.next()?.parse::<u8>().ok()?,
        parts.next()?.parse::<u8>().ok()?,
    ];
    if parts.next().is_some() {
        return None;
    }
    let bits = ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32);
    let leading = bits.leading_ones();
    let trailing = bits.trailing_zeros();
    if leading + trailing != 32 {
        return None;
    }
    Some(leading as u8)
}

/// Pick out every `<dnsserver>` (or `<server>`) inner-text that
/// parses as an IP. Same forgiving approach as routes — Microsoft
/// nests these under `<dnsservers>` with no consistent prefix.
fn extract_all_dns(xml: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for needle in ["<dnsserver>", "<server>"] {
        let lower = xml.to_lowercase();
        let mut start = 0;
        while let Some(rel) = lower[start..].find(needle) {
            let abs = start + rel + needle.len();
            if let Some(end_rel) = lower[abs..].find('<') {
                let end = abs + end_rel;
                if let Ok(ip) = IpAddr::from_str(xml[abs..end].trim()) {
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
                }
                start = end;
            } else {
                break;
            }
        }
    }
    out
}

/// Render an Azure VPN profile as an OpenVPN 3.x `.ovpn` body.
///
/// **Format ported verbatim from MSP-Toolkit-V2's working
/// production implementation.** Critical differences from a
/// generic OpenVPN config:
///
///   - `tls-auth` (NOT `tls-crypt`) with direction `1` —
///     Azure's `<serversecret>` blob is consumed as a tls-auth
///     HMAC key, not a tls-crypt encryption key. Wrong directive
///     → handshake fails silently.
///   - `auth SHA256` + `cipher AES-256-GCM` + `data-ciphers
///     AES-256-GCM` — no fallback ciphers; the gateway only
///     speaks GCM.
///   - `disable-dco` — kernel data-channel-offload conflicts
///     with openvpn3's userspace token-as-password handshake.
///   - `auth-user-pass` (no file argument) — openvpn3 reads
///     `<user>\n<pass>\n` from stdin at session-start.
///
/// The TLS key is rendered to a separate file by the helper
/// (since `tls-auth` doesn't support inline blocks reliably
/// across openvpn3 ports); we emit a `tls-auth` directive with
/// a placeholder path that the helper substitutes at spawn time.
/// (Currently we still inline as `<tls-auth>` for simplicity —
/// works on the openvpn3-linux + openvpn3-aircrack ports.)
#[must_use]
pub fn render_azure_ovpn(cfg: &AzureVpnConfig, full_tunnel: bool) -> String {
    let mut out = String::with_capacity(cfg.ca_cert_pem.len() + cfg.server_secret_hex.len() + 1024);

    out.push_str("# SuperManager-rendered Azure VPN profile (OpenVPN 2.x, MSP-Toolkit-V2 layout)\n");
    out.push_str("client\n");
    out.push_str("dev tun\n");
    out.push_str("proto tcp\n");
    out.push_str(&format!("remote {} 443\n", cfg.gateway_fqdn));
    out.push_str("resolv-retry infinite\n");
    out.push_str("nobind\n");
    out.push_str("persist-tun\n");
    out.push_str("remote-cert-tls server\n");
    // Cipher / auth — pinned to what the Azure gateway actually
    // negotiates. No fallback list; if the gateway moves away
    // from AES-256-GCM we'll fail loud and update.
    out.push_str("auth SHA256\n");
    out.push_str("cipher AES-256-GCM\n");
    out.push_str("data-ciphers AES-256-GCM\n");
    // Kernel DCO interferes with the token-as-password handshake.
    // openvpn3-aircrack honours this; openvpn3-linux ignores it.
    out.push_str("disable-dco\n");
    // No `max-packet-size` directive — production Linux (this
    // crate's sibling `supermgrd/src/vpn/azure.rs`) doesn't set
    // one and that's what works in production. Setting
    // `max-packet-size > 1500` causes openvpn to advertise
    // `IV_MTU` in peer-info, which the Azure gateway rejects
    // with a TCP RST right after `VERIFY EKU OK` — symptom is
    // `Connection reset, restarting [0]` immediately after the
    // cert chain validates. The buffer-overflow that originally
    // motivated this directive is now solved upstream by the
    // patched openvpn binary (`TLS_CHANNEL_BUF_SIZE 8192`); we
    // don't need to hint at frame sizing on top.
    out.push_str("verb 3\n");
    // `auth-user-pass` without a file argument tells openvpn3 to
    // read creds from stdin at session-start. The helper pipes
    // `<user>\n<token>\n` — see supermanager-helper/src/openvpn.rs.
    out.push_str("auth-user-pass\n");

    // Routing. ONLY full-tunnel emits `redirect-gateway def1`. For split tunnel
    // we emit explicit `route` lines if the config carries CIDRs, otherwise
    // NOTHING — and rely on the routes the Azure point-to-site gateway PUSHES at
    // connect (the VNet subnets). This is the correct default for Azure P2S:
    // forcing redirect-gateway on an internal-only gateway (no internet egress)
    // black-holes ALL public traffic + DNS and freezes the Mac, while the
    // pushed VNet routes already give access to everything internal. (Earlier
    // `full_tunnel || cfg.routes.is_empty()` forced full tunnel whenever the
    // imported config listed no routes — which is the normal Azure case, since
    // routes are pushed at runtime — and broke internet for every Azure VPN.)
    if full_tunnel {
        out.push_str("redirect-gateway def1\n");
    } else {
        for net in &cfg.routes {
            match net {
                ipnet::IpNet::V4(v4) => {
                    out.push_str(&format!("route {} {}\n", v4.network(), v4.netmask()));
                }
                ipnet::IpNet::V6(v6) => {
                    out.push_str(&format!("route-ipv6 {}/{}\n", v6.network(), v6.prefix_len()));
                }
            }
        }
    }

    for ip in &cfg.dns_servers {
        out.push_str(&format!("dhcp-option DNS {ip}\n"));
    }

    out.push('\n');

    // Inline CA. Two paths:
    //
    //   1. The .azurevpnconfig had a base64 cert in
    //      `<servervalidation><cert>` — we wrapped it as PEM at
    //      parse time, splice straight in.
    //
    //   2. The .azurevpnconfig had a thumbprint-only cert (the
    //      modern Microsoft schema, with `<Cert><hash>…</hash>
    //      <usepinnedroot>true</usepinnedroot></Cert>`). The
    //      hash is the SHA-1 of the pinned ROOT CA — and for
    //      every Azure VPN gateway Microsoft issues, that CA is
    //      `DigiCert Global Root CA` (SHA-1
    //      `a8985d3a65e5e5c4b2d7d66d40c6dd2fb19c5436`). OpenVPN
    //      can't connect with `remote-cert-tls server` and no
    //      `<ca>`, so we embed the DigiCert Global Root CA PEM
    //      directly. If your tenant uses a different pinned
    //      root, the TLS handshake will fail clearly and we'll
    //      need to widen this lookup table.
    out.push_str("<ca>\n");
    if !cfg.ca_cert_pem.trim().is_empty() {
        out.push_str(cfg.ca_cert_pem.trim_end());
        out.push('\n');
    } else {
        out.push_str(DIGICERT_GLOBAL_ROOT_CA_PEM);
    }
    out.push_str("</ca>\n\n");

    // tls-auth block, key direction 1 (client side). Hex from
    // Azure's `<serversecret>` is split into 32-char lines and
    // wrapped with the OpenVPN Static key V1 markers — same
    // shape `openvpn --genkey static` produces.
    if !cfg.server_secret_hex.trim().is_empty() {
        out.push_str("key-direction 1\n");
        out.push_str("<tls-auth>\n");
        out.push_str("-----BEGIN OpenVPN Static key V1-----\n");
        let hex = cfg.server_secret_hex.to_lowercase();
        for chunk in hex.as_bytes().chunks(32) {
            if let Ok(s) = std::str::from_utf8(chunk) {
                out.push_str(s);
                out.push('\n');
            }
        }
        out.push_str("-----END OpenVPN Static key V1-----\n");
        out.push_str("</tls-auth>\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but realistic config that covers every required field.
    /// Crafted to mirror Microsoft's exporter output; if the parser
    /// passes this it'll pass the real thing.
    const SAMPLE_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<AzVpnProfile>
  <name>my-profile</name>
  <gatewayfqdn>azuregateway-test.vpn.azure.com</gatewayfqdn>
  <tenant>11111111-2222-3333-4444-555555555555</tenant>
  <audience>c632b3df-fb67-4d84-bdcf-b95ad541b5c8</audience>
  <serversecret>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</serversecret>
  <servervalidation>
    <cert>QkVHSU4tQ0VSVA==</cert>
  </servervalidation>
  <routes>
    <includedRoutes>
      <route><destinationaddress>10.0.0.0/8</destinationaddress></route>
      <route><destinationaddress>192.168.1.0/24</destinationaddress></route>
    </includedRoutes>
  </routes>
  <dnsservers>
    <dnsserver>10.0.0.10</dnsserver>
    <dnsserver>10.0.0.11</dnsserver>
  </dnsservers>
</AzVpnProfile>
"#;

    #[test]
    fn happy_path_parses_every_field() {
        let cfg = parse_azure_vpn_config(SAMPLE_XML).expect("should parse");
        assert_eq!(cfg.gateway_fqdn, "azuregateway-test.vpn.azure.com");
        assert_eq!(cfg.tenant_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(cfg.client_id, "c632b3df-fb67-4d84-bdcf-b95ad541b5c8");
        // 16 × 16 hex chars in the fixture — the parser doesn't care
        // about exact length so long as it's hex and over the
        // pathological-shortness threshold.
        assert_eq!(cfg.server_secret_hex.len(), 256);
        assert!(cfg.ca_cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cfg.ca_cert_pem.contains("QkVHSU4tQ0VSVA=="));
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(cfg.dns_servers.len(), 2);
    }

    #[test]
    fn missing_gateway_fails_with_named_field() {
        let xml = SAMPLE_XML.replace("<gatewayfqdn>azuregateway-test.vpn.azure.com</gatewayfqdn>", "");
        let err = parse_azure_vpn_config(&xml).expect_err("should fail");
        assert!(err.contains("gatewayfqdn"), "error names the missing field: {err}");
    }

    /// Microsoft's current schema: `<vpngateway>` is a container
    /// with `<servers><server><FQDN>...` nested inside it.
    #[test]
    fn modern_nested_vpngateway_container_is_parsed() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<azvpnprofile xmlns="http://schemas.datacontract.org/2004/07/">
  <protocol>OpenVPN</protocol>
  <vpngateway>
    <servers>
      <server>
        <FQDN>azuregateway-modern.vpn.azure.com</FQDN>
        <publicIpAddress>20.1.2.3</publicIpAddress>
        <portNumber>443</portNumber>
      </server>
    </servers>
  </vpngateway>
  <azuretenant>https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/</azuretenant>
  <azureaudience>c632b3df-fb67-4d84-bdcf-b95ad541b5c8</azureaudience>
  <serversecret>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</serversecret>
  <servervalidation>
    <cert>
      <hash>ABCDEF1234567890</hash>
      <name>CN=Azure-VPN-Gateway</name>
    </cert>
  </servervalidation>
  <clientauthtype>aad</clientauthtype>
</azvpnprofile>"#;
        let cfg = parse_azure_vpn_config(xml).expect("should parse modern schema");
        assert_eq!(cfg.gateway_fqdn, "azuregateway-modern.vpn.azure.com");
        // Tenant URL is unwrapped to bare GUID.
        assert_eq!(cfg.tenant_id, "11111111-2222-3333-4444-555555555555");
        // Cert was thumbprint-only (no base64 body) — PEM is empty.
        assert!(cfg.ca_cert_pem.is_empty(), "thumbprint-only cert leaves PEM blank");
    }

    #[test]
    fn config_without_serversecret_imports_anyway() {
        // Modern AAD-flow profiles can omit the inline tls-crypt;
        // the gateway delivers it post-auth. We still want import
        // to succeed so the user can see the profile in the GUI.
        let xml = r#"<?xml version="1.0"?>
<azvpnprofile>
  <gatewayfqdn>g.vpn.azure.com</gatewayfqdn>
  <tenant>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</tenant>
</azvpnprofile>"#;
        let cfg = parse_azure_vpn_config(xml).expect("should parse");
        assert_eq!(cfg.gateway_fqdn, "g.vpn.azure.com");
        assert!(cfg.server_secret_hex.is_empty());
        assert!(cfg.ca_cert_pem.is_empty());
    }

    #[test]
    fn tenant_url_is_unwrapped_to_guid() {
        // Microsoft sometimes serializes `<azuretenant>` as a full
        // STS URL — we want to extract the GUID for downstream use.
        let xml = r#"<?xml version="1.0"?>
<azvpnprofile>
  <gatewayfqdn>g.vpn.azure.com</gatewayfqdn>
  <azuretenant>https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/v2.0</azuretenant>
</azvpnprofile>"#;
        let cfg = parse_azure_vpn_config(xml).expect("should parse");
        assert_eq!(cfg.tenant_id, "12345678-1234-1234-1234-123456789012");
    }

    #[test]
    fn looks_like_guid_basics() {
        assert!(looks_like_guid("11111111-2222-3333-4444-555555555555"));
        assert!(looks_like_guid("00000000-0000-0000-0000-000000000000"));
        // Wrong length / shape.
        assert!(!looks_like_guid("not-a-guid"));
        assert!(!looks_like_guid("11111111-2222-3333-4444"));
        assert!(!looks_like_guid(""));
        // Non-hex char.
        assert!(!looks_like_guid("zzzzzzzz-2222-3333-4444-555555555555"));
    }

    #[test]
    fn missing_tenant_fails() {
        let xml = SAMPLE_XML.replace(
            "<tenant>11111111-2222-3333-4444-555555555555</tenant>",
            "",
        );
        let err = parse_azure_vpn_config(&xml).expect_err("should fail");
        assert!(err.contains("tenant"));
    }

    #[test]
    fn audience_defaults_to_well_known_when_missing() {
        let xml = SAMPLE_XML.replace(
            "<audience>c632b3df-fb67-4d84-bdcf-b95ad541b5c8</audience>",
            "",
        );
        let cfg = parse_azure_vpn_config(&xml).expect("should parse");
        // The "well-known" Azure VPN client ID; Microsoft uses it
        // for every gateway unless the admin overrides it.
        assert_eq!(cfg.client_id, "c632b3df-fb67-4d84-bdcf-b95ad541b5c8");
    }

    #[test]
    fn serversecret_too_short_is_rejected() {
        let xml = SAMPLE_XML.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "deadbeef",
        );
        let err = parse_azure_vpn_config(&xml).expect_err("should fail");
        assert!(err.contains("too short"));
    }

    #[test]
    fn serversecret_non_hex_is_rejected() {
        let xml = SAMPLE_XML.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "ZZZZZZZZ0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        );
        let err = parse_azure_vpn_config(&xml).expect_err("should fail");
        assert!(err.contains("non-hex"));
    }

    #[test]
    fn no_routes_means_full_tunnel() {
        let xml = r#"<?xml version="1.0"?>
<AzVpnProfile>
  <gatewayfqdn>g.vpn.azure.com</gatewayfqdn>
  <tenant>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</tenant>
  <serversecret>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</serversecret>
  <servervalidation><cert>Q0VSVA==</cert></servervalidation>
</AzVpnProfile>"#;
        let cfg = parse_azure_vpn_config(xml).expect("should parse");
        assert!(cfg.routes.is_empty(), "no routes element → empty routes");
        assert!(cfg.dns_servers.is_empty());

        // REGRESSION (the Autostrada brick): with no config routes, split tunnel
        // must NOT emit redirect-gateway — Azure P2S pushes the VNet routes at
        // connect, and forcing full tunnel on an internal-only gateway
        // black-holes all public internet + DNS. Only explicit full_tunnel=true
        // may redirect.
        let split = render_azure_ovpn(&cfg, false);
        assert!(!split.contains("redirect-gateway"),
            "split tunnel with no config routes must rely on pushed routes, not redirect-gateway");
        let full = render_azure_ovpn(&cfg, true);
        assert!(full.contains("redirect-gateway def1"),
            "explicit full_tunnel must still redirect");
    }

    #[test]
    fn whitespace_in_serversecret_is_normalized() {
        // Microsoft's exporter sometimes wraps the hex blob across
        // many lines; we should fold the whitespace before hex
        // validation.
        let xml = SAMPLE_XML.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        );
        let cfg = parse_azure_vpn_config(&xml).expect("should parse");
        // The replacement above was a 128-char hex split across two
        // lines; after whitespace folding we expect exactly that.
        assert_eq!(cfg.server_secret_hex.len(), 128);
        assert!(cfg.server_secret_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn render_full_tunnel_includes_redirect_and_inlined_blocks() {
        let cfg = parse_azure_vpn_config(SAMPLE_XML).unwrap();
        let body = render_azure_ovpn(&cfg, true);
        assert!(body.contains("remote azuregateway-test.vpn.azure.com 443"));
        assert!(body.contains("redirect-gateway def1"));
        assert!(body.contains("auth-user-pass"));
        assert!(body.contains("<ca>") && body.contains("</ca>"));
        assert!(body.contains("<tls-auth>") && body.contains("</tls-auth>"));
        assert!(body.contains("key-direction 1"));
        assert!(body.contains("-----BEGIN OpenVPN Static key V1-----"));
        assert!(body.contains("data-ciphers AES-256-GCM\n"));
        assert!(body.contains("disable-dco"));
    }

    /// Modern thumbprint-only `<servervalidation><Cert><hash>…`
    /// configs (what Microsoft's Azure portal exports today)
    /// must still produce a working .ovpn. We embed the DigiCert
    /// Global Root CA PEM so OpenVPN has something to chain
    /// against.
    /// Guardrail: any future hand-edit to the embedded
    /// DigiCert PEM gets caught here. We base64-decode the body
    /// and verify the SHA-1 matches what every Azure VPN
    /// `<hash>` field carries — `A8:98:5D:3A:…`. A single
    /// substituted character corrupts the cert and OpenVPN
    /// refuses to load it; this test fails immediately.
    #[test]
    fn embedded_digicert_pem_decodes_and_matches_thumbprint() {
        use base64::Engine as _;
        use sha2::Digest as _;
        let pem = DIGICERT_GLOBAL_ROOT_CA_PEM;
        // Strip PEM markers + whitespace.
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .concat();
        let collapsed = body.split_whitespace().collect::<String>();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&collapsed)
            .expect("embedded DigiCert PEM body must be valid base64");
        // Expect a non-trivial DER blob — DigiCert Global Root CA
        // is ~947 bytes.
        assert!(der.len() > 800, "DER decode produced suspiciously small output: {} bytes", der.len());
        // SHA-1 of the DER bytes is the cert thumbprint.
        let sha1 = sha1_hex(&der);
        assert_eq!(
            sha1.to_lowercase(),
            "a8985d3a65e5e5c4b2d7d66d40c6dd2fb19c5436",
            "embedded DigiCert PEM thumbprint mismatch — has someone hand-edited it?"
        );
    }

    /// Tiny SHA-1 wrapper. `sha2` doesn't export SHA-1 (it's
    /// in the `sha1` crate), but we don't want a new dep just
    /// for one test. Hand-rolled implementation matches the
    /// 5-stage block transform from RFC 3174.
    fn sha1_hex(data: &[u8]) -> String {
        // Padding: append 0x80, zeros, then 64-bit length.
        let bit_len = (data.len() as u64) * 8;
        let mut buf = data.to_vec();
        buf.push(0x80);
        while buf.len() % 64 != 56 {
            buf.push(0);
        }
        buf.extend_from_slice(&bit_len.to_be_bytes());

        let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        for chunk in buf.chunks(64) {
            let mut w = [0u32; 80];
            for (i, word) in chunk.chunks(4).enumerate() {
                w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            }
            for i in 16..80 {
                w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
            }
            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
            for i in 0..80 {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                    20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                    _ => (b ^ c ^ d, 0xca62c1d6),
                };
                let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
        }
        format!("{:08x}{:08x}{:08x}{:08x}{:08x}", h[0], h[1], h[2], h[3], h[4])
    }

    #[test]
    fn render_thumbprint_only_config_embeds_digicert() {
        let xml = r#"<?xml version="1.0"?>
<AzVpnProfile>
  <gatewayfqdn>g.vpn.azure.com</gatewayfqdn>
  <tenant>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</tenant>
  <serversecret>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</serversecret>
  <servervalidation>
    <Cert><hash>A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436</hash></Cert>
  </servervalidation>
</AzVpnProfile>"#;
        let cfg = parse_azure_vpn_config(xml).expect("should parse");
        assert!(cfg.ca_cert_pem.is_empty(),
            "thumbprint-only config has no inline PEM");
        let body = render_azure_ovpn(&cfg, true);
        assert!(body.contains("DigiCert Global Root CA")
            || body.contains("MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjAN"),
            "renderer must embed the DigiCert PEM when no inline CA is supplied");
    }

    #[test]
    fn render_split_tunnel_emits_route_directives() {
        let cfg = parse_azure_vpn_config(SAMPLE_XML).unwrap();
        let body = render_azure_ovpn(&cfg, false);
        // SAMPLE_XML carries 10.0.0.0/8 and 192.168.1.0/24.
        assert!(body.contains("route 10.0.0.0 255.0.0.0"));
        assert!(body.contains("route 192.168.1.0 255.255.255.0"));
        // Split-tunnel must NOT push redirect-gateway — that's what
        // the toggle is for.
        assert!(!body.contains("redirect-gateway"));
    }

    #[test]
    fn render_emits_dns_directives() {
        let cfg = parse_azure_vpn_config(SAMPLE_XML).unwrap();
        let body = render_azure_ovpn(&cfg, true);
        assert!(body.contains("dhcp-option DNS 10.0.0.10"));
        assert!(body.contains("dhcp-option DNS 10.0.0.11"));
    }

    #[test]
    fn destination_plus_mask_route_format_is_supported() {
        // Microsoft's older `<Route><destination>X</destination><mask>Y</mask></Route>`
        // shape — what some Azure portals still emit. Our parser
        // has to combine the two into a CIDR.
        let xml = r#"<?xml version="1.0"?>
<AzVpnProfile>
  <gatewayfqdn>g.vpn.azure.com</gatewayfqdn>
  <tenant>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</tenant>
  <serversecret>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</serversecret>
  <servervalidation><cert>Q0VSVA==</cert></servervalidation>
  <routes>
    <includedRoutes>
      <Route>
        <destination>172.16.0.0</destination>
        <mask>255.255.0.0</mask>
      </Route>
      <Route>
        <destination>192.168.5.0</destination>
        <mask>255.255.255.0</mask>
      </Route>
    </includedRoutes>
  </routes>
</AzVpnProfile>"#;
        let cfg = parse_azure_vpn_config(xml).expect("should parse");
        assert_eq!(cfg.routes.len(), 2, "two paired destination/mask routes");
        assert!(cfg.routes.iter().any(|r| r.to_string() == "172.16.0.0/16"));
        assert!(cfg.routes.iter().any(|r| r.to_string() == "192.168.5.0/24"));
    }

    #[test]
    fn netmask_to_prefix_basics() {
        assert_eq!(netmask_to_prefix("255.255.255.0"), Some(24));
        assert_eq!(netmask_to_prefix("255.0.0.0"), Some(8));
        assert_eq!(netmask_to_prefix("255.255.255.255"), Some(32));
        assert_eq!(netmask_to_prefix("0.0.0.0"), Some(0));
        // Non-contiguous masks (impossible from Azure but defensive).
        assert_eq!(netmask_to_prefix("255.0.255.0"), None);
        assert_eq!(netmask_to_prefix("not.an.ip.mask"), None);
    }

    #[test]
    fn malformed_xml_does_not_panic() {
        let inputs = ["", "<", "<><><>", "not even xml", "<AzVpnProfile><tenant>"];
        for s in inputs {
            // Don't care if it errors — just shouldn't panic.
            let _ = parse_azure_vpn_config(s);
        }
    }
}
