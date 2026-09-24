//! Parsing and validation for imported VPN configurations.
//!
//! Pure functions over text: nothing here touches the filesystem, the
//! keyring or a network. They lived in the Linux daemon until the Windows
//! daemon needed the same two imports, and a second copy of a parser is a
//! second place for the two platforms to disagree about what a valid file
//! is. Both daemons now call these.

use crate::vpn::profile::AzureVpnConfig;

/// Validate that `text` looks like an OpenVPN client configuration.
///
/// Checks for the minimum set of directives an OpenVPN client needs:
/// - `client` or `tls-client` (identifies this as a client-mode config)
/// - at least one `remote` line (server address)
/// - a `dev` line (`tun` or `tap`)
/// - a CA certificate (either a `<ca>` inline block or a `ca <file>` directive)
///
/// Returns `Ok(())` when all checks pass, or `Err(human-readable message)`.
///
/// This catches the most common mistakes — importing a WireGuard `.conf`,
/// an SSH key, a plain-text file, or an OpenVPN _server_ config — before
/// any file is written to disk.
pub fn validate_ovpn_config(text: &str) -> Result<(), String> {
    // Strip comment lines (starting with `#` or `;`) for all checks.
    let active_lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';') && !l.is_empty())
        .collect();

    let has_directive = |name: &str| -> bool {
        active_lines.iter().any(|l| {
            let lc = l.to_ascii_lowercase();
            lc == name
                || lc.starts_with(&format!("{name} "))
                || lc.starts_with(&format!("{name}\t"))
        })
    };

    // Must be a client config, not a server config.
    if !has_directive("client") && !has_directive("tls-client") {
        if active_lines.contains(&"[Interface]") {
            return Err(
                "this looks like a WireGuard config — use 'Import WireGuard' instead".into(),
            );
        }
        return Err(
            "not a valid OpenVPN client config: missing 'client' or 'tls-client' directive".into(),
        );
    }

    if !has_directive("remote") {
        return Err(
            "not a valid OpenVPN client config: missing 'remote' directive (no server address)"
                .into(),
        );
    }

    if !has_directive("dev") {
        return Err(
            "not a valid OpenVPN client config: missing 'dev' directive (tun or tap)".into(),
        );
    }

    // A CA certificate must be present either inline or as a file reference.
    let has_ca_directive = has_directive("ca");
    let has_ca_inline = text.contains("<ca>") && text.contains("</ca>");
    if !has_ca_directive && !has_ca_inline {
        return Err("not a valid OpenVPN client config: missing CA certificate \
             ('ca <file>' directive or '<ca>...</ca>' inline block)"
            .into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Azure XML parser
// ---------------------------------------------------------------------------

/// Extract the first text content of the given XML `tag` from `xml`.
///
/// Returns `None` if the tag is absent or has no content.  This is a
/// minimal, dependency-free parser sufficient for the well-known Azure VPN
/// XML format — it does not handle CDATA, attributes, or namespaces.
fn xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open).map(|i| i + open.len())?;
    let end = xml[start..].find(&close).map(|i| i + start)?;
    let value = xml[start..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Extract all occurrences of `<tag>content</tag>` from `xml`.
fn xml_tags_all<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut results = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let after = &rest[s + open.len()..];
        if let Some(e) = after.find(&close) {
            let value = after[..e].trim();
            if !value.is_empty() {
                results.push(value);
            }
            rest = &after[e + close.len()..];
        } else {
            break;
        }
    }
    results
}

/// Wrap a raw base64 string (no headers) as a PEM certificate block,
/// folding at 64 characters per line.
fn base64_to_pem_cert(b64: &str) -> String {
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Parse `azurevpnconfig.xml` and `VpnSettings.xml` into an [`AzureVpnConfig`].
pub fn parse_azure_xml(azure_xml: &str, vpn_settings_xml: &str) -> Result<AzureVpnConfig, String> {
    use std::net::IpAddr;
    use std::str::FromStr;

    // -- Fields from azurevpnconfig.xml --
    let client_id = xml_tag(azure_xml, "audience")
        .ok_or("missing <audience> in azurevpnconfig.xml")?
        .to_owned();

    let tenant_url = xml_tag(azure_xml, "tenant")
        .or_else(|| xml_tag(azure_xml, "issuer"))
        .ok_or("missing <tenant>/<issuer> in azurevpnconfig.xml")?;
    let tenant_id = tenant_url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or("cannot extract tenant ID from tenant URL")?
        .to_owned();

    let gateway_fqdn = xml_tag(azure_xml, "fqdn")
        .or_else(|| xml_tag(vpn_settings_xml, "VpnServer"))
        .ok_or("missing <fqdn> / <VpnServer>")?
        .to_owned();

    let server_secret_hex = xml_tag(azure_xml, "serversecret")
        .ok_or("missing <serversecret> in azurevpnconfig.xml")?
        .to_owned();

    // DNS servers: prefer VpnSettings comma list, fall back to individual tags.
    let dns_servers: Vec<IpAddr> = {
        let mut servers = Vec::new();
        if let Some(csv) = xml_tag(vpn_settings_xml, "CustomDnsServers") {
            for part in csv.split(',') {
                if let Ok(ip) = part.trim().parse::<IpAddr>() {
                    servers.push(ip);
                }
            }
        }
        if servers.is_empty() {
            for tag in xml_tags_all(azure_xml, "dnsserver") {
                if let Ok(ip) = tag.parse::<IpAddr>() {
                    servers.push(ip);
                }
            }
        }
        servers
    };

    // -- CA certificate from VpnSettings.xml --
    let ca_cert_pem = xml_tags_all(vpn_settings_xml, "string")
        .into_iter()
        .find(|s| s.len() > 100) // all actual certs are long base64 blobs
        .map(base64_to_pem_cert)
        .unwrap_or_default();

    // -- Split-tunnel routes from VpnSettings.xml --
    let routes: Vec<ipnet::IpNet> = xml_tag(vpn_settings_xml, "Routes")
        .map(|csv| {
            csv.split(',')
                .filter_map(|r| ipnet::IpNet::from_str(r.trim()).ok())
                .collect()
        })
        .unwrap_or_default();

    if server_secret_hex.len() != 512 {
        return Err(format!(
            "<serversecret> must be 512 hex chars (got {})",
            server_secret_hex.len()
        ));
    }
    if !server_secret_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("<serversecret> contains non-hex characters".into());
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_OVPN: &str = "\
client
dev tun
proto udp
remote vpn.example.com 1194
<ca>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
";

    #[test]
    fn a_normal_client_config_passes() {
        assert_eq!(validate_ovpn_config(CLIENT_OVPN), Ok(()));
    }

    #[test]
    fn a_ca_by_file_reference_counts_as_a_ca() {
        let text = "client\ndev tun\nremote vpn.example.com 1194\nca ca.crt\n";
        assert_eq!(validate_ovpn_config(text), Ok(()));
    }

    #[test]
    fn a_wireguard_config_is_named_as_one() {
        // The single most likely wrong file, and the error should say so
        // rather than list four missing OpenVPN directives.
        let err = validate_ovpn_config("[Interface]\nPrivateKey = x\n").unwrap_err();
        assert!(err.contains("WireGuard"), "{err}");
    }

    #[test]
    fn a_server_config_is_refused() {
        let text = "server 10.8.0.0 255.255.255.0\ndev tun\nremote x 1194\n<ca>\n</ca>\n";
        assert!(validate_ovpn_config(text).unwrap_err().contains("client"));
    }

    #[test]
    fn each_missing_essential_is_reported_by_name() {
        for (drop, needle) in [("remote ", "remote"), ("dev ", "dev"), ("<ca>", "CA")] {
            let text: String = CLIENT_OVPN
                .lines()
                .filter(|l| !(l.starts_with(drop) || (drop == "<ca>" && l.starts_with("</ca>"))))
                .flat_map(|l| [l, "\n"])
                .collect();
            let err = validate_ovpn_config(&text).unwrap_err();
            assert!(err.contains(needle), "dropping {drop:?} gave: {err}");
        }
    }

    #[test]
    fn commented_out_directives_do_not_count() {
        // `#client` in a template is exactly the case where a user thinks the
        // file is complete and it is not.
        let text = "#client\n;client\ndev tun\nremote x 1194\n<ca>\n</ca>\n";
        assert!(validate_ovpn_config(text).is_err());
    }

    fn azure_xml(secret: &str) -> String {
        format!(
            "<AzVpnProfile>\
               <audience>41b23e61-6c1e-4545-b367-cd054e0ed4b4</audience>\
               <issuer>https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/</issuer>\
               <tenant>https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/</tenant>\
               <fqdn>azuregateway-abc.vpn.azure.com</fqdn>\
               <serversecret>{secret}</serversecret>\
               <dnsserver>10.1.0.4</dnsserver>\
             </AzVpnProfile>"
        )
    }

    const VPN_SETTINGS: &str = "<VpnProfile>\
          <VpnServer>azuregateway-abc.vpn.azure.com</VpnServer>\
          <Routes>10.1.0.0/16,10.2.0.0/16</Routes>\
        </VpnProfile>";

    #[test]
    fn an_azure_profile_is_read_whole() {
        let cfg = parse_azure_xml(&azure_xml(&"ab".repeat(256)), VPN_SETTINGS).expect("parses");
        assert_eq!(cfg.tenant_id, "72f988bf-86f1-41af-91ab-2d7cd011db47");
        assert_eq!(cfg.client_id, "41b23e61-6c1e-4545-b367-cd054e0ed4b4");
        assert_eq!(cfg.gateway_fqdn, "azuregateway-abc.vpn.azure.com");
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(
            cfg.dns_servers,
            vec!["10.1.0.4".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn a_server_secret_of_the_wrong_length_is_refused() {
        // The secret becomes the OpenVPN tls-auth key; a truncated one would
        // produce a config that fails at handshake time with a far less
        // useful error than this one.
        let err = parse_azure_xml(&azure_xml(&"ab".repeat(100)), VPN_SETTINGS).unwrap_err();
        assert!(err.contains("512"), "{err}");
    }

    #[test]
    fn a_server_secret_that_is_not_hex_is_refused() {
        let err = parse_azure_xml(&azure_xml(&"zz".repeat(256)), VPN_SETTINGS).unwrap_err();
        assert!(err.contains("hex"), "{err}");
    }

    #[test]
    fn the_wrong_file_is_named_rather_than_panicked_on() {
        // Swapping the two files is an easy mistake with two XMLs from the
        // same download.
        let err = parse_azure_xml(VPN_SETTINGS, &azure_xml(&"ab".repeat(256))).unwrap_err();
        assert!(err.contains("azurevpnconfig.xml"), "{err}");
    }
}
