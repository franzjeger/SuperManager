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
             ('ca [inline]' directive or '<ca>...</ca>' inline block)"
            .into());
    }

    // Enforce the strict C-parser directive allowlist so imported profiles
    // cannot execute scripts/plugins, load external modules, read/write
    // arbitrary root/SYSTEM files, or inject dangerous environment variables.
    crate::vpn::openvpn_config::check(text)
        .map_err(|refusal| format!("unsafe or unsupported OpenVPN directive ({refusal})"))?;

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
/// folding at 64 characters per line. Rejects non-base64 characters so
/// untrusted XML cannot break out of `<ca>...</ca>`.
fn base64_to_pem_cert(b64: &str) -> Result<String, String> {
    let cleaned: String = b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Err("empty certificate body".into());
    }
    if !cleaned
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    {
        return Err("certificate in Azure VPN profile contains invalid base64 characters".into());
    }
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in cleaned.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem)
}

/// DigiCert Global Root G2 / Global Root CA bundle used by Azure VPN Gateways
/// when `VpnSettings.xml` supplies only a `<Cert>` SHA-1 thumbprint rather than
/// an inline base64 root certificate.
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
DQYJKoZIhvcNAQELBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----
";

/// Parse `azurevpnconfig.xml` and `VpnSettings.xml` into an [`AzureVpnConfig`].
pub fn parse_azure_xml(azure_xml: &str, vpn_settings_xml: &str) -> Result<AzureVpnConfig, String> {
    use std::net::IpAddr;
    use std::str::FromStr;

    // -- Fields from azurevpnconfig.xml --
    let client_id = xml_tag(azure_xml, "audience")
        .ok_or("missing <audience> in azurevpnconfig.xml")?
        .to_owned();
    crate::sanitize::validate_safe_ident(&client_id, "Azure <audience>")?;

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
    crate::sanitize::validate_safe_ident(&tenant_id, "Azure tenant ID")?;

    let gateway_fqdn = xml_tag(azure_xml, "fqdn")
        .or_else(|| xml_tag(azure_xml, "FQDN"))
        .or_else(|| xml_tag(vpn_settings_xml, "VpnServer"))
        .ok_or("missing <fqdn> / <VpnServer>")?
        .to_owned();
    crate::sanitize::validate_host_or_ip(&gateway_fqdn)
        .map_err(|e| format!("invalid Azure gateway FQDN: {e}"))?;

    let server_secret_raw =
        xml_tag(azure_xml, "serversecret").ok_or("missing <serversecret> in azurevpnconfig.xml")?;
    let server_secret_hex: String = server_secret_raw
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

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

    // -- CA certificate from VpnSettings.xml or azurevpnconfig.xml --
    let ca_cert_pem = match xml_tags_all(vpn_settings_xml, "string")
        .into_iter()
        .chain(xml_tags_all(azure_xml, "cert"))
        .find(|s| s.len() > 100)
    {
        Some(raw_b64) => base64_to_pem_cert(raw_b64)?,
        None => DIGICERT_GLOBAL_ROOT_CA_PEM.to_owned(),
    };

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
    fn a_ca_inline_directive_counts_as_a_ca_while_external_file_paths_are_refused() {
        let ok_text =
            "client\ndev tun\nremote vpn.example.com 1194\nca [inline]\n<ca>\nMIIB\n</ca>\n";
        assert_eq!(validate_ovpn_config(ok_text), Ok(()));

        let path_text = "client\ndev tun\nremote vpn.example.com 1194\nca ca.crt\n";
        assert!(validate_ovpn_config(path_text).is_err());

        let rce_text = "client\ndev tun\nremote vpn.example.com 1194\nscript-security 2\nup /bin/sh\n<ca>\nMIIB\n</ca>\n";
        assert!(validate_ovpn_config(rce_text).is_err());
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
                .filter(|l| !l.starts_with(drop) && !(drop == "<ca>" && l.starts_with("</ca>")))
                .map(|l| format!("{l}\n"))
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
