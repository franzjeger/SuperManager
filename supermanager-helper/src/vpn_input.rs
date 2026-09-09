//! Conservative privileged-input grammar. Unknown execution/file directives fail closed.
use anyhow::{bail, Result};

pub fn profile_id(id: &str) -> Result<()> {
    if !(id.len() == 32 || id.len() == 36) || uuid::Uuid::parse_str(id).is_err() {
        bail!("Invalid VPN profile UUID");
    }
    Ok(())
}
pub fn wireguard(config: &str) -> Result<()> {
    if config.len() > 1024 * 1024 {
        bail!("WireGuard configuration too large");
    }
    let mut section = "";
    for raw in config.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "[Interface]" {
            section = "Interface";
            continue;
        }
        if line == "[Peer]" {
            section = "Peer";
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("Invalid WireGuard configuration");
        };
        let permitted = match section {
            "Interface" => ["PrivateKey", "Address", "ListenPort", "MTU"].contains(&key.trim()),
            "Peer" => [
                "PublicKey",
                "PresharedKey",
                "AllowedIPs",
                "Endpoint",
                "PersistentKeepalive",
            ]
            .contains(&key.trim()),
            _ => false,
        };
        // DNS/wg-quick hooks/Table/SaveConfig are deliberately unsupported at
        // this root boundary until implemented as typed helper operations.
        if !permitted
            || value.is_empty()
            || value
                .chars()
                .any(|c| c.is_control() || "$`;\\\"'{}()<>!".contains(c))
        {
            bail!("Unsupported or unsafe WireGuard field");
        }
    }
    Ok(())
}

pub fn openvpn(config: &str) -> Result<()> {
    if config.len() > 1024 * 1024 {
        bail!("OpenVPN configuration too large");
    }
    let mut inline: Option<&str> = None;
    for raw in config.lines() {
        let line = raw.trim();
        if let Some(tag) = inline {
            if line == format!("</{tag}>") {
                inline = None;
            } else if line.starts_with('<') {
                bail!("Nested inline OpenVPN blocks are unsupported");
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|v| v.strip_suffix('>')) {
            if !["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"].contains(&tag) {
                bail!("Unsupported OpenVPN inline block");
            }
            inline = Some(tag);
            continue;
        }
        // No parser ambiguities: includes, quoting/escapes, line continuations,
        // option prefixes, plugins, scripts and file-valued options are rejected.
        if line.chars().any(|c| c.is_control() || "\\\"'".contains(c)) {
            bail!("Unsupported OpenVPN quoting or control characters");
        }
        let mut fields = line.split_whitespace();
        let key = fields.next().unwrap_or("");
        let allowed = [
            "client",
            "dev",
            "dev-type",
            "proto",
            "remote",
            "resolv-retry",
            "nobind",
            "persist-key",
            "persist-tun",
            "remote-cert-tls",
            "auth",
            "cipher",
            "data-ciphers",
            "data-ciphers-fallback",
            "auth-nocache",
            "auth-retry",
            "connect-retry",
            "connect-timeout",
            "server-poll-timeout",
            "verb",
            "mute",
            "tun-mtu",
            "mssfix",
            "explicit-exit-notify",
            "key-direction",
            "reneg-sec",
            "tls-version-min",
            "tls-version-max",
            "setenv",
            "auth-user-pass",
            "route",
            "route-ipv6",
            "route-nopull",
            "redirect-gateway",
            "dhcp-option",
            "pull",
            "pull-filter",
            "ping",
            "ping-restart",
            "remote-random",
        ];
        if !allowed.contains(&key) {
            bail!("Unsupported OpenVPN directive: {key}");
        }
        let rest: Vec<_> = fields.collect();
        if key == "auth-user-pass" && !rest.is_empty() {
            bail!("External OpenVPN credential files are forbidden");
        }
        if key == "dev" && rest != ["tun"] {
            bail!("Only a tun device is supported");
        }
        if key == "setenv" && !(rest.len() == 2 && rest[0] == "CLIENT_CERT" && rest[1] == "0") {
            bail!("OpenVPN environment overrides are forbidden");
        }
    }
    if inline.is_some() {
        bail!("Unclosed OpenVPN inline block");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_hooks_and_shell_values() {
        assert!(wireguard("[Interface]\nPrivateKey=abc=\nAddress=10.0.0.1/32\n[Peer]\nPublicKey=def=\nAllowedIPs=0.0.0.0/0").is_ok());
        for text in [
            "PostUp=touch /tmp/pwn",
            "PreDown=id",
            "SaveConfig=true",
            "DNS=$(id)",
            "Address=$(id)",
        ] {
            assert!(wireguard(&format!("[Interface]\n{text}")).is_err());
        }
    }
    #[test]
    fn reject_openvpn_execution_includes_and_external_files() {
        assert!(openvpn("client\ndev tun\nremote vpn.example.com 1194\n<ca>\ncertificate\n</ca>\nauth-user-pass").is_ok());
        for directive in [
            "plugin /tmp/plugin",
            "config /tmp/more",
            "--config /tmp/more",
            "up /tmp/script",
            "log /etc/file",
            "ca /etc/shadow",
            "auth-user-pass /etc/shadow",
            "management 127.0.0.1 1234",
            "setenv PATH /tmp",
            "<connection>\nconfig /tmp/payload\n</connection>",
            "<ca>\nmissing end",
            "client\\\nplugin /tmp/payload",
        ] {
            assert!(openvpn(directive).is_err(), "{directive}");
        }
    }
    #[test]
    fn profile_paths_are_never_ids() {
        assert!(profile_id(&uuid::Uuid::new_v4().to_string()).is_ok());
        for id in ["../outside", "/tmp/x", "", "a\nb"] {
            assert!(profile_id(id).is_err());
        }
    }
}
