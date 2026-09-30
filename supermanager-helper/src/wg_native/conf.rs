//! The WireGuard configs SuperManager renders (`vpn_render_wireguard_conf`
//! in supermgr-engine), read into what the helper sets up.
//!
//! wg-quick read the same text, took out its own keys (`Address`, `MTU`)
//! and handed the rest to `wg`. This reads exactly the keys the renderer
//! writes, as `wg` reads them: case-insensitive, `#` to the end of a line
//! a comment, lists split on commas. Any other key is refused rather than
//! ignored, because the tunnel would not be the one the config describes.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;

/// A private, public or preshared key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Key([u8; 32]);

impl Key {
    fn parse(value: &str) -> Result<Self> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| anyhow!("not a base64 key"))?;
        Ok(Self(
            bytes.try_into().map_err(|_| anyhow!("not a 32-byte key"))?,
        ))
    }

    /// Hex, as wireguard-go's configuration socket takes keys.
    pub fn hex(&self) -> String {
        use std::fmt::Write as _;
        self.0
            .iter()
            .fold(String::with_capacity(64), |mut hex, byte| {
                let _ = write!(hex, "{byte:02x}");
                hex
            })
    }
}

/// Keys stay out of logs, the public ones too.
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

#[derive(Debug)]
pub struct Config {
    pub private_key: Key,
    pub listen_port: Option<u16>,
    /// The interface's own addresses, with their prefix length.
    pub addresses: Vec<IpNet>,
    pub mtu: Option<u32>,
    pub peers: Vec<Peer>,
}

#[derive(Debug)]
pub struct Peer {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    pub endpoint: Option<Endpoint>,
    /// Network addresses: host bits cleared, as `wg` shows them.
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<u16>,
}

/// A peer's `Endpoint`: an address or a name still to resolve, and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    fn parse(value: &str) -> Result<Self> {
        let (host, port) = if let Some(rest) = value.strip_prefix('[') {
            let (host, port) = rest
                .split_once("]:")
                .ok_or_else(|| anyhow!("an IPv6 endpoint is written [address]:port"))?;
            host.parse::<std::net::Ipv6Addr>()
                .map_err(|_| anyhow!("{host} is not an IPv6 address"))?;
            (host, port)
        } else {
            let (host, port) = value
                .rsplit_once(':')
                .ok_or_else(|| anyhow!("an endpoint is written host:port"))?;
            if host.contains(':') {
                bail!("an IPv6 endpoint is written [address]:port");
            }
            let valid = !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
            if !valid {
                bail!("{host:?} is not a host name or address");
            }
            (host, port)
        };
        let port = port
            .parse()
            .map_err(|_| anyhow!("{port:?} is not a port"))?;
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

/// An address with or without a prefix length; without one it is a host.
fn parse_net(value: &str) -> Result<IpNet> {
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(net);
    }
    let ip: IpAddr = value
        .parse()
        .map_err(|_| anyhow!("{value:?} is not an address"))?;
    Ok(IpNet::from(ip))
}

fn parse_list(value: &str, mut each: impl FnMut(&str) -> Result<()>) -> Result<()> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .try_for_each(|item| each(item))
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("{key} is set twice");
    }
    Ok(())
}

#[derive(Default)]
struct PeerFields {
    public_key: Option<Key>,
    preshared_key: Option<Key>,
    endpoint: Option<Endpoint>,
    allowed_ips: Vec<IpNet>,
    persistent_keepalive: Option<Option<u16>>,
}

pub fn parse(text: &str) -> Result<Config> {
    enum Section {
        None,
        Interface,
        Peer,
    }
    let mut section = Section::None;
    let mut interface_seen = false;
    let mut private_key = None;
    let mut listen_port = None;
    let mut addresses = Vec::new();
    let mut mtu = None;
    let mut peers: Vec<PeerFields> = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let at = || format!("line {}", index + 1);
        if line.starts_with('[') {
            if line.eq_ignore_ascii_case("[Interface]") {
                if interface_seen {
                    bail!("{}: a second [Interface]", at());
                }
                interface_seen = true;
                section = Section::Interface;
            } else if line.eq_ignore_ascii_case("[Peer]") {
                peers.push(PeerFields::default());
                section = Section::Peer;
            } else {
                bail!("{}: {line} is not a section SuperManager writes", at());
            }
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("{}: not key = value", at()))?;
        let (key, value) = (key.trim(), value.trim());
        let lower = key.to_ascii_lowercase();
        let result =
            match (&section, lower.as_str()) {
                (Section::None, _) => Err(anyhow!("{key} comes before [Interface]")),
                (Section::Interface, "privatekey") => {
                    Key::parse(value).and_then(|k| set_once(&mut private_key, k, key))
                }
                (Section::Interface, "listenport") => value
                    .parse()
                    .map_err(|_| anyhow!("{value:?} is not a port"))
                    .and_then(|port| set_once(&mut listen_port, port, key)),
                (Section::Interface, "address") => parse_list(value, |item| {
                    addresses.push(parse_net(item)?);
                    Ok(())
                }),
                (Section::Interface, "mtu") => value
                    .parse::<u32>()
                    .ok()
                    .filter(|mtu| (576..=65535).contains(mtu))
                    .ok_or_else(|| anyhow!("{value:?} is not an MTU"))
                    .and_then(|m| set_once(&mut mtu, m, key)),
                (Section::Peer, _) => {
                    let peer = peers.last_mut().expect("a [Peer] line pushed it");
                    match lower.as_str() {
                        "publickey" => {
                            Key::parse(value).and_then(|k| set_once(&mut peer.public_key, k, key))
                        }
                        "presharedkey" => Key::parse(value)
                            .and_then(|k| set_once(&mut peer.preshared_key, k, key)),
                        "endpoint" => Endpoint::parse(value)
                            .and_then(|e| set_once(&mut peer.endpoint, e, key)),
                        "allowedips" => parse_list(value, |item| {
                            peer.allowed_ips.push(parse_net(item)?.trunc());
                            Ok(())
                        }),
                        "persistentkeepalive" => {
                            let interval = if value.eq_ignore_ascii_case("off") {
                                Ok(None)
                            } else {
                                value
                                    .parse::<u16>()
                                    .map(|secs| (secs > 0).then_some(secs))
                                    .map_err(|_| anyhow!("{value:?} is not a number of seconds"))
                            };
                            interval.and_then(|i| set_once(&mut peer.persistent_keepalive, i, key))
                        }
                        _ => Err(anyhow!("not a key SuperManager sets up")),
                    }
                }
                (Section::Interface, _) => Err(anyhow!("not a key SuperManager sets up")),
            };
        result.with_context(|| format!("{}: {key}", at()))?;
    }

    let private_key = private_key.ok_or_else(|| anyhow!("the config has no PrivateKey"))?;
    let mut seen = HashSet::new();
    let peers = peers
        .into_iter()
        .enumerate()
        .map(|(index, fields)| {
            let public_key = fields
                .public_key
                .ok_or_else(|| anyhow!("peer {} has no PublicKey", index + 1))?;
            if !seen.insert(public_key.clone()) {
                bail!("peer {} repeats another peer's PublicKey", index + 1);
            }
            let mut unique = HashSet::new();
            Ok(Peer {
                public_key,
                preshared_key: fields.preshared_key,
                endpoint: fields.endpoint,
                allowed_ips: fields
                    .allowed_ips
                    .into_iter()
                    .filter(|net| unique.insert(*net))
                    .collect(),
                persistent_keepalive: fields.persistent_keepalive.flatten(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Config {
        private_key,
        listen_port,
        addresses,
        mtu,
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const KEY_B: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const KEY_C: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    /// What `vpn_render_wireguard_conf` writes, with every optional key.
    fn rendered() -> String {
        format!(
            "[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.8.0.2/24, fd00::2/64\n\
             MTU = 1380\nListenPort = 51820\n\n\
             [Peer]\nPublicKey = {KEY_B}\nEndpoint = vpn.example.com:51820\n\
             AllowedIPs = 0.0.0.0/0, ::/0\nPresharedKey = {KEY_C}\n\
             PersistentKeepalive = 25\n\n"
        )
    }

    #[test]
    fn a_config_as_supermanager_renders_it() {
        let config = parse(&rendered()).unwrap();
        assert_eq!(config.private_key, Key::parse(KEY_A).unwrap());
        assert_eq!(config.listen_port, Some(51820));
        assert_eq!(
            config.addresses,
            vec![
                "10.8.0.2/24".parse::<IpNet>().unwrap(),
                "fd00::2/64".parse().unwrap()
            ]
        );
        assert_eq!(config.mtu, Some(1380));
        let [peer] = config.peers.as_slice() else {
            panic!("{:?}", config.peers)
        };
        assert_eq!(peer.public_key, Key::parse(KEY_B).unwrap());
        assert_eq!(peer.preshared_key, Some(Key::parse(KEY_C).unwrap()));
        assert_eq!(
            peer.endpoint,
            Some(Endpoint {
                host: "vpn.example.com".into(),
                port: 51820
            })
        );
        assert_eq!(
            peer.allowed_ips,
            vec![
                "0.0.0.0/0".parse::<IpNet>().unwrap(),
                "::/0".parse().unwrap()
            ]
        );
        assert_eq!(peer.persistent_keepalive, Some(25));
    }

    #[test]
    fn keys_sections_and_lists_are_read_as_wg_reads_them() {
        let text = format!(
            "# A comment\n[interface]\nprivatekey={KEY_A}  # trailing comment\n\
             address = 10.8.0.2\naddress = 10.9.0.2/32,\n\
             [PEER]\npublickey = {KEY_B}\nallowedips = 10.1.2.3/24\n\
             ALLOWEDIPS = 192.168.1.10, 10.1.2.0/24\npersistentkeepalive = off\n\
             Endpoint = [2001:db8::1]:51820\n"
        );
        let config = parse(&text).unwrap();
        assert_eq!(
            config.addresses,
            vec![
                "10.8.0.2/32".parse::<IpNet>().unwrap(),
                "10.9.0.2/32".parse().unwrap()
            ]
        );
        let peer = &config.peers[0];
        // Host bits cleared, and the repeat gone.
        assert_eq!(
            peer.allowed_ips,
            vec![
                "10.1.2.0/24".parse::<IpNet>().unwrap(),
                "192.168.1.10/32".parse().unwrap(),
            ]
        );
        assert_eq!(peer.persistent_keepalive, None);
        assert_eq!(
            peer.endpoint,
            Some(Endpoint {
                host: "2001:db8::1".into(),
                port: 51820
            })
        );
        assert_eq!(config.listen_port, None);
        assert_eq!(config.mtu, None);
    }

    #[test]
    fn keys_supermanager_does_not_write_are_refused() {
        for line in [
            "DNS = 10.8.0.1",
            "Table = off",
            "PostUp = echo up",
            "SaveConfig = true",
            "FwMark = 51820",
        ] {
            let text = rendered().replace("MTU = 1380\n", &format!("{line}\n"));
            let err = format!("{:#}", parse(&text).unwrap_err());
            assert!(
                err.contains("not a key SuperManager sets up"),
                "{line}: {err}"
            );
        }
        let text = rendered().replace("PersistentKeepalive = 25\n", "Unknown = 1\n");
        assert!(parse(&text).is_err());
    }

    #[test]
    fn a_config_that_is_not_whole_is_refused() {
        let cases = [
            (
                "no private key",
                rendered().replace(&format!("PrivateKey = {KEY_A}\n"), ""),
            ),
            ("short key", rendered().replace(KEY_A, "c2hvcnQ=")),
            (
                "peer without a public key",
                rendered().replace(&format!("PublicKey = {KEY_B}\n"), ""),
            ),
            ("two interfaces", format!("{}[Interface]\n", rendered())),
            (
                "key before a section",
                format!("MTU = 1400\n{}", rendered()),
            ),
            ("unknown section", format!("{}[Tunnel]\n", rendered())),
            (
                "the same key twice",
                rendered().replace("MTU = 1380\n", "MTU = 1380\nMTU = 1400\n"),
            ),
            (
                "the same peer twice",
                format!("{}[Peer]\nPublicKey = {KEY_B}\n", rendered()),
            ),
            (
                "no port",
                rendered().replace("vpn.example.com:51820", "vpn.example.com"),
            ),
            (
                "bare IPv6 endpoint",
                rendered().replace("vpn.example.com:51820", "2001:db8::1:51820"),
            ),
            (
                "endpoint with spaces",
                rendered().replace("vpn.example.com:51820", "vpn example.com:51820"),
            ),
            ("tiny MTU", rendered().replace("MTU = 1380", "MTU = 100")),
            (
                "not an address",
                rendered().replace("0.0.0.0/0, ::/0", "0.0.0.0/0, example"),
            ),
        ];
        for (case, text) in cases {
            assert!(parse(&text).is_err(), "{case} was accepted");
        }
    }

    #[test]
    fn keys_are_hex_for_the_socket_and_hidden_from_logs() {
        let key = Key::parse(KEY_A).unwrap();
        assert_eq!(
            key.hex(),
            "c809f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669"
        );
        let config = parse(&rendered()).unwrap();
        let shown = format!("{config:?}");
        for secret in [KEY_A, KEY_B, KEY_C] {
            assert!(!shown.contains(secret), "{shown}");
        }
        assert!(!shown.contains(&key.hex()), "{shown}");
    }
}
