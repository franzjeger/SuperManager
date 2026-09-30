//! wireguard-go's configuration socket, `/var/run/wireguard/<utun>.sock`:
//! the cross-platform userspace protocol `wg` itself speaks
//! (<https://www.wireguard.com/xplatform/#configuration-protocol>).

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::conf::Config;

/// Replies are a few lines per peer; anything near this is not one.
const MAX_REPLY: usize = 1 << 20;
const TIMEOUT: Duration = Duration::from_secs(5);

pub fn socket(interface: &str) -> PathBuf {
    PathBuf::from(format!("/var/run/wireguard/{interface}.sock"))
}

/// Whether a wireguard-go serves the device's socket. A socket file alone
/// can be left from one that is gone.
pub async fn answers(interface: &str) -> bool {
    let connect = tokio::net::UnixStream::connect(socket(interface));
    matches!(tokio::time::timeout(TIMEOUT, connect).await, Ok(Ok(_)))
}

/// `set=1` for the whole device: its key and port, and its peers, which
/// replace any it had. `endpoints[i]` is peer `i`'s resolved endpoint.
fn set_request(config: &Config, endpoints: &[Option<SocketAddr>]) -> String {
    use std::fmt::Write as _;
    let mut request = String::from("set=1\n");
    let _ = writeln!(request, "private_key={}", config.private_key.hex());
    if let Some(port) = config.listen_port {
        let _ = writeln!(request, "listen_port={port}");
    }
    request.push_str("replace_peers=true\n");
    for (peer, endpoint) in config.peers.iter().zip(endpoints) {
        let _ = writeln!(request, "public_key={}", peer.public_key.hex());
        if let Some(psk) = &peer.preshared_key {
            let _ = writeln!(request, "preshared_key={}", psk.hex());
        }
        if let Some(endpoint) = endpoint {
            let _ = writeln!(request, "endpoint={endpoint}");
        }
        if let Some(interval) = peer.persistent_keepalive {
            let _ = writeln!(request, "persistent_keepalive_interval={interval}");
        }
        request.push_str("replace_allowed_ips=true\n");
        for net in &peer.allowed_ips {
            let _ = writeln!(request, "allowed_ip={net}");
        }
    }
    request.push('\n');
    request
}

/// Configure the device as `config` says.
pub async fn set(interface: &str, config: &Config, endpoints: &[Option<SocketAddr>]) -> Result<()> {
    let reply = exchange(interface, &set_request(config, endpoints)).await?;
    errno(&reply).context("wireguard-go refused the configuration")
}

/// The addresses the device's peers are sending to now. wireguard-go
/// moves a peer's endpoint to wherever authenticated packets come from.
pub async fn endpoints(interface: &str) -> Result<Vec<IpAddr>> {
    let reply = exchange(interface, "get=1\n\n").await?;
    errno(&reply)?;
    Ok(parse_endpoints(&reply))
}

fn parse_endpoints(reply: &str) -> Vec<IpAddr> {
    reply
        .lines()
        .filter_map(|line| line.strip_prefix("endpoint="))
        .filter_map(|endpoint| endpoint.parse::<SocketAddr>().ok())
        .map(|endpoint| endpoint.ip())
        .collect()
}

/// A reply ends with `errno=N`; 0 is success.
fn errno(reply: &str) -> Result<()> {
    let code = reply
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("errno="))
        .ok_or_else(|| anyhow!("no status in the reply"))?;
    if code != "0" {
        bail!("errno {code}");
    }
    Ok(())
}

async fn exchange(interface: &str, request: &str) -> Result<String> {
    exchange_at(&socket(interface), request).await
}

/// Send one request and read its reply, which ends with an empty line.
async fn exchange_at(path: &Path, request: &str) -> Result<String> {
    let talk = async {
        let mut stream = tokio::net::UnixStream::connect(path)
            .await
            .with_context(|| format!("connect {}", path.display()))?;
        stream.write_all(request.as_bytes()).await?;
        let mut reply = Vec::new();
        let mut chunk = [0u8; 4096];
        while !reply.ends_with(b"\n\n") {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                bail!("wireguard-go closed the socket mid-reply");
            }
            reply.extend_from_slice(&chunk[..n]);
            if reply.len() > MAX_REPLY {
                bail!("the reply is too large");
            }
        }
        Ok(String::from_utf8_lossy(&reply).into_owned())
    };
    tokio::time::timeout(TIMEOUT, talk)
        .await
        .map_err(|_| anyhow!("{} did not answer", path.display()))?
}

#[cfg(test)]
mod tests {
    use super::super::conf;
    use super::*;

    const KEY_A: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const KEY_B: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const KEY_C: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    #[test]
    fn the_request_sets_the_device_and_replaces_its_peers() {
        let config = conf::parse(&format!(
            "[Interface]\nPrivateKey = {KEY_A}\nListenPort = 51820\n\
             [Peer]\nPublicKey = {KEY_B}\nPresharedKey = {KEY_C}\n\
             Endpoint = vpn.example.com:51820\nPersistentKeepalive = 25\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             [Peer]\nPublicKey = {KEY_C}\nAllowedIPs = 10.9.0.0/16\n"
        ))
        .unwrap();
        let endpoints = [Some("[2001:db8::1]:51820".parse().unwrap()), None];
        let hex = |key: &str| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(key)
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            set_request(&config, &endpoints),
            format!(
                "set=1\nprivate_key={}\nlisten_port=51820\nreplace_peers=true\n\
                 public_key={}\npreshared_key={}\nendpoint=[2001:db8::1]:51820\n\
                 persistent_keepalive_interval=25\nreplace_allowed_ips=true\n\
                 allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n\
                 public_key={}\nreplace_allowed_ips=true\nallowed_ip=10.9.0.0/16\n\n",
                hex(KEY_A),
                hex(KEY_B),
                hex(KEY_C),
                hex(KEY_C),
            )
        );
    }

    #[test]
    fn a_reply_says_whether_it_worked_and_where_peers_are() {
        assert!(errno("errno=0\n\n").is_ok());
        assert!(errno("errno=-22\n\n").is_err());
        assert!(errno("").is_err());
        let reply = "private_key=00\nlisten_port=51820\npublic_key=11\n\
                     endpoint=192.0.2.1:51820\nlast_handshake_time_sec=0\n\
                     public_key=22\nendpoint=[2001:db8::1]:51820\n\
                     public_key=33\nerrno=0\n\n";
        assert!(errno(reply).is_ok());
        assert_eq!(
            parse_endpoints(reply),
            vec![
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
    }

    /// wireguard-go's side, as far as a reply that arrives in pieces.
    #[tokio::test]
    async fn a_reply_is_read_to_its_end() {
        let dir = std::env::temp_dir().join(format!(
            "smuapi-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("utun99.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 64];
            while !request.ends_with(b"\n\n") {
                let n = stream.read(&mut chunk).await.unwrap();
                request.extend_from_slice(&chunk[..n]);
            }
            stream
                .write_all(b"public_key=11\nendpoint=192.0.2.1:51820\nerr")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            stream.write_all(b"no=0\n\n").await.unwrap();
            request
        });
        let reply = exchange_at(&path, "get=1\n\n").await.unwrap();
        assert_eq!(server.await.unwrap(), b"get=1\n\n");
        assert!(errno(&reply).is_ok(), "{reply:?}");
        assert_eq!(
            parse_endpoints(&reply),
            vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_device_that_is_not_there_is_an_error() {
        let err = endpoints("utun-not-there").await.unwrap_err();
        assert!(
            format!("{err:#}").contains("utun-not-there.sock"),
            "{err:#}"
        );
    }
}
