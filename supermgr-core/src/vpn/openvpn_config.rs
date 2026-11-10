//! Strict allowlist validator for imported `OpenVPN` client configurations.
//!
//! Privilege-separated daemons (`supermgrd` on Linux, `supermgrd-win` on
//! Windows, `supermanager-helper` on macOS) execute `OpenVPN` as `root` or
//! `LocalSystem`. An imported `.ovpn` profile may describe where to connect,
//! how to verify the peer, and what routes/DNS to accept — never programs to
//! execute (`up`, `down`, `tls-verify`, `route-up`, `ipchange`), shared
//! libraries/engines to load (`plugin`, custom `providers`, `engine`), files
//! to read or overwrite (`log`, `status`, `writepid`, external `ca`/`key`
//! paths), or control sockets (`management`).
//!
//! Tokenisation mirrors `read_config_file` / `parse_line` in `OpenVPN` 2's
//! `options.c` so a line cannot read differently to `OpenVPN` than to this
//! validator.

use std::fmt;

/// Maximum single-line length outside inline PEM blocks, matching `parse_line`
/// safety bounds in `OpenVPN`.
const MAX_LINE: usize = 250;
/// `parse_line` stops after 16 words (`MAX_PARMS`).
const MAX_WORDS: usize = 16;

/// Reason an `OpenVPN` configuration line was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// 1-based line number in the input configuration.
    pub line: usize,
    /// Human-readable explanation of why the line was rejected.
    pub reason: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

/// Connection, crypto, routing, and socket directives safe regardless of args.
#[rustfmt::skip]
const ANY_ARGUMENTS: &[&str] = &[
    // Connection.
    "client", "tls-client", "pull", "proto", "remote", "remote-random",
    "remote-random-hostname", "resolv-retry", "nobind", "bind", "lport", "rport", "port",
    "local", "float", "connect-retry", "connect-retry-max", "connect-timeout",
    "server-poll-timeout", "explicit-exit-notify", "persist-key", "persist-tun",
    "persist-remote-ip", "persist-local-ip", "keepalive", "ping", "ping-restart", "ping-exit",
    "ping-timer-rem", "inactive", "hand-window", "tran-window", "reneg-sec", "reneg-bytes",
    "reneg-pkts", "session-timeout", "single-session", "tls-exit", "tls-timeout",
    "http-proxy-option", "http-proxy-retry", "http-proxy-timeout", "socks-proxy-retry",
    "disable-dco", "disable-occ", "remap-usr1",
    // Crypto and peer verification.
    "cipher", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers", "ncp-disable", "auth",
    "key-direction", "key-method", "tls-version-min", "tls-version-max", "tls-cipher",
    "tls-ciphersuites", "tls-groups", "ecdh-curve", "tls-cert-profile", "remote-cert-tls",
    "remote-cert-ku", "remote-cert-eku", "ns-cert-type", "verify-x509-name", "verify-hash",
    "peer-fingerprint", "auth-nocache", "auth-retry", "auth-token-user", "static-challenge",
    "push-peer-info",
    // Addresses, routes and DNS.
    "ifconfig", "ifconfig-ipv6", "ifconfig-noexec", "topology", "tun-ipv6", "route",
    "route-ipv6", "route-gateway", "route-ipv6-gateway", "route-metric", "route-delay",
    "route-nopull", "route-noexec", "redirect-gateway", "redirect-private", "block-ipv6",
    "dhcp-option", "dns", "pull-filter", "allow-pull-fqdn", "allow-recursive-routing",
    "max-routes",
    // Packets and sockets.
    "tun-mtu", "tun-mtu-extra", "link-mtu", "mtu-disc", "mtu-test", "fragment", "mssfix",
    "sndbuf", "rcvbuf", "txqueuelen", "socket-flags", "fast-io", "passtos", "comp-lzo",
    "compress", "allow-compression", "comp-noadapt", "replay-window", "mute-replay-warnings",
    // Process options (note: `script-security` is validated explicitly below).
    "verb", "mute", "echo", "user", "group", "nice", "mlock", "suppress-timestamps",
    "machine-readable-output", "ignore-unknown-option", "up-delay", "down-pre",
    // Windows-only options; harmless elsewhere.
    "block-outside-dns", "register-dns", "ip-win32", "route-method", "dhcp-renew",
    "dhcp-release", "tap-sleep", "win-sys", "windows-driver",
];

/// File-bearing directives allowed only with `[inline]` / `<tag>...</tag>`.
#[rustfmt::skip]
const INLINE_ONLY: &[&str] = &[
    "ca", "cert", "key", "pkcs12", "extra-certs", "tls-auth", "tls-crypt", "tls-crypt-v2",
    "secret", "dh", "crl-verify", "http-proxy-user-pass",
];

/// Built-in OpenSSL providers; any other name loads an arbitrary DSO.
const BUILT_IN_PROVIDERS: &[&str] = &["default", "legacy", "base", "fips"];

fn inline_block(name: &str) -> bool {
    INLINE_ONLY.contains(&name) || matches!(name, "auth-user-pass" | "peer-fingerprint")
}

enum Block {
    None,
    Inline(String),
    Connection,
}

/// Refuse `config` unless every directive and block is safe for a root/`SYSTEM`
/// daemon to pass to `OpenVPN`.
pub fn check(config: &str) -> Result<(), Refusal> {
    let mut block = Block::None;
    let mut opened_at = 0;
    for (index, raw) in config.split('\n').enumerate() {
        let number = index + 1;
        let refuse = |reason: String| Refusal {
            line: number,
            reason,
        };
        if raw.contains('\0') {
            return Err(refuse("a NUL character".into()));
        }
        let line = if index == 0 {
            raw.strip_prefix('\u{feff}').unwrap_or(raw)
        } else {
            raw
        };
        match &block {
            Block::Inline(name) => {
                if closes(line, name).map_err(refuse)? {
                    block = Block::None;
                } else if line.len() > MAX_LINE && line.contains('<') {
                    return Err(refuse(format!(
                        "a line in <{name}> longer than {MAX_LINE} characters with a `<` in it"
                    )));
                }
                continue;
            }
            Block::Connection => {
                if closes(line, "connection").map_err(refuse)? {
                    block = Block::None;
                    continue;
                }
            }
            Block::None => {}
        }
        if line.len() > MAX_LINE {
            return Err(refuse(format!("longer than {MAX_LINE} characters")));
        }
        let words = words(line).map_err(|reason| refuse(reason.into()))?;
        let Some(first) = words.first() else {
            continue;
        };
        if let Some(name) = first
            .strip_prefix('<')
            .and_then(|tag| tag.strip_suffix('>'))
            .filter(|_| words.len() == 1)
        {
            if matches!(block, Block::Connection) {
                return Err(refuse(format!(
                    "<{name}> inside <connection>, which SuperManager does not support"
                )));
            }
            if line.trim_matches(is_space) != format!("<{name}>") {
                return Err(refuse(format!("put <{name}> alone on its line")));
            }
            block = if name == "connection" {
                Block::Connection
            } else if inline_block(name) {
                Block::Inline(name.to_owned())
            } else {
                return Err(refuse(format!(
                    "SuperManager does not pass <{name}> to OpenVPN"
                )));
            };
            opened_at = number;
            continue;
        }
        let name = match first.strip_prefix("--") {
            Some(rest) if first.len() >= 3 => rest,
            _ => first.as_str(),
        };
        directive(name, &words[1..]).map_err(refuse)?;
    }
    match block {
        Block::None => Ok(()),
        Block::Inline(name) => Err(Refusal {
            line: opened_at,
            reason: format!("<{name}> is never closed"),
        }),
        Block::Connection => Err(Refusal {
            line: opened_at,
            reason: "<connection> is never closed".into(),
        }),
    }
}

fn closes(line: &str, name: &str) -> Result<bool, String> {
    let tag = format!("</{name}>");
    let Some(rest) = line.trim_start_matches(is_space).strip_prefix(&tag) else {
        return Ok(false);
    };
    if rest.trim_matches(is_space).is_empty() {
        Ok(true)
    } else {
        Err(format!("text after {tag}"))
    }
}

fn is_dangerous_env_var(variable: &str) -> bool {
    let upper = variable.to_ascii_uppercase();
    upper.starts_with("DYLD_")
        || upper.starts_with("LD_")
        || upper.starts_with("OPENSSL_")
        || upper.starts_with("SSL_")
        || upper.starts_with("PYTHON")
        || upper.starts_with("PERL")
        || matches!(
            upper.as_str(),
            "PATH" | "IFS" | "BASH_ENV" | "ENV" | "COMSPEC" | "SYSTEMROOT"
        )
}

fn directive(name: &str, args: &[String]) -> Result<(), String> {
    let lower = name.to_ascii_lowercase();
    let name = lower.as_str();
    let arg = |n: usize| args.get(n).map(String::as_str);
    if ANY_ARGUMENTS.contains(&name) {
        return Ok(());
    }
    if INLINE_ONLY.contains(&name) {
        return if arg(0) == Some("[inline]") {
            Ok(())
        } else {
            Err(format!(
                "`{name}` names a file; put its contents between <{name}> and </{name}> instead"
            ))
        };
    }
    match name {
        "script-security" => match (arg(0), args.len()) {
            (Some("0" | "1"), 1) => Ok(()),
            _ => Err(
                "`script-security` above 1 allows external script execution and is refused".into(),
            ),
        },
        "dev" | "dev-type" => match arg(0) {
            Some(device) if tunnel_device(name, device) => Ok(()),
            _ => Err(format!("`{name}` must be tun, tap or utun")),
        },
        "auth-user-pass" | "askpass" => match arg(0) {
            None | Some("[inline]") => Ok(()),
            Some(_) => Err(format!(
                "`{name}` names a file, which SuperManager does not read; it passes the \
                 credentials itself"
            )),
        },
        "http-proxy" | "socks-proxy" => match arg(2) {
            None | Some("[inline]") => Ok(()),
            Some("auto" | "auto-nct") if name == "http-proxy" => Ok(()),
            Some(_) => Err(format!(
                "`{name}` names a credentials file, which SuperManager does not read"
            )),
        },
        "providers"
            if !args.is_empty()
                && args
                    .iter()
                    .all(|p| BUILT_IN_PROVIDERS.contains(&p.as_str())) =>
        {
            Ok(())
        }
        "providers" => Err("`providers` loads a module that is not one of OpenSSL's own".into()),
        "setenv" => match (arg(0), args.get(1..)) {
            (Some("opt"), Some([wrapped, rest @ ..])) => directive(wrapped, rest),
            (Some(variable), _) if is_dangerous_env_var(variable) => Err(format!(
                "`setenv {variable}` would reach the commands OpenVPN runs"
            )),
            _ => Ok(()),
        },
        _ => Err(format!("SuperManager does not pass `{name}` to OpenVPN")),
    }
}

fn tunnel_device(directive: &str, device: &str) -> bool {
    let unit = |kind: &str| {
        device
            .strip_prefix(kind)
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
    };
    match directive {
        "dev-type" => matches!(device, "tun" | "tap"),
        _ => unit("utun") || unit("tun") || unit("tap"),
    }
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

fn words(line: &str) -> Result<Vec<String>, &'static str> {
    #[derive(PartialEq)]
    enum State {
        Initial,
        Unquoted,
        Quoted,
        SingleQuoted,
    }
    let mut state = State::Initial;
    let mut backslash = false;
    let mut words = Vec::new();
    let mut word = String::new();
    for c in line.chars().chain(std::iter::once('\0')) {
        let space = c == '\0' || is_space(c);
        if !c.is_ascii() && matches!(state, State::Initial | State::Unquoted) {
            return Err("a character outside ASCII outside quotes");
        }
        let mut out = None;
        let mut done = false;
        if !backslash && c == '\\' && state != State::SingleQuoted {
            backslash = true;
            continue;
        }
        match state {
            State::Initial if !space => {
                if c == '#' || c == ';' {
                    break;
                }
                if !backslash && c == '"' {
                    state = State::Quoted;
                } else if !backslash && c == '\'' {
                    state = State::SingleQuoted;
                } else {
                    out = Some(c);
                    state = State::Unquoted;
                }
            }
            State::Initial => {}
            State::Unquoted if !backslash && space => done = true,
            State::Quoted if !backslash && c == '"' => done = true,
            State::SingleQuoted if c == '\'' => done = true,
            State::Unquoted | State::Quoted | State::SingleQuoted => out = Some(c),
        }
        if let Some(out) = out.filter(|&out| out != '\0') {
            if backslash && !(out == '\\' || out == '"' || is_space(out)) {
                return Err("a backslash OpenVPN rejects");
            }
            word.push(out);
        }
        backslash = false;
        if done {
            words.push(std::mem::take(&mut word));
            state = State::Initial;
            if words.len() > MAX_WORDS {
                return Err("more than 16 words");
            }
        }
    }
    match state {
        State::Initial => Ok(words),
        State::Quoted | State::SingleQuoted => Err("a quote that is never closed"),
        State::Unquoted => Err("a line OpenVPN cannot read"),
    }
}

#[cfg(test)]
mod tests {
    use super::{check, words, Refusal};

    fn refused(config: &str) -> Refusal {
        check(config).expect_err(config)
    }

    #[test]
    fn ordinary_profiles_pass() {
        let profile = "client\ndev tun\nproto udp\nremote vpn.example.net 1194\n\
                       resolv-retry infinite\nnobind\nuser nobody\ngroup nogroup\n\
                       persist-key\npersist-tun\nremote-cert-tls server\nauth SHA256\n\
                       cipher AES-256-CBC\nkey-direction 1\ncomp-lzo\nreneg-sec 0\n\
                       redirect-gateway def1\nauth-user-pass\nverb 3\nscript-security 1\n\
                       <ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n\
                       <cert>\nMIIB\n</cert>\n<key>\nMIIE\n</key>\n\
                       <tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n00ff\n\
                       -----END OpenVPN Static key V1-----\n</tls-auth>\n";
        assert_eq!(check(profile), Ok(()));
    }

    #[test]
    fn directives_outside_the_allowlist_are_refused_by_line() {
        for (config, line) in [
            ("client\nup /usr/local/bin/hook\n", 2),
            ("client\n--up hook\n", 2),
            ("client\nscript-security 2\n", 2),
            ("\"up\" hook\n", 1),
            ("setenv opt up hook\n", 1),
            ("plugin /usr/lib/plugin.so\n", 1),
            ("management 127.0.0.1 7505\n", 1),
            ("log /var/log/x\n", 1),
            ("writepid /var/run/x\n", 1),
            ("config other.ovpn\n", 1),
            ("providers legacy /usr/local/lib/module.dylib\n", 1),
            ("dev disk0\n", 1),
            ("setenv DYLD_INSERT_LIBRARIES /tmp/lib.dylib\n", 1),
            ("setenv LD_PRELOAD /tmp/lib.so\n", 1),
            ("setenv OPENSSL_CONF /tmp/evil.cnf\n", 1),
            ("setenv PATH /tmp/evil\n", 1),
            ("<connection>\nremote a 1\nup hook\n</connection>\n", 3),
        ] {
            assert_eq!(refused(config).line, line, "{config:?}");
        }
    }

    #[test]
    fn words_follow_parse_line() {
        assert_eq!(
            words("  remote  host 1194  ").unwrap(),
            ["remote", "host", "1194"]
        );
        assert!(words(&"w ".repeat(17)).is_err());
    }
}
