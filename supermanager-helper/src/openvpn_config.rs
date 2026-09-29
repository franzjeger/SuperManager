//! What a profile's configuration may ask of OpenVPN, which the helper runs
//! as root.
//!
//! A configuration describes a connection: where to connect, how to
//! authenticate, what to route. It does not get to name programs to run,
//! plugins or crypto engines to load, files to read or write, or a control
//! socket to open. `check` holds it to an allowlist of directives, wants
//! keys and certificates inline, and says which line it refuses and why.
//!
//! Lines are read the way OpenVPN 2 reads them (`read_config_file` and
//! `parse_line` in its `options.c`): the first word is the directive, a
//! leading `--` is dropped, `#` or `;` at the start of a word begins a
//! comment, quotes and backslashes group and escape, `<name>` alone on a
//! line opens an inline block that the first line starting with `</name>`
//! closes, and `setenv opt` applies the directive that follows it. Where a
//! line could read differently to OpenVPN than to this check, it is refused:
//! anything `parse_line` rejects, bytes outside ASCII where it asks
//! `isspace`, and lines long enough for OpenVPN to read in pieces.

use std::fmt;

/// Longer lines could be read by OpenVPN in more than one piece. It also
/// keeps every word under `parse_line`'s limit of 256 bytes.
const MAX_LINE: usize = 250;
/// `parse_line` stops after this many words (`MAX_PARMS`).
const MAX_WORDS: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub line: usize,
    pub reason: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

/// Directives that describe the connection, whatever their arguments.
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
    // The process. The helper passes `--script-security 1` after the
    // configuration, and no directive that runs a script is allowed.
    "verb", "mute", "echo", "user", "group", "nice", "mlock", "suppress-timestamps",
    "machine-readable-output", "ignore-unknown-option", "script-security", "up-delay",
    "down-pre",
    // Windows-only; harmless where they are not understood.
    "block-outside-dns", "register-dns", "ip-win32", "route-method", "dhcp-renew",
    "dhcp-release", "tap-sleep", "win-sys", "windows-driver",
];

/// Directives that take a file, allowed only with its contents inline.
#[rustfmt::skip]
const INLINE_ONLY: &[&str] = &[
    "ca", "cert", "key", "pkcs12", "extra-certs", "tls-auth", "tls-crypt", "tls-crypt-v2",
    "secret", "dh", "crl-verify", "http-proxy-user-pass",
];

/// OpenSSL's own providers. Any other name is a module to load.
const BUILT_IN_PROVIDERS: &[&str] = &["default", "legacy", "base", "fips"];

/// Blocks a configuration may carry inline, besides `<connection>`.
fn inline_block(name: &str) -> bool {
    INLINE_ONLY.contains(&name) || matches!(name, "auth-user-pass" | "peer-fingerprint")
}

enum Block {
    None,
    Inline(String),
    Connection,
}

/// Refuse `config` unless every line is one OpenVPN may be given.
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
        // OpenVPN skips a UTF-8 byte order mark on the first line.
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
                    // A piece of it could start with the closing tag.
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
            // OpenVPN 2 also takes a quoted tag or one with a comment after
            // it; OpenVPN 3 may not, and the two must agree on where blocks
            // are.
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

/// Whether `line` ends the `<name>` block. OpenVPN closes it at the first
/// line whose text, after leading space, starts with `</name>`, and drops
/// the rest of that line; anything after the tag is refused rather than
/// dropped.
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

fn directive(name: &str, args: &[String]) -> Result<(), String> {
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
        // A tunnel device by kind. Another name would have OpenVPN open
        // `/dev/<name>`, whatever that is.
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
        // Host and port; credentials only inline, or `auto` for an HTTP
        // proxy that says what it wants.
        "http-proxy" | "socks-proxy" => match arg(2) {
            None | Some("[inline]") => Ok(()),
            Some("auto" | "auto-nct") if name == "http-proxy" => Ok(()),
            Some(_) => Err(format!(
                "`{name}` names a credentials file, which SuperManager does not read"
            )),
        },
        "providers"
            if args
                .iter()
                .all(|p| BUILT_IN_PROVIDERS.contains(&p.as_str())) =>
        {
            Ok(())
        }
        "providers" => Err("`providers` loads a module that is not one of OpenSSL's own".into()),
        // OpenVPN strips `setenv opt` and parses the rest as a directive.
        // Other variables go to the commands it runs, `route` and
        // `ifconfig`, where the dynamic linker would act on its own.
        "setenv" => match (arg(0), args.get(1..)) {
            (Some("opt"), Some([wrapped, rest @ ..])) => directive(wrapped, rest),
            (Some(variable), _) if variable.starts_with("DYLD_") => Err(format!(
                "`setenv {variable}` would reach the commands OpenVPN runs"
            )),
            _ => Ok(()),
        },
        _ => Err(format!("SuperManager does not pass `{name}` to OpenVPN")),
    }
}

/// `tun`, `tap` or `utun`, for `dev` with a unit number or without.
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

/// `space()` in `options.c`: NUL or C's `isspace` in the C locale.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// A line's words as `parse_line` splits them, or why it is refused.
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
    // `parse_line` walks the string including its terminating NUL.
    for c in line.chars().chain(std::iter::once('\0')) {
        let space = c == '\0' || is_space(c);
        // Outside quotes, `parse_line` asks `isspace` about every byte,
        // which is not defined for bytes above 0x7f.
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

    /// The directives an imported profile and an Azure one use.
    #[test]
    fn ordinary_profiles_pass() {
        let profile = "client\ndev tun\nproto udp\nremote vpn.example.net 1194\n\
                       resolv-retry infinite\nnobind\nuser nobody\ngroup nogroup\n\
                       persist-key\npersist-tun\nremote-cert-tls server\nauth SHA256\n\
                       cipher AES-256-CBC\nkey-direction 1\ncomp-lzo\nreneg-sec 0\n\
                       redirect-gateway def1\nauth-user-pass\nverb 3\n\
                       <ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n\
                       <cert>\nMIIB\n</cert>\n<key>\nMIIE\n</key>\n\
                       <tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n00ff\n\
                       -----END OpenVPN Static key V1-----\n</tls-auth>\n";
        assert_eq!(check(profile), Ok(()));
        let azure = "# SuperManager-rendered Azure VPN profile\nclient\ndev tun\nproto tcp\n\
                     remote azuregateway-1.vpn.azure.com 443\nresolv-retry infinite\nnobind\n\
                     persist-tun\nremote-cert-tls server\nauth SHA256\ncipher AES-256-GCM\n\
                     data-ciphers AES-256-GCM\ndisable-dco\nverb 3\nauth-user-pass\n\
                     route 10.1.0.0 255.255.0.0\nroute-ipv6 fd00::/64\ndhcp-option DNS 10.1.0.4\n\n\
                     <ca>\nMIIB\n</ca>\n\nkey-direction 1\n<tls-auth>\n00ff\n</tls-auth>\n";
        assert_eq!(check(azure), Ok(()));
    }

    #[test]
    fn comments_quotes_and_line_endings_read_as_openvpn_reads_them() {
        let config = "\u{feff}# first line after a byte order mark\r\n\
                      ; another comment\r\n\
                      remote vpn.example.net 1194 # trailing comment\r\n\
                      verify-x509-name \"C=NO, O=Example, CN=vpn\" subject\r\n\
                      static-challenge 'Enter PIN' 1\r\n\
                      pull-filter ignore \"route-ipv6\"\r\n\
                      --persist-tun\r\n\
                      setenv opt block-outside-dns\r\n\
                      setenv CLIENT_CERT 0\r\n\
                      <connection>\r\nremote backup.example.net 443\r\nproto tcp\r\n</connection>\r\n\
                      ca [inline]\r\n<ca>\r\nMIIB\r\n  </ca>  \r\n";
        assert_eq!(check(config), Ok(()));
    }

    #[test]
    fn directives_outside_the_allowlist_are_refused_by_line() {
        for (config, line) in [
            ("client\nup /usr/local/bin/hook\n", 2),
            ("client\n--up hook\n", 2),
            ("\"up\" hook\n", 1),
            ("setenv opt up hook\n", 1),
            ("setenv   opt   route-up hook\n", 1),
            ("plugin /usr/lib/plugin.so\n", 1),
            ("management 127.0.0.1 7505\n", 1),
            ("log /var/log/x\n", 1),
            ("writepid /var/run/x\n", 1),
            ("config other.ovpn\n", 1),
            ("providers legacy /usr/local/lib/module.dylib\n", 1),
            ("dev disk0\n", 1),
            ("dev ../disk0\n", 1),
            ("dev-type disk\n", 1),
            ("setenv DYLD_INSERT_LIBRARIES /tmp/lib.dylib\n", 1),
            ("<connection>\nremote a 1\nup hook\n</connection>\n", 3),
        ] {
            assert_eq!(refused(config).line, line, "{config:?}");
        }
    }

    #[test]
    fn files_must_be_inline() {
        for config in [
            "ca /etc/ssl/ca.pem\n",
            "tls-auth ta.key 1\n",
            "auth-user-pass creds.txt\n",
            "askpass pass.txt\n",
            "http-proxy proxy.example.net 8080 creds.txt\n",
            "socks-proxy proxy.example.net 1080 creds.txt\n",
            "setenv opt ca /etc/ssl/ca.pem\n",
        ] {
            assert!(check(config).is_err(), "{config:?}");
        }
        for config in [
            "tls-auth [inline] 1\n",
            "auth-user-pass\n",
            "auth-user-pass [inline]\n<auth-user-pass>\nuser\npass\n</auth-user-pass>\n",
            "http-proxy proxy.example.net 8080 auto\n",
            "http-proxy proxy.example.net 8080\n",
            "providers legacy default\n",
            "dev tun\ndev utun7\ndev tap0\ndev-type tun\n",
        ] {
            assert_eq!(check(config), Ok(()), "{config:?}");
        }
    }

    #[test]
    fn blocks_are_the_inline_kinds_and_close() {
        assert!(check("<up>\nhook\n</up>\n").is_err());
        assert_eq!(refused("client\n<ca>\nMIIB\n").line, 2);
        assert!(check("<ca>\nMIIB\n</ca> up hook\n").is_err());
        assert!(check("<connection>\n<ca>\nMIIB\n</ca>\n</connection>\n").is_err());
        // The tag alone on its line, as both OpenVPN 2 and 3 read it.
        assert!(check("\"<ca>\"\nMIIB\n</ca>\n").is_err());
        assert!(check("<ca> # certificate\nMIIB\n</ca>\n").is_err());
        // Inside a block, a directive is just text.
        assert_eq!(check("<ca>\nup hook\n</ca>\n"), Ok(()));
    }

    /// Lines OpenVPN could split, or tokenize differently from this check.
    #[test]
    fn lines_that_could_read_differently_are_refused() {
        let long = format!("setenv X {}\n", "a".repeat(250));
        assert!(check(&long).is_err());
        // A long line inside a block is fine unless a piece of it could
        // start with the closing tag.
        assert_eq!(
            check(&format!("<ca>\n{}\n</ca>\n", "A".repeat(4000))),
            Ok(())
        );
        assert!(check(&format!("<ca>\n{}</ca>\nup hook\n</ca>\n", "A".repeat(300))).is_err());
        assert!(check("remote vpn\u{a0}example.net 1194\n").is_err());
        assert!(check("verb 3\0\nup hook\n").is_err());
        assert!(check("remote \"vpn.example.net 1194\n").is_err());
        assert!(check("remote vpn\\x 1194\n").is_err());
    }

    #[test]
    fn words_follow_parse_line() {
        assert_eq!(
            words("  remote  host 1194  ").unwrap(),
            ["remote", "host", "1194"]
        );
        assert_eq!(
            words("a \"b c\" 'd \\e' f\\ g").unwrap(),
            ["a", "b c", "d \\e", "f g"]
        );
        assert_eq!(words("a #b").unwrap(), ["a"]);
        assert_eq!(words("a b#c").unwrap(), ["a", "b#c"]);
        assert_eq!(words("a \\#b").unwrap(), ["a"]);
        assert_eq!(words("a \"\"").unwrap(), ["a", ""]);
        assert_eq!(words("# comment").unwrap(), Vec::<String>::new());
        assert!(words(&"w ".repeat(17)).is_err());
    }
}
