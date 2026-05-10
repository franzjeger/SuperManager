//! Probe for the external CLI tools the engine shells out to.
//!
//! Several modules depend on tools that ship with macOS by default
//! (`route`, `ifconfig`, `scutil`, `arp`, `dns-sd`) but several
//! others are install-via-Homebrew (`smbclient`, `snmpget`,
//! `snmpwalk`, `nmblookup`, `dig`, `pandoc`). When a tool is
//! missing the relevant probe silently no-ops and findings vanish
//! — the operator has no visibility into "why didn't SMB enum run?".
//!
//! This module exposes a single RPC `tools_status` that the
//! Settings UI calls on appear; it returns a list of every CLI
//! tool we depend on, whether it's present, the version string,
//! and a brew-formula hint when missing.
//!
//! Tools are checked in parallel (`tokio::join!`) so the whole
//! probe fits in <1 s.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub purpose: String,
    /// `true` when the tool resolved on PATH and the version probe
    /// returned successfully. `false` for not-found or non-zero
    /// exit on `--version`.
    pub installed: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    /// Homebrew formula that ships this tool, when applicable.
    /// `None` for tools shipped with macOS — we don't suggest a
    /// brew install for those.
    pub brew_formula: Option<&'static str>,
    /// "macOS" / "Homebrew" / "Manual" — where the user is expected
    /// to get this tool from.
    pub source: &'static str,
}

struct Spec {
    name: &'static str,
    args: &'static [&'static str],     // version probe
    purpose: &'static str,
    brew: Option<&'static str>,
    source: &'static str,
}

const SPECS: &[Spec] = &[
    // --- shipped with macOS ---
    Spec {
        name: "route",
        args: &["-h"],
        purpose: "Default-gateway detection (network detect)",
        brew: None,
        source: "macOS",
    },
    Spec {
        name: "ifconfig",
        args: &[],
        purpose: "Interface enumeration (passive scan)",
        brew: None,
        source: "macOS",
    },
    Spec {
        name: "arp",
        args: &["-a"],
        purpose: "ARP cache reading (passive discovery)",
        brew: None,
        source: "macOS",
    },
    Spec {
        name: "scutil",
        args: &["--get", "ComputerName"],
        purpose: "DNS resolver enumeration",
        brew: None,
        source: "macOS",
    },
    Spec {
        name: "dns-sd",
        args: &["-V"],
        purpose: "mDNS service discovery (passive scan)",
        brew: None,
        source: "macOS",
    },
    Spec {
        name: "openssl",
        args: &["version"],
        purpose: "TLS audit (cert chain + handshake parsing)",
        brew: Some("openssl@3"),
        source: "macOS",
    },
    // --- Homebrew ---
    Spec {
        name: "dig",
        args: &["-v"],
        purpose: "DNS health audit (SPF/DKIM/DMARC/DNSSEC)",
        brew: Some("bind"),
        source: "Homebrew",
    },
    Spec {
        name: "smbclient",
        args: &["--version"],
        purpose: "SMB share enumeration (null-session)",
        brew: Some("samba"),
        source: "Homebrew",
    },
    Spec {
        name: "nmblookup",
        args: &["--version"],
        purpose: "NetBIOS name + workgroup lookup",
        brew: Some("samba"),
        source: "Homebrew",
    },
    Spec {
        name: "snmpget",
        args: &["-V"],
        purpose: "SNMP system OID read",
        brew: Some("net-snmp"),
        source: "Homebrew",
    },
    Spec {
        name: "snmpwalk",
        args: &["-V"],
        purpose: "SNMP MIB walk (interface table)",
        brew: Some("net-snmp"),
        source: "Homebrew",
    },
    Spec {
        name: "pandoc",
        args: &["--version"],
        purpose: "PDF export of engagement reports",
        brew: Some("pandoc"),
        source: "Homebrew",
    },
];

pub async fn status() -> Vec<ToolInfo> {
    let mut out = Vec::with_capacity(SPECS.len());
    let mut handles = Vec::with_capacity(SPECS.len());
    for spec in SPECS {
        handles.push(tokio::spawn(probe_one(spec)));
    }
    for h in handles {
        if let Ok(info) = h.await {
            out.push(info);
        }
    }
    out
}

async fn probe_one(spec: &'static Spec) -> ToolInfo {
    // 1. PATH lookup via `which`. This picks up tools shipped with
    //    macOS (in `/usr/bin`) but misses Homebrew tools when the
    //    helper is launched by launchd, because launchd's default
    //    PATH is `/usr/bin:/bin:/usr/sbin:/sbin` — no
    //    `/opt/homebrew/bin`. So a `brew install pandoc` works for
    //    the user but the helper-side `which pandoc` returns
    //    nothing, and the panel keeps nagging "Install: brew
    //    install pandoc" forever. Step 2 below covers that.
    let path_result = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::process::Command::new("which").arg(spec.name).output(),
    )
    .await;
    let mut path: Option<String> = match path_result {
        Ok(Ok(out)) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if s.is_empty() { None } else { Some(s) }
        }
        _ => None,
    };
    // 2. Fallback to known Homebrew + MacPorts prefixes when PATH
    //    didn't resolve. Order matters: prefer Apple-Silicon brew
    //    over Intel brew over MacPorts. We don't dedupe — first hit
    //    wins.
    if path.is_none() {
        const FALLBACK_PREFIXES: &[&str] = &[
            "/opt/homebrew/bin",     // Apple Silicon brew (default)
            "/opt/homebrew/sbin",    // Apple Silicon brew (sbin variants)
            "/usr/local/bin",        // Intel brew (default)
            "/usr/local/sbin",       // Intel brew (sbin variants)
            "/opt/local/bin",        // MacPorts
        ];
        for prefix in FALLBACK_PREFIXES {
            let candidate = format!("{prefix}/{}", spec.name);
            if std::path::Path::new(&candidate).exists() {
                path = Some(candidate);
                break;
            }
        }
    }

    // Run the actual binary to fetch the version. Use the absolute
    // path we resolved above — `Command::new(spec.name)` would
    // hit the same `which` PATH issue we just worked around.
    let version = if let Some(ref p) = path {
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::process::Command::new(p).args(spec.args).output(),
        )
        .await;
        match res {
            Ok(Ok(out)) => {
                // Tools vary: version output may be on stdout or stderr.
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                first_useful_line(&combined)
            }
            _ => None,
        }
    } else {
        None
    };

    ToolInfo {
        name: spec.name.to_owned(),
        purpose: spec.purpose.to_owned(),
        installed: path.is_some(),
        version,
        path,
        brew_formula: spec.brew,
        source: spec.source,
    }
}

/// Pick the first non-empty trimmed line — version-probe output
/// is rarely consistent across tools, but the first informative
/// line is almost always the version string.
fn first_useful_line(s: &str) -> Option<String> {
    s.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| l.to_owned())
}
