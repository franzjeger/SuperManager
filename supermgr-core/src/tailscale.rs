//! Shared Tailscale types.
//!
//! The daemon produces these by parsing `tailscale status --json`; the GUI
//! consumes them over D-Bus as a JSON array. One definition rather than two
//! matching ones, for the same reason [`crate::vpn::profile::ProfileSummary`]
//! lives here: a field renamed on one side and not the other is a bug that
//! compiles.

use serde::{Deserialize, Serialize};

/// Progress of an operator-owned browser sign-in. URLs are never in management snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleLoginAttempt {
    /// Unguessable attempt identifier, also bound to the caller UID.
    pub id: String,
    /// waiting, complete, cancelled or failed.
    pub state: String,
    /// HTTPS browser URL while waiting; cleared when the attempt ends.
    pub auth_url: String,
    /// Current progress or recovery result.
    pub message: String,
}

/// One observation from an explicit diagnostic run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleDiagnosticCheck {
    /// Human-readable check label.
    pub name: String,
    /// pass, fail, warning or unknown.
    pub status: String,
    /// Evidence or a specific next step.
    pub detail: String,
}

/// DNS observations from one account at a recorded time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleDnsReport {
    /// UTC RFC 3339 completion timestamp.
    pub checked_at: String,
    /// Account inspected, without authentication material.
    pub profile_id: String,
    /// Resolver comparison and account consistency checks.
    pub checks: Vec<TailscaleDiagnosticCheck>,
    /// Bounded DNS configuration text, excluding raw preferences and secrets.
    pub details: String,
}

/// One node in the tailnet, normalized for GUI consumption.
///
/// A curated subset of what `tailscale status --json` reports — the fields a
/// human reading a device list actually needs. Deliberately not the raw
/// upstream shape: that schema moves between minor versions, and pinning the
/// GUI to it would make every tailscale upgrade a potential breakage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleNode {
    /// Stable Tailscale node ID.
    pub id: String,
    /// Short hostname (e.g. `franzjeger`).
    pub hostname: String,
    /// MagicDNS name (e.g. `franzjeger.tailb0b06a.ts.net`).
    pub dns_name: String,
    /// Operating system as reported by tailscaled (e.g. `linux`, `macOS`,
    /// `iOS`, `windows`).
    pub os: String,
    /// All Tailscale IPs (IPv4 + IPv6) for this node.
    pub tailscale_ips: Vec<String>,
    /// Whether tailscaled currently considers this node online.
    pub online: bool,
    /// Whether this is the local node (`Self` in the raw JSON).
    pub is_self: bool,
    /// Whether this node is the exit node currently in use.
    ///
    /// Tailscale's `ExitNode`. Exactly one peer can have this set, and it
    /// means every packet leaving this machine is going through it right now —
    /// not that the peer is willing to carry traffic. That is
    /// [`Self::exit_node_option`], and conflating the two is how a UI ends up
    /// labelling six machines as exit nodes when none is in use.
    pub exit_node: bool,
    /// Whether this node advertises itself as available to be an exit node.
    ///
    /// Tailscale's `ExitNodeOption`, i.e. the peer ran
    /// `tailscale up --advertise-exit-node` and an admin approved it. The set
    /// of peers a user may legitimately choose between.
    #[serde(default)]
    pub exit_node_option: bool,
    /// RFC 3339 timestamp of last activity, when known. Empty for nodes that
    /// have never been seen on the tailnet.
    pub last_seen: String,
    /// Bytes received from this peer since tailscaled started.
    pub rx_bytes: u64,
    /// Bytes sent to this peer since tailscaled started.
    pub tx_bytes: u64,
    /// Direct endpoint observed by tailscaled; empty when no direct path is known.
    #[serde(default)]
    pub current_address: String,
    /// DERP region, when reported. This alone does not prove current relay use.
    #[serde(default)]
    pub relay: String,
}

/// A saved, already authenticated account; contains no authentication material.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TailscaleProfile {
    /// Stable saved-account identifier.
    pub id: String,
    /// Optional account nickname.
    pub nickname: String,
    /// Tailnet display name.
    pub tailnet: String,
    /// Account login label.
    pub account: String,
    /// Whether this account is active.
    pub selected: bool,
}

/// Only the preferences exposed by this application, never raw debug prefs.
/// Missing values remain unknown instead of becoming invented defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TailscalePreferences {
    /// Account to which these preferences belong.
    pub profile_id: Option<String>,
    /// Whether Tailscale is enabled.
    pub want_running: Option<bool>,
    /// Use tailnet DNS settings.
    pub accept_dns: Option<bool>,
    /// Accept advertised subnet routes.
    pub accept_routes: Option<bool>,
    /// Block incoming tailnet connections.
    pub shields_up: Option<bool>,
    /// Run the Tailscale SSH server.
    pub run_ssh: Option<bool>,
    /// Keep LAN access while using an exit node.
    pub exit_node_allow_lan: Option<bool>,
    /// Offer this machine as an exit node.
    pub advertise_exit_node: Option<bool>,
    /// Advertised subnet CIDRs, excluding default exit-node routes.
    pub advertise_routes: Option<Vec<String>>,
    /// Hostname override; empty uses the OS hostname.
    pub hostname: Option<String>,
    /// Apply Tailscale updates automatically.
    pub auto_update: Option<bool>,
}

/// Partial update: omitted fields are never sent to `tailscale set`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscalePreferencesPatch {
    /// Account to which these preferences belong.
    pub profile_id: String,
    /// Use tailnet DNS settings.
    pub accept_dns: Option<bool>,
    /// Accept advertised subnet routes.
    pub accept_routes: Option<bool>,
    /// Block incoming tailnet connections.
    pub shields_up: Option<bool>,
    /// Run the Tailscale SSH server.
    pub run_ssh: Option<bool>,
    /// Keep LAN access while using an exit node.
    pub exit_node_allow_lan: Option<bool>,
    /// Offer this machine as an exit node.
    pub advertise_exit_node: Option<bool>,
    /// Advertised subnet CIDRs, excluding default exit-node routes.
    pub advertise_routes: Option<Vec<String>>,
    /// Hostname override; empty uses the OS hostname.
    pub hostname: Option<String>,
    /// Apply Tailscale updates automatically.
    pub auto_update: Option<bool>,
}

/// Independent settings/account reads, retaining successful results on partial failure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TailscaleManagement {
    /// Projected preferences, if available.
    pub preferences: Option<TailscalePreferences>,
    /// Saved accounts reported by the local daemon.
    pub profiles: Vec<TailscaleProfile>,
    /// Read failures that leave part of the snapshot unavailable.
    pub warnings: Vec<String>,
}

impl TailscaleNode {
    /// The IPv4 (100.x) address, which is the one worth showing: it is what
    /// operators type, what `ssh` takes without brackets, and what appears in
    /// ACLs. Falls back to the first address of any family so a v6-only node
    /// still renders as something.
    #[must_use]
    pub fn primary_ip(&self) -> Option<&str> {
        self.tailscale_ips
            .iter()
            .find(|ip| ip.contains('.'))
            .or_else(|| self.tailscale_ips.first())
            .map(String::as_str)
    }

    /// Hostname if tailscaled reported one, otherwise the leading label of the
    /// MagicDNS name, otherwise the node ID.
    ///
    /// Never empty, because this is what a row is labelled with — a blank row
    /// is worse than an ugly one.
    #[must_use]
    pub fn display_name(&self) -> &str {
        if !self.hostname.is_empty() {
            return &self.hostname;
        }
        if let Some(label) = self.dns_name.split('.').next() {
            if !label.is_empty() {
                return label;
            }
        }
        &self.id
    }
}

/// The local Tailscale stack's condition, as far as the daemon can tell.
///
/// Produced by the daemon (`supermgrd::tailscale::health`), consumed by the
/// GUI over D-Bus as JSON. Exists because "Tailscale is broken" is four
/// different facts with four different remedies — CLI not installed, service
/// not running, logged out, brought down — and an error string collapses them
/// into a dead end. Each field maps to exactly one remediation the daemon can
/// perform, so the GUI can offer the fix instead of describing the failure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TailscaleHealth {
    /// The `tailscale` binary exists and could be spawned. When false the
    /// remedy is `TailscaleRepair` (package installation) and every other
    /// field is meaningless.
    pub cli_present: bool,
    /// The local tailscaled answered the CLI. When false the remedy is
    /// starting the service, which `TailscaleRepair` also does.
    pub daemon_running: bool,
    /// tailscaled's own `BackendState` string, verbatim: `Running`,
    /// `NeedsLogin`, `Stopped`, `Starting`, `NoState`. Verbatim rather than
    /// re-encoded because tailscale owns this vocabulary and inventing a
    /// parallel one means two lists to keep in step.
    pub backend_state: String,
    /// Interactive login URL, when tailscaled has one pending. Non-empty
    /// only in `NeedsLogin` after a login has been initiated — the GUI opens
    /// it in a browser and keeps polling until the state leaves `NeedsLogin`.
    pub auth_url: String,
    /// Human-readable detail for states the fields above cannot express —
    /// the spawn error, the CLI's stderr. Never a substitute for them.
    pub detail: String,
}

impl TailscaleHealth {
    /// Whether the stack is fully up: node listing will succeed and the
    /// device list is worth fetching.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.cli_present && self.daemon_running && self.backend_state == "Running"
    }

    /// Whether the only thing missing is a human authenticating in a
    /// browser — the one condition the daemon cannot repair by itself.
    #[must_use]
    pub fn needs_login(&self) -> bool {
        self.cli_present && self.daemon_running && self.backend_state == "NeedsLogin"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(ips: &[&str], hostname: &str, dns: &str) -> TailscaleNode {
        TailscaleNode {
            id: "nStableID".into(),
            hostname: hostname.into(),
            dns_name: dns.into(),
            os: "linux".into(),
            tailscale_ips: ips.iter().map(|s| (*s).to_owned()).collect(),
            online: true,
            is_self: false,
            exit_node: false,
            exit_node_option: false,
            last_seen: String::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            current_address: String::new(),
            relay: String::new(),
        }
    }

    #[test]
    fn primary_ip_prefers_v4() {
        let n = node(&["fd7a:115c::1", "100.101.102.103"], "host", "host.ts.net");
        assert_eq!(n.primary_ip(), Some("100.101.102.103"));
    }

    #[test]
    fn primary_ip_falls_back_to_v6_only() {
        let n = node(&["fd7a:115c::1"], "host", "host.ts.net");
        assert_eq!(n.primary_ip(), Some("fd7a:115c::1"));
    }

    #[test]
    fn primary_ip_is_none_when_the_node_has_no_addresses() {
        let n = node(&[], "host", "host.ts.net");
        assert_eq!(n.primary_ip(), None);
    }

    #[test]
    fn display_name_prefers_hostname_then_dns_label_then_id() {
        assert_eq!(
            node(&[], "shortname", "long.ts.net").display_name(),
            "shortname"
        );
        assert_eq!(
            node(&[], "", "fromdns.tailnet.ts.net").display_name(),
            "fromdns"
        );
        // A node with neither still labels its row rather than rendering blank.
        assert_eq!(node(&[], "", "").display_name(), "nStableID");
    }

    #[test]
    fn round_trips_through_json() {
        // The wire format between daemon and GUI. A field that fails to
        // deserialize here would surface as an empty device list.
        let n = node(&["100.64.0.1"], "host", "host.ts.net");
        let back: TailscaleNode =
            serde_json::from_str(&serde_json::to_string(&n).unwrap()).unwrap();
        assert_eq!(back.id, n.id);
        assert_eq!(back.tailscale_ips, n.tailscale_ips);
    }

    #[test]
    fn health_running_requires_all_three_layers() {
        // Each layer being down has a different remedy; `is_running` must
        // only say yes when none of them is needed.
        let mut h = TailscaleHealth {
            cli_present: true,
            daemon_running: true,
            backend_state: "Running".into(),
            ..TailscaleHealth::default()
        };
        assert!(h.is_running());
        h.backend_state = "NeedsLogin".into();
        assert!(!h.is_running());
        assert!(h.needs_login());
        h.daemon_running = false;
        assert!(!h.needs_login(), "a dead daemon is not a login problem");
    }

    #[test]
    fn health_deserializes_with_missing_fields() {
        // The daemon and GUI can be upgraded independently; an older daemon
        // sending fewer fields must not blank the whole page.
        let h: TailscaleHealth = serde_json::from_str("{}").unwrap();
        assert!(!h.cli_present);
        assert!(h.auth_url.is_empty());
    }
}
