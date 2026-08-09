//! Application state and inter-thread message types.
#![allow(missing_docs)]

use serde_json::Value;
use supermgr_core::{
    vpn::profile::ProfileSummary,
    vpn::state::VpnState,
    ssh::key::SshKeySummary,
    host::HostSummary,
    tailscale::TailscaleNode,
    compliance::{CheckDefinition, ComplianceRun, RunSummary},
};

/// Which top-level section is active in the UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Section {
    #[default]
    Vpn,
    Ssh,
    Console,
    Provisioning,
}

/// Shared application state — plain Rust types only, no GTK objects.
///
/// Held behind `Arc<Mutex<AppState>>` so both the GTK main thread and tokio
/// background tasks can access it.  Never hold the lock across an `.await`.
#[derive(Debug, Default)]
pub struct AppState {
    // VPN
    /// VPN profiles returned by `ListProfiles`.
    pub profiles: Vec<ProfileSummary>,
    /// Latest VPN state received from the daemon.
    pub vpn_state: VpnState,
    /// UUID string of the profile selected in the sidebar, if any.
    pub selected_profile: Option<String>,
    /// `true` when the daemon last responded successfully to a D-Bus call.
    pub daemon_available: bool,
    // SSH
    /// SSH keys returned by `SshListKeys`.
    pub ssh_keys: Vec<SshKeySummary>,
    /// SSH hosts returned by `SshListHosts`.
    pub hosts: Vec<HostSummary>,
    /// UUID string of the SSH key selected in the sidebar, if any.
    pub selected_ssh_key: Option<String>,
    /// UUID string of the SSH host selected in the sidebar, if any.
    pub selected_ssh_host: Option<String>,
    /// Which top-level section is currently active.
    #[allow(dead_code)]
    pub active_section: Section,
    /// Current SSH sidebar search/filter text.
    pub ssh_filter: String,
    /// Current VPN sidebar search/filter text.
    pub vpn_filter: String,
    /// SSH host reachability map: host UUID string → reachable.
    pub host_health: std::collections::HashMap<String, bool>,
    /// Conversation history for the Claude Console (multi-turn memory).
    pub console_messages: Vec<Value>,
    /// Notification history (newest first).
    pub notifications: Vec<Notification>,
}

/// A notification event stored in the notification center.
///
/// This is the source of truth for the bell popover: the UI renders rows
/// from these, rather than from the arguments that produced them. That
/// matters because the two used to be independent — clearing the popover
/// left the store untouched, and the 100-entry cap bounded the store
/// while the visible list grew without limit.
#[derive(Debug, Clone)]
pub struct Notification {
    /// When the event occurred.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Icon name for the event type.
    pub icon: &'static str,
    /// Short message describing the event.
    pub message: String,
}

impl AppState {
    /// Push a notification into the store (max 100, newest first).
    pub fn push_notification(&mut self, icon: &'static str, message: impl Into<String>) {
        self.notifications.insert(0, Notification {
            timestamp: chrono::Utc::now(),
            icon,
            message: message.into(),
        });
        self.notifications.truncate(NOTIFICATION_HISTORY_LIMIT);
    }

    /// Drop every stored notification.
    ///
    /// The popover's Clear button goes through here rather than emptying
    /// the `ListBox` directly, so the store and what's on screen can't
    /// disagree.
    pub fn clear_notifications(&mut self) {
        self.notifications.clear();
    }
}

/// How many notifications the centre keeps. Older ones fall off the end.
pub const NOTIFICATION_HISTORY_LIMIT: usize = 100;

#[cfg(test)]
mod notification_tests {
    use super::*;

    #[test]
    fn newest_notification_comes_first() {
        let mut s = AppState::default();
        s.push_notification("a-symbolic", "first");
        s.push_notification("b-symbolic", "second");
        assert_eq!(s.notifications[0].message, "second");
        assert_eq!(s.notifications[1].message, "first");
    }

    #[test]
    fn history_is_capped_and_drops_the_oldest() {
        // The cap has to bound what the popover renders, not just what
        // the store holds — those were different numbers before the UI
        // rendered from the store.
        let mut s = AppState::default();
        for i in 0..NOTIFICATION_HISTORY_LIMIT + 10 {
            s.push_notification("x-symbolic", format!("event {i}"));
        }
        assert_eq!(s.notifications.len(), NOTIFICATION_HISTORY_LIMIT);
        assert_eq!(s.notifications[0].message, "event 109");
        assert_eq!(
            s.notifications.last().unwrap().message,
            "event 10",
            "the oldest surviving entry should be the 11th pushed"
        );
    }

    #[test]
    fn clear_empties_the_store() {
        let mut s = AppState::default();
        s.push_notification("x-symbolic", "something happened");
        s.clear_notifications();
        assert!(s.notifications.is_empty());
    }

    #[test]
    fn icon_and_timestamp_are_retained_for_display() {
        // Both were captured and then never read; the popover now shows
        // them, so a regression here is visible rather than invisible.
        let before = chrono::Utc::now();
        let mut s = AppState::default();
        s.push_notification("network-vpn-symbolic", "VPN connected");
        let n = &s.notifications[0];
        assert_eq!(n.icon, "network-vpn-symbolic");
        assert!(n.timestamp >= before);
    }
}

// ---------------------------------------------------------------------------
// Inter-thread messages
// ---------------------------------------------------------------------------

/// Messages sent from tokio background tasks to the GTK main thread.
///
/// All variants are `Send`; GTK widget references live only on the main thread
/// and are updated by the `glib::timeout_add_local` drain loop.
#[allow(dead_code)]
pub enum AppMsg {
    /// Daemon responded; carry the refreshed profiles and current state.
    DaemonConnected {
        /// Refreshed profile list.
        profiles: Vec<ProfileSummary>,
        /// Current VPN state.
        state: VpnState,
    },
    /// Profile list refreshed; optionally show a toast (e.g. "Profile imported").
    /// Pass `toast: None` for silent refreshes (setting toggles, credential edits, etc.).
    ImportSucceeded {
        /// Profiles after the refresh (result of a fresh `ListProfiles` call).
        profiles: Vec<ProfileSummary>,
        /// If `Some`, show this string as an Adwaita toast.
        toast: Option<&'static str>,
    },
    /// VPN state changed (detected by the polling loop or an explicit call).
    StateUpdated(VpnState),
    /// Live tunnel statistics from the active VPN interface.
    StatsUpdated {
        /// Total bytes sent through the tunnel.
        bytes_sent: u64,
        /// Total bytes received through the tunnel.
        bytes_received: u64,
        /// Unix epoch timestamp (seconds) of the most recent WireGuard
        /// handshake, or `0` if not applicable / not yet occurred.
        last_handshake_secs: u64,
        /// VPN-assigned virtual IP (e.g. `10.134.2.3/24`).  Empty if not known.
        virtual_ip: String,
        /// Active routes through the tunnel (CIDR strings).  Empty if not reported.
        active_routes: Vec<String>,
        /// Seconds elapsed since the tunnel was established.
        uptime_secs: u64,
    },
    /// A profile was successfully deleted; `profile_id` is its UUID string.
    ProfileDeleted(String),
    /// The daemon could not be reached.
    DaemonUnavailable,
    /// A user-initiated operation failed; show this message as a toast.
    OperationFailed(String),
    /// A compliance scan finished. Carries the whole `Result` so the page can
    /// show a failed scan as its own state rather than a toast that vanishes.
    ComplianceRunFinished {
        /// Host the scan ran against.
        host_id: String,
        /// The run, or why it did not happen.
        result: Result<ComplianceRun, String>,
    },
    /// Check library and history fetched alongside a run — the run carries
    /// titles, but description, CIS reference and remediation live in the
    /// library, and history is a separate call.
    ComplianceContextLoaded {
        /// Host the context belongs to, so history rows know what to fetch.
        host_id: String,
        /// The library.
        library: Vec<CheckDefinition>,
        /// Run summaries for the host just scanned.
        history: Vec<RunSummary>,
    },
    /// Findings and counts for one scope, for the Security page.
    ///
    /// Both in one message rather than two: painting the counts before the rows
    /// would look like a stall, and a scope where the summary succeeded but the
    /// list failed is not a state worth rendering.
    FindingsLoaded {
        /// Scope they belong to.
        scope: String,
        /// The summary and the findings, or why neither arrived.
        result: Result<(supermgr_core::findings_store::StoreSummary, Vec<supermgr_core::findings_store::PersistedFinding>), String>,
    },
    /// A triage action finished. The page reloads the scope rather than patching
    /// the row, so what is on screen is what the daemon stored.
    FindingDispositionSet {
        /// Scope to reload.
        scope: String,
        /// Whether the write landed.
        result: Result<(), String>,
    },
    /// Outcome of a `TailscaleListNodes` call, for the Tailscale page.
    ///
    /// Carries the whole `Result` rather than routing the failure through
    /// `OperationFailed`: a tailnet that cannot be read is the page's own
    /// state, not a transient toast. "tailscaled is not running" needs to stay
    /// on screen until it stops being true.
    TailscaleNodesUpdated(Result<Vec<TailscaleNode>, String>),
    /// Copy text to clipboard and show a toast.
    CopyToClipboard(String),
    /// Show a success toast with the given message.
    ShowToast(String),
    /// The tray icon's "Open SuperManager" item was clicked.
    ShowWindow,
    /// The tray icon's "Quit" item was clicked.
    Quit,
    /// The daemon emitted an Entra ID device-code auth challenge.
    /// The GUI should show `user_code` and direct the user to `verification_url`.
    AuthChallenge {
        /// Short alphanumeric code the user must enter on the login page.
        user_code: String,
        /// URL to open in a browser (typically `https://microsoft.com/devicelogin`).
        verification_url: String,
    },
    // SSH messages
    /// The public key text for the currently selected SSH key was fetched.
    SshPublicKeyFetched(String),
    /// SSH key list was refreshed from the daemon.
    SshKeysRefreshed(Vec<SshKeySummary>),
    /// SSH host list was refreshed from the daemon.
    SshHostsRefreshed(Vec<HostSummary>),
    /// Right-click "Edit" on an SSH host row — select it and open the edit dialog.
    EditSshHost(String),
    /// Right-click "Edit" on a VPN profile row — select it and open the edit dialog.
    EditVpnProfile(String),
    /// Right-click "Push" on an SSH key row — open the push-key dialog for this key.
    PushSshKey(String),
    /// Progress update for an SSH operation (push, revoke, etc.).
    SshOperationProgress {
        /// Unique identifier for the operation.
        operation_id: String,
        /// Human-readable label of the target host.
        host_label: String,
        /// Progress message describing the current step.
        message: String,
    },
    /// SSH host health (reachability) changed.
    HostHealthChanged {
        /// UUID string of the host.
        host_id: String,
        /// Whether the host is reachable.
        reachable: bool,
    },
    /// The daemon's recorded SSH host-key fingerprint for a host was fetched.
    SshHostKeyFetched {
        /// UUID string of the host the fingerprint belongs to.
        host_id: String,
        /// SHA-256 fingerprint (lowercase hex), or `None` if the daemon has
        /// never connected to this host and so has nothing recorded.
        fingerprint: Option<String>,
    },
    // FortiGate messages
    /// FortiGate system status data fetched for a host.
    FortigateStatus {
        /// UUID string of the host.
        host_id: String,
        /// Parsed JSON response from `/api/v2/monitor/system/status`.
        data: Value,
    },

    /// FortiGate CIS compliance check results.
    FortigateCompliance {
        /// UUID string of the host.
        host_id: String,
        /// Parsed JSON compliance report.
        data: Value,
    },

    /// FortiGate API token fetched for display in the detail panel.
    FortigateApiTokenFetched {
        /// UUID string of the host.
        host_id: String,
        /// The API token string.
        token: String,
    },

    /// Dashboard device status data fetched for a local host (FortiGate/UniFi).
    DashboardDeviceStatus {
        /// UUID string of the host.
        host_id: String,
        /// Parsed JSON response (system status + resource + vpn tunnels).
        data: Value,
    },
    /// FortiGate config diff between two backups.
    FortigateConfigDiff {
        /// Hostname of the FortiGate.
        hostname: String,
        /// Unified diff text.
        diff: String,
    },
    /// Cloud-fetched devices from UI.com Site Manager API.
    DashboardCloudDevices {
        /// List of (device_id, device_name, hostname, data) tuples.
        devices: Vec<(String, String, String, Value)>,
    },
    /// FortiGate config backup completed.
    FortigateBackupDone {
        /// UUID string of the host.
        host_id: String,
        /// Filename where the backup was saved, or error message.
        result: Result<String, String>,
    },

    // Port forwarding messages
    /// Active port forwards list was refreshed (JSON array).
    PortForwardsRefreshed(String),

    // Console messages
    /// Append a message to the console chat (role = "assistant" or "tool").
    ConsoleResponse(String),
    /// Append a streaming text chunk to the console chat (assistant role).
    ConsoleStreamChunk(String),
    /// Claude is thinking / processing.
    ConsoleThinking(bool),

    // Provisioning messages
    /// Generated config text from Claude for the provisioning wizard.
    ProvisioningConfigGenerated(String),
    /// Config push to device completed (success or failure already toasted).
    ProvisioningPushDone,
}
