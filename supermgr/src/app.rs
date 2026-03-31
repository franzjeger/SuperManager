//! Application state and inter-thread message types.
#![allow(missing_docs)]

use serde_json::Value;
use supermgr_core::{
    vpn::profile::ProfileSummary,
    vpn::state::VpnState,
    ssh::key::SshKeySummary,
    ssh::host::SshHostSummary,
};

/// Which top-level section is active in the UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
    pub ssh_hosts: Vec<SshHostSummary>,
    /// UUID string of the SSH key selected in the sidebar, if any.
    pub selected_ssh_key: Option<String>,
    /// UUID string of the SSH host selected in the sidebar, if any.
    pub selected_ssh_host: Option<String>,
    /// Which top-level section is currently active.
    pub active_section: Section,
    /// Current SSH sidebar search/filter text.
    pub ssh_filter: String,
    /// Current VPN sidebar search/filter text.
    pub vpn_filter: String,
    /// SSH host reachability map: host UUID string → reachable.
    pub host_health: std::collections::HashMap<String, bool>,
    /// Conversation history for the Claude Console (multi-turn memory).
    pub console_messages: Vec<Value>,
}

// ---------------------------------------------------------------------------
// Inter-thread messages
// ---------------------------------------------------------------------------

/// Messages sent from tokio background tasks to the GTK main thread.
///
/// All variants are `Send`; GTK widget references live only on the main thread
/// and are updated by the `glib::timeout_add_local` drain loop.
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
    SshHostsRefreshed(Vec<SshHostSummary>),
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

    /// Dashboard device status data fetched for a FortiGate host.
    DashboardDeviceStatus {
        /// UUID string of the host.
        host_id: String,
        /// Parsed JSON response (system status + resource + vpn tunnels).
        data: Value,
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
