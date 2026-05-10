import Foundation
import Observation

/// User-tweakable preferences. Persisted to UserDefaults (per-bundle id,
/// `~/Library/Preferences/com.sybr.supermanager.plist`). Anything
/// secret-shaped (master-password hashes, PSKs) lives in the Keychain
/// instead — see `Services/MasterPassword.swift` and `VPNKeychain`.
///
/// `@Observable` so SwiftUI views re-render on change. Mutations go
/// through this single object so we can persist + emit notifications
/// from one place if we later need a side-channel for the daemon.
@Observable
@MainActor
final class AppSettings {
    /// Singleton — settings are app-wide, and binding @Bindable to a
    /// shared instance is simpler than threading it through the env.
    static let shared = AppSettings()

    // MARK: - General

    /// Refresh interval for SSH host health probes, in seconds.
    /// 30s is the same default as the Linux GUI; 0 disables polling.
    var hostHealthIntervalSeconds: Int {
        didSet { defaults.set(hostHealthIntervalSeconds, forKey: Keys.hostHealthInterval) }
    }

    /// Whether the menu bar extra ("terminal" icon top-right) is shown.
    /// Off-by-default users can keep the app dock-only.
    var showMenuBarItem: Bool {
        didSet { defaults.set(showMenuBarItem, forKey: Keys.showMenuBarItem) }
    }

    // MARK: - Notifications
    //
    // All four flags default to true — first-run users see the
    // notifications and learn what they communicate. Power
    // users can carve out the noisy ones via the Settings pane.

    /// "VPN reconnected" banner after auto-reconnect succeeds.
    var notifyVpnReconnected: Bool {
        didSet { defaults.set(notifyVpnReconnected, forKey: Keys.notifyVpnReconnected) }
    }

    /// "VPN reconnect failing" banner when auto-reconnect has
    /// missed a few cycles in a row — the noisy one if your
    /// network is flaky, but also the most useful for triage.
    var notifyVpnReconnectFailing: Bool {
        didSet { defaults.set(notifyVpnReconnectFailing, forKey: Keys.notifyVpnReconnectFailing) }
    }

    /// "Exit node auto-reverted" banner when the safety timer
    /// rolls back an exit-node selection that broke connectivity.
    var notifyExitNodeReverted: Bool {
        didSet { defaults.set(notifyExitNodeReverted, forKey: Keys.notifyExitNodeReverted) }
    }

    /// "Connectivity watchdog reset" banner when the panic-reset
    /// path fired (helper torn down stuck routes / DNS).
    var notifyWatchdogFired: Bool {
        didSet { defaults.set(notifyWatchdogFired, forKey: Keys.notifyWatchdogFired) }
    }

    // MARK: - Compliance

    /// Auto-scan every FortiGate host on app launch if its last
    /// scan is over 24 hours old. Off-by-default — auto-running
    /// against production firewalls without user opt-in is the
    /// kind of side-effect we want explicit consent for.
    var complianceAutoScanEnabled: Bool {
        didSet { defaults.set(complianceAutoScanEnabled, forKey: Keys.complianceAutoScanEnabled) }
    }

    /// Surface a system notification when an automatic scan
    /// reveals a score drop or new failures vs. the previous run.
    /// Independent of `complianceAutoScanEnabled` — manual scans
    /// from the GUI also trigger the notification.
    var notifyComplianceDrift: Bool {
        didSet { defaults.set(notifyComplianceDrift, forKey: Keys.notifyComplianceDrift) }
    }

    // MARK: - Claude AI

    /// Anthropic API key for the "Explain config" / "Augment
    /// template" features. Stored in UserDefaults for v1 — a
    /// future revision moves this to the Keychain for parity
    /// with how we store FortiGate / UniFi credentials. The
    /// key never leaves the user's Mac except in the
    /// `x-api-key` header when calling the Anthropic API.
    var anthropicApiKey: String {
        didSet { defaults.set(anthropicApiKey, forKey: Keys.anthropicApiKey) }
    }

    /// Whether AI-augmented features are unlocked (i.e. there's
    /// a non-empty API key). Computed; the GUI uses this to
    /// hide / disable Claude-related menu items when the user
    /// hasn't configured a key yet.
    var hasAnthropicKey: Bool {
        !anthropicApiKey.trimmingCharacters(in: .whitespaces).isEmpty
    }

    // MARK: - Security

    /// Whether to lock the app behind a master password. When this flag
    /// flips true the user is prompted to set a password; flipping it
    /// false removes it. Actual password material lives in the keychain.
    var requireMasterPassword: Bool {
        didSet { defaults.set(requireMasterPassword, forKey: Keys.requireMasterPassword) }
    }

    /// Auto-lock the app after this many minutes of inactivity. 0 = never.
    /// The lock state is in-memory; it persists only as long as the
    /// process runs. Re-launching always asks for the password.
    var autoLockMinutes: Int {
        didSet { defaults.set(autoLockMinutes, forKey: Keys.autoLockMinutes) }
    }

    // MARK: - Backup

    /// Default location for new backup exports. UserDefaults stores the
    /// security-scoped bookmark blob so the app can re-resolve the
    /// directory across launches without re-prompting for permission.
    var defaultBackupBookmark: Data? {
        didSet { defaults.set(defaultBackupBookmark, forKey: Keys.defaultBackupBookmark) }
    }

    /// Whether to include secrets (passwords, PSKs, key passphrases) in
    /// backups. Default off — backups stay safer at the cost of needing
    /// the user to re-enter creds on restore.
    var backupIncludesSecrets: Bool {
        didSet { defaults.set(backupIncludesSecrets, forKey: Keys.backupIncludesSecrets) }
    }

    // MARK: -

    private let defaults: UserDefaults

    private enum Keys {
        static let hostHealthInterval        = "general.hostHealthIntervalSeconds"
        static let showMenuBarItem           = "general.showMenuBarItem"
        static let requireMasterPassword     = "security.requireMasterPassword"
        static let autoLockMinutes           = "security.autoLockMinutes"
        static let defaultBackupBookmark     = "backup.defaultBookmark"
        static let backupIncludesSecrets     = "backup.includesSecrets"
        static let notifyVpnReconnected      = "notify.vpnReconnected"
        static let notifyVpnReconnectFailing = "notify.vpnReconnectFailing"
        static let notifyExitNodeReverted    = "notify.exitNodeReverted"
        static let notifyWatchdogFired       = "notify.watchdogFired"
        static let complianceAutoScanEnabled = "compliance.autoScanEnabled"
        static let notifyComplianceDrift     = "notify.complianceDrift"
        static let anthropicApiKey           = "claude.anthropicApiKey"
    }

    private init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        // Load with sensible defaults for first run.
        self.hostHealthIntervalSeconds =
            (defaults.object(forKey: Keys.hostHealthInterval) as? Int) ?? 30
        self.showMenuBarItem =
            (defaults.object(forKey: Keys.showMenuBarItem) as? Bool) ?? true
        self.requireMasterPassword =
            (defaults.object(forKey: Keys.requireMasterPassword) as? Bool) ?? false
        self.autoLockMinutes =
            (defaults.object(forKey: Keys.autoLockMinutes) as? Int) ?? 15
        self.defaultBackupBookmark =
            defaults.data(forKey: Keys.defaultBackupBookmark)
        self.backupIncludesSecrets =
            (defaults.object(forKey: Keys.backupIncludesSecrets) as? Bool) ?? false
        self.notifyVpnReconnected =
            (defaults.object(forKey: Keys.notifyVpnReconnected) as? Bool) ?? true
        self.notifyVpnReconnectFailing =
            (defaults.object(forKey: Keys.notifyVpnReconnectFailing) as? Bool) ?? true
        self.notifyExitNodeReverted =
            (defaults.object(forKey: Keys.notifyExitNodeReverted) as? Bool) ?? true
        self.notifyWatchdogFired =
            (defaults.object(forKey: Keys.notifyWatchdogFired) as? Bool) ?? true
        self.complianceAutoScanEnabled =
            (defaults.object(forKey: Keys.complianceAutoScanEnabled) as? Bool) ?? false
        self.notifyComplianceDrift =
            (defaults.object(forKey: Keys.notifyComplianceDrift) as? Bool) ?? true
        self.anthropicApiKey =
            (defaults.string(forKey: Keys.anthropicApiKey)) ?? ""
    }
}
