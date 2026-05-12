import SwiftUI
import ServiceManagement

/// General preferences pane — appearance + non-sensitive defaults.
///
/// Anything that wants a "Restart required" caveat *isn't* here; if a
/// setting's effect requires re-launching the app it goes into Security
/// or Backup so the affordance lives next to the consequence.
struct GeneralSettingsView: View {
    @State private var settings = AppSettings.shared
    /// `@ObservedObject` because SparkleUpdater is ObservableObject
    /// (NSObject-based for the SPUUpdaterDelegate conformance) — the
    /// `@Observable` macro can't apply to NSObject subclasses, so the
    /// view-binding path goes through `@ObservedObject` instead.
    @ObservedObject private var updater = SparkleUpdater.shared

    /// Local mirror of the SMAppService.mainApp status. We poll
    /// it on appear and after every toggle so the displayed
    /// state matches reality (the user may flip the login-item
    /// outside the app via System Settings).
    @State private var launchAtLoginEnabled = LaunchAtLogin.isEnabled
    @State private var launchAtLoginStatus = LaunchAtLogin.currentStatus
    @State private var launchAtLoginError: String?

    var body: some View {
        Form {
            Section("Startup") {
                Toggle("Launch SuperManager at login", isOn: Binding(
                    get: { launchAtLoginEnabled },
                    set: { newValue in
                        launchAtLoginError = nil
                        do {
                            try LaunchAtLogin.setEnabled(newValue)
                            launchAtLoginEnabled = LaunchAtLogin.isEnabled
                            launchAtLoginStatus = LaunchAtLogin.currentStatus
                        } catch {
                            launchAtLoginError = error.localizedDescription
                            // Re-read the truth — toggle revert if
                            // the OS rejected our request (e.g.
                            // user hasn't approved in System Settings).
                            launchAtLoginEnabled = LaunchAtLogin.isEnabled
                            launchAtLoginStatus = LaunchAtLogin.currentStatus
                        }
                    }
                ))
                .help("Re-open SuperManager automatically every time you log in. Uses macOS's modern login-items API (System Settings → General → Login Items shows the entry).")
                if launchAtLoginStatus == .requiresApproval {
                    Text("Awaiting approval — open System Settings → General → Login Items and enable SuperManager.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                } else if let err = launchAtLoginError {
                    Text(err)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
            Section("Appearance") {
                @Bindable var s = settings
                Toggle("Show menu bar item", isOn: $s.showMenuBarItem)
                    .help("Adds a terminal icon to the menu bar for quick access.")
            }

            Section("Updates") {
                // Beta-channel toggle. Bound directly to SparkleUpdater
                // so flipping it triggers `resetUpdateCycle()` and the
                // next check goes against appcast-beta.xml instead of
                // appcast.xml. Both feeds use the same EdDSA signature
                // so flipping back to stable doesn't require any
                // re-verification setup.
                Toggle("Include beta updates", isOn: $updater.includeBetaUpdates)
                    .help("Receive pre-release builds (1.0.1-beta.2, etc.) before they ship to the stable channel. Untick to roll back to stable at the next release.")
                if updater.includeBetaUpdates {
                    Text("Beta builds may have bugs the stable channel filters out. Suitable for the developer/operator's primary machine; not recommended for production-customer-facing deployments.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("Update feed: \(updater.feedURL)")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
                    .textSelection(.enabled)
            }

            Section("Notifications") {
                @Bindable var s = settings
                Toggle("VPN reconnected", isOn: $s.notifyVpnReconnected)
                    .help("Banner when always-on auto-reconnect successfully restores a tunnel.")
                Toggle("VPN reconnect failing", isOn: $s.notifyVpnReconnectFailing)
                    .help("Warn after a few failed reconnect attempts in a row.")
                Toggle("Exit node auto-reverted", isOn: $s.notifyExitNodeReverted)
                    .help("Tailscale exit-node selection rolled back because connectivity broke.")
                Toggle("Watchdog reset", isOn: $s.notifyWatchdogFired)
                    .help("Helper's connectivity watchdog tore down stuck routes / DNS.")
                Toggle("Compliance regression", isOn: $s.notifyComplianceDrift)
                    .help("Notify when a compliance scan reveals a score drop or new failures vs. the previous run.")
            }

            Section("Compliance") {
                @Bindable var s = settings
                Toggle("Auto-scan FortiGate hosts daily", isOn: $s.complianceAutoScanEnabled)
                    .help("On app launch, run a compliance scan for any FortiGate host whose last scan is over 24 hours old. Skips hosts without an API token.")
                Text("Custom checks: drop TOML files in `~/Library/Application Support/SuperManager/checks/` to extend the built-in CIS-FortiOS-7.4 baseline. The library reloads on every scan.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Section("Claude AI") {
                @Bindable var s = settings
                SecureField("Anthropic API key", text: $s.anthropicApiKey)
                    .help("Required for AI-augmented features like 'Explain config'. The key is stored locally in app preferences and only sent to api.anthropic.com.")
                if s.hasAnthropicKey {
                    Label("Key configured", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .font(.caption)
                } else {
                    Link(destination: URL(string: "https://console.anthropic.com/settings/keys")!) {
                        Label("Get an API key from console.anthropic.com", systemImage: "arrow.up.forward.app")
                    }
                    .font(.caption)
                }
                Text("Used to explain FortiOS / UniFi configurations and (in future) augment templates. No data is sent to Anthropic without an explicit user action.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Section("Polling") {
                @Bindable var s = settings
                // Picker with a few reasonable presets — user doesn't need
                // arbitrary integers, and "0" gets a real label.
                Picker("Host health check", selection: $s.hostHealthIntervalSeconds) {
                    Text("Off").tag(0)
                    Text("Every 10 seconds").tag(10)
                    Text("Every 30 seconds").tag(30)
                    Text("Every minute").tag(60)
                    Text("Every 5 minutes").tag(300)
                }
                .help("How often SuperManager pings each SSH host to update its health indicator.")
            }

            Section("About") {
                LabeledContent("Version") {
                    Text(Self.appVersion)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                LabeledContent("Build") {
                    Text(Self.buildNumber)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                LabeledContent("Bundle ID") {
                    Text(Bundle.main.bundleIdentifier ?? "—")
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
    }

    /// Read CFBundleShortVersionString; fall back to "—" so the UI never
    /// shows an unwrap-style placeholder.
    private static var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString")
            as? String ?? "—"
    }

    private static var buildNumber: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion")
            as? String ?? "—"
    }
}
