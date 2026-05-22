import SwiftUI

/// Root of the SwiftUI `Settings { ... }` scene.
///
/// macOS convention is one `TabView` with a fixed tab strip across the
/// top — `Cmd+,` opens this window from anywhere in the app, and
/// `windowResizability(.contentSize)` keeps it fitting its content like
/// every other Apple settings window.
///
/// Tabs map to the operational concerns the user might want to tweak:
///   • **General**     — appearance, menu bar, polling intervals
///   • **Security**    — master password, auto-lock
///   • **Backup**      — full-config export/import
///   • **Audit**       — viewer for the daemon's audit.log
///   • **Integrations** — third-party API keys
///   • **UniFi**       — standalone controller registry
///   • **Permissions** — macOS permissions + Homebrew tools state
///   • **Network**     — DNS fallbacks, device-type overrides
struct SettingsView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem { Label("General", systemImage: "gearshape") }

            SecuritySettingsView()
                .tabItem { Label("Security", systemImage: "lock") }

            BackupSettingsView()
                .tabItem { Label("Backup", systemImage: "tray.and.arrow.up") }

            AuditSettingsView()
                .tabItem { Label("Audit", systemImage: "doc.text.magnifyingglass") }

            IntegrationsSettingsView()
                .tabItem { Label("Integrations", systemImage: "puzzlepiece.extension") }

            UnifiControllersSettingsView()
                .tabItem {
                    Label("UniFi", systemImage: "antenna.radiowaves.left.and.right")
                }

            PermissionsSettingsView()
                .tabItem {
                    Label("Permissions", systemImage: "lock.shield")
                }

            NetworkSettingsView()
                .tabItem {
                    Label("Network", systemImage: "network")
                }
        }
        // Slight padding so each pane isn't flush against the tab strip.
        .padding(20)
        // Most settings panes are short — let the window shrink to fit
        // content rather than leaving lots of empty space.
        .frame(minWidth: 600, idealWidth: 680, minHeight: 480, idealHeight: 560)
    }
}
