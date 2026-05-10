import AppKit
import SwiftUI

/// Header strip that sits above the Tailnet peer list. Shows the
/// current connection/auth state of the local Tailscale daemon and
/// hosts the only buttons that actually mutate it (login, logout,
/// up/down).
///
/// The peer list below is purely diagnostic — *this* view is the
/// reason we built the integration. Moving Tailscale account
/// administration into SuperManager removes the last reason a user
/// has to keep `Tailscale.app` installed.
///
/// State machine driven entirely by `BackendState`:
///   • `NoState`    — daemon hasn't reported yet. Just show a spinner.
///   • `NeedsLogin` — auth required. Show **Login** button.
///   • `Stopped`    — authed, tunnel down. Show **Connect** + **Logout**.
///   • `Starting`   — transient. Show spinner; treat as `Running` for
///                    button affordances (so user can hit Disconnect
///                    if they regret it).
///   • `Running`    — happy path. Show **Disconnect** + **Logout**.
struct TailscaleHeaderView: View {
    @Environment(AppState.self) private var appState

    /// Bool flips set during async actions to grey out buttons while
    /// the CLI is mid-call. Without these, double-clicking Login
    /// fires `tailscale up` twice and the second invocation hangs
    /// waiting for the first one's auth.
    @State private var working = false
    /// Drives the settings sheet — toggled from the gear button in
    /// the ellipsis menu.
    @State private var showingSettings = false
    /// Drives the helper-log viewer sheet.
    @State private var showingHelperLog = false
    /// Confirmation alert for exit-node selection — exit-noding on
    /// macOS open-source tailscaled can break internet if the peer
    /// goes unreachable. We make the user confirm before any non-empty
    /// exit-node setting goes through.
    @State private var pendingExitNodeIP: String?
    @State private var pendingExitNodeName: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .center, spacing: 10) {
                statePill
                identityBlock
                Spacer()
                actionButtons
            }
            if let err = appState.tailscaleActionError {
                Text(err)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(2)
                    .truncationMode(.middle)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(.bar)
        .sheet(item: pendingAuthBinding) { wrapper in
            authPendingSheet(url: wrapper.url)
        }
        .sheet(isPresented: $showingSettings) {
            TailscaleSettingsView()
        }
        .sheet(isPresented: $showingHelperLog) {
            HelperLogView()
        }
        // Exit-node confirmation. Exit-noding rewrites the system
        // default route through the peer's TUN — if the peer is
        // unreachable, internet dies until panic-reset. The user
        // ALWAYS confirms before this happens.
        .alert(
            "Route all traffic through \(pendingExitNodeName ?? "")?",
            isPresented: Binding(
                get: { pendingExitNodeIP != nil },
                set: { if !$0 { pendingExitNodeIP = nil; pendingExitNodeName = nil } }
            )
        ) {
            Button("Use exit node") {
                if let ip = pendingExitNodeIP {
                    runAction { await appState.setExitNodeWithSafety(ip) }
                }
                pendingExitNodeIP = nil
                pendingExitNodeName = nil
            }
            Button("Cancel", role: .cancel) {
                pendingExitNodeIP = nil
                pendingExitNodeName = nil
            }
        } message: {
            Text("All internet traffic will route through this peer. If it becomes unreachable, your Mac may temporarily lose internet — SuperManager will auto-revert if that happens, but the recovery takes a few seconds.")
        }
    }

    // MARK: - Sub-views

    /// Coloured pill showing BackendState. Tailscale's strings are
    /// already user-readable so we render them verbatim instead of
    /// translating into our own vocabulary — keeps us aligned with
    /// what the Tailscale docs / admin console say.
    private var statePill: some View {
        let state = appState.tailscaleStatus?.backendState ?? "NoState"
        let (label, color) = pillStyle(for: state)
        return Text(label)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }

    private var identityBlock: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(tailnetLabel)
                .font(.callout.weight(.semibold))
                .lineLimit(1)
                .truncationMode(.middle)
            Text(deviceLabel)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }

    /// Right-side buttons. The exact set depends on whether the
    /// daemon is even installed/running, then on BackendState.
    @ViewBuilder
    private var actionButtons: some View {
        let state = appState.tailscaleStatus?.backendState ?? "NoState"
        let daemonRunning = appState.tailscaledRunning ?? false
        let daemonInstalled = appState.tailscaledInstalled ?? false
        if working {
            ProgressView().controlSize(.small)
        } else if !daemonRunning && appState.tailscaleIsBundled {
            // Daemon missing or stopped. We bundled tailscaled, so
            // we can install/start it ourselves rather than tossing
            // the user out to a Terminal.
            Button {
                runAction { await appState.installTailscaled() }
            } label: {
                Label(daemonInstalled ? "Start daemon" : "Install daemon",
                      systemImage: "arrow.down.app")
            }
            .buttonStyle(.borderedProminent)
            .help(daemonInstalled
                  ? "Restart the bundled tailscaled LaunchDaemon."
                  : "Install the bundled tailscaled as a system LaunchDaemon. Requires admin privileges.")
            logoutMenu
        } else {
            switch state {
            case "NeedsLogin":
                Button {
                    runAction { await appState.tailscaleLogin() }
                } label: {
                    Label("Sign in", systemImage: "person.crop.circle.badge.checkmark")
                }
                .buttonStyle(.borderedProminent)
                .help("Open the Tailscale login page in your browser to authenticate this Mac.")
            case "Stopped":
                Button {
                    runAction { await appState.tailscaleUp() }
                } label: {
                    Label("Connect", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                logoutMenu
            case "Running", "Starting":
                Button {
                    runAction { await appState.tailscaleDown() }
                } label: {
                    Label("Disconnect", systemImage: "stop.fill")
                }
                .buttonStyle(.bordered)
                logoutMenu
            default:
                // NoState / unknown — no buttons. The polling loop
                // will resolve this within a couple of seconds; if
                // it doesn't, the empty-state in TailscaleListView
                // takes over.
                EmptyView()
            }
        }
    }

    /// "More" menu hosting the destructive Logout action so it's not
    /// front-and-centre. Logging out wipes the node key on the
    /// coordinator — easy to confuse with Disconnect, which is
    /// non-destructive.
    ///
    /// Also hosts the per-node Settings entry. We could plant the
    /// gear icon next to the action buttons but the menu keeps the
    /// header narrow and groups all the "non-obvious" controls in
    /// one place.
    private var logoutMenu: some View {
        Menu {
            Button {
                showingSettings = true
            } label: {
                Label("Settings…", systemImage: "gear")
            }
            exitNodeSubmenu
            Divider()
            Button {
                Task { await appState.refreshTailscale() }
            } label: {
                Label("Refresh status", systemImage: "arrow.clockwise")
            }
            Button {
                Task { await appState.resetDNSToFallbacks() }
            } label: {
                Label("Reset DNS", systemImage: "questionmark.circle.fill")
            }
            .help("Force-write the system resolver to your fallback list. Use when DNS gets stuck after Tailscale state changes.")

            Button {
                showingHelperLog = true
            } label: {
                Label("Helper Log…", systemImage: "doc.text.magnifyingglass")
            }
            .help("Live-tail of helper diagnostics — useful when something doesn't behave.")

            Button {
                Task { _ = await SupportBundle.saveInteractive(appState: appState) }
            } label: {
                Label("Save Support Bundle…", systemImage: "doc.zipper")
            }
            .help("Tar.gz of helper log + tailscaled log + state snapshots. Excludes private keys + stored credentials.")

            Divider()

            // Always-on for Tailscale = LaunchDaemon-installed
            // tailscaled is already a system service that auto-
            // starts at boot and reconnects automatically. The
            // toggle here exposes whether the daemon is set up
            // that way, since "uninstall daemon" is the only way
            // to opt out. If installed: greyed-out informative
            // checkmark. If not: prompt to install.
            if (appState.tailscaledInstalled ?? false) {
                Label("Always on (LaunchDaemon)", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .help("tailscaled runs as a system LaunchDaemon — auto-starts at boot, auto-reconnects after sleep.")
            } else if appState.tailscaleIsBundled {
                Button {
                    runAction { await appState.installTailscaled() }
                } label: {
                    Label("Enable always-on", systemImage: "play.circle")
                }
                .help("Install tailscaled as a system LaunchDaemon for auto-start at boot.")
            }
            // Always-available rescue button. Even when status
            // RPCs are erroring, this triggers the helper to clear
            // exit-node + DHCP-renew the active interface — the
            // exact recovery path users have been doing manually
            // by cycling WiFi.
            Button {
                runAction { await appState.panicResetTailscale() }
            } label: {
                Label("Reset routing (emergency)", systemImage: "bolt.shield")
            }
            .help("Clear exit-node + accept-routes and renew DHCP. Use when an exit-node selection has broken your internet.")
            Divider()
            Button(role: .destructive) {
                runAction { await appState.tailscaleLogout() }
            } label: {
                Label("Sign out…", systemImage: "person.crop.circle.badge.xmark")
            }
            // Uninstall sits below the destructive Sign-out
            // because the consequence is bigger (no tailnet at all
            // until reinstall). State is preserved on disk so the
            // user can flip back without losing their identity.
            if (appState.tailscaledInstalled ?? false) {
                Button(role: .destructive) {
                    runAction { await appState.uninstallTailscaled() }
                } label: {
                    Label("Uninstall daemon…", systemImage: "trash")
                }
            }
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .frame(width: 30)
        .accessibilityLabel("Tailscale actions")
    }

    /// Quick exit-node selector inline in the header menu. Saves a
    /// round-trip through the settings sheet for the most common
    /// "use this peer as my exit" workflow. The sheet still has the
    /// same picker plus the LAN-access toggle.
    @ViewBuilder
    private var exitNodeSubmenu: some View {
        // Exit-node enabled. Four-layer safety:
        //
        //   1. Pre-flight test (`tailscale_test_exit_reachability`):
        //      installs a single /32 host route via utun, probes
        //      a public IP, cleans up. Aborts BEFORE installing
        //      any destructive routes if the chosen peer doesn't
        //      actually forward.
        //
        //   2. Auto-revert: if the post-install internet probe
        //      fails 2s after the split-default install, AppState
        //      runs panic_reset (removes routes, clears pref,
        //      DHCP-renews).
        //
        //   3. Route guardian (helper background thread):
        //      polls default route every 500ms, restores from
        //      snapshot within ~1s if tailscaled's reconfig
        //      strips it. Verified in isolation.
        //
        //   4. Connectivity watchdog (helper background thread):
        //      TCP-probes 1.1.1.1:443 every 2s. After 4s of
        //      sustained failure, force-restores the route.
        //      After 6s, escalates to full panic_reset. Acts as
        //      dead-man switch for any failure mode the other
        //      three layers miss.
        //
        // Worst-case bricking window: ~10s before watchdog
        // panic_reset auto-restores baseline. No user action
        // needed.
        let peers = appState.tailscaleStatus?.peers ?? []
        let exits = peers.filter { $0.exitNodeOption && $0.online }
        // Active exit-node resolved via either ExitNodeIP or
        // ExitNodeID (daemon stores as ID after `tailscale set
        // --exit-node=<ip>`).
        let active = appState.tailscalePrefs?.currentExitNode(in: peers)
        Menu {
            Button {
                Task { await appState.setExitNodeWithSafety("") }
            } label: {
                if active == nil { Image(systemName: "checkmark") }
                Text("None")
            }
            if !exits.isEmpty {
                Divider()
                ForEach(exits) { peer in
                    Button {
                        if let ip = peer.primaryIP {
                            Task { await appState.setExitNodeWithSafety(ip) }
                        }
                    } label: {
                        if active?.id == peer.id {
                            Image(systemName: "checkmark")
                        }
                        Text(peer.hostName)
                    }
                }
            }
        } label: {
            Label(exitNodeMenuLabel, systemImage: "arrow.up.forward.circle")
        }
        .disabled(exits.isEmpty)
        .help(exits.isEmpty
              ? "No online peer in your tailnet is advertising as an exit node."
              : "Pre-flight + auto-revert + route guardian + connectivity watchdog. Worst-case ~10s before auto-recovery.")
    }

    private var exitNodeMenuLabel: String {
        let peers = appState.tailscaleStatus?.peers ?? []
        if let active = appState.tailscalePrefs?.currentExitNode(in: peers) {
            return "Exit node: \(active.hostName)"
        }
        return "Exit node: None"
    }

    /// Modal shown while `tailscale up --force-reauth` is waiting for
    /// the user to complete the browser flow. We open the URL on
    /// demand (the OS already opened it once when auth started) so
    /// the user has a way back if they accidentally closed the tab.
    private func authPendingSheet(url: URL) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "person.crop.circle.badge.checkmark")
                    .font(.title2)
                    .foregroundStyle(.blue)
                Text("Sign in to Tailscale")
                    .font(.headline)
            }
            Text("A browser window should have opened to complete authentication. Once you've finished signing in, this dialog will dismiss automatically.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            // Surface the URL so the user can copy or re-open it. The
            // string is long so we wrap it in a scrolling text view.
            HStack(spacing: 6) {
                Text(url.absoluteString)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(url.absoluteString, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .accessibilityLabel("Copy auth URL")
                .buttonStyle(.borderless)
                .help("Copy auth URL")
            }
            .padding(8)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))

            HStack {
                Button("Open browser again") {
                    NSWorkspace.shared.open(url)
                }
                Spacer()
                Button("Cancel") {
                    appState.pendingTailscaleAuthURL = nil
                }
                .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    // MARK: - Helpers

    /// Two-way binding so SwiftUI's `.sheet(item:)` can dismiss the
    /// modal by writing nil back to AppState.
    private var pendingAuthBinding: Binding<IdentifiableURL?> {
        Binding(
            get: {
                appState.pendingTailscaleAuthURL.map { IdentifiableURL(url: $0) }
            },
            set: { appState.pendingTailscaleAuthURL = $0?.url }
        )
    }

    /// Headline string. Prefers the human-readable tailnet name, falls
    /// back to the MagicDNS suffix, then to a generic placeholder.
    private var tailnetLabel: String {
        if let name = appState.tailscaleStatus?.currentTailnetName, !name.isEmpty {
            return name
        }
        if let suffix = appState.tailscaleStatus?.magicDNSSuffix, !suffix.isEmpty {
            return suffix
        }
        return "Tailscale"
    }

    /// Sub-headline showing this Mac's name + first IP. Helps
    /// distinguish "I'm logged in but the daemon is on a different
    /// account than I expected" cases.
    private var deviceLabel: String {
        guard let s = appState.tailscaleStatus else {
            return "Not connected"
        }
        let host = s.selfNode.hostName
        let ip = s.selfNode.primaryIP ?? s.tailscaleIPs.first ?? "—"
        return "\(host) · \(ip)"
    }

    private func pillStyle(for state: String) -> (String, Color) {
        switch state {
        case "Running":    return ("Connected", .green)
        case "Starting":   return ("Starting…", .blue)
        case "Stopped":    return ("Disconnected", .gray)
        case "NeedsLogin": return ("Sign-in required", .orange)
        case "NoState":    return ("Loading…", .secondary)
        default:           return (state, .secondary)
        }
    }

    /// Wrap async work so we can flip the `working` flag cleanly
    /// without leaking it on early-return paths.
    private func runAction(_ block: @escaping () async -> Void) {
        Task {
            working = true
            defer { working = false }
            await block()
        }
    }

}

/// `Sheet(item:)` requires `Identifiable`. URLs aren't, so we wrap.
private struct IdentifiableURL: Identifiable {
    let url: URL
    var id: String { url.absoluteString }
}

private extension Color {
    /// `secondary` masquerading as a `Color` so the pill switch can
    /// return a uniform tuple. SwiftUI exposes `.secondary` as a
    /// HierarchicalShapeStyle by default, not a Color.
    static var secondary: Color { Color(nsColor: .secondaryLabelColor) }
}
