import SwiftUI

/// Sidebar list (column 2) for the Tailscale section. Renders the
/// full peer list with online/offline dots + OS icons, and lets the
/// user select one to open `TailscaleDetailView`.
///
/// Auto-refreshes every 5 s while visible — Tailscale's `online`
/// field is updated by the coordinator at roughly that cadence, so
/// faster polling buys nothing.
struct TailscaleListView: View {
    @Environment(AppState.self) private var appState
    /// Local search text — filters the peer list by hostname,
    /// IP, or OS. Local rather than global because the user's
    /// "search peers" intent is distinct from "search VPN
    /// profiles" and we don't want a Cmd-F in one section to
    /// leak filters into another.
    @State private var peerSearch: String = ""

    /// Apply the search filter to a peer list. Empty text =
    /// pass-through.
    private func filter(_ peers: [TailscalePeer]) -> [TailscalePeer] {
        if peerSearch.isEmpty { return peers }
        let needle = peerSearch.lowercased()
        return peers.filter { peer in
            peer.hostName.lowercased().contains(needle)
                || peer.dnsName.lowercased().contains(needle)
                || peer.os.lowercased().contains(needle)
                || peer.tailscaleIPs.contains(where: { $0.contains(needle) })
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header strip is always visible — it's how the user
            // signs in / out and toggles the tunnel. Even when the
            // peer list is empty (NeedsLogin / Stopped / NoState),
            // we want the buttons reachable.
            TailscaleHeaderView()
            Divider()

            // Body switches between three states:
            //   • daemon-error: orange banner with diagnostics
            //   • have status: peer list (or "no peers yet")
            //   • loading: neutral placeholder
            //
            // We don't blank the list on `tailscaleError` if the
            // user is mid-login — the CLI returns "not running"
            // until the auth completes, which would flicker the UI
            // for ~30 seconds. Suppressing the error in that window
            // gives us a calmer flow.
            if appState.tailscaleIsBundled
                && (appState.tailscaledRunning == false
                    || appState.tailscaleError != nil)
                && appState.pendingTailscaleAuthURL == nil {
                // Daemon-missing case is distinct from a generic CLI
                // error because we have a clear remediation: click
                // Install in the header. Use a calmer empty state
                // (network icon, not warning triangle).
                emptyState(
                    message: (appState.tailscaledInstalled ?? false)
                        ? "The Tailscale daemon isn't running. Click Start daemon above."
                        : "Tailscale isn't installed yet. Click Install daemon above to set up the bundled tailscaled as a system service.",
                    icon: "network",
                    tint: .secondary)
            } else if let error = appState.tailscaleError,
               appState.pendingTailscaleAuthURL == nil {
                emptyState(message: error,
                           icon: "exclamationmark.triangle.fill",
                           tint: .orange)
            } else if let status = appState.tailscaleStatus {
                if status.backendState == "NeedsLogin" {
                    emptyState(message: "Sign in to view your Tailnet.",
                               icon: "person.crop.circle.badge.questionmark",
                               tint: .orange)
                } else {
                    let visiblePeers = filter(status.peers)
                    VStack(spacing: 0) {
                        TextField("Search peers…", text: $peerSearch)
                            .textFieldStyle(.roundedBorder)
                            .padding(8)
                        List(selection: bindingSelection) {
                            Section("This Mac") {
                                peerRow(status.selfNode, isSelf: true,
                                        magicSuffix: status.magicDNSSuffix ?? "")
                                    .tag(status.selfNode.id)
                            }
                            if !visiblePeers.isEmpty {
                                Section("Peers (\(visiblePeers.count))") {
                                    ForEach(visiblePeers) { peer in
                                        peerRow(peer, isSelf: false,
                                                magicSuffix: status.magicDNSSuffix ?? "")
                                            .tag(peer.id)
                                    }
                                }
                            } else if !peerSearch.isEmpty {
                                Section {
                                    Text("No peers match ‘\(peerSearch)’.")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .listStyle(.sidebar)
                    }
                }
            } else {
                emptyState(message: "Loading Tailnet…",
                           icon: "network",
                           tint: .secondary)
            }
        }
        .task { await pollLoop() }
        .onChange(of: appState.tailscaleStatus?.backendState) { _, newState in
            // The login sheet auto-dismisses once the daemon flips
            // to Running — no need for the user to click Cancel
            // after a successful browser auth.
            if newState == "Running" {
                appState.pendingTailscaleAuthURL = nil
            }
        }
    }

    /// 5-second polling loop, gated to this view's lifetime via
    /// `.task`. SwiftUI cancels the task when the view goes off
    /// screen, so we don't burn CPU re-running the CLI when the
    /// user is in the SSH or VPN tab.
    private func pollLoop() async {
        await appState.refreshTailscale()
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(5))
            await appState.refreshTailscale()
        }
    }

    /// Tap-target selection bound back to AppState.
    private var bindingSelection: Binding<String?> {
        Binding(
            get: { appState.selectedTailscalePeerId },
            set: { appState.selectedTailscalePeerId = $0 }
        )
    }

    private func peerRow(_ peer: TailscalePeer,
                         isSelf: Bool,
                         magicSuffix: String) -> some View {
        HStack(spacing: 8) {
            Circle()
                .fill(peer.online ? .green : .gray.opacity(0.4))
                .frame(width: 8, height: 8)
            Image(systemName: osIcon(peer.os))
                .frame(width: 18)
                .foregroundStyle(.secondary)
                .accessibilityLabel("\(peer.os) peer")
            VStack(alignment: .leading, spacing: 2) {
                Text(peer.hostName)
                    .fontWeight(isSelf ? .semibold : .regular)
                HStack(spacing: 6) {
                    if let ip = peer.primaryIP {
                        Text(ip)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.tertiary)
                    }
                    // Last-seen pill for offline peers — answers
                    // "is this 5 minutes stale or 2 weeks gone?"
                    // without drilling into peer detail. Online
                    // peers don't need it; the green dot already
                    // means "right now".
                    if !peer.online, let seen = peer.lastSeen {
                        Text("·")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                        Text(seen, format: .relative(presentation: .numeric))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            if peer.exitNode {
                Spacer()
                Image(systemName: "arrow.up.forward.circle.fill")
                    .foregroundStyle(.blue)
                    .help("Currently routing through this peer as exit node.")
            }
        }
        .padding(.vertical, 2)
    }

    /// Map Tailscale's OS string to an SF Symbol. Anything we don't
    /// recognise falls back to a generic computer icon.
    private func osIcon(_ os: String) -> String {
        switch os.lowercased() {
        case "macos", "ios", "ipados":   return "apple.logo"
        case "linux":                    return "server.rack"
        case "windows":                  return "pc"
        case "android":                  return "smartphone"
        default:                          return "desktopcomputer"
        }
    }

    private func emptyState(message: String,
                            icon: String,
                            tint: Color) -> some View {
        VStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 32))
                .foregroundStyle(tint)
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            if !TailscaleClient.isInstalled {
                Link("Install Tailscale",
                     destination: URL(string: "https://tailscale.com/download/mac")!)
                    .controlSize(.small)
                    .padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
