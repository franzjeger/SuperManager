import AppKit
import SwiftUI

/// Detail view for a single Tailscale peer. Renders identity,
/// addresses, traffic, and a couple of action buttons.
///
/// Actions:
///   • **Connect via SSH** — opens the user's default `ssh://`
///     handler against the peer's MagicDNS name. Mirrors the
///     existing SSH host-detail flow (`NSWorkspace.open(ssh URL)`)
///     so we don't have to teach the SSH machinery a new node type.
///     The user's username goes through the URL too — Tailscale
///     auth happens via Tailscale-SSH on supported peers, otherwise
///     the user's normal SSH config + keys take over.
///   • **Ping** — runs `tailscale ping <ip>` and surfaces the
///     latency. Useful for "is this peer routable from where I'm
///     sitting" without having to switch terminal windows.
///   • **Copy IP / DNS name** — most common chore when wiring an
///     external tool to a Tailscale peer.
struct TailscaleDetailView: View {
    @Environment(AppState.self) private var appState

    let peer: TailscalePeer
    let magicSuffix: String

    @State private var pingResult: String?
    @State private var pinging = false

    @State private var sshUsername: String = NSUserName()
    @State private var showingSshSheet = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Divider()
                actionRow
                Divider()
                detailGrid
            }
            .padding()
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: osIcon(peer.os))
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
                .frame(width: 48, height: 48)
            VStack(alignment: .leading, spacing: 4) {
                Text(peer.hostName)
                    .font(.title2.weight(.semibold))
                Text(peer.shortDnsName(stripping: magicSuffix))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    // The shared vocabulary, not a hand-rolled dot — a peer's
                    // state renders the same way a tunnel's does.
                    StatusPill(
                        status: peer.online ? .online : .offline,
                        label: peer.online ? "Online" : "Offline"
                    )
                    if peer.exitNode {
                        Badge(text: "Exit node", kind: .ikev2)
                    }
                }
            }
        }
    }

    // MARK: - Action row

    private var actionRow: some View {
        HStack(spacing: 8) {
            Button {
                showingSshSheet = true
            } label: {
                Label("Connect via SSH", systemImage: "terminal")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!peer.online)
            .help(peer.online ? "Open an SSH session in your default terminal."
                              : "Peer is offline.")

            Button {
                Task { await runPing() }
            } label: {
                if pinging {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Ping", systemImage: "wave.3.right")
                }
            }
            .disabled(pinging || !peer.online)

            // Quick-launch a browser window pointed at the peer's
            // MagicDNS name. Uses http (not https) because most
            // home services skip TLS on the LAN; the user's
            // browser will follow whatever redirects exist.
            Button {
                openInBrowser()
            } label: {
                Label("Open in browser", systemImage: "safari")
            }
            .disabled(!peer.online)
            .help(peer.online
                  ? "Open http://<peer>.<tailnet>.ts.net in your default browser."
                  : "Peer is offline.")

            // Exit-node toggle. Four-layer safety net protects
            // against bricking — see TailscaleHeaderView for
            // details.
            if peer.exitNodeOption {
                Button {
                    Task { await toggleExitNode() }
                } label: {
                    Label(isCurrentExitNode ? "Stop using as exit"
                                            : "Use as exit node",
                          systemImage: isCurrentExitNode
                              ? "arrow.uturn.down.circle"
                              : "arrow.up.forward.circle")
                }
                .disabled(!isCurrentExitNode && !peer.online)
                .help(isCurrentExitNode
                      ? "Stop routing all internet traffic through this peer."
                      : (peer.online
                         ? "Pre-flight + watchdog. Worst-case ~10s recovery if peer is broken."
                         : "Peer is offline."))
            }

            if let pingResult {
                Text(pingResult)
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Menu {
                Button("Copy MagicDNS name") {
                    let n = peer.shortDnsName(stripping: magicSuffix)
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(n, forType: .string)
                }
                if let ip = peer.primaryIP {
                    Button("Copy IPv4 address") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(ip, forType: .string)
                    }
                }
                if peer.tailscaleIPs.count > 1 {
                    Button("Copy IPv6 address") {
                        if let v6 = peer.tailscaleIPs.first(where: { $0.contains(":") }) {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(v6, forType: .string)
                        }
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .frame(width: 30)
            .accessibilityLabel("Peer actions")
        }
        .sheet(isPresented: $showingSshSheet) {
            sshSheet
        }
    }

    /// Compact sheet to pick a username before launching SSH. We
    /// pre-fill with the user's current Mac username; most home
    /// tailnets use the same login across devices, so it's right
    /// most of the time.
    private var sshSheet: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Connect to \(peer.hostName)")
                .font(.headline)
            Text("Opens an SSH session in your default terminal handler. The peer's MagicDNS name is used; your `~/.ssh/config` and keys apply normally.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Username", text: $sshUsername)
                .textFieldStyle(.roundedBorder)
            HStack {
                Button("Cancel") { showingSshSheet = false }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Connect") {
                    showingSshSheet = false
                    openSsh()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(sshUsername.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding()
        .frame(width: 380)
    }

    // MARK: - Detail grid

    private var detailGrid: some View {
        // The detail grammar: a Machine section in the shared definition-list
        // shape, same as VPN's Configuration and SSH's Connection. The
        // hand-rolled `row()` predated the primitives and had its own key
        // width (130 vs the shared 140), so this view's keys sat 10pt off
        // from every other section's.
        DetailColumns {
            DetailSection(title: "Machine") {
                DefinitionList(rows: machineRows)
            }
        }
    }

    private var machineRows: [DefinitionRow] {
        var rows: [DefinitionRow] = [
            DefinitionRow("DNS name", peer.dnsName.trimmingCharacters(in: CharacterSet(charactersIn: "."))),
            DefinitionRow("IPv4", peer.primaryIP ?? "—"),
        ]
        if let ipv6 = peer.tailscaleIPs.first(where: { $0.contains(":") }) {
            rows.append(DefinitionRow("IPv6", ipv6))
        }
        rows.append(DefinitionRow("Operating system", peer.os, mono: false))
        rows.append(DefinitionRow(
            "Sent / Received",
            "\(byteCount(peer.txBytes)) ↑ · \(byteCount(peer.rxBytes)) ↓",
            mono: false
        ))
        rows.append(DefinitionRow("Tailscale ID", peer.id, deemphasized: true))
        return rows
    }

    // MARK: - Actions

    /// Open the peer's MagicDNS name in the default browser.
    /// We use the FULL DNS name (including the magicSuffix) so
    /// resolution works whether or not the user's split-DNS is
    /// fully set up — a fully-qualified name always resolves
    /// via tailscaled's resolver if MagicDNS is on, and via
    /// /etc/resolver/<tailnet>.ts.net via our helper backstop.
    private func openInBrowser() {
        let host = peer.shortDnsName(stripping: magicSuffix)
        let fullHost = magicSuffix.isEmpty ? host : "\(host).\(magicSuffix)"
        // Default to plain http — home LAN services rarely have
        // valid TLS certs, and the browser handles the upgrade
        // if the server returns one.
        if let url = URL(string: "http://\(fullHost)/") {
            NSWorkspace.shared.open(url)
        }
    }

    private func openSsh() {
        let host = peer.shortDnsName(stripping: magicSuffix)
        // Fully-qualified MagicDNS name (with suffix) is the most
        // reliable target — it works whether or not the user's
        // resolver has Tailscale's split DNS plumbed.
        let fullHost = magicSuffix.isEmpty ? host : "\(host).\(magicSuffix)"
        let user = sshUsername.trimmingCharacters(in: .whitespaces)
        let urlString = "ssh://\(user)@\(fullHost)"
        if let url = URL(string: urlString) {
            NSWorkspace.shared.open(url)
        }
    }

    /// Whether this peer is currently the active exit node.
    /// `tailscale set --exit-node=<ip>` on macOS stores the
    /// resolved peer as `ExitNodeID`, leaving `ExitNodeIP`
    /// empty. Match by either field via the model's helper.
    private var isCurrentExitNode: Bool {
        guard let prefs = appState.tailscalePrefs else { return false }
        if !prefs.exitNodeIP.isEmpty,
           peer.tailscaleIPs.contains(prefs.exitNodeIP) {
            return true
        }
        if !prefs.exitNodeID.isEmpty, peer.id == prefs.exitNodeID {
            return true
        }
        return false
    }

    /// Flip exit-node state for this peer. Sending the empty string
    /// clears the exit-node selection; otherwise we set it to this
    /// peer's primary IP via the safety wrapper that auto-reverts
    /// if the new exit kills internet.
    private func toggleExitNode() async {
        let target: String
        if isCurrentExitNode {
            target = ""
        } else if let ip = peer.primaryIP {
            target = ip
        } else {
            return
        }
        await appState.setExitNodeWithSafety(target)
    }

    private func runPing() async {
        guard let ip = peer.primaryIP else { return }
        pinging = true
        defer { pinging = false }
        do {
            if let ms = try await TailscaleClient.ping(ip) {
                pingResult = String(format: "%.0f ms", ms)
            } else {
                pingResult = "Timeout"
            }
        } catch {
            pingResult = "Error"
        }
    }

    private func byteCount(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    private func osIcon(_ os: String) -> String {
        switch os.lowercased() {
        case "macos", "ios", "ipados":   return "apple.logo"
        case "linux":                    return "server.rack"
        case "windows":                  return "pc"
        case "android":                  return "smartphone"
        default:                          return "desktopcomputer"
        }
    }
}
