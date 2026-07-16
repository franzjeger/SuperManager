import SwiftUI

/// The toolbar's connection status: one pill per system, not one string for all
/// of them.
///
/// The old single pill merged daemon health, Tailscale and VPN into one label
/// that changed shape with state — "Connected" when nothing was up, "Tailscale"
/// when the tailnet was, "Tailscale · 2 VPNs" when both. You could never tell
/// at a glance what it was reporting, which was the review's complaint. Now
/// each system owns a pill, always in the same place, always saying the same
/// kind of thing.
struct ToolbarStatusPills: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        // One HStack, not two bare views: a ToolbarItem hosts a SINGLE view, so
        // returning a two-element TupleView silently renders only the first —
        // the VPN pill just wasn't there.
        HStack(spacing: 8) {
            if !appState.daemonAvailable {
                // Both readings come through the daemon, so with it unreachable
                // two pills would just be two lies. One honest pill instead.
                StatusPill(status: .error, label: "Daemon offline")
                    .help("Can't reach the SuperManager daemon at its socket. Try Cmd-R to refresh.")
            } else {
                TailscaleStatusPill()
                VpnStatusPill()
            }
        }
    }
}

// MARK: - Tailscale

struct TailscaleStatusPill: View {
    @Environment(AppState.self) private var appState
    @State private var showingPopover = false
    @State private var working = false

    private var backendState: String {
        appState.tailscaleStatus?.backendState ?? "NoState"
    }
    private var isUp: Bool { backendState == "Running" }

    private var style: StatusStyle {
        switch backendState {
        case "Running":    return .online
        case "Starting":   return .pending
        case "Stopped":    return .offline
        case "NeedsLogin": return .warn
        default:           return .unknown
        }
    }

    var body: some View {
        Button {
            showingPopover.toggle()
        } label: {
            HStack(spacing: 3) {
                StatusPill(status: style, label: "Tailscale")
                Image(systemName: "chevron.down")
                    .font(.system(size: 7, weight: .bold))
                    .foregroundStyle(.tertiary)
            }
        }
        .buttonStyle(.plain)
        .help("Tailnet status. Click for peers and connect/disconnect.")
        .popover(isPresented: $showingPopover, arrowEdge: .bottom) {
            popoverBody.frame(width: 264)
        }
    }

    private var popoverBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "globe").foregroundStyle(.secondary)
                Text(tailnetLabel)
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.tail)
                Spacer(minLength: 6)
                // Never "Down" on a reading we don't have — an un-polled tailnet
                // is unknown, not offline. Same rule the VPN dot follows.
                StatusPill(status: style, label: popoverStateLabel)
            }
            Divider()
            VStack(alignment: .leading, spacing: 2) {
                Text("This Mac").font(.system(size: 11)).foregroundStyle(.secondary)
                Text(deviceLabel)
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Text(peerSummary)
                .font(.system(size: 11))
                .foregroundStyle(.tertiary)
            // An exit node silently rewrites the default route — if one is
            // active the operator needs to know without opening the tab.
            if appState.tailscalePrefs?.hasExitNode == true {
                Label("Exit node active", systemImage: "arrow.triangle.branch")
                    .font(.system(size: 11))
                    .foregroundStyle(.orange)
            }
            Divider()
            Button {
                working = true
                Task {
                    defer { working = false }
                    if isUp { await appState.tailscaleDown() } else { await appState.tailscaleUp() }
                }
                showingPopover = false
            } label: {
                if working {
                    ProgressView().controlSize(.small).frame(maxWidth: .infinity)
                } else {
                    Text(isUp ? "Disconnect" : "Connect").frame(maxWidth: .infinity)
                }
            }
            .controlSize(.small)
            .disabled(working)
        }
        .padding(12)
    }

    /// Tailscale's own wording, kept short for the pill.
    private var popoverStateLabel: String {
        switch backendState {
        case "Running":    return "Up"
        case "Starting":   return "Starting"
        case "Stopped":    return "Down"
        case "NeedsLogin": return "Sign in"
        default:           return "Unknown"
        }
    }

    private var tailnetLabel: String {
        if let n = appState.tailscaleStatus?.currentTailnetName, !n.isEmpty { return n }
        if let s = appState.tailscaleStatus?.magicDNSSuffix, !s.isEmpty { return s }
        return "Tailscale"
    }

    private var deviceLabel: String {
        // No status yet is not the same as not connected.
        guard let s = appState.tailscaleStatus else { return "Not polled yet" }
        let ip = s.selfNode.primaryIP ?? s.tailscaleIPs.first ?? "—"
        return "\(s.selfNode.hostName) · \(ip)"
    }

    /// Only meaningful while the tailnet is up: with the daemon stopped every
    /// peer reads offline, and "0 of 8 online" would claim we measured them.
    private var peerSummary: String {
        guard let s = appState.tailscaleStatus else { return "Waiting for tailnet status…" }
        guard isUp else { return "Tailnet offline" }
        return "\(s.peers.filter(\.online).count) of \(s.peers.count) peers online"
    }
}

// MARK: - VPN

struct VpnStatusPill: View {
    @Environment(AppState.self) private var appState
    @State private var showingPopover = false

    /// Tunnels worth showing: up, or on their way up.
    private var activeProfiles: [VpnProfileSummary] {
        appState.vpnProfiles.filter {
            let s = appState.vpnConnectionStates[$0.id]
            return s == "connected" || s == "connecting" || s == "reconnecting"
        }
    }
    private var onlineCount: Int {
        appState.vpnConnectionStates.values.filter { $0 == "connected" }.count
    }
    private var connectingCount: Int {
        appState.vpnConnectionStates.values.filter { $0 == "connecting" }.count
    }
    /// A tunnel that was up and can no longer be confirmed outranks a healthy
    /// one in the pill — that's the state you need to notice.
    private var problemCount: Int {
        appState.vpnConnectionStates.values.filter { $0 == "problem" }.count
    }

    private var style: StatusStyle {
        if problemCount > 0 { return .error }
        if connectingCount > 0 { return .pending }
        if onlineCount > 0 { return .online }
        return .offline
    }

    var body: some View {
        Button {
            showingPopover.toggle()
        } label: {
            HStack(spacing: 3) {
                StatusPill(status: style, label: "VPN")
                if onlineCount > 0 {
                    Text("\(onlineCount)")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(style.color, in: Capsule())
                }
                Image(systemName: "chevron.down")
                    .font(.system(size: 7, weight: .bold))
                    .foregroundStyle(.tertiary)
            }
        }
        .buttonStyle(.plain)
        .help("Active VPN tunnels. Click to disconnect one without leaving this tab.")
        .popover(isPresented: $showingPopover, arrowEdge: .bottom) {
            popoverBody.frame(width: 300)
        }
    }

    private var popoverBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "lock.shield").foregroundStyle(.secondary)
                Text("VPN tunnels").font(.system(size: 13, weight: .semibold))
                Spacer(minLength: 6)
                StatusPill(status: style, label: "\(onlineCount) active")
            }
            Divider()
            if activeProfiles.isEmpty {
                Text("No active tunnels. Connect one from the VPN tab.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(activeProfiles) { p in
                    row(for: p)
                }
            }
        }
        .padding(12)
    }

    private func row(for p: VpnProfileSummary) -> some View {
        let state = appState.vpnConnectionStates[p.id]
        return HStack(spacing: 8) {
            StatusDot(status: .vpn(state))
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 5) {
                    // Clicking the name jumps to the profile — the popover is a
                    // shortcut into the tab, not a dead end.
                    Button {
                        appState.selectedSection = .vpn
                        appState.selectedProfileId = p.id
                        showingPopover = false
                    } label: {
                        Text(p.name)
                            .font(.system(size: 12, weight: .medium))
                            .lineLimit(1)
                    }
                    .buttonStyle(.plain)
                    Badge(text: backendLabel(p.backend), kind: .backend(p.backend))
                }
                if let host = p.host, !host.isEmpty {
                    Text(host)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 4)
            if state == "connected" {
                Button("Disconnect") {
                    Task { await appState.forceDisconnect(profileId: p.id) }
                }
                .controlSize(.mini)
            } else {
                Text(state == "problem" ? "Problem" : "Connecting")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// The daemon's display strings are long ("FortiGate (IPsec/IKEv2)"); the
    /// badge needs the short form.
    private func backendLabel(_ raw: String) -> String {
        let s = raw.lowercased()
        if s.contains("azure") { return "Azure" }
        if s.contains("wire") { return "WireGuard" }
        if s.contains("open") { return "OpenVPN" }
        if s.contains("forti") || s.contains("ikev2") || s.contains("ipsec") { return "IKEv2" }
        return raw
    }
}
