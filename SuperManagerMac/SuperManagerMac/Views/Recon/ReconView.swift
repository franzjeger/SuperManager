import SwiftUI

/// First-class launcher for the toolkit's white/gray-hat
/// capabilities. Built so a fresh user can land here and see
/// every tool without hunting through menus or sub-panels.
///
/// Each capability is a tile with:
///   - Icon + name + one-line "what it does"
///   - Currently-relevant context (selected engagement, last run)
///   - A single button that opens the tool's sheet or runs it inline
///
/// Tools that require an engagement (active scan, traffic capture)
/// gate on an engagement picker at the top. Tools that don't (DNS
/// audit) run regardless. Status text under each tile tells the
/// operator what's missing if they click into a gated tile.
struct ReconView: View {
    @Environment(AppState.self) private var appState

    @State private var selectedEngagementId: String?
    @State private var presentedTool: ReconTool?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                engagementSelector
                Divider()
                toolsGrid
                tipsCard
            }
            .padding(24)
            .frame(maxWidth: 1100)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.controlBackgroundColor))
        .sheet(item: $presentedTool) { tool in
            sheetFor(tool: tool)
        }
        .onAppear { syncEngagementSelection() }
        .onChange(of: appState.engagements.map(\.id)) { _, _ in
            syncEngagementSelection()
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: "binoculars.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Recon & Pentest Toolkit").font(.largeTitle.bold())
                    Text("White/gray-hat audit capabilities — host discovery, DNS leaks, cleartext-protocol detection, evidence-grade packet capture.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: - Engagement picker

    private var activeEngagements: [Engagement] {
        appState.engagements.filter { $0.expiresAt > Date() }
    }

    private var engagementSelector: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Engagement", systemImage: "doc.text.fill")
                    .font(.headline)
                Spacer()
                Text("Scopes findings + evidence storage")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            if activeEngagements.isEmpty {
                emptyEngagementBanner
            } else {
                Picker("", selection: $selectedEngagementId) {
                    ForEach(activeEngagements) { e in
                        Text(engagementLabel(e)).tag(Optional(e.id))
                    }
                }
                .pickerStyle(.menu)
                .labelsHidden()
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10).fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10).stroke(.separator, lineWidth: 0.5)
        )
    }

    private var emptyEngagementBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 4) {
                Text("No active engagement").font(.subheadline.weight(.medium))
                Text("Create one in the Security section first — every tool here runs under an authorised engagement so the audit trail attributes its findings properly.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Go to Security") {
                appState.selectedSection = .security
            }
            .controlSize(.small)
        }
    }

    private func engagementLabel(_ e: Engagement) -> String {
        let scope = e.scopeCidrs.first ?? "no scope"
        return "\(e.title) — \(scope)"
    }

    private var selectedEngagement: Engagement? {
        guard let id = selectedEngagementId else { return nil }
        return activeEngagements.first(where: { $0.id == id })
    }

    private func syncEngagementSelection() {
        if selectedEngagement == nil {
            selectedEngagementId = activeEngagements.first?.id
        }
    }

    // MARK: - Tools grid

    private var toolsGrid: some View {
        LazyVGrid(
            columns: [
                GridItem(.flexible(minimum: 260), spacing: 16),
                GridItem(.flexible(minimum: 260), spacing: 16),
            ],
            spacing: 16
        ) {
            tile(.activeScan)
            tile(.passiveScan)
            tile(.dnsAudit)
            tile(.trafficCapture)
        }
    }

    private func tile(_ tool: ReconTool) -> some View {
        let gated = tool.requiresEngagement && selectedEngagement == nil
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: tool.icon)
                    .font(.system(size: 22))
                    .foregroundStyle(tool.tint)
                    .frame(width: 36, height: 36)
                    .background(tool.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 2) {
                    Text(tool.title).font(.headline)
                    Text(tool.tagline)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            Text(tool.detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .lineLimit(3, reservesSpace: true)
            HStack {
                if gated {
                    Text("Pick an engagement above to enable")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                Spacer()
                Button(tool.actionLabel) {
                    presentedTool = tool
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .disabled(gated)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10).fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10).stroke(.separator, lineWidth: 0.5)
        )
    }

    // MARK: - Tips card

    private var tipsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Notes", systemImage: "lightbulb.fill")
                .font(.subheadline.weight(.semibold))
            VStack(alignment: .leading, spacing: 6) {
                Text("• Findings flow into the **Security** tab under the engagement — open it after a tool runs.")
                Text("• Traffic captures save the full .pcap into `<engagement>/captures/` for Wireshark review. Per-finding redacted excerpts (passwords SHA-256 hashed) get written alongside.")
                Text("• DNS audit runs ~5–8 sec per nameserver. Domains with 2–4 NSes finish in well under a minute.")
                Text("• Active scans of /24 networks take a few minutes — the scope shown in the engagement picker is the target.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10).fill(.tint.opacity(0.06))
        )
    }

    // MARK: - Sheet routing

    @ViewBuilder
    private func sheetFor(tool: ReconTool) -> some View {
        switch tool {
        case .activeScan, .passiveScan:
            // These tools live inside the engagement panel today.
            // Bounce the user there with the engagement pre-selected.
            ActiveScanLaunchSheet(
                engagementId: selectedEngagement?.id,
                passive: tool == .passiveScan
            )
        case .dnsAudit:
            DnsAuditSheet()
        case .trafficCapture:
            if let eid = selectedEngagement?.id {
                TrafficCaptureSheet(engagementId: eid)
            }
        }
    }
}

// MARK: - Tool catalogue

enum ReconTool: String, Identifiable, CaseIterable {
    case passiveScan
    case activeScan
    case dnsAudit
    case trafficCapture

    var id: String { rawValue }

    var title: String {
        switch self {
        case .passiveScan: return "Passive discovery"
        case .activeScan: return "Active scan"
        case .dnsAudit: return "DNS zone-transfer audit"
        case .trafficCapture: return "Capture insecure traffic"
        }
    }

    var tagline: String {
        switch self {
        case .passiveScan: return "ARP + mDNS — no packets sent"
        case .activeScan: return "TCP sweep + banner + CVE matching"
        case .dnsAudit: return "Probes for AXFR leakage"
        case .trafficCapture: return "Cleartext-credential PoC evidence"
        }
    }

    var detail: String {
        switch self {
        case .passiveScan:
            return "Reads the system ARP cache + mDNS announcements to enumerate hosts on the local segment without sending traffic. Useful for low-impact inventory."
        case .activeScan:
            return "TCP-connect sweep across the top-100 service ports for every host in scope. Banner-grabs services, probes TLS, matches CVE database, runs SMB/LDAP/SNMP enumeration where applicable."
        case .dnsAudit:
            return "Queries every authoritative nameserver of the target domain for an AXFR transfer. A successful transfer leaks the entire zone — internal hostnames, mail routing, infra layout."
        case .trafficCapture:
            return "Helper runs tcpdump as root for a bounded duration. Engine analyses the .pcap for FTP/Telnet/HTTP-basic/HTTP-POST/POP3/IMAP/SMTP/SNMP/NTLM/MQTT cleartext + TLS 1.0/1.1 downgrade-attempting clients. Live findings stream every 5 sec."
        }
    }

    var icon: String {
        switch self {
        case .passiveScan: return "antenna.radiowaves.left.and.right"
        case .activeScan: return "scope"
        case .dnsAudit: return "network.badge.shield.half.filled"
        case .trafficCapture: return "waveform.path.ecg.rectangle"
        }
    }

    var tint: Color {
        switch self {
        case .passiveScan: return .gray
        case .activeScan: return .orange
        case .dnsAudit: return .blue
        case .trafficCapture: return .purple
        }
    }

    var requiresEngagement: Bool {
        switch self {
        case .passiveScan, .activeScan, .trafficCapture: return true
        case .dnsAudit: return false
        }
    }

    var actionLabel: String {
        switch self {
        case .passiveScan, .activeScan: return "Open in Security…"
        case .dnsAudit: return "Run DNS audit…"
        case .trafficCapture: return "Start capture…"
        }
    }
}

/// Hand-off sheet for tools that still live inside the engagement
/// panel (passive + active scan). Tells the user where to find
/// them and provides a one-click jump.
private struct ActiveScanLaunchSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    let engagementId: String?
    let passive: Bool

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: passive ? "antenna.radiowaves.left.and.right" : "scope")
                .font(.system(size: 48))
                .foregroundStyle(.tint)
            Text("Open the engagement to run \(passive ? "Passive" : "Active") scan")
                .font(.headline)
            Text("Discovery and scan controls live on the engagement page so the scan log + result snapshots stay paired with the engagement they ran under.")
                .font(.callout)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal)
            HStack {
                Button("Close") { dismiss() }
                Button("Go to Security") {
                    appState.selectedSection = .security
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return)
            }
            .padding(.top, 4)
        }
        .padding(28)
        .frame(width: 460)
    }
}

#if DEBUG
#Preview {
    ReconView()
        .environment(AppState.previewSeeded)
        .frame(width: 900, height: 700)
}
#endif
