import SwiftUI

/// First-class launcher for the toolkit's white/gray-hat
/// capabilities. Every tile here opens a sheet that runs the
/// tool directly from this section — no bounce-back to other
/// parts of the app.
///
/// Active scan + Passive scan are deliberately NOT in the grid:
/// they live in the Security engagement panel where they're
/// tightly coupled to the host inventory display. A small
/// footer points the user there so the absence isn't confusing.
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
                Divider()
                whereIsActiveScanCard
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
                    Text("White/gray-hat audit capabilities — every tile runs the tool directly from here. Findings flow into the Security tab under the selected engagement.")
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
                Text("Scopes findings + evidence storage for tools that need it")
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
                Text("Some tools (traffic capture) save evidence under an engagement directory and need one selected. DNS-based tools work without an engagement.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Create in Security") {
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
            tile(.dnsAudit)
            tile(.dnsHealth)
            tile(.subdomainEnum)
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
                .lineLimit(4, reservesSpace: true)
            HStack {
                if gated {
                    Text("Pick an engagement above")
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
                Text("• Findings emitted by these tools flow into the **Security** tab under the selected engagement.")
                Text("• Traffic captures save the full .pcap into `<engagement>/captures/` for Wireshark review. Per-finding redacted excerpts (passwords SHA-256 hashed) get written alongside.")
                Text("• DNS-based tools (zone transfer, health, subdomain enum) don't need an engagement — they only require a domain name.")
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

    /// Tells the user where Active + Passive scan live, because
    /// they're conspicuously absent from the grid. Without this
    /// they'd hunt and assume something's missing.
    private var whereIsActiveScanCard: some View {
        HStack(spacing: 10) {
            Image(systemName: "info.circle")
                .foregroundStyle(.secondary)
            Text("Active scan + passive discovery live on the engagement page (Security → pick engagement → \"Active scan\"). They're not duplicated here because they're tightly coupled to the engagement's host-inventory display.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button("Open Security") {
                appState.selectedSection = .security
            }
            .controlSize(.small)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8).fill(.background.tertiary)
        )
    }

    // MARK: - Sheet routing

    @ViewBuilder
    private func sheetFor(tool: ReconTool) -> some View {
        switch tool {
        case .dnsAudit:
            DnsAuditSheet()
        case .dnsHealth:
            DnsHealthSheet()
        case .subdomainEnum:
            SubdomainEnumSheet()
        case .trafficCapture:
            if let eid = selectedEngagement?.id {
                TrafficCaptureSheet(engagementId: eid)
            }
        }
    }
}

// MARK: - Tool catalogue

enum ReconTool: String, Identifiable, CaseIterable {
    case dnsAudit
    case dnsHealth
    case subdomainEnum
    case trafficCapture

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dnsAudit: return "DNS zone-transfer audit"
        case .dnsHealth: return "Email + DNS health audit"
        case .subdomainEnum: return "Subdomain enumeration"
        case .trafficCapture: return "Capture insecure traffic"
        }
    }

    var tagline: String {
        switch self {
        case .dnsAudit: return "Probes for AXFR leakage"
        case .dnsHealth: return "SPF / DKIM / DMARC / DNSSEC posture"
        case .subdomainEnum: return "Certificate-Transparency log search"
        case .trafficCapture: return "Cleartext-credential PoC evidence"
        }
    }

    var detail: String {
        switch self {
        case .dnsAudit:
            return "Queries every authoritative nameserver of the target domain for an AXFR transfer. A successful transfer leaks the entire zone — internal hostnames, mail routing, infra layout. Most NSes refuse this; the ones that don't are immediate findings."
        case .dnsHealth:
            return "Checks SPF, DKIM (common selectors), DMARC, MTA-STS, and DNSSEC for the target domain. Surfaces softfail/permissive/missing posture as findings — the email-deliverability + spoofing-resistance baseline every customer cares about."
        case .subdomainEnum:
            return "Queries crt.sh's Certificate Transparency database for every cert ever issued for *.<domain>. Returns the unique hostnames discovered. Passive recon — no traffic to the target. Useful for catching infra the customer didn't tell you about."
        case .trafficCapture:
            return "Helper runs tcpdump as root for a bounded duration. Engine analyses the .pcap for cleartext credentials (FTP/Telnet/HTTP-basic/HTTP-POST/POP3/IMAP/SMTP/SNMP/NTLM/MQTT) + TLS 1.0/1.1 downgrade-attempting clients. Live counter streams every 5 sec."
        }
    }

    var icon: String {
        switch self {
        case .dnsAudit: return "network.badge.shield.half.filled"
        case .dnsHealth: return "envelope.badge.shield.half.filled"
        case .subdomainEnum: return "magnifyingglass.circle.fill"
        case .trafficCapture: return "waveform.path.ecg.rectangle"
        }
    }

    var tint: Color {
        switch self {
        case .dnsAudit: return .blue
        case .dnsHealth: return .teal
        case .subdomainEnum: return .indigo
        case .trafficCapture: return .purple
        }
    }

    var requiresEngagement: Bool {
        switch self {
        case .trafficCapture: return true
        case .dnsAudit, .dnsHealth, .subdomainEnum: return false
        }
    }

    var actionLabel: String {
        switch self {
        case .dnsAudit: return "Run AXFR audit…"
        case .dnsHealth: return "Run health audit…"
        case .subdomainEnum: return "Enumerate…"
        case .trafficCapture: return "Start capture…"
        }
    }
}

#if DEBUG
#Preview {
    ReconView()
        .environment(AppState.previewSeeded)
        .frame(width: 900, height: 700)
}
#endif
