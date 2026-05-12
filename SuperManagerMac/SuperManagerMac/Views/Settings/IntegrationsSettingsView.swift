import SwiftUI
import AppKit

/// Settings tab — "Integrations" — surfaces the engine's external
/// dependencies + auxiliary feeds:
///   • CLI tools the engine shells out to (smbclient, dig, pandoc, …)
///   • NVD CVE feed status + manual refresh
///
/// Designed so an MSP operator can answer "why didn't this scan
/// produce SMB findings?" by glancing at one screen and copying
/// the brew-install command.
struct IntegrationsSettingsView: View {
    @Environment(AppState.self) private var appState

    @State private var tools: [ToolInfo] = []
    @State private var loadingTools = false
    @State private var cveStatus: CveFeedStatus?
    @State private var refreshingFeed = false
    @State private var lastFeedAdded: Int?
    @State private var notifyConfig: NotifyConfig?
    @State private var selectedScope: String = ""
    @State private var slackUrl: String = ""
    @State private var pagerdutyKey: String = ""
    @State private var opsgenieKey: String = ""
    @State private var savingNotify = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                toolsSection
                Divider()
                cveSection
                Divider()
                notificationsSection
            }
            .padding(.bottom, 12)
        }
        .task {
            await refreshAll()
        }
    }

    private func refreshAll() async {
        loadingTools = true
        async let tools = appState.loadToolStatus()
        async let cve = appState.loadCveFeedStatus()
        async let notify = appState.loadNotifyConfig()
        let (toolList, status, cfg) = await (tools, cve, notify)
        if let toolList { self.tools = toolList }
        cveStatus = status
        notifyConfig = cfg
        loadingTools = false
        // Auto-pick first available customer scope on initial load.
        if selectedScope.isEmpty,
           let first = appState.customers.first {
            selectedScope = first.slug
            hydrateNotifyFields()
        }
    }

    private func hydrateNotifyFields() {
        guard let cfg = notifyConfig, !selectedScope.isEmpty else {
            slackUrl = ""; pagerdutyKey = ""; opsgenieKey = ""
            return
        }
        slackUrl = cfg.webhooks[selectedScope] ?? ""
        pagerdutyKey = cfg.pagerdutyKeys[selectedScope] ?? ""
        opsgenieKey = cfg.opsgenieKeys[selectedScope] ?? ""
    }

    // MARK: - Tools section

    @ViewBuilder
    private var toolsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("CLI tool dependencies", systemImage: "terminal")
                    .font(.headline)
                Spacer()
                Button {
                    Task { await refreshAll() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .disabled(loadingTools)
                .accessibilityLabel("Refresh tool status")
            }
            Text("The engine shells out to these tools for several scan types. Missing tools cause the corresponding probes to silently no-op. macOS-shipped tools should be present out of the box; Homebrew tools require manual install.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if !missingHomebrew.isEmpty {
                installHint
            }

            VStack(spacing: 0) {
                ForEach(tools) { tool in
                    toolRow(tool)
                    if tool.id != tools.last?.id {
                        Divider().padding(.leading, 32)
                    }
                }
            }
            .background(.background.secondary)
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    /// Homebrew formulas the user is missing — surfaced as a single
    /// copy-paste command so the user doesn't have to compose it.
    private var missingHomebrew: [String] {
        var formulas: Set<String> = []
        for t in tools where !t.installed {
            if t.source == "Homebrew", let f = t.brewFormula {
                formulas.insert(f)
            }
        }
        return Array(formulas).sorted()
    }

    private var installHint: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label("Missing Homebrew tools — copy + run:", systemImage: "info.circle")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.orange)
            HStack {
                Text("brew install \(missingHomebrew.joined(separator: " "))")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.background.tertiary)
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(
                        "brew install \(missingHomebrew.joined(separator: " "))",
                        forType: .string
                    )
                }
                .controlSize(.small)
            }
        }
        .padding(10)
        .background(.orange.opacity(0.08))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(.orange.opacity(0.2), lineWidth: 0.5)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    @ViewBuilder
    private func toolRow(_ tool: ToolInfo) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: tool.installed ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(tool.installed ? .green : .orange)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(tool.name)
                        .font(.system(.callout, design: .monospaced))
                        .fontWeight(.medium)
                    Text("(\(tool.source))")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                Text(tool.purpose)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let v = tool.version {
                    Text(v)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                } else if !tool.installed, let brew = tool.brewFormula {
                    Text("Install: brew install \(brew)")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
            }
            Spacer()
        }
        .padding(8)
    }

    // MARK: - CVE feed section

    @ViewBuilder
    private var cveSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("NVD CVE feed", systemImage: "exclamationmark.shield")
                    .font(.headline)
                Spacer()
                Button {
                    Task { await refreshFeed() }
                } label: {
                    if refreshingFeed {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Refreshing…")
                        }
                    } else {
                        Label("Refresh now", systemImage: "arrow.down.circle")
                    }
                }
                .controlSize(.small)
                .disabled(refreshingFeed)
            }
            Text("Bundled CVE database covers ~30 high-impact vulnerabilities. The NVD feed extends this with everything published in the last week — refreshed automatically by the daemon's scheduler. Manual refresh useful when you've just deployed a new fleet and want today's data.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 16) {
                statTile(
                    label: "Cached entries",
                    value: cveStatus.map { "\($0.total)" } ?? "—",
                    icon: "tray.full"
                )
                statTile(
                    label: "Last refreshed",
                    value: cveStatus?.lastFetchedAt
                        .map { $0.formatted(.relative(presentation: .named)) }
                        ?? "Never",
                    icon: "clock"
                )
            }
            // Staleness pill — surfaces a problem the operator
            // wouldn't otherwise notice. The daemon's scheduler
            // auto-refreshes weekly, but if the daemon was off /
            // network-blocked / API-limited the feed quietly
            // ages out and scans use a stale CVE database.
            if let lastFetched = cveStatus?.lastFetchedAt {
                cveStalenessPill(for: lastFetched)
            }
            if let added = lastFeedAdded {
                Text("Added \(added) new CVE\(added == 1 ? "" : "s") in last refresh.")
                    .font(.caption)
                    .foregroundStyle(.green)
            }
        }
    }

    /// Coloured staleness indicator for the CVE feed. Buckets
    /// match the auto-refresh cadence in the daemon
    /// (`scheduler.rs` — weekly refresh, ~7 days):
    ///   - < 14 days   : green  ("Fresh")
    ///   - 14 - 30 days: orange ("Aging")
    ///   - > 30 days   : red    ("Stale — auto-refresh has failed")
    @ViewBuilder
    private func cveStalenessPill(for lastFetched: Date) -> some View {
        let days = Calendar.current.dateComponents(
            [.day], from: lastFetched, to: Date()
        ).day ?? 0
        let (label, color, icon): (String, Color, String) = {
            switch days {
            case ..<14:  return ("Fresh", .green, "checkmark.seal.fill")
            case 14..<30: return ("Aging — auto-refresh may be delayed", .orange, "exclamationmark.triangle.fill")
            default:      return ("Stale — auto-refresh has not run for \(days) days", .red, "xmark.octagon.fill")
            }
        }()
        Label(label, systemImage: icon)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(color.opacity(0.12))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    private func statTile(label: String, value: String, icon: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                Text(value)
                    .font(.callout.weight(.medium))
            }
            Spacer()
        }
        .padding(10)
        .background(.background.secondary)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func refreshFeed() async {
        refreshingFeed = true
        defer { refreshingFeed = false }
        if let added = await appState.refreshCveFeed() {
            lastFeedAdded = added
            cveStatus = await appState.loadCveFeedStatus()
        }
    }

    // MARK: - Notifications section

    @ViewBuilder
    private var notificationsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Notifications", systemImage: "bell.fill")
                .font(.headline)
            Text("Per-customer escalation. Slack/Mattermost webhooks fire on Critical+High new findings; PagerDuty + OpsGenie page only on Critical (de-duped via finding key so re-detection doesn't spam).")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if appState.customers.isEmpty {
                Text("Add a customer in the Provisioning section to configure escalation routes.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            } else {
                Picker("Customer", selection: $selectedScope) {
                    ForEach(appState.customers) { c in
                        Text(c.displayName).tag(c.slug)
                    }
                }
                .onChange(of: selectedScope) { _, _ in
                    hydrateNotifyFields()
                }

                notifyField(
                    label: "Slack / Mattermost",
                    binding: $slackUrl,
                    placeholder: "https://hooks.slack.com/services/...",
                    onSave: { url in
                        await appState.setNotifyWebhook(scope: selectedScope, webhookUrl: url)
                    }
                )
                notifyField(
                    label: "PagerDuty",
                    binding: $pagerdutyKey,
                    placeholder: "Events API v2 routing key",
                    onSave: { k in
                        await appState.setNotifyPagerduty(scope: selectedScope, key: k)
                    }
                )
                notifyField(
                    label: "OpsGenie",
                    binding: $opsgenieKey,
                    placeholder: "Genie API key",
                    onSave: { k in
                        await appState.setNotifyOpsgenie(scope: selectedScope, key: k)
                    }
                )
            }
        }
    }

    @ViewBuilder
    private func notifyField(
        label: String,
        binding: Binding<String>,
        placeholder: String,
        onSave: @escaping (String) async -> Void
    ) -> some View {
        HStack(spacing: 8) {
            Text(label)
                .font(.caption.weight(.medium))
                .frame(width: 130, alignment: .leading)
            SecureField(placeholder, text: binding)
                .textFieldStyle(.roundedBorder)
                .font(.caption.monospaced())
            Button("Save") {
                Task {
                    savingNotify = true
                    defer { savingNotify = false }
                    await onSave(binding.wrappedValue)
                    notifyConfig = await appState.loadNotifyConfig()
                }
            }
            .controlSize(.small)
            .disabled(savingNotify)
            Button {
                Task {
                    binding.wrappedValue = ""
                    await onSave("")
                    notifyConfig = await appState.loadNotifyConfig()
                }
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Clear \(label)")
            .help("Remove this notification target.")
        }
    }
}
