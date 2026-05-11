import SwiftUI

/// Discovery + active-scan panel. Sits in the SecurityView body
/// and runs all our active-recon tooling against the engagement
/// scope.
///
/// Two scan modes:
///   - **Passive** — ARP cache + mDNS browse + interfaces. No
///     packets sent.
///   - **Active** — TCP sweep over top-100 ports + service
///     banner-grab + TLS audit + CVE matching. Triggers
///     finding generation.
///
/// Findings render below in a severity-sorted list. Each
/// finding shows CVE link (if applicable), recommendation, and
/// (for credentials-related findings) lets the user trigger
/// follow-up tests.
struct DiscoveryPanel: View {
    @Environment(AppState.self) private var appState
    let engagement: Engagement

    @State private var passiveResult: AppState.PassiveScanResult?
    @State private var activeResult: ActiveScanResult?
    @State private var inventory: [AppState.DiscoveredHost] = []
    @State private var persistedFindings: [PersistedFinding] = []
    @State private var scanDiff: ScanDiff?
    @State private var showActive = false
    @State private var credTestInFlight: Set<String> = []
    @State private var selectedFinding: PersistedFinding?
    @State private var showReport = false
    /// Becomes true the first time the user interacts with a finding
    /// (taps a row, toggles a pin). Suppresses the auto-open of the
    /// most-severe finding after subsequent scans — once the user
    /// has shown intent, we stop second-guessing them.
    @State private var userHasInteracted = false

    private var hostsForDisplay: [AppState.DiscoveredHost] {
        if let p = passiveResult { return p.hosts }
        return inventory
    }

    /// Persistence scope for findings RPCs — customer slug if
    /// available, else fall back to engagement id.
    private var findingsScope: String? {
        engagement.customerSlug.isEmpty ? nil : engagement.customerSlug
    }

    private var openFindings: [PersistedFinding] {
        persistedFindings.filter {
            if case .open = $0.disposition { return true } else { return false }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            scanControls
            if let p = passiveResult {
                interfaceStrip(p.localInterfaces)
            }
            // When scope is empty but we have a viable source
            // (passive scan, connected VPN), surface a one-click
            // "Use as scope" so active-scan unblocks without leaving
            // the panel.
            if engagement.scopeCidrs.isEmpty,
               !scopeSources.isEmpty {
                useAsScopeBanner
            }
            if let a = activeResult, showActive {
                activeHostsTable(a)
            } else if !hostsForDisplay.isEmpty {
                passiveHostsTable
            } else {
                emptyState
            }
            if let diff = scanDiff {
                scanDiffCard(diff)
            }
            if !persistedFindings.isEmpty {
                findingsCard
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(.separator, lineWidth: 0.5)
        )
        .task(id: engagement.id) {
            await reloadAll()
        }
        .sheet(item: $selectedFinding) { finding in
            FindingDetailSheet(
                finding: finding,
                scope: findingsScope,
                engagementId: engagement.id
            ) { updated in
                if let idx = persistedFindings.firstIndex(where: { $0.id == updated.id }) {
                    persistedFindings[idx] = updated
                }
            }
        }
        .sheet(isPresented: $showReport) {
            EngagementReportSheet(engagementId: engagement.id, title: engagement.title)
        }
    }

    private func reloadAll() async {
        if !engagement.customerSlug.isEmpty {
            if let cached = await appState.loadDiscoveryInventory(
                customerSlug: engagement.customerSlug
            ) {
                inventory = cached
            }
        }
        if let list = await appState.loadPersistedFindings(
            scope: findingsScope,
            engagementId: engagement.id
        ) {
            persistedFindings = list
        }
    }

    // MARK: - Scan controls

    private var scanControls: some View {
        HStack(spacing: 8) {
            Image(systemName: "dot.radiowaves.left.and.right")
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 0) {
                Text("Network Discovery")
                    .font(.headline)
                if let r = passiveResult {
                    Text("Last passive scan \(r.finishedAt.formatted(date: .abbreviated, time: .shortened)) · \(r.hosts.count) hosts")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                } else if let a = activeResult {
                    let elapsed = a.finishedAt.timeIntervalSince(a.startedAt)
                    Text("Last active scan: \(a.hosts.count) hosts · \(a.findings.count) findings · \(String(format: "%.1f", elapsed))s")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                } else {
                    Text("Passive: ARP + mDNS · Active: TCP sweep + banner-grab + TLS + CVE matching")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            // Hierarchy:
            //   - Active scan = hero (borderedProminent, full size).
            //     Primary value-prop button on this panel.
            //   - Passive scan = secondary (bordered, small).
            //   - Report + future tools = "More…" pull-down menu.
            //     Demoted because users scan first and report later;
            //     putting Report at the same prominence as a scan
            //     button created visual ambiguity ("which one do I
            //     click?") without earning the real estate.
            Button {
                Task { await runPassive() }
            } label: {
                if appState.discoveryInFlight {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Passive…")
                    }
                } else {
                    Label("Passive scan", systemImage: "antenna.radiowaves.left.and.right")
                }
            }
            .controlSize(.small)
            .buttonStyle(.bordered)
            .disabled(appState.discoveryInFlight || appState.activeScanInFlight)
            .help("Read ARP cache + mDNS — no packets sent.")

            Button {
                Task { await runActive() }
            } label: {
                if appState.activeScanInFlight {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Active scan…")
                    }
                } else {
                    Label("Active scan", systemImage: "scope")
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.regular)
            .keyboardShortcut("r", modifiers: .command)
            .disabled(
                appState.discoveryInFlight
                    || appState.activeScanInFlight
                    || engagement.scopeCidrs.isEmpty
            )
            .help(
                engagement.scopeCidrs.isEmpty
                    ? "Set in-scope CIDRs on the engagement to enable active scanning."
                    : "Sweep all in-scope CIDRs for services, banners, TLS issues, and known CVEs."
            )

            // Stop button — only visible while an active scan
            // operation is running. Cancellation is cooperative
            // (engine polls the flag at host-batch boundaries),
            // so this is "request stop" rather than "kill now".
            if appState.activeScanInFlight,
               let op = appState.runningOperations.first(where: { $0.kind == "active_scan" }) {
                Button {
                    Task { await appState.cancelOperation(id: op.id) }
                } label: {
                    if op.cancelRequested {
                        HStack(spacing: 4) {
                            ProgressView().controlSize(.small)
                            Text("Cancelling…")
                        }
                    } else {
                        Label("Stop", systemImage: "stop.circle.fill")
                    }
                }
                .controlSize(.regular)
                .buttonStyle(.bordered)
                .tint(.red)
                .disabled(op.cancelRequested)
                .help(op.cancelRequested
                    ? "Cancellation requested — waiting for the current batch to finish."
                    : "Stop the active scan at its next safe checkpoint.")
            }

            Menu {
                Button {
                    showReport = true
                } label: {
                    Label("Engagement report…", systemImage: "doc.text.fill")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .controlSize(.small)
            .fixedSize()
            .accessibilityLabel("More actions")
            .help("Reports, exports, and other engagement tools.")
        }
    }

    private func interfaceStrip(_ interfaces: [AppState.LocalInterface]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Local interfaces (\(interfaces.count))")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(interfaces) { iface in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(iface.name).font(.caption.weight(.semibold))
                            if let cidr = iface.cidr {
                                Text(cidr).font(.caption2).foregroundStyle(.secondary).monospaced()
                            }
                        }
                        .padding(8)
                        .background(.tint.opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                    }
                }
            }
        }
    }

    /// Subnets observed by passive scan (interface CIDRs + the
    /// /24 of every discovered host), de-duped + sorted.
    private var suggestedScopeFromPassive: [String] {
        var subnets: Set<String> = []
        if let p = passiveResult {
            for iface in p.localInterfaces {
                if let c = iface.cidr, !c.isEmpty {
                    subnets.insert(c)
                }
            }
        }
        for h in hostsForDisplay {
            let parts = h.ip.split(separator: ".")
            if parts.count == 4 {
                subnets.insert("\(parts[0]).\(parts[1]).\(parts[2]).0/24")
            }
        }
        return Array(subnets).sorted()
    }

    private struct ScopeSource {
        let label: String          // "this LAN" / VPN profile name / etc.
        let icon: String           // SF Symbol name
        let cidrs: [String]
    }

    /// All currently-suggestable scope sources: the local LAN
    /// (from passive scan) plus every connected VPN profile's
    /// pushed routes. Empty array = nothing to suggest.
    private var scopeSources: [ScopeSource] {
        var out: [ScopeSource] = []
        let local = suggestedScopeFromPassive
        if !local.isEmpty {
            out.append(ScopeSource(
                label: "this LAN",
                icon: "antenna.radiowaves.left.and.right",
                cidrs: local
            ))
        }
        for vpn in appState.reachableVpnNetworks() {
            out.append(ScopeSource(
                label: "VPN: \(vpn.name)",
                icon: "lock.shield",
                cidrs: vpn.cidrs
            ))
        }
        return out
    }

    private var useAsScopeBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "scope")
                    .foregroundStyle(.tint)
                Text("Active scan disabled — engagement has no in-scope CIDRs")
                    .font(.callout.weight(.medium))
                Spacer()
            }
            ForEach(Array(scopeSources.enumerated()), id: \.offset) { _, source in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: source.icon)
                        .foregroundStyle(.secondary)
                        .frame(width: 18)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("From \(source.label)")
                            .font(.caption.weight(.semibold))
                        Text(source.cidrs.joined(separator: ", "))
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                    }
                    Spacer()
                    Button {
                        Task { await applyScope(cidrs: source.cidrs) }
                    } label: {
                        Label("Use as scope", systemImage: "arrow.right.square")
                    }
                    .controlSize(.small)
                    .buttonStyle(.borderedProminent)
                }
            }
        }
        .padding(10)
        .background(.tint.opacity(0.08))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(.tint.opacity(0.25), lineWidth: 0.5)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    /// Merge `cidrs` into the engagement's scope_cidrs (de-duped)
    /// and persist via `engagement_save`.
    private func applyScope(cidrs: [String]) async {
        var copy = engagement
        let existing = Set(copy.scopeCidrs)
        for s in cidrs where !existing.contains(s) {
            copy.scopeCidrs.append(s)
        }
        if await appState.saveEngagement(copy) != nil {
            await appState.refreshEngagements()
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "antenna.radiowaves.left.and.right")
                .font(.system(size: 36))
                .foregroundStyle(.tertiary)
            Text("No scans yet").foregroundStyle(.secondary)
            if engagement.scopeCidrs.isEmpty {
                Text("Run passive scan to query the local network. To enable active scanning, set in-scope CIDRs on the engagement.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            } else {
                Text("Run passive scan to query the local network, or active scan to probe scope CIDRs for services + vulnerabilities.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
    }

    // MARK: - Passive hosts table

    private var passiveHostsTable: some View {
        VStack(spacing: 0) {
            HStack {
                Text("IP").frame(width: 130, alignment: .leading)
                Text("Hostname").frame(maxWidth: .infinity, alignment: .leading)
                Text("Vendor").frame(width: 180, alignment: .leading)
                Text("Sources").frame(width: 80, alignment: .leading)
            }
            .font(.caption2).foregroundStyle(.tertiary)
            .padding(.horizontal, 8).padding(.vertical, 4)
            Divider()
            LazyVStack(spacing: 0) {
                ForEach(Array(hostsForDisplay.enumerated()), id: \.element.id) { idx, host in
                    HStack(alignment: .top) {
                        Text(host.ip)
                            .font(.system(.callout, design: .monospaced))
                            .frame(width: 130, alignment: .leading)
                        Text(host.hostname ?? "—")
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .foregroundStyle(host.hostname == nil ? .tertiary : .primary)
                        Text(host.vendor ?? "—")
                            .font(.caption)
                            .foregroundStyle(host.vendor == nil ? .tertiary : .secondary)
                            .frame(width: 180, alignment: .leading)
                            .lineLimit(1)
                        HStack(spacing: 4) {
                            ForEach(host.sources, id: \.self) { src in
                                Text(src)
                                    .font(.caption2)
                                    .padding(.horizontal, 4).padding(.vertical, 1)
                                    .background(.tint.opacity(0.12))
                                    .foregroundStyle(.tint)
                                    .clipShape(Capsule())
                            }
                        }
                        .frame(width: 80, alignment: .leading)
                    }
                    .padding(.horizontal, 8).padding(.vertical, 6)
                    .background(idx % 2 == 0 ? Color.clear : Color.gray.opacity(0.06))
                    .transition(.opacity.combined(with: .move(edge: .top)))
                }
            }
            .animation(.easeOut(duration: 0.18), value: hostsForDisplay.count)
        }
        .background(Color.gray.opacity(0.04))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    // MARK: - Active hosts table

    private func activeHostsTable(_ result: ActiveScanResult) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("\(result.hosts.count) responsive hosts")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text("\(result.findings.count) findings")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            ForEach(result.hosts) { host in
                ActiveHostCard(
                    host: host,
                    customerSlug: findingsScope
                ) { service, port in
                    Task { await runCredTest(host: host.ip, port: port, service: service) }
                }
                .disabled(credTestInFlight.contains(host.ip))
            }
        }
    }

    // MARK: - Scan-diff card

    private func scanDiffCard(_ diff: ScanDiff) -> some View {
        let buckets: [(String, Int, Color, String)] = [
            ("New", diff.newFindings.count, .red, "exclamationmark.triangle.fill"),
            ("Regressed", diff.regressed.count, .orange, "arrow.uturn.backward"),
            ("Still open", diff.stillOpen.count, .yellow, "clock.fill"),
            ("Auto-resolved", diff.autoResolved.count, .green, "checkmark.seal.fill"),
            ("Accepted", diff.acceptedRisk.count, .gray, "hand.raised.fill"),
        ]
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "arrow.triangle.swap")
                    .foregroundStyle(.tint)
                Text("What changed since last scan")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text(diff.generatedAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            HStack(spacing: 8) {
                ForEach(buckets, id: \.0) { (label, count, color, icon) in
                    HStack(spacing: 4) {
                        Image(systemName: icon)
                        Text("\(count) \(label.lowercased())")
                    }
                    .font(.caption2)
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    .background(color.opacity(count == 0 ? 0.06 : 0.15))
                    .foregroundStyle(count == 0 ? .secondary : color)
                    .clipShape(Capsule())
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.tint.opacity(0.04))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(.tint.opacity(0.18), lineWidth: 0.5)
        )
    }

    // MARK: - Findings card

    private var findingsCard: some View {
        let sorted = sortedFindings
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Findings (\(persistedFindings.count))")
                    .font(.headline)
                Text("\(openFindings.count) open")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                bucketCounts
            }
            ForEach(sorted) { f in
                FindingRow(
                    finding: f,
                    isPinned: appState.pinnedFindingIds.contains(f.id),
                    onTogglePin: {
                        appState.toggleFindingPin(f.id)
                        userHasInteracted = true
                    }
                )
                .onTapGesture {
                    userHasInteracted = true
                    selectedFinding = f
                }
                .transition(.opacity.combined(with: .move(edge: .top)))
                .contextMenu {
                    if let cve = f.finding.cve {
                        Button("Copy CVE") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(cve, forType: .string)
                        }
                    }
                    Button("Copy host IP") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(f.finding.hostIp, forType: .string)
                    }
                    Divider()
                    Button("Mark as accepted risk…") {
                        userHasInteracted = true
                        selectedFinding = f
                    }
                    Button("Mark as false positive…") {
                        userHasInteracted = true
                        selectedFinding = f
                    }
                    Divider()
                    Button(appState.pinnedFindingIds.contains(f.id) ? "Unpin" : "Pin to top") {
                        appState.toggleFindingPin(f.id)
                        userHasInteracted = true
                    }
                    Button("Open details…") {
                        userHasInteracted = true
                        selectedFinding = f
                    }
                }
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(.separator, lineWidth: 0.5)
        )
        .animation(.easeOut(duration: 0.18), value: persistedFindings.count)
    }

    /// Sort: pinned first, then severity descending. Stable so the
    /// list doesn't re-shuffle on every refresh.
    private var sortedFindings: [PersistedFinding] {
        let pinned = appState.pinnedFindingIds
        return persistedFindings.sorted { a, b in
            let ap = pinned.contains(a.id)
            let bp = pinned.contains(b.id)
            if ap != bp { return ap }
            return sevRank(a.finding.severity) < sevRank(b.finding.severity)
        }
    }

    private var bucketCounts: some View {
        // Only count Open + AcceptedRisk findings — fixed/false-positive
        // shouldn't drive the severity headline pills.
        let active = persistedFindings.filter {
            switch $0.disposition {
            case .open, .acceptedRisk: return true
            default: return false
            }
        }
        let counts = Dictionary(grouping: active, by: \.finding.severity)
            .mapValues { $0.count }
        return HStack(spacing: 6) {
            ForEach([
                FindingSeverity.critical,
                .high,
                .medium,
                .low,
            ], id: \.self) { s in
                if let n = counts[s], n > 0 {
                    Text("\(n) \(s.rawValue)")
                        .font(.caption2)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(severityColor(s).opacity(0.15))
                        .foregroundStyle(severityColor(s))
                        .clipShape(Capsule())
                }
            }
        }
    }

    private func severityColor(_ s: FindingSeverity) -> Color {
        switch s {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return .yellow
        case .low:      return .blue
        case .info:     return .gray
        }
    }

    private func sevRank(_ s: FindingSeverity) -> Int {
        switch s {
        case .critical: return 0
        case .high:     return 1
        case .medium:   return 2
        case .low:      return 3
        case .info:     return 4
        }
    }

    // MARK: - Actions

    private func runPassive() async {
        let slug = engagement.customerSlug.isEmpty ? nil : engagement.customerSlug
        if let r = await appState.runPassiveDiscovery(
            customerSlug: slug,
            engagementId: engagement.id
        ) {
            passiveResult = r
            showActive = false
            await appState.refreshEngagements()
        }
    }

    private func runActive() async {
        let slug = engagement.customerSlug.isEmpty ? nil : engagement.customerSlug
        if let r = await appState.runActiveDiscovery(
            targets: engagement.scopeCidrs,
            customerSlug: slug,
            engagementId: engagement.id
        ) {
            activeResult = r
            scanDiff = r.diff
            showActive = true
            // After the scan persists, reload from the store so we
            // pick up disposition state + accumulated history.
            if let list = await appState.loadPersistedFindings(
                scope: findingsScope,
                engagementId: engagement.id
            ) {
                persistedFindings = list
                // Auto-surface the worst open finding after the scan
                // so the user lands on it immediately. Only fires
                // when the user hasn't already engaged with the
                // findings list — once they've shown intent, we
                // stop second-guessing them.
                if !userHasInteracted {
                    let topPriority = sortedFindings.first { f in
                        if case .open = f.disposition {
                            return f.finding.severity == .critical
                                || f.finding.severity == .high
                        }
                        return false
                    }
                    if let topPriority {
                        selectedFinding = topPriority
                    }
                }
            }
            await appState.refreshEngagements()
        }
    }

    private func runCredTest(host: String, port: UInt16, service: String) async {
        credTestInFlight.insert(host)
        defer { credTestInFlight.remove(host) }
        if let new = await appState.testDefaultCreds(host: host, port: port, service: service),
           !new.isEmpty {
            // Cred-test runs out-of-band of the active scan, so we
            // refresh the persisted store so any newly-discovered
            // default-credential findings show up in the list with
            // disposition = open.
            if let reloaded = await appState.loadPersistedFindings(
                scope: findingsScope,
                engagementId: engagement.id
            ) {
                persistedFindings = reloaded
            }
        }
    }
}

// MARK: - Active host card

private struct ActiveHostCard: View {
    @Environment(AppState.self) private var appState
    let host: ActiveHost
    let customerSlug: String?
    let onCredTest: (String, UInt16) -> Void
    @State private var expanded = false
    @State private var addedToSsh = false
    @State private var linkedToCustomer = false
    @State private var showingNewCustomer = false
    @State private var slugsBeforeAdd: Set<String> = []

    /// SSH ports detected on this host — drives the "Add to SSH" affordance.
    private var sshPorts: [UInt16] {
        host.probes.filter { $0.service == "ssh" }.map(\.port)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(host.ip)
                    .font(.system(.callout, design: .monospaced))
                CopyButton(value: host.ip, helpText: "Copy IP")
                if let zone = host.zone, !zone.isEmpty {
                    // Zone classification — drives the operator's
                    // "is this internet-facing?" instinct check.
                    // Public IPs flagged in red; internal in gray.
                    let isPublic = zone == "public"
                    Text(zone)
                        .font(.caption2.weight(.medium))
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background((isPublic ? Color.red : Color.gray).opacity(0.15))
                        .foregroundStyle(isPublic ? .red : .secondary)
                        .clipShape(Capsule())
                        .help(isPublic
                              ? "Public-zone host — exposure multiplier 1.5× in risk score."
                              : "Internal/CGNAT/loopback — standard exposure.")
                }
                Spacer()
                if host.findingCount > 0 {
                    Text("\(host.findingCount) finding\(host.findingCount == 1 ? "" : "s")")
                        .font(.caption2)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.orange.opacity(0.15))
                        .foregroundStyle(.orange)
                        .clipShape(Capsule())
                }
                Text("\(host.probes.count) ports")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                actionMenu
                Image(systemName: expanded ? "chevron.up" : "chevron.down")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel(expanded ? "Collapse host" : "Expand host")
            }
            .contentShape(Rectangle())
            .onTapGesture { expanded.toggle() }
            if expanded {
                Divider().padding(.vertical, 2)
                ForEach(host.probes) { probe in
                    probeDetailRow(probe)
                }
            }
        }
        .padding(8)
        .background(.background.tertiary)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .contextMenu {
            Button("Copy IP") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(host.ip, forType: .string)
            }
            if !sshPorts.isEmpty {
                Divider()
                ForEach(sshPorts, id: \.self) { port in
                    Button(addedToSsh ? "SSH host added" : "Add as SSH host (\(port))") {
                        Task { await addAsSshHost(port: port) }
                    }
                    .disabled(addedToSsh)
                }
            }
            if let slug = customerSlug, !slug.isEmpty {
                Divider()
                Button(linkedToCustomer ? "Linked to site" : "Link to customer site") {
                    Task { await linkToCustomerSite(slug: slug) }
                }
                .disabled(linkedToCustomer)
            }
        }
    }

    // Compact action menu — exposes the cross-section flows
    // (Add to SSH, Link to customer site) without cluttering
    // the row.
    @ViewBuilder
    private var actionMenu: some View {
        Menu {
            if !sshPorts.isEmpty {
                ForEach(sshPorts, id: \.self) { port in
                    Button {
                        Task { await addAsSshHost(port: port) }
                    } label: {
                        Label(addedToSsh ? "SSH host added" : "Add as SSH host (\(port))",
                              systemImage: addedToSsh ? "checkmark.circle" : "terminal")
                    }
                }
            }
            if let slug = customerSlug, !slug.isEmpty {
                Button {
                    Task { await linkToCustomerSite(slug: slug) }
                } label: {
                    Label(linkedToCustomer ? "Linked to site" : "Link to customer site",
                          systemImage: linkedToCustomer ? "checkmark.circle" : "building.2")
                }
            } else {
                // No customer linked to engagement → offer to create one
                // and link this host to it in one go.
                Button {
                    slugsBeforeAdd = Set(appState.customers.map(\.slug))
                    showingNewCustomer = true
                } label: {
                    Label("Create customer + link…", systemImage: "building.2.crop.circle.badge.plus")
                }
            }
            Divider()
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(host.ip, forType: .string)
            } label: {
                Label("Copy IP", systemImage: "doc.on.clipboard")
            }
        } label: {
            Image(systemName: "ellipsis.circle")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .menuStyle(.button)
        .buttonStyle(.borderless)
        .fixedSize()
        .accessibilityLabel("Host actions")
        .sheet(isPresented: $showingNewCustomer, onDismiss: {
            Task {
                await appState.refreshCustomers()
                if let added = appState.customers
                    .first(where: { !slugsBeforeAdd.contains($0.slug) })
                {
                    await linkToCustomerSite(slug: added.slug)
                }
            }
        }) {
            CustomerEditSheet(customer: nil)
        }
    }

    private func addAsSshHost(port: UInt16) async {
        // Best-effort: pick a sensible default username + auth.
        // The user can edit afterwards via the SSH section.
        let defaultUser = "admin"
        let label = host.hostname ?? host.ip
        // Map vendor → device type best-guess.
        let device: DeviceType = {
            let v = host.vendor?.lowercased() ?? ""
            if v.contains("ubiquiti") { return .unifi }
            if v.contains("fortinet") { return .fortigate }
            if v.contains("synology") { return .linux }
            return .custom
        }()
        await appState.addHost(
            label: label,
            hostname: host.ip,
            port: port,
            username: defaultUser,
            group: "Discovered",
            deviceType: device,
            authMethod: .password
        )
        addedToSsh = true
    }

    private func linkToCustomerSite(slug: String) async {
        guard var customer = appState.customers.first(where: { $0.slug == slug }) else { return }
        // Best site to link: the one whose lanBase prefixes the host IP,
        // else the first site. Append the IP to its hostIds (de-duped).
        let pickIdx = bestSiteIndex(in: customer)
        guard !customer.sites.isEmpty else { return }
        var site = customer.sites[pickIdx]
        if !site.hostIds.contains(host.ip) {
            site.hostIds.append(host.ip)
        }
        customer.sites[pickIdx] = site
        if await appState.saveCustomer(customer) != nil {
            linkedToCustomer = true
        }
    }

    private func bestSiteIndex(in customer: Customer) -> Int {
        // Match by lanBase /24 prefix string equality — cheap + covers
        // the common case. CIDR overlap is overkill for this UX.
        let ipPrefix = host.ip.split(separator: ".").prefix(3).joined(separator: ".")
        for (i, s) in customer.sites.enumerated() {
            if s.lanBase.hasPrefix(ipPrefix) || s.lanBase.contains(ipPrefix) {
                return i
            }
        }
        return 0
    }

    @ViewBuilder
    private func probeDetailRow(_ probe: PortProbe) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .firstTextBaseline) {
                Text("\(probe.port)/\(probe.service)")
                    .font(.system(.caption, design: .monospaced))
                    .frame(width: 120, alignment: .leading)
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 1) {
                    if let banner = probe.banner ?? probe.serverHeader {
                        Text(banner)
                            .font(.caption)
                            .lineLimit(1)
                            .truncationMode(.tail)
                            .textSelection(.enabled)
                    }
                    if let title = probe.title {
                        Text("title: \(title)")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    if !probe.fingerprints.isEmpty {
                        // Wappalyzer-style framework chips.
                        HStack(spacing: 4) {
                            ForEach(probe.fingerprints, id: \.self) { fp in
                                Text(fp)
                                    .font(.caption2)
                                    .padding(.horizontal, 4)
                                    .background(.purple.opacity(0.12))
                                    .foregroundStyle(.purple)
                                    .clipShape(Capsule())
                            }
                        }
                    }
                    if let tls = probe.tls {
                        HStack(spacing: 4) {
                            Text(tls.version)
                                .font(.caption2)
                                .padding(.horizontal, 4)
                                .background(.green.opacity(0.12))
                                .foregroundStyle(.green)
                                .clipShape(Capsule())
                            if tls.selfSigned {
                                Text("self-signed")
                                    .font(.caption2)
                                    .padding(.horizontal, 4)
                                    .background(.orange.opacity(0.12))
                                    .foregroundStyle(.orange)
                                    .clipShape(Capsule())
                            }
                            if let cn = tls.certSubject {
                                Text(cn)
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                                    .lineLimit(1)
                            }
                        }
                        // Cipher matrix surfacing — every weak cipher
                        // family + deprecated protocol the server
                        // accepted. Operators see "RC4 + 3DES + TLSv1.0"
                        // at a glance; the full finding (severity +
                        // recommendation) lands in the findings list.
                        if !tls.weakCiphersAccepted.isEmpty || !tls.protocolsAccepted.isEmpty {
                            HStack(spacing: 4) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .font(.caption2)
                                    .foregroundStyle(.red)
                                ForEach(tls.weakCiphersAccepted, id: \.self) { c in
                                    Text(c)
                                        .font(.caption2.weight(.semibold))
                                        .padding(.horizontal, 4)
                                        .background(.red.opacity(0.15))
                                        .foregroundStyle(.red)
                                        .clipShape(Capsule())
                                }
                                ForEach(tls.protocolsAccepted, id: \.self) { p in
                                    Text(p)
                                        .font(.caption2)
                                        .padding(.horizontal, 4)
                                        .background(.orange.opacity(0.15))
                                        .foregroundStyle(.orange)
                                        .clipShape(Capsule())
                                }
                            }
                        }
                    }
                }
                Spacer()
                if probe.service == "ssh" || probe.service == "http" || probe.service == "https" {
                    Button {
                        onCredTest(probe.service, probe.port)
                    } label: {
                        Label("Test creds", systemImage: "key.fill")
                    }
                    .controlSize(.mini)
                }
            }
            // Web-path matched hits (only show matched=true, max 6).
            let matchedPaths = probe.webPaths.filter(\.matched).prefix(6)
            if !matchedPaths.isEmpty {
                HStack(spacing: 4) {
                    Image(systemName: "link.badge.plus")
                        .font(.caption2)
                        .foregroundStyle(.red)
                    ForEach(Array(matchedPaths), id: \.path) { p in
                        Text(p.path)
                            .font(.caption2.monospaced())
                            .padding(.horizontal, 4)
                            .background(.red.opacity(0.12))
                            .foregroundStyle(.red)
                            .clipShape(Capsule())
                    }
                }
                .padding(.leading, 120)
            }
            // SMB null-session + share list.
            if let smb = probe.smb, !smb.shares.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Image(systemName: "folder.badge.questionmark")
                            .font(.caption2)
                            .foregroundStyle(smb.nullSession ? .red : .secondary)
                        if smb.nullSession {
                            Text("null-session")
                                .font(.caption2)
                                .padding(.horizontal, 4)
                                .background(.red.opacity(0.12))
                                .foregroundStyle(.red)
                                .clipShape(Capsule())
                        }
                        if let nb = smb.netbiosName {
                            Text(nb)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.tertiary)
                        }
                        if let wg = smb.workgroup {
                            Text("WG: \(wg)")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    HStack(spacing: 4) {
                        ForEach(smb.shares.prefix(8)) { share in
                            Text("\(share.kind == "Disk" ? "📁" : (share.kind == "Printer" ? "🖨️" : "ℹ️")) \(share.name)")
                                .font(.caption2)
                                .padding(.horizontal, 4)
                                .background(.gray.opacity(0.1))
                                .foregroundStyle(.secondary)
                                .clipShape(Capsule())
                        }
                    }
                }
                .padding(.leading, 120)
            }
            // SNMP walk details
            if let snmp = probe.snmp {
                HStack(spacing: 6) {
                    Image(systemName: "rectangle.stack.badge.person.crop")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                    if let community = snmp.community {
                        Text("community=\(community)")
                            .font(.caption2)
                            .padding(.horizontal, 4)
                            .background(.orange.opacity(0.12))
                            .foregroundStyle(.orange)
                            .clipShape(Capsule())
                    }
                    if let name = snmp.sysName {
                        Text(name)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.tertiary)
                    }
                    if !snmp.interfaces.isEmpty {
                        Text("\(snmp.interfaces.count) iface(s)")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
                .padding(.leading, 120)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Finding row

/// Default SLA windows for remediation, expressed as days from
/// `first_seen`. Aligned with industry-typical MSP contracts —
/// Critical 7d, High 30d, Medium 90d, Low 180d. Tweak in one
/// place if customer SLAs differ.
private func slaDays(for severity: FindingSeverity) -> Int {
    switch severity {
    case .critical: return 7
    case .high:     return 30
    case .medium:   return 90
    case .low:      return 180
    case .info:     return 365
    }
}

private struct FindingRow: View {
    let finding: PersistedFinding
    let isPinned: Bool
    let onTogglePin: () -> Void

    /// Days since the finding was first detected. Negative is
    /// theoretically impossible but guards against clock skew.
    private var ageDays: Int {
        let secs = Date().timeIntervalSince(finding.firstSeen)
        return max(0, Int(secs / 86400))
    }

    /// True when the finding has been Open longer than its SLA
    /// window. Drives the "overdue" pill on the row.
    private var slaOverdue: Bool {
        guard case .open = finding.disposition else { return false }
        return ageDays > slaDays(for: finding.finding.severity)
    }

    private var severityColor: Color {
        switch finding.finding.severity {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return .yellow
        case .low:      return .blue
        case .info:     return .gray
        }
    }

    private var dispositionColor: Color {
        switch finding.disposition {
        case .open:           return severityColor
        case .acceptedRisk:   return .gray
        case .fixed:          return .green
        case .falsePositive:  return .secondary
        }
    }

    private var dimmed: Bool {
        switch finding.disposition {
        case .fixed, .falsePositive: return true
        default: return false
        }
    }

    var body: some View {
        HStack(spacing: 10) {
            Button {
                onTogglePin()
            } label: {
                Image(systemName: isPinned ? "pin.fill" : "pin")
                    .foregroundStyle(isPinned ? Color.orange : Color.secondary)
                    .font(.caption)
            }
            .buttonStyle(.plain)
            .help(isPinned ? "Unpin finding" : "Pin to top")
            .accessibilityLabel(isPinned ? "Unpin finding" : "Pin finding to top")
            Image(systemName: "exclamationmark.shield.fill")
                .foregroundStyle(severityColor)
            VStack(alignment: .leading, spacing: 1) {
                Text(finding.finding.title)
                    .font(.callout.weight(.medium))
                    .strikethrough(dimmed, color: .secondary)
                HStack(spacing: 6) {
                    Text(finding.finding.hostIp)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                    if let port = finding.finding.port {
                        Text("port \(port)")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    if let cve = finding.finding.cve {
                        Text(cve)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 4)
                            .background(.red.opacity(0.12))
                            .foregroundStyle(.red)
                            .clipShape(Capsule())
                    }
                    if let cvss = finding.finding.cvss {
                        Text("CVSS \(String(format: "%.1f", cvss))")
                            .font(.caption2)
                            .padding(.horizontal, 4)
                            .background(.gray.opacity(0.12))
                            .foregroundStyle(.secondary)
                            .clipShape(Capsule())
                    }
                    Text("seen \(finding.scanCount)×")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            if slaOverdue {
                let over = ageDays - slaDays(for: finding.finding.severity)
                Text("SLA +\(over)d")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(.red.opacity(0.18))
                    .foregroundStyle(.red)
                    .clipShape(Capsule())
                    .help("Open beyond \(slaDays(for: finding.finding.severity))-day SLA for \(finding.finding.severity.rawValue) findings.")
            }
            // Disposition + severity pills delegated to the shared
            // components — they own the colour + label canon, so
            // any future tweak (new disposition variant, new
            // severity colour) lands once.
            DispositionLabel(disposition: finding.disposition)
            if case .open = finding.disposition {
                SeverityBadge(severity: finding.finding.severity)
            }
            Image(systemName: "chevron.right")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
        }
        .padding(8)
        .background(severityColor.opacity(dimmed ? 0.02 : 0.05))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .opacity(dimmed ? 0.65 : 1.0)
        .contentShape(Rectangle())
    }

    private var dispositionLabel: String {
        switch finding.disposition {
        case .open: return "Open"
        case .acceptedRisk: return "Accepted"
        case .fixed(let auto): return auto ? "Auto-fixed" : "Fixed"
        case .falsePositive: return "False positive"
        }
    }
}
