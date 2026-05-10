import SwiftUI

/// Fleet view — cross-customer at-a-glance dashboard.
///
/// Aggregates persisted findings across every known customer's
/// findings store. Designed to answer the MSP morning-coffee
/// questions without clicking through each customer:
///   • Who's red right now?
///   • Which Critical findings are oldest?
///   • Which customers haven't been scanned recently?
///
/// Re-uses `findings_summary` per customer (one RPC each, run in
/// parallel) so we can show severity counts without pulling every
/// finding's full body. Drilling into a row sets the global
/// customer context + jumps to Security.
struct FleetView: View {
    @Environment(AppState.self) private var appState

    enum Tab: String, CaseIterable, Identifiable {
        case overview = "Overview"
        case activity = "Activity"
        var id: String { rawValue }
    }

    @State private var rows: [Row] = []
    @State private var loading = true
    @State private var tab: Tab = .overview
    @State private var timelineEvents: [ActivityEvent] = []
    @State private var loadingTimeline = false

    struct Row: Identifiable {
        let customer: Customer
        let summary: StoreSummary?
        let oldestOpenAt: Date?
        /// Top N hosts by risk score for this customer. Up to 3
        /// shown inline on the customer card; the full list lives
        /// in the customer's Security view.
        let topHostRisks: [HostRisk]
        var id: String { customer.slug }

        var totalActive: UInt32 {
            (summary?.critical ?? 0)
                + (summary?.high ?? 0)
                + (summary?.medium ?? 0)
                + (summary?.low ?? 0)
        }

        /// Customer-level risk = max host risk (the worst host
        /// drives perception of the customer). Falls back to 0
        /// when no host risks are computed.
        var topRiskScore: UInt8 {
            topHostRisks.first?.score ?? 0
        }

        var topRiskBand: RiskBand {
            topHostRisks.first?.band
                ?? (totalActive == 0 ? .clean : .low)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            tabBar
            content
        }
        .task { await reload() }
    }

    private var tabBar: some View {
        HStack {
            Picker("", selection: $tab) {
                ForEach(Tab.allCases) { t in
                    Text(t.rawValue).tag(t)
                }
            }
            .pickerStyle(.segmented)
            .frame(width: 220)
            Spacer()
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(.background.secondary)
        .onChange(of: tab) { _, new in
            if new == .activity, timelineEvents.isEmpty {
                Task { await reloadTimeline() }
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch tab {
        case .overview:
            overview
        case .activity:
            activityTab
        }
    }

    @ViewBuilder
    private var overview: some View {
        if loading && rows.isEmpty {
            ProgressView("Aggregating customer fleet…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if rows.isEmpty {
            ContentUnavailableView {
                Label("No customers yet", systemImage: "building.2")
            } description: {
                Text("Create a customer in the Provisioning section to start tracking findings here.")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                VStack(spacing: 8) {
                    kpiRow
                    ForEach(rows) { row in
                        customerCard(row)
                    }
                }
                .padding(14)
            }
        }
    }

    @ViewBuilder
    private var activityTab: some View {
        // Activity is per-customer; require global customer
        // context to be set so we don't try to aggregate an
        // unbounded stream across all customers.
        if appState.globalCustomerSlug.isEmpty {
            // Force the empty state to expand into the remaining
            // vertical space — without this the VStack containing
            // header + tabBar + ContentUnavailableView centers
            // vertically and the header floats away from the top.
            ContentUnavailableView {
                Label("Pick a customer to view activity", systemImage: "person.crop.rectangle.stack")
            } description: {
                Text("Set the global customer context (toolbar) to see a unified timeline of scans, deploys, and finding state changes for that customer.")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if loadingTimeline {
            ProgressView("Loading timeline…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if timelineEvents.isEmpty {
            ContentUnavailableView {
                Label("No activity yet", systemImage: "calendar")
            } description: {
                Text("Run a scan, deploy a config, or change a finding's disposition to populate the timeline.")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("Showing \(timelineEvents.count) events for \(currentCustomerLabel)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button {
                            Task { await reloadTimeline() }
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .controlSize(.small)
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Refresh timeline")
                    }
                    ForEach(timelineEvents) { ev in
                        timelineRow(ev)
                    }
                }
                .padding(14)
            }
        }
    }

    private var currentCustomerLabel: String {
        appState.customers.first { $0.slug == appState.globalCustomerSlug }?.displayName
            ?? appState.globalCustomerSlug
    }

    private func timelineRow(_ ev: ActivityEvent) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: ev.kind.icon)
                .foregroundStyle(.tint)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 1) {
                Text(ev.title)
                    .font(.callout.weight(.medium))
                if !ev.detail.isEmpty {
                    Text(ev.detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            Text(ev.at.formatted(.relative(presentation: .named)))
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(8)
        .background(.background.secondary)
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private func reloadTimeline() async {
        loadingTimeline = true
        defer { loadingTimeline = false }
        let slug = appState.globalCustomerSlug
        if slug.isEmpty { return }
        if let events = await appState.loadActivityTimeline(customerSlug: slug) {
            timelineEvents = events
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "building.2.fill")
                .font(.title2)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 1) {
                Text("Fleet overview")
                    .font(.title2.weight(.semibold))
                Text("\(rows.count) customer\(rows.count == 1 ? "" : "s") · refreshed \(Date().formatted(date: .omitted, time: .shortened))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await reload() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .accessibilityLabel("Refresh fleet")
            .help("Re-fetch every customer's findings summary.")
        }
        .padding(14)
        .background(.background.secondary)
    }

    /// Top-of-fleet aggregate KPIs — sum across every customer.
    private var kpiRow: some View {
        let crit = rows.reduce(0) { $0 + Int($1.summary?.critical ?? 0) }
        let high = rows.reduce(0) { $0 + Int($1.summary?.high ?? 0) }
        let med = rows.reduce(0) { $0 + Int($1.summary?.medium ?? 0) }
        let accepted = rows.reduce(0) { $0 + Int($1.summary?.acceptedRisk ?? 0) }
        let neverScanned = rows.filter { $0.summary?.lastScanAt == nil }.count
        return HStack(spacing: 10) {
            kpi("Critical open", "\(crit)", color: .red, icon: "exclamationmark.octagon.fill")
            kpi("High open", "\(high)", color: .orange, icon: "exclamationmark.triangle.fill")
            kpi("Medium open", "\(med)", color: .yellow, icon: "exclamationmark.circle.fill")
            kpi("Accepted risk", "\(accepted)", color: .gray, icon: "hand.raised.fill")
            kpi("Never scanned", "\(neverScanned)", color: .blue, icon: "questionmark.circle.fill")
        }
    }

    private func kpi(_ label: String, _ value: String, color: Color, icon: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: icon).foregroundStyle(color)
                Text(label).font(.caption2).foregroundStyle(.secondary)
            }
            Text(value)
                .font(.title2.weight(.semibold))
                .foregroundStyle(color)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(color.opacity(0.06))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(color.opacity(0.18), lineWidth: 0.5)
        )
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    @ViewBuilder
    private func customerCard(_ row: Row) -> some View {
        Button {
            // Set the global customer scope so the rest of the
            // app (SSH list, VPN list, Compliance, Provisioning,
            // Security) filters to this customer. We deliberately
            // DO NOT change the active section — earlier behavior
            // jumped to Security on customer click, which surprised
            // users who expected the click to "open this customer"
            // (and there's no Fleet-detail view that would justify
            // the chevron either). Use the sidebar to navigate.
            appState.globalCustomerSlug = row.customer.slug
            UserDefaults.standard.set(row.customer.slug, forKey: "globalCustomerSlug")
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "building.2.fill")
                    .foregroundStyle(.tint)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(row.customer.displayName)
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.primary)
                    HStack(spacing: 8) {
                        Text(row.customer.slug)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.tertiary)
                        if let last = row.summary?.lastScanAt {
                            Text("· last scan \(last.formatted(.relative(presentation: .named)))")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        } else {
                            Text("· never scanned")
                                .font(.caption2)
                                .foregroundStyle(.orange)
                        }
                        if !row.customer.sites.isEmpty {
                            Text("· \(row.customer.sites.count) site\(row.customer.sites.count == 1 ? "" : "s")")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
                Spacer()
                if !row.topHostRisks.isEmpty {
                    riskBadge(row)
                }
                severityPills(row.summary)
                // No chevron — the click only switches global
                // customer scope, it doesn't navigate anywhere,
                // so a chevron would mislead about drill-in.
            }
            .padding(12)
            .background(.background.secondary)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(.separator, lineWidth: 0.5)
            )
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
    }

    /// Compact risk badge for the customer card. Shows the worst
    /// host's score + band; the top-3 risks land in a help tooltip
    /// so the operator can see which hosts are dragging the
    /// customer's number up.
    @ViewBuilder
    private func riskBadge(_ row: Row) -> some View {
        let band = row.topRiskBand
        let tooltip = row.topHostRisks
            .map { "\($0.hostIp): \($0.score) (\($0.hint))" }
            .joined(separator: "\n")
        VStack(alignment: .trailing, spacing: 1) {
            HStack(spacing: 3) {
                Image(systemName: "gauge.with.dots.needle.50percent")
                    .font(.caption2)
                Text("\(row.topRiskScore)")
                    .font(.caption.weight(.bold))
                    .monospacedDigit()
            }
            .foregroundStyle(band.color)
            Text(band.label)
                .font(.caption2.weight(.semibold))
                .padding(.horizontal, 5).padding(.vertical, 1)
                .background(band.color.opacity(0.15))
                .foregroundStyle(band.color)
                .clipShape(Capsule())
        }
        .help(tooltip.isEmpty ? "Risk score 0-100. Higher = worse." : tooltip)
    }

    @ViewBuilder
    private func severityPills(_ summary: StoreSummary?) -> some View {
        let crit = Int(summary?.critical ?? 0)
        let high = Int(summary?.high ?? 0)
        let med = Int(summary?.medium ?? 0)
        let low = Int(summary?.low ?? 0)
        HStack(spacing: 4) {
            if crit > 0 { sevPill("\(crit)", color: .red) }
            if high > 0 { sevPill("\(high)", color: .orange) }
            if med > 0 { sevPill("\(med)", color: .yellow) }
            if low > 0 { sevPill("\(low)", color: .blue) }
            if crit == 0 && high == 0 && med == 0 && low == 0 {
                Text(summary == nil ? "—" : "clean")
                    .font(.caption2)
                    .foregroundStyle(.green)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(.green.opacity(0.12))
                    .clipShape(Capsule())
            }
        }
    }

    private func sevPill(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.18))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    private func reload() async {
        loading = true
        defer { loading = false }
        // In Preview / offline contexts, daemonAvailable is false
        // and the RPC calls would hang. Use the seeded state as-is.
        if !appState.daemonAvailable && !appState.customers.isEmpty {
            rows = appState.customers.map {
                Row(customer: $0, summary: nil, oldestOpenAt: nil, topHostRisks: [])
            }
            return
        }
        await appState.refreshCustomers()
        var newRows: [Row] = []
        for customer in appState.customers {
            // Two RPCs in parallel — summary + risk-by-host.
            async let summaryF = appState.loadFindingsSummary(scope: customer.slug)
            async let risksF   = appState.loadHostRisks(scope: customer.slug)
            let summary = await summaryF
            let risks   = (await risksF) ?? []
            newRows.append(Row(
                customer: customer,
                summary: summary,
                oldestOpenAt: nil,
                topHostRisks: Array(risks.prefix(3))
            ))
        }
        // Sort customers by their top-host risk score (the
        // single-number version of "how bad is this customer").
        // Falls back to legacy critical/high/total ordering when
        // risks aren't computed yet.
        newRows.sort { (a, b) in
            if a.topRiskScore != b.topRiskScore {
                return a.topRiskScore > b.topRiskScore
            }
            let ac = a.summary?.critical ?? 0
            let bc = b.summary?.critical ?? 0
            if ac != bc { return ac > bc }
            let ah = a.summary?.high ?? 0
            let bh = b.summary?.high ?? 0
            if ah != bh { return ah > bh }
            if a.totalActive != b.totalActive {
                return a.totalActive > b.totalActive
            }
            return a.customer.displayName < b.customer.displayName
        }
        rows = newRows
    }
}

#if DEBUG
#Preview("Fleet — populated") {
    FleetView()
        .environment(AppState.previewSeeded)
        .frame(width: 900, height: 600)
}

#Preview("Fleet — empty") {
    FleetView()
        .environment(AppState.previewEmpty)
        .frame(width: 900, height: 600)
}
#endif
