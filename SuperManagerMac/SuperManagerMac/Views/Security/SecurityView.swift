import SwiftUI

/// Detail panel for the Security section. Shows the selected
/// engagement's metadata + a Discovery panel that runs passive
/// network scans and renders the host inventory live.
///
/// Layout (top-to-bottom):
///   1. Engagement header card (title, scope, expiry, last 5 events)
///   2. Discovery panel (Run scan / interfaces / host list)
///   3. Audit log (collapsible)
struct SecurityView: View {
    @Environment(AppState.self) private var appState

    private var engagement: Engagement? {
        guard let id = appState.selectedEngagementId else { return nil }
        return appState.engagements.first { $0.id == id }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let e = engagement {
                    headerCard(e)
                    DiscoveryPanel(engagement: e)
                    auditLogCard(e)
                } else {
                    selectPrompt
                }
            }
            .padding(20)
        }
    }

    private var selectPrompt: some View {
        EmptyStateView(
            systemImage: "shield.lefthalf.filled.badge.checkmark",
            title: "Select an engagement to begin",
            hint: "An engagement scopes a customer's findings and holds the evidence from any scans you run against it."
        )
    }

    @ViewBuilder
    private func headerCard(_ e: Engagement) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(e.title).font(.title2.weight(.semibold))
                    HStack(spacing: 12) {
                        if !e.customerSlug.isEmpty {
                            Label(e.customerSlug, systemImage: "building.2")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                        if !e.authorizedBy.isEmpty {
                            Label(e.authorizedBy, systemImage: "person.badge.shield.checkmark")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 6) {
                    StatusPill(
                        status: .engagement(e),
                        label: e.isActive
                            ? "Active · expires \(e.expiryPhrase)"
                            : "Expired"
                    )
                    if let s = e.schedule {
                        let isPast = s.nextScanAt <= Date()
                        // Past nextScanAt happens when the scheduler
                        // can't fire — most often because scope is
                        // empty or the daemon hasn't woken yet.
                        // "Overdue" makes the cause clear.
                        let nextLabel: String = isPast
                            ? (e.scopeCidrs.isEmpty ? "Blocked — empty scope" : "Due now")
                            : "next \(s.nextScanAt.formatted(.relative(presentation: .named)))"
                        let chipColor: Color = isPast ? .orange : .accentColor
                        Label("\(s.cadence.label) · \(nextLabel)", systemImage: "clock.arrow.2.circlepath")
                            .font(.caption2)
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(chipColor.opacity(0.12))
                            .foregroundStyle(chipColor)
                            .clipShape(Capsule())
                    }
                }
            }
            if !e.scopeCidrs.isEmpty || !e.scopeHosts.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Scope").font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                    if !e.scopeCidrs.isEmpty {
                        HStack(alignment: .top, spacing: 6) {
                            Text(e.scopeCidrs.joined(separator: " · "))
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                            CopyButton(
                                value: e.scopeCidrs.joined(separator: "\n"),
                                helpText: "Copy scope CIDRs"
                            )
                        }
                    }
                    if !e.scopeHosts.isEmpty {
                        HStack(alignment: .top, spacing: 6) {
                            Text(e.scopeHosts.joined(separator: " · "))
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                            CopyButton(
                                value: e.scopeHosts.joined(separator: "\n"),
                                helpText: "Copy scope hostnames"
                            )
                        }
                    }
                }
            }
            if !e.exclusions.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Exclusions").font(.subheadline.weight(.semibold)).foregroundStyle(.red)
                    Text(e.exclusions.joined(separator: " · "))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            }
            if !e.allowedTechniques.isEmpty {
                FlowChips(items: e.allowedTechniques.map(\.label))
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
    }

    @ViewBuilder
    private func auditLogCard(_ e: Engagement) -> some View {
        if !e.log.isEmpty {
            DetailSection(title: "Audit log") {
                VStack(alignment: .leading, spacing: 8) {
                ForEach(e.log.suffix(20).reversed()) { event in
                    HStack(alignment: .top, spacing: 8) {
                        Text(event.at.formatted(date: .abbreviated, time: .shortened))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .frame(width: 130, alignment: .leading)
                        Text(event.technique.label)
                            .font(.caption2.weight(.semibold))
                            .frame(width: 110, alignment: .leading)
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(event.action).font(.caption)
                            Text("\(event.findings) result\(event.findings == 1 ? "" : "s") · \(event.notes)")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
                }
                .padding(14)
                .background(
                    RoundedRectangle(cornerRadius: 10)
                        .fill(.background.secondary)
                )
            }
        }
    }
}

/// Wrapping chip-list (for technique badges).
private struct FlowChips: View {
    let items: [String]
    var body: some View {
        let columns = [GridItem(.adaptive(minimum: 110), spacing: 6)]
        LazyVGrid(columns: columns, alignment: .leading, spacing: 4) {
            ForEach(items, id: \.self) { item in
                Text(item)
                    .font(.caption2)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.tint.opacity(0.12))
                    .foregroundStyle(.tint)
                    .clipShape(Capsule())
            }
        }
    }
}
