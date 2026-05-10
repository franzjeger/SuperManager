import SwiftUI

/// Middle column of the Security section. Lists engagements
/// grouped by status (active vs expired) so the operator sees
/// at a glance which customer-authorisation is currently
/// active for offensive testing.
///
/// "+ New engagement" lives in the footer for discoverability;
/// edit/delete are in the row context menu.
struct SecurityListColumn: View {
    @Environment(AppState.self) private var appState

    @State private var showingAdd = false
    @State private var engagementToEdit: Engagement?
    @State private var pendingDelete: Engagement?

    private var filtered: [Engagement] {
        let global = appState.globalCustomerSlug
        if global.isEmpty { return appState.engagements }
        return appState.engagements.filter { $0.customerSlug == global }
    }
    private var active: [Engagement] {
        filtered.filter(\.isActive)
    }
    private var expired: [Engagement] {
        filtered.filter { !$0.isActive }
    }

    var body: some View {
        VStack(spacing: 0) {
            if filtered.isEmpty {
                emptyState
            } else {
                list
            }
            footer
        }
        .sheet(isPresented: $showingAdd) {
            EngagementEditSheet(engagement: nil)
        }
        .sheet(item: $engagementToEdit) { e in
            EngagementEditSheet(engagement: e)
        }
        .alert(
            "Delete engagement?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            ),
            presenting: pendingDelete
        ) { e in
            Button("Delete \(e.title)", role: .destructive) {
                Task { await appState.deleteEngagement(id: e.id) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { e in
            Text("Removes the engagement record + audit log. Discovered hosts and findings remain in the customer's inventory.")
        }
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No engagements", systemImage: "shield.lefthalf.filled.badge.checkmark")
        } description: {
            Text("Engagements pin a scope + authorization period to security testing actions. Without one, scans run unscoped.")
        } actions: {
            Button {
                showingAdd = true
            } label: {
                Label("New engagement…", systemImage: "plus")
            }
            .controlSize(.large)
            .buttonStyle(.borderedProminent)
        }
    }

    private var list: some View {
        List(selection: Binding(
            get: { appState.selectedEngagementId },
            set: { appState.selectedEngagementId = $0 }
        )) {
            if !active.isEmpty {
                Section("Active") {
                    ForEach(active) { e in
                        row(for: e).tag(Optional(e.id))
                    }
                }
            }
            if !expired.isEmpty {
                Section("Expired") {
                    ForEach(expired) { e in
                        row(for: e).tag(Optional(e.id))
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    @ViewBuilder
    private func row(for e: Engagement) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(e.title)
                    .fontWeight(.medium)
                Spacer()
                statusPill(for: e)
            }
            Text(customerLabel(for: e))
                .font(.caption2)
                .foregroundStyle(.tertiary)
            if e.isActive {
                Text("Expires \(relativeDays(e.expiresAt))")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } else {
                Text("Expired \(e.expiresAt.formatted(date: .abbreviated, time: .omitted))")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .contextMenu {
            Button("Edit…") { engagementToEdit = e }
            Divider()
            Button("Delete…", role: .destructive) { pendingDelete = e }
        }
    }

    private func statusPill(for e: Engagement) -> some View {
        let color: Color = {
            if !e.isActive { return .secondary }
            let daysLeft = e.expiresAt.timeIntervalSinceNow / 86400
            if daysLeft < 7 { return .orange }
            return .green
        }()
        let label: String = e.isActive ? "Active" : "Expired"
        return Text(label)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    private func customerLabel(for e: Engagement) -> String {
        if e.customerSlug.isEmpty {
            return "(ad-hoc — no customer)"
        }
        if let c = appState.customers.first(where: { $0.slug == e.customerSlug }) {
            return c.displayName
        }
        return e.customerSlug
    }

    private func relativeDays(_ date: Date) -> String {
        let days = Int(date.timeIntervalSinceNow / 86400)
        if days < 1 { return "today" }
        if days == 1 { return "tomorrow" }
        return "in \(days) days"
    }

    private var footer: some View {
        HStack {
            Button {
                showingAdd = true
            } label: {
                Label("New engagement", systemImage: "plus")
            }
            .controlSize(.small)
            Spacer()
        }
        .padding(8)
        .background(.background.secondary)
    }
}
