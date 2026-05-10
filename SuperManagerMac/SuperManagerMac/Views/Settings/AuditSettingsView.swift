import AppKit
import SwiftUI

/// Audit-log viewer.
///
/// Reads `ssh-audit.log` directly off disk (no RPC — the file is in
/// the user's data dir and is public-by-design). Re-loads every 5 s
/// while the pane is visible so a connect that just happened shows up
/// without manual refresh.
///
/// UI shape: a search field, a row-per-entry list, and a footer
/// showing total count + log file path. Failures are coloured red so
/// they pop in a wall of green.
struct AuditSettingsView: View {
    @State private var entries: [AuditEntry] = []
    @State private var search: String = ""
    @State private var actionFilter: AuditEntry.Action? = nil
    @State private var showOnlyFailures = false
    @State private var lastLoaded = Date.distantPast
    /// Drives the auto-reload timer; tied to view lifetime via `.task`.
    @State private var refreshTrigger = 0

    var body: some View {
        VStack(spacing: 0) {
            // Filter strip
            HStack {
                TextField("Search hostname, key, or label",
                          text: $search)
                    .textFieldStyle(.roundedBorder)

                Picker("Action", selection: $actionFilter) {
                    Text("All actions").tag(AuditEntry.Action?.none)
                    ForEach(AuditEntry.Action.allCases, id: \.self) { a in
                        Text(a.rawValue.capitalized)
                            .tag(AuditEntry.Action?.some(a))
                    }
                }
                .pickerStyle(.menu)
                // Wider than 140 — "All actions" plus the picker
                // chevron just fit at 140, so the label was being
                // truncated to "All actio…". 200 leaves comfortable
                // headroom for longer action names too.
                .frame(width: 200)

                Toggle("Failures only", isOn: $showOnlyFailures)
                    .toggleStyle(.checkbox)
            }
            .padding(.bottom, 8)

            // Entry list
            if filtered.isEmpty {
                emptyState
            } else {
                List(filtered) { entry in
                    AuditRow(entry: entry)
                }
                .listStyle(.inset)
                .frame(minHeight: 260)
            }

            // Footer
            HStack(spacing: 12) {
                // Hide the entry-count line when there are zero
                // total entries — "0 of 0 entries" is just noise
                // alongside the empty-state already saying so.
                if !entries.isEmpty {
                    Text("\(filtered.count) of \(entries.count) entries")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Reveal in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([AuditLog.path])
                }
                .controlSize(.small)
                Button("Refresh") { reload() }
                    .controlSize(.small)
            }
            .padding(.top, 6)
        }
        .task {
            // Initial load + auto-reload loop. The view's `.task`
            // closure is automatically cancelled when the pane goes
            // off-screen, so the timer doesn't run forever.
            reload()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                reload()
            }
        }
    }

    /// Filtered entries that satisfy the current search + action +
    /// failures-only constraints. Cheap O(n) over a few thousand rows.
    private var filtered: [AuditEntry] {
        entries.filter { e in
            if showOnlyFailures && e.success { return false }
            if let a = actionFilter, a != e.action { return false }
            if !search.isEmpty {
                let hay = "\(e.hostLabel) \(e.hostname) \(e.keyName)"
                if !hay.localizedCaseInsensitiveContains(search) { return false }
            }
            return true
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 32))
                .foregroundStyle(.tertiary)
            Text(entries.isEmpty
                 ? "No audit entries yet"
                 : "No entries match the current filters")
                .font(.callout)
                .foregroundStyle(.secondary)
            if entries.isEmpty {
                Text(AuditLog.path.path)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 220)
    }

    private func reload() {
        entries = AuditLog.loadAll()
        lastLoaded = Date()
    }
}

/// One row in the audit list. Compact — single line if the row is
/// narrow, two lines on wider windows. Failures highlighted red.
private struct AuditRow: View {
    let entry: AuditEntry

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .medium
        return f
    }()

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: entry.action.icon)
                .frame(width: 20)
                .foregroundStyle(entry.success
                                 ? AnyShapeStyle(HierarchicalShapeStyle.secondary)
                                 : AnyShapeStyle(Color.red))

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(entry.action.rawValue)
                        .font(.caption.monospaced())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(.quaternary)
                        .clipShape(Capsule())
                    Text(entry.keyName)
                        .fontWeight(.medium)
                    Text("→")
                        .foregroundStyle(.tertiary)
                    Text(entry.hostLabel)
                    Text("(\(entry.hostname):\(String(entry.port)))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text(Self.dateFormatter.string(from: entry.timestamp))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if !entry.success {
                Text("FAILED")
                    .font(.caption.bold())
                    .foregroundStyle(.red)
            }
        }
        .padding(.vertical, 2)
    }
}
