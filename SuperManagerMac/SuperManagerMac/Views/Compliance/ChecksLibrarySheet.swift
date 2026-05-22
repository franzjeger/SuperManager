import SwiftUI

/// Browser for the full compliance check library — built-in
/// CIS-FortiOS-7.4 checks (FortiGate REST-API baseline) and
/// CIS-Linux-4.0 checks (Linux SSH baseline, since 1.12c), plus
/// any user-supplied TOML overlays from
/// `~/Library/Application Support/SuperManager/checks/`.
///
/// Layout:
///   - Left rail: category list (Authentication, Cryptography,
///     Logging, …) with check counts.
///   - Right pane: filtered checks for the selected category,
///     each expandable to show description, CIS reference, and
///     remediation snippet (with copy-to-clipboard).
///
/// Search field at the top filters by check title, description,
/// and CIS reference across all categories. Clears category
/// selection so results from any category surface.
struct ChecksLibrarySheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var searchText = ""
    @State private var selectedCategory: String?
    @FocusState private var searchFocused: Bool

    private var checks: [AppState.ComplianceCheckDefinition] {
        appState.complianceCheckLibrary
    }

    private var filtered: [AppState.ComplianceCheckDefinition] {
        if !searchText.isEmpty {
            return checks.filter { c in
                c.title.localizedCaseInsensitiveContains(searchText) ||
                    c.description.localizedCaseInsensitiveContains(searchText) ||
                    (c.cisReference?.localizedCaseInsensitiveContains(searchText) ?? false) ||
                    c.category.localizedCaseInsensitiveContains(searchText)
            }
        }
        if let cat = selectedCategory {
            return checks.filter { $0.category == cat }
        }
        return checks
    }

    private var categories: [(name: String, count: Int)] {
        let grouped = Dictionary(grouping: checks) { $0.category }
        return grouped.keys.sorted().map { ($0, grouped[$0]?.count ?? 0) }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            HStack(alignment: .top, spacing: 0) {
                categoryRail
                Divider()
                checksList
            }
        }
        .frame(width: 760, height: 560)
        .task {
            // Always refresh on open — picks up TOML user overlays
            // edited since last open.
            await appState.loadComplianceCheckLibrary()
            try? await Task.sleep(for: .milliseconds(100))
            searchFocused = true
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "books.vertical")
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 0) {
                Text("Checks Library")
                    .font(.title3.weight(.semibold))
                Text("\(checks.count) checks across \(categories.count) categories")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            TextField("Search…", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .frame(width: 220)
                .focused($searchFocused)
            Button("Done") { dismiss() }
                .keyboardShortcut(.cancelAction)
                .buttonStyle(.borderedProminent)
        }
        .padding(14)
        .background(.background.secondary)
    }

    private var categoryRail: some View {
        List(selection: $selectedCategory) {
            Text("All checks")
                .tag(nil as String?)
                .listRowSeparator(.hidden)
            Section("Categories") {
                ForEach(categories, id: \.name) { entry in
                    HStack {
                        Text(entry.name)
                        Spacer()
                        Text("\(entry.count)")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .monospacedDigit()
                    }
                    .tag(Optional(entry.name))
                }
            }
        }
        .listStyle(.sidebar)
        .frame(width: 220)
    }

    private var checksList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 6) {
                if filtered.isEmpty {
                    ContentUnavailableView.search(text: searchText)
                        .frame(maxWidth: .infinity, minHeight: 200)
                } else {
                    ForEach(filtered) { check in
                        CheckLibraryRow(check: check)
                    }
                }
            }
            .padding(14)
        }
    }
}

/// One expandable row in the library. Compact by default; click
/// to expand for full description + remediation.
private struct CheckLibraryRow: View {
    let check: AppState.ComplianceCheckDefinition
    @State private var expanded = false

    private var severityColor: Color {
        switch check.severity {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return .yellow
        case .low:      return .blue
        case .info:     return .secondary
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(check.title)
                        .font(.callout.weight(.semibold))
                    HStack(spacing: 6) {
                        Text(check.category)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        if let cis = check.cisReference {
                            Text("CIS \(cis)")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                        Text(check.framework)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
                Spacer()
                Text(check.severity.rawValue.capitalized)
                    .font(.caption2)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(severityColor.opacity(0.15))
                    .foregroundStyle(severityColor)
                    .clipShape(Capsule())
                Button {
                    expanded.toggle()
                } label: {
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .foregroundStyle(.secondary)
                        .font(.caption)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(expanded ? "Collapse check details" : "Expand check details")
            }
            if expanded {
                Divider()
                Text(check.description)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let remediation = check.remediation, !remediation.isEmpty {
                    HStack {
                        Text("Remediation")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(remediation, forType: .string)
                        }
                        .controlSize(.mini)
                    }
                    Text(remediation)
                        .font(.system(.caption, design: .monospaced))
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.black.opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                        .textSelection(.enabled)
                }
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(.background.tertiary)
        )
    }
}
