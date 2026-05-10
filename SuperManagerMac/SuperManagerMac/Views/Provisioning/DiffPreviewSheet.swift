import SwiftUI

/// Per-section diff preview shown before a deploy. Three-pane:
///   - Top: summary banner (added / modified / equal counts)
///   - Middle: per-section list (left rail) + selected section's
///     unified diff (right pane)
///   - Bottom: Cancel + Deploy buttons
///
/// Deploy here is the primary blue button — but we explicitly
/// require user confirmation via an alert before pushing. The
/// daemon takes a backup automatically before any line is sent,
/// so even an aborted/wrong deploy can be rolled back.
struct DiffPreviewSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    let hostId: String
    let hostLabel: String
    let templateId: String
    let customerSlug: String
    let siteId: String

    @State private var loading = true
    @State private var preview: AppState.DiffPreviewResult?
    @State private var loadError: String?
    @State private var selectedSectionPath: String?
    @State private var deploying = false
    @State private var deployResult: Deployment?
    @State private var showingDeployConfirm = false
    @State private var deployError: String?

    var body: some View {
        VStack(spacing: 0) {
            header
            if loading {
                loadingState
            } else if let err = loadError {
                errorState(err)
            } else if let preview {
                if let deployResult {
                    deployResultPane(result: deployResult, preview: preview)
                } else {
                    summaryBanner(summary: preview.summary)
                    Divider()
                    HStack(alignment: .top, spacing: 0) {
                        sectionList(preview: preview)
                        Divider()
                        diffPane(preview: preview)
                    }
                }
            }
            footer
        }
        .frame(width: 880, height: 600)
        .task {
            await load()
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "arrow.triangle.branch")
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 0) {
                Text("Preview deployment")
                    .font(.title3.weight(.semibold))
                Text("Target: \(hostLabel) · Template: \(templateId)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(14)
        .background(.background.secondary)
    }

    private var loadingState: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("Connecting to \(hostLabel) and pulling live config…")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorState(_ err: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Could not generate diff", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.red)
            ScrollView {
                Text(err)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(maxHeight: .infinity)
            .padding(12)
            .background(.red.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .padding(20)
    }

    // MARK: - Summary

    private func summaryBanner(summary: AppState.DiffSummary) -> some View {
        HStack(spacing: 16) {
            summaryTile(label: "Sections to add", count: summary.added, color: .green)
            summaryTile(label: "Sections to modify", count: summary.modified, color: .orange)
            summaryTile(label: "Already correct", count: summary.equal, color: .secondary)
            Spacer()
            Text("\(summary.total) section\(summary.total == 1 ? "" : "s") in template")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(12)
    }

    private func summaryTile(label: String, count: UInt32, color: Color) -> some View {
        HStack(spacing: 6) {
            Text("\(count)")
                .font(.title3.weight(.bold))
                .monospacedDigit()
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 0) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Section list

    private func sectionList(preview: AppState.DiffPreviewResult) -> some View {
        // Sort: modifications first (most interesting), then
        // additions, then equals. Within each group alphabetical.
        let sorted = preview.sections.sorted { a, b in
            statusRank(a.status) < statusRank(b.status)
                || (statusRank(a.status) == statusRank(b.status) && a.path < b.path)
        }
        return List(selection: $selectedSectionPath) {
            ForEach(sorted) { section in
                HStack(spacing: 6) {
                    statusIcon(section.status)
                    Text(section.path)
                        .font(.system(.callout, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
                .tag(Optional(section.path))
            }
        }
        .listStyle(.sidebar)
        .frame(width: 320)
        .onChange(of: preview.sections.first?.path) { _, _ in
            // Auto-select the first interesting (modified) section
            // so the right pane has content on open.
            if selectedSectionPath == nil {
                selectedSectionPath = sorted.first { s in
                    s.status == .modified || s.status == .added
                }?.path ?? sorted.first?.path
            }
        }
        .onAppear {
            if selectedSectionPath == nil {
                selectedSectionPath = sorted.first { s in
                    s.status == .modified || s.status == .added
                }?.path ?? sorted.first?.path
            }
        }
    }

    private func statusRank(_ status: AppState.SectionStatus) -> Int {
        switch status {
        case .modified:   return 0
        case .added:      return 1
        case .equal:      return 2
        case .deviceOnly: return 3
        }
    }

    @ViewBuilder
    private func statusIcon(_ status: AppState.SectionStatus) -> some View {
        switch status {
        case .added:
            Image(systemName: "plus.circle.fill")
                .foregroundStyle(.green)
                .font(.caption)
                .accessibilityLabel("Will create")
        case .modified:
            Image(systemName: "arrow.triangle.2.circlepath")
                .foregroundStyle(.orange)
                .font(.caption)
                .accessibilityLabel("Will modify")
        case .equal:
            Image(systemName: "checkmark.circle")
                .foregroundStyle(.secondary)
                .font(.caption)
                .accessibilityLabel("No change")
        case .deviceOnly:
            Image(systemName: "minus.circle")
                .foregroundStyle(.tertiary)
                .font(.caption)
                .accessibilityLabel("Device only")
        }
    }

    // MARK: - Diff pane

    @ViewBuilder
    private func diffPane(preview: AppState.DiffPreviewResult) -> some View {
        if let path = selectedSectionPath,
           let section = preview.sections.first(where: { $0.path == path }) {
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(section.path)
                            .font(.callout.weight(.semibold))
                            .textSelection(.enabled)
                        Spacer()
                        statusBadge(section.status)
                    }
                    .padding(.bottom, 4)
                    if section.status == .equal {
                        Label("This section is already correct on the device.", systemImage: "checkmark.circle")
                            .foregroundStyle(.green)
                            .padding(.vertical, 6)
                    } else if section.status == .added {
                        Text("This section is not present on the device. Deploy will create it.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .padding(.vertical, 4)
                        if let body = section.templateBody {
                            codeBlock(text: body, color: .green)
                        }
                    } else if section.status == .modified {
                        diffText(section.unifiedDiff)
                    }
                }
                .padding(14)
            }
        } else {
            VStack {
                Text("Select a section to view its diff")
                    .foregroundStyle(.tertiary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func statusBadge(_ status: AppState.SectionStatus) -> some View {
        let (text, color): (String, Color) = {
            switch status {
            case .added: return ("Will create", .green)
            case .modified: return ("Will modify", .orange)
            case .equal: return ("No change", .secondary)
            case .deviceOnly: return ("Device only", .gray)
            }
        }()
        return Text(text)
            .font(.caption)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    private func codeBlock(text: String, color: Color) -> some View {
        Text(text)
            .font(.system(.caption, design: .monospaced))
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(10)
            .background(color.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    /// Render a unified-diff transcript with per-line colouring.
    /// Lines starting with `+` get a green tint, `-` gets red,
    /// the rest are neutral. We use a `Text(verbatim:)` pile-up
    /// rather than full AttributedString since we render plain
    /// monospace.
    private func diffText(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(text.split(separator: "\n").enumerated()), id: \.offset) { _, line in
                let str = String(line)
                Text(str)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(diffLineColor(str))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(diffLineBackground(str))
            }
        }
    }

    private func diffLineColor(_ line: String) -> Color {
        if line.hasPrefix("+++") || line.hasPrefix("---") {
            return .secondary
        }
        if line.hasPrefix("+") { return .green }
        if line.hasPrefix("-") { return .red }
        return .primary
    }

    private func diffLineBackground(_ line: String) -> Color {
        if line.hasPrefix("+++") || line.hasPrefix("---") {
            return .clear
        }
        if line.hasPrefix("+") { return .green.opacity(0.08) }
        if line.hasPrefix("-") { return .red.opacity(0.08) }
        return .clear
    }

    // MARK: - Deploy result

    private func deployResultPane(
        result: Deployment,
        preview: AppState.DiffPreviewResult
    ) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: result.status == .succeeded
                      ? "checkmark.seal.fill"
                      : "exclamationmark.triangle.fill")
                    .foregroundStyle(result.status == .succeeded ? .green : .red)
                    .font(.title)
                VStack(alignment: .leading, spacing: 1) {
                    Text(result.status == .succeeded
                         ? "Deployment succeeded"
                         : "Deployment failed")
                        .font(.title3.weight(.semibold))
                    Text("\(result.linesPushed) line\(result.linesPushed == 1 ? "" : "s") pushed")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            if let err = result.error {
                Text(err)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(.red.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            if let backup = result.backupPath {
                HStack {
                    Image(systemName: "archivebox")
                        .foregroundStyle(.secondary)
                    Text("Pre-deploy backup")
                        .font(.callout)
                    Spacer()
                    Text(backup)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                .padding(10)
                .background(.background.tertiary)
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            if result.status == .succeeded {
                Text("A compliance scan was kicked off automatically. Check the Compliance section to see post-deploy posture.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(20)
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            if let err = deployError {
                Label(err, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            Spacer()
            Button(deployResult != nil ? "Close" : "Cancel") { dismiss() }
                .keyboardShortcut(.cancelAction)
            if deployResult == nil {
                Button {
                    showingDeployConfirm = true
                } label: {
                    if deploying {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Deploying…")
                        }
                    } else {
                        Label("Deploy", systemImage: "arrow.up.circle.fill")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(deploying || preview == nil || (preview?.summary.modified == 0 && preview?.summary.added == 0))
                .alert(
                    "Deploy to \(hostLabel)?",
                    isPresented: $showingDeployConfirm
                ) {
                    Button("Deploy", role: .destructive) {
                        Task { await deploy() }
                    }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    let summary = preview?.summary
                    Text("\(summary?.added ?? 0) section(s) will be created and \(summary?.modified ?? 0) modified. A backup of the current config is taken automatically before pushing.")
                }
            }
        }
        .padding(14)
        .background(.background.secondary)
    }

    // MARK: - Actions

    private func load() async {
        loading = true
        loadError = nil
        defer { loading = false }
        let result = await appState.diffPreview(
            hostId: hostId,
            templateId: templateId,
            customerSlug: customerSlug,
            siteId: siteId
        )
        if let result {
            preview = result
        } else {
            loadError = appState.errorMessage.isEmpty
                ? "Diff preview failed. The host may be unreachable, or SSH is not yet configured."
                : appState.errorMessage
        }
    }

    private func deploy() async {
        deploying = true
        deployError = nil
        defer { deploying = false }
        let result = await appState.deployTemplate(
            hostId: hostId,
            templateId: templateId,
            customerSlug: customerSlug,
            siteId: siteId
        )
        if let result {
            deployResult = result
        } else {
            deployError = appState.errorMessage.isEmpty
                ? "Deploy failed."
                : appState.errorMessage
        }
    }
}
