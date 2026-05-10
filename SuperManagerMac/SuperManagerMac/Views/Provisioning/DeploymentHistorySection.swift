import SwiftUI

/// Deployment history pane shown under the rendered-output card
/// in ProvisioningView. Lists every deploy attempt (succeeded /
/// failed / rolled-back) for the site's primary FortiGate host,
/// with expand-to-show details + Restore button per row.
///
/// Restore reads the saved pre-deploy backup `.conf` and pushes
/// it back via SSH. We surface the backup path in the row so
/// the user can copy / inspect it manually if they prefer.
///
/// This pane closes the safe-deploy loop: render → diff →
/// deploy → backup recorded → if anything went wrong, click
/// "Restore" and SuperManager pushes the pre-deploy snapshot
/// back. Critical for the "I'm comfortable letting SuperManager
/// touch this firewall" trust story.
struct DeploymentHistorySection: View {
    @Environment(AppState.self) private var appState

    /// FortiGate host the deployments were targeted at. The
    /// section is only mounted by ProvisioningView when this
    /// resolves to non-nil, so the optional is upstream-only.
    let hostId: String
    let hostLabel: String

    @State private var expandedDeploymentId: String?
    @State private var pendingRollback: Deployment?
    @State private var rollingBack = false
    @State private var statusBanner: String?

    private var deployments: [Deployment] {
        appState.deploymentHistory[hostId] ?? []
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if let banner = statusBanner {
                Text(banner)
                    .font(.callout)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.tint.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            if deployments.isEmpty {
                emptyState
            } else {
                ForEach(deployments) { deployment in
                    deploymentRow(deployment)
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
        .alert(
            "Restore previous configuration?",
            isPresented: Binding(
                get: { pendingRollback != nil },
                set: { if !$0 { pendingRollback = nil } }
            ),
            presenting: pendingRollback
        ) { deployment in
            Button("Restore", role: .destructive) {
                Task { await performRollback(deployment) }
            }
            Button("Cancel", role: .cancel) {
                pendingRollback = nil
            }
        } message: { deployment in
            let timestamp = deployment.startedAt.formatted(date: .abbreviated, time: .shortened)
            Text("Pushes the pre-deploy backup from \(timestamp) back to \(hostLabel) over SSH. The current configuration will be replaced. A new deployment record will be created with status 'Rolled back'.")
        }
        .task(id: hostId) {
            await appState.loadDeploymentHistory(hostId: hostId)
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "clock.arrow.circlepath")
                .foregroundStyle(.tint)
            Text("Deployment history")
                .font(.headline)
            Spacer()
            if !deployments.isEmpty {
                Text("\(deployments.count) record\(deployments.count == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            Button {
                Task { await appState.loadDeploymentHistory(hostId: hostId) }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.plain)
            .help("Refresh history")
            .accessibilityLabel("Refresh deployment history")
        }
    }

    private var emptyState: some View {
        Text("No deployments yet for \(hostLabel). Use 'Preview diff…' to plan a deploy and 'Deploy' to record one here.")
            .font(.callout)
            .foregroundStyle(.secondary)
            .padding(.vertical, 8)
    }

    @ViewBuilder
    private func deploymentRow(_ deployment: Deployment) -> some View {
        let isExpanded = expandedDeploymentId == deployment.id
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                statusIcon(deployment.status)
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(deployment.startedAt.formatted(date: .abbreviated, time: .shortened))
                            .font(.callout)
                        statusBadge(deployment.status)
                    }
                    Text("\(deployment.templateId) · \(deployment.linesPushed) line\(deployment.linesPushed == 1 ? "" : "s")")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                Spacer()
                Button {
                    expandedDeploymentId = isExpanded ? nil : deployment.id
                } label: {
                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .foregroundStyle(.secondary)
                        .font(.caption)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(isExpanded ? "Collapse deployment" : "Expand deployment")
            }
            if isExpanded {
                expandedDetail(deployment)
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(.background.tertiary)
        )
    }

    @ViewBuilder
    private func statusIcon(_ status: DeploymentStatus) -> some View {
        switch status {
        case .succeeded:
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .accessibilityLabel("Succeeded")
        case .failed:
            Image(systemName: "xmark.octagon.fill")
                .foregroundStyle(.red)
                .accessibilityLabel("Failed")
        case .rolledBack:
            Image(systemName: "arrow.uturn.backward.circle.fill")
                .foregroundStyle(.orange)
                .accessibilityLabel("Rolled back")
        case .running:
            ProgressView().controlSize(.small)
        }
    }

    private func statusBadge(_ status: DeploymentStatus) -> some View {
        let (text, color): (String, Color) = {
            switch status {
            case .succeeded: return ("Succeeded", .green)
            case .failed: return ("Failed", .red)
            case .rolledBack: return ("Rolled back", .orange)
            case .running: return ("Running", .blue)
            }
        }()
        return Text(text)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    @ViewBuilder
    private func expandedDetail(_ deployment: Deployment) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                GridRow {
                    Text("Customer").foregroundStyle(.secondary).font(.caption)
                    Text(deployment.customerSlug)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
                GridRow {
                    Text("Site").foregroundStyle(.secondary).font(.caption)
                    Text(deployment.siteId)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
                GridRow {
                    Text("Started").foregroundStyle(.secondary).font(.caption)
                    Text(deployment.startedAt.formatted(date: .abbreviated, time: .complete))
                        .font(.caption)
                }
                if let finished = deployment.finishedAt {
                    GridRow {
                        Text("Duration").foregroundStyle(.secondary).font(.caption)
                        let elapsed = finished.timeIntervalSince(deployment.startedAt)
                        Text(formatDuration(elapsed))
                            .font(.caption)
                    }
                }
                if let backup = deployment.backupPath {
                    GridRow {
                        Text("Backup").foregroundStyle(.secondary).font(.caption)
                        HStack {
                            Text(backup)
                                .font(.system(.caption2, design: .monospaced))
                                .textSelection(.enabled)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Button {
                                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: backup)])
                            } label: {
                                Image(systemName: "magnifyingglass")
                                    .font(.caption2)
                            }
                            .buttonStyle(.plain)
                            .help("Reveal backup in Finder")
                            .accessibilityLabel("Reveal backup in Finder")
                        }
                    }
                }
                if let err = deployment.error {
                    GridRow {
                        Text("Error").foregroundStyle(.red).font(.caption)
                        Text(err)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .textSelection(.enabled)
                            .lineLimit(3)
                    }
                }
            }
            // Restore is only meaningful when there's a backup
            // and the deployment isn't already a rollback. We
            // permit Restore on Failed deploys too — that's
            // arguably the most important case.
            if deployment.backupPath != nil && deployment.status != .rolledBack {
                HStack {
                    Spacer()
                    Button(role: .destructive) {
                        pendingRollback = deployment
                    } label: {
                        if rollingBack {
                            HStack(spacing: 4) {
                                ProgressView().controlSize(.small)
                                Text("Restoring…")
                            }
                        } else {
                            Label("Restore from backup", systemImage: "arrow.uturn.backward")
                        }
                    }
                    .controlSize(.small)
                    .disabled(rollingBack)
                }
                .padding(.top, 4)
            }
        }
    }

    private func formatDuration(_ seconds: TimeInterval) -> String {
        if seconds < 1 { return "<1s" }
        if seconds < 60 { return String(format: "%.0fs", seconds) }
        let m = Int(seconds) / 60
        let s = Int(seconds) % 60
        return "\(m)m \(s)s"
    }

    private func performRollback(_ deployment: Deployment) async {
        pendingRollback = nil
        guard let backupPath = deployment.backupPath else { return }
        rollingBack = true
        defer { rollingBack = false }
        let result = await appState.rollbackDeployment(
            hostId: deployment.hostId,
            backupPath: backupPath
        )
        if let result {
            statusBanner = result.status == .rolledBack
                ? "Restored backup successfully — \(result.linesPushed) line\(result.linesPushed == 1 ? "" : "s") pushed."
                : "Restore failed: \(result.error ?? "unknown error")"
        } else {
            statusBanner = "Restore failed."
        }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(10))
            statusBanner = nil
        }
    }
}
