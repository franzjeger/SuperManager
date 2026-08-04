import AppKit
import SwiftUI

/// Install-missing-tools UI, reusable wherever the operator runs into a
/// tool that isn't there.
///
/// Replaces the old pattern of printing a `brew install` line with a
/// Copy Command button. The app knows what is missing and can install
/// it; making the operator paste shell into Terminal is a support
/// burden and a poor first run.
struct DependencyCard: View {
    /// Show only these tools. `nil` shows everything missing — used by
    /// the Settings pane; the VPN detail view passes the one tool that
    /// profile needs.
    var only: [String]? = nil
    /// Called after a successful install so the caller can re-check.
    var onInstalled: (() -> Void)? = nil

    @State private var installing: String?
    @State private var failure: String?
    /// Bumped after each install to force `isInstalled` to be re-read —
    /// it hits the filesystem, so nothing else would invalidate it.
    @State private var refresh = 0

    private var tools: [Dependencies.Tool] {
        _ = refresh
        let missing = Dependencies.missing
        guard let only else { return missing }
        return missing.filter { only.contains($0.id) }
    }

    var body: some View {
        if !tools.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                if Dependencies.brewPath == nil {
                    // We never install Homebrew silently — it is a large
                    // third-party install the user should start knowingly.
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Homebrew is required").font(.callout.weight(.medium))
                            Text("SuperManager installs these tools through Homebrew. Install it once from brew.sh, then come back.")
                                .font(.caption).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Button("Open brew.sh") {
                                if let u = URL(string: "https://brew.sh") { NSWorkspace.shared.open(u) }
                            }
                            .controlSize(.small)
                            .padding(.top, 2)
                        }
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    }
                }

                ForEach(tools) { tool in
                    row(tool)
                    if tool.id != tools.last?.id { Divider() }
                }

                if let failure {
                    Text(failure)
                        .font(.caption.monospaced())
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                        .lineLimit(6)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(12)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    @ViewBuilder
    private func row(_ tool: Dependencies.Tool) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "shippingbox")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(tool.feature).font(.callout.weight(.medium))
                if let note = tool.manualNote {
                    Text(note)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("Not installed — needed only for this VPN type.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if installing == tool.id {
                ProgressView().controlSize(.small)
            } else if tool.formula != nil {
                Button("Install") { install(tool) }
                    .controlSize(.small)
                    .disabled(Dependencies.brewPath == nil || installing != nil)
            }
        }
    }

    private func install(_ tool: Dependencies.Tool) {
        failure = nil
        installing = tool.id
        Task {
            defer { installing = nil }
            do {
                _ = try await Dependencies.install(tool)
                refresh += 1
                onInstalled?()
            } catch {
                failure = error.localizedDescription
            }
        }
    }
}
