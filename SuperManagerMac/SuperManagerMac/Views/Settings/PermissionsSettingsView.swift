import AppKit
import SwiftUI

/// Settings tab that shows the macOS-level permissions + system
/// dependencies SuperManager relies on, with one-click jumps
/// into System Settings and a "what to install" panel for
/// missing Homebrew tools.
///
/// Why this exists (Phase 1 finding M4 + the Local-Network
/// permission incident behind it): macOS Sequoia/Tahoe enforce a
/// Local Network privacy gate that silently returns
/// `EHOSTUNREACH` on RFC1918 connects when the app hasn't been
/// approved. The operator has no way from inside the app to see
/// "do we have that permission?". This view surfaces:
///
///   1. Helper version + dev-rpc flag (we already had the RPC;
///      no in-app surface for the answer).
///   2. Homebrew tool readiness via the existing `tools_status`
///      RPC, with per-tool brew-install hints copyable to
///      clipboard. Surfaces the previously-wired-but-invisible
///      `tools_status` end-to-end.
///   3. macOS Local Network permission state (best-effort —
///      Apple deliberately doesn't expose this directly, so the
///      panel deep-links to the relevant System Settings pane).
///
/// Deliberately read-only: this view never *grants* permissions
/// (it can't), it shows status + provides one-click jumps so the
/// operator doesn't have to hunt through System Settings.
struct PermissionsSettingsView: View {
    @Environment(AppState.self) private var appState

    @State private var tools: [ToolInfo] = []
    @State private var loadingTools = false
    @State private var helperVersion: String = ""
    @State private var helperMethods: [String] = []
    @State private var helperDevRpc: Bool = false
    @State private var helperUnreachable: Bool = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                helperCard
                localNetworkCard
                toolsCard
            }
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .task { await refreshAll() }
    }

    // MARK: - Helper

    /// Helper version + dev-rpc flag + reachability. Driven by
    /// the existing `helper_version` RPC. The "Reveal helper
    /// log in Finder" + "Save support bundle" buttons live in
    /// the Help menu already; we link out rather than
    /// duplicating them here per principle P1.
    private var helperCard: some View {
        sectionCard(title: "Privileged helper", systemImage: "shield.lefthalf.filled") {
            if helperUnreachable {
                Label(
                    "Helper isn't reachable. Approve the background daemon under System Settings → General → Login Items, then click Refresh.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            } else {
                LabeledContent("Version", value: helperVersion.isEmpty ? "—" : helperVersion)
                LabeledContent("Dev RPC enabled", value: helperDevRpc ? "yes (development build)" : "no")
                LabeledContent("Advertised methods") {
                    Text("\(helperMethods.count) endpoints")
                        .foregroundStyle(.secondary)
                }
            }
            HStack {
                Button("Refresh") { Task { await refreshHelper() } }
                    .controlSize(.small)
                Spacer()
                Button("Open Login Items in System Settings") {
                    openSystemSettings(pane: "com.apple.LoginItems-Settings.extension")
                }
                .controlSize(.small)
            }
        }
    }

    // MARK: - Local network privacy

    /// macOS doesn't expose a programmatic API to query
    /// Local Network permission state — apps just attempt
    /// connections and observe `EHOSTUNREACH`. We show the
    /// caveat plus a deep-link to the privacy pane so the
    /// operator can check / fix without hunting.
    private var localNetworkCard: some View {
        sectionCard(title: "Local Network privacy", systemImage: "network") {
            Text("macOS Sequoia + Tahoe gate RFC1918 / link-local connects behind the Local Network permission. Without it, the app silently sees `no route to host` on local IPs. Apple doesn't expose a query API, so this panel can't show on/off here — but the button below opens the right pane.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Open Privacy → Local Network…") {
                    openSystemSettings(pane: "com.apple.preference.security?Privacy_LocalNetwork")
                }
                .controlSize(.small)
                Spacer()
            }
        }
    }

    // MARK: - Tools

    /// Homebrew-installed CLI tools we depend on for scans,
    /// VPN, etc. Driven by `tools_status` (was wired-but-
    /// invisible before this tab existed — see Phase 1
    /// verification table).
    private var toolsCard: some View {
        sectionCard(title: "External tools", systemImage: "wrench.and.screwdriver") {
            if loadingTools {
                ProgressView().controlSize(.small)
            } else if tools.isEmpty {
                Text("`tools_status` returned no entries — the engine probe found nothing to report on.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(tools) { t in
                        toolRow(t)
                    }
                }
            }
            HStack {
                Button("Refresh") { Task { await refreshTools() } }
                    .controlSize(.small)
                Spacer()
            }
        }
    }

    private func toolRow(_ t: ToolInfo) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: t.installed ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(t.installed ? .green : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(t.name)
                        .font(.body.weight(.medium))
                    if let path = t.path, !path.isEmpty {
                        Text(path)
                            .font(.caption.monospaced())
                            .foregroundStyle(.tertiary)
                    }
                }
                if let version = t.version, !version.isEmpty {
                    Text(version).font(.caption).foregroundStyle(.secondary)
                }
                if !t.installed, let formula = t.brewFormula, !formula.isEmpty {
                    let install = "brew install \(formula)"
                    HStack(spacing: 4) {
                        Text(install)
                            .font(.caption.monospaced())
                            .foregroundStyle(.orange)
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(install, forType: .string)
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .controlSize(.small)
                        .help("Copy install command to clipboard")
                    }
                }
            }
            Spacer()
        }
        .padding(.vertical, 2)
    }

    // MARK: - Section card chrome

    @ViewBuilder
    private func sectionCard<C: View>(
        title: String,
        systemImage: String,
        @ViewBuilder content: () -> C
    ) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: systemImage)
                    .foregroundStyle(.tint)
                Text(title).font(.headline)
                Spacer()
            }
            content()
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10).fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10).stroke(.separator, lineWidth: 0.5)
        )
    }

    // MARK: - Loading

    private func refreshAll() async {
        await refreshHelper()
        await refreshTools()
    }

    private func refreshHelper() async {
        helperUnreachable = false
        do {
            let result = try await HelperClient.shared.helperVersion()
            helperVersion = (result["version"] as? String) ?? "—"
            helperMethods = (result["methods"] as? [String]) ?? []
            helperDevRpc = (result["dev_rpc"] as? Bool) ?? false
        } catch {
            helperUnreachable = true
            helperVersion = ""
            helperMethods = []
            helperDevRpc = false
        }
    }

    private func refreshTools() async {
        loadingTools = true
        defer { loadingTools = false }
        let result = await appState.loadToolStatus()
        tools = result ?? []
    }

    // MARK: - System Settings deep-links

    /// Open a specific pane in System Settings. The two URL
    /// schemes we use:
    ///   - `x-apple.systempreferences:com.apple.…` works on
    ///     every macOS since 11 for app-installed prefpanes.
    ///   - `x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork`
    ///     is the privacy-pane anchor format Apple documents.
    private func openSystemSettings(pane: String) {
        let urlString = "x-apple.systempreferences:\(pane)"
        if let url = URL(string: urlString) {
            NSWorkspace.shared.open(url)
        }
    }
}
