import SwiftUI
import AppKit
import Foundation

/// Custom About window. Replaces the default "About SuperManager"
/// (which would show only Info.plist values) with a richer view
/// surfacing the *runtime* state the user actually cares about
/// when triaging an issue: helper version, helper RPC count,
/// bundled tailscaled version, and a one-click "Copy diagnostics"
/// button that produces a paste-ready blob for support tickets.
///
/// All values are loaded asynchronously on appear — `tailscaled
/// --version` runs the bundled binary, `helper_version` makes a
/// daemon RPC. While loading, the row shows "…"; if the call
/// errors, the error message is surfaced inline (instead of a
/// generic "—") so the user can see what's wrong.
struct AboutSheet: View {
    @Environment(\.dismiss) private var dismiss

    /// Helper version + RPC table, loaded on appear via the
    /// `helper_version` RPC. nil while the call is in-flight.
    @State private var helperVersion: String?
    @State private var helperMethodCount: Int?
    @State private var helperBuildTimestamp: String?
    @State private var helperDevRpc: Bool = false
    @State private var helperError: String?

    /// First line of `tailscaled --version`. Loads in parallel
    /// with the helper RPC.
    @State private var tailscaledVersion: String?
    @State private var tailscaledError: String?

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
    }

    private var appBuild: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
    }

    var body: some View {
        VStack(spacing: 16) {
            // Header — icon + name + version. Mirror of the
            // standard macOS about-window layout to keep things
            // familiar at a glance.
            HStack(alignment: .top, spacing: 16) {
                Image(nsImage: NSImage(named: "AppIcon") ?? NSImage())
                    .resizable()
                    .frame(width: 96, height: 96)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 6) {
                    Text("SuperManager")
                        .font(.title2.weight(.semibold))
                    Text("Version \(appVersion) (build \(appBuild))")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Text("SSH + VPN + Tailscale, native macOS.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            Divider()

            // Component versions. Helper + tailscaled are both
            // bundled binaries we control — surfacing them here
            // is the fastest way for the user to confirm a
            // post-update is actually deployed.
            VStack(alignment: .leading, spacing: 8) {
                componentRow(
                    label: "Privileged helper",
                    value: helperVersionDisplay,
                    error: helperError
                )
                componentRow(
                    label: "Helper RPCs",
                    value: helperMethodCount.map { "\($0) methods\(helperDevRpc ? " (dev RPCs enabled)" : "")" } ?? "…",
                    error: nil
                )
                componentRow(
                    label: "Bundled tailscaled",
                    value: tailscaledVersion ?? "…",
                    error: tailscaledError
                )
                componentRow(
                    label: "Daemon socket",
                    value: "/var/run/supermgrd.sock",
                    error: nil
                )
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Spacer(minLength: 4)

            // Footer buttons — Copy diagnostics emits a small
            // text blob (no logs, no PII) that the user can paste
            // into a support ticket. Close dismisses.
            HStack {
                Button("Copy diagnostics") {
                    copyDiagnostics()
                }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(24)
        .frame(width: 480)
        .task {
            await loadHelperVersion()
            await loadTailscaledVersion()
        }
    }

    @ViewBuilder
    private func componentRow(label: String, value: String, error: String?) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 140, alignment: .leading)
            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .lineLimit(2)
                    .truncationMode(.tail)
            } else {
                Text(value)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
        }
        .font(.callout)
    }

    private var helperVersionDisplay: String {
        if let helperVersion {
            if let ts = helperBuildTimestamp, !ts.isEmpty, ts != "0" {
                return "\(helperVersion) · built \(ts)"
            }
            return helperVersion
        }
        return "…"
    }

    private func loadHelperVersion() async {
        do {
            let r = try await HelperClient.shared.helperVersion()
            self.helperVersion = (r["version"] as? String) ?? "?"
            self.helperBuildTimestamp = r["build_timestamp"] as? String
            self.helperDevRpc = (r["dev_rpc"] as? Bool) ?? false
            if let methods = r["methods"] as? [String] {
                self.helperMethodCount = methods.count
            } else {
                self.helperMethodCount = 0
            }
        } catch {
            self.helperError = error.localizedDescription
        }
    }

    /// Run `tailscaled --version` (or `tailscale --version` as a
    /// fallback) on the bundled binary. Output is multi-line
    /// (version, commit hash, OS), we just take the first line —
    /// it's the human-readable version.
    private func loadTailscaledVersion() async {
        guard let bin = TailscaleClient.bundledDaemonPath else {
            self.tailscaledError = "Tailscale binaries not bundled in this build."
            return
        }
        do {
            let raw = try await runOneShot(bin: bin, args: ["--version"])
            let firstLine = raw
                .components(separatedBy: .newlines)
                .first?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            self.tailscaledVersion = firstLine.isEmpty ? "(unknown)" : firstLine
        } catch {
            self.tailscaledError = error.localizedDescription
        }
    }

    /// Local, simpler version of TailscaleClient.runTask — we
    /// don't want to depend on its private API and we have one
    /// trivial use here.
    private func runOneShot(bin: String, args: [String]) async throws -> String {
        try await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: bin)
            process.arguments = args
            let stdout = Pipe()
            let stderr = Pipe()
            process.standardOutput = stdout
            process.standardError = stderr
            try process.run()
            let outData = stdout.fileHandleForReading.readDataToEndOfFile()
            _ = stderr.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(data: outData, encoding: .utf8) ?? ""
        }.value
    }

    private func copyDiagnostics() {
        var lines: [String] = []
        lines.append("SuperManager \(appVersion) (build \(appBuild))")
        if let v = helperVersion {
            lines.append("Helper: \(v)" + (helperDevRpc ? " (dev RPCs)" : ""))
        } else if let e = helperError {
            lines.append("Helper: ERROR \(e)")
        }
        if let n = helperMethodCount {
            lines.append("Helper RPCs: \(n)")
        }
        if let v = tailscaledVersion {
            lines.append("Bundled tailscaled: \(v)")
        } else if let e = tailscaledError {
            lines.append("Bundled tailscaled: ERROR \(e)")
        }
        let blob = lines.joined(separator: "\n")
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(blob, forType: .string)
    }
}
