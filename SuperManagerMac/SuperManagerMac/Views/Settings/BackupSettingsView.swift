import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Backup / Restore pane.
///
/// Action buttons drive `NSSavePanel` / `NSOpenPanel`; the actual
/// archive work is in `Services/Backup.swift`. We keep the view thin
/// — it just orchestrates pickers, surfaces progress, and shows
/// success / failure inline.
struct BackupSettingsView: View {
    @State private var status: BackupStatus = .idle
    @State private var lastResult: String?
    @State private var error: String?

    /// Confirmation alert state. Restore needs the user to acknowledge
    /// that any unsaved daemon state will be lost.
    @State private var pendingRestoreURL: URL?
    /// Dress-rehearsal result, rendered as a per-check list.
    @State private var verifyReport: BackupVerify.Report?

    var body: some View {
        Form {
            Section {
                Text("Back up SSH keys, hosts, VPN profile metadata, and the audit log to a single `.tar.gz` archive. Restore reverses it on this Mac or another.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section {
                Button {
                    runExport()
                } label: {
                    Label("Export Backup…", systemImage: "tray.and.arrow.up")
                }
                .disabled(isWorking)

                Button {
                    pickRestoreFile()
                } label: {
                    Label("Restore from Backup…", systemImage: "tray.and.arrow.down")
                }
                .disabled(isWorking)

                // Dress rehearsal: extract to a scratch dir and run the
                // checks a restore would care about, without touching
                // the live data dir. Exists so a broken archive is found
                // the day it is taken, not the day it is needed.
                Button {
                    pickVerifyFile()
                } label: {
                    Label("Verify Backup…", systemImage: "checkmark.seal")
                }
                .disabled(isWorking)
            }

            if let report = verifyReport {
                Section("Verification") {
                    ForEach(report.checks) { check in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: symbol(for: check.status))
                                .foregroundStyle(color(for: check.status))
                            VStack(alignment: .leading, spacing: 1) {
                                Text(check.title).font(.callout.weight(.medium))
                                Text(check.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }
            }

            // Status / result
            if let result = lastResult {
                Section {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                        Text(result)
                            .font(.callout)
                            .textSelection(.enabled)
                    }
                }
            }
            if isWorking {
                Section {
                    HStack {
                        ProgressView().controlSize(.small)
                        Text(status.label)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            // Caveats — important enough to be visible from the page,
            // not buried in a docs link.
            Section {
                CaveatRow(
                    icon: "exclamationmark.triangle.fill",
                    color: .orange,
                    text: "The archive is a tar of the whole data directory, so treat everything in it as secret. That includes the daemon's secret store as plain text (SSH private keys and host passwords, FortiGate API tokens, UniFi controller passwords, WireGuard private keys and peer PSKs), your .ovpn files with their embedded client keys, and any notification webhooks and API keys. Keep it on encrypted storage."
                )
                CaveatRow(
                    icon: "lock.fill",
                    color: .blue,
                    text: "Secrets the app puts in the macOS Keychain are NOT in the archive, because they are bound to this Mac: IKEv2 passwords and PSKs, OpenVPN and Azure VPN usernames and passwords, and your master password. You re-enter those on restore."
                )
                CaveatRow(
                    icon: "arrow.counterclockwise",
                    color: .secondary,
                    text: "Quit SuperManager before restoring. The existing data directory is preserved as `SuperManager.before-restore-<timestamp>` in case you need to roll back."
                )
            }
        }
        .formStyle(.grouped)
        .alert("Restore from backup?",
               isPresented: Binding(
                   get: { pendingRestoreURL != nil },
                   set: { if !$0 { pendingRestoreURL = nil } }
               )) {
            Button("Cancel", role: .cancel) { pendingRestoreURL = nil }
            Button("Restore", role: .destructive) {
                if let url = pendingRestoreURL {
                    pendingRestoreURL = nil
                    runRestore(from: url)
                }
            }
        } message: {
            Text("This replaces the current data directory with the contents of the archive. Your current data will be moved aside (not deleted), but you'll need to quit and re-open SuperManager for the daemon to pick up the restored state.")
        }
        .alert("Error",
               isPresented: Binding(
                   get: { error != nil },
                   set: { if !$0 { error = nil } }
               )) {
            Button("OK") { error = nil }
        } message: {
            Text(error ?? "")
        }
    }

    // MARK: - State

    private enum BackupStatus {
        case idle
        case exporting
        case restoring
        case verifying

        var label: String {
            switch self {
            case .idle:      return ""
            case .exporting: return "Creating archive…"
            case .restoring: return "Restoring archive…"
            case .verifying: return "Verifying archive…"
            }
        }
    }

    private var isWorking: Bool {
        if case .idle = status { return false }
        return true
    }

    // MARK: - Actions

    private func runExport() {
        let panel = NSSavePanel()
        panel.title = "Export SuperManager Backup"
        panel.nameFieldStringValue = Backup.suggestedFilename()
        panel.allowedContentTypes = [
            UTType(filenameExtension: "gz") ?? .data,
        ]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false

        guard panel.runModal() == .OK, let url = panel.url else { return }

        status = .exporting
        lastResult = nil
        Task.detached(priority: .userInitiated) {
            do {
                try await Backup.export(to: url)
                let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                let sizeStr = ByteCountFormatter.string(fromByteCount: Int64(size),
                                                        countStyle: .file)
                await MainActor.run {
                    self.status = .idle
                    self.lastResult = "Exported \(sizeStr) to \(url.lastPathComponent)"
                }
            } catch {
                await MainActor.run {
                    self.status = .idle
                    self.error = error.localizedDescription
                }
            }
        }
    }

    private func symbol(for status: BackupVerify.Check.Status) -> String {
        switch status {
        case .pass: return "checkmark.circle.fill"
        case .warn: return "exclamationmark.triangle.fill"
        case .fail: return "xmark.octagon.fill"
        }
    }

    private func color(for status: BackupVerify.Check.Status) -> Color {
        switch status {
        case .pass: return .green
        case .warn: return .orange
        case .fail: return .red
        }
    }

    private func pickVerifyFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.gzip, .archive, .data]
        panel.allowsMultipleSelection = false
        panel.message = "Pick a SuperManager backup archive to verify."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        status = .verifying
        verifyReport = nil
        Task.detached {
            // Off the main actor — tar + extraction of a large archive
            // shouldn't freeze the pane.
            let report = BackupVerify.verify(archive: url)
            await MainActor.run {
                verifyReport = report
                status = .idle
            }
        }
    }

    private func pickRestoreFile() {
        let panel = NSOpenPanel()
        panel.title = "Choose a SuperManager Backup"
        panel.allowedContentTypes = [
            UTType(filenameExtension: "gz") ?? .data,
        ]
        panel.allowsMultipleSelection = false
        panel.canChooseFiles = true
        panel.canChooseDirectories = false

        guard panel.runModal() == .OK, let url = panel.url else { return }
        pendingRestoreURL = url
    }

    private func runRestore(from url: URL) {
        status = .restoring
        lastResult = nil
        Task.detached(priority: .userInitiated) {
            do {
                try await Backup.restore(from: url)
                await MainActor.run {
                    self.status = .idle
                    self.lastResult = "Restored from \(url.lastPathComponent). Quit and re-open SuperManager to load the restored state."
                }
            } catch {
                await MainActor.run {
                    self.status = .idle
                    self.error = error.localizedDescription
                }
            }
        }
    }
}

private struct CaveatRow: View {
    let icon: String
    let color: Color
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .frame(width: 18)
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }
}
