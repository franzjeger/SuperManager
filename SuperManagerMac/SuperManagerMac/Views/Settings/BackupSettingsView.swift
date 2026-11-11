import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Backup / Restore pane.
struct BackupSettingsView: View {
    @Environment(AppState.self) private var appState
    @State private var status: BackupStatus = .idle
    @State private var lastResult: String?
    @State private var lastWarning: String?
    @State private var error: String?

    @State private var pendingExportURL: URL?
    @State private var pendingRestoreURL: URL?
    @State private var pendingEncryptedRestoreURL: URL?
    @State private var pendingEncryptedVerifyURL: URL?
    @State private var verifyReport: BackupVerify.Report?

    var body: some View {
        Form {
            Section {
                Text("Back up SSH keys, hosts, VPN profile metadata, and the audit log to an `AES-256-GCM` passphrase-encrypted archive (`.tar.gz.enc`). Restore reverses it on this Mac or another.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section {
                Button {
                    pickExportDestination()
                } label: {
                    Label("Export Encrypted Backup…", systemImage: "tray.and.arrow.up")
                }
                .disabled(isWorking)

                Button {
                    pickRestoreFile()
                } label: {
                    Label("Restore from Backup…", systemImage: "tray.and.arrow.down")
                }
                .disabled(isWorking)

                Button {
                    pickVerifyFile()
                } label: {
                    Label("Verify Backup…", systemImage: "checkmark.seal")
                }
                .disabled(isWorking)
            }

            Section("Portable backup (Mac \u{2194} Linux)") {
                Text("A single `.json` backup that also restores on the Linux build. Carries everything the full archive does, plus the IKEv2/OpenVPN passwords the Mac keeps in the Keychain \u{2014} written owner-only (`0600`).")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Button {
                    runPortableExport()
                } label: {
                    Label("Export Portable Backup\u{2026}", systemImage: "arrow.up.doc")
                }
                .disabled(isWorking)
                Button {
                    runPortableImport()
                } label: {
                    Label("Import Portable Backup\u{2026}", systemImage: "arrow.down.doc")
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

            if let warning = lastWarning {
                Section {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        Text(warning)
                            .font(.callout)
                            .textSelection(.enabled)
                    }
                }
            }
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

            Section {
                CaveatRow(
                    icon: "lock.shield.fill",
                    color: .green,
                    text: "Full backups are encrypted with `PBKDF2-HMAC-SHA256` and `AES-256-GCM` (`SMBKUP01`) using your backup passphrase. On disk, the daemon's `secrets.json` is wrapped with a 256-bit key held in the macOS Data Protection Keychain."
                )
                CaveatRow(
                    icon: "lock.fill",
                    color: .blue,
                    text: "Secrets the app puts directly in the macOS Keychain are NOT in the `.tar.gz.enc` archive, because they are bound to this Mac: IKEv2 passwords and PSKs, OpenVPN and Azure VPN usernames and passwords, and your master password. Use Portable Backup or re-enter those on restore."
                )
                CaveatRow(
                    icon: "arrow.counterclockwise",
                    color: .secondary,
                    text: "Quit SuperManager before restoring. The existing data directory is preserved as `SuperManager.before-restore-<timestamp>` and rolled back automatically if extraction fails."
                )
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: Binding(
            get: { pendingExportURL != nil },
            set: { if !$0 { pendingExportURL = nil } }
        )) {
            if let url = pendingExportURL {
                BackupPassphraseSheet(
                    title: "Encrypt Backup Archive",
                    subtitle: "Choose a passphrase (at least \(Backup.minPasswordLength) characters) to encrypt \(url.lastPathComponent).",
                    requireConfirmation: true,
                    actionTitle: "Export"
                ) { password in
                    pendingExportURL = nil
                    executeExport(to: url, password: password)
                } onCancel: {
                    pendingExportURL = nil
                }
            }
        }
        .sheet(isPresented: Binding(
            get: { pendingEncryptedRestoreURL != nil },
            set: { if !$0 { pendingEncryptedRestoreURL = nil } }
        )) {
            if let url = pendingEncryptedRestoreURL {
                BackupPassphraseSheet(
                    title: "Unlock Encrypted Backup",
                    subtitle: "Enter the passphrase for \(url.lastPathComponent). Current data will be moved aside before extraction.",
                    requireConfirmation: false,
                    actionTitle: "Restore"
                ) { password in
                    pendingEncryptedRestoreURL = nil
                    runRestore(from: url, password: password)
                } onCancel: {
                    pendingEncryptedRestoreURL = nil
                }
            }
        }
        .sheet(isPresented: Binding(
            get: { pendingEncryptedVerifyURL != nil },
            set: { if !$0 { pendingEncryptedVerifyURL = nil } }
        )) {
            if let url = pendingEncryptedVerifyURL {
                BackupPassphraseSheet(
                    title: "Verify Encrypted Backup",
                    subtitle: "Enter the passphrase to authenticate and inspect \(url.lastPathComponent).",
                    requireConfirmation: false,
                    actionTitle: "Verify"
                ) { password in
                    pendingEncryptedVerifyURL = nil
                    executeVerify(url: url, password: password)
                } onCancel: {
                    pendingEncryptedVerifyURL = nil
                }
            }
        }
        .alert("Restore from backup?",
               isPresented: Binding(
                   get: { pendingRestoreURL != nil },
                   set: { if !$0 { pendingRestoreURL = nil } }
               )) {
            Button("Cancel", role: .cancel) { pendingRestoreURL = nil }
            Button("Restore", role: .destructive) {
                if let url = pendingRestoreURL {
                    pendingRestoreURL = nil
                    if Backup.isEncryptedArchive(url) {
                        pendingEncryptedRestoreURL = url
                    } else {
                        runRestore(from: url, password: nil)
                    }
                }
            }
        } message: {
            Text("This replaces the current data directory with the contents of the archive. Your current data will be moved aside (not deleted), and you should quit and re-open SuperManager after restoring.")
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

    private enum BackupStatus {
        case idle
        case exporting
        case restoring
        case verifying

        var label: String {
            switch self {
            case .idle:      return ""
            case .exporting: return "Encrypting archive…"
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

    private func pickExportDestination() {
        let panel = NSSavePanel()
        panel.title = "Export Encrypted SuperManager Backup"
        panel.nameFieldStringValue = Backup.suggestedFilename()
        panel.allowedContentTypes = [
            UTType(filenameExtension: "enc") ?? .data,
            UTType(filenameExtension: "gz") ?? .data,
        ]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false

        guard panel.runModal() == .OK, let url = panel.url else { return }
        pendingExportURL = url
    }

    private func executeExport(to url: URL, password: String) {
        status = .exporting
        lastResult = nil
        lastWarning = nil
        Task.detached(priority: .userInitiated) {
            do {
                let key = try? VPNKeychain.getData(account: VPNKeychain.engineSecretsMasterKeyAccount)
                try Backup.export(to: url, password: password, masterKey: key)
                let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                let sizeStr = ByteCountFormatter.string(fromByteCount: Int64(size),
                                                        countStyle: .file)
                await MainActor.run {
                    self.status = .idle
                    self.lastResult = "Exported encrypted backup (\(sizeStr)) to \(url.lastPathComponent)"
                }
            } catch {
                await MainActor.run {
                    self.status = .idle
                    self.error = error.localizedDescription
                }
            }
        }
    }

    private func runPortableExport() {
        let panel = NSSavePanel()
        panel.title = "Export Portable Backup"
        panel.nameFieldStringValue = "supermanager-portable-backup.json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        guard panel.runModal() == .OK, let url = panel.url else { return }

        status = .exporting
        lastResult = nil
        lastWarning = nil
        Task { @MainActor in
            do {
                let result = try await PortableBackup.export(client: appState.client)
                let exportBytes = result.data
                try await Task.detached(priority: .userInitiated) {
                    try exportBytes.write(to: url, options: [.atomic])
                    try? FileManager.default.setAttributes(
                        [.posixPermissions: 0o600], ofItemAtPath: url.path)
                }.value
                let size = ByteCountFormatter.string(
                    fromByteCount: Int64(result.data.count), countStyle: .file)
                status = .idle
                lastResult = "Exported \(size) to \(url.lastPathComponent)"
                var warnings: [String] = []
                if !result.unreadable.isEmpty {
                    warnings.append(
                        "\(result.unreadable.count) credential(s) could not be read "
                        + "from the Keychain and are NOT in this backup: "
                        + result.unreadable.joined(separator: ", ")
                        + ". Affected profiles: " + result.incompleteProfiles.joined(separator: ", ")
                        + ". Unlock the Keychain or re-enter the credentials, then export again.")
                }
                if !result.unverifiedProfiles.isEmpty {
                    warnings.append(
                        "Credential completeness could not be verified for these OpenVPN profiles "
                        + "because their configuration files are unavailable: "
                        + result.unverifiedProfiles.joined(separator: ", ")
                        + ". Restore access to the configuration files, then export again.")
                }
                lastWarning = warnings.isEmpty ? nil : warnings.joined(separator: "\n\n")
            } catch {
                status = .idle
                self.error = error.localizedDescription
            }
        }
    }

    private func runPortableImport() {
        let panel = NSOpenPanel()
        panel.title = "Import Portable Backup"
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }

        status = .restoring
        lastResult = nil
        lastWarning = nil
        Task { @MainActor in
            do {
                let data = try await Task.detached(priority: .userInitiated) {
                    try Data(contentsOf: url)
                }.value
                let summary = try await PortableBackup.restore(
                    from: data, client: appState.client)
                await appState.refreshProfiles()
                await appState.refreshHosts()
                status = .idle
                lastResult =
                    "Imported \(summary.profiles) profile(s), \(summary.sshKeys) key(s), "
                    + "\(summary.hosts) host(s), \(summary.secrets) secret(s), "
                    + "\(summary.keychainSecrets) Keychain credential(s)"
                if !summary.keychainFailures.isEmpty {
                    lastWarning =
                        "\(summary.keychainFailures.count) credential(s) could not be "
                        + "written to the Keychain — those profiles still have no "
                        + "password and will fail to connect: "
                        + summary.keychainFailures.joined(separator: ", ")
                }
            } catch {
                status = .idle
                self.error = error.localizedDescription
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
        panel.allowedContentTypes = [
            UTType(filenameExtension: "enc") ?? .data,
            .gzip,
            .archive,
            .data,
        ]
        panel.allowsMultipleSelection = false
        panel.message = "Pick a SuperManager backup archive to verify."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        if Backup.isEncryptedArchive(url) {
            pendingEncryptedVerifyURL = url
        } else {
            executeVerify(url: url, password: nil)
        }
    }

    private func executeVerify(url: URL, password: String?) {
        status = .verifying
        verifyReport = nil
        Task.detached {
            let report = BackupVerify.verify(archive: url, password: password)
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
            UTType(filenameExtension: "enc") ?? .data,
            UTType(filenameExtension: "gz") ?? .data,
            .data,
        ]
        panel.allowsMultipleSelection = false
        panel.canChooseFiles = true
        panel.canChooseDirectories = false

        guard panel.runModal() == .OK, let url = panel.url else { return }
        pendingRestoreURL = url
    }

    private func runRestore(from url: URL, password: String?) {
        status = .restoring
        lastResult = nil
        lastWarning = nil
        let state = appState
        Task { @MainActor in
            await DaemonSupervisor.pauseForRestore(appState: state)
            do {
                try await Task.detached(priority: .userInitiated) {
                    try Backup.restore(from: url, password: password)
                }.value
                await DaemonSupervisor.resumeAfterRestore(appState: state)
                status = .idle
                lastResult = "Restored from \(url.lastPathComponent) and reloaded daemon state."
            } catch {
                await DaemonSupervisor.resumeAfterRestore(appState: state)
                status = .idle
                self.error = error.localizedDescription
            }
        }
    }
}

private struct BackupPassphraseSheet: View {
    let title: String
    let subtitle: String
    let requireConfirmation: Bool
    let actionTitle: String
    let onSubmit: (String) -> Void
    let onCancel: () -> Void

    @State private var password = ""
    @State private var confirm = ""
    @State private var validationError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title).font(.headline)
            Text(subtitle)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            SecureField("Passphrase", text: $password)
                .textFieldStyle(.roundedBorder)

            if requireConfirmation {
                SecureField("Confirm Passphrase", text: $confirm)
                    .textFieldStyle(.roundedBorder)
            }

            if let validationError {
                Text(validationError)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                Button(actionTitle) {
                    submit()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(password.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 400)
    }

    private func submit() {
        if requireConfirmation {
            guard password.count >= Backup.minPasswordLength else {
                validationError = "Passphrase must be at least \(Backup.minPasswordLength) characters."
                return
            }
            guard password == confirm else {
                validationError = "Passphrases do not match."
                return
            }
        }
        onSubmit(password)
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
