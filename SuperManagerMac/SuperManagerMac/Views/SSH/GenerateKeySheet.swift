import SwiftUI

/// Two-mode sheet for adding an SSH key. Default mode generates
/// a fresh keypair; the "Import existing" button switches to a
/// picker over candidate keys the daemon found in `~/.ssh`.
///
/// Import is a separate mode rather than its own sheet so the
/// affordance lives next to "Generate" — operators looking for
/// "where do I put my existing key?" find it in the same place
/// they go to make a new one. Surfaces the previously
/// wired-but-invisible `ssh_import_keys_scan` + `ssh_import_key`
/// RPCs.
struct GenerateKeySheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    private enum Mode: String, CaseIterable, Identifiable {
        case generate
        case importExisting

        var id: String { rawValue }
        var label: String {
            switch self {
            case .generate: return "Generate new"
            case .importExisting: return "Import existing"
            }
        }
    }

    @State private var mode: Mode = .generate

    // -- Generate mode state --
    @State private var name = ""
    @State private var keyType = "ed25519"
    @State private var description = ""
    @State private var tagsText = ""
    @FocusState private var firstFieldFocused: Bool

    // -- Import mode state --
    @State private var scanLoading = false
    @State private var candidates: [AppState.ImportCandidate] = []
    @State private var selectedCandidatePath: String?
    @State private var importErrorMessage: String?
    @State private var importBusy = false

    var body: some View {
        VStack(spacing: 16) {
            Picker("", selection: $mode) {
                ForEach(Mode.allCases) { m in
                    Text(m.label).tag(m)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal)

            switch mode {
            case .generate:
                generateForm
            case .importExisting:
                importForm
            }
        }
        .padding()
        .frame(width: 480, height: 460)
        .task {
            try? await Task.sleep(for: .milliseconds(100))
            firstFieldFocused = true
        }
    }

    // MARK: - Generate

    private var generateForm: some View {
        VStack(spacing: 16) {
            Text("Generate SSH key")
                .font(.title2)

            Form {
                TextField("Name", text: $name)
                    .focused($firstFieldFocused)

                Picker("Key type", selection: $keyType) {
                    Text("Ed25519 (recommended)").tag("ed25519")
                    Text("RSA 2048").tag("rsa2048")
                    Text("RSA 4096").tag("rsa4096")
                }

                TextField("Description", text: $description)
                TextField("Tags (comma separated)", text: $tagsText)
            }
            .formStyle(.grouped)

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Generate") {
                    let tags = tagsText
                        .split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                    Task {
                        await appState.generateKey(
                            name: name,
                            keyType: keyType,
                            description: description,
                            tags: tags
                        )
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(name.isEmpty)
            }
        }
    }

    // MARK: - Import

    private var importForm: some View {
        VStack(spacing: 12) {
            Text("Import key from ~/.ssh")
                .font(.title2)
            Text("The daemon scans `~/.ssh` for OpenSSH private keys it can parse. Passphrase-protected keys are listed but can't be imported directly — strip the passphrase with `ssh-keygen -p -f <file>` first.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)

            if scanLoading {
                ProgressView("Scanning…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if candidates.isEmpty {
                ContentUnavailableView(
                    "No importable keys found",
                    systemImage: "key.slash",
                    description: Text("Nothing parseable under `~/.ssh`. Generate a new key instead, or drop a private-key file under `~/.ssh/` and click Rescan.")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(selection: $selectedCandidatePath) {
                    ForEach(candidates) { c in
                        candidateRow(c).tag(Optional(c.path))
                    }
                }
                .listStyle(.bordered)
            }

            if let err = importErrorMessage {
                Text(err)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Button("Rescan") { Task { await rescan() } }
                    .disabled(scanLoading)
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(importBusy ? "Importing…" : "Import") {
                    Task { await importSelected() }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(importBusy || selectedCandidatePath == nil || selectedCandidateIsPassphraseProtected)
            }
        }
        .task { await rescanIfEmpty() }
    }

    private func candidateRow(_ c: AppState.ImportCandidate) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Image(systemName: c.hasPassphrase ? "lock.fill" : "key.fill")
                    .foregroundStyle(c.hasPassphrase ? .orange : .blue)
                Text(c.name).font(.body.weight(.medium))
                Spacer()
                Text(c.keyType)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Text(c.path).font(.caption.monospaced()).foregroundStyle(.tertiary)
            if !c.fingerprint.isEmpty {
                Text(c.fingerprint).font(.caption2.monospaced()).foregroundStyle(.tertiary)
            }
            if c.hasPassphrase {
                Text("Passphrase-protected — strip it first with `ssh-keygen -p -f \(c.path)`")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }
        }
        .padding(.vertical, 2)
    }

    private var selectedCandidateIsPassphraseProtected: Bool {
        guard let p = selectedCandidatePath else { return false }
        return candidates.first(where: { $0.path == p })?.hasPassphrase ?? false
    }

    private func rescanIfEmpty() async {
        guard candidates.isEmpty, !scanLoading else { return }
        await rescan()
    }

    private func rescan() async {
        scanLoading = true
        defer { scanLoading = false }
        importErrorMessage = nil
        candidates = await appState.scanSshDirectory()
        // Auto-select first non-passphrase candidate so the
        // Import button enables itself in the common case.
        if selectedCandidatePath == nil {
            selectedCandidatePath = candidates.first(where: { !$0.hasPassphrase })?.path
        }
    }

    private func importSelected() async {
        guard let path = selectedCandidatePath,
              let c = candidates.first(where: { $0.path == path })
        else { return }
        importBusy = true
        defer { importBusy = false }
        importErrorMessage = nil
        let result = await appState.importSshKey(
            name: c.name,
            keyType: c.keyType,
            publicKey: c.publicKey,
            privateKeyPem: c.privateKeyPem
        )
        if result == nil {
            importErrorMessage = "Couldn't import — daemon refused. Check the helper log for details."
        } else {
            dismiss()
        }
    }
}
