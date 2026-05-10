import SwiftUI

struct KeyDetailView: View {
    @Environment(AppState.self) private var appState
    let keyId: String

    @State private var showingPushSheet = false

    private var key: SshKeySummary? {
        appState.sshKeys.first { $0.id == keyId }
    }

    var body: some View {
        if let key = key {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Header
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(key.name)
                                .font(.title)
                            Text(key.keyType.displayName)
                                .font(.title3)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if key.deployedCount > 0 {
                            Text("Deployed to \(key.deployedCount) host\(key.deployedCount == 1 ? "" : "s")")
                                .padding(.horizontal, 10)
                                .padding(.vertical, 4)
                                .background(.blue.opacity(0.1))
                                .clipShape(Capsule())
                        }
                    }

                    Divider()

                    // Fingerprint
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Fingerprint")
                            .font(.headline)
                        HStack {
                            Text(key.fingerprint)
                                .font(.system(.body, design: .monospaced))
                                .textSelection(.enabled)
                            Button(action: {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(key.fingerprint, forType: .string)
                            }) {
                                Image(systemName: "doc.on.doc")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel("Copy fingerprint")
                        }
                    }

                    // Tags
                    if !key.tags.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Tags")
                                .font(.headline)
                            HStack {
                                ForEach(key.tags, id: \.self) { tag in
                                    Text(tag)
                                        .font(.caption)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(.quaternary)
                                        .clipShape(Capsule())
                                }
                            }
                        }
                    }

                    Divider()

                    // Actions
                    HStack(spacing: 12) {
                        Button("Push to Hosts...") {
                            showingPushSheet = true
                        }

                        Button("Copy Public Key") {
                            Task {
                                // Daemon already exposes the OpenSSH-format
                                // public key via ssh_export_public_key
                                // (server.rs:411). Pull and stuff it into
                                // the system pasteboard.
                                do {
                                    let pubkey: String = try await appState.client.call(
                                        "ssh_export_public_key",
                                        params: ["key_id": keyId]
                                    )
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(pubkey, forType: .string)
                                } catch {
                                    // Surface a small toast-style error rather
                                    // than silently doing nothing.
                                    appState.errorMessage = error.localizedDescription
                                    appState.showingError = true
                                }
                            }
                        }

                        Spacer()

                        Button("Delete Key", role: .destructive) {
                            Task { await appState.deleteKey(keyId) }
                        }
                    }
                }
                .padding(20)
            }
            .sheet(isPresented: $showingPushSheet) {
                PushKeySheet(keyId: keyId)
            }
        } else {
            Text("Key not found")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

struct PushKeySheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    let keyId: String

    @State private var selectedHostIds: Set<String> = []
    @State private var useSudo = false
    @State private var results: [PushResult]?
    @State private var isPushing = false

    var body: some View {
        VStack(spacing: 16) {
            Text("Push Key to Hosts")
                .font(.title2)

            List(appState.sshHosts, selection: $selectedHostIds) { host in
                Text("\(host.label) (\(host.hostname))")
            }
            .frame(minHeight: 200)

            Toggle("Use sudo", isOn: $useSudo)

            if let results = results {
                Divider()
                ForEach(results) { result in
                    HStack {
                        Image(systemName: result.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(result.success ? .green : .red)
                        Text(result.hostLabel)
                        Spacer()
                        Text(result.message)
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    }
                }
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Push") {
                    Task {
                        isPushing = true
                        results = await appState.pushKey(
                            keyId: keyId,
                            hostIds: Array(selectedHostIds),
                            useSudo: useSudo
                        )
                        isPushing = false
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(selectedHostIds.isEmpty || isPushing)
            }
        }
        .padding()
        .frame(width: 500, height: 450)
    }
}
