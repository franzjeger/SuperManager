import AppKit
import SwiftUI

struct EditHostSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    let host: SshHostSummary

    @State private var label: String = ""
    @State private var hostname: String = ""
    @State private var port: UInt16 = 22
    @State private var username: String = ""
    @State private var group: String = ""
    @State private var deviceType: DeviceType = .linux
    /// The original wire string when the host's type was unrecognised
    /// on decode. Cleared when the operator explicitly picks a new
    /// type from the picker. The write path (updateHost) sends this
    /// back to the engine instead of `deviceType.rawValue`, preventing
    /// the silent write-amplification that would otherwise permanently
    /// overwrite the engine's type with "custom" on first save.
    @State private var unrecognizedDeviceTypeRaw: String? = nil
    @State private var authMethod: AuthMethod = .key
    @State private var selectedKeyId: String?
    @State private var password: String = ""
    /// Empty means "keep whatever is stored" — the same contract the
    /// password field above has. Never pre-filled: the certificate lives
    /// in the keychain and the summary only carries a presence flag.
    @State private var certificate: String = ""
    @State private var showingNewCustomer = false
    @State private var slugsBeforeAdd: Set<String> = []
    @FocusState private var firstFieldFocused: Bool

    var body: some View {
        VStack(spacing: 16) {
            Text("Edit Host")
                .font(.title2)

            Form {
                TextField("Label", text: $label)
                    .focused($firstFieldFocused)
                TextField("Hostname / IP", text: $hostname)
                TextField("Port", value: $port, format: .number)
                TextField("Username", text: $username)
                // Group is a customer-association key (group == customer slug)
                // that the HostIndex and every customer filter rely on. A bare
                // free-text field let an operator silently type a non-slug and
                // sever the host from its customer; use the same slug-bound
                // picker as AddHostSheet instead.
                groupPicker

                Picker("Device Type", selection: $deviceType) {
                    ForEach(DeviceType.allCases, id: \.self) { type in
                        Text(type.displayName).tag(type)
                    }
                }
                // Clear the carried raw string the moment the
                // operator makes an explicit picker choice — from
                // that point the rawValue of their selection is
                // the authoritative type, not the engine's original.
                .onChange(of: deviceType) {
                    unrecognizedDeviceTypeRaw = nil
                }

                Picker("Auth Method", selection: $authMethod) {
                    ForEach(AuthMethod.allCases, id: \.self) { method in
                        Text(method.displayName).tag(method)
                    }
                }

                // See AddHostSheet: certificate auth needs the key picker
                // as well as a certificate, so these are three
                // independent conditions rather than a two-way branch.
                if authMethod.requiresKey {
                    Picker("SSH Key", selection: $selectedKeyId) {
                        Text("None").tag(nil as String?)
                        ForEach(appState.sshKeys) { key in
                            Text("\(key.name) (\(key.keyType.displayName))").tag(key.id as String?)
                        }
                    }
                }
                if authMethod == .certificate {
                    certificateField
                }
                if authMethod == .password {
                    SecureField("Password (leave empty to keep current)", text: $password)
                }
            }
            .formStyle(.grouped)

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Save") {
                    Task {
                        await appState.updateHost(
                            id: host.id,
                            label: label,
                            hostname: hostname,
                            port: port,
                            username: username,
                            group: group,
                            deviceType: deviceType,
                            unrecognizedDeviceTypeRawValue: unrecognizedDeviceTypeRaw,
                            authMethod: authMethod,
                            authKeyId: authMethod.requiresKey ? selectedKeyId : nil,
                            password: authMethod == .password ? password : nil,
                            certificate: authMethod == .certificate ? certificate : nil
                        )
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(label.isEmpty || hostname.isEmpty || !certificateInputComplete)
            }
        }
        .padding()
        .frame(width: 450, height: 500)
        .onAppear {
            label = host.label
            hostname = host.hostname
            port = host.port
            username = host.username
            group = host.group
            deviceType = host.deviceType
            unrecognizedDeviceTypeRaw = host.unrecognizedDeviceTypeRawValue
            authMethod = host.authMethod
            selectedKeyId = host.authKeyId
        }
        .task {
            try? await Task.sleep(for: .milliseconds(100))
            firstFieldFocused = true
        }
    }

    /// Certificate input. Mirrors `AddHostSheet.certificateField` but with
    /// edit semantics: the prompt reflects whether one is already stored,
    /// and leaving the field empty keeps it.
    @ViewBuilder
    private var certificateField: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(host.hasCertificate ? "Replace certificate" : "Certificate")
                Spacer()
                Button("Load from file…") { loadCertificateFromFile() }
                    .controlSize(.small)
            }
            TextEditor(text: $certificate)
                .frame(minHeight: 64)
                .font(.system(.caption, design: .monospaced))
            Text(certificateHelpText)
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
    }

    /// Spells out the empty-field contract, which differs depending on
    /// whether this host already has a certificate: keeping the stored one
    /// is fine, but a host switched *to* certificate auth with no stored
    /// certificate would connect by plain key and silently look like it
    /// worked.
    private var certificateHelpText: String {
        if host.hasCertificate {
            return "A certificate is already stored. Leave this empty to keep it, or paste a new `*-cert.pub` to replace it."
        }
        return "Contents of the CA-signed `*-cert.pub` file — the certificate, not the public key. Required, since this host has none stored yet."
    }

    /// See `AddHostSheet.certificateInputComplete`. The edit sheet also
    /// accepts an empty field when a certificate is already stored, since
    /// that means "keep it".
    private var certificateInputComplete: Bool {
        guard authMethod == .certificate else { return true }
        guard selectedKeyId != nil else { return false }
        return host.hasCertificate
            || !certificate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Mirrors `AddHostSheet.loadCertificateFromFile`.
    private func loadCertificateFromFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.showsHiddenFiles = true
        panel.message = "Pick the CA-signed certificate (*-cert.pub) for this host."
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent(".ssh", isDirectory: true)
        guard panel.runModal() == .OK,
              let url = panel.url,
              let text = try? String(contentsOf: url, encoding: .utf8) else { return }
        certificate = text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Slug-bound customer picker (mirrors AddHostSheet.groupPicker). Offers
    /// "Ungrouped", every customer slug, and a `(custom)` fallback tag so a
    /// host whose existing group is a non-slug value stays selectable on edit
    /// without being able to type a fresh arbitrary string. `+` creates a new
    /// customer inline and selects it.
    @ViewBuilder
    private var groupPicker: some View {
        HStack {
            Picker("Group", selection: $group) {
                Text("Ungrouped").tag("")
                ForEach(appState.customers) { c in
                    Text("\(c.displayName) (\(c.slug))").tag(c.slug)
                }
                if !group.isEmpty
                    && !appState.customers.contains(where: { $0.slug == group })
                {
                    Text("\(group) (custom)").tag(group)
                }
            }
            .help("Group hosts by customer for cross-section linkage. Pick a customer or stay ungrouped.")
            Button {
                slugsBeforeAdd = Set(appState.customers.map(\.slug))
                showingNewCustomer = true
            } label: {
                Image(systemName: "plus.circle")
            }
            .buttonStyle(.borderless)
            .help("Create a new customer.")
            .accessibilityLabel("Add new customer")
        }
        .sheet(isPresented: $showingNewCustomer, onDismiss: {
            Task {
                await appState.refreshCustomers()
                if let added = appState.customers
                    .first(where: { !slugsBeforeAdd.contains($0.slug) })
                {
                    group = added.slug
                }
            }
        }) {
            CustomerEditSheet(customer: nil)
        }
    }
}
