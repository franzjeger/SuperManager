import SwiftUI

struct AddHostSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var label = ""
    @State private var hostname = ""
    @State private var port: UInt16 = 22
    @State private var username = "root"
    @State private var group = ""
    @State private var deviceType: DeviceType = .linux
    @State private var authMethod: AuthMethod = .key
    @State private var selectedKeyId: String?
    @State private var password = ""
    @State private var showingNewCustomer = false
    @State private var slugsBeforeAdd: Set<String> = []
    @FocusState private var firstFieldFocused: Bool

    var body: some View {
        VStack(spacing: 16) {
            Text("Add SSH Host")
                .font(.title2)

            Form {
                TextField("Label", text: $label)
                    .focused($firstFieldFocused)
                TextField("Hostname / IP", text: $hostname)
                TextField("Port", value: $port, format: .number)
                TextField("Username", text: $username)
                groupPicker

                Picker("Device Type", selection: $deviceType) {
                    ForEach(DeviceType.allCases, id: \.self) { type in
                        Text(type.displayName).tag(type)
                    }
                }

                Picker("Auth Method", selection: $authMethod) {
                    ForEach(AuthMethod.allCases, id: \.self) { method in
                        Text(method.displayName).tag(method)
                    }
                }

                if authMethod == .key {
                    Picker("SSH Key", selection: $selectedKeyId) {
                        Text("None").tag(nil as String?)
                        ForEach(appState.sshKeys) { key in
                            Text("\(key.name) (\(key.keyType.displayName))").tag(key.id as String?)
                        }
                    }
                } else {
                    SecureField("Password", text: $password)
                }
            }
            .formStyle(.grouped)

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Add") {
                    Task {
                        await appState.addHost(
                            label: label,
                            hostname: hostname,
                            port: port,
                            username: username,
                            group: group,
                            deviceType: deviceType,
                            authMethod: authMethod,
                            authKeyId: authMethod == .key ? selectedKeyId : nil,
                            password: authMethod == .password ? password : nil
                        )
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(label.isEmpty || hostname.isEmpty)
            }
        }
        .padding()
        .frame(width: 450, height: 500)
        .task {
            await appState.refreshCustomers()
            // Tiny delay so SwiftUI's sheet-mount animation
            // settles before we yank focus — without this the
            // focus ring sometimes doesn't render.
            try? await Task.sleep(for: .milliseconds(100))
            firstFieldFocused = true
        }
    }

    /// Group picker — uses customer slugs (the conventional grouping
    /// for an MSP fleet) plus a free-text "Other / Custom group" path
    /// for hosts that don't belong to a customer (lab, infra, etc.).
    /// `+` opens CustomerEditSheet so the user can add a new customer
    /// without leaving this sheet.
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
                    // Surface the existing free-text group so it
                    // remains selectable on edit.
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
