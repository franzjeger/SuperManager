import SwiftUI

struct AddHostSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    /// Caller can pre-select a device type (e.g. Compliance opens
    /// the sheet with `.fortigate` already chosen so the operator
    /// doesn't have to walk through the picker). Defaults to
    /// `.linux` to preserve the existing toolbar-`+` behaviour.
    let defaultDeviceType: DeviceType
    /// Optional pre-fill from a recently-discovered device
    /// (network scan row, web-capture URL, etc.). When supplied
    /// every field below is initialised from this capture so the
    /// operator only has to click Add (or pick auth + group).
    let prefill: WebCapture?

    init(
        defaultDeviceType: DeviceType = .linux,
        prefill: WebCapture? = nil
    ) {
        self.defaultDeviceType = defaultDeviceType
        self.prefill = prefill
        let dt = prefill?.deviceType ?? defaultDeviceType
        _deviceType = State(initialValue: dt)
        _label = State(initialValue: prefill?.label ?? "")
        _hostname = State(initialValue: prefill?.hostname ?? "")
        _port = State(initialValue: prefill?.port ?? 22)
        _username = State(initialValue: prefill?.username ?? Self.defaultUsername(for: dt))
    }

    /// Vendor-appropriate SSH username default. Mirrors
    /// WebCapture's heuristic so a pre-fill from a scan and a
    /// "blank" sheet for the same device type look identical.
    private static func defaultUsername(for type: DeviceType) -> String {
        switch type {
        case .unifi: return "ubnt"
        case .fortigate: return "admin"
        case .pfSense, .openWrt: return "root"
        case .windows: return "Administrator"
        case .linux, .custom: return "root"
        }
    }

    @State private var label: String
    @State private var hostname: String
    @State private var port: UInt16
    @State private var username: String
    @State private var group = ""
    @State private var deviceType: DeviceType
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
