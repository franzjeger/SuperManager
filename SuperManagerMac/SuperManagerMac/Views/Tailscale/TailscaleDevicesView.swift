import SwiftUI

/// "Manage tailnet devices" sheet: lists every device in the tailnet via
/// the Tailscale admin API and lets the operator remove stale ones
/// (e.g. a decommissioned server) without leaving the app.
///
/// The local `tailscale` CLI cannot delete other nodes — that is a
/// control-plane action — so this talks to `api.tailscale.com` using a
/// one-time OAuth client the user creates in the admin console. When no
/// client is configured yet, the sheet shows a short setup form instead
/// of the list.
///
/// Deleting is irreversible on Tailscale's side, so every removal goes
/// through a `confirmationDialog`, and the row for *this* Mac has no
/// delete button at all (removing your own node logs you out).
struct TailscaleDevicesView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var creds = TailscaleAdminCredentials.load()
    @State private var editingCreds = false
    @State private var clientIdField = ""
    @State private var clientSecretField = ""

    @State private var devices: [TailscaleAPI.Device] = []
    @State private var loading = false
    @State private var error: String?
    @State private var pendingDelete: TailscaleAPI.Device?
    @State private var deletingId: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if let error {
                errorBanner(error)
            }
            if !creds.isComplete || editingCreds {
                setupForm
            } else {
                deviceList
            }
        }
        .frame(width: 540, height: 480)
        .onAppear {
            clientIdField = creds.clientId
            clientSecretField = creds.clientSecret
            // Populate self-identity so the delete guard can tell which
            // row is THIS Mac before any trash button becomes tappable.
            Task { await appState.refreshTailscale() }
            if creds.isComplete { Task { await reload() } }
        }
        .confirmationDialog(
            "Remove \(pendingDelete?.hostname ?? "device") from the tailnet?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }),
            presenting: pendingDelete
        ) { dev in
            Button("Remove \(dev.hostname ?? dev.id)", role: .destructive) {
                Task { await performDelete(dev) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { dev in
            let addr = dev.addresses?.first.map { " (\($0))" } ?? ""
            Text("This permanently removes \(dev.hostname ?? dev.id)\(addr) from your tailnet. It must re-authenticate to rejoin. This cannot be undone.")
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            Label("Tailnet devices", systemImage: "externaldrive.connected.to.line.below")
                .font(.headline)
            Spacer()
            if creds.isComplete && !editingCreds {
                Button {
                    Task { await reload() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .disabled(loading)
                .help("Reload the device list")

                Menu {
                    Button("Reconfigure OAuth client…") { editingCreds = true }
                    Button("Forget stored credentials", role: .destructive) {
                        TailscaleAdminCredentials.clear()
                        creds = .init(clientId: "", clientSecret: "")
                        devices = []
                        clientIdField = ""; clientSecretField = ""
                        Task { await TailscaleAPI.forgetCachedToken() }
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .frame(width: 28)
            }
            Button("Done") { dismiss() }
        }
        .padding(12)
    }

    private func errorBanner(_ msg: String) -> some View {
        Text(msg)
            .font(.caption)
            .foregroundStyle(.red)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(.red.opacity(0.08))
    }

    // MARK: - Setup form

    private var setupForm: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Connect the Tailscale admin API")
                    .font(.title3.weight(.semibold))
                Text("Removing devices needs an OAuth client from your Tailscale admin console. It is created once and does not expire.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(alignment: .leading, spacing: 6) {
                    Text("1. Open Admin → Settings → OAuth clients.")
                    Link("Open OAuth clients page",
                         destination: URL(string: "https://login.tailscale.com/admin/settings/oauth")!)
                    Text("2. Generate a client with the Devices → Core → Write scope.")
                    Text("3. Paste the client id and secret below.")
                }
                .font(.callout)

                Form {
                    TextField("Client ID", text: $clientIdField)
                        .textFieldStyle(.roundedBorder)
                    SecureField("Client secret", text: $clientSecretField)
                        .textFieldStyle(.roundedBorder)
                }

                HStack {
                    if creds.isComplete {
                        Button("Cancel") {
                            editingCreds = false
                            clientIdField = creds.clientId
                            clientSecretField = creds.clientSecret
                        }
                    }
                    Spacer()
                    Button("Save & connect") { saveCreds() }
                        .buttonStyle(.borderedProminent)
                        .disabled(
                            clientIdField.trimmingCharacters(in: .whitespaces).isEmpty
                                || clientSecretField.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .padding(16)
        }
    }

    // MARK: - Device list

    private var deviceList: some View {
        Group {
            if loading && devices.isEmpty {
                VStack {
                    Spacer()
                    ProgressView("Loading devices…")
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else if devices.isEmpty {
                VStack(spacing: 8) {
                    Spacer()
                    Image(systemName: "externaldrive")
                        .font(.largeTitle).foregroundStyle(.secondary)
                    Text("No devices returned.").foregroundStyle(.secondary)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                List(devices) { dev in
                    deviceRow(dev)
                }
                .listStyle(.inset)
            }
        }
    }

    private func deviceRow(_ dev: TailscaleAPI.Device) -> some View {
        HStack(spacing: 10) {
            Image(systemName: osIcon(dev.os))
                .foregroundStyle(.secondary)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(dev.hostname ?? dev.name ?? dev.id)
                        .fontWeight(.medium)
                    if isSelf(dev) {
                        Text("This Mac")
                            .font(.caption2)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.blue.opacity(0.15), in: Capsule())
                    }
                }
                Text((dev.addresses?.first ?? dev.name ?? "") + lastSeenSuffix(dev.lastSeen))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if deletingId == dev.id {
                ProgressView().controlSize(.small)
            } else if selfIdentified && isSelf(dev) {
                // Deleting your own node logs this Mac out — never offer it.
                EmptyView()
            } else {
                Button(role: .destructive) {
                    pendingDelete = dev
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                // Fail CLOSED: until we know which device is THIS Mac,
                // every delete is disabled — otherwise a not-yet-loaded
                // status would expose a delete for our own admin node.
                .disabled(!selfIdentified)
                .help(selfIdentified
                    ? "Remove \(dev.hostname ?? "this device") from the tailnet"
                    : "Identifying this device first…")
            }
        }
        .padding(.vertical, 2)
    }

    // MARK: - Actions

    private func saveCreds() {
        let id = clientIdField.trimmingCharacters(in: .whitespaces)
        let secret = clientSecretField.trimmingCharacters(in: .whitespaces)
        TailscaleAdminCredentials.save(clientId: id, clientSecret: secret)
        creds = TailscaleAdminCredentials.load()
        editingCreds = false
        error = nil
        Task { await reload() }
    }

    @MainActor
    private func reload() async {
        loading = true
        error = nil
        defer { loading = false }
        do {
            let list = try await TailscaleAPI.listDevices(
                clientId: creds.clientId, clientSecret: creds.clientSecret)
            devices = list.sorted { ($0.hostname ?? "") < ($1.hostname ?? "") }
        } catch {
            self.error = error.localizedDescription
        }
    }

    @MainActor
    private func performDelete(_ dev: TailscaleAPI.Device) async {
        deletingId = dev.id
        defer { deletingId = nil }
        do {
            try await TailscaleAPI.deleteDevice(
                id: dev.id, clientId: creds.clientId, clientSecret: creds.clientSecret)
            devices.removeAll { $0.id == dev.id }
        } catch {
            self.error = error.localizedDescription
        }
    }

    // MARK: - Helpers

    private var selfIPs: Set<String> {
        guard let s = appState.tailscaleStatus else { return [] }
        return Set(s.tailscaleIPs).union(s.selfNode.tailscaleIPs)
    }

    private var selfHostname: String? {
        let h = appState.tailscaleStatus?.selfNode.hostName
        return (h?.isEmpty == false) ? h : nil
    }

    /// True once we know enough about THIS Mac to tell it apart from the
    /// other devices. Gates every delete button so a not-yet-loaded
    /// status can never expose a delete for our own node.
    private var selfIdentified: Bool {
        !selfIPs.isEmpty || selfHostname != nil
    }

    /// Whether this API device is the Mac we're running on. IP overlap is
    /// the reliable signal (the local node id is not guaranteed equal to
    /// the API's `nodeId`); hostname is a secondary check.
    private func isSelf(_ dev: TailscaleAPI.Device) -> Bool {
        if !selfIPs.isEmpty, !Set(dev.addresses ?? []).isDisjoint(with: selfIPs) {
            return true
        }
        if let h = selfHostname, dev.hostname == h {
            return true
        }
        return false
    }

    private func osIcon(_ os: String?) -> String {
        switch (os ?? "").lowercased() {
        case let s where s.contains("mac"): return "laptopcomputer"
        case "ios": return "iphone"
        case "android": return "candybarphone"
        case "linux": return "server.rack"
        case "windows": return "pc"
        default: return "network"
        }
    }

    private static let isoFractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    private static let isoPlain = ISO8601DateFormatter()

    private func lastSeenSuffix(_ iso: String?) -> String {
        guard let iso,
            let date = Self.isoFractional.date(from: iso) ?? Self.isoPlain.date(from: iso)
        else { return "" }
        let rel = RelativeDateTimeFormatter()
        rel.unitsStyle = .abbreviated
        return "  ·  seen \(rel.localizedString(for: date, relativeTo: Date()))"
    }
}
