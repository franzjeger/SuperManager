import SwiftUI

/// UniFi Controller integration panel — only shown for hosts
/// whose `device_type` is `.unifi`. Mirrors FortigateApiPanel's
/// design philosophy: status pill at top right, primary actions
/// inline, secondary actions behind ⋯-menu.
///
/// Two states:
///
/// - **Not configured**: educational prompt + buttons to (a)
///   point this device at a controller (`set-inform`) or (b)
///   register an existing controller URL + credentials so the
///   GUI can talk to it.
///
/// - **Configured**: green pill with controller version + admin
///   username, "Test connection" / "Open Controller GUI" /
///   "Re-point inform URL" / "Forget controller" actions.
struct UnifiControllerPanel: View {
    @Environment(AppState.self) private var appState
    let host: SshHostSummary

    @State private var testInfo: AppState.UnifiTestInfo?
    @State private var testing = false
    @State private var lastError: String?
    @State private var showingSetupSheet = false
    @State private var showingInformSheet = false
    @State private var inFlight = false

    var body: some View {
        if host.deviceType == .unifi {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Image(systemName: "wifi")
                        .foregroundStyle(.tint)
                    Text("UniFi Controller")
                        .font(.headline)
                    Spacer()
                    statusPill
                }
                if host.hasUnifiController {
                    configuredActions
                } else {
                    notConfiguredActions
                }
                if let err = lastError {
                    Label(err, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .padding(8)
                        .background(.red.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(.tint.opacity(0.04))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(.tint.opacity(0.18), lineWidth: 1)
            )
            .sheet(isPresented: $showingSetupSheet) {
                UnifiControllerSetupSheet(host: host) { saved in
                    showingSetupSheet = false
                    if saved {
                        testInfo = nil
                        Task { await runTest() }
                    }
                }
            }
            .sheet(isPresented: $showingInformSheet) {
                UnifiSetInformSheet(host: host) { _ in
                    showingInformSheet = false
                }
            }
            .task(id: host.id) {
                if host.hasUnifiController && testInfo == nil {
                    await runTest()
                }
            }
        }
    }

    @ViewBuilder
    private var statusPill: some View {
        if !host.hasUnifiController {
            pill(text: "Not configured", color: .secondary, icon: "circle.dashed")
        } else if testing {
            pill(text: "Testing…", color: .orange, icon: nil, showSpinner: true)
        } else if let info = testInfo {
            pill(
                text: "v\(info.serverVersion) · \(info.adminRole)",
                color: .green,
                icon: "checkmark.circle.fill"
            )
        } else if lastError != nil {
            pill(text: "Token error", color: .red, icon: "xmark.circle.fill")
        } else {
            pill(text: "Configured", color: .blue, icon: "key.fill")
        }
    }

    private func pill(
        text: String,
        color: Color,
        icon: String?,
        showSpinner: Bool = false
    ) -> some View {
        HStack(spacing: 4) {
            if showSpinner {
                ProgressView().controlSize(.small)
            } else if let icon {
                Image(systemName: icon).font(.caption)
            }
            Text(text).font(.caption).lineLimit(1)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(color.opacity(0.12))
        .foregroundStyle(color)
        .clipShape(Capsule())
    }

    private var notConfiguredActions: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Two paths to using this UniFi device with SuperManager: register an existing controller's URL + credentials, or send the device's inform URL so it appears on a controller for adoption.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                Button {
                    lastError = nil
                    showingSetupSheet = true
                } label: {
                    Label("Configure controller…", systemImage: "antenna.radiowaves.left.and.right")
                }
                .buttonStyle(.borderedProminent)
                .disabled(inFlight)

                Button {
                    lastError = nil
                    showingInformSheet = true
                } label: {
                    Label("Set inform URL…", systemImage: "arrow.up.forward.circle")
                }
                .disabled(inFlight)
            }
        }
    }

    private var configuredActions: some View {
        HStack(spacing: 8) {
            Button {
                Task { await runTest() }
            } label: {
                Label("Test", systemImage: "bolt.horizontal.circle")
            }
            .disabled(inFlight)

            Button {
                openControllerGui()
            } label: {
                Label("Open in browser", systemImage: "safari")
            }
            .disabled(inFlight)

            Spacer()

            Menu {
                Button("Re-point inform URL…") {
                    lastError = nil
                    showingInformSheet = true
                }
                Button("Replace controller…") {
                    lastError = nil
                    showingSetupSheet = true
                }
                Divider()
                Button("Forget controller", role: .destructive) {
                    Task { await forget() }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .disabled(inFlight)
            .accessibilityLabel("UniFi controller actions")
        }
    }

    // MARK: - Actions

    private func runTest() async {
        inFlight = true
        defer { inFlight = false }
        testing = true
        defer { testing = false }
        lastError = nil
        if let info = await appState.testUnifiController(hostId: host.id) {
            testInfo = info
        } else {
            lastError = appState.errorMessage.isEmpty
                ? "Controller test failed."
                : appState.errorMessage
        }
    }

    private func forget() async {
        inFlight = true
        defer { inFlight = false }
        if await appState.clearUnifiController(hostId: host.id) {
            testInfo = nil
        }
    }

    private func openControllerGui() {
        // Use the stored controller URL — Mac side doesn't have
        // it directly (it's on the server-side host record), so
        // we synthesize from `unifi_controller_url` via the SSH
        // host's hostname. Simpler: trust the user has it
        // bookmarked; but for the MVP we just open the host's
        // address in the browser at the standard UniFi GUI port
        // 8443.
        let url = URL(string: "https://\(host.hostname):8443/")
        if let url {
            NSWorkspace.shared.open(url)
        }
    }
}

/// Setup sheet for the controller URL + credentials. Validates
/// by attempting login; only persists on success. The daemon
/// stores the password in the macOS keychain so it never lives
/// on disk in plaintext.
struct UnifiControllerSetupSheet: View {
    @Environment(AppState.self) private var appState
    let host: SshHostSummary
    let onResult: (Bool) -> Void

    @State private var controllerUrl: String = "https://"
    @State private var username = ""
    @State private var password = ""
    @State private var saving = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Configure UniFi Controller")
                .font(.title3.weight(.semibold))
            Text("URL of the controller (e.g. UniFi Network Application or UDM) and an admin account that can read site-level data. Credentials are validated immediately and stored in the macOS Keychain.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Form {
                TextField("Controller URL", text: $controllerUrl)
                    .textFieldStyle(.roundedBorder)
                TextField("Username", text: $username)
                    .textFieldStyle(.roundedBorder)
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel") { onResult(false) }
                    .keyboardShortcut(.cancelAction)
                Button(saving ? "Validating…" : "Save") { Task { await save() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        saving
                            || controllerUrl.trimmingCharacters(in: .whitespaces).isEmpty
                            || username.trimmingCharacters(in: .whitespaces).isEmpty
                            || password.isEmpty
                    )
            }
        }
        .padding(24)
        .frame(width: 460)
    }

    private func save() async {
        saving = true
        defer { saving = false }
        error = nil
        let url = controllerUrl.trimmingCharacters(in: .whitespaces)
        if await appState.setUnifiController(
            hostId: host.id,
            url: url,
            username: username,
            password: password
        ) {
            onResult(true)
        } else {
            error = appState.errorMessage.isEmpty
                ? "Could not authenticate against the controller."
                : appState.errorMessage
        }
    }
}

/// Sheet for the `set-inform <url>` device-side adoption command.
/// Runs over SSH; the device's SSH credentials must already be
/// configured under SSH section. Default factory creds for
/// UniFi gear are `ubnt/ubnt` — the user has to set those up
/// in SuperManager's host edit dialog before this works.
struct UnifiSetInformSheet: View {
    @Environment(AppState.self) private var appState
    let host: SshHostSummary
    let onResult: (Bool) -> Void

    @State private var informUrl: String = "http://"
    @State private var running = false
    @State private var output: String?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Set UniFi inform URL")
                .font(.title3.weight(.semibold))
            Text("Tells this device to register with the controller at the inform URL. Required for adoption flow when the device is on factory defaults. Default port for inform is 8080.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Inform URL", text: $informUrl)
                .textFieldStyle(.roundedBorder)
                .help("e.g. http://10.0.0.5:8080/inform")
            if let output {
                Text(output)
                    .font(.system(.caption, design: .monospaced))
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.green.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .textSelection(.enabled)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Close") { onResult(output != nil) }
                    .keyboardShortcut(.cancelAction)
                Button(running ? "Running…" : "Run set-inform") {
                    Task { await run() }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(
                    running
                        || informUrl.trimmingCharacters(in: .whitespaces).isEmpty
                )
            }
        }
        .padding(24)
        .frame(width: 480)
    }

    private func run() async {
        running = true
        defer { running = false }
        error = nil
        output = nil
        let url = informUrl.trimmingCharacters(in: .whitespaces)
        if let stdout = await appState.unifiSetInform(hostId: host.id, informUrl: url) {
            output = stdout.isEmpty ? "set-inform completed (no output)." : stdout
        } else {
            error = appState.errorMessage.isEmpty
                ? "set-inform failed. Make sure the device is reachable over SSH and the credentials are correct."
                : appState.errorMessage
        }
    }
}
