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

    @State private var targetControllerId: String?
    @State private var overrideUrl: Bool = false
    @State private var customInformUrl: String = ""
    @State private var running = false
    @State private var output: String?
    @State private var error: String?

    /// Resolved inform URL — either auto-derived from the
    /// picked controller, or operator-overridden.
    private var resolvedInformUrl: String? {
        if overrideUrl {
            let s = customInformUrl.trimmingCharacters(in: .whitespaces)
            return s.isEmpty ? nil : s
        }
        guard let id = targetControllerId,
              let c = appState.unifiControllers.first(where: { $0.id == id })
        else { return nil }
        return c.derivedInformUrl
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Set UniFi inform URL")
                .font(.title3.weight(.semibold))
            Text("Tells this device to register with a controller at its inform URL. Pick a controller you've registered under Settings → UniFi — the URL is derived automatically.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if appState.unifiControllers.isEmpty {
                Label(
                    "No UniFi controllers configured. Add one under Settings → UniFi first.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            } else {
                Picker("Target controller", selection: $targetControllerId) {
                    Text("Pick…").tag(Optional<String>.none)
                    ForEach(appState.unifiControllers) { c in
                        Text(c.label).tag(Optional(c.id))
                    }
                }
                if let url = resolvedInformUrl, !overrideUrl {
                    Text("Inform URL: \(url)")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            Toggle("Override (non-standard port / proxy)", isOn: $overrideUrl)
                .toggleStyle(.checkbox)
            if overrideUrl {
                TextField(
                    "http://controller.lan:8080/inform",
                    text: $customInformUrl
                )
                .textFieldStyle(.roundedBorder)
                .font(.body.monospaced())
                .help("e.g. http://10.0.0.5:8080/inform")
            }
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
                VStack(alignment: .leading, spacing: 8) {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                    // When our daemon-side SSH fails (russh
                    // transport quirk, cold ARP, route flake),
                    // the operator's terminal almost always
                    // works. Give them a one-click fallback
                    // that opens Terminal.app with the exact
                    // command pre-filled — they enter the
                    // password in their own terminal, see the
                    // output there.
                    HStack(spacing: 8) {
                        Button {
                            openInTerminal()
                        } label: {
                            Label("Run via Terminal instead", systemImage: "terminal")
                        }
                        .controlSize(.small)
                        Button {
                            copyToClipboard()
                        } label: {
                            Label("Copy ssh command", systemImage: "doc.on.doc")
                        }
                        .controlSize(.small)
                    }
                }
                .padding(8)
                .background(
                    RoundedRectangle(cornerRadius: 6).fill(.red.opacity(0.08))
                )
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
                .disabled(running || resolvedInformUrl == nil)
            }
        }
        .padding(24)
        .frame(width: 480)
        .task { await appState.refreshUnifiControllers() }
        .onAppear {
            // Auto-pick the only controller if just one is
            // configured. Multiple configured → force the
            // operator to pick to avoid silently aiming a
            // device at the wrong controller.
            if targetControllerId == nil,
               appState.unifiControllers.count == 1
            {
                targetControllerId = appState.unifiControllers.first?.id
            }
        }
    }

    private func run() async {
        running = true
        defer { running = false }
        error = nil
        output = nil
        guard let url = resolvedInformUrl else {
            error = "Pick a controller (or enable Override and type a URL)."
            return
        }
        if let stdout = await appState.unifiSetInform(hostId: host.id, informUrl: url) {
            output = stdout.isEmpty ? "set-inform completed (no output)." : stdout
        } else {
            error = appState.errorMessage.isEmpty
                ? "set-inform failed. Make sure the device is reachable over SSH and the credentials are correct."
                : appState.errorMessage
        }
    }

    /// Build the SSH command that does the same thing the
    /// daemon would do — chained `mca-cli-op` → fallbacks so it
    /// works on every UniFi firmware generation.
    private func terminalCommand() -> String {
        let url = resolvedInformUrl ?? "http://controller.lan:8080/inform"
        return "ssh \(host.username)@\(host.hostname) "
            + "'mca-cli-op set-inform \(url) "
            + "|| /sbin/set-inform \(url) "
            + "|| /usr/bin/syswrapper.sh set-inform \(url) "
            + "|| set-inform \(url)'"
    }

    /// Open Terminal.app and paste the prepared command —
    /// the operator types their password in their own terminal,
    /// no SSH library involved. Reuses the working SSH path
    /// they've already proven works.
    private func openInTerminal() {
        let cmd = terminalCommand()
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = """
            tell application "Terminal"
                activate
                do script "\(cmd)"
            end tell
            """
        if let appleScript = NSAppleScript(source: script) {
            var err: NSDictionary?
            _ = appleScript.executeAndReturnError(&err)
        }
    }

    private func copyToClipboard() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(terminalCommand(), forType: .string)
    }
}
