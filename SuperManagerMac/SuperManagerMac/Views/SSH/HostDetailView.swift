import SwiftUI

struct HostDetailView: View {
    @Environment(AppState.self) private var appState
    let hostId: String

    @State private var commandInput = ""
    @State private var commandOutput = ""
    @State private var isRunning = false
    @State private var connectionStatus: String?
    @State private var showingEditSheet = false

    private var host: SshHostSummary? {
        appState.sshHosts.first { $0.id == hostId }
    }

    var body: some View {
        if let host = host {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Header
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(host.label)
                                .font(.title)
                            Text("\(host.username)@\(host.hostname):\(host.port)")
                                .font(.title3)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 4) {
                            HStack(spacing: 6) {
                                // Compliance pill — only renders for
                                // FortiGate hosts that have at least
                                // one stored run. Click jumps to the
                                // Compliance section with this host
                                // selected so the user can drill into
                                // the breakdown without hunting.
                                if host.deviceType == .fortigate,
                                   let summary = appState.complianceHistory[host.id]?.first {
                                    compliancePill(score: summary.score, hostId: host.id)
                                }
                                Text(host.deviceType.displayName)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(.blue.opacity(0.1))
                                    .clipShape(Capsule())
                            }
                            Text(host.authMethod == .key ? "Key Auth" : "Password Auth")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Divider()

                    // Actions
                    HStack(spacing: 12) {
                        Button(action: { openTerminal(host: host) }) {
                            Label("Connect", systemImage: "terminal")
                        }
                        .buttonStyle(.borderedProminent)

                        Button("Test Connection") {
                            Task {
                                connectionStatus = "Testing..."
                                let result = await appState.testConnection(hostId: hostId)
                                connectionStatus = result
                            }
                        }

                        if let status = connectionStatus {
                            HStack(spacing: 4) {
                                Image(systemName: status == "ok" ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundStyle(status == "ok" ? .green : .red)
                                Text(status)
                            }
                        }

                        Spacer()

                        Button("Edit") {
                            showingEditSheet = true
                        }

                        Button("Copy SSH Command") {
                            let cmd = "ssh \(host.username)@\(host.hostname) -p \(host.port)"
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(cmd, forType: .string)
                        }

                        // FortiGate-specific: open the device's
                        // web GUI in the default browser. Routes
                        // to the configured api_port (defaulting
                        // to 443) since admin-sport is the same
                        // port we use for REST. Lets the user
                        // jump from a failed compliance check to
                        // the matching settings page in the GUI.
                        if host.deviceType == .fortigate {
                            Button {
                                openWebGui(host: host)
                            } label: {
                                Label("Open Web GUI", systemImage: "safari")
                            }
                        }
                    }

                    // FortiGate REST API panel — only renders for
                    // FortiGate hosts. Self-contained: handles its
                    // own state for token gen/test/copy/forget.
                    FortigateApiPanel(host: host)

                    // UniFi Controller panel — parallel design,
                    // shown only for UniFi-typed hosts. Handles
                    // controller-credential setup, set-inform
                    // adoption flow, and REST connection test.
                    UnifiControllerPanel(host: host)

                    // Live FortiGate dashboard — only meaningful
                    // when an API token is configured. Polls the
                    // device every 5 s for KPIs, throughput, and
                    // tunnel state. Mounts/unmounts cleanly with
                    // host selection so we don't leak background
                    // tasks across hosts.
                    if host.deviceType == .fortigate && host.hasApi {
                        FortigateDashboardPanel(hostId: host.id)
                    }

                    Divider()

                    // Remote command execution
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Remote Command")
                            .font(.headline)

                        HStack {
                            TextField("Enter command...", text: $commandInput)
                                .textFieldStyle(.roundedBorder)
                                .onSubmit { executeCommand() }

                            Button(action: executeCommand) {
                                if isRunning {
                                    ProgressView()
                                        .controlSize(.small)
                                } else {
                                    Image(systemName: "play.fill")
                                }
                            }
                            .disabled(commandInput.isEmpty || isRunning)
                            .accessibilityLabel("Run remote command")
                        }

                        if !commandOutput.isEmpty {
                            ScrollView {
                                Text(commandOutput)
                                    .font(.system(.body, design: .monospaced))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .frame(maxHeight: 300)
                            .padding(8)
                            .background(.black.opacity(0.05))
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                        }
                    }

                    // Host info grid
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Details")
                            .font(.headline)

                        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                            GridRow {
                                Text("Group").foregroundStyle(.secondary)
                                if host.group.isEmpty {
                                    Text("Ungrouped")
                                        .foregroundStyle(.tertiary)
                                        .italic()
                                } else {
                                    Text(host.group)
                                }
                            }
                            GridRow {
                                Text("Device Type").foregroundStyle(.secondary)
                                Text(host.deviceType.displayName)
                            }
                            GridRow {
                                Text("Auth Method").foregroundStyle(.secondary)
                                Text(host.authMethod.displayName)
                            }
                            if host.hasApi {
                                GridRow {
                                    Text("API Port").foregroundStyle(.secondary)
                                    Text(host.apiPort.map(String.init) ?? "443")
                                }
                            }
                        }
                    }
                }
                .padding(20)
            }
            .sheet(isPresented: $showingEditSheet) {
                EditHostSheet(host: host)
            }
            .task(id: host.id) {
                // Lazy-load compliance history so the score pill
                // populates without requiring the user to visit
                // the Compliance section first. Cheap (one daemon
                // RPC, reads from disk) so we do it on every host
                // selection rather than caching forever.
                if host.deviceType == .fortigate && host.hasApi {
                    await appState.loadComplianceHistory(hostId: host.id, limit: 5)
                }
            }
        } else {
            Text("Host not found")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func openTerminal(host: SshHostSummary) {
        // Prefer the ssh:// URL scheme — Terminal.app registers for it out of the box
        // and iTerm2 will claim it if installed, so the user's default terminal wins.
        // AppleScript was unreliable because it requires the Automation TCC permission.
        if var comps = URLComponents(string: "ssh://") {
            comps.user = host.username
            comps.host = host.hostname
            comps.port = Int(host.port)
            if let url = comps.url, NSWorkspace.shared.open(url) {
                return
            }
        }

        // Fallback: write a .command shell script and hand it to the default opener.
        // Terminal.app executes .command files directly; no permission prompt.
        // Quote the user@host token so a hostname like `; rm -rf ~` cannot
        // escape the ssh argv. Port is an integer so we pass it directly.
        let q: (String) -> String = { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let userHost = q("\(host.username)@\(host.hostname)")
        let sshCmd = "ssh \(host.username)@\(host.hostname) -p \(host.port)"
        let script = "#!/bin/sh\nexec ssh \(userHost) -p \(host.port)\n"
        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("supermgr-ssh-\(UUID().uuidString).command")
        do {
            try script.write(to: scriptURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)
            NSWorkspace.shared.open(scriptURL)
        } catch {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(sshCmd, forType: .string)
        }
    }

    private func executeCommand() {
        guard !commandInput.isEmpty else { return }
        isRunning = true
        let cmd = commandInput
        Task {
            if let result = await appState.executeCommand(hostId: hostId, command: cmd) {
                commandOutput = result.stdout
                if !result.stderr.isEmpty {
                    commandOutput += "\n[stderr] \(result.stderr)"
                }
                if result.exitCode != 0 {
                    commandOutput += "\n[exit code: \(result.exitCode)]"
                }
            }
            isRunning = false
        }
    }

    /// Open the FortiGate's web GUI in the user's default browser.
    /// Uses the configured `api_port` (which equals admin-sport on
    /// FortiOS — same port serves REST and the web GUI).
    private func openWebGui(host: SshHostSummary) {
        let port = host.apiPort ?? 443
        let urlString = "https://\(host.hostname):\(port)/"
        if let url = URL(string: urlString) {
            NSWorkspace.shared.open(url)
        }
    }

    /// Score pill rendered next to the device-type chip in the
    /// host header. Tap navigates to the Compliance section with
    /// this host pre-selected — gives the user a one-click path
    /// from "I see my fleet has a bad pill" to "I'm looking at
    /// the breakdown of why".
    @ViewBuilder
    private func compliancePill(score: UInt8, hostId: String) -> some View {
        let color: Color = score >= 90 ? .green : (score >= 70 ? .orange : .red)
        Button {
            appState.selectedHostId = hostId
            appState.selectedSection = .compliance
        } label: {
            HStack(spacing: 4) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.caption2)
                Text("\(score)")
                    .font(.caption.weight(.semibold))
                    .monospacedDigit()
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(color.opacity(0.15))
            .foregroundStyle(color)
            .clipShape(Capsule())
        }
        .buttonStyle(.plain)
        .help("Compliance score \(score)/100 — click to view breakdown")
    }
}
