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
                            // The shared badge, not a hand-rolled capsule: a
                            // device type is a category, and categories render
                            // the same way everywhere in the app. The auth
                            // method moved into the Connection list below —
                            // it's configuration, not identity.
                            Badge(text: host.deviceType.displayName)

                            Button("Edit") {
                                showingEditSheet = true
                            }

                        // Secondary actions live in the kebab, same as the VPN
                        // detail — the row keeps the two things you do
                        // constantly (Connect, Test) plus Edit, and stops
                        // growing a button per feature. "Copy SSH command" was
                        // a full-width button for a two-second clipboard trip.
                        Menu {
                            Button {
                                let cmd = "ssh \(host.username)@\(host.hostname) -p \(host.port)"
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(cmd, forType: .string)
                            } label: {
                                Label("Copy SSH command", systemImage: "doc.on.doc")
                            }
                            // FortiGate-specific: open the device's web GUI in
                            // the default browser. Routes to the configured
                            // api_port (defaulting to 443) since admin-sport is
                            // the same port we use for REST. Lets the user jump
                            // from a failed compliance check to the matching
                            // settings page in the GUI.
                            if host.deviceType == .fortigate {
                                Button {
                                    openWebGui(host: host)
                                } label: {
                                    Label("Open web GUI", systemImage: "safari")
                                }
                            }
                        } label: {
                            Image(systemName: "ellipsis.circle")
                        }
                        .menuStyle(.borderlessButton)
                        .frame(width: 30)
                        .help("More actions")
                        }
                    }

                    // The grammar's connection card: the host's reachability
                    // as measured, one line of why, and the two actions that
                    // act on it. The old row mixed these with Edit and the
                    // kebab; those are identity/configuration actions and
                    // moved to the header, same split as the VPN detail.
                    ConnectionCard(
                        status: hostCardStatus,
                        title: hostCardTitle,
                        meta: hostCardMeta,
                        busy: connectionStatus == "Testing…"
                    ) {
                        HStack(spacing: 10) {
                            Button(action: { openTerminal(host: host) }) {
                                Label("Connect", systemImage: "terminal")
                            }
                            .buttonStyle(.borderedProminent)

                            Button("Test Connection") {
                                Task {
                                    connectionStatus = "Testing…"
                                    // Structured kinds from the daemon; the
                                    // card maps each to state + explanation:
                                    //   .authFailed    → error, message
                                    //   .networkFailed → offline, "is the
                                    //                    right VPN up?" hint
                                    //   .otherFailure  → error, message
                                    switch await appState.testConnection(hostId: hostId) {
                                    case .ok:
                                        connectionStatus = "ok"
                                    case .authFailed(let msg):
                                        connectionStatus = "auth: \(msg)"
                                    case .networkFailed(let msg):
                                        connectionStatus = "network: \(msg)"
                                    case .otherFailure(let msg):
                                        connectionStatus = msg
                                    }
                                }
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

                    // The detail grammar: sections in an adaptive grid, so a
                    // full-screen window puts Connection and Remote command
                    // side by side instead of hugging the left edge. Same
                    // shape as the VPN detail — one grammar, every section.
                    DetailColumns {
                        DetailSection(title: "Connection") {
                            DefinitionList(rows: connectionRows(host))
                        }

                        DetailSection(title: "Remote command") {
                            VStack(alignment: .leading, spacing: 8) {
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

    /// The Connection list, per the detail grammar: address first (what you
    /// copy), then what the host is, then how we get in. "Ungrouped" is
    /// de-emphasized because it's the absence of an answer, not an answer.
    private func connectionRows(_ host: SshHostSummary) -> [DefinitionRow] {
        var rows: [DefinitionRow] = [
            DefinitionRow("Address", "\(host.username)@\(host.hostname):\(host.port)"),
            DefinitionRow("Device type", host.deviceType.displayName, mono: false),
            DefinitionRow(
                "Group",
                host.group.isEmpty ? "Ungrouped" : host.group,
                mono: false,
                deemphasized: host.group.isEmpty
            ),
            DefinitionRow("Auth method", host.authMethod.displayName, mono: false),
        ]
        if host.hasApi {
            rows.append(DefinitionRow("API port", host.apiPort.map(String.init) ?? "443"))
        }
        return rows
    }

    /// The card's reading of `connectionStatus` — a manual, per-session probe,
    /// so "no reading yet" is `.unknown` and never a claim either way.
    ///
    /// A network failure maps to `.offline`, not `.error`: the host isn't
    /// broken, the path from HERE is — usually a VPN that isn't up — and the
    /// meta line says so. Auth failure is `.error`: the host answered and
    /// rejected us, which is a fact about configuration someone must fix.
    private var hostCardStatus: StatusStyle {
        switch connectionStatus {
        case nil:                                    return .unknown
        case "Testing…":                             return .pending
        case "ok":                                   return .online
        case .some(let s) where s.hasPrefix("auth"): return .error
        case .some(let s) where s.hasPrefix("network"): return .offline
        default:                                     return .error
        }
    }

    private var hostCardTitle: String {
        switch connectionStatus {
        case nil:                                    return "Not tested"
        case "Testing…":                             return "Testing…"
        case "ok":                                   return "Reachable"
        case .some(let s) where s.hasPrefix("auth"): return "Auth failed"
        case .some(let s) where s.hasPrefix("network"): return "Unreachable"
        default:                                     return "Failed"
        }
    }

    private var hostCardMeta: String {
        switch connectionStatus {
        case nil:
            return "Test the connection to verify reachability and credentials."
        case "Testing…":
            return ""
        case "ok":
            return "SSH connection and authentication verified."
        case .some(let s) where s.hasPrefix("auth: "):
            return String(s.dropFirst(6))
        case .some(let s) where s.hasPrefix("network: "):
            return String(s.dropFirst(9)) + " — check that the right VPN tunnel is up."
        case .some(let s):
            return s
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

    /// SF Symbol for the connection-status pill. We branch on the
    /// stable `kind`-derived prefix the test-connection task writes
    /// ("auth:", "network:", "ok") rather than parsing the human
    /// message — same idea as the daemon-side EngineError.kind
    /// design, applied to the view-state string.
}
