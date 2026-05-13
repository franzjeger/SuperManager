import SwiftUI

/// Full network scan — host discovery + port sweep + service
/// banner-grab + TLS audit + CVE matching, against a CIDR range.
/// Same engine RPC as the engagement-panel "Active scan" button,
/// but runs DIRECTLY from Recon with its own progress UI.
///
/// Targets default to the selected engagement's `scope_cidrs`,
/// but the user can override (engagement-less scans are fine —
/// findings get persisted to the engagement if one is selected,
/// otherwise they're returned in-memory only).
struct NetworkScanSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    let engagementId: String?
    let initialTargets: String

    @State private var targetsText: String
    @State private var isRunning: Bool = false
    @State private var result: ActiveScanResult?
    @State private var errorMessage: String?
    @State private var scanTask: Task<Void, Never>?
    @State private var operationsPollTask: Task<Void, Never>?
    @State private var startedAt: Date?
    /// Drives whichever per-host follow-up sheet the operator
    /// triggered from a row's "..." menu. Each case carries the
    /// host so the sheet can pre-fill against it without lookup.
    @State private var pendingHostAction: HostAction?

    /// One-click follow-up actions exposed inline in the scan
    /// results. Each scan row gets a menu populated with these,
    /// vendor-gated where appropriate.
    enum HostAction: Identifiable {
        case addSsh(ActiveHost)
        case adoptUnifi(ActiveHost)
        var id: String {
            switch self {
            case .addSsh(let h): return "ssh-\(h.ip)"
            case .adoptUnifi(let h): return "unifi-\(h.ip)"
            }
        }
    }

    init(engagementId: String?, initialTargets: String) {
        self.engagementId = engagementId
        self.initialTargets = initialTargets
        _targetsText = State(initialValue: initialTargets)
    }

    var body: some View {
        VStack(spacing: 0) {
            header

            Form {
                Section {
                    TextField(
                        "192.168.1.0/24, 10.0.0.0/24, 192.0.2.5",
                        text: $targetsText,
                        axis: .vertical
                    )
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .disabled(isRunning)
                    .lineLimit(2...4)
                } header: {
                    Text("Targets")
                } footer: {
                    Text(
                        "Comma- or space-separated CIDR blocks, ranges, or single IPs. "
                        + "Examples: `192.168.1.0/24`, `10.0.0.1-10.0.0.50`, `192.0.2.5`. "
                        + "Capped at 256 hosts per scan."
                    )
                    .font(.caption)
                }

                if isRunning {
                    Section {
                        scanProgressRow
                        if let opSummary = currentOperationSummary {
                            Text(opSummary)
                                .font(.caption.monospaced())
                                .foregroundStyle(.tertiary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    } header: {
                        Text("Running…")
                    }
                }

                if let r = result {
                    Section("Summary") {
                        LabeledContent("Hosts found") {
                            Text("\(r.hosts.count)").font(.body.bold())
                        }
                        LabeledContent("Open ports") {
                            Text("\(totalOpenPorts(r))").foregroundStyle(.secondary)
                        }
                        LabeledContent("Findings") {
                            Text("\(r.findings.count)").foregroundStyle(.secondary)
                        }
                        LabeledContent("Duration") {
                            Text(durationString(r))
                                .foregroundStyle(.secondary)
                        }
                    }

                    if !r.hosts.isEmpty {
                        Section {
                            ForEach(r.hosts) { host in
                                HostRow(
                                    host: host,
                                    onAction: { action in
                                        pendingHostAction = action
                                    },
                                    onProvision: { host in
                                        appState.selectedSection = .provisioning
                                    },
                                    onOpenInBrowser: { host in
                                        openInBrowser(host: host)
                                    },
                                    onCopyIp: { host in
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general
                                            .setString(host.ip, forType: .string)
                                    }
                                )
                            }
                        } header: {
                            Text("Hosts (\(r.hosts.count))")
                        } footer: {
                            Text(
                                "Click the **\"…\"** button on any row to add it as "
                                + "an SSH host, adopt to a UniFi controller, jump to "
                                + "provisioning, copy the IP, or open its web UI."
                            )
                            .font(.caption)
                        }
                    }

                    if !r.findings.isEmpty {
                        Section("Findings (\(r.findings.count))") {
                            ForEach(Array(r.findings.prefix(20).enumerated()), id: \.offset) { _, f in
                                FindingRow(finding: f)
                            }
                            if r.findings.count > 20 {
                                Text("…and \(r.findings.count - 20) more — open the engagement in Security for the full list.")
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                }

                if let err = errorMessage {
                    Section {
                        Text(err).foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                if isRunning {
                    Button("Stop scan", role: .destructive) { stop() }
                }
                if !isRunning, result != nil {
                    Button("Open in Security") {
                        appState.selectedSection = .security
                    }
                }
                Spacer()
                if !isRunning {
                    Button(result == nil ? "Start scan" : "Re-run") {
                        Task { await start() }
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(parsedTargets.isEmpty)
                }
                Button(isRunning ? "Close (scan keeps running)" : "Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(12)
        }
        .frame(minWidth: 720, minHeight: 540)
        .sheet(item: $pendingHostAction) { action in
            switch action {
            case .addSsh(let host):
                AddHostSheet(prefill: webCapture(from: host))
                    .environment(appState)
            case .adoptUnifi(let host):
                UnifiAdoptInlineSheet(host: host)
                    .environment(appState)
            }
        }
        .onAppear {
            // If the WebCapture flow handed off a target via
            // `pendingNetworkScanTargets`, clear it now so a
            // subsequent re-open of this sheet doesn't reuse a
            // stale capture target.
            appState.pendingNetworkScanTargets = nil
        }
        .onDisappear {
            // The user might close while scan is still going — keep
            // the daemon-side scan running so its results persist,
            // but stop polling from this view.
            operationsPollTask?.cancel()
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "network")
                .foregroundStyle(.tint).imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("Network scan").font(.headline)
                Text("Host discovery + port sweep + service banner-grab + CVE matching")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let eid = engagementId {
                Text("→ engagement \(eid.prefix(8))…")
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(.background.secondary)
    }

    // MARK: - Targets parsing

    private var parsedTargets: [String] {
        targetsText
            .split(whereSeparator: { c in c == "," || c.isWhitespace })
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    // MARK: - Progress row

    private var scanProgressRow: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            if let started = startedAt {
                let elapsed = Int(Date().timeIntervalSince(started))
                Text("Scanning… \(elapsed) sec elapsed").font(.body)
            } else {
                Text("Starting…").font(.body)
            }
            Spacer()
        }
    }

    private var currentOperationSummary: String? {
        appState.runningOperations
            .first(where: { $0.kind == "active_scan" })?
            .label
    }

    // MARK: - Run / stop

    private func start() async {
        result = nil
        errorMessage = nil
        isRunning = true
        startedAt = Date()
        let targets = parsedTargets

        // Poll the engine's operation list every 500ms while the
        // scan runs so we can show "scanning 192.168.1.0/24 (124 hosts)"
        // updating live. Cancelled on completion or close.
        operationsPollTask = Task {
            while !Task.isCancelled {
                _ = await appState.loadRunningOperations()
                try? await Task.sleep(for: .milliseconds(500))
            }
        }

        scanTask = Task {
            let r = await appState.runActiveDiscovery(
                targets: targets,
                customerSlug: nil,
                engagementId: engagementId
            )
            await MainActor.run {
                operationsPollTask?.cancel()
                isRunning = false
                if let r {
                    result = r
                } else {
                    errorMessage = "Scan failed — check daemon logs."
                }
            }
        }
    }

    private func stop() {
        // Find the engine's operation id + ask it to cancel.
        if let op = appState.runningOperations.first(where: { $0.kind == "active_scan" }) {
            Task { await appState.cancelOperation(id: op.id) }
        }
        scanTask?.cancel()
        operationsPollTask?.cancel()
        isRunning = false
    }

    // MARK: - Helpers

    private func totalOpenPorts(_ r: ActiveScanResult) -> Int {
        r.hosts.reduce(0) { $0 + $1.probes.count }
    }

    private func durationString(_ r: ActiveScanResult) -> String {
        let secs = Int(r.finishedAt.timeIntervalSince(r.startedAt))
        if secs < 60 { return "\(secs)s" }
        return "\(secs/60)m \(secs%60)s"
    }

    /// Build a WebCapture from a scanned host so the existing
    /// AddHostSheet pre-fill path works without duplicating
    /// initialiser logic. Vendor sniffing reads the engine's
    /// MAC-OUI lookup + per-port banners.
    private func webCapture(from host: ActiveHost) -> WebCapture {
        let dt = Self.deviceType(for: host)
        // First HTTP/HTTPS port (if any) makes the most
        // sensible "open in browser" default — preserved in
        // sourceUrl for the AddHost detail line.
        let webPort = host.probes
            .first(where: { $0.service.lowercased().contains("http") })?
            .port
        let url = webPort.map {
            URL(string: "https://\(host.ip):\($0)/")
        } ?? nil
        return WebCapture(
            hostname: host.ip,
            port: webPort,
            label: host.hostname?.isEmpty == false
                ? host.hostname!
                : "\(dt.displayName) — \(host.ip)",
            deviceType: dt,
            username: defaultUsername(for: dt),
            sourceUrl: url,
            pageTitle: host.vendor
        )
    }

    /// Sniff a vendor for a scanned host. The engine's OUI
    /// lookup writes `host.vendor` (e.g. "Ubiquiti Networks"),
    /// and per-port banners often disclose model names. We
    /// check both.
    static func deviceType(for host: ActiveHost) -> DeviceType {
        let vendor = (host.vendor ?? "").lowercased()
        let banners = host.probes
            .compactMap { p -> String? in
                let parts = [p.banner, p.title, p.serverHeader, p.poweredBy]
                    .compactMap { $0 }
                return parts.isEmpty ? nil : parts.joined(separator: " ")
            }
            .joined(separator: " ")
            .lowercased()
        let blob = vendor + " " + banners
        if blob.contains("fortinet") || blob.contains("fortigate") {
            return .fortigate
        }
        if blob.contains("ubiquiti") || blob.contains("unifi")
            || blob.contains("ubnt")
        {
            return .unifi
        }
        if blob.contains("pfsense") || blob.contains("netgate") {
            return .pfSense
        }
        if blob.contains("openwrt") || blob.contains("lede") {
            return .openWrt
        }
        if blob.contains("windows") || blob.contains("microsoft-iis") {
            return .windows
        }
        return .linux
    }

    private func defaultUsername(for type: DeviceType) -> String {
        switch type {
        case .unifi: return "ubnt"
        case .fortigate: return "admin"
        case .pfSense, .openWrt, .linux, .custom: return "root"
        case .windows: return "Administrator"
        }
    }

    private func openInBrowser(host: ActiveHost) {
        // Prefer HTTPS over HTTP if both are open, then whichever
        // is open. Bare IP works for the IP-as-host case (every
        // vendor admin UI accepts that even if its TLS cert is
        // self-signed).
        let preferred = [443, 8443, 80, 8080]
        let openHttps = host.probes.first(where: {
            preferred.prefix(2).contains(Int($0.port))
        })
        let openHttp = host.probes.first(where: {
            preferred.suffix(2).contains(Int($0.port))
        })
        let probe = openHttps ?? openHttp
        let scheme = (openHttps != nil) ? "https" : "http"
        let portStr: String = probe.map { ":\($0.port)" } ?? ""
        if let url = URL(string: "\(scheme)://\(host.ip)\(portStr)/") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - Sub-rows

/// One row per scanned host. Each row is interactive: the
/// trailing "…" menu lets the operator add the host as an SSH
/// device, adopt to a UniFi controller, jump to provisioning,
/// open the web UI, or copy the IP — *without* having to navigate
/// out of the scan results sheet. Vendor-specific entries (e.g.
/// "Adopt to UniFi controller") only render when the host's
/// detected device type matches.
private struct HostRow: View {
    let host: ActiveHost
    /// Callback for actions that need a sheet (Add SSH, Adopt).
    let onAction: (NetworkScanSheet.HostAction) -> Void
    /// Callback for the "Provision config" action — navigates
    /// out of this sheet so left to the parent to coordinate.
    let onProvision: (ActiveHost) -> Void
    let onOpenInBrowser: (ActiveHost) -> Void
    let onCopyIp: (ActiveHost) -> Void

    private var deviceType: DeviceType {
        NetworkScanSheet.deviceType(for: host)
    }

    private var hasWebPort: Bool {
        host.probes.contains(where: { p in
            let s = p.service.lowercased()
            return s.contains("http") || p.port == 443 || p.port == 80
                || p.port == 8443 || p.port == 8080
        })
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            // Vendor pill — gives instant signal that "this is
            // a UniFi" so the operator knows what action to use.
            vendorIcon
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(host.ip)
                        .font(.body.monospaced().weight(.medium))
                    Text("·")
                        .foregroundStyle(.tertiary)
                    Text(deviceType.displayName)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                    if let name = host.hostname, !name.isEmpty {
                        Text(name)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    if host.findingCount > 0 {
                        Label(
                            "\(host.findingCount)",
                            systemImage: "exclamationmark.triangle.fill"
                        )
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.orange)
                    }
                    Text("\(host.probes.count) ports")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                if !host.probes.isEmpty {
                    Text(portsSummary(host))
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }
            actionMenu
        }
        .padding(.vertical, 4)
    }

    private var vendorIcon: some View {
        let (sym, tint) = vendorBadge
        return Image(systemName: sym)
            .font(.system(size: 18))
            .foregroundStyle(tint)
            .frame(width: 26, height: 26)
            .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
    }

    private var vendorBadge: (String, Color) {
        switch deviceType {
        case .unifi: return ("wifi", .blue)
        case .fortigate: return ("shield.lefthalf.filled", .red)
        case .pfSense: return ("shield.lefthalf.filled", .orange)
        case .openWrt: return ("antenna.radiowaves.left.and.right", .purple)
        case .windows: return ("pc", .cyan)
        case .linux: return ("terminal", .green)
        case .custom: return ("desktopcomputer", .gray)
        }
    }

    private var actionMenu: some View {
        Menu {
            Button {
                onAction(.addSsh(host))
            } label: {
                Label("Add as SSH host…", systemImage: "terminal")
            }
            if deviceType == .unifi {
                Button {
                    onAction(.adoptUnifi(host))
                } label: {
                    Label(
                        "Adopt to UniFi controller…",
                        systemImage: "antenna.radiowaves.left.and.right.circle.fill"
                    )
                }
            }
            Button {
                onProvision(host)
            } label: {
                Label("Open Provisioning…", systemImage: "doc.text.fill")
            }
            Divider()
            if hasWebPort {
                Button {
                    onOpenInBrowser(host)
                } label: {
                    Label("Open web UI in browser", systemImage: "safari")
                }
            }
            Button {
                onCopyIp(host)
            } label: {
                Label("Copy IP", systemImage: "doc.on.doc")
            }
        } label: {
            Image(systemName: "ellipsis.circle.fill")
                .font(.system(size: 20))
                .foregroundStyle(.tint)
                .contentShape(Rectangle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Actions for this host")
    }

    private func portsSummary(_ h: ActiveHost) -> String {
        h.probes
            .sorted(by: { $0.port < $1.port })
            .map { "\($0.port)/\($0.service)" }
            .joined(separator: ", ")
    }
}

/// Inline sheet for "Adopt to UniFi controller". Two steps in
/// one panel: add the host to the SSH inventory (with the
/// factory-default `ubnt`/`ubnt` creds the operator just types
/// once here), then immediately run `set-inform <controller>`
/// over SSH. The discovered device starts trying to register
/// with the controller within a few seconds.
private struct UnifiAdoptInlineSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState
    let host: ActiveHost

    @State private var label: String = ""
    @State private var username: String = "ubnt"
    @State private var password: String = "ubnt"
    @State private var controllerUrl: String =
        "http://unifi.example.lan:8080/inform"
    @State private var group: String = ""
    @State private var step: String = ""
    @State private var output: String?
    @State private var errorMessage: String?
    @State private var running: Bool = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "antenna.radiowaves.left.and.right.circle.fill")
                    .foregroundStyle(.blue).imageScale(.large)
                VStack(alignment: .leading) {
                    Text("Adopt UniFi device to controller")
                        .font(.headline)
                    Text(
                        "Adds \(host.ip) as an SSH host with default "
                        + "`ubnt`/`ubnt` creds, then runs `set-inform "
                        + "<controller>` over SSH so the device registers "
                        + "with your UniFi controller."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(12)
            .background(.background.secondary)

            Form {
                Section("SSH login") {
                    TextField("Label", text: $label)
                    Text(host.ip).font(.body.monospaced()).foregroundStyle(.secondary)
                    TextField("Username", text: $username)
                    SecureField("Password", text: $password)
                    Picker("Group", selection: $group) {
                        Text("Ungrouped").tag("")
                        ForEach(appState.customers) { c in
                            Text("\(c.displayName) (\(c.slug))").tag(c.slug)
                        }
                    }
                }
                Section("Controller") {
                    TextField(
                        "http://controller.lan:8080/inform",
                        text: $controllerUrl
                    )
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    Text(
                        "Full URL including scheme + `/inform`. UniFi "
                        + "controllers default to port 8080 for inform "
                        + "traffic; the UI itself lives on 8443."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                if !step.isEmpty {
                    Section { Text(step).font(.caption) }
                }
                if let out = output {
                    Section("Controller response") {
                        Text(out)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
                if let err = errorMessage {
                    Section { Text(err).foregroundStyle(.red) }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(running ? "Adopting…" : "Adopt") {
                    Task { await runAdopt() }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(running || !canSubmit)
            }
            .padding(12)
        }
        .frame(minWidth: 560, minHeight: 520)
        .onAppear {
            if label.isEmpty {
                label = "UniFi @ \(host.ip)"
            }
        }
    }

    private var canSubmit: Bool {
        !label.isEmpty
            && !username.isEmpty
            && !password.isEmpty
            && controllerUrl.contains("inform")
    }

    private func runAdopt() async {
        running = true
        defer { running = false }
        errorMessage = nil
        output = nil
        step = "Adding SSH host…"
        await appState.addHost(
            label: label,
            hostname: host.ip,
            port: 22,
            username: username,
            group: group,
            deviceType: .unifi,
            authMethod: .password,
            authKeyId: nil,
            password: password
        )
        await appState.refreshHosts()
        guard let newHost = appState.sshHosts.first(where: {
            $0.hostname == host.ip && $0.username == username
        }) else {
            errorMessage =
                "Couldn't locate the freshly-added host in inventory. "
                + "Open the SSH tab to confirm it was added, then run "
                + "set-inform from the host detail panel."
            return
        }
        step = "Running `set-inform \(controllerUrl)`…"
        if let out = await appState.unifiSetInform(
            hostId: newHost.id,
            informUrl: controllerUrl
        ) {
            output = out.isEmpty
                ? "(no stdout — UniFi `set-inform` typically prints nothing on success)"
                : out
            step = "Done. Device will appear in the controller within a few seconds."
        } else {
            errorMessage =
                "set-inform failed. The host is in inventory, "
                + "but the controller URL or creds may be wrong. "
                + "Open the host's UniFi panel for diagnostics."
        }
    }
}

private struct FindingRow: View {
    let finding: SecurityFinding
    var body: some View {
        HStack(alignment: .top) {
            SeverityBadge(severity: finding.severity)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title)
                    .font(.body.weight(.medium))
                    .lineLimit(2)
                if !finding.hostIp.isEmpty {
                    Text("\(finding.hostIp)\(finding.port.map { ":\($0)" } ?? "")")
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
        }
        .padding(.vertical, 2)
    }
}

#if DEBUG
#Preview {
    NetworkScanSheet(engagementId: "preview-eng-1", initialTargets: "192.0.2.0/24")
        .environment(AppState.previewSeeded)
}
#endif
