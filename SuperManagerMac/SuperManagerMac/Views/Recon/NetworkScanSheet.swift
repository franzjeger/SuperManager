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
                        Section("Hosts (\(r.hosts.count))") {
                            ForEach(r.hosts) { host in
                                HostRow(host: host)
                            }
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
}

// MARK: - Sub-rows

private struct HostRow: View {
    let host: ActiveHost

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(host.ip).font(.body.monospaced().weight(.medium))
                if let name = host.hostname, !name.isEmpty {
                    Text(name)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if host.findingCount > 0 {
                    Label("\(host.findingCount)", systemImage: "exclamationmark.triangle.fill")
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
        .padding(.vertical, 2)
    }

    private func portsSummary(_ h: ActiveHost) -> String {
        h.probes
            .sorted(by: { $0.port < $1.port })
            .map { "\($0.port)/\($0.service)" }
            .joined(separator: ", ")
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
