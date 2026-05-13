import SwiftUI

/// "Capture insecure traffic" — kicks off a passive packet
/// capture via the privileged helper (`tcpdump` as root) for a
/// bounded duration, then analyses the pcap for cleartext-
/// credential exposure. Live progress polls the engine's
/// analyse-pcap endpoint every 5 seconds during the capture so
/// the finding count climbs in real-time.
///
/// Detects: FTP, Telnet, HTTP basic-auth, HTTP form-POST,
/// POP3, IMAP, SMTP cleartext AUTH, SNMP community strings,
/// NTLM handshakes, MQTT cleartext.
///
/// Evidence: the full unredacted .pcap is written to the
/// engagement's `captures/` directory for Wireshark / DLP
/// review. The engine also writes per-finding redacted
/// excerpts (passwords SHA-256 hashed) for embedding in
/// customer reports.
struct TrafficCaptureSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    /// Engagement to scope the capture under. Required: the pcap
    /// goes into `<engagement>/captures/` and the BPF filter is
    /// constructed from the engagement's `scope_cidrs`.
    let engagementId: String

    @State private var interface: String = "en0"
    @State private var durationSeconds: Double = 60
    @State private var isCapturing: Bool = false
    @State private var pcapPath: String?
    @State private var liveFindings: [SecurityFinding] = []
    @State private var packetsInspected: Int = 0
    @State private var startedAt: Date?
    @State private var pollTask: Task<Void, Never>?
    @State private var captureTask: Task<Void, Never>?
    @State private var status: String?
    @State private var completed: Bool = false

    var body: some View {
        VStack(spacing: 0) {
            header

            Form {
                Section("Capture options") {
                    Picker("Interface", selection: $interface) {
                        ForEach(commonInterfaces, id: \.self) { iface in
                            Text(iface).tag(iface)
                        }
                    }
                    .disabled(isCapturing)

                    VStack(alignment: .leading) {
                        HStack {
                            Text("Duration")
                            Spacer()
                            Text("\(Int(durationSeconds)) sec").foregroundStyle(.secondary).font(.caption)
                        }
                        Slider(value: $durationSeconds, in: 30...600, step: 30)
                            .disabled(isCapturing)
                    }
                }

                if let status = status {
                    Section {
                        HStack {
                            if isCapturing && !completed {
                                ProgressView().controlSize(.small)
                            } else if completed {
                                Image(systemName: liveFindings.isEmpty
                                      ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                    .foregroundStyle(liveFindings.isEmpty ? .green : .orange)
                            }
                            Text(status)
                            Spacer()
                        }
                    }
                }

                if !liveFindings.isEmpty {
                    Section("Findings — \(liveFindings.count) so far") {
                        ForEach(Array(liveFindings.enumerated()), id: \.offset) { _, f in
                            FindingRow(finding: f)
                        }
                    }
                }

                if let pcap = pcapPath, completed {
                    Section("Evidence") {
                        LabeledContent("Full .pcap") {
                            HStack {
                                Text(pcap).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                                Button(action: { revealInFinder(path: pcap) }) {
                                    Image(systemName: "magnifyingglass")
                                }.buttonStyle(.borderless)
                            }
                        }
                        Text("Open the .pcap in Wireshark for full unredacted packet review. Per-finding redacted excerpts (passwords SHA-256 hashed) are in the same directory.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                if isCapturing && !completed {
                    Button("Cancel", role: .destructive) { stop() }
                }
                Spacer()
                if !isCapturing {
                    Button("Start capture") { start() }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.return, modifiers: .command)
                }
                Button(completed ? "Done" : "Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(12)
        }
        .frame(minWidth: 620, minHeight: 480)
        .onDisappear {
            pollTask?.cancel()
            captureTask?.cancel()
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "waveform.path.ecg.rectangle")
                .foregroundStyle(.tint)
                .imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("Capture insecure traffic").font(.headline)
                Text("Detects cleartext credentials + protocols on the wire — PoC evidence for customer audits")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(.background.secondary)
    }

    /// Common macOS interfaces. The user can also type something
    /// else if they're on a weird config — but for the GUI we
    /// stick to a curated list.
    private var commonInterfaces: [String] {
        ["en0", "en1", "en2", "utun0", "lo0", "bridge100"]
    }

    private func start() {
        isCapturing = true
        completed = false
        liveFindings = []
        packetsInspected = 0
        pcapPath = nil
        startedAt = Date()
        let duration = Int(durationSeconds)
        let pcapBasename = "traffic-\(ISO8601DateFormatter().string(from: Date()))"
            .replacingOccurrences(of: ":", with: "-")
        let pcapFile = "\(pcapBasename).pcap"
        // Engagement directory built by the engine; we just say "where".
        let home = NSHomeDirectory()
        let path = "\(home)/Library/Application Support/SuperManager/findings_store/\(engagementId)/captures/\(pcapFile)"
        pcapPath = path
        status = "Starting capture on \(interface) for \(duration) sec…"

        captureTask = Task {
            do {
                let report = try await appState.startTrafficCapture(
                    interface: interface,
                    outputPath: path,
                    bpfFilter: AppState.cleartextProtocolBpf,
                    durationSecs: duration
                )
                await MainActor.run {
                    // Capture has completed — do one final analysis pass.
                    status = "Capture complete (\(report.packetCountEstimate) packets). Analysing…"
                }
                await analyseOnce(path: path, isFinal: true)
                await MainActor.run {
                    completed = true
                    isCapturing = false
                    if liveFindings.isEmpty {
                        status = "✓ No cleartext credentials seen in \(duration) sec."
                    } else {
                        status = "\(liveFindings.count) cleartext-credential cluster(s) captured. Evidence saved."
                    }
                }
            } catch {
                await MainActor.run {
                    status = "Capture failed: \(error.localizedDescription)"
                    isCapturing = false
                }
            }
        }

        // Live-polling loop: every 5 seconds, analyse whatever's
        // in the pcap so far and update the findings list.
        pollTask = Task {
            try? await Task.sleep(for: .seconds(3))
            while !Task.isCancelled && isCapturing && !completed {
                await analyseOnce(path: path, isFinal: false)
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    private func analyseOnce(path: String, isFinal: Bool) async {
        guard let r = await appState.analyseTrafficPcap(
            pcapPath: path,
            engagementId: engagementId
        ) else {
            return
        }
        await MainActor.run {
            liveFindings = r.findings
            packetsInspected = r.packetsInspected
            if !completed {
                let elapsed = Int(Date().timeIntervalSince(startedAt ?? Date()))
                let total = Int(durationSeconds)
                status = "Capturing… \(elapsed)/\(total) sec · \(r.eventsMatched) event(s) so far · \(r.packetsInspected) packets inspected"
            }
        }
    }

    private func stop() {
        captureTask?.cancel()
        pollTask?.cancel()
        isCapturing = false
        status = "Cancelled."
    }

    private func revealInFinder(path: String) {
        let url = URL(fileURLWithPath: path)
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}

private struct FindingRow: View {
    let finding: SecurityFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                SeverityBadge(severity: finding.severity)
                Text(finding.title).font(.body.weight(.medium))
                Spacer()
            }
            if !finding.detail.isEmpty {
                Text(finding.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(4)
            }
        }
        .padding(.vertical, 4)
    }
}

#if DEBUG
#Preview {
    TrafficCaptureSheet(engagementId: "preview-eng-1")
        .environment(AppState.previewSeeded)
}
#endif
