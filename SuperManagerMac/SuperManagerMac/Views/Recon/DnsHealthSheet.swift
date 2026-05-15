import SwiftUI

/// SPF / DKIM / DMARC / DNSSEC audit for a target domain.
/// Surfaces all four email-auth + zone-integrity components
/// plus any emitted findings in a single pass.
struct DnsHealthSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    @State private var domain: String = ""
    @State private var isRunning: Bool = false
    @State private var report: DnsHealthReport?

    var body: some View {
        VStack(spacing: 0) {
            header

            Form {
                Section {
                    HStack {
                        TextField("example.com", text: $domain)
                            .textFieldStyle(.roundedBorder)
                            .font(.body.monospaced())
                            .disabled(isRunning)
                            .onSubmit { Task { await run() } }
                        Button(isRunning ? "Auditing…" : "Run") {
                            Task { await run() }
                        }
                        .keyboardShortcut(.return, modifiers: [])
                        .disabled(isRunning || cleanDomain.isEmpty)
                    }
                } header: {
                    Text("Domain")
                } footer: {
                    Text(
                        "Checks SPF, DKIM (common selectors), DMARC, MTA-STS, "
                        + "and DNSSEC. Plus parses each record for severity issues "
                        + "(~all softfail, missing reject policy, unsigned zone, etc.)."
                    )
                    .font(.caption)
                }

                if let r = report {
                    Section("Email-auth + zone integrity") {
                        labelRow("SPF",     r.spfLabel,     severity: spfSeverity(r.spfLabel))
                        labelRow("DMARC",   r.dmarcLabel,   severity: dmarcSeverity(r.dmarcLabel))
                        labelRow("DNSSEC",  r.dnssecLabel,  severity: dnssecSeverity(r.dnssecLabel))
                        labelRow("MTA-STS", r.mtaStsLabel,  severity: .info)
                    }
                    if !r.dkimSelectorsFound.isEmpty {
                        Section("DKIM selectors found (\(r.dkimSelectorsFound.count))") {
                            ForEach(r.dkimSelectorsFound, id: \.self) {
                                Text($0).font(.body.monospaced())
                            }
                        }
                    }
                    if !r.mxRecords.isEmpty {
                        Section("MX records") {
                            ForEach(r.mxRecords, id: \.self) {
                                Text($0).font(.caption.monospaced())
                            }
                        }
                    }
                    if !r.findings.isEmpty {
                        Section("Findings (\(r.findings.count))") {
                            ForEach(Array(r.findings.enumerated()), id: \.offset) { _, f in
                                FindingRow(finding: f)
                            }
                        }
                    } else {
                        Section {
                            Text("✓ No DNS-health findings emitted.")
                                .foregroundStyle(.green)
                        }
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(12)
        }
        .frame(minWidth: 560, minHeight: 420)
    }

    private var header: some View {
        HStack {
            Image(systemName: "envelope.badge.shield.half.filled")
                .foregroundStyle(.tint).imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("Email + DNS health audit").font(.headline)
                Text("SPF / DKIM / DMARC / DNSSEC posture check")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(.background.secondary)
    }

    private var cleanDomain: String {
        domain.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func run() async {
        guard !cleanDomain.isEmpty else { return }
        isRunning = true
        defer { isRunning = false }
        report = await appState.runDnsHealthAudit(domain: cleanDomain)
    }

    // MARK: - Severity from label-tag

    private enum RowSeverity { case info, ok, warn, bad }

    /// Derive severity from the Rust enum variant tag (e.g.
    /// "Strict" / "Missing" / "None"). The label IS the tag —
    /// see DnsHealthReport's custom decoder.
    private func spfSeverity(_ tag: String) -> RowSeverity {
        switch tag {
        case "Strict": return .ok
        case "Soft", "Neutral", "NoTerminator": return .warn
        case "Missing", "Permissive", "Multiple": return .bad
        default: return .info
        }
    }

    private func dmarcSeverity(_ tag: String) -> RowSeverity {
        switch tag {
        case "Reject": return .ok
        case "Quarantine": return .warn
        case "Missing", "None", "Malformed", "Multiple": return .bad
        default: return .info
        }
    }

    private func dnssecSeverity(_ tag: String) -> RowSeverity {
        switch tag {
        case "Signed": return .ok
        case "Unsigned": return .warn
        default: return .info
        }
    }

    @ViewBuilder
    private func labelRow(_ component: String, _ tag: String, severity: RowSeverity) -> some View {
        HStack {
            Image(systemName: iconFor(severity))
                .foregroundStyle(colorFor(severity))
                .frame(width: 20)
            Text(component).font(.body.weight(.medium))
                .frame(width: 70, alignment: .leading)
            Text(tag).font(.body.monospaced())
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    private func iconFor(_ s: RowSeverity) -> String {
        switch s {
        case .ok: return "checkmark.circle.fill"
        case .info: return "info.circle"
        case .warn: return "exclamationmark.triangle.fill"
        case .bad: return "xmark.octagon.fill"
        }
    }

    private func colorFor(_ s: RowSeverity) -> Color {
        switch s {
        case .ok: return .green
        case .info: return .secondary
        case .warn: return .orange
        case .bad: return .red
        }
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
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(6)
            }
        }
        .padding(.vertical, 4)
    }
}

#if DEBUG
#Preview {
    DnsHealthSheet().environment(AppState.previewSeeded)
}
#endif
