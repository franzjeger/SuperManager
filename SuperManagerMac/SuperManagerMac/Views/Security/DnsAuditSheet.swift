import SwiftUI

/// "Run DNS audit" — kicks off a zone-transfer (AXFR) probe
/// against every authoritative NS of the given domain. A
/// successful transfer leaks the entire zone, which is one of
/// the highest-signal-to-effort recon findings an MSP audit
/// can produce.
///
/// Backed by the engine's `discovery_dns_axfr` RPC. The probe
/// shells out to `dig` (no extra deps) and runs ~5-8 sec per NS;
/// typical domain has 2-4 NSes so wall-clock is 10-30 sec.
struct DnsAuditSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    @State private var domain: String = ""
    @State private var isRunning: Bool = false
    @State private var findings: [SecurityFinding] = []
    @State private var resultBanner: String?
    @State private var hasRun: Bool = false

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
                        Button(isRunning ? "Probing…" : "Run") {
                            Task { await run() }
                        }
                        .keyboardShortcut(.return, modifiers: [])
                        .disabled(isRunning || cleanDomain.isEmpty)
                    }
                } header: {
                    Text("Domain")
                } footer: {
                    Text(
                        "Probes every authoritative nameserver for the domain "
                        + "with `dig @<ns> AXFR <domain>`. A successful transfer "
                        + "dumps the entire zone — A / CNAME / MX / TXT / SRV. "
                        + "Most authoritative DNS rejects this; the ones that "
                        + "don't are immediate findings."
                    )
                    .font(.caption)
                }

                if let banner = resultBanner {
                    Section {
                        Text(banner)
                            .foregroundStyle(findings.isEmpty ? .green : .orange)
                    }
                }

                if !findings.isEmpty {
                    Section("Findings") {
                        ForEach(Array(findings.enumerated()), id: \.offset) { _, f in
                            FindingRow(finding: f)
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
        .frame(minWidth: 560, minHeight: 380)
    }

    private var header: some View {
        HStack {
            Image(systemName: "network.badge.shield.half.filled")
                .foregroundStyle(.tint)
                .imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("DNS zone-transfer audit").font(.headline)
                Text("Detects misconfigured authoritative DNS that leaks the zone")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(.background.secondary)
    }

    private var cleanDomain: String {
        domain.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func run() async {
        guard !cleanDomain.isEmpty else { return }
        isRunning = true
        findings = []
        resultBanner = nil
        defer { isRunning = false }

        if let result = await appState.runDnsAxfr(domain: cleanDomain) {
            findings = result
            hasRun = true
            if result.isEmpty {
                resultBanner = "✓ No AXFR leakage detected. Every authoritative NS refused the transfer."
            } else {
                resultBanner = "⚠ \(result.count) nameserver(s) leaked the zone."
            }
        } else {
            resultBanner = "Could not query the domain — check the daemon is running and the domain resolves."
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
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(6)
            }
        }
        .padding(.vertical, 4)
    }
}

#if DEBUG
#Preview("Empty") {
    DnsAuditSheet()
        .environment(AppState.previewSeeded)
}
#endif
