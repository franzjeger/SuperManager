import SwiftUI

/// Middle column of the Compliance section. Shows one row per
/// FortiGate host with a live score pill so the user can see
/// fleet posture at a glance, then drill into one host for the
/// full run breakdown.
///
/// Scores come from the most recently fetched run summary (if
/// any). On appear the view kicks off a history fetch for each
/// host so the pills hydrate without an explicit run. Hosts
/// without an API token configured render with a "—" pill and
/// a discoverable hint.
struct ComplianceListColumn: View {
    @Environment(AppState.self) private var appState

    @State private var showingChecksLibrary = false
    @State private var scanAllResultBanner: String?

    /// FortiGate hosts only — compliance checks target FortiOS.
    /// Filtered by global customer-context when set; otherwise
    /// all FortiGate hosts across the fleet.
    /// Other device types will surface in later phases (UniFi,
    /// pfSense, …) once we have framework definitions for them.
    private var fortigateHosts: [SshHostSummary] {
        let global = appState.globalCustomerSlug
        return appState.sshHosts
            .filter { $0.deviceType == .fortigate }
            .filter { global.isEmpty || $0.group == global }
    }

    var body: some View {
        VStack(spacing: 0) {
            actionsBar
            if let banner = scanAllResultBanner {
                Text(banner)
                    .font(.caption)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.tint.opacity(0.12))
            }
            if fortigateHosts.isEmpty {
                ContentUnavailableView {
                    Label("No FortiGate hosts", systemImage: "shield.lefthalf.filled")
                } description: {
                    Text("Compliance scans require a FortiGate host with a REST API token. Add a host in the SSH section, set its device type to FortiGate, and generate a token.")
                } actions: {
                    Button {
                        appState.selectedSection = .ssh
                    } label: {
                        Label("Go to SSH", systemImage: "terminal")
                    }
                    .buttonStyle(.borderedProminent)
                }
            } else {
                List(selection: Binding(
                    get: { appState.selectedHostId },
                    set: { appState.selectedHostId = $0 }
                )) {
                    ForEach(fortigateHosts) { host in
                        row(for: host)
                            .tag(host.id)
                    }
                }
                .listStyle(.sidebar)
            }
        }
        .task {
            // On entry to the section, kick off a parallel
            // history fetch for every FortiGate host so the
            // score pills render with cached data, not "—".
            for host in fortigateHosts where host.hasApi {
                Task { await appState.loadComplianceHistory(hostId: host.id, limit: 5) }
            }
            await appState.loadComplianceCheckLibrary()
        }
        .sheet(isPresented: $showingChecksLibrary) {
            ChecksLibrarySheet()
        }
    }

    /// Top action bar: scan-all (only when there are scannable
    /// hosts) and "Browse checks" (always — useful even before
    /// hosts exist for understanding what we evaluate against).
    private var actionsBar: some View {
        HStack(spacing: 8) {
            Spacer()
            Button {
                showingChecksLibrary = true
            } label: {
                Label("Library", systemImage: "books.vertical")
            }
            .controlSize(.small)
            if !fortigateHosts.filter(\.hasApi).isEmpty {
                Button {
                    Task { await runScanAll() }
                } label: {
                    if appState.complianceScanAllInFlight {
                        HStack(spacing: 4) {
                            ProgressView().controlSize(.small)
                            Text("Scanning…")
                        }
                    } else {
                        Label("Scan all", systemImage: "checkmark.shield.fill")
                    }
                }
                .controlSize(.small)
                .buttonStyle(.borderedProminent)
                .disabled(appState.complianceScanAllInFlight)
            }
        }
        .padding(8)
    }

    private func runScanAll() async {
        scanAllResultBanner = nil
        guard let results = await appState.runComplianceScanAll(unconditional: true) else {
            return
        }
        let succeeded = results.filter { $0.runId != nil }.count
        let failed = results.filter { $0.error != nil && $0.runId == nil }.count
        scanAllResultBanner =
            "Scanned \(succeeded) host\(succeeded == 1 ? "" : "s")"
            + (failed > 0 ? ", \(failed) failed" : "")
        // Auto-dismiss the banner after a few seconds so it
        // doesn't persist forever; users can re-trigger to see
        // updated text.
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(8))
            scanAllResultBanner = nil
        }
    }

    @ViewBuilder
    private func row(for host: SshHostSummary) -> some View {
        let history = appState.complianceHistory[host.id] ?? []
        let lastScore = history.first?.score
        let lastRunAt = history.first?.startedAt

        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(host.label)
                    .fontWeight(.medium)
                Text("\(host.username)@\(host.hostname)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                if let lastRunAt {
                    Text("Last run \(lastRunAt.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                } else if !host.hasApi {
                    Text("API token required")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                } else {
                    Text("Never scanned")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            scorePill(score: lastScore, hasApi: host.hasApi)
        }
        .padding(.vertical, 2)
    }

    /// Three-state pill: explicit number when we have a run, "—"
    /// when API token is missing or no scan has run yet. Number
    /// pill colour follows the score-grade table (green ≥ 90,
    /// yellow ≥ 70, red < 70).
    private func scorePill(score: UInt8?, hasApi: Bool) -> some View {
        if let s = score {
            let color: Color = s >= 90 ? .green : (s >= 70 ? .orange : .red)
            return AnyView(
                Text("\(s)")
                    .font(.callout.weight(.semibold))
                    .monospacedDigit()
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(color.opacity(0.15))
                    .foregroundStyle(color)
                    .clipShape(Capsule())
            )
        }
        let color: Color = hasApi ? .secondary : .orange
        return AnyView(
            Text("—")
                .font(.callout)
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(color.opacity(0.15))
                .foregroundStyle(color)
                .clipShape(Capsule())
        )
    }
}
