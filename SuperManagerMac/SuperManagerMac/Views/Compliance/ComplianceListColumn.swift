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
    @State private var showingAddHost = false
    @State private var scanAllResultBanner: String?

    /// Hosts the compliance allowlist routes to a baseline runner —
    /// FortiGate (REST API) and Linux (SSH) today (1.12b). Anything
    /// outside the allowlist is filtered out so the list never
    /// surfaces a row that would dispatch to nothing.
    ///
    /// Allowlist source-of-truth lives on `DeviceType.complianceDispatch`;
    /// adding a new DeviceType case fails the build there until
    /// classified, which keeps this filter in sync without manual
    /// updates here.
    private var complianceCapableHosts: [SshHostSummary] {
        let global = appState.globalCustomerSlug
        return appState.sshHosts
            .filter { $0.deviceType.complianceDispatch != .notApplicable }
            .filter { global.isEmpty || $0.group == global }
    }

    /// FortiGate-only subset, used to gate the "Scan all" toolbar
    /// affordance. Auto-scan-on-launch and scan-all stay FortiGate-
    /// only in 1.12b by design — widening them to Linux would
    /// sweep every credentialed SSH host on launch (SSH pool
    /// pressure, drift-notification volume on a previously-
    /// unscanned fleet). 1.12c+ can revisit once there's real
    /// Linux-host usage to size the blast radius against.
    private var fortigateScannableHosts: [SshHostSummary] {
        complianceCapableHosts.filter { $0.deviceType == .fortigate && $0.hasApi }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Only show the actions bar when there's something to
            // act on. Previously it rendered above the empty state
            // with a lone Library button floating in the upper
            // right — looked disconnected from anything. The
            // Library now lives as a secondary CTA inside the
            // empty state itself.
            if !complianceCapableHosts.isEmpty {
                actionsBar
            }
            if let banner = scanAllResultBanner {
                Text(banner)
                    .font(.caption)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.tint.opacity(0.12))
            }
            if complianceCapableHosts.isEmpty {
                ContentUnavailableView {
                    Label("No compliance-capable hosts", systemImage: "shield.lefthalf.filled")
                } description: {
                    Text("Compliance scans run against FortiGate hosts (REST API) and Linux hosts (SSH). Add a host below — device type defaults to FortiGate; switch the picker to Linux for Ubuntu/Debian/RHEL hosts.")
                } actions: {
                    VStack(spacing: 8) {
                        // Primary CTA stays on FortiGate as the
                        // default — the dominant use case today.
                        // Operator can switch the picker in
                        // AddHostSheet to Linux.
                        Button {
                            showingAddHost = true
                        } label: {
                            Label("Add host…", systemImage: "plus")
                        }
                        .buttonStyle(.borderedProminent)
                        Button {
                            showingChecksLibrary = true
                        } label: {
                            Label("Browse checks library", systemImage: "books.vertical")
                        }
                        .buttonStyle(.borderless)
                        .foregroundStyle(.tint)
                    }
                }
            } else {
                List(selection: Binding(
                    get: { appState.selectedHostId },
                    set: { appState.selectedHostId = $0 }
                )) {
                    ForEach(complianceCapableHosts) { host in
                        row(for: host)
                            .tag(host.id)
                    }
                }
                .listStyle(.sidebar)
            }
        }
        .task {
            // On entry to the section, kick off a parallel history
            // fetch for every compliance-capable host so the
            // score pills render with cached data, not "—".
            // FortiGate without an API token can't be scanned so
            // skip those (no history exists). Linux has no
            // hasApi concept — fetch unconditionally.
            for host in complianceCapableHosts {
                if host.deviceType == .fortigate && !host.hasApi { continue }
                Task { await appState.loadComplianceHistory(hostId: host.id, limit: 5) }
            }
            await appState.loadComplianceCheckLibrary()
        }
        .sheet(isPresented: $showingChecksLibrary) {
            ChecksLibrarySheet()
        }
        .sheet(isPresented: $showingAddHost) {
            // Default to FortiGate as the dominant case; operator
            // can switch to Linux in the device-type picker before
            // saving. After save, the new host appears in the SSH
            // list AND in this compliance list (via the
            // allowlist filter on `complianceDispatch`), so the
            // empty state self-replaces with the host row +
            // (for FortiGate) scan-all action bar.
            AddHostSheet(defaultDeviceType: .fortigate)
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
            if !fortigateScannableHosts.isEmpty {
                Button {
                    Task { await runScanAll() }
                } label: {
                    if appState.complianceScanAllInFlight {
                        // Live counter: how many hosts done / total.
                        // The progress map is updated as each per-
                        // host fan-out completes, so the user sees
                        // "Scanning 3/12" instead of an opaque spinner.
                        let total = appState.complianceScanProgress.count
                        let done = appState.complianceScanProgress.values
                            .filter { $0 == "done" || $0 == "failed" }
                            .count
                        HStack(spacing: 4) {
                            ProgressView().controlSize(.small)
                            Text(total > 0 ? "Scanning \(done)/\(total)" : "Scanning…")
                                .monospacedDigit()
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
        // Use the concurrent fan-out variant so the per-host
        // progress map fills in incrementally — drives the
        // "Scanning 3/12" counter on the toolbar button.
        let results = await appState.runComplianceScanAllConcurrent()
        let succeeded = results.filter { $0.runId != nil }.count
        let failed = results.filter { $0.error != nil && $0.runId == nil }.count
        scanAllResultBanner =
            "Scanned \(succeeded) host\(succeeded == 1 ? "" : "s")"
            + (failed > 0 ? ", \(failed) failed" : "")
        // Auto-dismiss the banner + clear progress after a few
        // seconds so the toolbar button returns to its idle state.
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(8))
            scanAllResultBanner = nil
            appState.clearComplianceScanProgress()
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
                } else if host.deviceType == .fortigate && !host.hasApi {
                    // "API token required" is FortiGate-specific —
                    // `hasApi` is the FortiGate REST API token
                    // flag, with no Linux equivalent. Linux hosts
                    // never reach this branch.
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
            scorePill(score: lastScore, host: host)
        }
        .padding(.vertical, 2)
    }

    /// Three-state pill: explicit number when we have a run, "—"
    /// when there's no score yet. The "—" colour signals whether
    /// setup is needed (orange for FortiGate-without-API-token —
    /// actionable; secondary for everything else — just waiting
    /// for a scan). Number pill colour follows the score-grade
    /// table (green ≥ 90, yellow ≥ 70, red < 70).
    private func scorePill(score: UInt8?, host: SshHostSummary) -> some View {
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
        let needsSetup = host.deviceType == .fortigate && !host.hasApi
        let color: Color = needsSetup ? .orange : .secondary
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
