import SwiftUI
import Charts

/// Live dashboard for a FortiGate. Mounts when a FortiGate host is
/// selected, polls `fortigate_get_dashboard` every 5 seconds while
/// visible, and renders:
///
///   1. **Identity strip** — model, FortiOS version, uptime, serial.
///      Reads at-a-glance the way the FortiGate web GUI's banner does.
///
///   2. **KPI cards** — CPU, memory, sessions, disk. Numeric value
///      + tinted circle that fills to indicate utilisation. Color
///      grades (green / yellow / red) by threshold so the user
///      sees "everything fine" or "this CPU is hot" instantly.
///
///   3. **Throughput sparkline** — aggregate RX/TX rate across
///      WAN-tagged interfaces over the last ~60 s. Computed
///      client-side from successive snapshots' byte-counter
///      deltas. Sparkline = `Charts` framework's tiny line plot.
///
///   4. **Interface table** — one row per physical/aggregate
///      interface, with status pill, link speed, and live rate.
///
/// Polling is deliberately client-side (rather than a daemon push):
/// the daemon already has 4 RPCs in flight per tick and adding a
/// pub/sub layer doubles complexity for marginal latency gain. 5 s
/// matches the FortiGate web GUI's own dashboard refresh and is
/// well below the rate at which FortiOS resource-usage data is
/// itself updated.
///
/// On host change, all history clears: a different device's
/// throughput shouldn't blend into ours.
struct FortigateDashboardPanel: View {
    @Environment(AppState.self) private var appState
    let hostId: String

    /// Most recent successfully-fetched snapshot. nil before the
    /// first tick or after the host changes; the view shows a
    /// skeleton state in that case.
    @State private var snapshot: AppState.FortigateDashboardSnapshot?

    /// Ring of (timestamp, snapshot) for throughput-rate
    /// derivation. Capped to ~12 entries (60 s at 5 s cadence)
    /// so memory stays bounded if the user leaves the view open
    /// for hours.
    @State private var history: [HistoryEntry] = []

    /// True between `appState.fetchFortigateDashboard` start and
    /// finish — drives the small spinner in the header. Distinct
    /// from "we have no data" so the UI can show "refreshing"
    /// without yanking back to skeleton state.
    @State private var refreshing = false

    /// Set if the most recent fetch failed. Cleared on next
    /// successful tick. After 2+ consecutive failures the
    /// header shows "stale" so the user knows to investigate.
    @State private var consecutiveFailures = 0

    private static let pollInterval: Duration = .seconds(5)
    private static let historyCap = 24  // 2 minutes at 5 s cadence

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            if let s = snapshot {
                if let status = s.status {
                    identityStrip(status)
                }
                if let resource = s.resource {
                    kpiGrid(resource, vpn: s.vpn)
                }
                throughputSection
                if let interfaces = s.interfaces, !interfaces.isEmpty {
                    interfaceTable(interfaces)
                }
            } else {
                skeletonContent
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(.separator, lineWidth: 0.5)
        )
        .task(id: hostId) {
            // Clear history whenever the host changes — different
            // device, different baseline. Otherwise we'd compute
            // spurious "rate" from one device's bytes minus
            // another's.
            history.removeAll()
            snapshot = nil
            consecutiveFailures = 0
            await pollLoop()
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: "gauge.with.dots.needle.67percent")
                .foregroundStyle(.tint)
            Text("Live Dashboard")
                .font(.headline)
            Spacer()
            if refreshing {
                ProgressView().controlSize(.small)
            } else if consecutiveFailures >= 2 {
                Label("Stale", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            } else if let s = snapshot {
                Text("Updated \(relativeTime(from: s.fetchedAt))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Identity strip

    private func identityStrip(_ status: AppState.DashboardStatus) -> some View {
        HStack(spacing: 16) {
            kvPair("Model", status.model)
            kvPair("FortiOS", status.version)
            kvPair("Hostname", status.hostname)
            kvPair("Uptime", uptimeFormatted(status.uptimeSeconds))
            Spacer()
            Text(status.serial)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.tertiary)
                .textSelection(.enabled)
        }
        .padding(.vertical, 4)
    }

    private func kvPair(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label)
                .font(.caption2)
                .foregroundStyle(.tertiary)
            Text(value)
                .font(.callout.weight(.medium))
                .lineLimit(1)
        }
    }

    // MARK: - KPI grid

    private func kpiGrid(
        _ r: AppState.DashboardResource,
        vpn: AppState.DashboardVpn?
    ) -> some View {
        HStack(spacing: 8) {
            kpiCard(label: "CPU", value: "\(r.cpuPct)%", pct: Double(r.cpuPct), icon: "cpu")
            kpiCard(label: "Memory", value: "\(r.memPct)%", pct: Double(r.memPct), icon: "memorychip")
            kpiCard(
                label: "Sessions",
                value: formatThousands(r.sessions),
                pct: nil,
                icon: "network"
            )
            kpiCard(label: "Disk", value: "\(r.diskPct)%", pct: Double(r.diskPct), icon: "internaldrive")
            if let v = vpn {
                kpiCard(
                    label: "Tunnels",
                    value: "\(v.tunnelsUp)/\(v.tunnelsTotal)",
                    pct: nil,
                    icon: "link"
                )
            }
        }
    }

    /// Single KPI tile. `pct` drives the colour (green ≤ 60,
    /// yellow ≤ 85, red > 85) and the circular fill. Counter
    /// metrics (sessions, tunnels) pass nil and just render the
    /// value with a neutral tint.
    private func kpiCard(label: String, value: String, pct: Double?, icon: String) -> some View {
        let color: Color = {
            guard let pct else { return .blue }
            if pct >= 85 { return .red }
            if pct >= 60 { return .orange }
            return .green
        }()
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.caption)
                    .foregroundStyle(color)
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if let pct {
                    ZStack {
                        Circle()
                            .stroke(color.opacity(0.18), lineWidth: 3)
                        Circle()
                            .trim(from: 0, to: max(0.02, pct / 100))
                            .stroke(color, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                    }
                    .frame(width: 18, height: 18)
                }
            }
            Text(value)
                .font(.title3.weight(.semibold))
                .monospacedDigit()
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.06))
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(color.opacity(0.18), lineWidth: 0.5)
        )
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    // MARK: - Throughput sparkline

    /// Aggregate WAN-tagged throughput over the last few snapshots.
    /// Implementation: walk pairs of (oldSnap, newSnap) in history,
    /// for each WAN-named interface (`wan*`) sum the per-second
    /// delta, plot. If history < 2 entries we render an empty
    /// chart with a "warming up" caption.
    @ViewBuilder
    private var throughputSection: some View {
        let series = throughputSeries()
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("WAN Throughput")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Spacer()
                if let latest = series.last {
                    HStack(spacing: 8) {
                        Label(formatRate(latest.rxRate), systemImage: "arrow.down")
                            .font(.caption)
                            .foregroundStyle(.green)
                            .monospacedDigit()
                        Label(formatRate(latest.txRate), systemImage: "arrow.up")
                            .font(.caption)
                            .foregroundStyle(.blue)
                            .monospacedDigit()
                    }
                }
            }
            if series.count < 2 {
                HStack {
                    Text("Warming up… (need 2+ samples)")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                    Spacer()
                }
                .frame(height: 60)
            } else {
                Chart {
                    ForEach(Array(series.enumerated()), id: \.offset) { idx, point in
                        AreaMark(
                            x: .value("t", idx),
                            y: .value("RX", point.rxRate)
                        )
                        .foregroundStyle(.green.opacity(0.25))
                        .interpolationMethod(.catmullRom)
                        AreaMark(
                            x: .value("t", idx),
                            y: .value("TX", point.txRate)
                        )
                        .foregroundStyle(.blue.opacity(0.25))
                        .interpolationMethod(.catmullRom)
                        LineMark(
                            x: .value("t", idx),
                            y: .value("RX", point.rxRate)
                        )
                        .foregroundStyle(.green)
                        .interpolationMethod(.catmullRom)
                        LineMark(
                            x: .value("t", idx),
                            y: .value("TX", point.txRate)
                        )
                        .foregroundStyle(.blue)
                        .interpolationMethod(.catmullRom)
                    }
                }
                .chartXAxis(.hidden)
                .chartYAxis {
                    AxisMarks(position: .leading) { value in
                        AxisValueLabel {
                            if let v = value.as(Double.self) {
                                Text(formatRate(v))
                                    .font(.caption2)
                            }
                        }
                        AxisGridLine()
                    }
                }
                .frame(height: 80)
            }
        }
    }

    // MARK: - Interface table

    private func interfaceTable(_ ifaces: [AppState.DashboardInterface]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Interfaces")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Spacer()
                Text("\(ifaces.count) total")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(.bottom, 6)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                GridRow {
                    Text("Interface").gridColumnAlignment(.leading)
                    Text("Status")
                    Text("Speed")
                    Text("Down").gridColumnAlignment(.trailing)
                    Text("Up").gridColumnAlignment(.trailing)
                }
                .font(.caption)
                .foregroundStyle(.tertiary)

                ForEach(ifaces) { iface in
                    GridRow {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(iface.name).font(.callout)
                            if !iface.alias.isEmpty {
                                Text(iface.alias)
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                        statusPill(iface.status)
                        Text(iface.speedMbps == 0 ? "—" : "\(iface.speedMbps) Mbps")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                        Text(formatRate(rateFor(iface.name).rx))
                            .font(.caption)
                            .foregroundStyle(.green)
                            .monospacedDigit()
                            .gridColumnAlignment(.trailing)
                        Text(formatRate(rateFor(iface.name).tx))
                            .font(.caption)
                            .foregroundStyle(.blue)
                            .monospacedDigit()
                            .gridColumnAlignment(.trailing)
                    }
                }
            }
        }
    }

    private func statusPill(_ status: String) -> some View {
        let color: Color = status == "up" ? .green : (status == "down" ? .red : .gray)
        return Text(status)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.16))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    // MARK: - Skeleton

    private var skeletonContent: some View {
        HStack {
            ProgressView()
            Text(consecutiveFailures > 0
                 ? "Could not reach FortiGate (\(consecutiveFailures) failure\(consecutiveFailures > 1 ? "s" : "")). Retrying…"
                 : "Loading dashboard…")
                .font(.callout)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.vertical, 12)
    }

    // MARK: - Polling

    /// Repeatedly fetch the dashboard while the view is mounted.
    /// `Task.sleep` yields cooperatively so the loop exits cleanly
    /// when SwiftUI cancels the .task on view-unmount.
    private func pollLoop() async {
        while !Task.isCancelled {
            await tick()
            // Use Task.sleep — it respects cancellation. If we
            // used DispatchQueue.asyncAfter the sleep wouldn't
            // abort on host change.
            do {
                try await Task.sleep(for: Self.pollInterval)
            } catch {
                break
            }
        }
    }

    private func tick() async {
        refreshing = true
        defer { refreshing = false }
        if let snap = await appState.fetchFortigateDashboard(hostId: hostId) {
            snapshot = snap
            consecutiveFailures = 0
            history.append(HistoryEntry(at: snap.fetchedAt, interfaces: snap.interfaces ?? []))
            if history.count > Self.historyCap {
                history.removeFirst(history.count - Self.historyCap)
            }
        } else {
            consecutiveFailures += 1
        }
    }

    // MARK: - Throughput math

    /// Per-interface (rx/sec, tx/sec) computed from the two most
    /// recent history entries. Returns (0, 0) for interfaces that
    /// don't exist in both.
    private func rateFor(_ ifname: String) -> (rx: Double, tx: Double) {
        guard history.count >= 2 else { return (0, 0) }
        let prev = history[history.count - 2]
        let curr = history[history.count - 1]
        let dt = curr.at.timeIntervalSince(prev.at)
        guard dt > 0 else { return (0, 0) }
        guard let p = prev.interfaces.first(where: { $0.name == ifname }),
              let c = curr.interfaces.first(where: { $0.name == ifname }) else {
            return (0, 0)
        }
        // Counter wrap (FortiOS resets counters on link-flap):
        // treat negative delta as a reset and emit 0 for that tick.
        let rxDelta = c.rxBytes >= p.rxBytes ? Double(c.rxBytes - p.rxBytes) : 0
        let txDelta = c.txBytes >= p.txBytes ? Double(c.txBytes - p.txBytes) : 0
        return (rx: rxDelta / dt, tx: txDelta / dt)
    }

    /// Aggregate throughput over WAN interfaces (`wan*`). One
    /// point per consecutive history pair → up to historyCap-1
    /// points. Empty if history < 2.
    private func throughputSeries() -> [ThroughputPoint] {
        guard history.count >= 2 else { return [] }
        var out: [ThroughputPoint] = []
        for i in 1..<history.count {
            let prev = history[i - 1]
            let curr = history[i]
            let dt = curr.at.timeIntervalSince(prev.at)
            guard dt > 0 else { continue }
            var rx: Double = 0
            var tx: Double = 0
            for c in curr.interfaces where c.name.hasPrefix("wan") {
                if let p = prev.interfaces.first(where: { $0.name == c.name }) {
                    let rxDelta = c.rxBytes >= p.rxBytes ? Double(c.rxBytes - p.rxBytes) : 0
                    let txDelta = c.txBytes >= p.txBytes ? Double(c.txBytes - p.txBytes) : 0
                    rx += rxDelta / dt
                    tx += txDelta / dt
                }
            }
            out.append(ThroughputPoint(at: curr.at, rxRate: rx, txRate: tx))
        }
        return out
    }

    // MARK: - Formatters

    private func formatRate(_ bytesPerSec: Double) -> String {
        let bps = bytesPerSec * 8  // convert to bits/sec for network-conventional display
        let units = ["bps", "Kbps", "Mbps", "Gbps"]
        var v = bps
        var u = 0
        while v >= 1000 && u < units.count - 1 {
            v /= 1000
            u += 1
        }
        if u == 0 {
            return "\(Int(v)) \(units[u])"
        }
        return String(format: "%.1f %@", v, units[u])
    }

    private func formatThousands(_ n: UInt64) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private func uptimeFormatted(_ seconds: UInt64) -> String {
        let days = seconds / 86400
        let hours = (seconds % 86400) / 3600
        let mins = (seconds % 3600) / 60
        if days > 0 { return "\(days)d \(hours)h" }
        if hours > 0 { return "\(hours)h \(mins)m" }
        return "\(mins)m"
    }

    private func relativeTime(from date: Date) -> String {
        let elapsed = Date().timeIntervalSince(date)
        if elapsed < 2 { return "now" }
        if elapsed < 60 { return "\(Int(elapsed))s ago" }
        return "\(Int(elapsed / 60))m ago"
    }
}

// MARK: - Local types

private struct HistoryEntry {
    let at: Date
    let interfaces: [AppState.DashboardInterface]
}

private struct ThroughputPoint {
    let at: Date
    let rxRate: Double  // bytes/sec
    let txRate: Double
}
