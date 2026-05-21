import AppKit
import Charts
import CoreText
import SwiftUI
import UniformTypeIdentifiers

/// Detail panel for one host's compliance posture.
///
/// Layout (top-to-bottom):
///   1. **Header card** — host identity, current score (large
///      circular gauge), pass/fail counters, "Run scan" button.
///   2. **Latest run breakdown** — failed checks first (sorted
///      by severity), then passed, then errored. Each row is
///      expandable to show the remediation snippet.
///   3. **History strip** — small bar chart of recent run scores,
///      click a bar to load that run.
///
/// Run takes ~2–10 seconds depending on FortiGate response time.
/// While running, button shows spinner + "Scanning…" — the rest
/// of the view stays interactive (user can still click into
/// historical runs).
struct ComplianceHostView: View {
    @Environment(AppState.self) private var appState
    let hostId: String

    /// Currently-displayed run. Initially the latest one stored in
    /// `appState.complianceLatestRun`, but the user can switch to
    /// any historical run via the history strip — this state holds
    /// that selection independently of the latest-run cache.
    @State private var displayedRunId: String?

    private var host: SshHostSummary? {
        appState.sshHosts.first { $0.id == hostId }
    }

    private var latestRun: AppState.ComplianceRun? {
        appState.complianceLatestRun[hostId]
    }

    private var history: [AppState.ComplianceRunSummary] {
        appState.complianceHistory[hostId] ?? []
    }

    private var isRunning: Bool {
        appState.complianceRunInFlight.contains(hostId)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let host {
                    if !host.hasApi {
                        notConfiguredCard
                    } else {
                        headerCard(for: host)
                        if let run = displayedRun() {
                            if history.count >= 2 {
                                trendChartSection
                            }
                            if let drift = appState.complianceDrift[hostId],
                               drift.previousRunId != nil {
                                driftSection(drift: drift)
                            } else if history.count == 1 {
                                baselineEstablishedCard
                            }
                            breakdownSection(for: run)
                        } else {
                            emptyStateCard
                        }
                    }
                } else {
                    Text("Host not found")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(20)
        }
        .task(id: hostId) {
            // On host change: load the most recent stored run so
            // the breakdown renders without a fresh scan. Don't
            // auto-trigger a run — that's an explicit user action.
            await appState.loadComplianceHistory(hostId: hostId, limit: 50)
            if let mostRecent = appState.complianceHistory[hostId]?.first,
               appState.complianceLatestRun[hostId] == nil {
                _ = await appState.loadComplianceRun(hostId: hostId, runId: mostRecent.id)
                await appState.loadComplianceDrift(hostId: hostId, runId: mostRecent.id)
            }
            displayedRunId = nil
        }
    }

    private func displayedRun() -> AppState.ComplianceRun? {
        if let id = displayedRunId {
            return appState.complianceLatestRun[hostId]?.id == id
                ? appState.complianceLatestRun[hostId]
                : nil
        }
        return latestRun
    }

    // MARK: - Header card

    @ViewBuilder
    private func headerCard(for host: SshHostSummary) -> some View {
        let run = displayedRun()
        let score = run?.score
        let scoreColor: Color = {
            guard let s = score else { return .secondary }
            return s >= 90 ? .green : (s >= 70 ? .orange : .red)
        }()
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 16) {
                scoreGauge(score: score, color: scoreColor)
                VStack(alignment: .leading, spacing: 6) {
                    Text(host.label).font(.title2.weight(.semibold))
                    Text("\(host.username)@\(host.hostname)")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    if let run {
                        HStack(spacing: 12) {
                            statTile(
                                count: run.passed,
                                label: "Passed",
                                color: .green
                            )
                            statTile(
                                count: run.failed,
                                label: "Failed",
                                color: .red
                            )
                            if run.errored > 0 {
                                statTile(
                                    count: run.errored,
                                    label: "Errored",
                                    color: .orange
                                )
                            }
                        }
                        Text("Last scan \(run.startedAt.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    } else {
                        Text("Never scanned")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                }
                Spacer()
                VStack(spacing: 6) {
                    Button {
                        Task {
                            let result = await appState.runCompliance(hostId: hostId)
                            if let result {
                                displayedRunId = result.id
                            }
                        }
                    } label: {
                        if isRunning {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text("Scanning…")
                            }
                        } else {
                            Label("Run scan", systemImage: "play.fill")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                    .disabled(isRunning)

                    if displayedRun() != nil {
                        Button {
                            Task { await exportReport() }
                        } label: {
                            Label("Export Markdown…", systemImage: "doc.text")
                        }
                        .controlSize(.small)
                        Button {
                            Task { await exportPdf() }
                        } label: {
                            Label("Export PDF…", systemImage: "square.and.arrow.up")
                        }
                        .controlSize(.small)
                        .buttonStyle(.borderedProminent)
                    }
                }
            }
            if let run, run.failed > 0 {
                let critical = run.checks.filter {
                    $0.status == .fail && $0.severity == .critical
                }.count
                let high = run.checks.filter {
                    $0.status == .fail && $0.severity == .high
                }.count
                if critical > 0 || high > 0 {
                    summaryBanner(critical: critical, high: high)
                }
            }
        }
        .padding(18)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(.separator, lineWidth: 0.5)
        )
    }

    private func scoreGauge(score: UInt8?, color: Color) -> some View {
        ZStack {
            Circle()
                .stroke(color.opacity(0.15), lineWidth: 8)
            Circle()
                .trim(from: 0, to: score.map { Double($0) / 100.0 } ?? 0)
                .stroke(color, style: StrokeStyle(lineWidth: 8, lineCap: .round))
                .rotationEffect(.degrees(-90))
            VStack(spacing: 0) {
                if let s = score {
                    Text("\(s)")
                        .font(.system(size: 28, weight: .bold, design: .rounded))
                        .monospacedDigit()
                        .foregroundStyle(color)
                } else {
                    Text("—")
                        .font(.title.weight(.bold))
                        .foregroundStyle(.secondary)
                }
                Text("score")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .frame(width: 90, height: 90)
    }

    private func statTile(count: UInt32, label: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(count)")
                .font(.title3.weight(.semibold))
                .monospacedDigit()
                .foregroundStyle(color)
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    private func summaryBanner(critical: Int, high: Int) -> some View {
        let parts: [String] = {
            var p: [String] = []
            if critical > 0 { p.append("\(critical) critical") }
            if high > 0 { p.append("\(high) high") }
            return p
        }()
        return HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            Text("\(parts.joined(separator: " · ")) finding\(critical + high == 1 ? "" : "s") need attention")
                .font(.callout)
                .foregroundStyle(.red)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.red.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }

    // MARK: - Breakdown

    private func breakdownSection(for run: AppState.ComplianceRun) -> some View {
        // Sort: failures by severity desc → errored → skip → pass.
        let sorted = run.checks.sorted { a, b in
            statusRank(a.status, severity: a.severity) <
                statusRank(b.status, severity: b.severity)
        }
        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Findings")
                    .font(.headline)
                Spacer()
                Text("\(run.checks.count) checks")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            ForEach(sorted) { check in
                CheckRow(check: check, library: appState.complianceCheckLibrary)
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .animation(.easeOut(duration: 0.18), value: run.checks.count)
    }

    private func statusRank(_ status: AppState.ComplianceStatus, severity: AppState.ComplianceSeverity) -> Int {
        switch status {
        case .fail:
            switch severity {
            case .critical: return 0
            case .high:     return 1
            case .medium:   return 2
            case .low:      return 3
            case .info:     return 4
            }
        case .error: return 5
        case .skip:  return 6
        case .pass:  return 7
        }
    }

    // MARK: - Trend chart

    /// Replaces the simple bar strip when there are 2+ runs.
    /// Renders a smooth line chart of score over time using the
    /// macOS Charts framework. Click+drag to inspect a run; we
    /// highlight the currently-displayed run with a marker.
    @ViewBuilder
    private var trendChartSection: some View {
        // Pull the last 30 runs in chronological order. Charts
        // expects oldest-first so the X-axis reads left-to-right
        // as time progresses.
        let chronological: [AppState.ComplianceRunSummary] = history
            .prefix(30)
            .reversed()
        let displayedId = displayedRunId ?? latestRun?.id
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Score trend")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Spacer()
                Text("\(history.count) runs · last \(chronological.count) shown")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            Chart {
                ForEach(chronological, id: \.id) { run in
                    LineMark(
                        x: .value("Time", run.startedAt),
                        y: .value("Score", Int(run.score))
                    )
                    .foregroundStyle(.tint)
                    .interpolationMethod(.catmullRom)
                    AreaMark(
                        x: .value("Time", run.startedAt),
                        y: .value("Score", Int(run.score))
                    )
                    .foregroundStyle(.tint.opacity(0.15))
                    .interpolationMethod(.catmullRom)
                    PointMark(
                        x: .value("Time", run.startedAt),
                        y: .value("Score", Int(run.score))
                    )
                    .symbolSize(run.id == displayedId ? 100 : 30)
                    .foregroundStyle(scoreColor(for: run.score))
                }
                // Reference lines at the score thresholds so the
                // user can see "you're below 70" at a glance.
                RuleMark(y: .value("Pass", 90))
                    .foregroundStyle(.green.opacity(0.3))
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
                RuleMark(y: .value("Warning", 70))
                    .foregroundStyle(.orange.opacity(0.3))
                    .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
            }
            .chartYScale(domain: 0...100)
            .chartYAxis {
                AxisMarks(position: .leading, values: [0, 25, 50, 75, 100])
            }
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 5)) { _ in
                    AxisValueLabel(format: .dateTime.day().month(.abbreviated))
                    AxisGridLine()
                }
            }
            .frame(height: 130)
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
    }

    private func scoreColor(for score: UInt8) -> Color {
        if score >= 90 { return .green }
        if score >= 70 { return .orange }
        return .red
    }

    // MARK: - Drift section

    /// First-run state: a single run has been recorded so there's
    /// no previous run to diff against. Explicit copy so the
    /// operator doesn't read "no drift section" as "no problem"
    /// — drift detection literally hasn't run yet because it
    /// requires two runs to compare. Replaced by `driftSection`
    /// on the second scan onward.
    private var baselineEstablishedCard: some View {
        HStack(spacing: 10) {
            Image(systemName: "flag.checkered.circle.fill")
                .foregroundStyle(.tint)
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text("Baseline established")
                    .font(.subheadline.weight(.semibold))
                Text("This is the first compliance run for this host. Drift detection compares future runs against this one — re-scan to see what changes.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(.tint.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(.tint.opacity(0.25), lineWidth: 0.5)
        )
    }

    /// "Since last scan" panel. Surfaces what changed: newly
    /// failing checks (top priority), newly passing (good news),
    /// and persistent failures (still need work). Score delta is
    /// rendered with an arrow + ± number.
    private func driftSection(drift: AppState.DriftReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Since last scan")
                    .font(.headline)
                Spacer()
                if let prev = drift.previousScore {
                    let arrow: String = {
                        if drift.scoreDelta > 0 { return "arrow.up" }
                        if drift.scoreDelta < 0 { return "arrow.down" }
                        return "minus"
                    }()
                    let color: Color = {
                        if drift.scoreDelta > 0 { return .green }
                        if drift.scoreDelta < 0 { return .red }
                        return .secondary
                    }()
                    HStack(spacing: 4) {
                        Text("\(prev)")
                            .foregroundStyle(.tertiary)
                            .monospacedDigit()
                        Image(systemName: arrow)
                            .foregroundStyle(color)
                            .font(.caption)
                        Text("\(drift.currentScore)")
                            .foregroundStyle(color)
                            .fontWeight(.semibold)
                            .monospacedDigit()
                        Text("(\(drift.scoreDelta > 0 ? "+" : "")\(drift.scoreDelta))")
                            .font(.caption)
                            .foregroundStyle(color)
                    }
                }
            }
            if drift.newlyFailing.isEmpty && drift.newlyPassing.isEmpty && drift.errored.isEmpty {
                Text("No status changes since the previous scan.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            } else {
                if !drift.newlyFailing.isEmpty {
                    driftBucket(
                        title: "Newly failing",
                        icon: "xmark.octagon.fill",
                        color: .red,
                        entries: drift.newlyFailing
                    )
                }
                if !drift.errored.isEmpty {
                    driftBucket(
                        title: "Errored (couldn't evaluate)",
                        icon: "exclamationmark.triangle.fill",
                        color: .orange,
                        entries: drift.errored
                    )
                }
                if !drift.newlyPassing.isEmpty {
                    driftBucket(
                        title: "Newly passing",
                        icon: "checkmark.seal.fill",
                        color: .green,
                        entries: drift.newlyPassing
                    )
                }
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
    }

    @ViewBuilder
    private func driftBucket(
        title: String,
        icon: String,
        color: Color,
        entries: [AppState.DriftEntry]
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: icon).foregroundStyle(color)
                Text("\(title) (\(entries.count))")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(color)
            }
            ForEach(entries) { entry in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text("•")
                        .foregroundStyle(color)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(entry.title)
                            .font(.callout)
                        if let detail = entry.currentDetail, !detail.isEmpty {
                            Text(detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                        }
                    }
                    Spacer()
                    Text(entry.severity.rawValue.capitalized)
                        .font(.caption2)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(severityColor(entry.severity).opacity(0.15))
                        .foregroundStyle(severityColor(entry.severity))
                        .clipShape(Capsule())
                }
            }
        }
    }

    private func severityColor(_ severity: AppState.ComplianceSeverity) -> Color {
        switch severity {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return .yellow
        case .low:      return .blue
        case .info:     return .secondary
        }
    }

    // MARK: - Export

    /// Render the displayed run to Markdown via the daemon and
    /// hand it to NSSavePanel for the user to choose where to
    /// save. The default name encodes hostname + date so library
    /// files are self-organising.
    private func exportReport() async {
        guard let run = displayedRun() else { return }
        guard let markdown = await appState.renderComplianceReport(
            hostId: hostId,
            runId: run.id
        ) else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [
            UTType(filenameExtension: "md") ?? .plainText,
            .plainText,
        ]
        let date = run.startedAt.formatted(.iso8601.year().month().day())
        let safeHost = (run.hostname ?? "fortigate")
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: " ", with: "_")
        panel.nameFieldStringValue = "compliance-\(safeHost)-\(date).md"
        panel.title = "Export compliance report"
        panel.message = "Save the Markdown report — convert to PDF later via Print → Save as PDF in Preview."

        if panel.runModal() == .OK, let url = panel.url {
            do {
                try markdown.write(to: url, atomically: true, encoding: .utf8)
            } catch {
                appState.errorMessage = "Failed to write report: \(error.localizedDescription)"
            }
        }
    }

    /// Render the displayed run to PDF in-process. Path:
    ///   Markdown → AttributedString → off-screen NSTextView →
    ///   `NSPrintOperation.dataRepresentation(...)` to a PDF blob.
    /// No external tools needed. Lays the text out at standard
    /// US-Letter portrait with 0.75" margins. Multi-page handled
    /// by the print system.
    private func exportPdf() async {
        guard let run = displayedRun() else { return }
        guard let markdown = await appState.renderComplianceReport(
            hostId: hostId,
            runId: run.id
        ) else { return }
        // Markdown → AttributedString with full block parsing so
        // headings, bold, lists, and links render as styled runs.
        let nsAttr: NSAttributedString
        do {
            let parsed = try AttributedString(
                markdown: markdown,
                options: AttributedString.MarkdownParsingOptions(
                    interpretedSyntax: .full,
                    failurePolicy: .returnPartiallyParsedIfPossible
                )
            )
            nsAttr = NSAttributedString(parsed)
        } catch {
            appState.errorMessage = "Failed to parse Markdown: \(error.localizedDescription)"
            return
        }

        // Build the PDF. NSAttributedString → CGPDFContext via a
        // sized CTFramesetter; this is the "no NSView" path so we
        // can run from a fully background context without owning
        // a window.
        let pageSize = CGSize(width: 612, height: 792) // US Letter (72 dpi)
        let margin: CGFloat = 54 // 0.75"
        let drawableWidth = pageSize.width - 2 * margin
        let drawableHeight = pageSize.height - 2 * margin
        let pdfData = NSMutableData()
        guard let consumer = CGDataConsumer(data: pdfData) else {
            appState.errorMessage = "Could not create PDF buffer."
            return
        }
        var mediaBox = CGRect(origin: .zero, size: pageSize)
        guard let pdfContext = CGContext(consumer: consumer, mediaBox: &mediaBox, nil) else {
            appState.errorMessage = "Could not create PDF context."
            return
        }

        let framesetter = CTFramesetterCreateWithAttributedString(nsAttr)
        var currentRange = CFRange(location: 0, length: 0)
        let totalLength = nsAttr.length

        // Page-by-page layout. CT returns the consumed range per
        // frame; loop until we've laid out every glyph.
        while currentRange.location < totalLength {
            pdfContext.beginPDFPage(nil)
            // CGContext has Y-axis flipped for PDF; CT also wants
            // a flipped path so glyphs read left-to-right top-down
            // in our coordinate system.
            pdfContext.translateBy(x: 0, y: pageSize.height)
            pdfContext.scaleBy(x: 1, y: -1)

            let path = CGMutablePath()
            // After the flip, y=0 is at the top — so the drawable
            // box's origin moves to (margin, margin) and grows
            // downward in the now-flipped coords.
            path.addRect(CGRect(
                x: margin,
                y: margin,
                width: drawableWidth,
                height: drawableHeight
            ))
            let frame = CTFramesetterCreateFrame(
                framesetter,
                currentRange,
                path,
                nil
            )
            // Y-flip CT's coords so it draws right-side-up inside
            // our flipped CGContext.
            pdfContext.textMatrix = CGAffineTransform(scaleX: 1, y: -1)
            CTFrameDraw(frame, pdfContext)
            let visible = CTFrameGetVisibleStringRange(frame)
            if visible.length == 0 { break }
            currentRange.location += visible.length
            pdfContext.endPDFPage()
        }
        pdfContext.closePDF()

        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType.pdf]
        let date = run.startedAt.formatted(.iso8601.year().month().day())
        let safeHost = (run.hostname ?? "fortigate")
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: " ", with: "_")
        panel.nameFieldStringValue = "compliance-\(safeHost)-\(date).pdf"
        panel.title = "Export compliance report (PDF)"

        if panel.runModal() == .OK, let url = panel.url {
            do {
                try (pdfData as Data).write(to: url, options: .atomic)
            } catch {
                appState.errorMessage = "Failed to write PDF: \(error.localizedDescription)"
            }
        }
    }

    // MARK: - History strip

    private var historyStrip: some View {
        let runs = history.prefix(20).reversed()
        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("History")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Spacer()
                Text("\(history.count) total")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            HStack(alignment: .bottom, spacing: 4) {
                ForEach(Array(runs), id: \.id) { summary in
                    historyBar(summary: summary)
                }
            }
            .frame(height: 40)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(.separator, lineWidth: 0.5)
        )
    }

    private func historyBar(summary: AppState.ComplianceRunSummary) -> some View {
        let color: Color = summary.score >= 90
            ? .green
            : (summary.score >= 70 ? .orange : .red)
        let isSelected = (displayedRunId ?? latestRun?.id) == summary.id
        return Button {
            Task {
                _ = await appState.loadComplianceRun(hostId: hostId, runId: summary.id)
                displayedRunId = summary.id
            }
        } label: {
            VStack(spacing: 0) {
                Spacer(minLength: 0)
                RoundedRectangle(cornerRadius: 2)
                    .fill(color)
                    .frame(width: 12, height: max(4, CGFloat(summary.score) / 100 * 36))
            }
        }
        .buttonStyle(.plain)
        .help("\(summary.startedAt.formatted(date: .abbreviated, time: .shortened)) — score \(summary.score)")
        .overlay(
            RoundedRectangle(cornerRadius: 2)
                .stroke(isSelected ? Color.accentColor : .clear, lineWidth: 1.5)
                .padding(-2)
        )
    }

    // MARK: - States

    private var notConfiguredCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("API token required", systemImage: "lock.shield")
                .font(.headline)
            Text("Compliance scans use the FortiGate REST API to read configuration values without an interactive shell session. Generate a token under the host's Detail page in the SSH section.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                appState.selectedSection = .ssh
            } label: {
                Label("Open host detail in SSH", systemImage: "arrow.right.circle")
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.orange.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(.orange.opacity(0.3), lineWidth: 0.5)
        )
    }

    private var emptyStateCard: some View {
        VStack(spacing: 8) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 40))
                .foregroundStyle(.tertiary)
            Text("No scans yet")
                .font(.headline)
            Text("Click 'Run scan' to evaluate this host against the CIS FortiOS 7.4 Level 1 baseline.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }
}

// MARK: - Check row

/// One row in the findings list. Failed/errored checks are
/// expanded by default so the user sees what's wrong without
/// extra clicks. Passed checks collapse to a compact row.
private struct CheckRow: View {
    let check: AppState.ComplianceCheckResult
    let library: [AppState.ComplianceCheckDefinition]

    @State private var expanded: Bool = false
    @State private var initialized = false

    private var definition: AppState.ComplianceCheckDefinition? {
        library.first { $0.id == check.checkId }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                statusIcon
                VStack(alignment: .leading, spacing: 1) {
                    Text(check.title)
                        .font(.callout.weight(.medium))
                    HStack(spacing: 6) {
                        Text(check.category)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                        if let cis = definition?.cisReference {
                            Text("CIS \(cis)")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                        severityChip
                    }
                }
                Spacer()
                Button {
                    expanded.toggle()
                } label: {
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .foregroundStyle(.secondary)
                        .font(.caption)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(expanded ? "Collapse check details" : "Expand check details")
            }
            if expanded {
                expandedDetail
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(rowBackground)
        )
        .onAppear {
            // Auto-expand failed/errored checks once on first
            // appearance so the user doesn't have to click them
            // open. Passed checks collapse for compactness.
            if !initialized {
                expanded = (check.status == .fail || check.status == .error)
                initialized = true
            }
        }
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch check.status {
        case .pass:
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .accessibilityLabel("Passed")
        case .fail:
            Image(systemName: "xmark.circle.fill")
                .foregroundStyle(.red)
                .accessibilityLabel("Failed")
        case .error:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityLabel("Errored")
        case .skip:
            Image(systemName: "minus.circle")
                .foregroundStyle(.secondary)
                .accessibilityLabel("Skipped")
        }
    }

    private var severityChip: some View {
        Text(check.severity.rawValue.capitalized)
            .font(.caption2)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(severityColor.opacity(0.15))
            .foregroundStyle(severityColor)
            .clipShape(Capsule())
    }

    private var severityColor: Color {
        switch check.severity {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return .yellow
        case .low:      return .blue
        case .info:     return .secondary
        }
    }

    private var rowBackground: AnyShapeStyle {
        switch check.status {
        case .fail:  return AnyShapeStyle(.red.opacity(0.05))
        case .error: return AnyShapeStyle(.orange.opacity(0.05))
        default:     return AnyShapeStyle(.background.tertiary)
        }
    }

    @ViewBuilder
    private var expandedDetail: some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            if let def = definition {
                Text(def.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(alignment: .firstTextBaseline) {
                Text("Detail:")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                Text(check.detail)
                    .font(.caption)
                    .textSelection(.enabled)
            }
            if let raw = check.rawValue {
                HStack(alignment: .firstTextBaseline) {
                    Text("Raw:")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                    Text(raw.isEmpty ? "(empty)" : raw)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            if check.status == .fail, let fix = definition?.remediation {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("Remediation")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(fix, forType: .string)
                        }
                        .controlSize(.mini)
                    }
                    Text(fix)
                        .font(.system(.caption2, design: .monospaced))
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.black.opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                        .textSelection(.enabled)
                }
            }
        }
    }
}
