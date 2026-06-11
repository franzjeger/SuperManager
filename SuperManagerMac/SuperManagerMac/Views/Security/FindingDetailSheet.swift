import SwiftUI

/// Edit a finding's disposition (workflow state) + add a note.
/// Shows the full disposition history at the bottom so the
/// operator can see who decided what when.
///
/// Designed to be shown via `.sheet(item:)` from a `FindingRow`
/// click. The sheet calls back via `onSaved(updated)` so the
/// parent can refresh its list in-place.
struct FindingDetailSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    let finding: PersistedFinding
    let scope: String?
    let engagementId: String?
    let onSaved: (PersistedFinding) -> Void

    @State private var dispositionKind: DispositionKind
    @State private var reason: String
    @State private var until: Date
    @State private var hasUntil: Bool
    @State private var note: String
    @State private var saving = false
    @State private var error: String?
    @State private var remediationScript: String?
    @State private var generatingScript = false
    @ScaledMetric private var sheetWidth: CGFloat = 720
    @ScaledMetric private var sheetHeight: CGFloat = 640

    enum DispositionKind: String, CaseIterable, Identifiable {
        case open
        case acceptedRisk = "accepted_risk"
        case fixed
        case falsePositive = "false_positive"
        var id: String { rawValue }
        var label: String {
            switch self {
            case .open: return "Open"
            case .acceptedRisk: return "Accepted risk"
            case .fixed: return "Fixed"
            case .falsePositive: return "False positive"
            }
        }
    }

    init(
        finding: PersistedFinding,
        scope: String?,
        engagementId: String?,
        onSaved: @escaping (PersistedFinding) -> Void
    ) {
        self.finding = finding
        self.scope = scope
        self.engagementId = engagementId
        self.onSaved = onSaved
        // Hydrate from the existing disposition.
        switch finding.disposition {
        case .open:
            _dispositionKind = State(initialValue: .open)
            _reason = State(initialValue: "")
            _until = State(initialValue: Date().addingTimeInterval(90 * 86400))
            _hasUntil = State(initialValue: false)
        case .acceptedRisk(let r, let u):
            _dispositionKind = State(initialValue: .acceptedRisk)
            _reason = State(initialValue: r)
            _until = State(initialValue: u ?? Date().addingTimeInterval(90 * 86400))
            _hasUntil = State(initialValue: u != nil)
        case .fixed:
            _dispositionKind = State(initialValue: .fixed)
            _reason = State(initialValue: "")
            _until = State(initialValue: Date())
            _hasUntil = State(initialValue: false)
        case .falsePositive(let r):
            _dispositionKind = State(initialValue: .falsePositive)
            _reason = State(initialValue: r)
            _until = State(initialValue: Date())
            _hasUntil = State(initialValue: false)
        }
        _note = State(initialValue: finding.note)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    summaryCard
                    remediationCard
                    dispositionCard
                    noteCard
                    if !finding.history.isEmpty {
                        historyCard
                    }
                }
                .padding(16)
            }
            footer
        }
        .frame(width: sheetWidth, height: sheetHeight)
        // Disposition + note edits happen here; an accidental
        // Cmd-W or background-click dismissing the sheet would
        // discard the in-progress changes silently.
        .interactiveDismissDisabled()
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.shield.fill")
                .foregroundStyle(severityColor)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.finding.title)
                    .font(.headline)
                HStack(spacing: 8) {
                    Text(finding.finding.hostIp)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                    CopyButton(value: finding.finding.hostIp, helpText: "Copy host IP")
                    // Bridge the IP-keyed finding back to a known SSH host via
                    // the HostIndex, so the operator sees which managed device
                    // this finding is on instead of a bare IP.
                    if let known = appState.hostIndex.host(forIp: finding.finding.hostIp) {
                        Label(known.label, systemImage: "desktopcomputer")
                            .font(.caption2)
                            .foregroundStyle(.tint)
                            .help("Managed SSH host \(known.label) (\(known.deviceType.displayName))")
                    }
                    if let port = finding.finding.port {
                        Text("port \(port)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if let cve = finding.finding.cve {
                        Text(cve)
                            .font(.caption.weight(.semibold))
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(.red.opacity(0.12))
                            .foregroundStyle(.red)
                            .clipShape(Capsule())
                        CopyButton(value: cve, helpText: "Copy CVE number")
                    }
                    if let cvss = finding.finding.cvss {
                        Text("CVSS \(String(format: "%.1f", cvss))")
                            .font(.caption2)
                            .padding(.horizontal, 4).padding(.vertical, 1)
                            .background(.gray.opacity(0.12))
                            .foregroundStyle(.secondary)
                            .clipShape(Capsule())
                    }
                }
            }
            Spacer()
        }
        .padding(14)
        .background(.background.secondary)
    }

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Detail", systemImage: "doc.text")
                .font(.subheadline.weight(.semibold))
            Text(finding.finding.detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Divider().padding(.vertical, 2)
            Label("Recommendation", systemImage: "checkmark.shield")
                .font(.subheadline.weight(.semibold))
            Text(finding.finding.recommendation)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let cve = finding.finding.cve {
                Link(
                    "View CVE \(cve) on NVD",
                    destination: URL(string: "https://nvd.nist.gov/vuln/detail/\(cve)")!
                )
                .font(.callout)
            }
            HStack(spacing: 16) {
                Label(finding.firstSeen.formatted(date: .abbreviated, time: .omitted), systemImage: "clock.arrow.circlepath")
                Label("Last seen \(finding.lastSeen.formatted(date: .abbreviated, time: .omitted))", systemImage: "clock")
                Label("\(finding.scanCount) scan\(finding.scanCount == 1 ? "" : "s")", systemImage: "scope")
            }
            .font(.caption2)
            .foregroundStyle(.tertiary)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(.background.secondary)
        )
    }

    @ViewBuilder
    private var remediationCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Remediation script", systemImage: "wrench.and.screwdriver")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Button {
                    Task { await generateScript() }
                } label: {
                    if generatingScript {
                        HStack(spacing: 4) {
                            ProgressView().controlSize(.mini)
                            Text("Generating…")
                        }
                    } else {
                        Label("Generate", systemImage: "wand.and.stars")
                    }
                }
                .controlSize(.small)
                .disabled(generatingScript)
            }
            if let script = remediationScript {
                if script.isEmpty {
                    Text("No automated remediation recipe is available for this finding type yet — see the Recommendation above for manual steps.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                } else {
                    ScrollView {
                        Text(script)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                    }
                    .frame(maxHeight: 200)
                    .background(.background.tertiary)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    Button("Copy script") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(script, forType: .string)
                    }
                    .controlSize(.small)
                    .help("Paste into an SSH session on \(finding.finding.hostIp). Backs up affected files first; idempotent re-runs are safe.")
                }
            } else {
                Text("Click Generate to produce a paste-into-ssh fix script. Recipes exist for telnet/FTP/SNMP-public/SMB-null-session/old-TLS/.git-exposed/.env-exposed/phpinfo/Apache mod_status.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(.background.secondary)
        )
    }

    private func generateScript() async {
        generatingScript = true
        defer { generatingScript = false }
        // Pull scope from same logic as the disposition save:
        // prefer explicit `scope`, else engagement_id.
        let scope = (self.scope ?? engagementId) ?? ""
        guard !scope.isEmpty else {
            remediationScript = ""
            return
        }
        if let r = await appState.generateRemediationScript(
            scope: scope,
            host: finding.finding.hostIp,
            key: finding.key
        ) {
            remediationScript = r.script
        } else {
            remediationScript = ""
        }
    }

    private var dispositionCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Disposition", systemImage: "tag.fill")
                .font(.subheadline.weight(.semibold))
            Picker("", selection: $dispositionKind) {
                ForEach(DispositionKind.allCases) { k in
                    Text(k.label).tag(k)
                }
            }
            .pickerStyle(.segmented)

            if dispositionKind == .acceptedRisk || dispositionKind == .falsePositive {
                TextField(
                    dispositionKind == .acceptedRisk
                        ? "Reason for accepting (e.g. legacy system, EOL Q3)"
                        : "Why is this a false positive?",
                    text: $reason
                )
                .textFieldStyle(.roundedBorder)
            }
            if dispositionKind == .acceptedRisk {
                Toggle("Auto-reopen after a date", isOn: $hasUntil)
                if hasUntil {
                    DatePicker("Reopen on", selection: $until, displayedComponents: [.date])
                        .datePickerStyle(.field)
                }
            }
            Text(dispositionHint)
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(.background.secondary)
        )
    }

    private var noteCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Note (visible in reports)", systemImage: "text.badge.plus")
                .font(.subheadline.weight(.semibold))
            TextEditor(text: $note)
                .frame(minHeight: 70)
                .font(.callout)
                .padding(4)
                .background(.background.tertiary)
                .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(.background.secondary)
        )
    }

    private var historyCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("History", systemImage: "clock.arrow.2.circlepath")
                .font(.subheadline.weight(.semibold))
            ForEach(Array(finding.history.enumerated()), id: \.offset) { _, change in
                HStack(alignment: .top, spacing: 8) {
                    Text(change.at.formatted(date: .abbreviated, time: .shortened))
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                        .frame(width: 130, alignment: .leading)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\(change.from.label) → \(change.to.label)")
                            .font(.caption.weight(.medium))
                        if !change.note.isEmpty {
                            Text(change.note)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text("by \(change.by)")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
                .padding(.vertical, 2)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(.background.secondary)
        )
    }

    private var dispositionHint: String {
        switch dispositionKind {
        case .open:
            return "Active — counts toward open-finding totals + appears on reports."
        case .acceptedRisk:
            return "Customer-acknowledged risk. Excluded from open totals; tracked for audit. Auto-reopen flips back to Open after the date."
        case .fixed:
            return "Manually marked fixed. If the next scan still detects this finding it will reopen as a regression."
        case .falsePositive:
            return "Detection rule misfired. Hidden from totals; the next scan will not reopen it unless you change disposition."
        }
    }

    private var footer: some View {
        HStack {
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
                    .font(.caption)
            }
            Spacer()
            Button("Cancel") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button(saving ? "Saving…" : "Save") { Task { await save() } }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(saving)
        }
        .padding(14)
        .background(.background.secondary)
    }

    private var severityColor: Color {
        switch finding.finding.severity {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return .yellow
        case .low:      return .blue
        case .info:     return .gray
        }
    }

    private func save() async {
        saving = true
        defer { saving = false }
        // Skip RPC entirely in preview / offline mode.
        guard appState.daemonAvailable else {
            onSaved(finding)
            dismiss()
            return
        }
        let disposition: Disposition
        switch dispositionKind {
        case .open:
            disposition = .open
        case .acceptedRisk:
            disposition = .acceptedRisk(reason: reason, until: hasUntil ? until : nil)
        case .fixed:
            disposition = .fixed(auto: false)
        case .falsePositive:
            disposition = .falsePositive(reason: reason)
        }
        let updated = await appState.setFindingDisposition(
            scope: scope,
            engagementId: engagementId,
            key: finding.key,
            disposition: disposition,
            note: note
        )
        if let updated {
            onSaved(updated)
            dismiss()
        } else {
            error = "Could not save disposition."
        }
    }
}

#if DEBUG
#Preview("Finding — Open") {
    FindingDetailSheet(
        finding: .previewExampleSshOpen,
        scope: "acme-corp",
        engagementId: "preview-eng-1",
        onSaved: { _ in }
    )
    .environment(AppState.previewSeeded)
}

#Preview("Finding — Accepted Risk") {
    FindingDetailSheet(
        finding: .previewAccepted,
        scope: "acme-corp",
        engagementId: "preview-eng-1",
        onSaved: { _ in }
    )
    .environment(AppState.previewSeeded)
}
#endif
