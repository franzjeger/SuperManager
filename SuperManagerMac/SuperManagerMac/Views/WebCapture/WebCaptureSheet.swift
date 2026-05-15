import AppKit
import SwiftUI

/// Quick-add sheet for devices the operator discovered out of
/// band. Two ways to land here:
///
/// 1. **`supermgr://addhost?…` URL scheme** — invoked from a
///    browser bookmarklet placed on a vendor admin page (UniFi
///    cloud, FortiGate webadmin, pfSense, etc.). The OS routes
///    the URL to SuperManagerApp's `.onOpenURL` which sets
///    `appState.pendingWebCapture` to drive this sheet.
///
/// 2. **Help → Capture from Web…** / `⌘⇧W` — opens with whatever
///    is currently on the clipboard auto-parsed, so the operator
///    can paste any IP / URL / banner string and get the same
///    confirm-and-add flow.
///
/// One sheet, one confirmation, three possible actions:
///   - Add as SSH host (most common — pre-filled with vendor
///     defaults like username `admin` for FortiGate).
///   - Add this IP to an engagement's scope (so the next scan
///     picks it up).
///   - Run a network scan against this IP right now.
struct WebCaptureSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    /// Pre-populated capture (typically from a `supermgr://`
    /// URL). When nil the sheet opens in "paste" mode and tries
    /// the clipboard first.
    let initialCapture: WebCapture?

    @State private var capture: WebCapture?
    @State private var rawPaste: String = ""
    @State private var action: CaptureAction = .addSshHost

    // SSH-host form mirrors AddHostSheet's fields. We don't
    // reuse that view directly because its layout is built
    // around a blank form, and the WebCapture flow needs to
    // surface the source-URL provenance prominently.
    @State private var label: String = ""
    @State private var hostname: String = ""
    @State private var port: UInt16 = 22
    @State private var username: String = "root"
    @State private var deviceType: DeviceType = .linux
    @State private var group: String = ""

    @State private var attachToEngagementId: String?
    @State private var saving: Bool = false
    @State private var errorMessage: String?

    init(initialCapture: WebCapture? = nil) {
        self.initialCapture = initialCapture
    }

    enum CaptureAction: String, CaseIterable, Identifiable {
        case addSshHost = "Add as SSH host"
        case addToScope = "Add to engagement scope"
        case scanNow = "Run network scan now"
        case copyDetails = "Copy device details"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Form {
                pasteSection
                if capture != nil {
                    contextSection
                    actionSection
                    fieldsSection
                }
                if let err = errorMessage {
                    Section { Text(err).foregroundStyle(.red) }
                }
            }
            .formStyle(.grouped)
            Divider()
            footer
        }
        .frame(minWidth: 580, minHeight: 520)
        .onAppear { applyInitialCaptureOrClipboard() }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "globe.americas.fill")
                .font(.system(size: 26))
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text("Capture from web").font(.headline)
                Text("Quick-add gear you found in a browser without retyping.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(.background.secondary)
    }

    // MARK: - Sections

    @ViewBuilder
    private var pasteSection: some View {
        if capture == nil {
            Section {
                howToCard
                TextField(
                    "Paste an IP, URL, or banner string here",
                    text: $rawPaste,
                    axis: .vertical
                )
                .textFieldStyle(.roundedBorder)
                .font(.body.monospaced())
                .lineLimit(3...6)
                HStack {
                    Button("Parse what I pasted") { parseAndApply() }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.regular)
                        .disabled(rawPaste.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    Button("Try clipboard again") { retryClipboard() }
                        .controlSize(.regular)
                }
            } header: {
                Text("1. Tell me what device")
            } footer: {
                Text(
                    "Examples that all work: `192.0.2.5`, "
                    + "`fw1.example.com:22`, `https://10.0.0.1:8443/admin/`, "
                    + "or a copy-paste banner string like "
                    + "`FortiGate-100F v7.4.1 192.0.2.5`."
                )
                .font(.caption)
            }
        }
    }

    /// Quick-start card shown in the empty-paste state. The user
    /// has multiple ways to land here so we tell them what
    /// they're looking at + how the bookmarklet route works
    /// (since that's the one that requires a one-time setup).
    private var howToCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Three ways to populate this sheet:", systemImage: "lightbulb.fill")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 4) {
                Text("**Paste** any IP, URL, or banner below — then click Parse.")
                Text("**⌘⇧W** anywhere in the app — auto-grabs the clipboard.")
                Text("**Bookmarklet** in your browser → click while on a vendor admin page.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            HStack(spacing: 8) {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(
                        SuperManagerApp.webCaptureBookmarklet,
                        forType: .string
                    )
                } label: {
                    Label("Copy bookmarklet to clipboard", systemImage: "bookmark.fill")
                }
                .controlSize(.small)
                Text("then paste it as the URL of a new browser bookmark.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 8).fill(.tint.opacity(0.08))
        )
    }

    private func retryClipboard() {
        if let s = NSPasteboard.general.string(forType: .string),
           let c = WebCapture.from(pastedText: s)
        {
            rawPaste = s
            capture = c
            applyCaptureToFields(c)
            errorMessage = nil
        } else {
            errorMessage = "Clipboard doesn't contain anything host-shaped."
        }
    }

    @ViewBuilder
    private var contextSection: some View {
        if let c = capture {
            Section("Captured from") {
                if let url = c.sourceUrl {
                    LabeledContent("URL") {
                        Text(url.absoluteString)
                            .font(.caption.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                if let title = c.pageTitle, !title.isEmpty {
                    LabeledContent("Title") {
                        Text(title).font(.caption).lineLimit(1)
                    }
                }
                Button("Change source") {
                    capture = nil
                    rawPaste = ""
                    errorMessage = nil
                }
                .controlSize(.small)
            }
        }
    }

    private var actionSection: some View {
        Section("Action") {
            Picker("", selection: $action) {
                ForEach(CaptureAction.allCases) { a in
                    Text(a.rawValue).tag(a)
                }
            }
            .pickerStyle(.inline)
            .labelsHidden()
        }
    }

    @ViewBuilder
    private var fieldsSection: some View {
        switch action {
        case .addSshHost:
            Section("SSH host") {
                TextField("Label", text: $label)
                TextField("Hostname / IP", text: $hostname)
                TextField("Port", value: $port, format: .number)
                TextField("Username", text: $username)
                Picker("Device type", selection: $deviceType) {
                    ForEach(DeviceType.allCases, id: \.self) { t in
                        Text(t.displayName).tag(t)
                    }
                }
                Picker("Group", selection: $group) {
                    Text("Ungrouped").tag("")
                    ForEach(appState.customers) { c in
                        Text("\(c.displayName) (\(c.slug))").tag(c.slug)
                    }
                }
                Text(
                    "Auth method defaults to SSH key. Pick a key, password, or "
                    + "edit the host on the SSH page after it's added."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        case .addToScope:
            Section("Add to engagement scope") {
                if appState.engagements.isEmpty {
                    Text("No engagements exist yet. Create one in Security first.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                } else {
                    Picker("Engagement", selection: $attachToEngagementId) {
                        Text("Pick…").tag(Optional<String>.none)
                        ForEach(appState.engagements) { e in
                            Text(e.title).tag(Optional(e.id))
                        }
                    }
                    Text(
                        "Appends `\(hostname)/32` to the engagement's "
                        + "`scope_cidrs`. Future active scans automatically "
                        + "include it; existing scope entries are preserved."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
        case .scanNow:
            Section("Network scan target") {
                TextField("Target", text: $hostname)
                    .font(.body.monospaced())
                Text(
                    "Kicks off `discovery_active_scan` against this single "
                    + "host. Switches to the Recon section so you can watch "
                    + "the live progress and triage findings."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        case .copyDetails:
            Section("Clipboard payload") {
                Text(clipboardPayload)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(4)
                Text("Paste-friendly summary for tickets / runbooks.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private var footer: some View {
        HStack {
            Button("Cancel") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Spacer()
            if capture != nil {
                Button(actionButtonLabel) {
                    Task { await performAction() }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(saving || !canSubmit)
            }
        }
        .padding(12)
    }

    private var actionButtonLabel: String {
        switch action {
        case .addSshHost: return saving ? "Adding…" : "Add SSH host"
        case .addToScope: return saving ? "Updating…" : "Add to scope"
        case .scanNow: return saving ? "Starting…" : "Start scan"
        case .copyDetails: return "Copy & close"
        }
    }

    private var canSubmit: Bool {
        guard let c = capture, !c.hostname.isEmpty else { return false }
        switch action {
        case .addSshHost: return !label.isEmpty && !hostname.isEmpty
        case .addToScope: return attachToEngagementId != nil && !hostname.isEmpty
        case .scanNow: return !hostname.isEmpty
        case .copyDetails: return true
        }
    }

    private var clipboardPayload: String {
        let portSuffix = port == 22 ? "" : ":\(port)"
        var lines: [String] = []
        lines.append("\(label) — \(hostname)\(portSuffix)")
        lines.append("Device: \(deviceType.displayName)")
        if let url = capture?.sourceUrl {
            lines.append("Source: \(url.absoluteString)")
        }
        return lines.joined(separator: "\n")
    }

    // MARK: - State plumbing

    private func applyInitialCaptureOrClipboard() {
        if let c = initialCapture {
            capture = c
            applyCaptureToFields(c)
            return
        }
        // Auto-attempt the clipboard so a typical "I just copied
        // the URL/IP and triggered the menu shortcut" flow doesn't
        // require an extra paste step.
        if let s = NSPasteboard.general.string(forType: .string),
           let c = WebCapture.from(pastedText: s)
        {
            rawPaste = s
            capture = c
            applyCaptureToFields(c)
        }
    }

    private func parseAndApply() {
        let trimmed = rawPaste.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let c = WebCapture.from(pastedText: trimmed) else {
            errorMessage = "Couldn't extract a host or IP from the pasted text."
            return
        }
        errorMessage = nil
        capture = c
        applyCaptureToFields(c)
    }

    private func applyCaptureToFields(_ c: WebCapture) {
        hostname = c.hostname
        port = c.port ?? 22
        label = c.label
        deviceType = c.deviceType
        username = c.username
    }

    // MARK: - Actions

    private func performAction() async {
        saving = true
        defer { saving = false }
        switch action {
        case .addSshHost:
            await appState.addHost(
                label: label,
                hostname: hostname,
                port: port,
                username: username,
                group: group,
                deviceType: deviceType,
                authMethod: .key,
                authKeyId: nil,
                password: nil
            )
            appState.selectedSection = .ssh
        case .addToScope:
            await addToEngagementScope()
        case .scanNow:
            await runScanNow()
        case .copyDetails:
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(clipboardPayload, forType: .string)
        }
        dismiss()
    }

    private func addToEngagementScope() async {
        guard let id = attachToEngagementId,
              let existing = appState.engagements.first(where: { $0.id == id })
        else {
            errorMessage = "Engagement not found — refresh and retry."
            return
        }
        let entry = hostname.contains("/") ? hostname : "\(hostname)/32"
        var newScope = existing.scopeCidrs
        if !newScope.contains(entry) { newScope.append(entry) }
        // appState's engagement update RPC. If it doesn't exist
        // yet, fall back to selecting Security so the operator
        // can edit the engagement manually.
        if !(await appState.updateEngagementScope(
            id: id, scopeCidrs: newScope
        )) {
            errorMessage =
                "Couldn't update scope automatically — open the engagement in "
                + "Security and add `\(entry)` manually."
            appState.selectedSection = .security
        }
    }

    private func runScanNow() async {
        // Stash the target on AppState so the Recon view's
        // network-scan tile can pick it up on appear. Switching
        // sections at the same time gives a clean hand-off.
        appState.pendingNetworkScanTargets = [hostname]
        appState.selectedSection = .recon
    }
}

#if DEBUG
#Preview("Empty") {
    WebCaptureSheet()
        .environment(AppState.previewSeeded)
}

#Preview("Pre-filled") {
    WebCaptureSheet(
        initialCapture: WebCapture(
            hostname: "192.0.2.5",
            port: 8443,
            label: "FortiGate-100F",
            deviceType: .fortigate,
            username: "admin",
            sourceUrl: URL(string: "https://192.0.2.5:8443/admin/"),
            pageTitle: "FortiGate 100F — Status"
        )
    )
    .environment(AppState.previewSeeded)
}
#endif
