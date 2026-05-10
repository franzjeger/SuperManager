import SwiftUI

/// FortiGate REST-API control panel — shown inside HostDetailView when
/// the selected host is a FortiGate.
///
/// Three states drive the panel's appearance:
///
/// - **Not configured** (`!host.hasApi`): introduces the feature and
///   offers two paths to get a token — generate one over SSH (one
///   click), or paste an existing token (escape hatch when the
///   FortiOS shell is unreachable for some reason).
///
/// - **Configured but unverified**: token is stored, "Test connection"
///   has not run since launch. Render a "Test" button + Copy / Reveal
///   / Forget actions.
///
/// - **Configured and verified**: green pill with model + firmware,
///   served from the most recent `testFortigateConnection` call.
///   Sticks across re-renders until the token changes or the user
///   forgets it. This is what makes the dashboard feel "live" —
///   you see device identity right at the top, not just "OK".
///
/// Token display is one-shot. After generation we show the cleartext
/// in the result sheet (with explicit "Copy" affordance). On
/// subsequent reads via "Reveal", we go through `getFortigateApiToken`
/// which hits the keychain — that's where the macOS ACL prompt lives.
struct FortigateApiPanel: View {
    @Environment(AppState.self) private var appState
    let host: SshHostSummary

    /// Last successful `testFortigateConnection` response. Cleared
    /// when the host changes, when the token is regenerated, or
    /// when the token is forgotten. Holds device model/firmware/
    /// hostname/serial so the green pill can render rich text.
    @State private var testInfo: AppState.FortigateTestInfo?

    /// One-of: "idle", "testing", "error". "success" is implicit
    /// when `testInfo != nil`. Drives spinner + error banner.
    @State private var testStatus: TestStatus = .idle

    /// Last error from any FortiGate-API operation. Surfaces in
    /// an inline banner under the action row.
    @State private var lastError: String?

    /// Sheet visibility for the three modal flows.
    @State private var showingGenerateSheet = false
    @State private var showingPasteSheet = false
    @State private var showingRevealSheet = false

    /// Cleartext token stash. Populated on successful generate
    /// or successful reveal. Cleared on sheet dismiss so it lives
    /// only as long as the user is looking at it.
    @State private var revealedToken: String?

    /// Per-action in-flight flag. Only one operation runs at a
    /// time (the actions are mutually exclusive — generating while
    /// testing makes no sense).
    @State private var inFlight = false

    enum TestStatus { case idle, testing, error }

    var body: some View {
        if host.deviceType == .fortigate {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Image(systemName: "shield.lefthalf.filled")
                        .foregroundStyle(.tint)
                    Text("FortiGate REST API")
                        .font(.headline)
                    Spacer()
                    statusPill
                }
                if host.hasApi {
                    configuredActions
                } else {
                    notConfiguredActions
                }
                if let lastError {
                    Label(lastError, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .padding(8)
                        .background(.red.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(.tint.opacity(0.04))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(.tint.opacity(0.18), lineWidth: 1)
            )
            .sheet(isPresented: $showingGenerateSheet) {
                GenerateTokenSheet(
                    hostId: host.id,
                    onResult: { token in
                        revealedToken = token
                        testInfo = nil  // Force re-test against new token
                        showingGenerateSheet = false
                        if token != nil {
                            // Auto-test after generation so the user
                            // sees immediate confirmation the token
                            // works. No spinner blocking — fire and
                            // forget into testStatus.
                            Task { await runTest() }
                        }
                    }
                )
            }
            .sheet(isPresented: $showingPasteSheet) {
                PasteTokenSheet(
                    hostId: host.id,
                    onSaved: {
                        showingPasteSheet = false
                        testInfo = nil
                        Task { await runTest() }
                    }
                )
            }
            .sheet(isPresented: $showingRevealSheet) {
                if let token = revealedToken {
                    RevealTokenSheet(token: token, onClose: {
                        revealedToken = nil
                        showingRevealSheet = false
                    })
                }
            }
            .task(id: host.id) {
                // Auto-test once per host-selection if a token is
                // already stored. Cheap (one HTTP GET) and gives
                // the user immediate "you're connected" feedback.
                if host.hasApi && testInfo == nil && testStatus == .idle {
                    await runTest()
                }
            }
        }
    }

    // MARK: - Status pill

    @ViewBuilder
    private var statusPill: some View {
        switch (host.hasApi, testStatus, testInfo) {
        case (false, _, _):
            pill(text: "Not configured", color: .secondary, icon: "circle.dashed")
        case (true, .testing, _):
            pill(text: "Testing…", color: .orange, icon: nil, showSpinner: true)
        case (true, .error, _):
            pill(text: "Token error", color: .red, icon: "xmark.circle.fill")
        case (true, .idle, .some(let info)):
            pill(
                text: "\(info.model) · FortiOS \(info.version)",
                color: .green,
                icon: "checkmark.circle.fill"
            )
        case (true, .idle, .none):
            pill(text: "Configured", color: .blue, icon: "key.fill")
        }
    }

    private func pill(
        text: String,
        color: Color,
        icon: String?,
        showSpinner: Bool = false
    ) -> some View {
        HStack(spacing: 4) {
            if showSpinner {
                ProgressView().controlSize(.small)
            } else if let icon {
                Image(systemName: icon).font(.caption)
            }
            Text(text)
                .font(.caption)
                .lineLimit(1)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(color.opacity(0.12))
        .foregroundStyle(color)
        .clipShape(Capsule())
    }

    // MARK: - Action rows

    private var notConfiguredActions: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Enable the REST API to unlock the live dashboard, compliance checks, and template-based deployment.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                Button {
                    lastError = nil
                    showingGenerateSheet = true
                } label: {
                    Label("Generate token via SSH", systemImage: "wand.and.stars")
                }
                .buttonStyle(.borderedProminent)
                .disabled(inFlight)

                Button {
                    lastError = nil
                    showingPasteSheet = true
                } label: {
                    Label("Paste existing token…", systemImage: "square.and.pencil")
                }
                .disabled(inFlight)
            }
        }
    }

    private var configuredActions: some View {
        HStack(spacing: 8) {
            Button {
                Task { await runTest() }
            } label: {
                Label("Test connection", systemImage: "bolt.horizontal.circle")
            }
            .disabled(inFlight)

            Button {
                Task { await revealToken() }
            } label: {
                Label("Reveal", systemImage: "eye")
            }
            .disabled(inFlight)

            Button {
                Task { await copyToken() }
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
            .disabled(inFlight)

            Spacer()

            Menu {
                Button("Regenerate token via SSH") {
                    lastError = nil
                    showingGenerateSheet = true
                }
                Button("Replace with pasted token…") {
                    lastError = nil
                    showingPasteSheet = true
                }
                Divider()
                Button("Forget token", role: .destructive) {
                    Task { await forgetToken() }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .disabled(inFlight)
            .accessibilityLabel("FortiGate token actions")
        }
    }

    // MARK: - Operations

    private func runTest() async {
        inFlight = true
        defer { inFlight = false }
        testStatus = .testing
        lastError = nil
        if let info = await appState.testFortigateConnection(hostId: host.id) {
            testInfo = info
            testStatus = .idle
        } else {
            testStatus = .error
            // appState handleError already surfaced a global toast;
            // duplicate it here with a more specific message so the
            // user sees what action failed.
            if lastError == nil {
                lastError = "API call failed. Token may be stale or device unreachable."
            }
        }
    }

    private func revealToken() async {
        inFlight = true
        defer { inFlight = false }
        if let token = await appState.getFortigateApiToken(hostId: host.id) {
            revealedToken = token
            showingRevealSheet = true
        } else {
            lastError = "Could not retrieve token from keychain."
        }
    }

    private func copyToken() async {
        inFlight = true
        defer { inFlight = false }
        if let token = await appState.getFortigateApiToken(hostId: host.id) {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(token, forType: .string)
        } else {
            lastError = "Could not retrieve token from keychain."
        }
    }

    private func forgetToken() async {
        inFlight = true
        defer { inFlight = false }
        if await appState.clearFortigateApiToken(hostId: host.id) {
            testInfo = nil
            testStatus = .idle
        }
    }
}

// MARK: - Generate sheet

/// Sheet shown while `fortigate_generate_api_token` runs. The RPC is
/// blocking from the GUI's perspective (SSH connect + interactive
/// shell takes several seconds), so the sheet renders a spinner +
/// what's happening, and on result either closes (success → caller's
/// onResult fires with the token) or shows the error inline.
private struct GenerateTokenSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss
    let hostId: String
    let onResult: (String?) -> Void

    @State private var apiUser: String = "supermgr-api"
    @State private var phase: Phase = .form
    @State private var errorText: String?
    @State private var generatedToken: String?

    enum Phase { case form, generating, done, errored }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Generate FortiGate API token")
                .font(.title3.weight(.semibold))

            switch phase {
            case .form:
                formContent
            case .generating:
                generatingContent
            case .done:
                doneContent
            case .errored:
                erroredContent
            }
        }
        .padding(24)
        .frame(width: 480)
    }

    private var formContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("SuperManager will connect over SSH and run the FortiOS interactive command sequence to mint a new API user with super_admin profile. The token is stored in the macOS Keychain.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Text("API user:")
                TextField("supermgr-api", text: $apiUser)
                    .textFieldStyle(.roundedBorder)
            }
            Text("If a user with this name already exists on the FortiGate, FortiOS will replace its key. Existing scripts using a different api-user are unaffected.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel") { onResult(nil) }
                    .keyboardShortcut(.cancelAction)
                Button("Generate") { Task { await generate() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(apiUser.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private var generatingContent: some View {
        VStack(spacing: 12) {
            ProgressView()
                .controlSize(.large)
            Text("Connecting via SSH and minting token…")
                .foregroundStyle(.secondary)
            Text("Typically takes 5–10 seconds.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
    }

    private var doneContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Token created and stored", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
                .font(.headline)
            if let t = generatedToken {
                Text("This is the only time the token will be shown in plain text. SuperManager has saved it to the keychain — you don't need to copy it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(t)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.black.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            HStack {
                Button("Copy") {
                    if let t = generatedToken {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(t, forType: .string)
                    }
                }
                Spacer()
                Button("Done") { onResult(generatedToken) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    private var erroredContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Could not generate token", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .font(.headline)
            ScrollView {
                Text(errorText ?? "Unknown error")
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(maxHeight: 160)
            .padding(8)
            .background(.red.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            Text("Common causes: no admin password configured, FortiOS prompts in an unexpected language, or the device requires 2FA. Use 'Paste existing token' if SSH-based generation isn't possible.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Close") { onResult(nil) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    private func generate() async {
        phase = .generating
        let token = await appState.generateFortigateApiToken(
            hostId: hostId,
            apiUser: apiUser.trimmingCharacters(in: .whitespaces)
        )
        if let token {
            generatedToken = token
            phase = .done
        } else {
            // appState.handleError surfaced the underlying error to
            // the global toast. Pull it back here for inline display
            // so the user doesn't have to re-find it.
            errorText = appState.errorMessage.isEmpty
                ? "See the toast notification for details."
                : appState.errorMessage
            phase = .errored
        }
    }
}

// MARK: - Paste sheet

private struct PasteTokenSheet: View {
    @Environment(AppState.self) private var appState
    let hostId: String
    let onSaved: () -> Void

    @State private var tokenInput = ""
    @State private var apiPort = "443"
    @State private var saving = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Paste FortiGate API token")
                .font(.title3.weight(.semibold))
            Text("Paste a token you generated outside SuperManager (e.g. via the FortiGate web GUI under System → Administrators → REST API Admin).")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            // SecureField hides while typing — same behaviour as
            // password entry. The user can paste from clipboard
            // even though they can't read what they typed.
            SecureField("Token", text: $tokenInput)
                .textFieldStyle(.roundedBorder)

            HStack {
                Text("API port:")
                TextField("443", text: $apiPort)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 80)
                Text("(typically 443)")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }

            if let error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Cancel") { onSaved() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") { Task { await save() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(saving || tokenInput.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 480)
    }

    private func save() async {
        saving = true
        defer { saving = false }
        let port = UInt16(apiPort) ?? 443
        let trimmed = tokenInput.trimmingCharacters(in: .whitespaces)
        if await appState.setFortigateApiToken(hostId: hostId, token: trimmed, apiPort: port) {
            onSaved()
        } else {
            error = appState.errorMessage.isEmpty
                ? "Could not store token."
                : appState.errorMessage
        }
    }
}

// MARK: - Reveal sheet

private struct RevealTokenSheet: View {
    let token: String
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("API token", systemImage: "key.fill")
                .font(.headline)
            Text(token)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.black.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            Text("Token retrieved from macOS Keychain. Closing this window discards the cleartext copy from memory.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(token, forType: .string)
                }
                Spacer()
                Button("Close") { onClose() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}
