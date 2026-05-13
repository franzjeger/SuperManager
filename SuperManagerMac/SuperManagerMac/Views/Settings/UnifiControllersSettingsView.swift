import SwiftUI

/// Settings tab where the operator manages the standalone
/// UniFi controller registry. Replaces the old per-host
/// "UniFi Controller" sub-section that conflated "an SSH host
/// that happens to be the controller" with "any controller".
///
/// One controller, many devices — register the controller
/// once, all UniFi gear it manages becomes addressable from
/// scan results / Recon / inventory.
struct UnifiControllersSettingsView: View {
    @Environment(AppState.self) private var appState

    @State private var selectedId: String?
    @State private var showingAdd = false
    @State private var editing: UnifiController?
    @State private var devices: [UnifiManagedDevice] = []
    @State private var loadingDevices = false
    @State private var devicesError: String?

    var body: some View {
        HStack(spacing: 0) {
            controllerList
                .frame(minWidth: 260, maxWidth: 320)
            Divider()
            detail
                .frame(maxWidth: .infinity)
        }
        .frame(minHeight: 480)
        .task { await appState.refreshUnifiControllers() }
        .sheet(isPresented: $showingAdd) {
            UnifiControllerEditSheet(controller: nil)
                .environment(appState)
        }
        .sheet(item: $editing) { c in
            UnifiControllerEditSheet(controller: c)
                .environment(appState)
        }
    }

    private var controllerList: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Controllers").font(.headline)
                Spacer()
                Button {
                    showingAdd = true
                } label: {
                    Image(systemName: "plus")
                }
                .buttonStyle(.borderless)
                .help("Add UniFi controller")
            }
            .padding(12)
            Divider()
            if appState.unifiControllers.isEmpty {
                ContentUnavailableView(
                    "No controllers",
                    systemImage: "antenna.radiowaves.left.and.right",
                    description: Text(
                        "Click + to add your UniFi controller. "
                        + "Once registered, every device it manages "
                        + "shows up in network scans with one-click "
                        + "actions (locate / restart / forget / adopt)."
                    )
                )
                .frame(maxHeight: .infinity)
            } else {
                List(selection: $selectedId) {
                    ForEach(appState.unifiControllers) { c in
                        row(c).tag(Optional(c.id))
                    }
                }
                .listStyle(.sidebar)
            }
        }
    }

    private func row(_ c: UnifiController) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Image(systemName: "wifi.router.fill")
                    .foregroundStyle(.tint)
                Text(c.label).font(.body.weight(.medium))
                Spacer()
                if c.verifiedAt != nil {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                        .font(.caption)
                } else {
                    Image(systemName: "questionmark.circle")
                        .foregroundStyle(.orange)
                        .font(.caption)
                }
            }
            Text(c.url)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder
    private var detail: some View {
        if let id = selectedId,
           let c = appState.unifiControllers.first(where: { $0.id == id })
        {
            controllerDetail(c)
        } else {
            ContentUnavailableView(
                "Pick a controller",
                systemImage: "hand.point.left",
                description: Text(
                    "Select a controller on the left to see managed "
                    + "devices, run a connection test, or edit creds."
                )
            )
        }
    }

    private func controllerDetail(_ c: UnifiController) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading) {
                    Text(c.label).font(.title2.weight(.semibold))
                    Text(c.url).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Spacer()
                Menu {
                    Button {
                        editing = c
                    } label: {
                        Label("Edit…", systemImage: "pencil")
                    }
                    Button(role: .destructive) {
                        Task { _ = await appState.deleteUnifiController(id: c.id) }
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }

            Form {
                Section("Connection") {
                    LabeledContent("Site", value: c.siteId)
                    LabeledContent("Username", value: c.username)
                    LabeledContent("Verified") {
                        if let v = c.verifiedAt {
                            Text(v.formatted(date: .abbreviated, time: .shortened))
                                .foregroundStyle(.green)
                        } else {
                            Text("Never").foregroundStyle(.orange)
                        }
                    }
                    if let slug = c.customerSlug {
                        LabeledContent("Customer scope", value: slug)
                    }
                    HStack {
                        Button("Test connection") {
                            Task { await testConnection(c) }
                        }
                        .controlSize(.small)
                        Button("Refresh devices") {
                            Task { await loadDevices(c) }
                        }
                        .controlSize(.small)
                        Spacer()
                    }
                }

                if loadingDevices {
                    Section("Devices") {
                        HStack {
                            ProgressView().controlSize(.small)
                            Text("Loading…").foregroundStyle(.secondary)
                        }
                    }
                } else if let err = devicesError {
                    Section("Devices") {
                        Text(err).foregroundStyle(.red).font(.caption)
                    }
                } else if !devices.isEmpty {
                    Section("Devices (\(devices.count))") {
                        ForEach(devices) { d in
                            deviceRow(d)
                        }
                    }
                }
            }
            .formStyle(.grouped)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onChange(of: selectedId) { _, _ in
            devices = []
            devicesError = nil
        }
    }

    private func deviceRow(_ d: UnifiManagedDevice) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(d.name ?? d.model ?? d.mac)
                    .font(.body.weight(.medium))
                Spacer()
                stateBadge(d.state)
            }
            HStack(spacing: 8) {
                Text(d.mac).font(.caption.monospaced()).foregroundStyle(.tertiary)
                if let ip = d.ip {
                    Text(ip).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                if let model = d.model, model != d.name {
                    Text(model).font(.caption).foregroundStyle(.tertiary)
                }
                Spacer()
                if let version = d.version {
                    Text("fw \(version)").font(.caption).foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.vertical, 2)
    }

    private func stateBadge(_ state: String) -> some View {
        let (sym, tint): (String, Color) = {
            switch state {
            case "connected": return ("circle.fill", .green)
            case "pending-adoption": return ("circle.dotted", .orange)
            case "disconnected": return ("circle.fill", .red)
            case "adopting", "provisioning", "upgrading":
                return ("arrow.triangle.2.circlepath", .blue)
            case "managed-by-other": return ("exclamationmark.circle.fill", .yellow)
            case "isolated": return ("network.slash", .red)
            default: return ("circle", .gray)
            }
        }()
        return Label(state, systemImage: sym)
            .font(.caption.weight(.medium))
            .foregroundStyle(tint)
    }

    private func testConnection(_ c: UnifiController) async {
        devicesError = nil
        let result = await appState.testUnifiController(id: c.id)
        switch result {
        case .success(let info):
            devicesError = "Connected — UniFi Network \(info.version)"
        case .failure(let msg):
            devicesError = msg.message
        }
    }

    private func loadDevices(_ c: UnifiController) async {
        loadingDevices = true
        defer { loadingDevices = false }
        devicesError = nil
        let result = await appState.listUnifiControllerDevices(id: c.id)
        switch result {
        case .success(let list):
            devices = list
        case .failure(let msg):
            devicesError = msg.message
            devices = []
        }
    }
}

/// Add / edit sheet for a single controller. Two phases:
///   1. **Form**  — operator fills auth method + credentials.
///   2. **MFA**   — only reached if auth_method=password AND the
///                  controller demands a second factor. The sheet
///                  shows the authenticator list, lets the
///                  operator pick one + receive the email code,
///                  then completes the login.
struct UnifiControllerEditSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    let controller: UnifiController?

    @State private var label: String
    @State private var url: String
    @State private var siteId: String
    @State private var authMethod: UnifiAuthMethod
    @State private var username: String
    @State private var credential: String   // password OR api key, depending on authMethod
    @State private var customerSlug: String
    @State private var saving = false
    @State private var errorMessage: String?

    /// MFA challenge state, populated after a `.mfaRequired`
    /// save outcome. While non-nil the sheet renders the MFA
    /// sub-view instead of the form.
    @State private var mfaChallenge: MfaChallengeState?

    struct MfaChallengeState {
        let challengeId: String
        let authenticators: [MfaAuthenticator]
        var selectedAuthId: String?
        var emailSent: Bool = false
        var code: String = ""
    }

    init(controller: UnifiController?) {
        self.controller = controller
        _label = State(initialValue: controller?.label ?? "")
        _url = State(initialValue: controller?.url ?? "https://")
        _siteId = State(initialValue: controller?.siteId ?? "default")
        _authMethod = State(initialValue: controller?.authMethod ?? .apiKey)
        _username = State(initialValue: controller?.username ?? "")
        _credential = State(initialValue: "")
        _customerSlug = State(initialValue: controller?.customerSlug ?? "")
    }

    private var isEdit: Bool { controller != nil }

    private var canSubmit: Bool {
        guard !label.isEmpty, !url.isEmpty else { return false }
        switch authMethod {
        case .apiKey:
            return isEdit || !credential.isEmpty
        case .password:
            return !username.isEmpty && (isEdit || !credential.isEmpty)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            if let _ = mfaChallenge {
                mfaPhaseForm
            } else {
                formPhase
            }
        }
        .frame(minWidth: 560, minHeight: 520)
    }

    private var header: some View {
        HStack {
            Image(systemName: mfaChallenge == nil ? "wifi.router.fill" : "lock.shield.fill")
                .foregroundStyle(.tint).imageScale(.large)
            VStack(alignment: .leading) {
                Text(mfaChallenge != nil
                     ? "Second factor required"
                     : (isEdit ? "Edit UniFi controller" : "Add UniFi controller"))
                    .font(.headline)
                Text(headerSubtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(12)
        .background(.background.secondary)
    }

    private var headerSubtitle: String {
        if mfaChallenge != nil {
            return "Your controller wants a second factor. Pick an email authenticator, request the code, paste it below."
        }
        return "URL of your UniFi Network Application + credentials. Cred is verified on save; only stored on success."
    }

    // ---------------------------------------------------------
    // Phase 1: form
    // ---------------------------------------------------------

    private var formPhase: some View {
        VStack(spacing: 0) {
            Form {
                Section("Identity") {
                    TextField("Label", text: $label)
                    TextField("Customer slug (optional)", text: $customerSlug)
                        .help("MSP scoping. Leave blank for global.")
                }
                Section("Authentication") {
                    Picker("Method", selection: $authMethod) {
                        Text("API key (recommended)").tag(UnifiAuthMethod.apiKey)
                        Text("Username + password").tag(UnifiAuthMethod.password)
                    }
                    .pickerStyle(.segmented)
                    .help(
                        "API keys bypass MFA, can be revoked independently, "
                        + "and don't expire when you rotate your password. "
                        + "Mint one in the controller UI: Admins → API."
                    )
                    authMethodHint
                }
                Section("Connection") {
                    TextField("URL", text: $url)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                        .help("e.g. https://192.168.1.1:8443 or https://unifi.example.com")
                    TextField("Site ID", text: $siteId)
                        .help("Most installs use 'default'. Multi-site deploys have distinct IDs.")
                    if authMethod == .password {
                        TextField("Username", text: $username)
                        SecureField(
                            isEdit ? "Password (leave blank to keep)" : "Password",
                            text: $credential
                        )
                    } else {
                        SecureField(
                            isEdit ? "API key (leave blank to keep)" : "API key",
                            text: $credential
                        )
                        .help("Paste the X-API-KEY value minted in the controller UI.")
                    }
                }
                if let err = errorMessage {
                    Section { Text(err).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(saving ? "Saving…" : (isEdit ? "Save" : "Add")) {
                    Task { await save() }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(saving || !canSubmit)
            }
            .padding(12)
        }
    }

    @ViewBuilder
    private var authMethodHint: some View {
        switch authMethod {
        case .apiKey:
            Text(
                "**Best path.** In your UniFi controller, sign in → Admins → "
                + "API → Create API Key → copy the token → paste it below."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        case .password:
            Text(
                "Works on every UniFi version including older ones. If your "
                + "account has 2FA we'll walk through it on the next screen."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    // ---------------------------------------------------------
    // Phase 2: MFA challenge
    // ---------------------------------------------------------

    private var mfaPhaseForm: some View {
        VStack(spacing: 0) {
            Form {
                if let challenge = mfaChallenge {
                    Section("Pick an authenticator") {
                        let emailAuths = challenge.authenticators.filter { $0.isSupported }
                        let otherAuths = challenge.authenticators.filter { !$0.isSupported }
                        if emailAuths.isEmpty {
                            Label(
                                "This account only has WebAuthn / passkey authenticators registered. SuperManager can't drive those yet — please add an Email authenticator in your Ubiquiti account, or use an API key.",
                                systemImage: "exclamationmark.triangle.fill"
                            )
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                        } else {
                            Picker("Email", selection: Binding(
                                get: { mfaChallenge?.selectedAuthId ?? emailAuths.first?.id ?? "" },
                                set: { mfaChallenge?.selectedAuthId = $0 }
                            )) {
                                ForEach(emailAuths) { a in
                                    Text(a.name).tag(a.id)
                                }
                            }
                            Button(challenge.emailSent ? "Re-send code" : "Send code to email") {
                                Task { await sendEmail() }
                            }
                            .controlSize(.small)
                            .disabled(emailAuths.isEmpty)
                        }
                        if !otherAuths.isEmpty {
                            Text(
                                "Other authenticators on the account "
                                + "(unsupported by SuperManager): "
                                + otherAuths.map { "\($0.name) [\($0.kind)]" }
                                    .joined(separator: ", ")
                            )
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                        }
                    }
                    if challenge.emailSent {
                        Section("Code") {
                            TextField("6-digit code from email", text: Binding(
                                get: { mfaChallenge?.code ?? "" },
                                set: { mfaChallenge?.code = $0 }
                            ))
                            .textFieldStyle(.roundedBorder)
                            .font(.body.monospaced())
                            Text("Code expires in 5 minutes.")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
                if let err = errorMessage {
                    Section { Text(err).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Button("Back") {
                    mfaChallenge = nil
                    errorMessage = nil
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                if mfaChallenge?.emailSent == true {
                    Button(saving ? "Verifying…" : "Verify code") {
                        Task { await verifyCode() }
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(saving || (mfaChallenge?.code.isEmpty ?? true))
                }
            }
            .padding(12)
        }
    }

    // ---------------------------------------------------------
    // Actions
    // ---------------------------------------------------------

    private func save() async {
        saving = true
        defer { saving = false }
        errorMessage = nil
        let trimmedSlug = customerSlug.trimmingCharacters(in: .whitespaces)
        let result = await appState.saveUnifiController(
            id: controller?.id,
            label: label,
            url: url.trimmingCharacters(in: .whitespaces),
            authMethod: authMethod,
            username: authMethod == .password ? username : "",
            credential: credential.isEmpty ? nil : credential,
            siteId: siteId.isEmpty ? "default" : siteId,
            customerSlug: trimmedSlug.isEmpty ? nil : trimmedSlug
        )
        switch result {
        case .success(.saved):
            dismiss()
        case .success(.mfaRequired(let cid, let auths)):
            let emailAuth = auths.first(where: { $0.isSupported })
            mfaChallenge = MfaChallengeState(
                challengeId: cid,
                authenticators: auths,
                selectedAuthId: emailAuth?.id
            )
        case .failure(let err):
            errorMessage = err.message
        }
    }

    private func sendEmail() async {
        guard let cid = mfaChallenge?.challengeId,
              let aid = mfaChallenge?.selectedAuthId
        else { return }
        saving = true
        defer { saving = false }
        errorMessage = nil
        let result = await appState.sendUnifiMfaEmail(
            challengeId: cid,
            authenticatorId: aid
        )
        switch result {
        case .success:
            mfaChallenge?.emailSent = true
        case .failure(let err):
            errorMessage = err.message
        }
    }

    private func verifyCode() async {
        guard let cid = mfaChallenge?.challengeId,
              let code = mfaChallenge?.code
        else { return }
        saving = true
        defer { saving = false }
        errorMessage = nil
        let result = await appState.completeUnifiMfa(
            challengeId: cid,
            code: code.trimmingCharacters(in: .whitespaces)
        )
        switch result {
        case .success:
            dismiss()
        case .failure(let err):
            errorMessage = err.message
        }
    }
}

#if DEBUG
#Preview {
    UnifiControllersSettingsView()
        .environment(AppState.previewSeeded)
        .frame(width: 820, height: 560)
}
#endif
