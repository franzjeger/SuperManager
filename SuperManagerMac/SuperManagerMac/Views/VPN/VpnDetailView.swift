import SwiftUI

/// Detail view for a single VPN profile. Connect / disconnect goes through
/// the privileged helper (`HelperClient`) which spawns strongSwan in the
/// background. The user never has to touch System Settings — that's the
/// whole point of the rewrite.
struct VpnDetailView: View {
    let profileId: String
    @Environment(AppState.self) private var appState
    @State private var profile: VpnProfile?
    @State private var loading = true
    @State private var loadError: String?
    @State private var actionError: String?
    @State private var busy = false

    /// Tunnel state as reported by the helper, refreshed on a 3 s poll.
    /// "disconnected" / "connecting" / "connected" / "reconnecting".
    @State private var vpnState: String = "disconnected"
    @State private var stateDetail: String = ""
    /// Last error surfaced from the VPN log when state is "reconnecting"
    /// or "disconnected" — e.g. "EVENT: TRANSPORT_ERROR NETWORK_EOF_ERROR".
    /// Shown as a small caption below the status pill so the user knows
    /// WHY the connection is retrying without having to open the log viewer.
    @State private var reconnectReason: String? = nil
    /// What the tunnel looks like right now, as the helper reports it. Empty
    /// when nothing's connected, so the "Live tunnel" section hides itself.
    ///
    /// One struct rather than four loose `@State`s so that switching profiles
    /// drops all of it in a single assignment. As four fields they had to be
    /// listed by hand in `.task(id: profileId)`'s reset, and they never were:
    /// select a connected Azure profile, then click an IKEv2 one, and Azure's
    /// interface, assigned IP and pushed routes were still on screen —
    /// attributed to a profile that doesn't even report them.
    struct LiveTunnel: Equatable {
        var interface = ""
        var virtualIp = ""
        var virtualGateway = ""
        var routes: [String] = []

        /// Nothing measured. Also the test for whether the section renders at
        /// all — an empty tunnel has nothing to say.
        var isEmpty: Bool {
            interface.isEmpty && virtualIp.isEmpty && routes.isEmpty
        }
    }

    @State private var live = LiveTunnel()
    @State private var helperReachable: Bool = false
    @State private var pollTask: Task<Void, Never>?

    /// The two "helper isn't up yet" banners surfaced during a boot race
    /// (the app probed the socket before launchd finished spawning the
    /// daemon). Hoisted to constants so `refreshHelperState()` can clear
    /// exactly these once the socket comes up, and never a genuine connect
    /// error. Setting them inline and clearing by loose string match would
    /// silently drift apart.
    static let helperSocketPendingMessage =
        "Helper installed but socket isn't up yet. " +
        "Check System Settings → General → Login Items if a " +
        "background-item approval prompt was shown."
    static let helperNotRunningMessage =
        "Helper isn't running yet. Approve the " +
        "background daemon prompt in System Settings → " +
        "General → Login Items, then click Connect again."

    /// Helper-log viewer state. Surfaced as a sheet from the inline
    /// "View Helper Log" button that appears next to a connect error.
    @State private var showingLog = false
    @State private var logText = ""
    @State private var logLoading = false

    /// OpenVPN-credential editor state. Sheet trigger in the detail
    /// row; reads/writes DPK directly (`EditOvpnCredentialsSheet`).
    @State private var editingOvpnCreds = false

    /// Routing editor state. Sheet trigger in the detail row; the
    /// sheet calls `vpn_set_routing` on save (`EditRoutingSheet`).
    @State private var editingRouting = false
    /// Full IKEv2 profile editor (name / server / username / credentials /
    /// routing). Sheet trigger in the kebab menu; saves via
    /// `vpn_update_ikev2_profile` (`EditVpnProfileSheet`).
    @State private var editingProfile = false
    @State private var showingAzureSignIn = false
    @State private var azureSummaryForSignIn: AzureVpnSummary?
    /// Inline-rename UI. Click the title in the header to enter
    /// edit mode; press Return to commit or Escape to cancel.
    @State private var isRenaming = false
    @State private var renameDraft = ""
    @FocusState private var renameFocused: Bool

    /// Set to true when the helper reports its strongSwan probe failed.
    /// First-run users won't have brew strongSwan; we put a banner above
    /// the connect bar with a one-click "copy install command" + open
    /// Terminal.
    @State private var strongswanMissing = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if loading {
                    ProgressView("Loading profile…")
                        .frame(maxWidth: .infinity)
                        .padding()
                } else if let profile {
                    header(profile)
                    Divider()
                    if strongswanMissing { strongswanBanner }
                    connectionBar(profile)
                    Divider()
                    details(profile)
                } else if let loadError {
                    ContentUnavailableView(
                        "Couldn't load profile",
                        systemImage: "exclamationmark.triangle",
                        description: Text(loadError)
                    )
                }
            }
            .padding()
        }
        .task(id: profileId) {
            // Seed from the GLOBAL poller's last known state for this
            // profile rather than hardcoding "disconnected". The global
            // poller (AppState.startVpnStatusPolling) drives the sidebar
            // dot and runs continuously; seeding from it means a profile
            // that is actually connected shows "Connected" immediately on
            // selection instead of flashing "disconnected" until the
            // local poll catches up (or never, if its Task has died).
            vpnState = appState.vpnConnectionStates[profileId] ?? "disconnected"
            // Everything below describes the profile we just navigated AWAY
            // from. None of it survives the switch — the poll for the new
            // profile refills what applies to it, and a backend that doesn't
            // report a given field leaves it empty rather than inheriting the
            // last profile's answer.
            stateDetail = ""
            actionError = nil
            strongswanMissing = false
            reconnectReason = nil
            live = LiveTunnel()
            await load()
        }
        .onAppear { startPolling() }
        .onDisappear { stopPolling() }
        // Single source of truth (for real): mirror the global poller
        // into the detail pane. The detail pane used to rely solely on
        // its own `startPolling` Task, whose lifecycle is tied to
        // onAppear/onDisappear and could die (e.g. after a connect/
        // disconnect cycle), leaving `vpnState` stuck on "disconnected"
        // while the sidebar dot — driven by the always-on global poller
        // — correctly showed green. Reading both from
        // `vpnConnectionStates` makes that divergence structurally
        // impossible. We skip the sync while a user action is in flight
        // so the optimistic local "connecting" state isn't clobbered.
        .onChange(of: appState.vpnConnectionStates[profileId]) { _, newValue in
            guard !busy, let s = newValue else { return }
            vpnState = s
        }
        .sheet(isPresented: $showingLog) { logSheet }
        .sheet(isPresented: $editingOvpnCreds) {
            EditOvpnCredentialsSheet(profileId: profileId, onSaved: {
                // Reading the stored username inline in `details(_:)`
                // already updates on next render; nothing else to do.
            })
        }
        .sheet(isPresented: $editingRouting) {
            // The sheet needs the full Profile, so only present
            // when we have one. Rendered inside the conditional so
            // the optional unwrap is safe.
            if let profile {
                EditRoutingSheet(profile: profile) {
                    // Routing is on the daemon-stored profile, not in
                    // local state, so a fresh `load()` picks up the
                    // new full_tunnel + routes for display.
                    Task { await load() }
                }
            }
        }
        .sheet(isPresented: $editingProfile) {
            // Full IKEv2 editor. Same guard as the routing sheet: only
            // present with a loaded profile so the pre-fill has data.
            // A fresh `load()` after save picks up the new host /
            // username / routing from the daemon store.
            if let profile {
                EditVpnProfileSheet(profile: profile) {
                    Task { await load() }
                }
            }
        }
        .sheet(isPresented: $showingAzureSignIn) {
            // Azure connect runs in its own sheet because the
            // device-code flow has multiple phases (loading,
            // awaiting browser, bringing up tunnel) and benefits
            // from owning its own Task lifetime.
            if let az = azureSummaryForSignIn {
                AzureSignInSheet(profileId: profileId, summary: az) {
                    // Tunnel just came up — fast-path a status
                    // refresh so the dot flips green without
                    // waiting for the 3-second poll cycle.
                    Task { await refreshHelperState() }
                }
            }
        }
    }

    /// Banner shown above the connect bar when the helper's strongSwan
    /// probe fails. SuperManager's free-tier VPN architecture relies on
    /// brew-installed strongSwan; first-run users haven't done that yet
    /// and need a one-click path. We drop the install one-liner onto the
    /// pasteboard and offer to open Terminal — the user pastes, the
    /// brew install completes in ~30s, the next status poll flips this
    /// banner off automatically.
    /// Push the rename draft to the daemon. Reloads the profile
    /// snapshot on success so the UI shows the canonical (trimmed)
    /// name.
    private func commitRename() {
        let draft = renameDraft.trimmingCharacters(in: .whitespaces)
        isRenaming = false
        guard !draft.isEmpty,
              let p = profile,
              draft != p.name
        else {
            return
        }
        Task {
            _ = await appState.renameVpnProfile(profileId: profileId, newName: draft)
            await load()
        }
    }

    /// Compact recent-activity list for this profile. Renders
    /// as a disclosure section so it doesn't add visual weight
    /// for users who don't care about history. Empty state
    /// hides the entire section.
    @ViewBuilder
    /// The last few connect/disconnect events for this profile. Capped at 10:
    /// this is a glance, not a log viewer.
    private var activityEvents: [ActivityLog.Event] {
        Array(ActivityLog.shared.events(for: profileId).prefix(10))
    }

    /// Activity rows, no DisclosureGroup wrapper.
    ///
    /// `DetailSection` now supplies the heading, so the group's own "Recent
    /// activity" label would just repeat it — and inside a grid cell that sizes
    /// to its content there's nothing worth collapsing. The caller renders the
    /// whole section only when `activityEvents` is non-empty, so this never
    /// leaves a bare heading behind.
    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(activityEvents) { ev in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: ev.kind.symbol)
                        .font(.caption)
                        .foregroundStyle(activityIconColor(for: ev.kind))
                        .frame(width: 16)
                    Text(ev.message)
                        .font(.caption)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Spacer()
                    Text(ev.timestamp, format: .relative(presentation: .numeric))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    private func activityIconColor(for kind: ActivityLog.Kind) -> Color {
        switch kind {
        case .connectSucceeded, .killSwitchEngaged, .autoReconnectFired:
            return .green
        case .connectFailed, .forceDisconnect, .panicReset:
            return .red
        case .killSwitchReleased, .disconnectComplete, .disconnectRequested:
            return .secondary
        case .connectStarted:
            return .blue
        }
    }

    /// SwiftUI binding for the kill-switch Toggle. Reads from the
    /// profile's persisted flag; on flip calls AppState's daemon
    /// RPC + helper for immediate teardown when disabling.
    private var killSwitchBinding: Binding<Bool> {
        Binding(
            get: { profile?.killSwitch ?? false },
            set: { newValue in
                Task {
                    _ = await appState.setKillSwitch(
                        profileId: profileId, enabled: newValue)
                    // Refresh the local profile snapshot so the
                    // toggle reflects daemon truth.
                    await load()
                }
            }
        )
    }

    /// SwiftUI binding for the always-on Toggle. Reads from
    /// AppState's set; on flip calls `setAutoReconnect` which
    /// pushes to the helper.
    private var alwaysOnBinding: Binding<Bool> {
        Binding(
            get: { appState.autoReconnectEnabled.contains(profileId) },
            set: { newValue in
                Task {
                    await appState.setAutoReconnect(
                        profileId: profileId, enabled: newValue)
                }
            }
        )
    }

    private var strongswanBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text("strongSwan is not installed")
                    .font(.headline)
            }
            Text("SuperManager controls the VPN tunnel through a bundled-with-Homebrew copy of strongSwan. Run the command below in Terminal — it installs Homebrew (if missing) and strongSwan in one shot. About 30 seconds on a fast Mac. Once it's done, this banner disappears on its own.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Text(installCommand)
                .font(.system(size: 11, design: .monospaced))
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.black.opacity(0.05), in: RoundedRectangle(cornerRadius: 4))
                .textSelection(.enabled)

            HStack(spacing: 8) {
                Button("Copy Command") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(installCommand, forType: .string)
                }
                .controlSize(.small)
                Button("Open Terminal") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(installCommand, forType: .string)
                    NSWorkspace.shared.launchApplication("Terminal")
                }
                .controlSize(.small)
                .buttonStyle(.borderedProminent)
                Spacer()
            }
        }
        .padding(12)
        .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    private var installCommand: String {
        // Same one-liner from the original install session: brew (if
        // missing) + strongswan + a sentinel echo.
        "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\" " +
        "&& /opt/homebrew/bin/brew install strongswan && echo SM_DONE_INSTALLING"
    }

    /// Sheet presenting the helper's recent log lines. Pulled lazily so
    /// `tail_log` only runs when the user explicitly asks for it.
    private var logSheet: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Helper Log")
                    .font(.headline)
                Spacer()
                Button("Refresh") {
                    Task { await loadLog() }
                }
                .disabled(logLoading)
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(logText, forType: .string)
                }
                .disabled(logText.isEmpty)
                Button("Close") { showingLog = false }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(12)

            Divider()

            if logLoading && logText.isEmpty {
                ProgressView("Loading…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    Text(logText.isEmpty ? "(empty)" : logText)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                }
            }
        }
        .frame(minWidth: 800, minHeight: 500)
    }

    private func loadLog() async {
        logLoading = true
        defer { logLoading = false }
        do {
            logText = try await HelperClient.shared.tailLog(bytes: 16 * 1024)
            showingLog = true
        } catch {
            logText = "Could not fetch helper log: \(error.localizedDescription)"
            showingLog = true
        }
    }

    private func header(_ profile: VpnProfile) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            // Inline-rename: tap the title to edit. Commit on
            // Return or losing focus; cancel via Escape resets
            // the text to the persisted value.
            HStack(alignment: .firstTextBaseline) {
                if isRenaming {
                    TextField("Profile name", text: $renameDraft)
                        .textFieldStyle(.plain)
                        .font(.title2.weight(.semibold))
                        .focused($renameFocused)
                        .onSubmit {
                            commitRename()
                        }
                        .onExitCommand {
                            renameDraft = profile.name
                            isRenaming = false
                        }
                        .frame(maxWidth: 360)
                } else {
                    Text(profile.name)
                        .font(.title2.weight(.semibold))
                        .onTapGesture {
                            renameDraft = profile.name
                            isRenaming = true
                            renameFocused = true
                        }
                        .help("Click to rename.")
                }
            }
            switch profile.config {
            case .ikev2(let cfg):
                Text("IPSec — \(cfg.username)@\(cfg.host)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .wireguard(let wg):
                let endpoint = wg.firstPeerEndpoint ?? "no peer"
                Text("WireGuard — \(wg.peerCount) peer\(wg.peerCount == 1 ? "" : "s") · \(endpoint)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .openvpn:
                Text("OpenVPN — imported configuration")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .azure(let az):
                Text("Azure VPN — \(az.gatewayFqdn)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            case .unsupported(let backend):
                Text("Backend \(backend) is not yet supported on macOS")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
        }
    }

    private func connectionBar(_ profile: VpnProfile) -> some View {
        // Visual states the dot needs to convey, in priority order:
        //   yellow  — helper not installed (the user has work to do)
        //   green   — connected
        //   orange  — connecting
        //   gray    — disconnected, helper present (the boring "ready" state)
        // Conflating "not installed" with "disconnected" was misleading; the
        // first is "the app needs setup", the second is "everything is fine,
        // just not active." Different colors, different next-actions.
        let dotColor: Color = !helperReachable ? .yellow : statusColor(vpnState)
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                // Status pill: filled when connected (impossible to
                // miss — green capsule with white "Connected" inside),
                // outlined dot when otherwise. Mid-screen feedback was
                // too easy to overlook, especially when the action
                // button switched from "Connect" to "Disconnect" with
                // no other visual confirmation.
                statusPill(dotColor)
                    .font(.callout.weight(.medium))

                Spacer()

                switch profile.config {
                case .ikev2:
                    if !helperReachable {
                        Button("Install Helper…") {
                            Task { await installHelper() }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                    } else if vpnState == "connected" {
                        Button("Disconnect", role: .destructive) {
                            Task { await disconnect(profile) }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.red)
                        .disabled(busy)
                    } else {
                        // `vpnState` here is "disconnected", "connecting",
                        // or anything else strongSwan reports. Don't
                        // disable on "connecting" — letting the user
                        // re-trigger Connect if they suspect it's
                        // stuck is more useful than locking them out
                        // until polling clears the state.
                        Button(busy || vpnState == "connecting" ? "Connecting…" : "Connect") {
                            Task { await connect(profile) }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                    }
                case .wireguard:
                    if !helperReachable {
                        Button("Install Helper…") {
                            Task { await installHelper() }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                    } else if vpnState == "connected" {
                        Button("Disconnect", role: .destructive) {
                            Task { await disconnectWireGuard(profile) }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.red)
                        .disabled(busy)
                    } else {
                        Button(busy ? "Connecting…" : "Connect") {
                            Task { await connectWireGuard(profile) }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                    }
                case .openvpn(let cfg):
                    if !helperReachable {
                        Button("Install Helper…") {
                            Task { await installHelper() }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                    } else if vpnState == "connected" || vpnState == "reconnecting" {
                        // Show Disconnect for both states — if reconnecting,
                        // the user can abort the retry loop and restart cleanly.
                        Button("Disconnect", role: .destructive) {
                            Task { await disconnectOpenVPN(profile) }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.red)
                        .disabled(busy)
                    } else {
                        Button(busy ? "Connecting…" : "Connect") {
                            Task { await connectOpenVPN(profile, configFile: cfg.configFile) }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                    }
                case .azure(let az):
                    if !helperReachable {
                        Button("Install Helper…") {
                            Task { await installHelper() }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                    } else if vpnState == "connected" || vpnState == "reconnecting" {
                        // "reconnecting" shows Disconnect so the user can
                        // abort the loop and re-authenticate via Entra ID.
                        // Azure P2S Entra ID tokens expire (~1 h); when they
                        // do, the gateway sends TCP EOF and ovpncli retries
                        // with the same expired token forever. The correct
                        // recovery is Disconnect → Connect (new device-code flow).
                        Button("Disconnect", role: .destructive) {
                            Task { await disconnectOpenVPN(profile) }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.red)
                        .disabled(busy)
                    } else {
                        // The connect-sheet drives auth + tunnel
                        // bring-up. It tries the cached refresh
                        // token first (silent — no browser), so
                        // the button reads "Connect" like every
                        // other backend; we only re-prompt the
                        // user with a browser when the refresh
                        // fails. The sheet owns the polling Task;
                        // closing it cancels.
                        Button(busy ? "Connecting…" : "Connect") {
                            azureSummaryForSignIn = az
                            showingAzureSignIn = true
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy)
                        .help("Brings up the Azure VPN tunnel via Entra ID. If the cached refresh token is still valid the connect is silent; otherwise a browser opens for sign-in.")
                    }
                case .unsupported:
                    EmptyView()
                }

                // Belt-and-braces: a "Force Disconnect" menu option
                // tucked behind a kebab. Users hit it when the
                // primary Connect/Disconnect button has gotten out
                // of sync with reality (e.g. UI says "Disconnected"
                // but the tunnel is actually still up). Calls the
                // backend disconnect RPC directly without consulting
                // local UI state. Safe to spam — disconnect is
                // idempotent on every backend.
                Menu {
                    // Full profile editor — only IKEv2 profiles have a
                    // backend update RPC (`vpn_update_ikev2_profile`); the
                    // other backends edit through their own dedicated
                    // sheets (routing / OpenVPN creds) or re-import.
                    if case .ikev2 = profile.config {
                        Button("Edit profile…") { editingProfile = true }
                        Divider()
                    }
                    Button("Force Disconnect", role: .destructive) {
                        Task {
                            await appState.forceDisconnect(profileId: profileId)
                            // Reset local view state so nothing
                            // lingers from a stuck "connecting".
                            vpnState = "disconnected"
                            stateDetail = ""
                            actionError = nil
                        }
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .frame(width: 30)
                .help("More actions")
            }

            if let actionError {
                VStack(alignment: .leading, spacing: 6) {
                    Text(actionError)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    // The error text from swanctl is usually truncated and
                    // unhelpful; the actual diagnosis lives in the charon
                    // log lines a few KB above. Surface a one-click jump
                    // into them so users don't have to open Console.app
                    // and chase root permission.
                    if helperReachable {
                        HStack(spacing: 8) {
                            Button("View Helper Log…") {
                                Task { await loadLog() }
                            }
                            .controlSize(.small)
                            .buttonStyle(.bordered)
                            Spacer()
                        }
                    }
                }
                .padding(8)
                .background(.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
            }

            if !stateDetail.isEmpty {
                Text(stateDetail)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
            }

            // Reconnect diagnostic — shown when the helper reports
            // state="reconnecting" and supplies an error_reason.
            // Gives the user immediate visibility into WHY the
            // connection is retrying (e.g. NETWORK_EOF_ERROR means
            // the Azure gateway rejected the token; user knows to
            // hit Disconnect and re-authenticate rather than waiting
            // for a retry that will never succeed).
            if vpnState == "reconnecting", let reason = reconnectReason {
                HStack(spacing: 6) {
                    Image(systemName: "arrow.clockwise.circle")
                        .foregroundStyle(.orange)
                    Text(reason)
                        .font(.caption.monospaced())
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                        .lineLimit(2)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
                .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
            }
        }
    }

    /// Mirror of the daemon's match-arms in `handle_vpn_set_routing`.
    /// Backends whose routing lives inside an imported config file
    /// (OpenVPN, Azure, Generic) can't be toggled via the RPC, so
    /// we hide the Edit affordance entirely.
    private func backendSupportsRoutingToggle(_ config: VpnProfileConfig) -> Bool {
        switch config {
        case .ikev2, .wireguard: return true
        case .openvpn, .azure, .unsupported: return false
        }
    }

    private func details(_ profile: VpnProfile) -> some View {
        // The detail pane is ~1000pt wide at full screen and this content used
        // to hug the left ~300pt of it in one tall column. DetailColumns fits as
        // many ~340pt sections side by side as the width allows and reflows to a
        // single column when narrow, so a wide window is actually used.
        DetailColumns {
            DetailSection(title: "Configuration") {
                VStack(alignment: .leading, spacing: 10) {
                    DefinitionList(rows: configRows(profile))

                    // OpenVPN creds live in the login Keychain, not the
                    // daemon-side config, so they get their own editor.
                    if case .openvpn = profile.config {
                        Button {
                            editingOvpnCreds = true
                        } label: {
                            Label("Edit credentials", systemImage: "key.horizontal")
                        }
                        .controlSize(.small)
                    }
                    if case .azure = profile.config {
                        Text("Authenticates via Entra ID (device-code flow) at connect.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            DetailSection(title: "Routing & protection") {
                VStack(alignment: .leading, spacing: 10) {
                    ToggleGroup {
                        // Kill switch: connect installs pf rules blocking all
                        // egress except via the tunnel iface + LAN. Reconnect
                        // required to take effect on an already-up tunnel;
                        // toggling OFF tears the rules down immediately.
                        ToggleRow(
                            title: "Kill switch",
                            help: "Block all traffic if the tunnel drops.",
                            isOn: killSwitchBinding
                        )
                        Divider()
                        // Helper-side watchdog reconnects this profile every 30s
                        // if it drops, surviving the GUI being closed (the helper
                        // is a LaunchDaemon). It replays args from the most recent
                        // successful connect — so for IKEv2 you must connect once
                        // manually after enabling it (WireGuard reads the daemon's
                        // secret store, so it works on first toggle).
                        ToggleRow(
                            title: "Always on",
                            help: appState.autoReconnectEnabled.contains(profileId)
                                ? "Reconnecting automatically every 30s."
                                : "Reconnect automatically if the tunnel drops.",
                            isOn: alwaysOnBinding
                        )
                    }

                    // Routing changes need a reconnect, so they commit through a
                    // sheet rather than a live toggle. Hidden for backends whose
                    // routing `vpn_set_routing` doesn't accept (OpenVPN — routing
                    // is encoded inside the imported `.ovpn`): a button opening a
                    // sheet that immediately says "you can't change this" is worse
                    // than no button.
                    if backendSupportsRoutingToggle(profile.config) {
                        Button {
                            editingRouting = true
                        } label: {
                            Label("Edit routing…", systemImage: "arrow.triangle.branch")
                        }
                        .controlSize(.small)
                    }
                }
            }

            if hasSessionDetail {
                DetailSection(title: "Session") {
                    VStack(alignment: .leading, spacing: 10) {
                        // WireGuard's kernel module exposes rx/tx via `wg show`;
                        // OpenVPN and IKEv2 don't expose counters cheaply, so
                        // this simply hides when there's no data.
                        if let counters = appState.vpnByteCounters[profileId] {
                            bandwidthRow(
                                rx: counters.rx,
                                tx: counters.tx,
                                rate: appState.vpnByteRates[profileId]
                            )
                        }
                        // Live handshake age (WG-only). TimelineView ticks every
                        // second so "12s ago" updates without forcing a redraw.
                        if let unix = appState.vpnLastHandshakeUnix[profileId] {
                            handshakeRow(handshakeUnix: unix)
                        }
                        // The address we're actually talking to right now —
                        // useful when a profile has several peers and you need to
                        // know which one is carrying traffic.
                        if let endpoint = appState.vpnPeerEndpoints[profileId] {
                            row("Active peer", endpoint)
                        }
                        // Gateway-pushed interface / IP / routes. Not present in
                        // the static profile, so it's shown separately: this is
                        // what the session is actually carrying. Self-hides when
                        // the helper has reported no tunnel metadata.
                        liveTunnelRows()
                    }
                }
            }

            // Only when there's something to show — an empty grid cell would
            // otherwise render as a bare "RECENT ACTIVITY" heading over nothing.
            if !activityEvents.isEmpty {
                DetailSection(title: "Recent activity") {
                    activitySection
                }
            }
        }
    }

    /// True when there is anything live worth showing, so the Session section is
    /// omitted rather than rendered as an empty box.
    private var hasSessionDetail: Bool {
        appState.vpnByteCounters[profileId] != nil
            || appState.vpnLastHandshakeUnix[profileId] != nil
            || appState.vpnPeerEndpoints[profileId] != nil
            || !live.isEmpty
    }

    /// A profile's static configuration, per backend, as definition rows.
    ///
    /// Tunnel mode and Profile ID close every backend's list so the shape stays
    /// predictable no matter which one you're looking at.
    private func configRows(_ profile: VpnProfile) -> [DefinitionRow] {
        var rows: [DefinitionRow] = []
        switch profile.config {
        case .ikev2(let cfg):
            rows.append(DefinitionRow("Server", cfg.host))
            rows.append(DefinitionRow("Username", cfg.username))
            // Only when set: a blank Local ID means strongSwan defaults IDi to
            // the connection IP, which is a non-fact not worth a row.
            if !cfg.localId.isEmpty {
                rows.append(DefinitionRow("Local ID", cfg.localId))
            }
            if !cfg.dnsServers.isEmpty {
                rows.append(DefinitionRow("DNS", cfg.dnsServers.joined(separator: ", ")))
            }
            if !cfg.routes.isEmpty {
                rows.append(DefinitionRow("Split routes", cfg.routes.joined(separator: ", ")))
            }

        case .wireguard(let wg):
            if !wg.addresses.isEmpty {
                rows.append(DefinitionRow("Addresses", wg.addresses.joined(separator: ", ")))
            }
            if !wg.dns.isEmpty {
                rows.append(DefinitionRow("DNS", wg.dns.joined(separator: ", ")))
            }
            rows.append(DefinitionRow("Peers", String(wg.peerCount), mono: false))
            if let endpoint = wg.firstPeerEndpoint {
                rows.append(DefinitionRow("Endpoint", endpoint))
            }
            if !wg.splitRoutes.isEmpty {
                rows.append(DefinitionRow("Split routes", wg.splitRoutes.joined(separator: ", ")))
            }

        case .azure(let az):
            // Tenant + gateway FQDN are the unique-identifier pair; client ID is
            // the OAuth2 audience the daemon uses when acquiring an Entra-ID
            // token at connect time.
            rows.append(DefinitionRow("Gateway", az.gatewayFqdn))
            rows.append(DefinitionRow("Tenant ID", az.tenantId))
            rows.append(DefinitionRow("Client ID", az.clientId))
            if !az.dnsServers.isEmpty {
                rows.append(DefinitionRow("DNS", az.dnsServers.joined(separator: ", ")))
            }
            if !az.routes.isEmpty {
                rows.append(DefinitionRow("Split routes", az.routes.joined(separator: ", ")))
            }

        case .openvpn(let cfg):
            // Filename only — the full path is long and includes our own
            // data-dir, which isn't useful at a glance.
            rows.append(DefinitionRow(
                "Config file",
                URL(fileURLWithPath: cfg.configFile).lastPathComponent
            ))
            // The daemon-side `OpenVpnConfig.username` is empty on import; the
            // creds live in the login Keychain. Reading is cheap.
            let storedUser = (try? VPNKeychain.getString(
                account: "vpn/\(profile.id)/ovpn-username"
            )) ?? ""
            if !storedUser.isEmpty {
                rows.append(DefinitionRow("Username", storedUser))
            }

        case .unsupported(let backend):
            rows.append(DefinitionRow("Backend", backend, mono: false))
        }

        rows.append(DefinitionRow(
            "Tunnel mode",
            profile.fullTunnel ? "Full tunnel" : "Split tunnel",
            mono: false
        ))
        // Greyed: you only reach for the UUID when something is wrong, so it
        // shouldn't compete with the server and username above it.
        rows.append(DefinitionRow("Profile ID", profile.id, deemphasized: true))
        return rows
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary).frame(width: 120, alignment: .leading)
            Text(value).textSelection(.enabled)
        }
        .font(.callout)
    }

    /// Render the live-tunnel block (interface, virtual IP,
    /// gateway, pushed routes). Hides itself when nothing's
    /// connected — an empty `live` implies the helper
    /// hasn't reported any tunnel metadata yet.
    @ViewBuilder
    private func liveTunnelRows() -> some View {
        if !live.isEmpty {
            Divider().padding(.vertical, 4)
            Text("LIVE TUNNEL")
                .font(.caption.smallCaps())
                .foregroundStyle(.secondary)
                .padding(.bottom, 2)
            if !live.interface.isEmpty {
                row("Interface", live.interface)
            }
            if !live.virtualIp.isEmpty {
                let assigned = live.virtualGateway.isEmpty
                    ? live.virtualIp
                    : "\(live.virtualIp) → \(live.virtualGateway)"
                row("Assigned IP", assigned)
            }
            // Connection-uptime row, ticking every second via
            // TimelineView. Sourced from the latest
            // `.connectSucceeded` activity event — same source the
            // Recent activity row uses, so the two stay in sync.
            // Hidden if we can't determine a connect time (e.g.
            // tunnel was already up when the app launched).
            if let connectedAt = latestConnectTime {
                connectedDurationRow(since: connectedAt)
            }
            // Throughput is rendered once, by the existing
            // `bandwidthRow` near the top of the detail view —
            // it reads the same `vpnByteCounters` AppState exposes
            // for every backend, including Azure now that the
            // helper returns `rx_bytes`/`tx_bytes` from netstat.
            // Don't duplicate it here.
            if !live.routes.isEmpty {
                HStack(alignment: .firstTextBaseline) {
                    Text("Pushed routes")
                        .foregroundStyle(.secondary)
                        .frame(width: 120, alignment: .leading)
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(live.routes, id: \.self) { cidr in
                            Text(cidr)
                                .font(.callout.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                }
                .font(.callout)
            }
        }
    }

    /// Throughput row: counters from helper's wgStatus. Down /
    /// up arrows are placed inline with the byte count so the
    /// row reads "↓ 4.5 MB · ↑ 1.2 MB" — matches the conventions
    /// in tools like nload / iftop where down comes first.
    /// `rate` is optional — only shown after at least two polls,
    /// when AppState has computed a delta.
    private func bandwidthRow(
        rx: UInt64,
        tx: UInt64,
        rate: (rxPerSec: Double, txPerSec: Double)?
    ) -> some View {
        let totalFormatter = ByteCountFormatter()
        totalFormatter.allowedUnits = [.useKB, .useMB, .useGB, .useTB]
        totalFormatter.countStyle = .binary
        let rxStr = totalFormatter.string(fromByteCount: Int64(min(rx, UInt64(Int64.max))))
        let txStr = totalFormatter.string(fromByteCount: Int64(min(tx, UInt64(Int64.max))))

        let rateFormatter = ByteCountFormatter()
        rateFormatter.allowedUnits = [.useKB, .useMB, .useGB]
        rateFormatter.countStyle = .binary
        rateFormatter.includesUnit = true
        let rxRateStr = rate.map { rateFormatter.string(fromByteCount: Int64($0.rxPerSec)) + "/s" }
        let txRateStr = rate.map { rateFormatter.string(fromByteCount: Int64($0.txPerSec)) + "/s" }

        return HStack(alignment: .firstTextBaseline) {
            Text("Throughput").foregroundStyle(.secondary)
                .frame(width: 120, alignment: .leading)
            HStack(spacing: 4) {
                Image(systemName: "arrow.down")
                    .foregroundStyle(.secondary)
                    .imageScale(.small)
                Text(rxStr).textSelection(.enabled).monospacedDigit()
                if let rxRateStr {
                    Text("(\(rxRateStr))")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .monospacedDigit()
                }
            }
            Text("·").foregroundStyle(.tertiary)
            HStack(spacing: 4) {
                Image(systemName: "arrow.up")
                    .foregroundStyle(.secondary)
                    .imageScale(.small)
                Text(txStr).textSelection(.enabled).monospacedDigit()
                if let txRateStr {
                    Text("(\(txRateStr))")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .monospacedDigit()
                }
            }
            Spacer()
        }
        .font(.callout)
        .help("Total bytes received (↓) and sent (↑) on this tunnel since connect, with current rate in parentheses. Updated every poll cycle (~3 s).")
    }

    /// Walk this profile's ActivityLog from newest backwards. The
    /// most recent `.connectSucceeded` is the start of the active
    /// session — UNLESS a disconnect/forceDisconnect/connectFailed
    /// has fired since, which would mean the session ended. Returns
    /// `nil` when we can't tell (no events recorded yet, or the
    /// last event isn't a connect).
    private var latestConnectTime: Date? {
        let events = ActivityLog.shared.events(for: profileId)  // newest first
        for ev in events {
            switch ev.kind {
            case .connectSucceeded:
                return ev.timestamp
            case .disconnectComplete, .disconnectRequested,
                 .forceDisconnect, .panicReset, .connectFailed:
                return nil
            default:
                continue  // ignore connectStarted, killSwitch*, etc.
            }
        }
        return nil
    }

    /// "Connected for 5m 12s" row, ticks every second via
    /// TimelineView. Same pattern as `handshakeRow` for WG.
    private func connectedDurationRow(since start: Date) -> some View {
        TimelineView(.periodic(from: .now, by: 1.0)) { context in
            let age = max(0, Int(context.date.timeIntervalSince(start)))
            let label: String = {
                if age < 60 { return "\(age)s" }
                if age < 3600 { return "\(age / 60)m \(age % 60)s" }
                let hours = age / 3600
                let mins = (age % 3600) / 60
                return "\(hours)h \(mins)m"
            }()
            HStack(alignment: .firstTextBaseline) {
                Text("Connected for")
                    .foregroundStyle(.secondary)
                    .frame(width: 120, alignment: .leading)
                Text(label)
                    .monospacedDigit()
                Spacer()
            }
            .font(.callout)
            .help("Time since the tunnel reached `connected`. Sourced from the local activity log; resets on disconnect/reconnect.")
        }
    }

    /// "Last handshake" row that ticks every second so the operator
    /// can see at a glance whether the tunnel is actually live or
    /// has gone idle. WireGuard's data-plane stays up between
    /// handshakes, but a handshake older than ~3 minutes usually
    /// means the peer is unreachable and a reconnect is in order.
    /// Colored amber past 180 s (the WG REKEY_AFTER_TIME default
    /// window) and red past 300 s.
    private func handshakeRow(handshakeUnix: Int64) -> some View {
        TimelineView(.periodic(from: .now, by: 1.0)) { context in
            let age = max(0, Int(context.date.timeIntervalSince1970) - Int(handshakeUnix))
            let (label, color): (String, Color) = {
                if age < 60 { return ("\(age)s ago", .secondary) }
                if age < 180 { return ("\(age / 60)m \(age % 60)s ago", .secondary) }
                if age < 300 { return ("\(age / 60)m \(age % 60)s ago — stale", .orange) }
                return ("\(age / 60)m \(age % 60)s ago — peer unreachable?", .red)
            }()
            HStack(alignment: .firstTextBaseline) {
                Text("Last handshake")
                    .foregroundStyle(.secondary)
                    .frame(width: 120, alignment: .leading)
                Text(label)
                    .monospacedDigit()
                    .foregroundStyle(color)
                Spacer()
            }
            .font(.callout)
            .help("Time since the most recent successful handshake with any peer. WireGuard rekeys every ~120 s under load; values over 3 min usually mean the peer is unreachable.")
        }
    }

    // MARK: - State formatting

    private func displayState(_ state: String) -> String {
        switch state {
        case "connected":    return "Connected"
        case "connecting":   return "Connecting…"
        case "reconnecting": return "Reconnecting…"
        // Was connected, but the helper can no longer confirm the tunnel
        // (repeated status timeouts / RPC failures). Distinct from a clean
        // "Disconnected" so the user knows something is wrong, not that they
        // deliberately hung up.
        case "problem":      return "Disconnected (problem)"
        case "disconnected":
            return helperReachable ? "Disconnected" : "Helper not installed"
        default: return state.capitalized
        }
    }

    private func statusColor(_ state: String) -> Color {
        switch state {
        case "connected":    return .green
        case "connecting":   return .yellow    // initial handshake in progress
        case "reconnecting": return .orange    // session dropped, retrying — warmer than yellow
        case "problem":      return .red        // was up, now unconfirmable
        default:             return .gray.opacity(0.5)
        }
    }

    /// Status pill — filled-and-prominent when connected (the state
    /// that needs the strongest visual confirmation; users care most
    /// about "is the tunnel actually up"), outlined-with-dot for
    /// other states. Replaces the tiny dot+caption combo, which was
    /// easy to miss when the user's eye was on the action button.
    @ViewBuilder
    private func statusPill(_ color: Color) -> some View {
        let label = displayState(vpnState)
        if vpnState == "connected" && helperReachable {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.shield.fill")
                Text(label.uppercased())
            }
            .font(.callout.weight(.bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(color, in: Capsule())
        } else {
            HStack(spacing: 8) {
                Circle()
                    .fill(color)
                    .frame(width: 10, height: 10)
                Text(label)
                    .foregroundStyle(.primary)
            }
        }
    }

    // MARK: - Lifecycle

    private func load() async {
        loading = true
        loadError = nil
        do {
            let p: VpnProfile = try await appState.client.call(
                "vpn_get_profile",
                params: ["id": profileId]
            )
            profile = p
        } catch {
            loadError = error.localizedDescription
        }
        loading = false
    }

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task {
            while !Task.isCancelled {
                await refreshHelperState()
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }

    private func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    private func refreshHelperState() async {
        // Suspend background status polling while a user-initiated
        // connect/disconnect is in flight. The connect Task already
        // updates `vpnState` ("connecting" → "connected"); having a
        // 3-second poll race against it overwrote that with
        // "disconnected" between RPC call and tunnel-actually-up,
        // making the UI flicker.
        if busy { return }
        helperReachable = await HelperClient.shared.isReachable()
        // Boot-race recovery: the daemon's Unix socket appears a few
        // seconds after login, but the app may probe (and latch a scary
        // "helper isn't up" banner) before launchd finishes spawning it.
        // Once the socket is actually live, drop that stale banner so a
        // reboot doesn't leave the profile looking permanently broken.
        // Only the two helper-availability messages are cleared — a real
        // connect error, set while the helper was already reachable, is
        // never one of these and so is left untouched.
        if helperReachable,
           actionError == Self.helperSocketPendingMessage
            || actionError == Self.helperNotRunningMessage {
            actionError = nil
        }
        guard helperReachable, let profile = profile else {
            // Helper briefly unreachable (mid bootout/bootstrap, or a socket
            // hiccup). HOLD the last state — do NOT flip to "disconnected", that
            // was a flicker source. The global poller owns the state and leaves
            // it alone too when the helper is unreachable.
            return
        }
        // SINGLE SOURCE OF TRUTH: `vpnState` is driven ONLY by the global
        // debounced poller via `onChange(of: vpnConnectionStates[profileId])`.
        // This local poll no longer writes `vpnState` or
        // `vpnConnectionStates` — it used to write a RAW, un-debounced per-poll
        // status straight into the shared map, which bypassed the debounce and
        // was the primary cause of the constant connected/connecting blink.
        // It now only fetches backend-specific ENRICHMENT (the detail line,
        // strongSwan-missing flag, reconnect reason, live-tunnel metadata),
        // gated on the raw connected-ness of THIS poll (fine for descriptive
        // text; it never touches the dot).
        do {
            switch profile.config {
            case .ikev2:
                let result = try await HelperClient.shared.vpnStatus(profileId: profileId)
                stateDetail = result["detail"] as? String ?? ""
                strongswanMissing = stateDetail.contains("strongSwan not installed")
            case .wireguard:
                let result = try await HelperClient.shared.wgStatus(profileId: profileId)
                let rawConnected = (result["state"] as? String) == "connected"
                if let rx = result["rx_bytes"] as? Int,
                   let tx = result["tx_bytes"] as? Int,
                   rawConnected {
                    stateDetail = "rx \(rx) bytes · tx \(tx) bytes"
                } else {
                    stateDetail = ""
                }
            case .openvpn:
                let result = try await HelperClient.shared.ovpnStatus(profileId: profileId)
                let rawConnected = (result["state"] as? String) == "connected"
                reconnectReason = result["error_reason"] as? String
                if let pid = result["pid"] as? Int, rawConnected {
                    stateDetail = "openvpn pid \(pid)"
                } else {
                    stateDetail = ""
                }
                applyLiveTunnelMetadata(from: result, connected: rawConnected)
            case .azure:
                // Azure → OpenVPN tunnel (helper spawns ovpncli /
                // openvpn 2.x via the same `ovpnConnect` RPC the
                // OpenVPN backend uses), so status flows through
                // the same `ovpn_status` endpoint.
                let result = try await HelperClient.shared.ovpnStatus(profileId: profileId)
                let rawConnected = (result["state"] as? String) == "connected"
                // Surface the last transport error so the user knows
                // why the connection is in a retry loop.
                reconnectReason = result["error_reason"] as? String
                if let pid = result["pid"] as? Int, rawConnected {
                    stateDetail = "openvpn pid \(pid)"
                } else {
                    stateDetail = ""
                }
                applyLiveTunnelMetadata(from: result, connected: rawConnected)
            case .unsupported:
                stateDetail = ""
            }
        } catch {
            // Don't surface poll errors — they spam the UI. Log to console.
            print("vpn status poll error: \(error)")
        }
    }

    /// Copy `interface` / `virtual_ip` / `virtual_gateway` /
    /// `active_routes` out of an `ovpn_status` JSON dict into the
    /// `live*` @State fields. Clears them on disconnect so the
    /// "Live tunnel" section disappears cleanly.
    private func applyLiveTunnelMetadata(from result: [String: Any], connected: Bool) {
        guard connected else {
            live = LiveTunnel()
            return
        }
        live = LiveTunnel(
            interface: (result["interface"] as? String) ?? "",
            virtualIp: (result["virtual_ip"] as? String) ?? "",
            virtualGateway: (result["virtual_gateway"] as? String) ?? "",
            routes: (result["active_routes"] as? [String]) ?? []
        )
    }

    // MARK: - Actions

    private func installHelper() async {
        actionError = nil
        busy = true
        defer { busy = false }
        do {
            try await HelperInstaller.install()
            // launchd spawns the daemon and it binds its Unix socket a
            // beat later. Poll the socket DIRECTLY here — refreshHelperState()
            // is suppressed while `busy`, so calling it would no-op and
            // leave `helperReachable` stale, latching the banner even when
            // the socket came up fine. Give it a few seconds before giving
            // up so a normal cold start doesn't flash a "socket isn't up"
            // banner the instant the click lands.
            var reachable = false
            for _ in 0..<12 {                       // ~6 s: 12 × 500 ms
                if await HelperClient.shared.isReachable() {
                    reachable = true
                    break
                }
                try? await Task.sleep(for: .milliseconds(500))
            }
            helperReachable = reachable
            if !reachable {
                actionError = Self.helperSocketPendingMessage
            }
        } catch {
            actionError = error.localizedDescription
        }
    }

    private func connect(_ profile: VpnProfile) async {
        actionError = nil
        busy = true
        defer { busy = false }
        guard case .ikev2(let cfg) = profile.config else {
            actionError = "Profile has no IKEv2 configuration"
            return
        }
        do {
            // Re-check reachability synchronously RIGHT NOW. The polled
            // `helperReachable` flag updates every 3 s; if the user
            // clicks Connect during a transient window we'd otherwise
            // call HelperInstaller.install() — which can prompt for the
            // admin password. By probing the socket here first, we skip
            // the install path entirely whenever the helper is actually
            // up, regardless of what the polled flag says. This is the
            // single fix that eliminated the "50 password popups per
            // connect" behaviour the user reported.
            let reachableNow = await HelperClient.shared.isReachable()
            if reachableNow {
                helperReachable = true
            } else {
                try await HelperInstaller.install()
                try? await Task.sleep(for: .milliseconds(700))
                helperReachable = await HelperClient.shared.isReachable()
                if !helperReachable {
                    actionError = Self.helperNotRunningMessage
                    return
                }
            }

            let password = try VPNKeychain.getString(account: cfg.password)
            let psk = cfg.psk.isEmpty ? "" : (try VPNKeychain.getString(account: cfg.psk))

            vpnState = "connecting"
            // Pass split-tunnel routes through to the helper so it can
            // template `remote_ts` per the user's choice. Empty
            // routes + `full_tunnel = true` is the default and means
            // "everything through the tunnel"; non-empty routes +
            // `full_tunnel = false` is split mode.
            let result = try await HelperClient.shared.vpnConnect(
                profileId: profile.id,
                name: profile.name,
                host: cfg.host,
                username: cfg.username,
                password: password,
                sharedSecret: psk,
                fullTunnel: profile.fullTunnel,
                routes: cfg.routes,
                localId: cfg.localId
            )
            if let ok = result["ok"] as? Bool, !ok {
                actionError = (result["message"] as? String) ?? "Connect failed"
                vpnState = "disconnected"
            }
            // Refresh state after connect — gives the user immediate feedback
            // rather than waiting for the next poll tick.
            try? await Task.sleep(for: .milliseconds(500))
            await refreshHelperState()
        } catch {
            actionError = error.localizedDescription
            vpnState = "disconnected"
        }
    }

    private func disconnect(_ profile: VpnProfile) async {
        actionError = nil
        busy = true
        defer { busy = false }
        do {
            _ = try await HelperClient.shared.vpnDisconnect(profileId: profile.id)
            try? await Task.sleep(for: .milliseconds(500))
            await refreshHelperState()
        } catch {
            actionError = error.localizedDescription
        }
    }

    // MARK: - WireGuard

    private func connectWireGuard(_ profile: VpnProfile) async {
        actionError = nil
        busy = true
        defer { busy = false }

        // Re-probe helper, as in the IKEv2 path. Same race window
        // applies — user might toggle the SMAppService approval
        // between view appearance and clicking Connect.
        if !helperReachable {
            helperReachable = await HelperClient.shared.isReachable()
            if !helperReachable {
                actionError = "Helper isn't running yet. Approve the " +
                    "background daemon prompt in System Settings → " +
                    "General → Login Items, then click Connect again."
                return
            }
        }

        vpnState = "connecting"
        let (ok, message) = await appState.wireguardConnect(profileId: profile.id)
        if !ok {
            actionError = message
            vpnState = "disconnected"
        } else {
            // Optimistic — reflect connected state immediately. The
            // 5-second status poll below verifies and corrects.
            vpnState = "connected"
            stateDetail = message
        }
        try? await Task.sleep(for: .milliseconds(500))
        await refreshWireGuardState(profile)
    }

    private func disconnectWireGuard(_ profile: VpnProfile) async {
        actionError = nil
        busy = true
        defer { busy = false }
        let (_, message) = await appState.wireguardDisconnect(profileId: profile.id)
        stateDetail = message
        try? await Task.sleep(for: .milliseconds(500))
        await refreshWireGuardState(profile)
    }

    /// Poll `wg_status` and reflect into `vpnState`. Helper returns
    /// `connected` / `disconnected` plus byte counters; we only show
    /// the state in the dot for now.
    private func refreshWireGuardState(_ profile: VpnProfile) async {
        do {
            let result = try await HelperClient.shared.wgStatus(profileId: profile.id)
            let state = (result["state"] as? String) ?? "disconnected"
            vpnState = state
            // Surface byte counters as a secondary line — same place
            // strongSwan's `local_ts` / `remote_ts` lands.
            if let rx = result["rx_bytes"] as? Int,
               let tx = result["tx_bytes"] as? Int {
                stateDetail = "rx \(rx) bytes · tx \(tx) bytes"
            }
        } catch {
            // Don't surface poll errors as connect errors — the user
            // is staring at the result of an action they took, the
            // poll is background plumbing.
        }
    }

    // MARK: - OpenVPN

    private func connectOpenVPN(_ profile: VpnProfile, configFile: String) async {
        actionError = nil
        busy = true
        defer { busy = false }

        if !helperReachable {
            helperReachable = await HelperClient.shared.isReachable()
            if !helperReachable {
                actionError = "Helper isn't running yet. Approve the " +
                    "background daemon prompt in System Settings → " +
                    "General → Login Items, then click Connect again."
                return
            }
        }

        // Credentials (if any) are pulled from DPK by AppState —
        // they were stashed there at import time when the user filled
        // in the "Authentication" section of `ImportVpnSheet`.
        // Cert-only profiles store nothing and connect without creds.
        vpnState = "connecting"
        let (ok, message) = await appState.openVPNConnect(
            profileId: profile.id,
            configFile: configFile
        )
        if !ok {
            actionError = message
            vpnState = "disconnected"
        } else {
            vpnState = "connected"
            stateDetail = message
        }
        try? await Task.sleep(for: .milliseconds(500))
        await refreshOpenVPNState(profile)
    }

    private func disconnectOpenVPN(_ profile: VpnProfile) async {
        actionError = nil
        busy = true
        defer { busy = false }
        let (_, message) = await appState.openVPNDisconnect(profileId: profile.id)
        stateDetail = message
        try? await Task.sleep(for: .milliseconds(500))
        await refreshOpenVPNState(profile)
    }

    private func refreshOpenVPNState(_ profile: VpnProfile) async {
        do {
            let result = try await HelperClient.shared.ovpnStatus(profileId: profile.id)
            let state = (result["state"] as? String) ?? "disconnected"
            vpnState = state
            if let pid = result["pid"] as? Int {
                stateDetail = "openvpn pid \(pid)"
            }
        } catch {
            // Same rationale as WireGuard's poll — silent on errors.
        }
    }

}
