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
    /// "disconnected" / "connecting" / "connected".
    @State private var vpnState: String = "disconnected"
    @State private var stateDetail: String = ""
    // Live tunnel metadata, populated from `ovpn_status` /
    // `wg_status` once the tunnel is up. Empty when nothing's
    // connected so the "Live tunnel" section can hide itself.
    @State private var liveInterface: String = ""
    @State private var liveVirtualIp: String = ""
    @State private var liveVirtualGateway: String = ""
    @State private var liveActiveRoutes: [String] = []
    @State private var helperReachable: Bool = false
    @State private var pollTask: Task<Void, Never>?

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
            // Wipe per-view state on profile switch. Without this,
            // bouncing between profiles in the sidebar carries stale
            // status from the previously-selected profile until the
            // next poll arrives — making it look like every profile
            // is "Connected" when only one actually is.
            vpnState = "disconnected"
            stateDetail = ""
            actionError = nil
            strongswanMissing = false
            await load()
        }
        .onAppear { startPolling() }
        .onDisappear { stopPolling() }
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
    private var activitySection: some View {
        let events = Array(ActivityLog.shared.events(for: profileId).prefix(10))
        if !events.isEmpty {
            DisclosureGroup {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(events) { ev in
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
                .padding(.top, 4)
            } label: {
                HStack {
                    Text("Recent activity")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("\(events.count) events")
                        .font(.caption)
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
                    } else if vpnState == "connected" {
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
                    } else if vpnState == "connected" {
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
        VStack(alignment: .leading, spacing: 10) {
            row("Profile ID", profile.id)
            // Tunnel mode: showing the value as a row + an "Edit"
            // affordance keeps the details list consistent while
            // making the toggle two clicks away (button → sheet
            // → save). Routing changes are non-trivial (require
            // reconnect), and a sheet is the right commit boundary.
            //
            // Edit button is hidden for backends whose routing the
            // daemon's `vpn_set_routing` doesn't accept (OpenVPN —
            // routing is encoded inside the imported `.ovpn` file).
            // Showing a button that opens a sheet that immediately
            // says "you can't change this" is bad UX; better to
            // not offer the action at all.
            HStack(alignment: .firstTextBaseline) {
                Text("Tunnel mode").foregroundStyle(.secondary)
                    .frame(width: 120, alignment: .leading)
                Text(profile.fullTunnel ? "Full tunnel" : "Split tunnel")
                    .textSelection(.enabled)
                Spacer()
                if backendSupportsRoutingToggle(profile.config) {
                    Button {
                        editingRouting = true
                    } label: {
                        Label("Edit", systemImage: "arrow.triangle.branch")
                    }
                    .controlSize(.small)
                }
            }
            .font(.callout)

            // Kill switch: when enabled, connect installs pf
            // rules that block all egress except via the tunnel
            // iface + LAN. Reconnect required to take effect on
            // an already-up tunnel; toggling OFF tears the rules
            // down immediately.
            HStack(alignment: .firstTextBaseline) {
                Text("Kill switch").foregroundStyle(.secondary)
                    .frame(width: 120, alignment: .leading)
                Toggle("", isOn: killSwitchBinding)
                    .toggleStyle(.switch)
                    .labelsHidden()
                Spacer()
                Text(profile.killSwitch
                     ? "blocks egress except via tunnel"
                     : "no leak protection")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .font(.callout)

            // Throughput counters: WireGuard kernel module exposes
            // rx/tx bytes via `wg show`. AppState polls these every
            // few seconds into `vpnByteCounters`. Other backends
            // (OpenVPN, IKEv2) don't expose counters cheaply — the
            // row simply hides when no data is available.
            if let counters = appState.vpnByteCounters[profileId] {
                bandwidthRow(
                    rx: counters.rx,
                    tx: counters.tx,
                    rate: appState.vpnByteRates[profileId]
                )
            }

            // Live handshake age (WG-only). TimelineView ticks
            // every second so the "12s ago" updates without us
            // forcing a redraw. Hidden for non-WG and for any
            // tunnel that hasn't completed an initial handshake yet.
            if let unix = appState.vpnLastHandshakeUnix[profileId] {
                handshakeRow(handshakeUnix: unix)
            }

            // Active peer endpoint (the address we're actually
            // talking to right now). Useful when a profile has
            // multiple peers and you need to confirm which one
            // is carrying traffic.
            if let endpoint = appState.vpnPeerEndpoints[profileId] {
                row("Active peer", endpoint)
            }

            // Recent activity — last few connect/disconnect events
            // for this profile. Pulled from ActivityLog (persists
            // across app launches). Capped to 10 to keep the
            // detail view from sprawling.
            activitySection

            // Always-on: helper-side watchdog reconnects this
            // profile every 30s if it goes down, surviving the
            // GUI being closed (helper is a LaunchDaemon).
            // Captures connect args from the most-recent
            // successful connect — so the user must connect at
            // least once manually after enabling this for IKEv2
            // (WireGuard reads from daemon's secret store, so
            // it works on first toggle).
            HStack(alignment: .firstTextBaseline) {
                Text("Always on").foregroundStyle(.secondary)
                    .frame(width: 120, alignment: .leading)
                Toggle("", isOn: alwaysOnBinding)
                    .toggleStyle(.switch)
                    .labelsHidden()
                Spacer()
                Text(appState.autoReconnectEnabled.contains(profileId)
                     ? "auto-reconnect every 30s"
                     : "manual connect only")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .font(.callout)

            switch profile.config {
            case .ikev2(let cfg):
                row("Server", cfg.host)
                row("Username", cfg.username)
                if !cfg.dnsServers.isEmpty {
                    row("DNS", cfg.dnsServers.joined(separator: ", "))
                }
                if !cfg.routes.isEmpty {
                    row("Split routes", cfg.routes.joined(separator: ", "))
                }

            case .wireguard(let wg):
                if !wg.addresses.isEmpty {
                    row("Addresses", wg.addresses.joined(separator: ", "))
                }
                if !wg.dns.isEmpty {
                    row("DNS", wg.dns.joined(separator: ", "))
                }
                row("Peers", String(wg.peerCount))
                if let endpoint = wg.firstPeerEndpoint {
                    row("Endpoint", endpoint)
                }
                if !wg.splitRoutes.isEmpty {
                    row("Split routes", wg.splitRoutes.joined(separator: ", "))
                }

            case .azure(let az):
                // Azure-specific fields. Tenant + gateway FQDN are
                // the unique-identifier pair; client ID is the
                // OAuth2 audience the daemon uses when acquiring
                // an Entra-ID token at connect time.
                row("Gateway", az.gatewayFqdn)
                row("Tenant ID", az.tenantId)
                row("Client ID", az.clientId)
                if !az.dnsServers.isEmpty {
                    row("DNS", az.dnsServers.joined(separator: ", "))
                }
                if !az.routes.isEmpty {
                    row("Split routes", az.routes.joined(separator: ", "))
                }
                // Live tunnel state — only renders when ovpncli /
                // openvpn 2.x is up and reporting routes/IP. The
                // gateway pushes these at connect; they're not
                // present in the static profile so we surface them
                // separately so the operator can see what their
                // session is actually carrying.
                liveTunnelRows()
                Text("Authenticates via Entra ID (device-code flow) at connect.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.top, 4)

            case .openvpn(let cfg):
                // Show just the filename — the full path is long and
                // includes our own data-dir, which isn't useful at a
                // glance.
                row("Config file", URL(fileURLWithPath: cfg.configFile).lastPathComponent)
                // Surface the username from the keychain (the daemon-
                // side `OpenVpnConfig.username` field is empty on
                // import; creds live in DPK). Reading is cheap.
                let storedUser = (try? VPNKeychain.getString(
                    account: "vpn/\(profile.id)/ovpn-username"
                )) ?? ""
                if !storedUser.isEmpty {
                    row("Username", storedUser)
                }
                Button {
                    editingOvpnCreds = true
                } label: {
                    Label("Edit credentials", systemImage: "key.horizontal")
                }
                .controlSize(.small)
                .padding(.top, 4)

            case .unsupported(let backend):
                row("Backend", backend)
            }
        }
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
    /// connected — `liveInterface` empty implies the helper
    /// hasn't reported any tunnel metadata yet.
    @ViewBuilder
    private func liveTunnelRows() -> some View {
        if !liveInterface.isEmpty
            || !liveVirtualIp.isEmpty
            || !liveActiveRoutes.isEmpty
        {
            Divider().padding(.vertical, 4)
            Text("LIVE TUNNEL")
                .font(.caption.smallCaps())
                .foregroundStyle(.secondary)
                .padding(.bottom, 2)
            if !liveInterface.isEmpty {
                row("Interface", liveInterface)
            }
            if !liveVirtualIp.isEmpty {
                let assigned = liveVirtualGateway.isEmpty
                    ? liveVirtualIp
                    : "\(liveVirtualIp) → \(liveVirtualGateway)"
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
            if !liveActiveRoutes.isEmpty {
                HStack(alignment: .firstTextBaseline) {
                    Text("Pushed routes")
                        .foregroundStyle(.secondary)
                        .frame(width: 120, alignment: .leading)
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(liveActiveRoutes, id: \.self) { cidr in
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
        case "connected": return "Connected"
        case "connecting": return "Connecting…"
        case "disconnected":
            return helperReachable ? "Disconnected" : "Helper not installed"
        default: return state.capitalized
        }
    }

    private func statusColor(_ state: String) -> Color {
        switch state {
        case "connected": return .green
        case "connecting": return .orange
        default: return .gray.opacity(0.5)
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
        guard helperReachable, let profile = profile else {
            if !helperReachable { vpnState = "disconnected" }
            return
        }
        // Pick the right helper RPC based on the profile's backend.
        // Each backend has its own status shape — we extract the
        // common `state` string and surface a backend-appropriate
        // `detail` line so the UI is uniform from the user's side.
        do {
            switch profile.config {
            case .ikev2:
                let result = try await HelperClient.shared.vpnStatus(profileId: profileId)
                vpnState = result["state"] as? String ?? "disconnected"
                stateDetail = result["detail"] as? String ?? ""
                // The helper reports "strongSwan not installed" via
                // the status detail when its binary probe fails.
                // Surfacing that in `actionError` would drown the
                // user in noise; flip the dedicated flag and the
                // detail view renders a setup banner instead.
                strongswanMissing = stateDetail.contains("strongSwan not installed")
            case .wireguard:
                let result = try await HelperClient.shared.wgStatus(profileId: profileId)
                vpnState = result["state"] as? String ?? "disconnected"
                if let rx = result["rx_bytes"] as? Int,
                   let tx = result["tx_bytes"] as? Int,
                   vpnState == "connected" {
                    stateDetail = "rx \(rx) bytes · tx \(tx) bytes"
                } else {
                    stateDetail = ""
                }
            case .openvpn:
                let result = try await HelperClient.shared.ovpnStatus(profileId: profileId)
                vpnState = result["state"] as? String ?? "disconnected"
                if let pid = result["pid"] as? Int, vpnState == "connected" {
                    stateDetail = "openvpn pid \(pid)"
                } else {
                    stateDetail = ""
                }
                applyLiveTunnelMetadata(from: result, connected: vpnState == "connected")
            case .azure:
                // Azure → OpenVPN tunnel (helper spawns ovpncli /
                // openvpn 2.x via the same `ovpnConnect` RPC the
                // OpenVPN backend uses), so status flows through
                // the same `ovpn_status` endpoint.
                let result = try await HelperClient.shared.ovpnStatus(profileId: profileId)
                vpnState = result["state"] as? String ?? "disconnected"
                if let pid = result["pid"] as? Int, vpnState == "connected" {
                    stateDetail = "openvpn pid \(pid)"
                } else {
                    stateDetail = ""
                }
                applyLiveTunnelMetadata(from: result, connected: vpnState == "connected")
            case .unsupported:
                vpnState = "disconnected"
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
            liveInterface = ""
            liveVirtualIp = ""
            liveVirtualGateway = ""
            liveActiveRoutes = []
            return
        }
        liveInterface = (result["interface"] as? String) ?? ""
        liveVirtualIp = (result["virtual_ip"] as? String) ?? ""
        liveVirtualGateway = (result["virtual_gateway"] as? String) ?? ""
        liveActiveRoutes = (result["active_routes"] as? [String]) ?? []
    }

    // MARK: - Actions

    private func installHelper() async {
        actionError = nil
        busy = true
        defer { busy = false }
        do {
            try await HelperInstaller.install()
            // Give launchd a moment to spawn the daemon, then re-check.
            try? await Task.sleep(for: .milliseconds(700))
            await refreshHelperState()
            if !helperReachable {
                actionError = "Helper installed but socket isn't up yet. " +
                    "Check System Settings → General → Login Items if a " +
                    "background-item approval prompt was shown."
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
                    actionError = "Helper isn't running yet. Approve the " +
                        "background daemon prompt in System Settings → " +
                        "General → Login Items, then click Connect again."
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
                routes: cfg.routes
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
