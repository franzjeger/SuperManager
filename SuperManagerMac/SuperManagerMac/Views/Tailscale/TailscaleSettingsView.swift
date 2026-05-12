import AppKit
import SwiftUI

/// Settings sheet for the Tailscale daemon — accept routes/DNS,
/// shields-up, Tailscale SSH, exit-node advertising, subnet routes,
/// hostname override, auto-update.
///
/// Each toggle is wired to `applyTailscalePref(...)`, which mutates a
/// local copy of the prefs for an instant snap, then runs the CLI and
/// reconciles via a refresh. Failures surface inline at the bottom of
/// the sheet rather than in a modal alert — auth/network hiccups in
/// a sheet that's already modal would be visually noisy.
struct TailscaleSettingsView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    /// Local working copy of the routes textbox. The daemon stores
    /// this as a `[String]` but for editing it's friendlier as a
    /// comma-separated string the user can type into directly.
    @State private var advertiseRoutesText: String = ""
    /// Same for hostname — bound to a TextField, applied on commit
    /// rather than every keystroke (the CLI is fast but invoking
    /// it 30 times during typing is silly).
    @State private var hostnameText: String = ""
    /// User-configured fallback DNS list. Comma-separated.
    /// Persisted in helper at /var/lib/supermanager/dns_fallbacks.json.
    @State private var dnsFallbacksText: String = ""
    @State private var originalDNSFallbacksText: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    accountSection
                    routingSection
                    dnsSection
                    incomingSection
                    subnetRouterSection
                    advancedSection
                }
                .padding(20)
            }
            Divider()
            footer
        }
        // Switch-style toggles read more clearly than the macOS
        // default checkbox at this size, and stop users wondering
        // whether a faded checkbox is interactive or disabled.
        .toggleStyle(.switch)
        .frame(width: 520, height: 620)
        .onAppear {
            // Seed the text fields from the live prefs once on
            // open. Subsequent edits are local until commit.
            advertiseRoutesText = appState.tailscalePrefs?.manualAdvertiseRoutes
                .joined(separator: ", ") ?? ""
            hostnameText = appState.tailscalePrefs?.hostname ?? ""
            // DNS fallback list lives in helper persistence; fetch.
            Task {
                if let r = try? await HelperClient.shared.tailscaleGetDNSFallbacks(),
                   let list = r["fallbacks"] as? [String] {
                    let joined = list.joined(separator: ", ")
                    dnsFallbacksText = joined
                    originalDNSFallbacksText = joined
                }
            }
            // Pull a fresh snapshot so we're not editing stale state.
            Task { await appState.refreshTailscale() }
        }
    }

    // MARK: - Header / footer

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "gear")
                .font(.title2)
                .foregroundStyle(.secondary)
            Text("Tailscale Settings")
                .font(.title3.weight(.semibold))
            Spacer()
            Button {
                Task { await appState.refreshTailscale() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .help("Reload preferences from the daemon.")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var footer: some View {
        HStack {
            if let err = appState.tailscaleActionError {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text(err)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(2)
                    .truncationMode(.middle)
            }
            Spacer()
            Button("Done") { dismiss() }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }

    // MARK: - Sections

    /// Read-only "logged in as …" block. Lets the user verify which
    /// account this Mac is on without leaving the sheet.
    private var accountSection: some View {
        section(title: "Account") {
            HStack {
                Image(systemName: "person.crop.circle")
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(appState.tailscalePrefs?.userLogin ?? "—")
                        .font(.callout.weight(.medium))
                    if let suffix = appState.tailscaleStatus?.magicDNSSuffix {
                        Text(suffix)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
            }
        }
    }

    /// "Use exit node" + "Allow LAN access" + "Accept advertised routes."
    /// Co-located because they're conceptually all about how this Mac
    /// routes its outgoing traffic.
    private var routingSection: some View {
        section(title: "Routing") {
            // Exit node picker. Built from peers with
            // ExitNodeOption=true. The Self node is excluded — using
            // yourself as your own exit is meaningless.
            HStack {
                Text("Exit node")
                Spacer()
                exitNodePicker
            }
            Toggle("Allow LAN access while using exit node", isOn: Binding(
                get: { appState.tailscalePrefs?.exitNodeAllowLANAccess ?? false },
                set: { newValue in
                    DebugLog.write("[ts/toggle] exitNodeAllowLAN -> \(newValue)")
                    Task {
                        await appState.applyTailscalePref(
                            optimistic: { $0.exitNodeAllowLANAccess = newValue },
                            cli: { try await TailscaleClient.setExitNodeAllowLAN(newValue) }
                        )
                    }
                }
            ))
            .disabled(!hasExitNode)
            .help(!hasExitNode
                  ? "Only meaningful when an exit node is selected."
                  : "Reach printers / NAS on your local network even while exit-noding.")
            Toggle("Accept routes advertised by other peers", isOn: Binding(
                get: { appState.tailscalePrefs?.routeAll ?? false },
                set: { newValue in
                    DebugLog.write("[ts/toggle] routeAll -> \(newValue)")
                    Task {
                        await appState.applyTailscalePref(
                            optimistic: { $0.routeAll = newValue },
                            cli: { try await TailscaleClient.setAcceptRoutes(newValue) }
                        )
                    }
                }
            ))
            .help("Lets you reach subnets behind subnet routers in your tailnet.")
        }
    }

    /// Exit-node picker. Four-layer safety net (pre-flight,
    /// auto-revert, route guardian, connectivity watchdog) —
    /// see TailscaleHeaderView.exitNodeSubmenu for full details.
    private var exitNodePicker: some View {
        let peers = exitCandidates.filter { $0.online }
        let allPeers = appState.tailscaleStatus?.peers ?? []
        let active = appState.tailscalePrefs?.currentExitNode(in: allPeers)
        return Menu {
            Button {
                Task { await setExitNode("") }
            } label: {
                if active == nil { Image(systemName: "checkmark") }
                Text("None")
            }
            if !peers.isEmpty {
                Divider()
                ForEach(peers) { peer in
                    Button {
                        if let ip = peer.primaryIP {
                            Task { await setExitNode(ip) }
                        }
                    } label: {
                        if active?.id == peer.id {
                            Image(systemName: "checkmark")
                        }
                        Text(peer.hostName)
                    }
                }
            }
        } label: {
            Text(currentExitNodeLabel)
                .font(.callout)
        }
        .menuStyle(.borderlessButton)
        .frame(maxWidth: 220, alignment: .trailing)
    }

    /// MagicDNS toggle + fallback DNS config + manual reset.
    private var dnsSection: some View {
        section(title: "DNS") {
            Toggle("Use Tailscale DNS", isOn: Binding(
                get: { appState.tailscalePrefs?.corpDNS ?? false },
                set: { newValue in
                    DebugLog.write("[ts/toggle] corpDNS -> \(newValue)")
                    Task {
                        await appState.applyTailscalePref(
                            optimistic: { $0.corpDNS = newValue },
                            cli: { try await TailscaleClient.setAcceptDNS(newValue) }
                        )
                    }
                }
            ))
            .help("Required for MagicDNS names like `mac.tailnet.ts.net` to resolve.")

            Divider()

            // Fallback list — used by the helper's DNS health
            // watchdog. When the active resolver fails its 30s
            // probe, the watchdog force-writes State to this
            // list (in priority order). Comma-separated input;
            // applied on Done click.
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Fallback DNS servers")
                        .font(.callout)
                    Spacer()
                    Button("Apply") {
                        Task { await commitDNSFallbacks() }
                    }
                    .controlSize(.small)
                    .disabled(dnsFallbacksText == originalDNSFallbacksText)
                    Button("Reset DNS now") {
                        Task { await appState.resetDNSToFallbacks() }
                    }
                    .controlSize(.small)
                    .help("Force the system resolver to this list immediately.")
                }
                TextField("1.1.1.1, 9.9.9.9", text: $dnsFallbacksText)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                Text("DNS health watchdog uses these when the resolver gets stuck on a non-responsive nameserver.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Inbound-traffic controls — Tailscale-SSH and shields-up.
    private var incomingSection: some View {
        section(title: "Incoming") {
            Toggle("Run Tailscale SSH server", isOn: Binding(
                get: { appState.tailscalePrefs?.runSSH ?? false },
                set: { newValue in
                    DebugLog.write("[ts/toggle] runSSH -> \(newValue)")
                    Task {
                        await appState.applyTailscalePref(
                            optimistic: { $0.runSSH = newValue },
                            cli: { try await TailscaleClient.setRunSSH(newValue) }
                        )
                    }
                }
            ))
            .help("Allow tailnet peers to SSH in using Tailscale-managed auth instead of SSH keys.")
            Toggle("Block incoming connections (Shields up)", isOn: Binding(
                get: { appState.tailscalePrefs?.shieldsUp ?? false },
                set: { newValue in
                    DebugLog.write("[ts/toggle] shieldsUp -> \(newValue)")
                    Task {
                        await appState.applyTailscalePref(
                            optimistic: { $0.shieldsUp = newValue },
                            cli: { try await TailscaleClient.setShieldsUp(newValue) }
                        )
                    }
                }
            ))
            .help("Block all inbound from peers regardless of ACLs. Outbound is unaffected.")
        }
    }

    /// Subnet-router controls — advertise this Mac as an exit node,
    /// or advertise specific routes for peers to reach networks
    /// behind us.
    private var subnetRouterSection: some View {
        section(title: "Advertise routes") {
            Toggle("Run as exit node for the tailnet",
                   isOn: bindAdvertiseExitNode)
            .help("Other tailnet members can route their internet traffic through this Mac. The admin must approve in the Tailscale console before it's active.")

            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Subnet routes")
                        .font(.callout)
                    Spacer()
                    Button("Apply") {
                        Task { await commitAdvertiseRoutes() }
                    }
                    .controlSize(.small)
                    .disabled(advertiseRoutesText == originalAdvertiseRoutesText)
                }
                TextEditor(text: $advertiseRoutesText)
                    .font(.body.monospaced())
                    .frame(height: 60)
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(.quaternary)
                    )
                Text("Comma-separated CIDR list, e.g. 192.168.1.0/24, 10.0.0.0/8")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Hostname override + auto-update.
    private var advancedSection: some View {
        section(title: "Advanced") {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Hostname override")
                    Spacer()
                    Button("Apply") {
                        Task { await commitHostname() }
                    }
                    .controlSize(.small)
                    .disabled(hostnameText == (appState.tailscalePrefs?.hostname ?? ""))
                }
                TextField("Use OS hostname", text: $hostnameText)
                    .textFieldStyle(.roundedBorder)
                Text("Leave empty to fall back to the system hostname.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Toggle("Auto-update Tailscale",
                   isOn: bindAutoUpdate)
            .help("Only takes effect on installs from the Tailscale installer — Homebrew / App Store builds ignore this and update via their own channel.")
        }
    }

    // MARK: - Computed helpers

    /// Peers that advertise themselves as exit nodes. Self is
    /// excluded — using yourself as exit is a no-op.
    private var exitCandidates: [TailscalePeer] {
        guard let s = appState.tailscaleStatus else { return [] }
        return s.peers.filter { $0.exitNodeOption }
    }

    /// IP of the currently selected exit node, or empty string if
    /// none. The CLI accepts either ID or IP, but the prefs object
    /// always reports both — IP is more stable because we can match
    /// it against TailscalePeer.tailscaleIPs.
    /// Whether ANY exit-node is active (via either ExitNodeIP or
    /// ExitNodeID). Used to enable/disable the "Allow LAN
    /// access" toggle which is meaningless without an exit-node.
    private var hasExitNode: Bool {
        appState.tailscalePrefs?.hasExitNode ?? false
    }
    private var currentExitNodeIP: String {
        appState.tailscalePrefs?.exitNodeIP ?? ""
    }

    /// Display label for the picker — peer hostname if we can
    /// resolve it, IP otherwise, "None" if no exit node selected.
    private var currentExitNodeLabel: String {
        let allPeers = appState.tailscaleStatus?.peers ?? []
        if let active = appState.tailscalePrefs?.currentExitNode(in: allPeers) {
            return active.hostName
        }
        return "None"
    }
    /// Snapshot of the prefs' current advertiseRoutes serialized
    /// the same way the textbox renders, so we can detect "no
    /// changes" for disabling the Apply button.
    private var originalAdvertiseRoutesText: String {
        (appState.tailscalePrefs?.manualAdvertiseRoutes ?? [])
            .joined(separator: ", ")
    }

    // MARK: - Bindings

    /// Build a SwiftUI Binding<Bool> that reads from
    /// `tailscalePrefs.<keyPath>` and writes via the supplied CLI
    /// closure. Optimistic update happens inside
    /// `applyTailscalePref`, so the toggle snaps instantly.
    private func bindToggle(
        _ keyPath: WritableKeyPath<TailscalePrefs, Bool>,
        cli: @escaping (Bool) async throws -> Void
    ) -> Binding<Bool> {
        Binding(
            get: { appState.tailscalePrefs?[keyPath: keyPath] ?? false },
            set: { newValue in
                // Synchronous log so we KNOW the binding fired even
                // when the async work behind it errors silently.
                DebugLog.write("[ts/binding] toggle set newValue=\(newValue)")
                Task {
                    await appState.applyTailscalePref(
                        optimistic: { $0[keyPath: keyPath] = newValue },
                        cli: { try await cli(newValue) }
                    )
                }
            }
        )
    }

    /// Special-case binding for advertiseExitNode (computed
    /// property; can't use the generic keypath helper).
    /// `advertiseExitNode` is derived from `advertiseRoutes` so we
    /// don't optimistically mutate it — we just refresh after.
    /// Generic helper above only works for stored Bool keypaths.
    private var bindAdvertiseExitNode: Binding<Bool> {
        Binding(
            get: { appState.tailscalePrefs?.advertiseExitNode ?? false },
            set: { newValue in
                DebugLog.write("[ts/binding] advertiseExitNode set \(newValue)")
                Task {
                    await appState.applyTailscalePref(
                        optimistic: { _ in /* derived; no-op */ },
                        cli: { try await TailscaleClient.setAdvertiseExitNode(newValue) }
                    )
                }
            }
        )
    }

    private var bindAutoUpdate: Binding<Bool> {
        Binding(
            get: { appState.tailscalePrefs?.autoUpdate?.apply ?? false },
            set: { newValue in
                DebugLog.write("[ts/binding] autoUpdate set \(newValue)")
                Task {
                    await appState.applyTailscalePref(
                        optimistic: { p in
                            // Mutate nested AutoUpdate; create one
                            // if the daemon hadn't reported any.
                            if var au = p.autoUpdate {
                                au = .init(check: au.check, apply: newValue)
                                p.autoUpdate = au
                            }
                        },
                        cli: { try await TailscaleClient.setAutoUpdate(newValue) }
                    )
                }
            }
        )
    }

    // MARK: - Actions

    private func setExitNode(_ ipOrAuto: String) async {
        DebugLog.write("[ts/binding] setExitNode \(ipOrAuto)")
        // Route through the safety wrapper — applies the change,
        // probes internet, auto-reverts if connectivity is dead.
        // See AppState.setExitNodeWithSafety.
        await appState.setExitNodeWithSafety(ipOrAuto)
    }

    private func commitAdvertiseRoutes() async {
        let routes = advertiseRoutesText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        // Preserve the exit-node magic routes if currently set.
        // Otherwise toggling subnet routes would also accidentally
        // disable advertise-exit-node.
        var combined = routes
        if appState.tailscalePrefs?.advertiseExitNode == true {
            combined.append("0.0.0.0/0")
            combined.append("::/0")
        }
        await appState.applyTailscalePref(
            optimistic: { p in p.advertiseRoutes = combined },
            cli: { try await TailscaleClient.setAdvertiseRoutes(combined) }
        )
    }

    /// Push the user's edited DNS fallback list to the helper.
    /// The watchdog will use this list on its next escalation.
    private func commitDNSFallbacks() async {
        let servers = dnsFallbacksText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !servers.isEmpty else { return }
        do {
            _ = try await HelperClient.shared.tailscaleSetDNSFallbacks(servers: servers)
            originalDNSFallbacksText = servers.joined(separator: ", ")
            dnsFallbacksText = originalDNSFallbacksText
        } catch {
            // Surface inline via the existing footer error path.
            appState.tailscaleActionError = error.localizedDescription
        }
    }

    private func commitHostname() async {
        let trimmed = hostnameText.trimmingCharacters(in: .whitespaces)
        await appState.applyTailscalePref(
            optimistic: { p in p.hostname = trimmed },
            cli: { try await TailscaleClient.setHostname(trimmed) }
        )
    }

    // MARK: - Layout helper

    @ViewBuilder
    private func section<Content: View>(
        title: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title.uppercased())
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 8) {
                content()
            }
            .padding(12)
            .background(.quaternary.opacity(0.4),
                        in: RoundedRectangle(cornerRadius: 8))
        }
    }
}
