import SwiftUI

struct ContentView: View {
    @Environment(AppState.self) private var appState
    @State private var sshTab: SSHTab = .hosts
    /// The design's sun/moon toolbar toggle, persisted. "system" (default)
    /// follows macOS; "light"/"dark" override just this app. Stored as a
    /// string rather than ColorScheme because @AppStorage can't hold an
    /// optional enum and "follow the OS" needs to be representable.
    @AppStorage("appearanceOverride") private var appearanceOverride = "system"
    @State private var searchText = ""
    @State private var showingAddHost = false
    @State private var showingGenerateKey = false
    @State private var showingAddVpn = false
    @State private var showingImportVpn = false
    @State private var showingDisconnectAllConfirm = false
    /// Profile the operator asked to delete, awaiting confirmation.
    /// Deleting a VPN profile irreversibly wipes the tunnel and every
    /// stored credential, so we gate it behind an alert rather than
    /// firing on the bare context-menu click.
    @State private var vpnProfilePendingDelete: VpnProfileSummary?
    /// Drives the visual drop-zone overlay during a drag-and-drop
    /// VPN import. Bound to `.onDrop(isTargeted:)`.
    @State private var vpnImportTargeted = false
    /// Last drop-import error (e.g. "unknown extension" or daemon
    /// rejection). Surfaced as a transient alert so it doesn't
    /// linger after the user moves on.
    @State private var dropImportError: String?

    /// Bound to whichever Search TextField is currently visible
    /// (hosts, keys, or VPN profiles — only one exists in the view
    /// hierarchy at a time, depending on the selected sidebar
    /// section). Cmd-F flips this to true; the field's `.focused`
    /// modifier moves keyboard focus there.
    @FocusState private var searchFieldFocused: Bool

    /// About-sheet visibility. Triggered from the SuperManager →
    /// About SuperManager menu (overridden via CommandGroup) and
    /// observed via NotificationCenter so the menu can reach into
    /// the active window scene.
    @State private var showingAbout = false

    /// "Explain configuration" sheet visibility. Triggered from
    /// the Help → Explain Configuration… menu item (Cmd-Shift-E).
    @State private var showingExplain = false
    @State private var explainPrefillText: String = ""

    enum SSHTab: String, CaseIterable {
        case hosts = "Hosts"
        case keys = "Keys"
    }

    var body: some View {
        // NavigationSplitView gives us native macOS sidebar styling — items
        // pack at the top, the divider drag is correct, and the system
        // handles the empty-detail state without us showing two parallel
        // "select a thing" placeholders. The previous HSplitView produced
        // the half-finished look the user called out (sidebar items
        // clustered mid-column, dead vertical space everywhere).
        Group {
            if sectionHasListColumn {
                NavigationSplitView {
                    sidebarColumn
                } content: {
                    listColumn
                        // ideal == max on purpose. Switching to Fleet or Recon
                        // and back rebuilds this split view, and a fresh build
                        // settles the column at max while a rebuild settles it
                        // at ideal — so with the two apart (280/380) the list
                        // was 380pt wide if you came here directly and 280pt if
                        // you came via Fleet. Same section, same window, two
                        // widths. Equal values make every path agree; the 240
                        // floor keeps the divider draggable.
                        .navigationSplitViewColumnWidth(min: 240, ideal: 380, max: 380)
                } detail: {
                    detailColumn
                        // Title on the DETAIL column, not the split view. Set
                        // globally, macOS floats it after the toolbar items
                        // with no relationship to the column edges, and with a
                        // wide list column it straddled the divider hairline.
                        // Anchored here it starts where the detail pane does.
                        .navigationTitle("SuperManager")
                        .navigationSplitViewColumnWidth(min: 480, ideal: 720)
                }
            } else {
                // Two columns, because these sections have two things to show.
                // See `sectionHasListColumn` for why the third can't just be
                // left empty.
                NavigationSplitView {
                    sidebarColumn
                } detail: {
                    detailColumn
                        .navigationTitle("SuperManager")
                }
            }
        }
        // nil = follow macOS. The override applies to this window and every
        // sheet and popover presented from it.
        .preferredColorScheme(
            appearanceOverride == "light" ? .light
                : appearanceOverride == "dark" ? .dark
                : nil
        )
        // Drag-and-drop VPN config import from anywhere in the
        // window. Works for `.conf` (WireGuard) and `.ovpn`
        // (OpenVPN). Auto-routes by extension, prompts the
        // user for a friendly name based on the filename, and
        // selects the new profile on success so it's immediately
        // visible. No drop target overlay — drop anywhere in
        // the window's content area.
        .onDrop(of: [.fileURL], isTargeted: $vpnImportTargeted) { providers in
            handleDroppedFiles(providers)
        }
        .overlay {
            if vpnImportTargeted {
                ZStack {
                    Color.accentColor.opacity(0.15)
                        .allowsHitTesting(false)
                    VStack(spacing: 12) {
                        Image(systemName: "arrow.down.doc.fill")
                            .font(.system(size: 64))
                            .foregroundStyle(.tint)
                        Text("Drop a .conf, .ovpn, or .azurevpnconfig to import")
                            .font(.headline)
                            .foregroundStyle(.secondary)
                    }
                    .padding(40)
                    .background(.ultraThickMaterial,
                                in: RoundedRectangle(cornerRadius: 18))
                }
                .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.15), value: vpnImportTargeted)
        .toolbar {
            // One pill per system (Tailscale, VPN), leading so they sit next to
            // the sidebar rather than lost in the trailing soup of actions.
            // Each is clickable for a popover with the detail + the one action
            // you'd otherwise switch tabs for.
            ToolbarItem(placement: .navigation) {
                ToolbarStatusPills()
            }
            // Global customer-context picker — sits next to the
            // connection pill so the operator always sees which
            // customer they're acting on. Hidden on Tailscale: the
            // tailnet is a per-account concept with no customer
            // scope, so showing the picker there is misleading.
            ToolbarItem(placement: .navigation) {
                if appState.selectedSection != .tailscale {
                    GlobalCustomerPicker()
                }
            }
            // Flexible space. The toolbar title used to be what separated the
            // leading group from the trailing one; with it hidden (it floated
            // across the column divider), macOS packs every item leading. A
            // Spacer as a toolbar item maps to NSToolbar's flexible space and
            // restores the split: pills and picker left, actions right.
            ToolbarItem(placement: .primaryAction) {
                Spacer()
            }
            // The design's appearance toggle: system → dark → light → system.
            // Cycling three states rather than flipping two because "follow
            // macOS" is the right default and must stay reachable — a
            // two-state flip would trap the app in an override forever.
            ToolbarItem(placement: .primaryAction) {
                Button {
                    switch appearanceOverride {
                    case "system": appearanceOverride = "dark"
                    case "dark":   appearanceOverride = "light"
                    default:       appearanceOverride = "system"
                    }
                } label: {
                    Image(systemName: appearanceOverride == "dark" ? "moon.fill"
                            : appearanceOverride == "light" ? "sun.max.fill"
                            : "circle.lefthalf.filled")
                }
                .help(appearanceOverride == "system"
                        ? "Appearance: following macOS. Click for dark."
                        : appearanceOverride == "dark"
                        ? "Appearance: dark. Click for light."
                        : "Appearance: light. Click to follow macOS.")
                .accessibilityLabel("Appearance")
            }
            // ONE "+", every section, same place, same meaning: make a new one
            // of whatever you're looking at. Click adds the obvious thing;
            // hold for the alternatives.
            //
            // This spot used to carry TWO plus buttons side by side — a global
            // "Add device" menu (plus.circle.fill) and a section "+" (plus) —
            // and in SSH they were the same action twice: the menu's first item
            // and the button both opened Add Host. Meanwhile Provisioning and
            // Security kept their create button in a footer, so the top-right
            // "+" was present but wrong there: it added a *device*, never a
            // customer or an engagement.
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    sectionAddMenuItems
                } label: {
                    Image(systemName: "plus")
                } primaryAction: {
                    sectionPrimaryAdd()
                }
                .menuStyle(.borderlessButton)
                .help(sectionAddLabel)
                .accessibilityLabel(sectionAddLabel)
                .keyboardShortcut("n", modifiers: .command)
            }
            // "Disconnect all" — only renders when at least one
            // profile is currently flagged as up. Confirmation
            // alert because this is a fleet-level action; one
            // accidental click shouldn't take down a working
            // tunnel.
            ToolbarItem(placement: .primaryAction) {
                if appState.selectedSection == .vpn && anyVpnConnected {
                    Button {
                        showingDisconnectAllConfirm = true
                    } label: {
                        Label("Disconnect All", systemImage: "bolt.slash")
                    }
                    .foregroundStyle(.red)
                    .help("Force disconnect every active VPN tunnel.")
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button(action: { Task { await appState.refreshAll() } }) {
                    if appState.isRefreshing {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .disabled(appState.isRefreshing)
                .help(appState.isRefreshing ? "Refreshing…" : "Refresh from daemon")
                .accessibilityLabel("Refresh from daemon")
            }
        }
        // Hidden Cmd-F handler. The button itself never renders
        // (frame: 0 + hidden), but SwiftUI still routes the
        // shortcut to it. Setting `searchFieldFocused = true`
        // moves keyboard focus to whichever Search TextField
        // is visible in the active section (only one exists at a
        // time, so there's no ambiguity).
        .background(
            Button("Focus search") {
                searchFieldFocused = true
            }
            .keyboardShortcut("f", modifiers: .command)
            .frame(width: 0, height: 0)
            .hidden()
        )
        .sheet(isPresented: $showingAddHost) { AddHostSheet() }
        .sheet(isPresented: $showingGenerateKey) { GenerateKeySheet() }
        .sheet(isPresented: $showingAddVpn) { AddVpnProfileSheet() }
        .sheet(isPresented: $showingImportVpn) { ImportVpnSheet() }
        .sheet(isPresented: $showingAbout) { AboutSheet() }
        .sheet(isPresented: $showingExplain) {
            ExplainConfigSheet(initialConfig: explainPrefillText)
        }
        // Web-capture sheet — driven by `pendingWebCapture` so
        // both the `supermgr://` URL-scheme handler (in
        // SuperManagerApp's `.onOpenURL`) and the Help → Capture
        // from Web… menu item can trigger presentation. Sheet
        // clears the binding on dismiss so the next URL/menu
        // click presents a fresh sheet.
        .sheet(
            item: Binding(
                get: { appState.pendingWebCapture },
                set: { appState.pendingWebCapture = $0 }
            )
        ) { capture in
            // Only forward a non-empty capture as the initial
            // value — for the "menu-triggered, paste-mode" case
            // the sheet attempts the clipboard on its own.
            let prefill: WebCapture? = capture.hostname.isEmpty ? nil : capture
            WebCaptureSheet(initialCapture: prefill)
                .environment(appState)
        }
        // The custom About menu item posts this notification —
        // ContentView is the canonical "first window" we present
        // sheets from, so it owns the visibility state.
        .onReceive(NotificationCenter.default.publisher(for: .superManagerShowAbout)) { _ in
            showingAbout = true
        }
        .onReceive(NotificationCenter.default.publisher(for: .superManagerOpenAddHost)) { _ in
            // Recon's "Type details" quick-add button posts this
            // after switching to the SSH section, so the form
            // opens as a top-of-stack sheet ready for input.
            sshTab = .hosts
            showingAddHost = true
        }
        .onReceive(NotificationCenter.default.publisher(for: .superManagerShowExplain)) { _ in
            explainPrefillText = ""
            showingExplain = true
        }
        .alert("Couldn't import VPN file", isPresented: Binding(
            get: { dropImportError != nil },
            set: { if !$0 { dropImportError = nil } }
        )) {
            Button("OK") { dropImportError = nil }
        } message: {
            Text(dropImportError ?? "")
        }
        .alert("Disconnect every VPN?",
               isPresented: $showingDisconnectAllConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Disconnect All", role: .destructive) {
                Task { await appState.disconnectAllVpns() }
            }
        } message: {
            Text("This tears down every active VPN tunnel — IKEv2, WireGuard, and OpenVPN. Reconnect manually afterwards.")
        }
        .alert(
            "Delete this VPN profile?",
            isPresented: Binding(
                get: { vpnProfilePendingDelete != nil },
                set: { if !$0 { vpnProfilePendingDelete = nil } }
            ),
            presenting: vpnProfilePendingDelete
        ) { profile in
            Button("Cancel", role: .cancel) { vpnProfilePendingDelete = nil }
            Button("Delete", role: .destructive) {
                Task { await appState.deleteVpnProfile(profile.id, profileName: profile.name) }
                vpnProfilePendingDelete = nil
            }
        } message: { profile in
            Text("This permanently removes \"\(profile.name)\" and every stored credential for it. This cannot be undone.")
        }
        // Lock-state branching is handled at the root in `RootView` —
        // ContentView is only built when the app is unlocked, so we
        // don't need to think about the lock state in here.
    }

    // MARK: - Section add menu

    /// What a plain click on "+" (and Cmd-N) creates. Every section has one
    /// obvious answer — the menu carries the rest.
    private func sectionPrimaryAdd() {
        switch appState.selectedSection {
        case .ssh where sshTab == .keys: showingGenerateKey = true
        case .vpn:                       showingAddVpn = true
        case .provisioning:              appState.showingAddCustomer = true
        case .security:                  appState.showingAddEngagement = true
        default:                         showingAddHost = true
        }
    }

    /// Names the primary action, so the tooltip and the VoiceOver label say
    /// what the click will actually do rather than a generic "Add".
    private var sectionAddLabel: String {
        switch appState.selectedSection {
        case .ssh where sshTab == .keys: return "Generate SSH key"
        case .vpn:                       return "Add VPN profile"
        case .provisioning:              return "Add customer"
        case .security:                  return "New engagement"
        default:                         return "Add host"
        }
    }

    @ViewBuilder
    private var sectionAddMenuItems: some View {
        switch appState.selectedSection {
        case .ssh where sshTab == .keys:
            Button("Generate SSH key…") { showingGenerateKey = true }
            Divider()
            addDeviceMenu
        case .vpn:
            Button("New IKEv2 profile…") { showingAddVpn = true }
            Button("Import from file…") { showingImportVpn = true }
            Divider()
            addDeviceMenu
        case .provisioning:
            Button("Add customer…") { appState.showingAddCustomer = true }
            Divider()
            addDeviceMenu
        case .security:
            Button("New engagement…") { appState.showingAddEngagement = true }
            Divider()
            addDeviceMenu
        default:
            // Fleet, SSH hosts, Compliance, Recon, Tailscale: the thing this
            // section creates IS a device, so the paths sit at the top level
            // rather than a level down under their own name.
            addDeviceItems
        }
    }

    /// Nested under its own name in sections that create something other than
    /// a device, so capture-a-device stays reachable from everywhere. That
    /// reach was the whole point of the old global menu and it survives here.
    private var addDeviceMenu: some View {
        Menu {
            addDeviceItems
        } label: {
            Label("Add device", systemImage: "desktopcomputer")
        }
    }

    /// The three ways a device gets into the app, plus the bookmarklet feeding
    /// the second one.
    @ViewBuilder
    private var addDeviceItems: some View {
        Button {
            showingAddHost = true
        } label: {
            Label("Type details manually…", systemImage: "keyboard")
        }
        .help("Open the standard 'Add SSH Host' form.")

        Button {
            appState.pendingWebCapture = WebCapture(
                hostname: "",
                label: "",
                deviceType: .linux,
                username: "root"
            )
        } label: {
            Label(
                "Paste from web or clipboard…",
                systemImage: "globe.americas.fill"
            )
        }
        .help(
            "Opens the Web Capture sheet. Auto-pulls "
            + "from clipboard, parses IPs / URLs / banners, "
            + "and lets you add as SSH host, append to "
            + "engagement scope, or kick off a network scan."
        )

        Button {
            appState.selectedSection = .recon
        } label: {
            Label("Scan network for devices…", systemImage: "network")
        }
        .help(
            "Opens the Recon section. The Network Scan tile "
            + "discovers hosts + open ports in a CIDR range."
        )

        Divider()

        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(
                SuperManagerApp.webCaptureBookmarklet,
                forType: .string
            )
        } label: {
            Label("Copy browser bookmarklet", systemImage: "bookmark.fill")
        }
        .help(
            "Copies a JavaScript bookmarklet to the clipboard. "
            + "Paste it as the URL of a new bookmark in your "
            + "browser; clicking that bookmark on any vendor "
            + "admin page captures the device in one click."
        )
    }

    // MARK: - Column 1: Section Sidebar

    /// Shared by both split-view shapes so the sidebar keeps the same width
    /// when the section switches between them.
    private var sidebarColumn: some View {
        sectionSidebar
            .navigationSplitViewColumnWidth(min: 140, ideal: 170, max: 220)
    }

    private var sectionSidebar: some View {
        // Bind List(selection:) directly to AppState. SwiftUI then handles
        // selection highlighting, keyboard nav, and uses macOS's native
        // sidebar item style — which packs items at the top of the
        // column instead of leaving them stranded mid-pane like the old
        // hand-rolled Button-in-List version did.
        @Bindable var appState = appState
        return List(selection: $appState.selectedSection) {
            Section("Manage") {
                ForEach(AppSection.allCases) { section in
                    Label(section.rawValue, systemImage: section.icon)
                        .tag(section)
                }
            }
        }
        .listStyle(.sidebar)
    }

    // MARK: - Column 2: List

    /// Fleet and Recon are single full-width surfaces — a dashboard and a tool
    /// launcher. Neither has anything to navigate, so neither gets a middle
    /// column, and the split view is built with two columns instead of three.
    ///
    /// Both previously returned `EmptyView()` from `listColumn`, which does not
    /// remove the column — NavigationSplitView reserves it regardless of what
    /// renders into it, so each showed a band of blank white between the
    /// sidebar and its content. Measured at 720pt on an 1800pt window: wider
    /// than the sidebar and the blank column's own declared 380pt maximum,
    /// because with nothing to size to it just takes a share of the slack.
    /// Pinning the width to zero doesn't help either — the constraint is
    /// ignored, which is how it got to 720 in the first place.
    private var sectionHasListColumn: Bool {
        switch appState.selectedSection {
        case .fleet, .recon: return false
        default:             return true
        }
    }

    @ViewBuilder
    private var listColumn: some View {
        switch appState.selectedSection {
        case .fleet:
            EmptyView()
        case .ssh:
            sshListColumn
        case .vpn:
            vpnListColumn
        case .tailscale:
            TailscaleListView()
        case .compliance:
            ComplianceListColumn()
        case .provisioning:
            ProvisioningListColumn()
        case .security:
            SecurityListColumn()
        case .recon:
            EmptyView()
        }
    }

    // MARK: - Column 3: Detail

    /// True iff the user has nothing configured anywhere — drives
    /// the first-run welcome screen. Once they import a profile,
    /// add a host, or install Tailscale, the detail column reverts
    /// to its normal section-specific empty state.
    private var isFirstRun: Bool {
        appState.sshHosts.isEmpty
            && appState.vpnProfiles.isEmpty
            && (appState.tailscaledInstalled != true)
    }

    @ViewBuilder
    private var detailColumn: some View {
        // Show welcome screen on first launch. Otherwise fall
        // through to the per-section detail/empty view.
        if isFirstRun {
            WelcomeView(showingAddHost: $showingAddHost,
                        showingImportVpn: $showingImportVpn)
        } else {
            sectionDetail
        }
    }

    @ViewBuilder
    private var sectionDetail: some View {
        switch appState.selectedSection {
        case .fleet:
            FleetView()
        case .ssh:
            if let hostId = appState.selectedHostId, sshTab == .hosts {
                HostDetailView(hostId: hostId)
            } else if let keyId = appState.selectedKeyId, sshTab == .keys {
                KeyDetailView(keyId: keyId)
            } else if sshTab == .keys {
                // Distinct copy per tab: the old shared "Select a host or key"
                // described the UI rather than the job, and said the same thing
                // whichever tab you were on.
                EmptyStateView(
                    systemImage: "key",
                    title: "Select a key",
                    hint: "Manage the SSH keys used across the fleet and see which hosts trust each one."
                )
            } else {
                EmptyStateView(
                    systemImage: "terminal",
                    title: "Select a host",
                    hint: "Pick a host to open a session, review its details, or run a compliance scan."
                )
            }
        case .vpn:
            if let profileId = appState.selectedProfileId {
                VpnDetailView(profileId: profileId)
            } else {
                EmptyStateView(
                    systemImage: "lock.shield",
                    title: "Select a VPN profile",
                    hint: "Pick a tunnel from the list to view its status, routing and credentials."
                )
            }
        case .tailscale:
            // Detail view needs both the peer and the magic suffix
            // for fully-qualified DNS rendering; pull both from
            // AppState's last `tailscaleStatus` snapshot.
            if let status = appState.tailscaleStatus,
               let peerId = appState.selectedTailscalePeerId,
               let peer = (status.peers + [status.selfNode]).first(where: { $0.id == peerId }) {
                TailscaleDetailView(peer: peer,
                                    magicSuffix: status.magicDNSSuffix ?? "")
            } else {
                EmptyStateView(
                    systemImage: "globe",
                    title: "Select a Tailnet peer",
                    hint: "Choose a machine on the tailnet to see its address, route it, or open a session."
                )
            }
        case .compliance:
            // Gate on the SAME allowlist the list column uses
            // (`complianceDispatch != .notApplicable`), not on
            // `deviceType == .fortigate`. The list deliberately includes
            // Linux hosts and tells operators to add them; pinning the
            // detail gate to FortiGate dead-ended every Linux row on
            // "Select a FortiGate host" and made the whole Linux CIS scan
            // path unreachable. ComplianceHostView already branches on
            // complianceDispatch, so it renders Linux hosts correctly.
            if let hostId = appState.selectedHostId,
               appState.sshHosts.contains(where: {
                   $0.id == hostId && $0.deviceType.complianceDispatch != .notApplicable
               }) {
                ComplianceHostView(hostId: hostId)
            } else {
                // The old single line tried to carry both the instruction and
                // the caveat ("compliance-capable") and did neither well. The
                // hint now explains WHY a host might not be listed, which is
                // the actual question when your host isn't there.
                EmptyStateView(
                    systemImage: "checkmark.shield",
                    title: "Select a host to scan",
                    hint: "Pick a host from the list to run a CIS baseline and review its findings. Only FortiGate and Linux hosts can be scanned."
                )
            }
        case .provisioning:
            ProvisioningView()
        case .security:
            SecurityView()
        case .recon:
            ReconView()
        }
    }

    // MARK: - SSH List Column

    private var sshListColumn: some View {
        VStack(spacing: 0) {
            Picker("", selection: $sshTab) {
                ForEach(SSHTab.allCases, id: \.self) { tab in
                    Text(tab.rawValue).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .padding(8)

            TextField("Search...", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .focused($searchFieldFocused)
                .padding(.horizontal, 8)
                .padding(.bottom, 8)

            switch sshTab {
            case .hosts:
                hostList
            case .keys:
                keyList
            }
        }
    }

    // MARK: - VPN List Column

    /// VPN profiles filtered by the global search text. Same
    /// matching strategy as SSH hosts: case-insensitive substring
    /// across name, backend, and host.
    private var filteredVpnProfiles: [VpnProfileSummary] {
        // Pinned profiles always come first (matches SSH host
        // behaviour). Within each pin-group, alphabetical by
        // display name so the order is stable and discoverable.
        let pinned = appState.pinnedVpnIds
        let sorted = appState.vpnProfiles.sorted { a, b in
            let aPin = pinned.contains(a.id)
            let bPin = pinned.contains(b.id)
            if aPin != bPin { return aPin }
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
        if searchText.isEmpty { return sorted }
        return sorted.filter { p in
            p.name.localizedCaseInsensitiveContains(searchText) ||
            p.backend.localizedCaseInsensitiveContains(searchText) ||
            (p.host ?? "").localizedCaseInsensitiveContains(searchText)
        }
    }

    private var vpnListColumn: some View {
        VStack(spacing: 0) {
            // Search field — same control as SSH so muscle memory
            // works regardless of section. Filters by name,
            // backend, or host.
            TextField("Search VPN profiles...", text: $searchText)
                .textFieldStyle(.roundedBorder)
                .focused($searchFieldFocused)
                .padding(8)

            if appState.vpnProfiles.isEmpty {
                ContentUnavailableView {
                    Label("No VPN Profiles", systemImage: "lock.shield")
                } description: {
                    Text("Drag a `.conf` (WireGuard), `.ovpn` (OpenVPN), or `.azurevpnconfig` (Azure) file anywhere in this window, or use the + menu in the toolbar.")
                } actions: {
                    HStack(spacing: 12) {
                        Button {
                            showingImportVpn = true
                        } label: {
                            Label("Import file…", systemImage: "arrow.down.doc")
                        }
                        .controlSize(.large)
                        .buttonStyle(.borderedProminent)
                        Button {
                            showingAddVpn = true
                        } label: {
                            Label("New IKEv2…", systemImage: "lock.shield")
                        }
                        .controlSize(.large)
                    }
                }
            } else {
                vpnProfileList
            }
        }
    }

    /// VPN profile list. Sectioned when the user has 2+
    /// different backends (so a Wireguard-only user gets a flat
    /// list — sections would be visual noise). Pinned profiles
    /// always come first in their own "Pinned" section,
    /// regardless of backend, mirroring the SSH-host pattern.
    @ViewBuilder
    private var vpnProfileList: some View {
        let pinned = filteredVpnProfiles.filter { appState.pinnedVpnIds.contains($0.id) }
        let unpinned = filteredVpnProfiles.filter { !appState.pinnedVpnIds.contains($0.id) }
        let backendGroups = Dictionary(grouping: unpinned) { backendDisplayGroup($0.backend) }
        let backendOrder = backendGroups.keys.sorted()
        let shouldGroup = backendGroups.count >= 2

        List {
            if !pinned.isEmpty {
                Section("Pinned") {
                    ForEach(pinned) { vpnProfileRow($0) }
                }
            }
            if shouldGroup {
                ForEach(backendOrder, id: \.self) { group in
                    let profiles = backendGroups[group] ?? []
                    // Count badge in the section header — operator
                    // can see at a glance how many of each backend
                    // they have without reading the rows.
                    Section {
                        ForEach(profiles) { vpnProfileRow($0) }
                    } header: {
                        HStack {
                            Text(group)
                            Spacer()
                            Text("\(profiles.count)")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
            } else {
                // Single backend (or empty) — flat list, no
                // pointless one-section header.
                ForEach(unpinned) { vpnProfileRow($0) }
            }
        }
        .listStyle(.sidebar)
    }

    /// Map the daemon's verbose backend name ("FortiGate
    /// (IPsec/IKEv2)", "OpenVPN3") onto a short header bucket
    /// ("IKEv2", "OpenVPN", "WireGuard"). Substring-matched so
    /// we're robust to label tweaks on the daemon side.
    private func backendDisplayGroup(_ backend: String) -> String {
        let b = backend.lowercased()
        if b.contains("wireguard") || b.contains("wire_guard") { return "WireGuard" }
        if b.contains("openvpn") || b.contains("open_vpn") { return "OpenVPN" }
        if b.contains("forti") || b.contains("ikev2") || b.contains("ipsec") { return "IKEv2" }
        if b.contains("azure") { return "Azure" }
        return "Other"
    }

    /// Per-backend pill colour so the operator sees at a glance
    /// which protocol a row represents. Same buckets as
    /// `backendDisplayGroup`. Picked to be distinguishable
    /// from the connection-dot palette (green/yellow/red) so
    /// the row's "is it connected?" signal and "what kind?"
    /// signal don't visually compete.
    private func backendBadgeColor(_ backend: String) -> Color {
        switch backendDisplayGroup(backend) {
        case "IKEv2":     return .blue
        case "OpenVPN":   return .purple
        case "WireGuard": return .teal
        case "Azure":     return .indigo
        default:          return .gray
        }
    }

    /// Render the inline backend pill shown next to a profile's
    /// name in the sidebar list. Replaces the previous plain
    /// caption — same information, more glanceable.
    private func backendBadge(_ backend: String) -> some View {
        let label = backendDisplayGroup(backend)
        let color = backendBadgeColor(backend)
        return Text(label)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
            .help("VPN backend: \(backend)")
    }

    /// One row in the VPN sidebar list. Extracted from
    /// `vpnProfileList` so the SwiftUI type-checker doesn't
    /// time out on the deeply-nested HStacks + modifiers.
    @ViewBuilder
    private func vpnProfileRow(_ profile: VpnProfileSummary) -> some View {
        Button(action: { appState.selectedProfileId = profile.id }) {
            HStack(spacing: 8) {
                Circle()
                    .fill(vpnDotColor(for: profile.id))
                    .frame(width: 8, height: 8)
                if appState.pinnedVpnIds.contains(profile.id) {
                    Image(systemName: "pin.fill")
                        .foregroundStyle(.orange)
                        .font(.caption2)
                }
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 4) {
                        Text(profile.name)
                            .fontWeight(appState.pinnedVpnIds.contains(profile.id) ? .semibold : .medium)
                        backendBadge(profile.backend)
                        if appState.autoReconnectEnabled.contains(profile.id) {
                            Image(systemName: "arrow.clockwise.circle.fill")
                                .font(.caption2)
                                .foregroundStyle(.blue)
                                .help("Always-on: helper auto-reconnects every 30s")
                        }
                    }
                    if let host = profile.host {
                        Text(host).font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.vertical, 2)
        .background(
            RoundedRectangle(cornerRadius: 4)
                .fill(appState.selectedProfileId == profile.id ? Color.accentColor.opacity(0.15) : Color.clear)
        )
        .contextMenu {
            Button(appState.pinnedVpnIds.contains(profile.id) ? "Unpin" : "Pin") {
                appState.toggleVpnPin(profile.id)
            }
            Button("Duplicate") {
                Task { await appState.duplicateVpnProfile(profileId: profile.id) }
            }
            Divider()
            Button("Force Disconnect") {
                Task { await appState.forceDisconnect(profileId: profile.id) }
            }
            Divider()
            Button("Delete", role: .destructive) {
                vpnProfilePendingDelete = profile
            }
        }
    }

    /// True iff at least one VPN profile is currently flagged as
    /// "connected" or "connecting" by the global poller. Drives
    /// whether the "Disconnect All" toolbar action is even visible
    /// — there's no point in showing the nuke when nothing is up.
    private var anyVpnConnected: Bool {
        appState.vpnConnectionStates.values.contains { state in
            state == "connected" || state == "connecting"
        }
    }

    /// Map a profile's polled connection state to a sidebar-dot
    /// colour. Mirrors the dot palette in `VpnDetailView`:
    /// connected = green, connecting = orange, anything else =
    /// muted gray. Unknown id (not yet polled) is gray-30%, just
    /// distinct enough to read as "we don't know yet."
    /// Handle dropped file URLs for VPN import. Picks the right
    /// importer based on file extension, derives a friendly
    /// profile name from the filename, and selects the new
    /// profile on success. Returns true if at least one provider
    /// was claimed (drop accepted).
    private func handleDroppedFiles(_ providers: [NSItemProvider]) -> Bool {
        var claimed = false
        for provider in providers {
            guard provider.hasItemConformingToTypeIdentifier("public.file-url") else { continue }
            claimed = true
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in
                    await importDroppedFile(at: url)
                }
            }
        }
        return claimed
    }

    @MainActor
    private func importDroppedFile(at url: URL) async {
        let ext = url.pathExtension.lowercased()
        let baseName = url.deletingPathExtension().lastPathComponent
        // Default profile name = filename without extension. User
        // can rename later in the detail view.
        let name = baseName.isEmpty ? "Imported VPN" : baseName

        let content: String
        do {
            content = try String(contentsOf: url, encoding: .utf8)
        } catch {
            dropImportError = "Couldn't read \(url.lastPathComponent): \(error.localizedDescription)"
            return
        }

        let newId: String?
        switch ext {
        case "conf":
            newId = await appState.importWireguard(name: name, content: content)
        case "ovpn":
            newId = await appState.importOpenVPN(name: name, content: content)
        case "azurevpnconfig", "xml":
            // Azure VPN Client config — XML downloaded from the
            // Azure portal's "Download VPN client" button.
            newId = await appState.importAzureVPN(name: name, content: content)
        default:
            dropImportError = "Unsupported file type ‘.\(ext)’ — drop a .conf (WireGuard), .ovpn (OpenVPN), or .azurevpnconfig (Azure)."
            return
        }
        if let id = newId {
            // Switch the user to the VPN tab and select the new
            // profile so the import is immediately visible.
            appState.selectedSection = .vpn
            appState.selectedProfileId = id
        } else {
            // appState.importWireguard / importOpenVPN already
            // surface their own errors via the global error
            // alert; nothing more to do here.
        }
    }


    /// Right-click "Open in Terminal" on a sidebar SSH host.
    /// Re-uses the same `ssh://` URL handler that the host
    /// detail view's Connect button does — Terminal.app is
    /// registered for it out of the box.
    private func openInTerminal(host: SshHostSummary) {
        var comps = URLComponents(string: "ssh://")
        comps?.user = host.username
        comps?.host = host.hostname
        if host.port != 22 { comps?.port = Int(host.port) }
        if let url = comps?.url {
            NSWorkspace.shared.open(url)
        }
    }

    /// Right-click → copy a fully-formed `ssh user@host -p N`
    /// command to the clipboard.
    private func copySSHCommand(host: SshHostSummary) {
        let cmd = "ssh \(host.username)@\(host.hostname) -p \(host.port)"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(cmd, forType: .string)
    }

    private func vpnDotColor(for profileId: String) -> Color {
        switch appState.vpnConnectionStates[profileId] {
        case "connected":  return .green
        case "connecting": return .orange
        case "disconnected": return .gray.opacity(0.4)
        default:           return .gray.opacity(0.25)
        }
    }

    // MARK: - Host List

    private var filteredHosts: [SshHostSummary] {
        let global = appState.globalCustomerSlug
        let hosts = appState.sshHosts
            // Resolve customer membership through the HostIndex, not a raw
            // `group == slug` match, so a host linked to its customer only by
            // IP in Site.hostIds (or carrying group:"Discovered") still shows
            // when that customer is selected.
            .filter { global.isEmpty || appState.hostIndex.customerSlug(forHost: $0) == global }
            .sorted { a, b in
                if a.pinned != b.pinned { return a.pinned }
                if a.group != b.group { return a.group < b.group }
                return a.label < b.label
            }
        if searchText.isEmpty { return hosts }
        return hosts.filter {
            $0.label.localizedCaseInsensitiveContains(searchText) ||
            $0.hostname.localizedCaseInsensitiveContains(searchText) ||
            $0.group.localizedCaseInsensitiveContains(searchText)
        }
    }

    @ViewBuilder
    private var hostList: some View {
        if filteredHosts.isEmpty {
            // Predicate is `filteredHosts`, not the unfiltered
            // `sshHosts` — otherwise a customer with zero hosts
            // shows the empty list silently while another customer
            // has hosts (the global pool is non-empty so the
            // empty-state branch never fires).
            let isSearching = !searchText.isEmpty
            let customerSlug = appState.globalCustomerSlug
            ContentUnavailableView {
                Label(
                    isSearching ? "No matches"
                        : !customerSlug.isEmpty ? "No hosts for this customer"
                        : "No SSH hosts",
                    systemImage: isSearching ? "magnifyingglass" : "terminal"
                )
            } description: {
                Text(isSearching
                     ? "No SSH host matches “\(searchText)”."
                     : "Add a host to keep its credentials, run remote commands, and push SSH keys from the keys tab.")
            } actions: {
                if isSearching {
                    Button("Clear search") { searchText = "" }
                        .buttonStyle(.bordered)
                } else {
                    Button {
                        showingAddHost = true
                    } label: {
                        Label("Add host…", systemImage: "plus")
                    }
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
                }
            }
        } else {
            hostListContent
        }
    }

    /// Which section a host files under, by precedence: the customer the
    /// HostIndex resolver links it to (the spec's grouping), else the manual
    /// group field, else "Ungrouped". Customer wins because it's the grouping
    /// the rest of the app thinks in — the same resolver drives the global
    /// customer filter — and falls through gracefully for lab hosts nobody
    /// has linked.
    private func hostSectionTitle(for host: SshHostSummary) -> String {
        if let slug = appState.hostIndex.customerSlug(forHost: host),
           !slug.isEmpty,
           let customer = appState.customers.first(where: { $0.slug == slug }) {
            return customer.displayName
        }
        return host.group.isEmpty ? "Ungrouped" : host.group
    }

    private var hostListContent: some View {
        List {
            let grouped = Dictionary(grouping: filteredHosts) { hostSectionTitle(for: $0) }
            // Alphabetical, except Ungrouped sinks to the bottom — named
            // groups are the signal, the catch-all is the noise.
            let sortedGroups = grouped.keys.sorted {
                if $0 == "Ungrouped" { return false }
                if $1 == "Ungrouped" { return true }
                return $0 < $1
            }

            ForEach(sortedGroups, id: \.self) { group in
                Section(group) {
                    ForEach(grouped[group] ?? []) { host in
                        Button(action: { appState.selectedHostId = host.id }) {
                            HStack {
                                if host.pinned {
                                    Image(systemName: "pin.fill")
                                        .foregroundStyle(.orange)
                                        .font(.caption2)
                                }
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack(spacing: 5) {
                                        Text(host.label)
                                            .fontWeight(host.pinned ? .semibold : .regular)
                                        // The density fix: two rows that both
                                        // read ubnt@192.168.2.x now differ at
                                        // a glance by what the box IS.
                                        Badge(text: host.deviceType.displayName)
                                    }
                                    Text("\(host.username)@\(host.hostname)")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                // The shared vocabulary: unmeasured is blue
                                // unknown (same as "Never scanned"), not a
                                // gray that claims a reading of down.
                                StatusDot(status: hostHealthStatus(for: host.id))
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .padding(.vertical, 2)
                        .background(
                            RoundedRectangle(cornerRadius: 4)
                                .fill(appState.selectedHostId == host.id ? Color.accentColor.opacity(0.15) : Color.clear)
                        )
                        .contextMenu {
                            Button("Open in Terminal") {
                                openInTerminal(host: host)
                            }
                            Button("Copy SSH command") {
                                copySSHCommand(host: host)
                            }
                            Divider()
                            Button(host.pinned ? "Unpin" : "Pin") {
                                Task { await appState.togglePin(host.id) }
                            }
                            Divider()
                            Button("Delete", role: .destructive) {
                                Task { await appState.deleteHost(host.id) }
                            }
                        }
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    private func hostHealthStatus(for hostId: String) -> StatusStyle {
        guard let healthy = appState.hostHealth[hostId] else { return .unknown }
        return healthy ? .online : .error
    }

    // MARK: - Key List

    private var filteredKeys: [SshKeySummary] {
        if searchText.isEmpty { return appState.sshKeys }
        return appState.sshKeys.filter {
            $0.name.localizedCaseInsensitiveContains(searchText) ||
            $0.fingerprint.localizedCaseInsensitiveContains(searchText)
        }
    }

    private var keyList: some View {
        List {
            ForEach(filteredKeys) { key in
                Button(action: { appState.selectedKeyId = key.id }) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text(key.name)
                            Spacer()
                            Text(key.keyType.displayName)
                                .font(.caption)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(.quaternary)
                                .clipShape(Capsule())
                        }
                        Text(key.fingerprint)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        if key.deployedCount > 0 {
                            Text("Deployed to \(key.deployedCount) host\(key.deployedCount == 1 ? "" : "s")")
                                .font(.caption2)
                                .foregroundStyle(.blue)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.vertical, 2)
                .background(
                    RoundedRectangle(cornerRadius: 4)
                        .fill(appState.selectedKeyId == key.id ? Color.accentColor.opacity(0.15) : Color.clear)
                )
                .contextMenu {
                    Button("Delete", role: .destructive) {
                        Task { await appState.deleteKey(key.id) }
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }
}
