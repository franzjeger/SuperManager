import SwiftUI

/// Full network scan — host discovery + port sweep + service
/// banner-grab + TLS audit + CVE matching, against a CIDR range.
/// Same engine RPC as the engagement-panel "Active scan" button,
/// but runs DIRECTLY from Recon with its own progress UI.
///
/// Targets default to the selected engagement's `scope_cidrs`,
/// but the user can override (engagement-less scans are fine —
/// findings get persisted to the engagement if one is selected,
/// otherwise they're returned in-memory only).
struct NetworkScanSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    let engagementId: String?
    let initialTargets: String

    @State private var targetsText: String
    @State private var isRunning: Bool = false
    @State private var result: ActiveScanResult?
    @State private var errorMessage: String?
    @State private var scanTask: Task<Void, Never>?
    @State private var operationsPollTask: Task<Void, Never>?
    @State private var startedAt: Date?
    /// Drives whichever per-host follow-up sheet the operator
    /// triggered from a row's "..." menu. Each case carries the
    /// host so the sheet can pre-fill against it without lookup.
    @State private var pendingHostAction: HostAction?
    /// Set of IPs whose row is currently expanded to show the
    /// full Advanced-IP-Scanner-style detail panel (MAC,
    /// vendor, per-port banners, SMB/SNMP detail, etc.).
    @State private var expandedIps: Set<String> = []

    /// One-click follow-up actions exposed inline in the scan
    /// results. Each scan row gets a menu populated with these,
    /// vendor-gated where appropriate.
    enum HostAction: Identifiable {
        case addSsh(ActiveHost)
        case adoptUnifi(ActiveHost)
        var id: String {
            switch self {
            case .addSsh(let h): return "ssh-\(h.ip)"
            case .adoptUnifi(let h): return "unifi-\(h.ip)"
            }
        }
    }

    init(engagementId: String?, initialTargets: String) {
        self.engagementId = engagementId
        self.initialTargets = initialTargets
        _targetsText = State(initialValue: initialTargets)
    }

    var body: some View {
        VStack(spacing: 0) {
            header

            Form {
                Section {
                    TextField(
                        "192.168.1.0/24, 10.0.0.0/24, 192.0.2.5",
                        text: $targetsText,
                        axis: .vertical
                    )
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .disabled(isRunning)
                    .lineLimit(2...4)
                } header: {
                    Text("Targets")
                } footer: {
                    Text(
                        "Comma- or space-separated CIDR blocks, ranges, or single IPs. "
                        + "Examples: `192.168.1.0/24`, `10.0.0.1-10.0.0.50`, `192.0.2.5`. "
                        + "Capped at 256 hosts per scan."
                    )
                    .font(.caption)
                }

                if isRunning {
                    Section {
                        scanProgressRow
                        if let opSummary = currentOperationSummary {
                            Text(opSummary)
                                .font(.caption.monospaced())
                                .foregroundStyle(.tertiary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    } header: {
                        Text("Running…")
                    }
                }

                if let r = result {
                    Section("Summary") {
                        LabeledContent("Hosts found") {
                            Text("\(r.hosts.count)").font(.body.bold())
                        }
                        LabeledContent("Open ports") {
                            Text("\(totalOpenPorts(r))").foregroundStyle(.secondary)
                        }
                        LabeledContent("Findings") {
                            Text("\(r.findings.count)").foregroundStyle(.secondary)
                        }
                        LabeledContent("Duration") {
                            Text(durationString(r))
                                .foregroundStyle(.secondary)
                        }
                    }

                    if !r.hosts.isEmpty {
                        Section {
                            ForEach(r.hosts) { host in
                                HostRow(
                                    host: host,
                                    isExpanded: expandedIps.contains(host.ip),
                                    onToggleExpand: {
                                        if expandedIps.contains(host.ip) {
                                            expandedIps.remove(host.ip)
                                        } else {
                                            expandedIps.insert(host.ip)
                                        }
                                    },
                                    onAction: { action in
                                        pendingHostAction = action
                                    },
                                    onProvision: { host in
                                        appState.selectedSection = .provisioning
                                    },
                                    onOpenInBrowser: { host in
                                        openInBrowser(host: host)
                                    },
                                    onCopyIp: { host in
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general
                                            .setString(host.ip, forType: .string)
                                    }
                                )
                            }
                        } header: {
                            HStack {
                                Text("Hosts (\(r.hosts.count))")
                                Spacer()
                                if !expandedIps.isEmpty {
                                    Button("Collapse all") {
                                        expandedIps.removeAll()
                                    }
                                    .controlSize(.small)
                                } else if r.hosts.count <= 32 {
                                    Button("Expand all") {
                                        expandedIps = Set(r.hosts.map(\.ip))
                                    }
                                    .controlSize(.small)
                                }
                            }
                        } footer: {
                            Text(
                                "Click a row to expand for full device detail — "
                                + "MAC, vendor, OS guess, banners, TLS cert, SMB "
                                + "shares, SNMP info. Click **\"…\"** for actions: "
                                + "Add SSH host, UniFi adopt, provision, open web UI."
                            )
                            .font(.caption)
                        }
                    }

                    if !r.findings.isEmpty {
                        Section("Findings (\(r.findings.count))") {
                            ForEach(Array(r.findings.prefix(20).enumerated()), id: \.offset) { _, f in
                                FindingRow(finding: f)
                            }
                            if r.findings.count > 20 {
                                Text("…and \(r.findings.count - 20) more — open the engagement in Security for the full list.")
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                }

                if let err = errorMessage {
                    Section {
                        Text(err).foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                if isRunning {
                    Button("Stop scan", role: .destructive) { stop() }
                }
                if !isRunning, result != nil {
                    Button("Open in Security") {
                        appState.selectedSection = .security
                    }
                }
                Spacer()
                if !isRunning {
                    Button(result == nil ? "Start scan" : "Re-run") {
                        Task { await start() }
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(parsedTargets.isEmpty)
                }
                Button(isRunning ? "Close (scan keeps running)" : "Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(12)
        }
        .frame(minWidth: 720, minHeight: 540)
        .sheet(item: $pendingHostAction) { action in
            switch action {
            case .addSsh(let host):
                AddHostSheet(prefill: webCapture(from: host))
                    .environment(appState)
            case .adoptUnifi(let host):
                UnifiAdoptInlineSheet(host: host)
                    .environment(appState)
            }
        }
        .onAppear {
            // If the WebCapture flow handed off a target via
            // `pendingNetworkScanTargets`, clear it now so a
            // subsequent re-open of this sheet doesn't reuse a
            // stale capture target.
            appState.pendingNetworkScanTargets = nil
        }
        .onDisappear {
            // The user might close while scan is still going — keep
            // the daemon-side scan running so its results persist,
            // but stop polling from this view.
            operationsPollTask?.cancel()
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "network")
                .foregroundStyle(.tint).imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("Network scan").font(.headline)
                Text("Host discovery + port sweep + service banner-grab + CVE matching")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let eid = engagementId {
                Text("→ engagement \(eid.prefix(8))…")
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(.background.secondary)
    }

    // MARK: - Targets parsing

    private var parsedTargets: [String] {
        targetsText
            .split(whereSeparator: { c in c == "," || c.isWhitespace })
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    // MARK: - Progress row

    private var scanProgressRow: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            if let started = startedAt {
                let elapsed = Int(Date().timeIntervalSince(started))
                Text("Scanning… \(elapsed) sec elapsed").font(.body)
            } else {
                Text("Starting…").font(.body)
            }
            Spacer()
        }
    }

    private var currentOperationSummary: String? {
        appState.runningOperations
            .first(where: { $0.kind == "active_scan" })?
            .label
    }

    // MARK: - Run / stop

    private func start() async {
        result = nil
        errorMessage = nil
        isRunning = true
        startedAt = Date()
        let targets = parsedTargets

        // Poll the engine's operation list every 500ms while the
        // scan runs so we can show "scanning 192.168.1.0/24 (124 hosts)"
        // updating live. Cancelled on completion or close.
        operationsPollTask = Task {
            while !Task.isCancelled {
                _ = await appState.loadRunningOperations()
                try? await Task.sleep(for: .milliseconds(500))
            }
        }

        scanTask = Task {
            let r = await appState.runActiveDiscovery(
                targets: targets,
                customerSlug: nil,
                engagementId: engagementId
            )
            await MainActor.run {
                operationsPollTask?.cancel()
                isRunning = false
                if let r {
                    result = r
                } else {
                    errorMessage = "Scan failed — check daemon logs."
                }
            }
        }
    }

    private func stop() {
        // Find the engine's operation id + ask it to cancel.
        if let op = appState.runningOperations.first(where: { $0.kind == "active_scan" }) {
            Task { await appState.cancelOperation(id: op.id) }
        }
        scanTask?.cancel()
        operationsPollTask?.cancel()
        isRunning = false
    }

    // MARK: - Helpers

    private func totalOpenPorts(_ r: ActiveScanResult) -> Int {
        r.hosts.reduce(0) { $0 + $1.probes.count }
    }

    private func durationString(_ r: ActiveScanResult) -> String {
        let secs = Int(r.finishedAt.timeIntervalSince(r.startedAt))
        if secs < 60 { return "\(secs)s" }
        return "\(secs/60)m \(secs%60)s"
    }

    /// Build a WebCapture from a scanned host so the existing
    /// AddHostSheet pre-fill path works without duplicating
    /// initialiser logic. Vendor sniffing reads the engine's
    /// MAC-OUI lookup + per-port banners.
    private func webCapture(from host: ActiveHost) -> WebCapture {
        let dt = Self.deviceType(for: host)
        // First HTTP/HTTPS port (if any) makes the most
        // sensible "open in browser" default — preserved in
        // sourceUrl for the AddHost detail line.
        let webPort = host.probes
            .first(where: { $0.service.lowercased().contains("http") })?
            .port
        let url = webPort.map {
            URL(string: "https://\(host.ip):\($0)/")
        } ?? nil
        return WebCapture(
            hostname: host.ip,
            port: webPort,
            label: host.hostname?.isEmpty == false
                ? host.hostname!
                : "\(dt.displayName) — \(host.ip)",
            deviceType: dt,
            username: defaultUsername(for: dt),
            sourceUrl: url,
            pageTitle: host.vendor
        )
    }

    /// Sniff a vendor for a scanned host. Reads:
    ///   - `host.vendor`  (OUI lookup string from the engine —
    ///                     e.g. "Ubiquiti Networks Inc.")
    ///   - `host.mac`     (raw — so curated-list OUI prefixes
    ///                     win even if the vendor string
    ///                     never made it through)
    ///   - each probe's banner / title / server / x-powered-by
    ///
    /// MAC-prefix shortcuts cover the case where the engine
    /// found the MAC (via ARP) but our OUI database missed the
    /// prefix, AND the device exposes nothing over TCP we can
    /// fingerprint from (typical for an adopted UniFi AP).
    static func deviceType(for host: ActiveHost) -> DeviceType {
        let vendor = (host.vendor ?? "").lowercased()
        let mac = (host.mac ?? "").lowercased()
        let banners = host.probes
            .compactMap { p -> String? in
                let parts = [p.banner, p.title, p.serverHeader, p.poweredBy]
                    .compactMap { $0 }
                return parts.isEmpty ? nil : parts.joined(separator: " ")
            }
            .joined(separator: " ")
            .lowercased()
        let fingerprintBlob = host.probes
            .flatMap { $0.fingerprints }
            .joined(separator: " ")
            .lowercased()
        let blob = vendor + " " + banners + " " + fingerprintBlob

        // 1. Vendor / banner string contains a known token.
        if blob.contains("fortinet") || blob.contains("fortigate") {
            return .fortigate
        }
        if blob.contains("ubiquiti") || blob.contains("ubnt")
            || blob.contains("unifi") || blob.contains("airmax")
            || blob.contains("edgemax") || blob.contains("amplifi")
        {
            return .unifi
        }
        if blob.contains("pfsense") || blob.contains("netgate") {
            return .pfSense
        }
        if blob.contains("openwrt") || blob.contains("lede") {
            return .openWrt
        }
        if blob.contains("windows") || blob.contains("microsoft-iis") {
            return .windows
        }

        // 2. MAC-prefix fallback. The same Ubiquiti / Fortinet
        //    prefix list the engine ships, but used here so a
        //    GUI rebuild that ran before the engine's curated
        //    list updated still labels correctly.
        let prefix = mac.split(separator: ":").prefix(3)
            .joined(separator: ":")
        if Self.ubiquitiOuiPrefixes.contains(prefix) {
            return .unifi
        }
        if Self.fortinetOuiPrefixes.contains(prefix) {
            return .fortigate
        }
        if Self.mikrotikOuiPrefixes.contains(prefix) {
            return .openWrt  // closest match in our enum
        }
        return .linux
    }

    private static let ubiquitiOuiPrefixes: Set<String> = [
        "00:15:6d", "00:27:22", "04:18:d6", "18:e8:29", "24:5a:4c",
        "24:a4:3c", "28:70:4e", "44:d9:e7", "60:22:32", "68:72:51",
        "68:d7:9a", "70:a7:41", "74:83:c2", "74:ac:b9", "78:45:58",
        "78:8a:20", "80:2a:a8", "80:2d:7a", "8c:ed:e1", "94:2a:6f",
        "a0:36:bc", "ac:8b:a9", "b4:fb:e4", "d0:21:f9", "d2:21:f9",
        "dc:9f:db", "e0:63:da", "e4:38:83", "e4:6f:13", "f0:9f:c2",
        "f4:e2:c6", "f8:1b:73", "f8:8e:38", "fc:ec:da",
    ]
    private static let fortinetOuiPrefixes: Set<String> = [
        "00:09:0f", "00:13:5f", "04:d5:90", "08:5b:0e", "08:5b:0f",
        "08:62:66", "0c:74:c2", "10:0a:f8", "1c:a4:dc", "70:4c:a5",
        "78:f0:9c", "90:6c:ac", "b4:cb:57", "e8:1c:ba", "f0:b2:b9",
    ]
    private static let mikrotikOuiPrefixes: Set<String> = [
        "00:0c:42", "08:55:31", "18:fd:74", "2c:c8:1b", "48:8f:5a",
        "4c:5e:0c", "64:d1:54", "6c:3b:6b", "74:4d:28", "78:9a:18",
        "b8:69:f4", "c4:ad:34", "cc:2d:e0", "d4:ca:6d", "dc:2c:6e",
        "e4:8d:8c",
    ]

    private func defaultUsername(for type: DeviceType) -> String {
        switch type {
        case .unifi: return "ubnt"
        case .fortigate: return "admin"
        case .pfSense, .openWrt, .linux, .custom: return "root"
        case .windows: return "Administrator"
        }
    }

    private func openInBrowser(host: ActiveHost) {
        // Prefer HTTPS over HTTP if both are open, then whichever
        // is open. Bare IP works for the IP-as-host case (every
        // vendor admin UI accepts that even if its TLS cert is
        // self-signed).
        let preferred = [443, 8443, 80, 8080]
        let openHttps = host.probes.first(where: {
            preferred.prefix(2).contains(Int($0.port))
        })
        let openHttp = host.probes.first(where: {
            preferred.suffix(2).contains(Int($0.port))
        })
        let probe = openHttps ?? openHttp
        let scheme = (openHttps != nil) ? "https" : "http"
        let portStr: String = probe.map { ":\($0.port)" } ?? ""
        if let url = URL(string: "\(scheme)://\(host.ip)\(portStr)/") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - Sub-rows

/// Rich per-host row. Compact view shows IP + vendor pill +
/// device type + identity strings + port summary + action menu
/// + expand chevron. Tapping the chevron unrolls a detail panel
/// modeled after Advanced IP Scanner: MAC, vendor, OS guess,
/// per-port banners (server/title/x-powered-by), TLS cert info,
/// SMB shares, SNMP detail, and findings tied to this host.
private struct HostRow: View {
    let host: ActiveHost
    let isExpanded: Bool
    let onToggleExpand: () -> Void
    let onAction: (NetworkScanSheet.HostAction) -> Void
    let onProvision: (ActiveHost) -> Void
    let onOpenInBrowser: (ActiveHost) -> Void
    let onCopyIp: (ActiveHost) -> Void

    private var deviceType: DeviceType {
        NetworkScanSheet.deviceType(for: host)
    }

    private var hasWebPort: Bool {
        host.probes.contains(where: { p in
            let s = p.service.lowercased()
            return s.contains("http") || p.port == 443 || p.port == 80
                || p.port == 8443 || p.port == 8080
        })
    }

    /// Best one-line identity. Order of preference:
    ///   1. Reverse-DNS hostname
    ///   2. NetBIOS computer name (SMB)
    ///   3. SNMP sysName
    ///   4. HTTP page title (often vendor model: "USW-Pro-24")
    private var bestIdentity: String? {
        if let h = host.hostname, !h.isEmpty { return h }
        if let nb = host.probes.compactMap({ $0.smb?.netbiosName }).first {
            return nb
        }
        if let sn = host.probes.compactMap({ $0.snmp?.sysName }).first,
           !sn.isEmpty
        {
            return sn
        }
        if let title = host.probes.compactMap({ $0.title }).first,
           !title.isEmpty
        {
            return title
        }
        return nil
    }

    /// Cheap OS guess from probe data. The engine doesn't run a
    /// nmap-style OS fingerprint scan; this is purely banner-
    /// derived but covers the common cases.
    private var osGuess: String? {
        let blob = host.probes
            .flatMap { p -> [String] in
                [p.banner, p.title, p.serverHeader, p.poweredBy]
                    .compactMap { $0 }
            }
            .joined(separator: " ")
            .lowercased()
        let role = host.probes.compactMap { $0.smb?.serverRole }.first?
            .lowercased() ?? ""
        if blob.contains("microsoft-iis") || role.contains("primary domain")
            || role.contains("nt server")
        {
            return "Windows"
        }
        if blob.contains("fortios") { return "FortiOS" }
        if blob.contains("unifi os") || blob.contains("ubnt") { return "UniFi OS (Linux)" }
        if blob.contains("openwrt") { return "OpenWrt" }
        if blob.contains("pfsense") { return "FreeBSD (pfSense)" }
        if blob.contains("openssh") && blob.contains("ubuntu") { return "Linux (Ubuntu)" }
        if blob.contains("openssh") && blob.contains("debian") { return "Linux (Debian)" }
        if blob.contains("openssh") { return "Linux / *nix" }
        if blob.contains("samba") { return "Linux (Samba)" }
        if blob.contains("nginx") || blob.contains("apache") { return "Linux (likely)" }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            primaryLine
            secondaryLine
            tertiaryLine
            if isExpanded { expandedDetail }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .onTapGesture { onToggleExpand() }
    }

    private var primaryLine: some View {
        HStack(alignment: .center, spacing: 10) {
            vendorIcon
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 8) {
                    Text(host.ip)
                        .font(.body.monospaced().weight(.medium))
                    Text("·").foregroundStyle(.tertiary)
                    Text(deviceType.displayName)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                    if let identity = bestIdentity {
                        Text("·").foregroundStyle(.tertiary)
                        Text(identity)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer()
                }
            }
            badgesAndActions
        }
    }

    private var secondaryLine: some View {
        HStack(spacing: 8) {
            // Skip the row when there's no identifying detail
            // — keeps the visual rhythm tight for hosts that
            // only revealed a single open port.
            if let mac = host.mac, !mac.isEmpty {
                Label(mac, systemImage: "barcode")
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
            }
            if let vendor = host.vendor, !vendor.isEmpty {
                Text(vendor)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            if let os = osGuess {
                HStack(spacing: 4) {
                    Image(systemName: "cpu")
                    Text(os)
                }
                .font(.caption.weight(.medium))
                .foregroundStyle(.tertiary)
            }
            Spacer()
        }
    }

    @ViewBuilder
    private var tertiaryLine: some View {
        if !host.probes.isEmpty {
            Text(portsSummary(host))
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(2)
        } else {
            // ARP-only host (no TCP port answered, but the
            // device is on the LAN). Common for adopted UniFi
            // gear / printers / IoT that locks down everything
            // except the inform / discovery channel.
            HStack(spacing: 6) {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .foregroundStyle(.orange)
                Text("No open TCP ports — discovered via ARP")
                    .font(.caption.italic())
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private var badgesAndActions: some View {
        HStack(spacing: 6) {
            if host.findingCount > 0 {
                Label("\(host.findingCount)", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.orange)
            }
            Text("\(host.probes.count) ports")
                .font(.caption)
                .foregroundStyle(.tertiary)
            actionMenu
            Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.tertiary)
        }
    }

    // MARK: - Expanded detail

    private var expandedDetail: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider().padding(.vertical, 2)

            // Identity card
            VStack(alignment: .leading, spacing: 3) {
                identityRow("IP", host.ip, monospaced: true)
                if let mac = host.mac, !mac.isEmpty {
                    identityRow("MAC", mac, monospaced: true)
                }
                if let v = host.vendor, !v.isEmpty {
                    identityRow("Vendor (OUI)", v)
                }
                if let h = host.hostname, !h.isEmpty {
                    identityRow("Hostname (rDNS)", h)
                }
                if let nb = host.probes.compactMap({ $0.smb?.netbiosName }).first {
                    identityRow("NetBIOS name", nb)
                }
                if let wg = host.probes.compactMap({ $0.smb?.workgroup }).first {
                    identityRow("Workgroup", wg)
                }
                if let sn = host.probes.compactMap({ $0.snmp?.sysName }).first,
                   !sn.isEmpty
                {
                    identityRow("SNMP sysName", sn)
                }
                if let sd = host.probes.compactMap({ $0.snmp?.sysDescr }).first,
                   !sd.isEmpty
                {
                    identityRow("SNMP sysDescr", sd)
                }
                if let loc = host.probes.compactMap({ $0.snmp?.sysLocation }).first,
                   !loc.isEmpty
                {
                    identityRow("SNMP sysLocation", loc)
                }
                if let os = osGuess {
                    identityRow("OS guess", os)
                }
                if let zone = host.zone {
                    identityRow("Zone", zone)
                }
            }

            // Per-port detail
            if !host.probes.isEmpty {
                detailHeader("Ports & services")
                ForEach(host.probes.sorted(by: { $0.port < $1.port })) { probe in
                    probeRow(probe)
                }
            }

            // SMB shares — collapsed by default unless something
            // jumps out as worrying (null session, SYSVOL exposed).
            if let smb = host.probes.compactMap({ $0.smb }).first,
               !smb.shares.isEmpty || smb.nullSession
            {
                detailHeader("SMB / file sharing")
                VStack(alignment: .leading, spacing: 2) {
                    if smb.nullSession {
                        Label(
                            "Null session accepted (unauthenticated browse possible)",
                            systemImage: "exclamationmark.octagon.fill"
                        )
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.red)
                    }
                    ForEach(smb.shares) { share in
                        HStack(spacing: 6) {
                            Image(systemName: "folder.fill").foregroundStyle(.tint)
                            Text(share.name).font(.caption.monospaced())
                            Text("·").foregroundStyle(.tertiary)
                            Text(share.kind)
                                .font(.caption.weight(.medium))
                                .foregroundStyle(.secondary)
                            if !share.comment.isEmpty {
                                Text("— \(share.comment)")
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                                    .lineLimit(1)
                            }
                        }
                    }
                }
            }

            // SNMP interfaces — only worth showing for switches
            // / routers, which is where the SNMP probe finds
            // populated `interfaces`.
            if let snmp = host.probes.compactMap({ $0.snmp }).first,
               !snmp.interfaces.isEmpty
            {
                detailHeader("SNMP interfaces (\(snmp.interfaces.count))")
                Text(snmp.interfaces.prefix(8).joined(separator: ", "))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
                if snmp.interfaces.count > 8 {
                    Text("… and \(snmp.interfaces.count - 8) more")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.leading, 36)
    }

    private func identityRow(_ label: String, _ value: String, monospaced: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.tertiary)
                .frame(width: 110, alignment: .trailing)
            Text(value)
                .font(monospaced ? .caption.monospaced() : .caption)
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .lineLimit(2)
            Spacer()
        }
    }

    private func detailHeader(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.tertiary)
            .padding(.top, 6)
    }

    private func probeRow(_ probe: PortProbe) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text("\(probe.port)/\(probe.service)")
                    .font(.caption.monospaced().weight(.medium))
                    .foregroundStyle(.primary)
                if let title = probe.title, !title.isEmpty {
                    Text("·").foregroundStyle(.tertiary)
                    Text("\"\(title)\"")
                        .font(.caption.italic())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                if !probe.fingerprints.isEmpty {
                    Text(probe.fingerprints.prefix(3).joined(separator: ", "))
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                Spacer()
            }
            // Server banner / x-powered-by / generic banner
            if let s = probe.serverHeader, !s.isEmpty {
                Text("server: \(s)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            if let pb = probe.poweredBy, !pb.isEmpty {
                Text("x-powered-by: \(pb)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            if let b = probe.banner, !b.isEmpty,
               probe.serverHeader == nil
            {
                // Show generic banner only when there's no HTTP
                // server header (otherwise the two overlap and
                // the server line is the more useful one).
                Text(b.prefix(120))
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            if let tls = probe.tls {
                tlsLine(tls)
            }
        }
        .padding(.vertical, 1)
    }

    private func tlsLine(_ tls: TlsInfo) -> some View {
        HStack(spacing: 6) {
            Image(systemName: tls.selfSigned ? "lock.trianglebadge.exclamationmark" : "lock")
                .foregroundStyle(tls.selfSigned ? .orange : .green)
            Text(tls.version)
                .font(.caption.monospaced().weight(.medium))
                .foregroundStyle(.secondary)
            if let s = tls.certSubject, !s.isEmpty {
                Text("· \(s)")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            if let exp = tls.certExpiresIso, !exp.isEmpty {
                Text("· expires \(exp.prefix(10))")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            Spacer()
        }
    }

    private var vendorIcon: some View {
        let (sym, tint) = vendorBadge
        return Image(systemName: sym)
            .font(.system(size: 18))
            .foregroundStyle(tint)
            .frame(width: 26, height: 26)
            .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
    }

    private var vendorBadge: (String, Color) {
        switch deviceType {
        case .unifi: return ("wifi", .blue)
        case .fortigate: return ("shield.lefthalf.filled", .red)
        case .pfSense: return ("shield.lefthalf.filled", .orange)
        case .openWrt: return ("antenna.radiowaves.left.and.right", .purple)
        case .windows: return ("pc", .cyan)
        case .linux: return ("terminal", .green)
        case .custom: return ("desktopcomputer", .gray)
        }
    }

    private var actionMenu: some View {
        Menu {
            Button {
                onAction(.addSsh(host))
            } label: {
                Label("Add as SSH host…", systemImage: "terminal")
            }
            if deviceType == .unifi {
                Button {
                    onAction(.adoptUnifi(host))
                } label: {
                    Label(
                        "Adopt to UniFi controller…",
                        systemImage: "antenna.radiowaves.left.and.right.circle.fill"
                    )
                }
            }
            Button {
                onProvision(host)
            } label: {
                Label("Open Provisioning…", systemImage: "doc.text.fill")
            }
            Divider()
            if hasWebPort {
                Button {
                    onOpenInBrowser(host)
                } label: {
                    Label("Open web UI in browser", systemImage: "safari")
                }
            }
            Button {
                onCopyIp(host)
            } label: {
                Label("Copy IP", systemImage: "doc.on.doc")
            }
        } label: {
            Image(systemName: "ellipsis.circle.fill")
                .font(.system(size: 20))
                .foregroundStyle(.tint)
                .contentShape(Rectangle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Actions for this host")
    }

    private func portsSummary(_ h: ActiveHost) -> String {
        h.probes
            .sorted(by: { $0.port < $1.port })
            .map { "\($0.port)/\($0.service)" }
            .joined(separator: ", ")
    }
}

/// Inline sheet for "Adopt to UniFi controller". Two steps in
/// one panel: add the host to the SSH inventory (with the
/// factory-default `ubnt`/`ubnt` creds the operator just types
/// once here), then immediately run `set-inform <controller>`
/// over SSH. The discovered device starts trying to register
/// with the controller within a few seconds.
private struct UnifiAdoptInlineSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState
    let host: ActiveHost

    @State private var label: String = ""
    @State private var username: String = "ubnt"
    @State private var password: String = "ubnt"
    @State private var controllerUrl: String =
        "http://unifi.example.lan:8080/inform"
    @State private var group: String = ""
    @State private var step: String = ""
    @State private var output: String?
    @State private var errorMessage: String?
    @State private var running: Bool = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "antenna.radiowaves.left.and.right.circle.fill")
                    .foregroundStyle(.blue).imageScale(.large)
                VStack(alignment: .leading) {
                    Text("Adopt UniFi device to controller")
                        .font(.headline)
                    Text(
                        "Adds \(host.ip) as an SSH host with default "
                        + "`ubnt`/`ubnt` creds, then runs `set-inform "
                        + "<controller>` over SSH so the device registers "
                        + "with your UniFi controller."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(12)
            .background(.background.secondary)

            Form {
                Section("SSH login") {
                    TextField("Label", text: $label)
                    Text(host.ip).font(.body.monospaced()).foregroundStyle(.secondary)
                    TextField("Username", text: $username)
                    SecureField("Password", text: $password)
                    Picker("Group", selection: $group) {
                        Text("Ungrouped").tag("")
                        ForEach(appState.customers) { c in
                            Text("\(c.displayName) (\(c.slug))").tag(c.slug)
                        }
                    }
                }
                Section("Controller") {
                    TextField(
                        "http://controller.lan:8080/inform",
                        text: $controllerUrl
                    )
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    Text(
                        "Full URL including scheme + `/inform`. UniFi "
                        + "controllers default to port 8080 for inform "
                        + "traffic; the UI itself lives on 8443."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                if !step.isEmpty {
                    Section { Text(step).font(.caption) }
                }
                if let out = output {
                    Section("Controller response") {
                        Text(out)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
                if let err = errorMessage {
                    Section { Text(err).foregroundStyle(.red) }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(running ? "Adopting…" : "Adopt") {
                    Task { await runAdopt() }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(running || !canSubmit)
            }
            .padding(12)
        }
        .frame(minWidth: 560, minHeight: 520)
        .onAppear {
            if label.isEmpty {
                label = "UniFi @ \(host.ip)"
            }
        }
    }

    /// Normalised inform URL — trims whitespace + strips any
    /// stray `set-inform` prefix the user accidentally included
    /// when pasting a full command. The engine does the same on
    /// its side; doing it here too keeps the live "Running
    /// `set-inform <url>`" preview accurate.
    private var sanitisedUrl: String {
        let trimmed = controllerUrl.trimmingCharacters(in: .whitespaces)
        if let r = trimmed.range(
            of: #"^set-inform\s+"#,
            options: [.regularExpression, .caseInsensitive]
        ) {
            return String(trimmed[r.upperBound...]).trimmingCharacters(in: .whitespaces)
        }
        return trimmed
    }

    private var canSubmit: Bool {
        let url = sanitisedUrl
        return !label.isEmpty
            && !username.isEmpty
            && !password.isEmpty
            && (url.hasPrefix("http://") || url.hasPrefix("https://"))
            && url.contains("inform")
    }

    private func runAdopt() async {
        running = true
        defer { running = false }
        errorMessage = nil
        output = nil
        let url = sanitisedUrl
        step = "Adding SSH host…"
        await appState.addHost(
            label: label,
            hostname: host.ip,
            port: 22,
            username: username,
            group: group,
            deviceType: .unifi,
            authMethod: .password,
            authKeyId: nil,
            password: password
        )
        await appState.refreshHosts()
        guard let newHost = appState.sshHosts.first(where: {
            $0.hostname == host.ip && $0.username == username
        }) else {
            errorMessage =
                "Couldn't locate the freshly-added host in inventory. "
                + "Open the SSH tab to confirm it was added, then run "
                + "set-inform from the host detail panel."
            return
        }
        step = "Running `set-inform \(url)` over SSH…"
        let result = await appState.unifiSetInformDetailed(
            hostId: newHost.id,
            informUrl: url
        )
        switch result {
        case .success(let out):
            output = out.isEmpty
                ? "(no stdout — UniFi `set-inform` typically prints nothing on success)"
                : out
            step = "Done. Device will appear in the controller within a few seconds."
        case .failure(let err):
            // Surface the engine's real error string. Most
            // common shapes:
            //   - "set-inform returned exit 1: stdout=… stderr=Permission denied"
            //     → device booted up locked, default creds reset
            //   - "ssh exec: Authentication failed"
            //     → wrong username/password
            //   - "invalid inform URL: ..."
            //     → URL didn't parse
            //   - "open_session: Connection refused"
            //     → SSH is disabled on the device (often the
            //       case for already-adopted devices)
            errorMessage = humanise(err)
        }
    }

    /// Map raw engine error strings into hints the operator
    /// can act on without grepping the daemon logs.
    private func humanise(_ raw: String) -> String {
        let low = raw.lowercased()
        if low.contains("authentication") || low.contains("permission denied") {
            return
                "SSH login refused. The device may not be on factory "
                + "defaults — try the controller's adopted-device "
                + "password instead of `ubnt`/`ubnt`. Raw: \(raw)"
        }
        if low.contains("connection refused") || low.contains("timed out") {
            return
                "Couldn't reach SSH on \(host.ip):22. Adopted UniFi "
                + "devices often disable SSH; factory-reset the device "
                + "(hold reset for 10 s with PoE applied) to enable it "
                + "and try again. Raw: \(raw)"
        }
        if low.contains("invalid inform url") || low.contains("invalid url") {
            return "URL didn't parse — check the format. Raw: \(raw)"
        }
        if low.contains("set-inform returned exit") {
            return
                "Device rejected the set-inform command — check the "
                + "URL path includes `/inform` and the controller is "
                + "reachable from the device's network. Raw: \(raw)"
        }
        return raw
    }
}

private struct FindingRow: View {
    let finding: SecurityFinding
    var body: some View {
        HStack(alignment: .top) {
            SeverityBadge(severity: finding.severity)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title)
                    .font(.body.weight(.medium))
                    .lineLimit(2)
                if !finding.hostIp.isEmpty {
                    Text("\(finding.hostIp)\(finding.port.map { ":\($0)" } ?? "")")
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
        }
        .padding(.vertical, 2)
    }
}

#if DEBUG
#Preview {
    NetworkScanSheet(engagementId: "preview-eng-1", initialTargets: "192.0.2.0/24")
        .environment(AppState.previewSeeded)
}
#endif
