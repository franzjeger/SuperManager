import SwiftUI

/// Add / Edit customer dialog. Two-column layout:
///   Left: customer-level fields (display name, contact info, notes)
///   Right: sites list with add/remove + per-site editor
///
/// We deliberately collapse "Add customer" and "Edit customer" into
/// the same sheet — the only difference is the initial state and
/// whether `slug` is editable (it's not after first save: changing
/// the slug would orphan deployment history pointing at the old one).
struct CustomerEditSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    /// nil → adding, non-nil → editing.
    let customer: Customer?

    @State private var displayName = ""
    @State private var contactName = ""
    @State private var contactEmail = ""
    @State private var primaryDomain = ""
    @State private var notes = ""
    @State private var dnsAuditing = false
    @State private var dnsReport: DnsHealthReport?
    @State private var subdomainEnum: SubdomainResult?
    @State private var subdomainBusy = false
    /// Scaled with Dynamic Type so users with larger system text
    /// don't get clipped fields. The numeric base matches the
    /// design width at default (100%) text size.
    @ScaledMetric private var sheetWidth: CGFloat = 980
    @ScaledMetric private var sheetHeight: CGFloat = 600
    /// Newline-separated allowlist; serialised to/from
    /// `Customer.mgmtAllowlistDomains` on save/hydrate. Each
    /// non-empty line becomes one entry — easier for the user
    /// than chip-style editors and matches how config files
    /// usually express domain lists.
    @State private var mgmtAllowlistText = ""
    @State private var sites: [Site] = []
    @State private var selectedSiteId: String?
    @State private var saving = false
    @State private var errorMessage: String?
    @State private var detecting = false
    @State private var detectMessage: String?
    /// Site index pending deletion — drives the confirmation
    /// alert. Removing a site permanently drops its VLAN config +
    /// host-id list, so we never delete in-place on the button
    /// click; the user explicitly confirms.
    @State private var pendingSiteRemoval: Int?
    @FocusState private var firstFieldFocused: Bool

    private var isEditing: Bool { customer != nil }

    var body: some View {
        VStack(spacing: 0) {
            header
            HStack(spacing: 0) {
                customerFields
                Divider()
                siteSection
            }
            footer
        }
        // Sized to comfortably fit a 360-pt customer pane + a
        // wide-enough site editor that the VLAN row's five
        // columns (id / name / subnet / purpose / delete) all
        // render without clipping. Earlier 760-wide layout
        // squeezed both panes too hard.
        .frame(width: sheetWidth, height: sheetHeight)
        .onAppear { hydrate() }
        .task {
            try? await Task.sleep(for: .milliseconds(100))
            firstFieldFocused = true
        }
        // Editing a customer touches multiple sites, VLANs and
        // DNS settings — dismissing accidentally would lose all of
        // it. Force explicit Save / Cancel.
        .interactiveDismissDisabled()
    }

    private func hydrate() {
        guard let c = customer else { return }
        displayName = c.displayName
        contactName = c.contactName
        contactEmail = c.contactEmail
        primaryDomain = c.primaryDomain
        notes = c.notes
        mgmtAllowlistText = c.mgmtAllowlistDomains.joined(separator: "\n")
        sites = c.sites
        selectedSiteId = c.sites.first?.id
    }

    /// Domain to audit. Prefer explicit `primaryDomain`; fall back
    /// to the part of `contactEmail` after `@`.
    private var auditDomain: String {
        if !primaryDomain.isEmpty { return primaryDomain }
        if let at = contactEmail.lastIndex(of: "@") {
            return String(contactEmail[contactEmail.index(after: at)...])
        }
        return ""
    }

    @ViewBuilder
    private var subdomainSection: some View {
        Section("Subdomain enumeration") {
            if auditDomain.isEmpty {
                Text("Set Primary domain to enable Cert Transparency lookup.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            } else {
                HStack {
                    Text("CT logs for *.\(auditDomain)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        Task { await runSubdomainEnum() }
                    } label: {
                        if subdomainBusy {
                            HStack(spacing: 4) {
                                ProgressView().controlSize(.mini)
                                Text("Looking up…")
                            }
                        } else {
                            Label("Enumerate", systemImage: "magnifyingglass")
                        }
                    }
                    .controlSize(.small)
                    .disabled(subdomainBusy)
                }
                if let r = subdomainEnum {
                    Text("\(r.found.count) unique subdomains across \(r.certCount) certificates")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if !r.found.isEmpty {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 1) {
                                ForEach(r.found.prefix(40), id: \.self) { sub in
                                    Text(sub)
                                        .font(.caption2.monospaced())
                                        .textSelection(.enabled)
                                }
                                if r.found.count > 40 {
                                    Text("…and \(r.found.count - 40) more")
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 140)
                        .padding(6)
                        .background(.background.tertiary)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                        Button("Copy all") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(r.found.joined(separator: "\n"), forType: .string)
                        }
                        .controlSize(.small)
                    }
                }
            }
        }
    }

    private func runSubdomainEnum() async {
        subdomainBusy = true
        defer { subdomainBusy = false }
        if let r = await appState.enumerateSubdomains(domain: auditDomain) {
            subdomainEnum = r
        }
    }

    @ViewBuilder
    private var dnsHealthSection: some View {
        Section("DNS health") {
            if auditDomain.isEmpty {
                Text("Set Primary domain or Contact email to enable DNS health audit.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                HStack {
                    Text("Audit \(auditDomain)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        Task { await runDnsAudit() }
                    } label: {
                        if dnsAuditing {
                            HStack(spacing: 4) {
                                ProgressView().controlSize(.mini)
                                Text("Auditing…")
                            }
                        } else {
                            Label("Run audit", systemImage: "stethoscope")
                        }
                    }
                    .controlSize(.small)
                    .disabled(dnsAuditing)
                }
                if let r = dnsReport {
                    dnsResultRow("SPF", r.spfLabel)
                    dnsResultRow("DMARC", r.dmarcLabel)
                    dnsResultRow("MTA-STS", r.mtaStsLabel)
                    dnsResultRow("DNSSEC", r.dnssecLabel)
                    dnsResultRow("DKIM selectors", "\(r.dkimSelectorsFound.count) found")
                    if !r.findings.isEmpty {
                        Text("\(r.findings.count) finding\(r.findings.count == 1 ? "" : "s") — visible in customer Security tab")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    } else {
                        Text("No DNS health issues detected.")
                            .font(.caption2)
                            .foregroundStyle(.green)
                    }
                }
            }
        }
    }

    private func dnsResultRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.caption.monospaced())
                .foregroundStyle(dnsValueColor(value))
        }
    }

    private func dnsValueColor(_ s: String) -> Color {
        // Green for "good" states, orange for warnings, red for bad.
        switch s {
        case "Strict", "Reject", "Enabled", "Soft", "Quarantine":
            return .green
        case "Missing", "Permissive", "Disabled":
            return .red
        case "None", "Multiple", "NoTerminator", "Neutral":
            return .orange
        default:
            return .primary
        }
    }

    private func runDnsAudit() async {
        dnsAuditing = true
        defer { dnsAuditing = false }
        let scope = customer?.slug
        if let r = await appState.auditDnsHealth(domain: auditDomain, scope: scope) {
            dnsReport = r
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "building.2")
                .foregroundStyle(.tint)
            Text(isEditing ? "Edit customer" : "Add customer")
                .font(.title3.weight(.semibold))
            Spacer()
        }
        .padding(14)
        .background(.background.secondary)
    }

    private var customerFields: some View {
        Form {
            Section("Customer") {
                TextField("Display name", text: $displayName)
                    .focused($firstFieldFocused)
                TextField("Contact name", text: $contactName)
                TextField("Contact email", text: $contactEmail)
                TextField("Primary domain", text: $primaryDomain)
                    .help("Public domain used for DNS health audit (SPF/DKIM/DMARC). Falls back to contact-email domain when empty.")
                if isEditing {
                    LabeledContent("Slug") {
                        Text(customer?.slug ?? "")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
            }
            dnsHealthSection
            subdomainSection
            Section("Notes") {
                TextEditor(text: $notes)
                    .frame(minHeight: 60)
                    .font(.callout)
            }
            Section {
                TextEditor(text: $mgmtAllowlistText)
                    .frame(minHeight: 80)
                    .font(.system(.caption, design: .monospaced))
                Text("One domain per line. Wildcards OK (`*.unifi.example.no`). Allowed past FortiGuard's Newly-Observed-Domains and Newly-Registered-Domains categories on management VLANs.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("MGMT allowlist")
            }
        }
        .formStyle(.grouped)
        // 360 leaves room for Form's grouped-style internal
        // padding plus 120-pt labels + 180-pt fields without
        // the labels getting clipped. Keep this in lockstep
        // with the sheet width above.
        .frame(width: 360)
    }

    @ViewBuilder
    private var siteSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Sites")
                    .font(.headline)
                Spacer()
                Button {
                    let newId = UUID().uuidString.lowercased().prefix(8)
                    let newSite = Site(
                        id: String(newId),
                        displayName: "New site",
                        address: "",
                        hostIds: [],
                        wanType: "dhcp",
                        wanStaticIp: "",
                        lanBase: "10.0.0.0/24",
                        vlans: []
                    )
                    sites.append(newSite)
                    selectedSiteId = newSite.id
                } label: {
                    Label("Add site", systemImage: "plus")
                }
                .controlSize(.small)
            }
            if sites.isEmpty {
                Text("No sites yet. Click 'Add site' to create one.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HStack(alignment: .top, spacing: 12) {
                    sitePicker
                    Divider()
                    if let idx = sites.firstIndex(where: { $0.id == selectedSiteId }) {
                        siteEditor(idx: idx)
                    } else {
                        Text("Select a site")
                            .foregroundStyle(.tertiary)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var sitePicker: some View {
        List(selection: $selectedSiteId) {
            ForEach(sites) { site in
                Text(site.displayName)
                    .tag(Optional(site.id))
            }
        }
        .listStyle(.sidebar)
        .frame(width: 140)
    }

    @ViewBuilder
    private func siteEditor(idx: Int) -> some View {
        // Editing through bindings into the array. SwiftUI's
        // `Binding(get:set:)` re-reads the array so list reorders
        // and deletions don't leave stale bindings around.
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                TextField("Display name", text: Binding(
                    get: { sites[idx].displayName },
                    set: { sites[idx].displayName = $0 }
                ))
                TextField("Address", text: Binding(
                    get: { sites[idx].address },
                    set: { sites[idx].address = $0 }
                ))
                HStack {
                    Picker("WAN type", selection: Binding(
                        get: { sites[idx].wanType },
                        set: { sites[idx].wanType = $0 }
                    )) {
                        Text("DHCP").tag("dhcp")
                        Text("Static").tag("static")
                        Text("PPPoE").tag("pppoe")
                        Text("Fiber").tag("fiber")
                    }
                    .pickerStyle(.segmented)
                    Button {
                        Task { await autodetect(siteIdx: idx) }
                    } label: {
                        if detecting {
                            HStack(spacing: 4) {
                                ProgressView().controlSize(.mini)
                                Text("Detecting…")
                            }
                        } else {
                            Label("Detect from current network",
                                  systemImage: "wand.and.rays")
                        }
                    }
                    .controlSize(.small)
                    .disabled(detecting)
                    .help("Probes the Mac's current LAN: pulls WAN public IP, default gateway, lanBase, DNS, and infers VLANs from observed subnets in the latest passive scan.")
                }
                if let msg = detectMessage {
                    Text(msg)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 4)
                }
                if sites[idx].wanType == "static" {
                    TextField("Static WAN IP (CIDR)", text: Binding(
                        get: { sites[idx].wanStaticIp },
                        set: { sites[idx].wanStaticIp = $0 }
                    ))
                }
                TextField("LAN base (CIDR)", text: Binding(
                    get: { sites[idx].lanBase },
                    set: { sites[idx].lanBase = $0 }
                ))

                Divider().padding(.vertical, 4)

                HStack {
                    Text("VLANs (\(sites[idx].vlans.count))")
                        .font(.subheadline.weight(.semibold))
                    Spacer()
                    Button {
                        let newId = (sites[idx].vlans.map(\.id).max() ?? 9) + 1
                        sites[idx].vlans.append(Vlan(
                            id: newId,
                            name: "VLAN\(newId)",
                            subnet: "10.0.\(newId).0/24",
                            purpose: "internal"
                        ))
                    } label: {
                        Label("Add VLAN", systemImage: "plus.circle")
                    }
                    .controlSize(.small)
                }
                ForEach(sites[idx].vlans.indices, id: \.self) { vlanIdx in
                    VlanRow(vlan: Binding(
                        get: { sites[idx].vlans[vlanIdx] },
                        set: { sites[idx].vlans[vlanIdx] = $0 }
                    ), onDelete: {
                        sites[idx].vlans.remove(at: vlanIdx)
                    })
                }

                Divider().padding(.vertical, 4)

                Button("Remove site…", role: .destructive) {
                    pendingSiteRemoval = idx
                }
                .controlSize(.small)
            }
            .padding(.trailing, 4)
        }
        .alert(
            "Remove site?",
            isPresented: Binding(
                get: { pendingSiteRemoval != nil },
                set: { if !$0 { pendingSiteRemoval = nil } }
            )
        ) {
            Button("Remove", role: .destructive) {
                if let i = pendingSiteRemoval, i < sites.count {
                    sites.remove(at: i)
                    selectedSiteId = sites.first?.id
                }
                pendingSiteRemoval = nil
            }
            Button("Cancel", role: .cancel) {
                pendingSiteRemoval = nil
            }
        } message: {
            if let i = pendingSiteRemoval, i < sites.count {
                let site = sites[i]
                Text("Removes \"\(site.displayName)\" with its \(site.vlans.count) VLAN(s) and \(site.hostIds.count) linked host(s). This is permanent — the customer's other sites are unaffected.")
            } else {
                Text("This is permanent.")
            }
        }
    }

    private var footer: some View {
        HStack {
            if let err = errorMessage {
                Label(err, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            Spacer()
            Button("Cancel") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button(saving ? "Saving…" : "Save") {
                Task { await save() }
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .disabled(saving || displayName.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(14)
        .background(.background.secondary)
    }

    /// Auto-fill site fields from:
    ///   1. `network_detect` RPC → WAN public IP, default gateway, lanBase
    ///   2. Latest passive-scan inventory → discovered host IPs become
    ///      hostIds; distinct /24 subnets become suggested VLAN entries.
    ///
    /// Existing values are preserved unless empty so we don't clobber
    /// hand-edited fields. New VLAN suggestions are merged by id-uniqueness.
    private func autodetect(siteIdx: Int) async {
        detecting = true
        defer { detecting = false }
        detectMessage = nil

        guard let info = await appState.detectNetwork() else {
            detectMessage = "Detection failed — daemon unreachable."
            return
        }

        // 1) WAN — if user picked Static, fill `wan_static_ip`
        //    with the public IP. Otherwise just leave it.
        if let pub = info.publicIp, !pub.isEmpty {
            if sites[siteIdx].wanType == "static" && sites[siteIdx].wanStaticIp.isEmpty {
                sites[siteIdx].wanStaticIp = pub
            }
        }

        // 2) LAN base from primary interface, if currently empty
        //    or still the placeholder value.
        if let base = info.lanBase,
           !base.isEmpty,
           sites[siteIdx].lanBase.isEmpty || sites[siteIdx].lanBase == "10.0.0.0/24"
        {
            sites[siteIdx].lanBase = base
        }

        // 3) Run a passive scan for VLAN inference + host import.
        //    Best-effort: this populates the inventory and gives us
        //    hostnames/vendors, but if scan fails we still ship the
        //    netdetect data above.
        let scan = await appState.runPassiveDiscovery(
            customerSlug: customer?.slug,
            engagementId: nil
        )

        var addedVlans = 0
        var addedHosts = 0

        if let scan {
            // Collect every distinct /24 we observed in the scan.
            var subnets: Set<String> = []
            for h in scan.hosts {
                if let net = derive24(from: h.ip) {
                    subnets.insert(net)
                }
            }
            // Skip the lanBase /24 itself — it's already covered by
            // the primary interface's flat LAN.
            let lanBase24 = info.lanBase.flatMap { derive24From(cidr: $0) }
            // Take VLAN ids from the third-octet of each subnet so
            // 10.0.50.0/24 → VLAN 50; deterministic, matches MSP convention.
            let existingVlanIds = Set(sites[siteIdx].vlans.map(\.id))
            for net in subnets.sorted() {
                if lanBase24 == net { continue }
                let parts = net.split(separator: ".")
                guard parts.count >= 4, let third = UInt16(parts[2]) else { continue }
                let vlanId = third == 0 ? 1 : third
                if existingVlanIds.contains(vlanId) { continue }
                sites[siteIdx].vlans.append(Vlan(
                    id: vlanId,
                    name: "VLAN\(vlanId)",
                    subnet: net,
                    purpose: "internal"
                ))
                addedVlans += 1
            }

            // Merge discovered host IPs into site.hostIds (de-duped).
            var ids = sites[siteIdx].hostIds
            for h in scan.hosts where !ids.contains(h.ip) {
                ids.append(h.ip)
                addedHosts += 1
            }
            sites[siteIdx].hostIds = ids
        }

        let parts: [String] = [
            info.publicIp.map { "WAN \($0)" },
            info.defaultGateway.map { "GW \($0)" },
            info.lanBase.map { "LAN \($0)" },
            addedVlans > 0 ? "+ \(addedVlans) VLAN\(addedVlans == 1 ? "" : "s")" : nil,
            addedHosts > 0 ? "+ \(addedHosts) host\(addedHosts == 1 ? "" : "s")" : nil,
        ].compactMap { $0 }
        detectMessage = parts.isEmpty ? "Nothing new detected." : parts.joined(separator: " · ")
    }

    /// Tiny helper: "10.0.50.42" → "10.0.50.0".
    private func derive24(from ip: String) -> String? {
        let octets = ip.split(separator: ".")
        guard octets.count == 4 else { return nil }
        return "\(octets[0]).\(octets[1]).\(octets[2]).0"
    }

    /// "10.0.50.0/24" → "10.0.50.0" (no mask).
    private func derive24From(cidr: String) -> String? {
        cidr.split(separator: "/").first.map(String.init)
    }

    private func save() async {
        saving = true
        defer { saving = false }
        var c = customer ?? Customer(
            slug: "",
            displayName: "",
            contactName: "",
            contactEmail: "",
            notes: "",
            defaultTemplate: nil,
            mgmtAllowlistDomains: [],
            primaryDomain: "",
            sites: []
        )
        c.displayName = displayName.trimmingCharacters(in: .whitespaces)
        c.contactName = contactName
        c.contactEmail = contactEmail
        c.primaryDomain = primaryDomain.trimmingCharacters(in: .whitespaces)
        c.notes = notes
        c.mgmtAllowlistDomains = mgmtAllowlistText
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        c.sites = sites
        if let saved = await appState.saveCustomer(c) {
            appState.selectedCustomerSlug = saved.slug
            dismiss()
        } else {
            errorMessage = appState.errorMessage.isEmpty
                ? "Could not save customer."
                : appState.errorMessage
        }
    }
}

#if DEBUG
#Preview("Customer — new") {
    CustomerEditSheet(customer: nil)
        .environment(AppState.previewSeeded)
}

#Preview("Customer — edit Aarsleff") {
    CustomerEditSheet(customer: .previewAarsleff)
        .environment(AppState.previewSeeded)
}
#endif

/// Single VLAN row inside the site editor. Inline-editable fields
/// + a small delete button. Column widths are calibrated to fit
/// a typical CIDR (`10.0.10.0/24` = 12 chars) plus the trash
/// button without horizontal clipping inside the site-editor
/// pane (~580 pt wide on the 980-pt sheet).
private struct VlanRow: View {
    @Binding var vlan: Vlan
    let onDelete: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            TextField("ID", value: $vlan.id, format: .number)
                .frame(width: 48)
            TextField("Name", text: $vlan.name)
                .frame(width: 100)
            TextField("Subnet", text: $vlan.subnet)
                .frame(width: 130)
            Picker("", selection: $vlan.purpose) {
                Text("Internal").tag("internal")
                Text("Mgmt").tag("mgmt")
                Text("IoT").tag("iot")
                Text("Guest").tag("guest")
                Text("Voice").tag("voice")
            }
            .labelsHidden()
            .frame(width: 100)
            Button {
                onDelete()
            } label: {
                Image(systemName: "minus.circle")
                    .foregroundStyle(.red)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Remove VLAN")
        }
    }
}
