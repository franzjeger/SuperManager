import SwiftUI

/// Add / Edit engagement dialog. Layout:
///   Left  — meta (title, customer, expiry, authorized-by)
///   Right — scope (CIDRs, hosts, exclusions) + allowed
///           techniques + notes
///
/// "Authorized by" is free-form free text; later phases can add
/// PDF-upload + hash for legal-defensible audit. For this v1 the
/// presence of a non-empty authorized_by is enough.
struct EngagementEditSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    let engagement: Engagement?

    @State private var title = ""
    @State private var customerSlug = ""
    @State private var authorizedBy = ""
    @State private var notes = ""
    // Lazily initialised in `hydrate` / `.onAppear` to avoid
    // recomputing `Date()` on every view re-evaluation. SwiftUI
    // re-runs property initialisers on each parent recompose for
    // `@State` defaults that capture mutable state — using
    // `Optional<Date>` plus a one-shot setter sidesteps that.
    @State private var expiresAt = Date(timeIntervalSinceReferenceDate: 0)
    @State private var scopeCidrsText = ""
    @State private var scopeHostsText = ""
    @State private var exclusionsText = ""
    @State private var allowedTechniques: Set<SecurityTechnique> =
        Set(SecurityTechnique.allCases.filter {
            $0 != .wireless && $0 != .dosTest
        })
    @State private var scheduleEnabled = false
    @State private var scheduleCadence: ScheduleCadence = .weekly
    @State private var saving = false
    @State private var error: String?
    @State private var showingNewCustomer = false
    /// Customer slugs that existed *before* opening the new-customer
    /// sheet — used to detect which one is new and auto-select it.
    @State private var slugsBeforeAdd: Set<String> = []
    @ScaledMetric private var sheetWidth: CGFloat = 980
    @ScaledMetric private var sheetHeight: CGFloat = 620
    @FocusState private var firstFieldFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            header
            HStack(alignment: .top, spacing: 0) {
                metaPane
                Divider()
                scopePane
            }
            footer
        }
        .frame(width: sheetWidth, height: sheetHeight)
        .onAppear { hydrate() }
        .task {
            // Make sure the customer list is fresh so the picker
            // shows everything currently provisioned.
            await appState.refreshCustomers()
            try? await Task.sleep(for: .milliseconds(100))
            firstFieldFocused = true
        }
        // Prevent silent dismissal mid-edit (Cmd-W / click-outside).
        // The user explicitly hits Cancel or Save.
        .interactiveDismissDisabled()
    }

    private var customerPicker: some View {
        // Picker over known customers + an explicit "ad-hoc" option.
        // When the user picks a customer, we suggest its known
        // networks (lanBase + per-VLAN subnets) as scope CIDRs.
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Picker("Linked customer", selection: $customerSlug) {
                    Text("(ad-hoc — no customer)").tag("")
                    ForEach(appState.customers) { c in
                        Text("\(c.displayName) (\(c.slug))").tag(c.slug)
                    }
                }
                .help("Linking enables auto-scope from customer's known networks + per-customer Slack notifications.")
                Button {
                    slugsBeforeAdd = Set(appState.customers.map(\.slug))
                    showingNewCustomer = true
                } label: {
                    Image(systemName: "plus.circle")
                }
                .buttonStyle(.borderless)
                .help("Create a new customer without leaving this sheet.")
                .accessibilityLabel("Add new customer")
            }
            .sheet(isPresented: $showingNewCustomer, onDismiss: {
                Task {
                    await appState.refreshCustomers()
                    // Auto-select whichever slug is new vs the
                    // pre-add snapshot.
                    if let added = appState.customers
                        .first(where: { !slugsBeforeAdd.contains($0.slug) })
                    {
                        customerSlug = added.slug
                    }
                }
            }) {
                CustomerEditSheet(customer: nil)
            }
            // Suggest scope-from-customer when scope CIDRs are empty
            // and a customer is picked.
            if !customerSlug.isEmpty,
               let customer = appState.customers.first(where: { $0.slug == customerSlug }) {
                let suggested = derivedScopeCidrs(for: customer)
                if !suggested.isEmpty {
                    let alreadyHave = scopeCidrsText
                        .split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
                    let newOnes = suggested.filter { !alreadyHave.contains($0) }
                    if !newOnes.isEmpty {
                        Button {
                            let prefix = scopeCidrsText.isEmpty ? "" : (scopeCidrsText + "\n")
                            scopeCidrsText = prefix + newOnes.joined(separator: "\n")
                        } label: {
                            Label("Add \(newOnes.count) network\(newOnes.count == 1 ? "" : "s") from \(customer.displayName)", systemImage: "plus.rectangle.on.rectangle")
                                .font(.caption)
                        }
                        .controlSize(.small)
                    }
                }
            }
        }
    }

    private func derivedScopeCidrs(for customer: Customer) -> [String] {
        var out: Set<String> = []
        for site in customer.sites {
            // lanBase is e.g. "10.0.0.0" — fold into a /16 if it's just an IP.
            let base = site.lanBase.trimmingCharacters(in: .whitespaces)
            if !base.isEmpty {
                if base.contains("/") {
                    out.insert(base)
                } else if !base.isEmpty {
                    out.insert("\(base)/16")
                }
            }
            for vlan in site.vlans where !vlan.subnet.isEmpty {
                let s = vlan.subnet.trimmingCharacters(in: .whitespaces)
                out.insert(s.contains("/") ? s : "\(s)/24")
            }
        }
        return Array(out).sorted()
    }

    private func hydrate() {
        // Default for "new" engagement = 90 days from now.
        // Set unconditionally so even when there's no existing
        // engagement to hydrate from, expiresAt has a sane value.
        if engagement == nil
            && expiresAt == Date(timeIntervalSinceReferenceDate: 0)
        {
            expiresAt = Date().addingTimeInterval(90 * 86400)
        }
        guard let e = engagement else { return }
        title = e.title
        customerSlug = e.customerSlug
        authorizedBy = e.authorizedBy
        notes = e.notes
        expiresAt = e.expiresAt
        scopeCidrsText = e.scopeCidrs.joined(separator: "\n")
        scopeHostsText = e.scopeHosts.joined(separator: "\n")
        exclusionsText = e.exclusions.joined(separator: "\n")
        allowedTechniques = Set(e.allowedTechniques)
        if let s = e.schedule {
            scheduleEnabled = true
            scheduleCadence = s.cadence
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                .foregroundStyle(.tint)
            Text(engagement == nil ? "New engagement" : "Edit engagement")
                .font(.title3.weight(.semibold))
            Spacer()
        }
        .padding(14)
        .background(.background.secondary)
    }

    private var metaPane: some View {
        Form {
            Section("Engagement") {
                TextField("Title", text: $title)
                    .textFieldStyle(.roundedBorder)
                    .focused($firstFieldFocused)
                customerPicker
                DatePicker("Expires at", selection: $expiresAt, displayedComponents: [.date])
            }
            Section("Authorization") {
                TextField("Authorized by", text: $authorizedBy)
                    .textFieldStyle(.roundedBorder)
                    .help("Name + role of the customer-side authorizer. Surfaces on every report.")
                Text("Future: drag a signed PDF here for hashed-record-of-authorization.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            Section("Recurring scan") {
                Toggle("Enable scheduled active scan", isOn: $scheduleEnabled)
                if scheduleEnabled {
                    Picker("Cadence", selection: $scheduleCadence) {
                        ForEach(ScheduleCadence.allCases) { c in
                            Text(c.label).tag(c)
                        }
                    }
                    Text("First scan fires ~60 s after save. Daemon must be running.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            Section("Notes") {
                TextEditor(text: $notes)
                    .frame(minHeight: 60)
                    .font(.callout)
            }
        }
        .formStyle(.grouped)
        .frame(width: 380)
    }

    private var scopePane: some View {
        // ScrollView so the techniques list + three text editors
        // can't push the footer (Save button) below the sheet's
        // 620-pt fixed height. Before this wrap, the user opened
        // "New engagement" and saw scope panes but no Save button —
        // the button was rendered, just clipped off-screen.
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Scope")
                    .font(.headline)

                VStack(alignment: .leading, spacing: 4) {
                    Text("In-scope CIDRs")
                        .font(.subheadline.weight(.semibold))
                    Text("One per line. Examples: `10.0.0.0/16`, `192.168.50.0/24`")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                    TextEditor(text: $scopeCidrsText)
                        .frame(minHeight: 60)
                        .font(.system(.caption, design: .monospaced))
                        .background(.background.tertiary)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("In-scope hostnames")
                        .font(.subheadline.weight(.semibold))
                    TextEditor(text: $scopeHostsText)
                        .frame(minHeight: 50)
                        .font(.system(.caption, design: .monospaced))
                        .background(.background.tertiary)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Exclusions")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.red)
                    Text("Trumps scope. Critical infrastructure that must not be probed.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                    TextEditor(text: $exclusionsText)
                        .frame(minHeight: 50)
                        .font(.system(.caption, design: .monospaced))
                        .background(.red.opacity(0.05))
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                }

                Divider()

                VStack(alignment: .leading, spacing: 6) {
                    Text("Allowed techniques")
                        .font(.subheadline.weight(.semibold))
                    ForEach(SecurityTechnique.allCases, id: \.self) { tech in
                        Toggle(
                            tech.label,
                            isOn: Binding(
                                get: { allowedTechniques.contains(tech) },
                                set: { on in
                                    if on { allowedTechniques.insert(tech) }
                                    else  { allowedTechniques.remove(tech) }
                                }
                            )
                        )
                        .toggleStyle(.checkbox)
                        .disabled(tech == .wireless || tech == .dosTest)
                        if tech == .wireless || tech == .dosTest {
                            Text("(reserved — not implemented)")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                                .padding(.leading, 22)
                        }
                    }
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var footer: some View {
        HStack {
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            Spacer()
            Button("Cancel") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button(saving ? "Saving…" : "Save") { Task { await save() } }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(saving || title.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(14)
        .background(.background.secondary)
    }

    private func save() async {
        saving = true
        defer { saving = false }
        let parseLines: (String) -> [String] = { text in
            text.split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }
        let payload = Engagement(
            id: engagement?.id ?? "",
            customerSlug: customerSlug.trimmingCharacters(in: .whitespaces),
            title: title.trimmingCharacters(in: .whitespaces),
            scopeCidrs: parseLines(scopeCidrsText),
            scopeHosts: parseLines(scopeHostsText),
            exclusions: parseLines(exclusionsText),
            allowedTechniques: SecurityTechnique.allCases.filter { allowedTechniques.contains($0) },
            startedAt: engagement?.startedAt ?? Date(),
            expiresAt: expiresAt,
            authorizedBy: authorizedBy,
            authorizationDocPath: engagement?.authorizationDocPath,
            log: engagement?.log ?? [],
            notes: notes
        )
        if let saved = await appState.saveEngagement(payload) {
            // Apply schedule via dedicated RPC. Cadence transitions:
            //   off → on    : set
            //   on  → off   : clear
            //   on  → other : set new
            let prevSchedule = engagement?.schedule
            let cadenceChanged = (prevSchedule?.cadence != scheduleCadence)
            if scheduleEnabled && (prevSchedule == nil || cadenceChanged) {
                _ = await appState.setEngagementSchedule(
                    engagementId: saved.id,
                    cadence: scheduleCadence
                )
            } else if !scheduleEnabled && prevSchedule != nil {
                _ = await appState.setEngagementSchedule(
                    engagementId: saved.id,
                    cadence: nil
                )
            }
            appState.selectedEngagementId = saved.id
            dismiss()
        } else {
            error = appState.errorMessage.isEmpty ? "Could not save engagement." : appState.errorMessage
        }
    }
}

#if DEBUG
#Preview("Engagement — new") {
    EngagementEditSheet(engagement: nil)
        .environment(AppState.previewSeeded)
}

#Preview("Engagement — edit") {
    EngagementEditSheet(engagement: .previewActive)
        .environment(AppState.previewSeeded)
}
#endif
