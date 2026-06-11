import SwiftUI
import UniformTypeIdentifiers

/// Detail panel for the Provisioning section. Three-column-feel
/// inside one view:
///
///   1. **Header** — selected customer + site, with quick path
///      back to the customer edit sheet.
///
///   2. **Template + extras form** — the user picks a template
///      from the picker, fills in any one-off variables (PPPoE
///      creds, S2S peer IP, etc.), and clicks Render.
///
///   3. **Output pane** — monospace render result with line
///      numbers, copy-all + save-to-file affordances. Errors
///      from Tera surface here in red.
///
/// We deliberately render *server-side*: the GUI never embeds a
/// template engine. That keeps the render path identical for
/// future use cases (CLI tool, scheduled batch rolls) and means
/// custom user templates work the same way as built-ins without
/// duplicating the Tera dependency on macOS.
struct ProvisioningView: View {
    @Environment(AppState.self) private var appState

    @State private var selectedTemplateId: String?
    @State private var extras: [ExtraField] = []
    @State private var rendering = false
    @State private var renderError: String?
    @State private var rendered: ProvisioningRenderResult?
    @State private var showingAddExtra = false
    @State private var newExtraKey = ""
    @State private var customerToEdit: Customer?
    @State private var showingDiffPreview = false
    @State private var diffPreviewHostId: String?
    @State private var showingExplain = false
    @State private var explainConfigText: String = ""
    @State private var showingReport = false

    private var customer: Customer? {
        appState.customers.first { $0.slug == appState.selectedCustomerSlug }
    }

    private var site: Site? {
        guard let c = customer, let id = appState.selectedSiteId else { return nil }
        return c.sites.first { $0.id == id }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let customer, let site {
                    headerCard(customer: customer, site: site)
                    templateForm(customer: customer)
                    if rendering {
                        renderingCard
                    } else if let err = renderError {
                        errorCard(err)
                    } else if let r = rendered {
                        outputCard(result: r)
                    }
                    // Deployment history — only mounts when the
                    // site has a FortiGate host attached. Same
                    // gating as Preview-diff button so the user
                    // doesn't see a blank "no history" panel
                    // when they haven't picked a target yet.
                    if let hostId = pickFortigateHostId(customer: customer, site: site),
                       let host = appState.sshHosts.first(where: { $0.id == hostId }) {
                        DeploymentHistorySection(hostId: host.id, hostLabel: host.label)
                    }
                } else if customer != nil {
                    selectSitePrompt
                } else {
                    selectCustomerPrompt
                }
            }
            .padding(20)
        }
        .sheet(item: $customerToEdit) { customer in
            CustomerEditSheet(customer: customer)
        }
        .sheet(isPresented: $showingExplain) {
            ExplainConfigSheet(initialConfig: explainConfigText)
        }
        .sheet(isPresented: $showingReport) {
            if let c = customer {
                CustomerReportSheet(
                    customerSlug: c.slug,
                    customerName: c.displayName
                )
            }
        }
        .sheet(isPresented: $showingDiffPreview) {
            if let hostId = diffPreviewHostId,
               let customer,
               let site,
               let templateId = effectiveTemplateId(customer: customer),
               let host = appState.sshHosts.first(where: { $0.id == hostId }) {
                DiffPreviewSheet(
                    hostId: hostId,
                    hostLabel: host.label,
                    templateId: templateId,
                    customerSlug: customer.slug,
                    siteId: site.id,
                    // Carry the same one-off render variables the operator
                    // entered on the form, so the diff + deploy use the exact
                    // config they rendered and reviewed — not one rendered
                    // with empty extras.
                    extras: Dictionary(uniqueKeysWithValues: extras.map { ($0.key, $0.value) })
                )
            }
        }
        .task {
            // Hydrate templates on first appearance.
            if appState.provisioningTemplates.isEmpty {
                await appState.loadProvisioningTemplates()
            }
        }
        // Render output + form inputs are view-local @State on this
        // persistent view. Without resetting them when the operator
        // switches site or customer, the header would show the new
        // selection while Copy / Save / Deploy still acted on the
        // PREVIOUS site's rendered config — worst case deploying site
        // A's config to site B. Clear the stale state on every switch.
        .onChange(of: appState.selectedSiteId) { _, _ in resetRenderState() }
        .onChange(of: appState.selectedCustomerSlug) { _, _ in resetRenderState() }
    }

    /// Wipe everything derived from the previously-selected site so a
    /// fresh selection starts clean. Called on site/customer switch.
    private func resetRenderState() {
        selectedTemplateId = nil
        extras = []
        rendered = nil
        renderError = nil
        rendering = false
    }

    // MARK: - Empty states

    private var selectCustomerPrompt: some View {
        VStack(spacing: 12) {
            Image(systemName: "wand.and.stars")
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)
            Text("Select a customer to begin")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var selectSitePrompt: some View {
        VStack(spacing: 12) {
            Image(systemName: "mappin.and.ellipse")
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)
            Text("Select a site under \(customer?.displayName ?? "this customer")")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Header

    private func headerCard(customer: Customer, site: Site) -> some View {
        HStack(alignment: .top, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text(customer.displayName)
                    .font(.title2.weight(.semibold))
                Text(site.displayName)
                    .font(.title3)
                    .foregroundStyle(.secondary)
                if !site.address.isEmpty {
                    Text(site.address)
                        .font(.callout)
                        .foregroundStyle(.tertiary)
                }
                HStack(spacing: 12) {
                    metaTile(label: "WAN", value: site.wanType.uppercased())
                    metaTile(label: "LAN", value: site.lanBase.isEmpty ? "—" : site.lanBase)
                    metaTile(label: "VLANs", value: "\(site.vlans.count)")
                    metaTile(label: "Hosts", value: "\(site.hostIds.count)")
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 6) {
                Button {
                    customerToEdit = customer
                } label: {
                    Label("Edit customer…", systemImage: "pencil")
                }
                .controlSize(.small)
                Button {
                    showingReport = true
                } label: {
                    Label("Generate report…", systemImage: "doc.text")
                }
                .controlSize(.small)
                .help("Aggregate site map + per-host compliance + deployment history into a customer-facing Markdown report.")
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(.separator, lineWidth: 0.5)
        )
    }

    private func metaTile(label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label)
                .font(.caption2)
                .foregroundStyle(.tertiary)
            Text(value)
                .font(.callout.weight(.medium))
                .monospacedDigit()
        }
    }

    // MARK: - Template form

    private func templateForm(customer: Customer) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Template")
                    .font(.headline)
                Spacer()
                Picker("", selection: Binding(
                    get: { selectedTemplateId ?? customer.defaultTemplate ?? appState.provisioningTemplates.first?.id ?? "" },
                    set: { selectedTemplateId = $0 }
                )) {
                    ForEach(appState.provisioningTemplates) { tmpl in
                        Text("\(tmpl.displayName)\(tmpl.builtIn ? "" : " · custom")")
                            .tag(tmpl.id)
                    }
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .frame(minWidth: 280)
            }

            if let chosen = chosenTemplate() {
                Text(chosen.description)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // Extras: free-form key=value rows. Persist nowhere
            // — they're rendering-time inputs only. To preserve
            // them long-term, the user adds the value as a site
            // field in customer edit.
            if !extras.isEmpty {
                Divider()
                Text("Extras")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                ForEach(extras.indices, id: \.self) { i in
                    HStack {
                        Text(extras[i].key)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .frame(width: 140, alignment: .leading)
                        TextField("value", text: Binding(
                            get: { extras[i].value },
                            set: { extras[i].value = $0 }
                        ))
                        Button {
                            extras.remove(at: i)
                        } label: {
                            Image(systemName: "minus.circle")
                                .foregroundStyle(.red)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Remove extra")
                    }
                }
            }
            HStack(spacing: 8) {
                if showingAddExtra {
                    TextField("extra_key", text: $newExtraKey)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 200)
                    Button("Add") {
                        let trimmed = newExtraKey.trimmingCharacters(in: .whitespaces)
                        if !trimmed.isEmpty {
                            extras.append(ExtraField(key: trimmed, value: ""))
                            newExtraKey = ""
                            showingAddExtra = false
                        }
                    }
                    Button("Cancel") {
                        newExtraKey = ""
                        showingAddExtra = false
                    }
                } else {
                    Button {
                        showingAddExtra = true
                    } label: {
                        Label("Add template variable…", systemImage: "plus")
                    }
                    .controlSize(.small)
                    .help("Add a custom key/value pair the template can interpolate via {{ extra.key }}. Useful for tenant-specific values not in the standard schema (NTP server, syslog target, etc.).")
                }
                Spacer()
                if let activeSite = site {
                    Button {
                        diffPreviewHostId = pickFortigateHostId(customer: customer, site: activeSite)
                        if diffPreviewHostId != nil {
                            showingDiffPreview = true
                        }
                    } label: {
                        Label("Preview diff…", systemImage: "arrow.triangle.branch")
                    }
                    .controlSize(.large)
                    .disabled(rendering || effectiveTemplateId(customer: customer) == nil
                              || pickFortigateHostId(customer: customer, site: activeSite) == nil)
                }
                Button {
                    Task { await render() }
                } label: {
                    if rendering {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Rendering…")
                        }
                    } else {
                        Label("Render", systemImage: "play.fill")
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(rendering || effectiveTemplateId(customer: customer) == nil)
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(.separator, lineWidth: 0.5)
        )
    }

    private func chosenTemplate() -> ProvisioningTemplate? {
        let id = selectedTemplateId ?? customer?.defaultTemplate ?? appState.provisioningTemplates.first?.id
        return appState.provisioningTemplates.first { $0.id == id }
    }

    /// The template id that would be used if Render were clicked.
    /// nil only when the library is empty (no built-ins, no user
    /// templates) — which would be a packaging bug, not user
    /// error. Used to gate the Render button enable/disable.
    private func effectiveTemplateId(customer: Customer) -> String? {
        selectedTemplateId
            ?? customer.defaultTemplate
            ?? appState.provisioningTemplates.first?.id
    }

    /// Pick the first FortiGate host attached to the site, or
    /// fall back to any FortiGate host owned by the customer.
    /// Diff/deploy needs an actual device target — without one,
    /// the buttons stay disabled.
    private func pickFortigateHostId(customer: Customer, site: Site) -> String? {
        // Prefer site-attached hosts. Resolve each Site.hostIds token through
        // the HostIndex: the token is usually an IP (what the discovery/
        // autodetect writers store), not a record id, so a raw `$0.id ==
        // hostId` match never resolved an auto-discovered FortiGate — which
        // is what kept Preview-diff/deploy permanently disabled for them.
        for token in site.hostIds {
            if let host = appState.hostIndex.host(forToken: token),
               host.deviceType == .fortigate {
                return host.id
            }
        }
        // Fall back to any FortiGate the customer's other sites
        // have attached. Lets a user with a single FortiGate at
        // multiple sites (uncommon but happens with shared HQ
        // gateways) deploy without explicit attachment.
        for s in customer.sites {
            for token in s.hostIds {
                if let host = appState.hostIndex.host(forToken: token),
                   host.deviceType == .fortigate {
                    return host.id
                }
            }
        }
        return nil
    }

    private func hasFortigateHost(in customer: Customer) -> Bool {
        customer.sites
            .flatMap(\.hostIds)
            .contains { token in
                appState.hostIndex.host(forToken: token)?.deviceType == .fortigate
            }
    }

    // MARK: - Output

    private var renderingCard: some View {
        HStack {
            ProgressView()
            Text("Calling daemon to render template…")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
    }

    private func errorCard(_ err: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Render failed", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.red)
            ScrollView {
                Text(err)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(maxHeight: 200)
            .padding(8)
            .background(.red.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.background.secondary)
        )
    }

    private func outputCard(result: ProvisioningRenderResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Rendered output", systemImage: "doc.text")
                    .font(.headline)
                Spacer()
                Text("\(result.output.split(separator: "\n").count) lines · \(result.output.count) chars")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(result.output, forType: .string)
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                .controlSize(.small)
                Button {
                    saveOutputToFile(result: result)
                } label: {
                    Label("Save…", systemImage: "square.and.arrow.down")
                }
                .controlSize(.small)
                if AppSettings.shared.hasAnthropicKey {
                    Button {
                        explainConfigText = result.output
                        showingExplain = true
                    } label: {
                        Label("Explain", systemImage: "sparkles")
                    }
                    .controlSize(.small)
                    .help("Send this rendered config to Claude for a plain-English explanation.")
                }
            }
            ScrollView([.horizontal, .vertical]) {
                Text(result.output)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 480)
            .background(.black.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(.separator, lineWidth: 0.5)
        )
    }

    // MARK: - Actions

    private func render() async {
        guard let customer, let site else { return }
        let templateId = selectedTemplateId
            ?? customer.defaultTemplate
            ?? appState.provisioningTemplates.first?.id
        guard let templateId else { return }
        rendering = true
        renderError = nil
        rendered = nil
        defer { rendering = false }
        let extrasDict = Dictionary(uniqueKeysWithValues: extras.map { ($0.key, $0.value) })
        if let result = await appState.renderProvisioningTemplate(
            templateId: templateId,
            customerSlug: customer.slug,
            siteId: site.id,
            extras: extrasDict
        ) {
            rendered = result
        } else {
            renderError = appState.errorMessage.isEmpty
                ? "Unknown render error."
                : appState.errorMessage
        }
    }

    private func saveOutputToFile(result: ProvisioningRenderResult) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [
            UTType(filenameExtension: "conf") ?? .plainText,
            .plainText,
        ]
        let safeName = (customer?.slug ?? "customer")
            .replacingOccurrences(of: "/", with: "-")
        panel.nameFieldStringValue = "\(safeName)-\(result.templateId).conf"
        panel.title = "Save rendered configuration"
        if panel.runModal() == .OK, let url = panel.url {
            try? result.output.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}

private struct ExtraField {
    var key: String
    var value: String
}
