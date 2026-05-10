import SwiftUI

/// Sheet for switching a VPN profile between full-tunnel and
/// split-tunnel mode. Wraps `vpn_set_routing` on the daemon.
///
/// Why a sheet (and not an inline toggle in `VpnDetailView`):
/// switching mode is a non-trivial change with a hard validation
/// (split tunnel REQUIRES at least one route) and a "you must
/// reconnect to apply" follow-up. Modal commit boundary lets the
/// user gather routes, see the warning, and click Save once —
/// rather than a live-mutating toggle that's confusing to undo.
///
/// Supported backends (per the daemon's RPC):
///   • WireGuard — rewrites `WireGuardConfig.split_routes`
///   • FortiGate IKEv2 — rewrites `FortiGateConfig.routes`
///
/// OpenVPN / Azure / Generic backends — daemon refuses the call
/// because routing is encoded inside their imported config files.
/// We disable the toggle for those.
struct EditRoutingSheet: View {
    let profile: VpnProfile
    let onSaved: () -> Void

    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var fullTunnel: Bool = true
    /// Comma-or-newline-separated CIDR list. Parsed at save-time;
    /// blanks are tolerated so the user can paste from a config doc.
    @State private var routesText: String = ""
    @State private var error: String?
    @State private var isSaving = false

    /// Subnet-discovery state. `nil` while idle, populated after
    /// `SubnetDiscovery.sampleConnections()` returns. Empty array
    /// means "scanned, found nothing useful."
    @State private var suggestions: [SubnetDiscovery.Suggestion]?
    @State private var isScanning = false

    var body: some View {
        // Branch at the body root: backends whose routing the daemon
        // can't change get a static info view, not the full editor.
        // Showing the toggle / routes textarea / Save would imply
        // there's something to do here when there isn't.
        if backendSupportsToggle {
            editorBody
        } else {
            unsupportedBody
        }
    }

    /// Empty-state body for OpenVPN / Generic / etc. — just an info
    /// banner pointing at the import flow, plus a Close button.
    private var unsupportedBody: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Tunnel routing")
                .font(.headline)
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "info.circle.fill")
                    .foregroundStyle(.blue)
                Text("Routing for the \(profile.config.backendDisplayName) backend is configured inside the imported `.ovpn` file. To change it, edit the file and re-import the profile.")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    /// Full editor body for backends the daemon can rewrite
    /// (WireGuard, FortiGate IKEv2).
    private var editorBody: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Tunnel routing")
                .font(.headline)

            // Full vs split picker.
            Picker("Mode", selection: $fullTunnel) {
                Text("Full tunnel").tag(true)
                Text("Split tunnel").tag(false)
            }
            .pickerStyle(.segmented)

            // Mode explainer — keeps the implication of each choice
            // visible so a glance answers "which one do I want."
            Text(fullTunnel
                 ? "All traffic goes through the VPN. Default-route style — you appear at the VPN's exit IP for everything."
                 : "Only the routes below go through the VPN. Other traffic uses your normal connection.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            // Routes editor — only meaningful in split mode.
            if !fullTunnel {
                Divider()
                HStack {
                    Text("Routes")
                        .font(.subheadline.weight(.medium))
                    Spacer()
                    // Subnet discovery — sample current TCP/UDP
                    // connections to suggest /24s the user is
                    // actually talking to. Most useful when run
                    // while connected in full-tunnel (then suggested
                    // subnets are ones you actually want over the
                    // VPN).
                    Button {
                        Task { await scanForSuggestions() }
                    } label: {
                        if isScanning {
                            ProgressView()
                                .controlSize(.small)
                                .frame(width: 14, height: 14)
                        } else {
                            Label("Suggest from current traffic",
                                  systemImage: "wand.and.stars")
                        }
                    }
                    .controlSize(.small)
                    .disabled(isScanning)
                }
                Text("CIDR notation, one per line. Examples: `10.0.0.0/8`, `192.168.1.0/24`, `2001:db8::/32`")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextEditor(text: $routesText)
                    .font(.system(.callout, design: .monospaced))
                    .frame(minHeight: 100, maxHeight: 180)
                    .scrollContentBackground(.hidden)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .strokeBorder(.tertiary, lineWidth: 0.5)
                    )

                // Suggestions panel — only renders after a scan.
                // Toggling a row mutates the textarea directly: ON
                // appends the CIDR if missing, OFF removes the line
                // if present. No "Add selected" mid-step — the
                // textarea is the single source of truth, and the
                // checkboxes drive it directly. (Earlier UX put a
                // confirmation step in the way; users tried to Save
                // and got "needs at least one route" because they
                // hadn't clicked Add yet. This way the obvious
                // action — tick — is also the right one.)
                if let suggestions {
                    SuggestionsPanel(
                        suggestions: suggestions,
                        currentRoutes: $routesText
                    )
                }
            }

            if let error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            // Reconnect notice — clear and unmissable, *not* an action.
            // We intentionally don't auto-reconnect on Save because
            // some users will be on a flaky network and want to time
            // it themselves.
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.circle.fill")
                    .foregroundStyle(.orange)
                Text("Disconnect and reconnect to apply the new routing.")
                    .font(.callout)
            }
            .padding(.top, 4)

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Save") { Task { await save() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(isSaving || !backendSupportsToggle)
            }
        }
        .padding(20)
        .frame(width: 480)
        .onAppear { load() }
    }

    /// Whether the daemon will accept `vpn_set_routing` for this
    /// profile's backend. Mirrors the daemon's match arms.
    private var backendSupportsToggle: Bool {
        switch profile.config {
        case .ikev2, .wireguard: return true
        case .openvpn, .azure, .unsupported: return false
        }
    }

    private func load() {
        fullTunnel = profile.fullTunnel
        // Pre-populate with whatever routes the profile currently
        // has, so a user toggling Full→Split sees the historical
        // list (if any) instead of starting blank.
        let routes: [String]
        switch profile.config {
        case .ikev2(let cfg):     routes = cfg.routes
        case .wireguard(let wg):  routes = wg.splitRoutes
        case .openvpn:            routes = []
        case .azure(let az):      routes = az.routes
        case .unsupported:        routes = []
        }
        routesText = routes.joined(separator: "\n")
    }

    /// Run `SubnetDiscovery.sampleConnections` on a background task;
    /// stash result in `suggestions`. Idempotent — repeated clicks
    /// re-scan and replace the list.
    private func scanForSuggestions() async {
        isScanning = true
        defer { isScanning = false }
        suggestions = await SubnetDiscovery.sampleConnections()
    }

    private func save() async {
        isSaving = true
        defer { isSaving = false }
        error = nil

        // Parse the textarea: split on whitespace AND commas, drop
        // blanks. Any trailing comma or stray whitespace from a
        // pasted config doesn't break us.
        let parsedRoutes: [String] = routesText
            .split(whereSeparator: { c in c.isWhitespace || c == "," })
            .map { String($0) }
            .filter { !$0.isEmpty }

        if !fullTunnel && parsedRoutes.isEmpty {
            error = "Split tunnel needs at least one route."
            return
        }

        let ok = await appState.setRouting(
            profileId: profile.id,
            fullTunnel: fullTunnel,
            routes: parsedRoutes
        )
        if ok {
            onSaved()
            dismiss()
        }
        // On failure AppState's global error handler surfaces the
        // daemon's INVALID_PARAMS message; sheet stays open so the
        // user can adjust.
    }
}

private extension VpnProfileConfig {
    /// Human-readable backend name for use in copy.
    var backendDisplayName: String {
        switch self {
        case .ikev2:        return "FortiGate IKEv2"
        case .wireguard:    return "WireGuard"
        case .openvpn:      return "OpenVPN"
        case .azure:        return "Azure VPN (Entra ID)"
        case .unsupported(let s): return s
        }
    }
}

/// Suggestions list. Drawn under the routes textarea after a
/// `SubnetDiscovery.sampleConnections()` finishes. Each row's
/// checkbox toggles the CIDR directly in the parent's routes
/// textarea — tick to add, untick to remove. The textarea is the
/// single source of truth; checkbox state is derived from "is this
/// CIDR currently in the textarea."
///
/// We deliberately do NOT auto-tick suggestions on render — the
/// discovery scan picks up CDN edges (Cloudflare, AWS) that the
/// user almost certainly doesn't want forced through the VPN.
/// Checking is an active choice.
private struct SuggestionsPanel: View {
    let suggestions: [SubnetDiscovery.Suggestion]
    @Binding var currentRoutes: String

    var body: some View {
        if suggestions.isEmpty {
            // Empty-state — happens if the scan ran while no
            // sockets were open. Easy to retry.
            Text("No active connections found. Try connecting in full-tunnel first, then re-scan.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.top, 4)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                Text("Suggested subnets (from active connections)")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                Text("Tick a row to include it; untick to remove.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)

                // Vertical list. Capped height so a machine with
                // hundreds of sockets doesn't take over the sheet.
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(suggestions) { suggestion in
                            Toggle(isOn: bindingFor(suggestion.subnet)) {
                                HStack {
                                    Text(suggestion.subnet)
                                        .font(.system(.callout, design: .monospaced))
                                    Spacer()
                                    Text("\(suggestion.peerCount) peer\(suggestion.peerCount == 1 ? "" : "s")")
                                        .font(.caption)
                                        .foregroundStyle(.tertiary)
                                }
                            }
                            .toggleStyle(.checkbox)
                            .padding(.vertical, 2)
                        }
                    }
                }
                .frame(maxHeight: 140)
                .background(.quaternary.opacity(0.5),
                            in: RoundedRectangle(cornerRadius: 6))
            }
            .padding(.top, 4)
        }
    }

    /// Binding that reads "is `cidr` currently in `currentRoutes`?"
    /// and writes "include or exclude" by editing the textarea text
    /// in-place. Whitespace/comma separators are preserved.
    private func bindingFor(_ cidr: String) -> Binding<Bool> {
        Binding(
            get: { tokens(in: currentRoutes).contains(cidr) },
            set: { isOn in
                var lines = currentRoutes
                    .split(whereSeparator: { c in c.isWhitespace || c == "," })
                    .map(String.init)
                if isOn {
                    if !lines.contains(cidr) { lines.append(cidr) }
                } else {
                    lines.removeAll { $0 == cidr }
                }
                currentRoutes = lines.joined(separator: "\n")
                if !currentRoutes.isEmpty && !currentRoutes.hasSuffix("\n") {
                    currentRoutes.append("\n")
                }
            }
        )
    }

    private func tokens(in text: String) -> Set<String> {
        Set(
            text
                .split(whereSeparator: { c in c.isWhitespace || c == "," })
                .map(String.init)
                .filter { !$0.isEmpty }
        )
    }
}
