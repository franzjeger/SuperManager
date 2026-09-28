import SwiftUI

struct AddVpnProfileSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var host = ""
    @State private var localId = ""
    @State private var username = ""
    @State private var password = ""
    @State private var sharedSecret = ""
    @State private var fullTunnel = true
    @State private var killSwitch = false
    @State private var dnsServers = ""
    @State private var splitRoutes = ""

    @State private var saving = false
    @State private var error: String?

    var body: some View {
        VStack(spacing: 0) {
            // Sheet title — without it the form just starts at
            // "Profile" and there's no signal what kind of profile
            // this sheet creates (the dropdown that opens it is
            // narrower than the sheet itself).
            HStack(spacing: 10) {
                Image(systemName: "lock.shield.fill")
                    .foregroundStyle(.tint)
                    .font(.title2)
                Text("New IKEv2 profile")
                    .font(.title2.weight(.semibold))
                Spacer()
            }
            .padding(.horizontal, 22)
            .padding(.top, 18)
            .padding(.bottom, 6)

            Form {
                Section("Profile") {
                    TextField("Name", text: $name)
                    TextField("Server", text: $host, prompt: Text("vpn.example.com"))
                    TextField("Local ID", text: $localId, prompt: Text("e.g. sybr-porsgrunn"))
                    Text("IKE identity (IDi). Leave blank to use the connection IP. Needed when a gateway routes multiple dial-up tunnels on one IP by peer ID.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Credentials") {
                    TextField("Username", text: $username)
                    SecureField("Password (EAP)", text: $password)
                    SecureField("Shared Secret (PSK)", text: $sharedSecret)
                    Text("Leave the shared secret blank for certificate-based servers.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Routing") {
                    Toggle("Route all traffic through VPN", isOn: $fullTunnel)
                    Toggle("Block non-VPN traffic (kill switch)", isOn: $killSwitch)
                    TextField("DNS servers (comma-separated IPs)", text: $dnsServers)
                    if !fullTunnel {
                        TextField("Split-tunnel routes (comma-separated CIDRs)", text: $splitRoutes)
                    }
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button(saving ? "Saving…" : "Add") {
                    Task { await save() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(saving || name.isEmpty || host.isEmpty || username.isEmpty || password.isEmpty)
            }
            .padding(12)
        }
        .frame(minWidth: 520, minHeight: 460)
    }

    private func save() async {
        saving = true
        error = nil
        defer { saving = false }

        let dns = dnsServers.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let routes = splitRoutes.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }

        // Add is now cheap and reversible: we persist the profile to the
        // user-space daemon and stash credentials in the login Keychain,
        // and exit. No admin auth, no system writes, no orphan-leaving
        // paths. Actual VPN bring-up happens when the user clicks Connect
        // on the detail view, which delegates to the privileged helper.
        var createdProfileId: String?
        do {
            let profile: VpnProfile = try await appState.client.call(
                "vpn_add_ikev2_profile",
                params: [
                    "name": name,
                    "host": host,
                    "username": username,
                    "local_id": localId.trimmingCharacters(in: .whitespacesAndNewlines),
                    "full_tunnel": fullTunnel,
                    "kill_switch": killSwitch,
                    "dns_servers": dns,
                    "routes": routes,
                ]
            )
            createdProfileId = profile.id

            if case .ikev2(let cfg) = profile.config {
                if let pwData = password.data(using: .utf8) {
                    try VPNKeychain.set(pwData, account: cfg.password)
                }
                // Persist an empty value too: it records the user's choice
                // of certificate authentication, distinct from a lost PSK.
                try VPNKeychain.set(Data(sharedSecret.utf8), account: cfg.psk)
            }

            // No system-level write here — the privileged helper handles the
            // VPN bring-up when the user clicks Connect on the detail view.
            await appState.refreshProfiles()
            appState.selectedProfileId = profile.id
            dismiss()
        } catch {
            if let pid = createdProfileId {
                _ = try? await appState.client.callVoid(
                    "vpn_delete_profile", params: ["id": pid]
                )
                VPNKeychain.deleteAll(profileId: pid)
            }
            self.error = error.localizedDescription
        }
    }
}

// MARK: - Edit existing IKEv2 profile

/// Editor for an existing IKEv2 profile. Mirrors `AddVpnProfileSheet` but
/// pre-fills every field from the loaded profile and persists via
/// `vpn_update_ikev2_profile` (name / server / username / routing) plus
/// the login Keychain (EAP password + PSK).
///
/// Secrets are never displayed: the two secure fields start blank and are
/// only written when the user types a replacement, so a blank field means
/// "keep the stored secret". Lives in this file rather than its own so it
/// doesn't need a manual pbxproj registration (the project has no
/// file-system-synchronized groups).
struct EditVpnProfileSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    let profile: VpnProfile
    let missingCredentials: VPNKeychain.MissingIKEv2Credentials?
    /// Invoked after a successful save so the detail view can reload the
    /// daemon-stored profile (host / username / routing all live there).
    var onSaved: () -> Void

    @State private var name: String
    @State private var host: String
    @State private var localId: String
    @State private var username: String
    @State private var password = ""        // blank = keep current
    @State private var sharedSecret = ""    // blank = keep current
    @State private var fullTunnel: Bool
    @State private var killSwitch: Bool
    @State private var dnsServers: String
    @State private var splitRoutes: String

    @State private var saving = false
    @State private var error: String?

    init(profile: VpnProfile,
         missingCredentials: VPNKeychain.MissingIKEv2Credentials? = nil,
         onSaved: @escaping () -> Void) {
        self.profile = profile
        self.missingCredentials = missingCredentials
        self.onSaved = onSaved
        _name = State(initialValue: profile.name)
        _fullTunnel = State(initialValue: profile.fullTunnel)
        _killSwitch = State(initialValue: profile.killSwitch)
        if case .ikev2(let cfg) = profile.config {
            _host = State(initialValue: cfg.host)
            _username = State(initialValue: cfg.username)
            _localId = State(initialValue: cfg.localId)
            _dnsServers = State(initialValue: cfg.dnsServers.joined(separator: ", "))
            _splitRoutes = State(initialValue: cfg.routes.joined(separator: ", "))
        } else {
            // Non-IKEv2 profiles never reach this sheet (the menu entry is
            // gated on `.ikev2`), but initialise cleanly so the struct is
            // always in a valid state.
            _host = State(initialValue: "")
            _username = State(initialValue: "")
            _localId = State(initialValue: "")
            _dnsServers = State(initialValue: "")
            _splitRoutes = State(initialValue: "")
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "lock.shield.fill")
                    .foregroundStyle(.tint)
                    .font(.title2)
                Text(missingCredentials == nil ? "Edit IKEv2 profile" : "Restore VPN credentials")
                    .font(.title2.weight(.semibold))
                Spacer()
            }
            .padding(.horizontal, 22)
            .padding(.top, 18)
            .padding(.bottom, 6)

            Form {
                Section("Profile") {
                    TextField("Name", text: $name)
                    TextField("Server", text: $host, prompt: Text("vpn.example.com"))
                    TextField("Local ID", text: $localId, prompt: Text("e.g. sybr-porsgrunn"))
                    Text("IKE identity (IDi). Leave blank to use the connection IP. Needed when a gateway routes multiple dial-up tunnels on one IP by peer ID.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Credentials") {
                    if let missingCredentials {
                        Text("This profile is missing credentials on this Mac. Re-enter them below, save, then connect again.")
                            .font(.callout)
                        if missingCredentials.sharedSecret {
                            Text("Enter the shared secret if your VPN uses one. Leave it blank only if the server uses certificate authentication.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    TextField("Username", text: $username)
                    SecureField("New password (EAP)", text: $password)
                    SecureField("New shared secret (PSK)", text: $sharedSecret)
                    Text("Existing credentials are kept unless you enter a replacement.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Routing") {
                    Toggle("Route all traffic through VPN", isOn: $fullTunnel)
                    Toggle("Block non-VPN traffic (kill switch)", isOn: $killSwitch)
                    TextField("DNS servers (comma-separated IPs)", text: $dnsServers)
                    if !fullTunnel {
                        TextField("Split-tunnel routes (comma-separated CIDRs)", text: $splitRoutes)
                    }
                }

                if let error {
                    Section { Text(error).foregroundStyle(.red) }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button(saving ? "Saving…" : "Save") {
                    Task { await save() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(saving || name.isEmpty || host.isEmpty || username.isEmpty
                          || (missingCredentials?.password == true && password.isEmpty))
            }
            .padding(12)
        }
        .frame(minWidth: 520, minHeight: 460)
    }

    private func save() async {
        saving = true
        error = nil
        defer { saving = false }

        let dns = dnsServers.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let routes = splitRoutes.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }

        do {
            // Persist profile metadata. The daemon preserves any field we
            // omit, but we send them all so the form is the single source
            // of truth. `routes` only takes effect in split mode; sending
            // it in full-tunnel mode is harmless (the daemon templates it
            // only when full_tunnel is false).
            let updated: VpnProfile = try await appState.client.call(
                "vpn_update_ikev2_profile",
                params: [
                    "id": profile.id,
                    "name": name,
                    "host": host,
                    "username": username,
                    "local_id": localId.trimmingCharacters(in: .whitespacesAndNewlines),
                    "full_tunnel": fullTunnel,
                    "kill_switch": killSwitch,
                    "dns_servers": dns,
                    "routes": routes,
                ]
            )

            // Secrets live in the login Keychain, not the daemon store.
            // Only overwrite when the user actually typed a replacement.
            // Use the account labels from the freshly-returned config so we
            // always write the exact items the helper reads at connect.
            if case .ikev2(let cfg) = updated.config {
                if !password.isEmpty, let pw = password.data(using: .utf8) {
                    try VPNKeychain.set(pw, account: cfg.password)
                }
                if !sharedSecret.isEmpty || missingCredentials?.sharedSecret == true {
                    try VPNKeychain.set(Data(sharedSecret.utf8), account: cfg.psk)
                }
            }

            await appState.refreshProfiles()
            onSaved()
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
