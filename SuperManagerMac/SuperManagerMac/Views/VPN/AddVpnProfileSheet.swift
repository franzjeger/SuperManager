import SwiftUI

struct AddVpnProfileSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var host = ""
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
                if !sharedSecret.isEmpty, let pskData = sharedSecret.data(using: .utf8) {
                    try VPNKeychain.set(pskData, account: cfg.psk)
                }
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
