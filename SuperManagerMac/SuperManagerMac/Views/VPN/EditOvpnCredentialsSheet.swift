import SwiftUI

/// Sheet for editing the stored username + password on an OpenVPN
/// profile. Reads the current values from DPK, lets the user change
/// them, writes back. Optional fields — leaving both empty deletes
/// the keychain entries (cert-only profiles).
///
/// Why a separate sheet (rather than a panel inside `VpnDetailView`):
/// passwords are a destructive surface — accidentally clicking
/// `SecureField` and typing into it shouldn't update the stored
/// password until the user explicitly hits Save. A modal keeps the
/// commit boundary obvious.
struct EditOvpnCredentialsSheet: View {
    let profileId: String
    let onSaved: () -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var username = ""
    @State private var password = ""
    @State private var error: String?
    @State private var isSaving = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("OpenVPN credentials")
                .font(.headline)

            Text("Stored in the macOS Keychain (Data Protection Keychain). Sent to the privileged helper at connect time only.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Form {
                TextField("Username", text: $username)
                    .textContentType(.username)
                SecureField("Password", text: $password)
                    .textContentType(.password)
            }
            .formStyle(.columns)

            if let error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            HStack {
                Button("Clear stored credentials", role: .destructive) {
                    Task { await clear() }
                }
                .disabled(isSaving)
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    Task { await save() }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(isSaving)
            }
        }
        .padding(20)
        .frame(width: 420)
        .onAppear { load() }
    }

    private func load() {
        // Pre-fill with whatever's already in DPK so the user knows
        // what's stored. Missing values just leave the field empty.
        username = (try? VPNKeychain.getString(account: "vpn/\(profileId)/ovpn-username")) ?? ""
        password = (try? VPNKeychain.getString(account: "vpn/\(profileId)/ovpn-password")) ?? ""
    }

    private func save() async {
        isSaving = true
        defer { isSaving = false }
        error = nil
        do {
            if let userData = username.data(using: .utf8) {
                try VPNKeychain.set(userData, account: "vpn/\(profileId)/ovpn-username")
            }
            if let pwData = password.data(using: .utf8) {
                try VPNKeychain.set(pwData, account: "vpn/\(profileId)/ovpn-password")
            }
            onSaved()
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func clear() async {
        VPNKeychain.delete(account: "vpn/\(profileId)/ovpn-username")
        VPNKeychain.delete(account: "vpn/\(profileId)/ovpn-password")
        onSaved()
        dismiss()
    }
}
