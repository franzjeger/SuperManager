import SwiftUI

/// Focused two-field sheet for editing the IKEv2 EAP username +
/// password on an existing profile. Triggered from the inline
/// "Edit credentials" button in the VPN detail view's
/// auth-failure toast.
///
/// Why a separate sheet (vs sending the operator into the full
/// profile editor): the auth-failure path is high-friction
/// already — they just tried Connect, got rejected, and need to
/// fix one of two values and try again. A focused sheet keeps
/// every other field of the profile invisible so a typo in the
/// host or routes can't sneak in alongside the credential fix.
///
/// Persistence:
///   - Username goes through `vpn_update_ikev2_profile`
///     (engine rewrites the profile TOML server-side).
///   - Password is written directly into the macOS Data
///     Protection Keychain under the existing label that
///     `cfg.password` refers to — same path the original
///     AddVpnProfileSheet uses, so no migration concerns.
///
/// On save the parent view's `onSaved` callback fires which
/// triggers an auto-reconnect. The whole point of this sheet
/// is "fix the typo and try again" — making the operator click
/// Connect manually after saving would be a UX miss.
struct IkeCredentialsEditSheet: View {
    let profileId: String
    let profileName: String
    let currentUsername: String
    let onSaved: () -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    @State private var username: String
    @State private var password: String = ""
    @State private var keepExistingPassword: Bool = true
    @State private var error: String?
    @State private var isSaving = false

    init(
        profileId: String,
        profileName: String,
        currentUsername: String,
        onSaved: @escaping () -> Void
    ) {
        self.profileId = profileId
        self.profileName = profileName
        self.currentUsername = currentUsername
        self.onSaved = onSaved
        _username = State(initialValue: currentUsername)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "person.crop.circle.badge.exclamationmark")
                    .foregroundStyle(.orange)
                    .imageScale(.large)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Fix \(profileName) credentials")
                        .font(.headline)
                    Text("Server rejected the last attempt. Re-enter username + password (case matters), then we'll auto-reconnect.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Form {
                TextField("Username", text: $username)
                    .textContentType(.username)
                if currentUsername != username {
                    HStack(spacing: 4) {
                        Image(systemName: "info.circle")
                        Text("Changed from `\(currentUsername)`")
                            .font(.caption.monospaced())
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                Toggle("Keep existing password", isOn: $keepExistingPassword)
                    .help("If only the username case was wrong, leave this on.")
                if !keepExistingPassword {
                    SecureField("New password", text: $password)
                        .textContentType(.password)
                }
            }
            .formStyle(.columns)

            if let error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(isSaving ? "Saving…" : "Save & reconnect") {
                    Task { await save() }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(isSaving || username.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private func save() async {
        isSaving = true
        defer { isSaving = false }
        error = nil

        // Persist the password update first (keychain). If the
        // operator left "Keep existing password" on, skip this
        // step entirely so we don't blank a known-good password
        // with an empty string by accident.
        if !keepExistingPassword {
            do {
                guard let data = password.data(using: .utf8) else {
                    error = "Password contains characters that can't be UTF-8 encoded."
                    return
                }
                // Mirrors the label IKEv2Config.password points
                // at — `vpn/<id>/password`. The engine looks
                // this up by name at connect time.
                try VPNKeychain.set(data, account: "vpn/\(profileId)/password")
            } catch {
                self.error = "Couldn't write password to keychain: \(error.localizedDescription)"
                return
            }
        }

        // Persist the username update via the engine. Even if
        // the value didn't change, calling the RPC is cheap and
        // forces a profile re-load so any other stale state
        // gets refreshed before the auto-reconnect.
        do {
            let _: [String: AnyDecodable] = try await appState.client.call(
                "vpn_update_ikev2_profile",
                params: [
                    "id": profileId,
                    "username": username,
                ]
            )
        } catch {
            self.error = "Couldn't update profile: \(error.localizedDescription)"
            return
        }

        onSaved()
        dismiss()
    }
}

/// Tiny Any-wrapper for decoding the engine's update-RPC
/// response when we only care that the call succeeded — the
/// returned profile body is unused here.
private struct AnyDecodable: Decodable {
    init(from decoder: Decoder) throws {
        // No-op — we never read the value.
        _ = try decoder.singleValueContainer()
    }
}
