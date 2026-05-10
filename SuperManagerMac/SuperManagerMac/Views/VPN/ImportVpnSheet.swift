import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Sheet for importing an existing VPN profile from a file.
///
/// Two paths today:
///   • **WireGuard** — `.conf` (INI). Daemon parses, stores private
///     key and per-peer PSKs in its secret store, persists profile.
///   • **OpenVPN** — `.ovpn` (OpenVPN's own directive format). Daemon
///     stashes the raw file under `<data_dir>/ovpn/<id>.ovpn` and
///     records minimal metadata. If the .ovpn declares
///     `auth-user-pass`, we collect username + password here and
///     stash them in the Data Protection Keychain so connect can
///     send them to the privileged helper.
///
/// We don't try to auto-detect the format from file content. The
/// extensions are reliable, and the user explicitly picks a "WireGuard
/// (.conf)" or "OpenVPN (.ovpn)" file in the open panel — that's
/// clearer than a heuristic that gets it wrong on the third edge case.
struct ImportVpnSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var selectedFile: URL?
    @State private var selectedFormat: Format = .wireguard
    @State private var profileName: String = ""
    @State private var error: String?
    @State private var isImporting = false

    // OpenVPN credentials. Only collected for the OpenVPN format and
    // only if the .ovpn declares `auth-user-pass`. Auto-detected
    // when the user picks a file (see `pickFile`).
    @State private var ovpnRequiresAuth = false
    @State private var ovpnUsername = ""
    @State private var ovpnPassword = ""

    enum Format: String, CaseIterable, Identifiable {
        case wireguard = "WireGuard"
        case openvpn   = "OpenVPN"
        // Microsoft's `.azurevpnconfig` (XML) — what the Azure
        // portal hands you for a Point-to-Site Entra-ID VPN. We
        // parse it server-side and store as the AzureVpn variant;
        // connect renders an OpenVPN body on the fly so the
        // existing helper handles the actual tunnel.
        case azure     = "Azure"

        var id: String { rawValue }

        var fileExtension: String {
            switch self {
            case .wireguard: return "conf"
            case .openvpn:   return "ovpn"
            case .azure:     return "azurevpnconfig"
            }
        }

        var description: String {
            switch self {
            case .wireguard:
                return "WireGuard `.conf` (INI format). Private keys and per-peer pre-shared keys are extracted and stored in the macOS Keychain."
            case .openvpn:
                return "OpenVPN `.ovpn` directive file. Saved as-is; if the file declares `auth-user-pass`, we'll prompt for the credentials here and store them in the Keychain."
            case .azure:
                return "Microsoft Azure VPN Client `.azurevpnconfig` (XML). Downloaded from the Azure portal under Virtual Network Gateway → Point-to-site → Download VPN client. Tip: if your file is greyed out in the file dialog, click the file-type popup and choose \"All files\"."
            }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Import VPN profile")
                .font(.headline)

            // Format picker.
            Picker("Format", selection: $selectedFormat) {
                ForEach(Format.allCases) { f in
                    Text(f.rawValue).tag(f)
                }
            }
            .pickerStyle(.segmented)
            .onChange(of: selectedFormat) { _, _ in
                // Clear file selection if the user changes format —
                // .conf isn't valid for OpenVPN and vice versa.
                selectedFile = nil
                ovpnRequiresAuth = false
                ovpnUsername = ""
                ovpnPassword = ""
            }

            Text(selectedFormat.description)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            // File picker row.
            HStack {
                if let url = selectedFile {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(url.lastPathComponent)
                            .fontWeight(.medium)
                        Text(url.deletingLastPathComponent().path)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("No file selected")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Choose…") { pickFile() }
            }

            // Profile name. Pre-populated from the filename without
            // extension when the user picks a file.
            TextField("Profile name", text: $profileName)
                .textFieldStyle(.roundedBorder)

            // OpenVPN auth-user-pass section. Shown when:
            //   - format is OpenVPN
            //   - file is selected
            //   - file's content declared `auth-user-pass`
            //
            // We don't disable Import without creds — some users have
            // their creds in `auth-user-pass <file>` already and just
            // want the profile imported. The hint text below the
            // fields clarifies what we'll do with what they enter.
            if selectedFormat == .openvpn && ovpnRequiresAuth {
                Divider()
                Text("Authentication")
                    .font(.subheadline.weight(.medium))
                TextField("Username", text: $ovpnUsername)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.username)
                SecureField("Password", text: $ovpnPassword)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.password)
                Text("This profile uses `auth-user-pass`. Credentials are stored in the macOS Keychain and only sent to the privileged helper at connect time.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            // Action buttons.
            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Import") {
                    Task { await runImport() }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!canImport || isImporting)
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private var canImport: Bool {
        selectedFile != nil
            && !profileName.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.title = "Choose a \(selectedFormat.rawValue) configuration"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        // Build the allow-list per format. `.azurevpnconfig` isn't a
        // registered UTI on macOS so `UTType(filenameExtension:)`
        // returns a `dyn.…` placeholder that the picker treats as
        // "nothing matches" and greys out every file. Adding `.xml`
        // (the actual content type) plus `.data` (the wildcard) makes
        // the file selectable.
        var types: [UTType] = []
        if let utt = UTType(filenameExtension: selectedFormat.fileExtension) {
            types.append(utt)
        }
        if selectedFormat == .azure {
            types.append(.xml)
        }
        types.append(.data)
        panel.allowedContentTypes = types
        guard panel.runModal() == .OK, let url = panel.url else { return }
        selectedFile = url
        // Default the profile name to the filename stem so the user
        // doesn't have to type something they already have.
        if profileName.isEmpty {
            profileName = url.deletingPathExtension().lastPathComponent
        }
        // For OpenVPN, peek into the file to see whether it needs
        // creds. `auth-user-pass` (without an arg) means OpenVPN will
        // prompt at connect time; with an arg it points at a creds
        // file we don't want to inherit. We treat both as "asks the
        // user for creds" and surface the username/password fields.
        if selectedFormat == .openvpn,
           let body = try? String(contentsOf: url, encoding: .utf8) {
            ovpnRequiresAuth = bodyDeclaresAuthUserPass(body)
        }
    }

    /// Detect `auth-user-pass` directive in an OpenVPN config body.
    /// Tolerant of leading whitespace and inline comments. Doesn't
    /// distinguish between bare `auth-user-pass` and
    /// `auth-user-pass <path>` — both signal "this profile expects
    /// credentials," and we always handle them by sending creds via
    /// the helper rather than inheriting any external file.
    private func bodyDeclaresAuthUserPass(_ body: String) -> Bool {
        body.split(separator: "\n").contains { line in
            let trimmed = line.split(separator: "#").first ?? line[...]
            return trimmed.trimmingCharacters(in: .whitespaces)
                .hasPrefix("auth-user-pass")
        }
    }

    private func runImport() async {
        guard let url = selectedFile else { return }
        isImporting = true
        defer { isImporting = false }
        error = nil

        let content: String
        do {
            content = try String(contentsOf: url, encoding: .utf8)
        } catch {
            self.error = "Couldn't read file: \(error.localizedDescription)"
            return
        }

        let trimmedName = profileName.trimmingCharacters(in: .whitespaces)
        let imported: String?
        switch selectedFormat {
        case .wireguard:
            imported = await appState.importWireguard(name: trimmedName, content: content)
        case .openvpn:
            imported = await appState.importOpenVPN(name: trimmedName, content: content)
            // If the user supplied creds, store them in DPK against
            // the new profile id. Same account-name format as the
            // helper uses to look them up at connect time.
            if let id = imported, ovpnRequiresAuth,
               !ovpnUsername.isEmpty, !ovpnPassword.isEmpty {
                do {
                    if let userData = ovpnUsername.data(using: .utf8) {
                        try VPNKeychain.set(userData, account: "vpn/\(id)/ovpn-username")
                    }
                    if let pwData = ovpnPassword.data(using: .utf8) {
                        try VPNKeychain.set(pwData, account: "vpn/\(id)/ovpn-password")
                    }
                } catch {
                    // Don't fail the whole import — creds can be
                    // re-entered via Edit Credentials later. Surface
                    // the keychain error so it's not silent.
                    self.error = "Profile imported, but storing credentials failed: \(error.localizedDescription)"
                    return
                }
            }
        case .azure:
            // Call the daemon directly here so a parse / validation
            // error from `vpn_import_azure` shows up *in the sheet*
            // rather than only as a global alert behind it. The
            // user can read what the daemon rejected and edit the
            // file before retrying.
            do {
                let profile: VpnProfile = try await appState.client.call(
                    "vpn_import_azure",
                    params: ["name": trimmedName, "content": content]
                )
                await appState.refreshProfiles()
                imported = profile.id
            } catch {
                self.error = "Couldn't import Azure config: \(error.localizedDescription)"
                return
            }
        }

        if let id = imported {
            appState.selectedProfileId = id
            dismiss()
        }
        // On failure, AppState surfaces the error via its global error
        // handler — but we also keep the sheet open so the user can
        // inspect the file path / format and retry.
    }
}
