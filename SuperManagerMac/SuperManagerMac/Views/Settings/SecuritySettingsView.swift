import SwiftUI

/// Security pane — master password + auto-lock.
///
/// Layout note: keep the master-password section above auto-lock,
/// because the auto-lock toggle is meaningless without a password set.
/// We disable it (with a `help` tooltip) when the password isn't set,
/// rather than hiding it, so users discover that the dependency exists.
struct SecuritySettingsView: View {
    @State private var settings = AppSettings.shared

    /// Drives the "Set Password" / "Change Password" sheet.
    @State private var showingSetSheet = false
    /// Drives the "Remove Password" confirmation alert.
    @State private var showingRemoveConfirm = false
    /// Surfaces keychain / verification errors to the user.
    @State private var errorMessage: String?
    /// Reflects keychain truth — used to drive button labels and the
    /// auto-lock toggle's enabled state. Refreshed on appear and after
    /// every mutation.
    @State private var passwordIsSet = MasterPassword.isSet

    var body: some View {
        Form {
            Section("Master Password") {
                @Bindable var s = settings
                Toggle("Require master password to use SuperManager",
                       isOn: $s.requireMasterPassword)
                    .help("Locks the app behind a password. Asks on launch and after the auto-lock interval.")
                    .onChange(of: settings.requireMasterPassword) { _, on in
                        // Flipping the toggle drives the right sheet:
                        // ON → prompt to set a password (if none set).
                        // OFF → prompt to confirm removing the password.
                        if on && !passwordIsSet {
                            showingSetSheet = true
                        } else if !on && passwordIsSet {
                            showingRemoveConfirm = true
                        }
                    }

                if passwordIsSet {
                    HStack {
                        Button("Change Password…") {
                            showingSetSheet = true
                        }
                        Button("Remove Password…", role: .destructive) {
                            showingRemoveConfirm = true
                        }
                    }
                    .controlSize(.small)
                }
            }

            Section("Auto-Lock") {
                @Bindable var s = settings
                Picker("Lock app after", selection: $s.autoLockMinutes) {
                    Text("Never").tag(0)
                    Text("1 minute").tag(1)
                    Text("5 minutes").tag(5)
                    Text("15 minutes").tag(15)
                    Text("30 minutes").tag(30)
                    Text("1 hour").tag(60)
                }
                .disabled(!passwordIsSet)
                .help(passwordIsSet
                      ? "Re-prompt for the master password after this period of inactivity."
                      : "Set a master password first to enable auto-lock.")
            }
        }
        .formStyle(.grouped)
        // Set / change sheet
        .sheet(isPresented: $showingSetSheet) {
            SetMasterPasswordSheet(
                isChange: passwordIsSet,
                onSaved: {
                    passwordIsSet = MasterPassword.isSet
                    // Setting a password implies wanting it required —
                    // flip the toggle on if the user reached this sheet
                    // via "Change Password…" button (toggle was already on).
                    if passwordIsSet {
                        settings.requireMasterPassword = true
                    }
                },
                onError: { errorMessage = $0 }
            )
        }
        // Remove-password confirmation
        .alert("Remove master password?",
               isPresented: $showingRemoveConfirm) {
            Button("Cancel", role: .cancel) {
                settings.requireMasterPassword = true   // revert toggle
            }
            Button("Remove", role: .destructive) {
                do {
                    try MasterPassword.remove()
                    passwordIsSet = MasterPassword.isSet
                    settings.requireMasterPassword = false
                } catch {
                    errorMessage = error.localizedDescription
                    settings.requireMasterPassword = true
                }
            }
        } message: {
            Text("Anyone with access to this Mac will be able to open SuperManager and view stored credentials.")
        }
        // Error surface
        .alert("Error",
               isPresented: Binding(
                   get: { errorMessage != nil },
                   set: { if !$0 { errorMessage = nil } }
               )) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
        .onAppear { passwordIsSet = MasterPassword.isSet }
    }
}

/// Sheet for setting or changing the master password.
///
/// In "change" mode (a password is already set) it asks for the current
/// password first and verifies it before accepting the new one. In
/// "set" mode it only collects + confirms a new password.
private struct SetMasterPasswordSheet: View {
    let isChange: Bool
    let onSaved: () -> Void
    let onError: (String) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var currentPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var isWorking = false
    @State private var inlineError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(isChange ? "Change master password" : "Set master password")
                .font(.headline)

            Form {
                if isChange {
                    SecureField("Current password", text: $currentPassword)
                }
                SecureField("New password", text: $newPassword)
                SecureField("Confirm new password", text: $confirmPassword)
            }
            .formStyle(.columns)

            if let inlineError {
                Text(inlineError)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(isChange ? "Change" : "Set") {
                    Task { await save() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!isFormValid || isWorking)
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    private var isFormValid: Bool {
        guard !newPassword.isEmpty, newPassword == confirmPassword else { return false }
        if isChange { return !currentPassword.isEmpty }
        return true
    }

    private func save() async {
        isWorking = true
        defer { isWorking = false }
        inlineError = nil
        do {
            if isChange {
                let ok = try MasterPassword.verify(currentPassword)
                guard ok else {
                    inlineError = "Current password is incorrect."
                    return
                }
            }
            try MasterPassword.set(newPassword)
            onSaved()
            dismiss()
        } catch {
            inlineError = error.localizedDescription
            onError(error.localizedDescription)
        }
    }
}
