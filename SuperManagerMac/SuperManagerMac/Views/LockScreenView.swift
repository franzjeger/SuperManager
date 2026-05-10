import SwiftUI

/// Full-window overlay shown when the app is locked behind the master
/// password. While `LockState.shared.isLocked == true`, the main UI is
/// blurred / replaced and only this view is interactive — preventing
/// accidental actions through keyboard shortcuts (Cmd+W, Cmd+Q still
/// work; that's by design — the user is supposed to be able to walk
/// away from a locked app).
struct LockScreenView: View {
    @State private var password = ""
    @State private var error: String?
    @State private var isVerifying = false

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.fill")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(.tint)

            Text("SuperManager is locked")
                .font(.title2.weight(.semibold))

            Text("Enter your master password to continue.")
                .font(.callout)
                .foregroundStyle(.secondary)

            SecureField("Master password", text: $password)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
                .onSubmit { Task { await unlock() } }

            if let error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            Button {
                Task { await unlock() }
            } label: {
                if isVerifying {
                    ProgressView()
                        .controlSize(.small)
                        .frame(maxWidth: 320)
                } else {
                    Text("Unlock")
                        .frame(maxWidth: 320)
                }
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .disabled(password.isEmpty || isVerifying)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // Standard window background. We don't need translucency
        // tricks — RootView only builds this view (and never
        // ContentView) when locked, so there's nothing underneath
        // to bleed through.
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func unlock() async {
        guard !password.isEmpty, !isVerifying else { return }
        isVerifying = true
        defer { isVerifying = false }
        do {
            // PBKDF2 verification is intentionally slow (~250 ms);
            // run on a background thread so the spinner can render.
            let pwd = password
            let ok = try await Task.detached(priority: .userInitiated) {
                try MasterPassword.verify(pwd)
            }.value
            if ok {
                LockState.shared.unlock()
                password = ""
                error = nil
            } else {
                error = "Incorrect password."
                password = ""
            }
        } catch {
            self.error = error.localizedDescription
        }
    }
}

/// In-memory lock state. Owned process-globally; nothing about lock
/// state is persisted, by design — closing the app re-locks it.
///
/// `@Observable` so we can drive `if isLocked { LockScreenView() }` in
/// `ContentView` without having to plumb a binding through every layer.
@Observable
@MainActor
final class LockState {
    static let shared = LockState()

    /// True when the app should be obscured by `LockScreenView`.
    /// Initial value is computed at instantiation:
    ///   - if a master password is set AND the user wants it required,
    ///     start locked.
    ///   - otherwise start unlocked.
    private(set) var isLocked: Bool

    /// Wall-clock time of the last user activity. Updated by the
    /// app's idle observer; auto-lock fires when (now - lastActivity)
    /// exceeds the configured timeout.
    private(set) var lastActivity = Date()

    private init() {
        self.isLocked = AppSettings.shared.requireMasterPassword
            && MasterPassword.isSet
    }

    /// Mark the user as active right now. Called by every meaningful
    /// UI interaction (typing, clicking, opening sheets).
    func noteActivity() { lastActivity = Date() }

    /// Lock the app. Called manually (Lock Now button), on auto-lock
    /// timer expiry, and at app start when the password gate applies.
    func lock() { isLocked = true }

    /// Unlock the app — only call after a successful PBKDF2 verify.
    func unlock() {
        isLocked = false
        lastActivity = Date()
    }
}
