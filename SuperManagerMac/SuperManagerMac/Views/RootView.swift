import SwiftUI

/// Top-level view inside `WindowGroup`. Branches between `LockScreenView`
/// and `ContentView` based on `LockState.shared.isLocked`.
///
/// Why this exists (and not just an `.overlay`): SwiftUI materials are
/// translucent by design. A material-backed lock overlay leaks the
/// outline of any TextField/SecureField sitting in the toolbar
/// underneath — not a pretty look on a security screen. Branching at
/// the root means the locked window literally contains nothing else;
/// there's nothing to bleed through.
///
/// The `onAppear` closure is the app-startup hook. It runs once when
/// the very first content appears (whether that's `LockScreenView` or
/// `ContentView`), so daemon spawn + connect + auto-lock-timer happen
/// regardless of initial lock state.
struct RootView: View {
    let appState: AppState
    let onAppear: () -> Void

    @State private var lockState = LockState.shared
    @State private var didFireAppear = false

    var body: some View {
        Group {
            if lockState.isLocked {
                LockScreenView()
                    .frame(minWidth: 900, minHeight: 600)
            } else {
                ContentView()
                    .environment(appState)
                    .frame(minWidth: 900, minHeight: 600)
                    .alert("Error", isPresented: alertBinding) {
                        Button("OK") {}
                    } message: {
                        Text(appState.errorMessage)
                    }
            }
        }
        // Animate the swap — quick fade keeps the window from jumping
        // visually and signals the state change clearly.
        .animation(.easeInOut(duration: 0.15), value: lockState.isLocked)
        .onAppear {
            // Guard against re-fires from SwiftUI re-evaluating the
            // body. Daemon spawn / timer must only happen once.
            guard !didFireAppear else { return }
            didFireAppear = true
            onAppear()
        }
    }

    /// Bridges `appState.showingError` (a `Bool` on a non-Bindable
    /// reference type) into the alert presentation Binding the
    /// modifier needs. Reading the boolean is read-only via the
    /// non-`@Bindable` path; resetting it to false on dismiss goes
    /// through the same setter that originally set it.
    private var alertBinding: Binding<Bool> {
        Binding(
            get: { appState.showingError },
            set: { newValue in
                appState.showingError = newValue
                // When SwiftUI flips this to false (user clicked
                // OK), pop the next queued error if any. AppState
                // handles the runloop deferral.
                if !newValue {
                    appState.dismissCurrentError()
                }
            }
        )
    }
}
