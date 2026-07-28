import SwiftUI

/// Wraps a binding so that writes of the value it already holds are
/// dropped instead of forwarded.
///
/// This exists for `MenuBarExtra(isInserted:)`, and the reason is worth
/// spelling out because the naive version looks correct and bricks the app.
///
/// `MenuBarExtra` KVO-observes its `NSStatusItem` and writes the item's
/// current visibility back through the `isInserted` binding on every update
/// — including updates where nothing changed. Hand it `$showMenuBarItem`
/// (an `@AppStorage` binding rooted in the `App` struct) and that echo
/// invalidates the `App`, which rebuilds the scene list, which touches the
/// status item, which writes back again. The app spins at 100% CPU on
/// launch and never finishes bootstrapping — no crash log, just a hang.
///
/// Dropping same-value writes cuts the cycle while leaving real changes
/// (the Settings toggle, or the user cmd-dragging the icon out of the menu
/// bar) free to propagate in both directions.
///
/// The obvious alternative — a conditional scene — is not available:
/// `@SceneBuilder` cannot type-check `if showMenuBarItem { MenuBarExtra… }`
/// in this app's scene body, which is why `isInserted` exists in the first
/// place.
func echoSuppressed<Value: Equatable>(_ stored: Binding<Value>) -> Binding<Value> {
    Binding(
        get: { stored.wrappedValue },
        set: { newValue in
            guard newValue != stored.wrappedValue else { return }
            stored.wrappedValue = newValue
        }
    )
}
