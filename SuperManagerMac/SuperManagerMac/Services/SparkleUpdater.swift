import Foundation
import Sparkle
import SwiftUI

/// Thin SwiftUI-friendly facade over Sparkle's `SPUStandardUpdaterController`.
///
/// ## What Sparkle does for us
///
/// On launch (and every `SUScheduledCheckInterval` seconds while running)
/// Sparkle fetches the appcast.xml at the `SUFeedURL` baked into our
/// Info.plist, compares the advertised version against `CFBundleShortVersionString`,
/// and — if newer — verifies the appcast's EdDSA signature against the
/// `SUPublicEDKey` (also from Info.plist). Only after both the version
/// check AND signature verification pass does it offer the update to the
/// operator. Sparkle then downloads the .dmg/.zip, validates its
/// signature again, presents the standard "Install and Relaunch" UI, and
/// hand-off to Apple's installer chain on quit.
///
/// ## Why a wrapper class
///
/// `SPUStandardUpdaterController` needs to be a stored property somewhere
/// that lives for the lifetime of the app — Sparkle internally retains it
/// for delegate callbacks. SwiftUI's `@StateObject`/`@State` aren't a clean
/// match because we instantiate this before the SwiftUI app phase begins
/// (`@main` struct). The convention is a top-level singleton.
///
/// ## What the menu does
///
/// `checkForUpdates()` triggers a manual user-initiated check that bypasses
/// the throttle (Sparkle normally won't re-check more than once per
/// `SUScheduledCheckInterval`). Used by the "Check for Updates…" menu
/// item the operator clicks when they want to force a refresh.
@MainActor
final class SparkleUpdater: NSObject, ObservableObject, SPUUpdaterDelegate {
    static let shared = SparkleUpdater()

    /// UserDefaults key for the beta-channel opt-in toggle. Stable
    /// across releases — if a user has opted into betas, they stay
    /// opted in across upgrades unless they untick the box.
    static let includeBetaUpdatesDefaultsKey = "supermgr.includeBetaUpdates"

    /// Filename Sparkle fetches when the operator opts into betas.
    /// We bake the stable feed URL into Info.plist
    /// (`SUFeedURL = .../releases/latest/download/appcast.xml`) and
    /// derive the beta URL by swapping the filename. Both files
    /// live in the same GitHub Release directory so the swap is
    /// just `appcast.xml` ↔ `appcast-beta.xml`.
    private static let betaFeedFilename = "appcast-beta.xml"

    /// Sparkle's controller, only initialised when a real
    /// `SUPublicEDKey` is set in Info.plist. Until the developer
    /// runs `scripts/sparkle-keygen.sh` and pastes the public key
    /// into `project.yml`, Sparkle's init fails ("EdDSA public key
    /// is not valid") and the controller is left nil. `var` (not
    /// `let`) because NSObject ordering forces us to assign it
    /// AFTER `super.init()` so we can pass `self` as the delegate.
    private var controller: SPUStandardUpdaterController?

    /// Reason Sparkle is disabled, if any. Surfaced in the
    /// "Check for Updates…" dialog so the operator sees an
    /// actionable message instead of Sparkle's "updater failed
    /// to start" generic alert.
    private(set) var disabledReason: String?

    /// `canCheckForUpdates` is published so SwiftUI menu items can
    /// gate themselves while a check is in-flight. Sparkle exposes
    /// this on the underlying `SPUUpdater` as KVO-observable.
    @Published private(set) var canCheckForUpdates = true

    /// Whether the operator has opted into beta updates. Mirrored
    /// from UserDefaults so a SwiftUI toggle can bind both ways.
    @Published var includeBetaUpdates: Bool {
        didSet {
            UserDefaults.standard.set(includeBetaUpdates, forKey: Self.includeBetaUpdatesDefaultsKey)
            // Tell Sparkle the feed has changed so its next check
            // sees the new URL. Without this, Sparkle would only
            // notice on app relaunch or next scheduled check.
            controller?.updater.resetUpdateCycle()
        }
    }

    private var observation: NSKeyValueObservation?

    private override init() {
        includeBetaUpdates = UserDefaults.standard.bool(forKey: Self.includeBetaUpdatesDefaultsKey)
        super.init()

        // Detect XCTest. When the test runner launches the host app
        // briefly to load the test bundle, an active Sparkle scheduler
        // fires a network update check that can hang indefinitely on
        // a network-isolated CI runner (macos-latest images).
        // Don't start the auto-check timer under tests — manual
        // `checkForUpdates()` is still available from the menu.
        let underXCTest = ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil

        // Fail-soft on the placeholder public key. Sparkle 2's init
        // refuses to start with an unparseable EdDSA key (correct
        // security default), but unhandled it produces a generic
        // "updater failed to start" alert that gives the operator
        // no clue what's wrong. Skip Sparkle entirely until a real
        // key is in place; the menu item then shows a one-liner
        // pointing at the keygen script.
        let publicKey = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String ?? ""
        let isPlaceholder = publicKey.isEmpty || publicKey.hasPrefix("REPLACE_ME_")
        if isPlaceholder {
            controller = nil
            disabledReason = "Auto-updates are not configured yet. Run scripts/sparkle-keygen.sh and paste the public key into SuperManagerMac/project.yml's SUPublicEDKey."
            return
        }

        // Pass `self` as the updaterDelegate so Sparkle calls
        // `feedURLString(for:)` on every check to pick stable vs
        // beta. Init order requires super.init() before `self`,
        // which is why we couldn't use `let controller`.
        let ctl = SPUStandardUpdaterController(
            startingUpdater: !underXCTest,
            updaterDelegate: self,
            userDriverDelegate: nil
        )
        controller = ctl

        observation = ctl.updater.observe(
            \.canCheckForUpdates,
            options: [.initial, .new]
        ) { [weak self] updater, _ in
            Task { @MainActor in
                self?.canCheckForUpdates = updater.canCheckForUpdates
            }
        }
    }

    /// User-initiated update check. Pops Sparkle's standard UI if a
    /// newer version is found, or a "you're up to date" alert if not.
    /// When Sparkle is disabled (placeholder key in dev builds) we
    /// show a clearer message instead of "updater failed to start".
    func checkForUpdates() {
        if let ctl = controller {
            ctl.checkForUpdates(nil)
        } else {
            showSparkleDisabledAlert()
        }
    }

    /// Returns the configured feed URL for diagnostics / about-pane
    /// display. Reads straight from Info.plist so it always matches
    /// what Sparkle actually polls.
    var feedURL: String {
        currentFeedURLString()
    }

    /// Standalone alert shown when the operator hits Check for
    /// Updates on a build without a real Sparkle public key.
    private func showSparkleDisabledAlert() {
        let alert = NSAlert()
        alert.messageText = "Auto-updates not configured"
        alert.informativeText = disabledReason
            ?? "Sparkle is disabled for this build."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    // MARK: - SPUUpdaterDelegate

    /// Sparkle calls this on every check to ask which feed URL
    /// to fetch. We override the Info.plist default to swap in
    /// `appcast-beta.xml` when the user has opted into betas.
    nonisolated func feedURLString(for updater: SPUUpdater) -> String? {
        MainActor.assumeIsolated { currentFeedURLString() }
    }

    /// Compute the effective feed URL given the current beta
    /// toggle state. Stable: returns the Info.plist value untouched.
    /// Beta: swaps the trailing filename to `appcast-beta.xml`.
    private func currentFeedURLString() -> String {
        let base = (Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String) ?? ""
        guard includeBetaUpdates,
              let url = URL(string: base) else { return base }
        let betaURL = url.deletingLastPathComponent()
            .appendingPathComponent(Self.betaFeedFilename)
        return betaURL.absoluteString
    }
}
