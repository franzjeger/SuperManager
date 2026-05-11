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
final class SparkleUpdater: ObservableObject {
    static let shared = SparkleUpdater()

    /// Sparkle's controller, only initialised when a real
    /// `SUPublicEDKey` is set in Info.plist. Until the developer
    /// runs `scripts/sparkle-keygen.sh` and pastes the public key
    /// into `project.yml`, Sparkle's init fails ("EdDSA public key
    /// is not valid") and the controller is left nil.
    private let controller: SPUStandardUpdaterController?

    /// Reason Sparkle is disabled, if any. Surfaced in the
    /// "Check for Updates…" dialog so the operator sees an
    /// actionable message instead of Sparkle's "updater failed
    /// to start" generic alert.
    private(set) var disabledReason: String?

    /// `canCheckForUpdates` is published so SwiftUI menu items can
    /// gate themselves while a check is in-flight. Sparkle exposes
    /// this on the underlying `SPUUpdater` as KVO-observable.
    @Published private(set) var canCheckForUpdates = true

    private var observation: NSKeyValueObservation?

    private init() {
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

        // `userDriverDelegate: nil` and `delegate: nil` use Sparkle's
        // standard UI + behaviour. If we ever need to customise
        // (e.g. add telemetry on update success) those land here.
        let ctl = SPUStandardUpdaterController(
            startingUpdater: !underXCTest,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
        controller = ctl
        disabledReason = nil

        // Mirror Sparkle's KVO property onto our `@Published` so
        // SwiftUI rebinds correctly. Capture self weakly — the
        // observer outlives the init scope.
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
        (Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String) ?? "(unset)"
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
}
