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

    /// Sparkle's controller. `startingUpdater: true` kicks the
    /// background scheduled-check timer on instantiation, so the
    /// operator gets update offers without ever opening the menu.
    private let controller: SPUStandardUpdaterController

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

        // `userDriverDelegate: nil` and `delegate: nil` use Sparkle's
        // standard UI + behaviour. If we ever need to customise
        // (e.g. add telemetry on update success) those land here.
        controller = SPUStandardUpdaterController(
            startingUpdater: !underXCTest,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )

        // Mirror Sparkle's KVO property onto our `@Published` so
        // SwiftUI rebinds correctly. Capture self weakly — the
        // observer outlives the init scope.
        observation = controller.updater.observe(
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
    /// Distinct from the scheduled background check (which silently
    /// just downloads + offers when applicable).
    func checkForUpdates() {
        controller.checkForUpdates(nil)
    }

    /// Returns the configured feed URL for diagnostics / about-pane
    /// display. Reads straight from Info.plist so it always matches
    /// what Sparkle actually polls.
    var feedURL: String {
        (Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String) ?? "(unset)"
    }
}
