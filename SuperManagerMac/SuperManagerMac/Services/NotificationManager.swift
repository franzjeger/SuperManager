import Foundation
import UserNotifications

/// Surface system notifications for events the user wants to know
/// about even when the app window is in the background — primarily
/// auto-reconnect activity. Without this, the helper might restore
/// a tunnel three times in five minutes and the user has no idea.
///
/// We follow the macOS Notification Center conventions:
///   - Request permission once on first send (`requestAuthorization`).
///   - Use a deterministic identifier per (event-class, profile)
///     so a flap doesn't pile up dozens of stale notifications.
///   - Set the bundle's notifications "interruption level" to
///     `.active` (default) — these aren't critical alerts, just
///     awareness pings.
///
/// All entry points are `@MainActor` because UNUserNotificationCenter
/// is implicitly main-thread.
@MainActor
enum NotificationManager {
    /// Request permission. Idempotent — macOS caches the user's
    /// answer and silently no-ops on repeat calls. Called from
    /// `AppState.connectToDaemon()` so we ask early in the app
    /// lifecycle, before the first tunnel event would fire.
    static func requestAuthorization() async {
        let center = UNUserNotificationCenter.current()
        do {
            _ = try await center.requestAuthorization(options: [.alert, .sound])
        } catch {
            // User denied or system errored — both fine, we just
            // won't see notifications. No fallback needed; the
            // helper log is still authoritative.
        }
    }

    /// Auto-reconnect just brought a profile back up.
    /// Gated by `AppSettings.notifyVpnReconnected` — the user can
    /// silence this category from the General preferences pane
    /// without losing the others.
    static func vpnReconnected(profileLabel: String) {
        guard AppSettings.shared.notifyVpnReconnected else { return }
        post(
            id: "vpn-reconnected-\(profileLabel)",
            title: "VPN reconnected",
            body: "\(profileLabel) was down — auto-reconnect restored it."
        )
    }

    /// Auto-reconnect failed N times in a row. Surface this so
    /// the user knows their always-on profile is broken (likely
    /// stale credentials / config) and we're not silently retrying.
    static func vpnReconnectFailing(profileLabel: String, attempts: Int) {
        guard AppSettings.shared.notifyVpnReconnectFailing else { return }
        post(
            id: "vpn-reconnect-failing-\(profileLabel)",
            title: "Always-on VPN failing",
            body: "\(profileLabel) auto-reconnect failed \(attempts)× — check credentials."
        )
    }

    /// Tailscale exit-node was auto-reverted by panic-reset because
    /// the chosen peer wasn't forwarding traffic.
    static func exitNodeAutoReverted(peerName: String) {
        guard AppSettings.shared.notifyExitNodeReverted else { return }
        post(
            id: "tailscale-exit-reverted",
            title: "Exit node auto-reverted",
            body: "\(peerName) wasn't forwarding internet. Reverted to direct routing."
        )
    }

    /// A compliance scan revealed regression vs. the previous run.
    /// Caller passes a stable id (e.g. "compliance-drift-<hostId>")
    /// so successive notifications for the same host coalesce
    /// rather than pile up. The setting gate is checked at the
    /// callsite (AppState.maybeNotifyDrift) since the threshold
    /// for "worth notifying about" is policy, not transport.
    static func complianceDrift(id: String, title: String, body: String) {
        post(id: id, title: title, body: body)
    }

    /// Watchdog detected sustained internet loss and ran panic_reset.
    static func connectivityWatchdogFired() {
        guard AppSettings.shared.notifyWatchdogFired else { return }
        post(
            id: "connectivity-watchdog",
            title: "Internet recovery triggered",
            body: "Connectivity was lost; SuperManager reset routing to baseline."
        )
    }

    private static func post(id: String, title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: id,
            content: content,
            trigger: nil // deliver immediately
        )
        Task {
            try? await UNUserNotificationCenter.current().add(request)
        }
    }
}
