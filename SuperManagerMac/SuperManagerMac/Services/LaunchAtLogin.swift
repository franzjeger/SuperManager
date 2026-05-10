import Foundation
import ServiceManagement

/// Thin wrapper around `SMAppService.mainApp` for the
/// "launch at login" preference. The modern (macOS 13+) API
/// replaces `SMLoginItemSetEnabled` and `LSSharedFileList`.
///
/// SMAppService is identity-based: the registered service is
/// identified by the *bundle* (not a path), so an upgraded app
/// in a different location continues to be the same login item.
/// That's the key reason to use this over the legacy APIs which
/// would silently break on every app move.
///
/// All methods are synchronous and run on the calling thread —
/// SMAppService's API is sync (it talks to launchd locally).
/// Bool getters are non-throwing; the registration setter throws
/// and we surface the error to the UI.
enum LaunchAtLogin {
    /// Whether the app is currently registered to launch at login.
    /// `.enabled` is the only "yes"; everything else (`.notRegistered`,
    /// `.notFound`, `.requiresApproval`) is treated as "no", but the
    /// raw status is exposed via `currentStatus` for richer UI.
    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    /// Raw SMAppService status. Useful when the UI wants to
    /// surface "User must approve in System Settings" (the
    /// `.requiresApproval` case macOS introduced in 13).
    static var currentStatus: SMAppService.Status {
        SMAppService.mainApp.status
    }

    /// Enable or disable launch-at-login. Throws on unregister
    /// failure or registration rejection (most commonly when the
    /// user has the app blocked in System Settings → Login Items).
    static func setEnabled(_ enabled: Bool) throws {
        let service = SMAppService.mainApp
        if enabled {
            // `register()` is idempotent — calling it on an
            // already-registered service is a no-op.
            try service.register()
        } else {
            try service.unregister()
        }
    }

    /// Human-readable description of the status, suitable for
    /// the Settings caveat row. Stable across macOS versions:
    /// translates each enum case to a fixed string we know how
    /// to localize later.
    static func statusDescription(_ status: SMAppService.Status) -> String {
        switch status {
        case .notRegistered:    return "Not enabled"
        case .enabled:          return "Enabled"
        case .requiresApproval: return "Awaiting approval in System Settings → Login Items"
        case .notFound:         return "App registration record not found"
        @unknown default:       return "Unknown status"
        }
    }
}
