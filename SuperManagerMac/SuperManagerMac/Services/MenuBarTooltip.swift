import AppKit

/// Hover tooltip for the menu bar item.
///
/// SwiftUI's `MenuBarExtra` does not expose its `NSStatusItem`, and
/// `.help()` on a `Scene` does nothing, so there is no supported way to
/// set a tooltip on it. The button is located instead by walking
/// `NSApp.windows` for the status-bar window and finding the
/// `NSStatusBarButton` inside it, then cached.
///
/// That walk leans on AppKit internals, so it is written to fail soft:
/// if the button is ever not found — a future macOS reorganising the
/// status-bar window, the item hidden by the Settings toggle — the
/// tooltip is simply absent and nothing else is affected. Never make
/// anything depend on this succeeding.
@MainActor
enum MenuBarTooltip {
    /// Weak so hiding the menu bar item (which destroys the status
    /// item) doesn't leave us writing to a dead button.
    private static weak var cachedButton: NSStatusBarButton?

    /// Set the tooltip text, locating the button on first use.
    ///
    /// Called from the app's existing one-second poll loop, so it must
    /// stay cheap: the common path is a cache hit plus a string compare.
    static func set(_ text: String) {
        guard let button = cachedButton ?? locateButton() else { return }
        cachedButton = button
        // AppKit re-lays out the tooltip on every assignment; only
        // write when the text actually changed.
        if button.toolTip != text {
            button.toolTip = text
        }
    }

    private static func locateButton() -> NSStatusBarButton? {
        for window in NSApp.windows {
            if let button = statusBarButton(in: window.contentView) {
                return button
            }
        }
        return nil
    }

    private static func statusBarButton(in view: NSView?) -> NSStatusBarButton? {
        guard let view else { return nil }
        if let button = view as? NSStatusBarButton { return button }
        for subview in view.subviews {
            if let button = statusBarButton(in: subview) { return button }
        }
        return nil
    }
}

/// One tunnel's worth of what the tooltip needs to say.
struct MenuBarTunnel: Equatable {
    let name: String
    /// Raw daemon state string, e.g. "connected" / "connecting".
    let state: String
}

/// Builds the tooltip text.
///
/// Split out from `MenuBarTooltip` because the AppKit lookup there
/// can't be exercised in a test, and the wording is the part worth
/// pinning down. Pure function, no app state.
enum MenuBarTooltipText {
    /// The tooltip is read at a glance while hovering, so it stays
    /// exception-based: the daemon line only appears when the daemon is
    /// missing, and Tailscale is omitted entirely when it isn't running.
    /// A healthy machine with one tunnel up is two short lines.
    static func build(
        daemonAvailable: Bool,
        tunnels: [MenuBarTunnel],
        tailscale: String?
    ) -> String {
        var lines: [String] = []

        if !daemonAvailable {
            lines.append("Daemon offline — status may be stale")
        }

        let connected = tunnels.filter { $0.state == "connected" }
        let connecting = tunnels.filter { $0.state == "connecting" || $0.state == "reconnecting" }

        if connected.isEmpty && connecting.isEmpty {
            lines.append("No VPN connected")
        } else {
            if !connected.isEmpty {
                lines.append("VPN: " + connected.map(\.name).joined(separator: ", "))
            }
            if !connecting.isEmpty {
                lines.append("Connecting: " + connecting.map(\.name).joined(separator: ", "))
            }
        }

        if let tailscale, !tailscale.isEmpty {
            lines.append(tailscale)
        }

        return lines.joined(separator: "\n")
    }
}
