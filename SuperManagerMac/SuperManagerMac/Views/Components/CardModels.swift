import Foundation

/// Pure presentation decisions extracted from the detail views.
///
/// Each of these used to be a `private var`/`func` inside a SwiftUI view,
/// which put the decision — what state to show, what to title it, what one
/// line of context to give — beyond the reach of `@testable import`. The
/// logic is exactly the kind that breaks silently (a green dot over a dead
/// tunnel, a status string mis-parsed), so it belongs in a seam a test can
/// hold. The views now build one of these from their `@State` and read the
/// three outputs; the tests build one from plain values.
///
/// Nothing here touches a View, AppState, or the daemon.

// MARK: - VPN connection card

/// The connection card at the top of `VpnDetailView`: state, title, and the
/// one meta line under it.
struct VpnConnectionCardModel {
    /// False when the privileged helper's socket is unreachable — a distinct
    /// state from any tunnel state, because the next action is "install/approve
    /// the daemon", not "connect".
    let helperReachable: Bool
    /// False when the helper exists but did not answer its last ping. Nothing
    /// the card shows can be confirmed then, and the fix is not reinstalling.
    var helperResponding: Bool = true
    /// The state on screen — `shownState(busy:actionState:polled:)`'s answer.
    let state: String
    /// Full vs split tunnel, for the meta line.
    let fullTunnel: Bool
    /// The helper's own summary line ("established 26s ago, rekeying in…"),
    /// empty when it has nothing to say.
    let detail: String
    /// Most recent successful connect, whether or not that session still
    /// stands — drives "Last connected …" on a disconnected card. Passed in
    /// (not read from a clock) so the decision stays pure.
    let lastConnectedAt: Date?

    var status: StatusStyle {
        if !helperReachable || !helperResponding { return .warn }
        return .vpn(state)
    }

    var title: String {
        if !helperReachable { return "Helper not running" }
        if !helperResponding { return "Helper not responding" }
        switch state {
        case "connected":     return "Connected"
        case "connecting":    return "Connecting…"
        case "reconnecting":  return "Reconnecting…"
        case "disconnecting": return "Disconnecting…"
        case "problem":       return "Problem"
        default:              return "Disconnected"
        }
    }

    var meta: String {
        if !helperReachable {
            return "Approve or install the background daemon to control this tunnel."
        }
        if !helperResponding {
            return "The background daemon is running but not answering, so this tunnel's state can't be confirmed."
        }
        let mode = fullTunnel ? "Full tunnel" : "Split tunnel"
        switch state {
        case "connected":
            return detail.isEmpty ? mode : detail
        case "disconnected":
            if let last = lastConnectedAt {
                return "Last connected \(last.formatted(.relative(presentation: .named))) · \(mode)"
            }
            return mode
        default:
            // Mid-transition the helper's detail line is the most honest thing
            // we have (e.g. "status query timed out (charon busy)").
            return detail
        }
    }

    /// Which state the card, and the connect/disconnect button with it, shows.
    ///
    /// A user action on the profile owns the answer while it runs: it starts
    /// from what was on screen and moves it as it learns, because the poller's
    /// samples in that window are noise — a half-negotiated SA reads as
    /// "disconnected". The moment the action ends, the global poller's
    /// debounced state is the answer again.
    ///
    /// Worked out on every render, never mirrored into view state: a mirror
    /// that skips updates while an action runs loses the one that lands in
    /// that window, and "connected" always does — it is ready the instant
    /// `vpn_connect` releases the helper's strongSwan lock.
    static func shownState(busy: Bool, actionState: String?, polled: String?) -> String {
        if busy, let actionState { return actionState }
        return polled ?? "disconnected"
    }
}

// MARK: - SSH host connection card

/// What the manual "Test connection" probe last told us about a host.
///
/// Replaces a `String?` that packed six states into one field with `nil`,
/// `"Testing…"`, `"ok"`, and `"<kind>: <message>"` prefixes — a shape the
/// card then re-parsed by string-matching. `AppState.SshTestResult` was
/// already a proper enum; this carries that structure through to the card
/// instead of flattening it to a string and picking it back apart.
enum HostProbeState: Equatable {
    /// No probe run this session.
    case notTested
    /// A probe is in flight.
    case testing
    /// SSH connected and authenticated.
    case reachable
    /// Couldn't reach the host — the path from here is down (often a VPN
    /// that isn't up), not the host itself.
    case unreachable(String)
    /// The host answered and rejected our credentials.
    case authFailed(String)
    /// Anything else the probe reported.
    case failed(String)
}

/// The connection card at the top of `HostDetailView`, decided from the
/// probe state.
struct HostConnectionCardModel {
    let probe: HostProbeState

    /// A network failure is `.offline`, not `.error`: the host isn't broken,
    /// the path from here is. An auth failure is `.error`: the host answered
    /// and rejected us. Not-tested is `.unknown`, never a reading of down.
    var status: StatusStyle {
        switch probe {
        case .notTested:    return .unknown
        case .testing:      return .pending
        case .reachable:    return .online
        case .unreachable:  return .offline
        case .authFailed:   return .error
        case .failed:       return .error
        }
    }

    var title: String {
        switch probe {
        case .notTested:    return "Not tested"
        case .testing:      return "Testing…"
        case .reachable:    return "Reachable"
        case .unreachable:  return "Unreachable"
        case .authFailed:   return "Auth failed"
        case .failed:       return "Failed"
        }
    }

    var meta: String {
        switch probe {
        case .notTested:
            return "Test the connection to verify reachability and credentials."
        case .testing:
            return ""
        case .reachable:
            return "SSH connection and authentication verified."
        case .unreachable(let msg):
            return msg + " — check that the right VPN tunnel is up."
        case .authFailed(let msg):
            return msg
        case .failed(let msg):
            return msg
        }
    }
}

// MARK: - SSH sidebar grouping

enum SshHostGrouping {
    /// Which section a host files under in the SSH sidebar, by precedence:
    /// the customer the resolver links it to (the grouping the rest of the app
    /// thinks in), else the manual `group` field, else "Ungrouped".
    ///
    /// `customers` is needed for the display name — `HostIndex` resolves a
    /// slug, not a label.
    static func sectionTitle(
        for host: SshHostSummary,
        hostIndex: HostIndex,
        customers: [Customer]
    ) -> String {
        if let slug = hostIndex.customerSlug(forHost: host),
           !slug.isEmpty,
           let customer = customers.first(where: { $0.slug == slug }) {
            return customer.displayName
        }
        return host.group.isEmpty ? "Ungrouped" : host.group
    }
}
