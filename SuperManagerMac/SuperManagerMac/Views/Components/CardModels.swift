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
    /// The debounced per-profile state string (`stabilizedVpnState`'s output).
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
        if !helperReachable { return .warn }
        return .vpn(state)
    }

    var title: String {
        if !helperReachable { return "Helper not running" }
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
}

// MARK: - SSH host connection card

/// The connection card at the top of `HostDetailView`, decided from the
/// manual test-connection probe result.
///
/// `probe` is the raw `connectionStatus` string the view holds: `nil` (not
/// tested), `"Testing…"`, `"ok"`, or `"<kind>: <message>"` where kind is
/// `auth` / `network` / anything else. The stringly-typed contract is
/// preserved verbatim from the view — see the note in HostConnectionCardTests
/// on why it's worth eventually replacing with the structured kind the daemon
/// already returns.
struct HostConnectionCardModel {
    let probe: String?

    /// A network failure is `.offline`, not `.error`: the host isn't broken,
    /// the path from here is. An auth failure is `.error`: the host answered
    /// and rejected us. "Not tested" is `.unknown`, never a reading of down.
    var status: StatusStyle {
        switch probe {
        case nil:                                       return .unknown
        case "Testing…":                                return .pending
        case "ok":                                      return .online
        case .some(let s) where s.hasPrefix("auth"):    return .error
        case .some(let s) where s.hasPrefix("network"): return .offline
        default:                                        return .error
        }
    }

    var title: String {
        switch probe {
        case nil:                                       return "Not tested"
        case "Testing…":                                return "Testing…"
        case "ok":                                      return "Reachable"
        case .some(let s) where s.hasPrefix("auth"):    return "Auth failed"
        case .some(let s) where s.hasPrefix("network"): return "Unreachable"
        default:                                        return "Failed"
        }
    }

    var meta: String {
        switch probe {
        case nil:
            return "Test the connection to verify reachability and credentials."
        case "Testing…":
            return ""
        case "ok":
            return "SSH connection and authentication verified."
        case .some(let s) where s.hasPrefix("auth: "):
            return String(s.dropFirst(6))
        case .some(let s) where s.hasPrefix("network: "):
            return String(s.dropFirst(9)) + " — check that the right VPN tunnel is up."
        case .some(let s):
            return s
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
