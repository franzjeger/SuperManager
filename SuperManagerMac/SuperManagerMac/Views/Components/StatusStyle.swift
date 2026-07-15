import SwiftUI

/// The single status vocabulary for the whole app.
///
/// Every section — VPN tunnels, Tailscale peers, SSH hosts, compliance hosts,
/// engagements — renders state through this enum instead of inventing its own
/// dots, pills and colours. Two renderings of the same value: `StatusDot` in
/// list rows, `StatusPill` in detail headers, connection cards and the toolbar.
///
/// Colours are SwiftUI's system semantic colours on purpose. The design spec
/// gives literal hex targets so a non-SwiftUI target could match them, but tells
/// us to prefer system tokens here so the app tracks the user's macOS appearance
/// and accent automatically.
enum StatusStyle: Hashable {
    /// Connected, online, reachable.
    case online
    /// Deliberately down, or simply not connected. A real reading.
    case offline
    /// Handshake or scan in progress.
    case pending
    /// Was working and demonstrably is not.
    case error
    /// Up but impaired — retrying, route-less, partially reachable.
    case warn
    /// Never measured. Distinct from `offline`: we have no reading at all,
    /// rather than a reading of "down".
    case unknown

    var color: Color {
        switch self {
        case .online:  return .green
        case .offline: return .gray
        case .pending: return .orange
        case .error:   return .red
        case .warn:    return .orange
        case .unknown: return .blue
        }
    }

    /// Used when the caller doesn't override it. Sections with a better word
    /// for the same state (Tailscale says "Online", a retrying tunnel says
    /// "Reconnecting…") pass their own label rather than adding a case.
    var defaultLabel: String {
        switch self {
        case .online:  return "Connected"
        case .offline: return "Disconnected"
        case .pending: return "Connecting"
        case .error:   return "Error"
        case .warn:    return "Degraded"
        case .unknown: return "Never scanned"
        }
    }
}

extension StatusStyle {
    /// Map the daemon's VPN state strings onto the shared vocabulary.
    ///
    /// `nil` means "not polled yet" and maps to `.unknown`, NOT `.offline` —
    /// asserting a tunnel is down before we have measured it is exactly the
    /// lie the status-hysteresis work removed.
    static func vpn(_ state: String?) -> StatusStyle {
        switch state {
        case "connected":     return .online
        case "connecting":    return .pending
        case "disconnecting": return .pending
        // Retrying on its own after an unclean drop: up-ish, not healthy.
        case "reconnecting":  return .warn
        case "disconnected":  return .offline
        // Set by the poller when a tunnel was up and the helper can no longer
        // confirm it (repeated status timeouts / RPC failures).
        case "problem":       return .error
        case .some(let s) where s.contains("error"): return .error
        default:              return .unknown
        }
    }
}

extension StatusStyle {
    /// An engagement's state.
    ///
    /// Expired is `.error`, not `.offline`. An engagement is the record of a
    /// customer's authorization to run offensive tests against them, so an
    /// expired one doesn't mean "idle" — it means every scan under it is now
    /// unauthorized. That's worth red.
    ///
    /// The two views that show this disagreed: the list column painted expired
    /// `.secondary` grey while the detail header painted it red. Same
    /// engagement, two verdicts, depending which pane you looked at.
    static func engagement(_ e: Engagement) -> StatusStyle {
        guard e.isActive else { return .error }
        // A week's warning before authorization lapses — enough time to get it
        // renewed before scans start failing the scope check.
        return e.expiresAt.timeIntervalSinceNow / 86400 < 7 ? .warn : .online
    }
}

extension Engagement {
    /// "today" / "tomorrow" / "in 12 days".
    ///
    /// Never "in 0 days", which is what the detail header said for anything
    /// inside 24 hours — it truncated the interval to an Int and printed it.
    /// The list column already phrased this correctly; now both read the same
    /// sentence from the same place.
    var expiryPhrase: String {
        let days = Int(expiresAt.timeIntervalSinceNow / 86400)
        if days < 1 { return "today" }
        if days == 1 { return "tomorrow" }
        return "in \(days) days"
    }
}

/// 8pt dot for list rows — the compact rendering of `StatusStyle`.
struct StatusDot: View {
    let status: StatusStyle
    /// Overrides the accessibility label when the section has a better word.
    var label: String?

    var body: some View {
        Circle()
            .fill(status.color)
            .frame(width: 8, height: 8)
            .accessibilityLabel(label ?? status.defaultLabel)
    }
}

/// Dot + label chip — the verbose rendering of `StatusStyle`, for detail
/// headers, connection cards and the toolbar.
struct StatusPill: View {
    let status: StatusStyle
    var label: String?

    var body: some View {
        HStack(spacing: 5) {
            Circle()
                .fill(status.color)
                .frame(width: 6, height: 6)
            Text(label ?? status.defaultLabel)
                .font(.system(size: 11, weight: .semibold))
                .fixedSize()          // a status must never hyphen-wrap
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .foregroundStyle(status.color)
        .background(status.color.opacity(0.15), in: Capsule())
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
#Preview("Status vocabulary") {
    let all: [StatusStyle] = [.online, .offline, .pending, .error, .warn, .unknown]
    return VStack(alignment: .leading, spacing: 12) {
        ForEach(all, id: \.self) { s in
            HStack(spacing: 10) {
                StatusDot(status: s)
                StatusPill(status: s)
            }
        }
        Divider()
        StatusPill(status: .warn, label: "Reconnecting…")
    }
    .padding()
}
#endif
