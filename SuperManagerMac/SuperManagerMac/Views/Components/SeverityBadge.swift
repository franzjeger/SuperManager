import SwiftUI

/// Compact severity pill — used everywhere a finding's severity
/// needs to be surfaced (Discovery panel, Fleet, Finding detail,
/// Engagement report). Centralizes color + label so we don't have
/// 5 copies drifting out of sync.
///
/// Sizes:
///   - `.compact` for table rows (caption2, 6×2 padding)
///   - `.regular` for cards (caption, 8×4 padding)
struct SeverityBadge: View {
    let severity: FindingSeverity
    var size: Size = .compact

    enum Size { case compact, regular }

    var body: some View {
        Text(severity.rawValue.capitalized)
            .font(size == .compact ? .caption2.weight(.semibold) : .caption.weight(.semibold))
            .padding(.horizontal, size == .compact ? 6 : 8)
            .padding(.vertical, size == .compact ? 2 : 4)
            .background(SeverityBadge.color(for: severity).opacity(0.15))
            .foregroundStyle(SeverityBadge.color(for: severity))
            .clipShape(Capsule())
    }

    /// Canonical severity → Color mapping. Public so non-badge
    /// callers (icons, dimming, finding-row backgrounds) get the
    /// same color set without copying the switch statement.
    static func color(for severity: FindingSeverity) -> Color {
        switch severity {
        case .critical: return .red
        case .high:     return .orange
        case .medium:   return .yellow
        case .low:      return .blue
        case .info:     return .gray
        }
    }

    /// 0-4 sort key so callers can sort findings by severity
    /// (Critical first) without re-implementing the rank table.
    static func rank(_ s: FindingSeverity) -> Int {
        switch s {
        case .critical: return 0
        case .high:     return 1
        case .medium:   return 2
        case .low:      return 3
        case .info:     return 4
        }
    }
}

extension AppState.ComplianceSeverity {
    /// Render a compliance severity through the finding palette.
    ///
    /// The two enums exist because compliance checks and security findings
    /// arrive from different engine endpoints, not because a critical check
    /// means something different from a critical finding. They graded
    /// identically apart from `.info`, where compliance had drifted to
    /// `.secondary` against the badge's `.gray` — and `.secondary` is a
    /// foreground hierarchy style, not a fill, so it was the odd one out as
    /// well as the minority. One palette, one meaning.
    var asFindingSeverity: FindingSeverity {
        switch self {
        case .critical: return .critical
        case .high:     return .high
        case .medium:   return .medium
        case .low:      return .low
        case .info:     return .info
        }
    }
}

/// How many findings sit at one severity: "3", tinted red for critical.
///
/// Separate type from `SeverityBadge` because it says a different thing — the
/// badge names a severity, this counts findings at one. Used where several sit
/// in a row (Fleet's customer cards) and spelling out every name would crowd
/// the row out; the colour carries the severity for sighted readers and the
/// accessibility label spells it out for everyone else, since a bare "3" is
/// meaningless read aloud.
///
/// Takes its colour from `SeverityBadge.color(for:)` rather than a parameter.
/// Fleet hand-rolled this pill with the palette repeated at the call site and
/// it had already drifted — a tint of 0.18 against the badge's 0.15 — which is
/// exactly the split this file exists to prevent.
struct SeverityCountBadge: View {
    let count: Int
    let severity: FindingSeverity

    var body: some View {
        Text("\(count)")
            .font(.caption2.weight(.semibold))
            // Counts change on every poll; unequal digit widths make the row
            // twitch as they do.
            .monospacedDigit()
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(SeverityBadge.color(for: severity).opacity(0.15))
            .foregroundStyle(SeverityBadge.color(for: severity))
            .clipShape(Capsule())
            .accessibilityLabel("\(count) \(severity.rawValue)")
    }
}

#if DEBUG
#Preview("Severity badges") {
    VStack(alignment: .leading, spacing: 8) {
        ForEach([
            FindingSeverity.critical,
            .high, .medium, .low, .info,
        ], id: \.self) { sev in
            HStack {
                SeverityBadge(severity: sev, size: .compact)
                SeverityBadge(severity: sev, size: .regular)
                SeverityCountBadge(count: 3, severity: sev)
            }
        }
        Divider()
        // The row as Fleet builds it.
        HStack(spacing: 4) {
            SeverityCountBadge(count: 2, severity: .critical)
            SeverityCountBadge(count: 11, severity: .high)
            SeverityCountBadge(count: 4, severity: .medium)
            SeverityCountBadge(count: 7, severity: .low)
        }
    }
    .padding()
}
#endif
