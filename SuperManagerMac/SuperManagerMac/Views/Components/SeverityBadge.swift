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
            }
        }
    }
    .padding()
}
#endif
