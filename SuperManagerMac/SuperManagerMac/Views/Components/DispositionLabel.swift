import SwiftUI

/// Compact disposition pill (Open / Accepted / Fixed / False positive).
/// Used in finding rows + history timelines + remediation script
/// preamble — centralizes the colour+label mapping so the
/// rendering doesn't drift across views.
struct DispositionLabel: View {
    let disposition: Disposition
    var size: Size = .compact

    enum Size { case compact, regular }

    var body: some View {
        Text(Self.label(disposition))
            .font(size == .compact ? .caption2.weight(.semibold) : .caption.weight(.semibold))
            .padding(.horizontal, size == .compact ? 6 : 8)
            .padding(.vertical, size == .compact ? 2 : 4)
            .background(Self.color(disposition).opacity(0.15))
            .foregroundStyle(Self.color(disposition))
            .clipShape(Capsule())
    }

    /// Short user-facing label. Distinguishes Auto-fixed from
    /// manually Fixed because the operator's response differs:
    /// auto-fixed = next scan didn't see it; manual = operator
    /// took action.
    static func label(_ d: Disposition) -> String {
        switch d {
        case .open: return "Open"
        case .acceptedRisk: return "Accepted"
        case .fixed(let auto): return auto ? "Auto-fixed" : "Fixed"
        case .falsePositive: return "False positive"
        }
    }

    /// Canonical disposition → Color. Re-used by FindingRow's
    /// background + dimming logic.
    static func color(_ d: Disposition) -> Color {
        switch d {
        case .open:           return .red       // attention demanded
        case .acceptedRisk:   return .gray      // intentional, tracked
        case .fixed:          return .green     // resolved
        case .falsePositive:  return .secondary // hidden from totals
        }
    }
}

#if DEBUG
#Preview("Disposition labels") {
    VStack(alignment: .leading, spacing: 8) {
        DispositionLabel(disposition: .open)
        DispositionLabel(disposition: .acceptedRisk(reason: "intentional", until: nil))
        DispositionLabel(disposition: .fixed(auto: true))
        DispositionLabel(disposition: .fixed(auto: false))
        DispositionLabel(disposition: .falsePositive(reason: "rule misfired"))
    }
    .padding()
}
#endif
