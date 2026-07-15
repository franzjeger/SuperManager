import SwiftUI

/// What a notice is about, which is the only thing that picks its colour.
///
/// Closed set for the same reason `BadgeKind` is: a call site that can pass any
/// `Color` will eventually pass a new one, and then the tenth notice is a
/// slightly different orange than the other nine.
enum NoticeKind {
    /// Worth knowing, nothing wrong. "Baseline established."
    case info
    /// Needs attention before the thing works. "API token required."
    case warning
    /// Was working and demonstrably is not.
    case error
    /// A fact about what this thing is, carrying no urgency. "Compliance
    /// baselines aren't available for this device type."
    case neutral

    /// Literal semantic colours, not `.accentColor` — the same choice
    /// `StatusStyle` and `SeverityBadge` make.
    ///
    /// `.info` was `.accentColor` for one build, which the cards this replaces
    /// also used via `.tint`. It renders as the user's system accent, and that
    /// accent can be Graphite — as it is on this machine. Under Graphite,
    /// `.info` and `.neutral` are the same grey, so "Baseline established" and
    /// "Compliance not available for this device type" become indistinguishable
    /// despite saying entirely different things. A kind that can collapse into
    /// another kind isn't carrying meaning.
    var color: Color {
        switch self {
        case .info:    return .blue
        case .warning: return .orange
        case .error:   return .red
        case .neutral: return .secondary
        }
    }
}

/// An inline notice about the thing you're looking at, optionally with the one
/// action that resolves it.
///
/// Not `EmptyStateView`: that one fills a pane to say nothing is selected. A
/// notice sits inside a populated view, in flow with the rest of the content,
/// and says something about what IS there.
///
/// Roughly this shape was in the app eight times over, every one of them
/// tinting the background at 0.08 and then disagreeing about everything else:
/// corner radius 6, 8 or 10; padding 8, 12 or 20; a hairline stroke on some at
/// 0.25, 0.3 or `.separator`, and none on others. Same idea, drawn six ways,
/// because there was nothing to reach for.
///
/// Three of them are Compliance's and are exactly this shape, so they use it.
/// The rest are deliberately left alone rather than forced through:
///
///   - VPN's strongSwan-install card puts a copyable command block between the
///     message and its buttons. That isn't an action, and widening the slot to
///     swallow it would make this type a generic tinted box.
///   - VPN's action-error card has neither a title nor an icon — just swanctl's
///     text and a log button. Converting means inventing a heading for an
///     arbitrary error string, which is writing copy, not consolidating.
///   - UniFi's controller error and WebCapture's hint are unexamined.
///
/// A primitive that fits three call sites honestly is worth more than one that
/// fits eight by distorting itself. Grep counts aren't the goal.
struct NoticeCard<Action: View>: View {
    let kind: NoticeKind
    let systemImage: String
    let title: String
    let message: String
    @ViewBuilder var action: () -> Action

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: systemImage)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(kind.color)
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                // Notices carry a sentence or three of explanation; without
                // this they get one line and an ellipsis.
                .fixedSize(horizontal: false, vertical: true)
            action()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(kind.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(kind.color.opacity(0.25), lineWidth: 0.5)
        )
    }
}

extension NoticeCard where Action == EmptyView {
    /// A notice with nothing to click — it states a fact and stops.
    init(kind: NoticeKind, systemImage: String, title: String, message: String) {
        self.init(
            kind: kind,
            systemImage: systemImage,
            title: title,
            message: message,
            action: { EmptyView() }
        )
    }
}

#if DEBUG
#Preview("Notices") {
    VStack(spacing: 12) {
        NoticeCard(
            kind: .warning,
            systemImage: "lock.shield",
            title: "API token required",
            message: "Compliance scans use the FortiGate REST API to read configuration values without an interactive shell session."
        ) {
            Button("Open host detail in SSH") {}
                .controlSize(.small)
                .buttonStyle(.borderedProminent)
        }
        NoticeCard(
            kind: .info,
            systemImage: "flag.checkered",
            title: "Baseline established",
            message: "This is the first compliance run for this host. Drift detection compares future runs against this one."
        )
        NoticeCard(
            kind: .error,
            systemImage: "exclamationmark.triangle.fill",
            title: "Tunnel failed",
            message: "The helper rejected the connection."
        )
        NoticeCard(
            kind: .neutral,
            systemImage: "questionmark.app.dashed",
            title: "Compliance not available for this device type",
            message: "Currently supported: FortiGate (REST API) and Linux (SSH)."
        )
    }
    .padding()
    .frame(width: 520)
}
#endif
