import SwiftUI

/// The detail pane's connection card: what state this thing is in, one line of
/// context, and the action that changes it — one full-width block at the top
/// of the pane that cannot be overlooked.
///
/// This is the grammar's second element (header, then THIS, then the column
/// grid). VPN profiles, SSH hosts and Tailscale peers all lead with one, so
/// the tile, type scale and paddings live here and the card reads as the same
/// object in every section.
///
/// The tile repeats the status colour behind a larger dot — the same signal as
/// the row's `StatusDot`, scaled up. While an action is in flight the dot
/// yields to a spinner, which is the spec's "connecting" treatment and beats a
/// second, competing progress indicator elsewhere in the card.
struct ConnectionCard<Action: View>: View {
    let status: StatusStyle
    let title: String
    let meta: String
    /// Swap the tile's dot for a spinner — connect/disconnect in flight.
    var busy: Bool = false
    @ViewBuilder var action: () -> Action

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(status.color.opacity(0.14))
                    .frame(width: 44, height: 44)
                if busy {
                    ProgressView()
                        .controlSize(.small)
                } else {
                    Circle()
                        .fill(status.color)
                        .frame(width: 12, height: 12)
                }
            }
            .accessibilityHidden(true)  // the title carries the state in words

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 16, weight: .semibold))
                if !meta.isEmpty {
                    Text(meta)
                        .font(.system(size: 12.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }

            Spacer(minLength: 12)

            action()
        }
        .padding(16)
        // controlBackground over windowBackground is a near-invisible lift in
        // light mode by design (the spec's #fbfbfc on #ffffff) — the hairline
        // is what draws the card; the fill is there for dark mode's #262628.
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 0.5)
        )
    }
}

extension ConnectionCard where Action == EmptyView {
    /// A card with no trailing action — the state IS the content. Tailscale
    /// peers use this: their actions (SSH, ping, exit node) live in the action
    /// row below, and duplicating one into the card would just crowd it.
    init(status: StatusStyle, title: String, meta: String, busy: Bool = false) {
        self.init(status: status, title: title, meta: meta, busy: busy, action: { EmptyView() })
    }
}

#if DEBUG
#Preview("Connection cards") {
    VStack(spacing: 12) {
        ConnectionCard(
            status: .offline,
            title: "Disconnected",
            meta: "Last connected yesterday · Full tunnel"
        ) {
            Button("Connect") {}.buttonStyle(.borderedProminent)
        }
        ConnectionCard(
            status: .online,
            title: "Connected",
            meta: "established 26s ago, rekeying in 14128s"
        ) {
            Button("Disconnect", role: .destructive) {}
                .buttonStyle(.borderedProminent).tint(.red)
        }
        ConnectionCard(
            status: .pending,
            title: "Connecting…",
            meta: "",
            busy: true
        ) {
            Button("Connect") {}.disabled(true)
        }
    }
    .padding()
    .frame(width: 640)
}
#endif
