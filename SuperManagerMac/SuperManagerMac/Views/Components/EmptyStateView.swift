import SwiftUI

/// The detail pane's placeholder when nothing is selected.
///
/// Deliberately more than a glyph plus a noun. The old placeholders said
/// "Select a VPN profile" and stopped, which tells the user what they already
/// know; the `hint` line says what they can DO once they pick something, so an
/// empty pane teaches the section instead of just admitting it's empty.
struct EmptyStateView: View {
    let systemImage: String
    let title: String
    var hint: String?

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 52, weight: .light))
                .foregroundStyle(.tertiary)
            Text(title)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.secondary)
            if let hint {
                Text(hint)
                    .font(.system(size: 12.5))
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    // Held narrow so the hint reads as one calm sentence
                    // rather than a line stretched across a wide pane.
                    .frame(maxWidth: 280)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
#Preview("Empty states") {
    HStack(spacing: 0) {
        EmptyStateView(
            systemImage: "lock.shield",
            title: "Select a VPN profile",
            hint: "Pick a tunnel from the list to view its status, routing and credentials."
        )
        Divider()
        EmptyStateView(
            systemImage: "terminal",
            title: "Select a host",
            hint: "Pick a host to open a session, review its details, or run a compliance scan."
        )
    }
    .frame(width: 900, height: 380)
}
#endif
