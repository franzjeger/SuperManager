import SwiftUI

/// One key/value row of a `DefinitionList`.
struct DefinitionRow: Identifiable {
    let id = UUID()
    let key: String
    let value: String
    /// IPs, IDs, fingerprints and subnets are monospaced so digits align and
    /// stay scannable; prose values ("Full tunnel", an OS name) are not.
    let mono: Bool
    /// Present-but-rarely-needed values — a profile UUID you only reach for
    /// when something is wrong. Rendered tertiary so it stays available
    /// without competing with the address and username above it.
    let deemphasized: Bool

    init(_ key: String, _ value: String, mono: Bool = true, deemphasized: Bool = false) {
        self.key = key
        self.value = value
        self.mono = mono
        self.deemphasized = deemphasized
    }
}

/// Two-column key/value list with hairline separators — the detail pane's
/// standard way to present configuration.
///
/// Values are selectable: these are addresses, UUIDs and fingerprints that the
/// operator copies into a terminal or a ticket all day, and a value you can see
/// but not copy is a small daily tax.
struct DefinitionList: View {
    let rows: [DefinitionRow]

    /// Fixed key column so keys and values line up across sections in the same
    /// grid cell, rather than each list picking its own width.
    private let keyWidth: CGFloat = 140

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                // Side-by-side when the value fits, stacked when it doesn't.
                //
                // These lists live in ~340pt grid cells, so after the key column
                // a value gets ~190pt — enough for an IP or a username, not for
                // a 36-character UUID (~280pt in 13pt mono) or a long
                // split-route list. Those used to wrap mid-string into a ragged
                // two-line block. Now they drop below the key and take the full
                // cell width instead. `.fixedSize()` on the first branch's value
                // is what makes this work: without it Text reports that it
                // "fits" at any width by wrapping, and the fallback never fires.
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        keyText(row)
                            .frame(width: keyWidth, alignment: .leading)
                        valueText(row)
                            .fixedSize()
                        Spacer(minLength: 0)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        keyText(row)
                        valueText(row)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(.vertical, 7)

                if index < rows.count - 1 {
                    Divider()
                }
            }
        }
    }

    private func keyText(_ row: DefinitionRow) -> some View {
        Text(row.key)
            .font(.system(size: 13))
            .foregroundStyle(.secondary)
    }

    private func valueText(_ row: DefinitionRow) -> some View {
        Text(row.value)
            .font(row.mono
                  ? .system(size: 13, design: .monospaced)
                  : .system(size: 13))
            .foregroundStyle(row.deemphasized ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.primary))
            .textSelection(.enabled)
    }
}

#if DEBUG
#Preview("Definition list") {
    DefinitionList(rows: [
        DefinitionRow("Server", "141.0.90.150"),
        DefinitionRow("Username", "sybr_admin"),
        DefinitionRow("Tunnel mode", "Full tunnel", mono: false),
        DefinitionRow("Local ID", "sybr-porsgrunn"),
        DefinitionRow("Profile ID", "f1bb5fb6-ad97-491a-a346-a5ff6e3e169b"),
    ])
    .padding()
    .frame(width: 460)
}
#endif
