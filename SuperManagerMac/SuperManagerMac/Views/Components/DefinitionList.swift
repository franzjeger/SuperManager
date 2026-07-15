import SwiftUI

/// One key/value row of a `DefinitionList`.
struct DefinitionRow: Identifiable {
    let id = UUID()
    let key: String
    let value: String
    /// IPs, IDs, fingerprints and subnets are monospaced so digits align and
    /// stay scannable; prose values ("Full tunnel", an OS name) are not.
    let mono: Bool

    init(_ key: String, _ value: String, mono: Bool = true) {
        self.key = key
        self.value = value
        self.mono = mono
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
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text(row.key)
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .frame(width: keyWidth, alignment: .leading)
                    Text(row.value)
                        .font(row.mono
                              ? .system(size: 13, design: .monospaced)
                              : .system(size: 13))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(.vertical, 7)

                if index < rows.count - 1 {
                    Divider()
                }
            }
        }
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
