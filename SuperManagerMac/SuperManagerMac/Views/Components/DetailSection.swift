import SwiftUI

/// One titled block in a detail pane — "Configuration", "Routing & protection",
/// "Live tunnel". Sections are the grid items of `DetailColumns`, so on a wide
/// window they sit side by side instead of stacking down the left edge.
///
/// `accessory` is the optional control on the heading line — the spec's
/// "VLANs section with a right-aligned Add VLAN button". It lives here rather
/// than in each caller so a section-level action always sits in the same spot
/// with the same alignment, instead of every view hand-building the heading
/// row and drifting.
struct DetailSection<Content: View, Accessory: View>: View {
    let title: String
    private let accessory: Accessory
    private let content: Content

    init(
        title: String,
        @ViewBuilder accessory: () -> Accessory,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.accessory = accessory()
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(title.uppercased())
                    .font(.system(size: 11, weight: .semibold))
                    .tracking(0.5)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 8)
                accessory
            }
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

extension DetailSection where Accessory == EmptyView {
    /// The common case: a heading and its content, no control on the line.
    init(title: String, @ViewBuilder content: () -> Content) {
        self.init(title: title, accessory: { EmptyView() }, content: content)
    }
}

/// The dead-space fix.
///
/// The detail pane is ~1000pt wide at full screen and the old content hugged
/// the left ~300pt of it. This lays sections out in a grid that fits as many
/// columns as the width allows and reflows to a single column when narrow —
/// the SwiftUI equivalent of the spec's `repeat(auto-fit, minmax(340px, 1fr))`.
/// Wide displays get used; narrow ones still read top to bottom.
struct DetailColumns<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        LazyVGrid(
            columns: [GridItem(.adaptive(minimum: 340), spacing: 40, alignment: .topLeading)],
            alignment: .leading,
            spacing: 28
        ) {
            content
        }
    }
}

/// A single switch with its own explanation. The helper line is not decoration:
/// "Kill switch" and "Always on" are both destructive-adjacent settings whose
/// behaviour you cannot guess from the label alone.
struct ToggleRow: View {
    let title: String
    let help: String
    @Binding var isOn: Bool
    var disabled: Bool = false

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                Text(help)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Toggle("", isOn: $isOn)
                .toggleStyle(.switch)
                .labelsHidden()
                .disabled(disabled)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }
}

/// Bordered container that groups `ToggleRow`s, separated by hairlines — the
/// same shape a macOS `Form` gives you, but usable inside a grid cell.
struct ToggleGroup<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            content
        }
        .background(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        )
    }
}

#if DEBUG
#Preview("Detail grammar") {
    @Previewable @State var kill = false
    @Previewable @State var always = true

    return ScrollView {
        DetailColumns {
            DetailSection(title: "Configuration") {
                DefinitionList(rows: [
                    DefinitionRow("Server", "141.0.90.150"),
                    DefinitionRow("Username", "sybr_admin"),
                    DefinitionRow("Tunnel mode", "Full tunnel", mono: false),
                    DefinitionRow("Local ID", "sybr-porsgrunn"),
                ])
            }
            DetailSection(title: "Routing & protection") {
                ToggleGroup {
                    ToggleRow(
                        title: "Kill switch",
                        help: "Block all traffic if the tunnel drops.",
                        isOn: $kill
                    )
                    Divider()
                    ToggleRow(
                        title: "Always on",
                        help: "Reconnect automatically on network change.",
                        isOn: $always
                    )
                }
            }
        }
        .padding(30)
    }
    .frame(width: 900, height: 400)
}
#endif
