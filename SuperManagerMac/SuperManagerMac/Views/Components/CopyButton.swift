import SwiftUI
import AppKit

/// Tiny reusable "Copy to clipboard" affordance. Renders as a
/// borderless monochrome glyph (`doc.on.doc`) so it can sit
/// inline next to a monospaced ID/CIDR/CVE without demanding
/// visual weight. On click it overwrites the system pasteboard
/// with `value` and briefly swaps the glyph for a checkmark so
/// the user gets feedback that the copy actually fired.
///
/// Used in 3+ places (CIDRs in SecurityView, finding/host IDs in
/// detail views, CVE numbers in finding rows) — extracted here
/// rather than being re-typed at every call site.
struct CopyButton: View {
    let value: String
    /// Custom help-tooltip text. Defaults to "Copy".
    var helpText: String = "Copy"

    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(value, forType: .string)
            copied = true
            // Brief checkmark-flash before reverting back. ~1.2 s
            // is enough to register without persisting longer
            // than the user's eye lingers on the glyph.
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(1200))
                copied = false
            }
        } label: {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                .font(.caption2)
                .foregroundStyle(copied ? .green : .secondary)
        }
        .buttonStyle(.plain)
        .help(helpText)
        .accessibilityLabel(helpText)
    }
}

#if DEBUG
#Preview {
    HStack {
        Text("10.0.50.0/24").font(.system(.caption, design: .monospaced))
        CopyButton(value: "10.0.50.0/24")
    }
    .padding()
}
#endif
