import SwiftUI
import UniformTypeIdentifiers

/// Customer Report — aggregates a customer's site map, per-host
/// compliance scores, and recent deployments into a single
/// Markdown document the MSP can hand to the client.
///
/// We deliberately produce Markdown (not PDF directly):
///   - PDF gen requires pulling a heavy native dep or a system
///     pandoc dependency we don't ship.
///   - macOS Preview already turns Markdown → PDF when you Print
///     and choose "Save as PDF" — we just hand the user the
///     Markdown, then they can polish in their editor of choice
///     (Marked, Typora, Notion, GitHub PR description) before
///     converting if needed.
///
/// The sheet shows a live Markdown preview (rendered as
/// `Text`'s native AttributedString), with Copy / Save buttons.
struct CustomerReportSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    let customerSlug: String
    let customerName: String

    @State private var loading = true
    @State private var markdown: String = ""
    @State private var error: String?

    var body: some View {
        VStack(spacing: 0) {
            header
            if loading {
                loadingState
            } else if let error {
                errorState(error)
            } else {
                preview
            }
            footer
        }
        .frame(width: 880, height: 640)
        .task {
            await load()
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "doc.text.fill")
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 0) {
                Text("Customer report")
                    .font(.title3.weight(.semibold))
                Text("\(customerName) · \(markdown.split(separator: "\n").count) lines")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(14)
        .background(.background.secondary)
    }

    private var loadingState: some View {
        VStack(spacing: 10) {
            ProgressView()
            Text("Aggregating compliance + deployment data…")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorState(_ err: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Could not generate report", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .font(.headline)
            ScrollView {
                Text(err)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .padding(8)
            .background(.red.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .padding(20)
    }

    /// Render the Markdown using SwiftUI's native AttributedString
    /// support (macOS 12+). Tables don't render natively but
    /// headings, lists, bold, and links do — and that covers
    /// the bulk of our report's visual content.
    private var preview: some View {
        ScrollView {
            if let attributed = try? AttributedString(
                markdown: markdown,
                options: AttributedString.MarkdownParsingOptions(
                    interpretedSyntax: .inlineOnlyPreservingWhitespace
                )
            ) {
                Text(attributed)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(20)
                    .textSelection(.enabled)
            } else {
                Text(markdown)
                    .font(.system(.callout, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(20)
                    .textSelection(.enabled)
            }
        }
    }

    private var footer: some View {
        HStack {
            if !markdown.isEmpty {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(markdown, forType: .string)
                } label: {
                    Label("Copy Markdown", systemImage: "doc.on.doc")
                }
                Button {
                    saveToFile()
                } label: {
                    Label("Save as .md…", systemImage: "square.and.arrow.down")
                }
                Text("Tip: open the saved file in macOS Preview / Marked, then ⌘P → Save as PDF.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            Spacer()
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
        }
        .padding(14)
        .background(.background.secondary)
    }

    private func load() async {
        loading = true
        defer { loading = false }
        if let md = await appState.renderCustomerReport(slug: customerSlug) {
            markdown = md
        } else {
            error = appState.errorMessage.isEmpty
                ? "Report generation failed."
                : appState.errorMessage
        }
    }

    private func saveToFile() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [
            UTType(filenameExtension: "md") ?? .plainText,
            .plainText,
        ]
        let date = Date().formatted(.iso8601.year().month().day())
        let safeName = customerSlug.replacingOccurrences(of: "/", with: "-")
        panel.nameFieldStringValue = "\(safeName)-network-report-\(date).md"
        panel.title = "Save customer report"
        if panel.runModal() == .OK, let url = panel.url {
            try? markdown.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}
