import SwiftUI
import AppKit

/// Renders the engagement report (Markdown) and lets the user
/// copy to clipboard or save to disk. Pandoc-friendly so a future
/// "Export PDF" button can shell out to pandoc with this same
/// Markdown as input.
struct EngagementReportSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    let engagementId: String
    let title: String

    @State private var markdown: String = ""
    @State private var loading = true
    @State private var error: String?
    @State private var saveTarget: SaveTarget?
    @ScaledMetric private var sheetWidth: CGFloat = 820
    @ScaledMetric private var sheetHeight: CGFloat = 720

    struct SaveTarget: Identifiable {
        let id = UUID()
        let url: URL
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            content
            footer
        }
        .frame(width: sheetWidth, height: sheetHeight)
        .task { await load() }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "doc.text.fill")
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 1) {
                Text("Engagement report")
                    .font(.headline)
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(14)
        .background(.background.secondary)
    }

    @ViewBuilder
    private var content: some View {
        if loading {
            VStack {
                Spacer()
                ProgressView()
                Text("Rendering report…").font(.caption).foregroundStyle(.secondary)
                Spacer()
            }
            .frame(maxWidth: .infinity)
        } else if let error {
            VStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(.red)
                Text(error)
                    .multilineTextAlignment(.center)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .padding(40)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                Text(markdown)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(14)
            }
            .background(.background.tertiary)
        }
    }

    @State private var exportingPdf = false

    private var footer: some View {
        HStack {
            Spacer()
            Button("Copy Markdown") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(markdown, forType: .string)
            }
            .disabled(markdown.isEmpty)

            Button("Save .md…") { saveToDisk() }
                .disabled(markdown.isEmpty)

            Button {
                Task { await exportPdf() }
            } label: {
                if exportingPdf {
                    HStack(spacing: 4) {
                        ProgressView().controlSize(.small)
                        Text("Rendering PDF…")
                    }
                } else {
                    Text("Export PDF…")
                }
            }
            .disabled(markdown.isEmpty || exportingPdf)
            .help("Renders via pandoc — install with `brew install pandoc basictex` if missing.")

            Button("Close") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(14)
        .background(.background.secondary)
    }

    private func exportPdf() async {
        exportingPdf = true
        defer { exportingPdf = false }
        guard let pdf = await appState.renderEngagementPdf(engagementId: engagementId) else {
            error = "PDF rendering failed — verify pandoc is installed (Settings → Integrations)."
            return
        }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.pdf]
        panel.nameFieldStringValue = "\(title.replacingOccurrences(of: " ", with: "_")).pdf"
        panel.canCreateDirectories = true
        panel.title = "Save engagement report (PDF)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try pdf.write(to: url, options: .atomic)
        } catch {
            self.error = "Could not save PDF: \(error.localizedDescription)"
        }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        if let md = await appState.renderEngagementReport(engagementId: engagementId) {
            markdown = md
        } else {
            error = appState.errorMessage.isEmpty ? "Could not render report." : appState.errorMessage
        }
    }

    private func saveToDisk() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "\(title.replacingOccurrences(of: " ", with: "_")).md"
        panel.canCreateDirectories = true
        panel.title = "Save engagement report"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try markdown.data(using: .utf8)?.write(to: url, options: .atomic)
            saveTarget = SaveTarget(url: url)
        } catch {
            self.error = "Could not save: \(error.localizedDescription)"
        }
    }
}
