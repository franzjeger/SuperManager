import SwiftUI
import AppKit
import WebKit

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
            .help("Renders via pandoc. For typographic quality install `tectonic` or `basictex`; otherwise falls back to a built-in WebKit renderer.")

            Button("Close") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(14)
        .background(.background.secondary)
    }

    private func exportPdf() async {
        exportingPdf = true
        defer { exportingPdf = false }
        // First try the server-side pandoc+LaTeX path — gives the
        // best typography when BasicTeX / tectonic is installed.
        var pdfData = await appState.renderEngagementPdf(engagementId: engagementId)
        var sourceNote: String?
        if pdfData == nil {
            // No LaTeX engine? Fall back to the HTML path: ask
            // pandoc for HTML (no engine needed), render in
            // WKWebView, and export PDF locally. The user always
            // gets a PDF as long as pandoc itself is installed.
            sourceNote = appState.errorMessage
            if let html = await appState.renderEngagementHtml(engagementId: engagementId) {
                pdfData = await Self.htmlToPdf(html)
            }
        }
        guard let pdf = pdfData else {
            let hint = (sourceNote?.isEmpty == false ? "\n\n" + (sourceNote ?? "") : "")
            error = "Could not generate PDF. Install pandoc + a PDF engine (`brew install --cask basictex` or `brew install tectonic`) and retry.\(hint)"
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

    /// Render an HTML string to PDF via an offscreen `WKWebView`.
    /// Used as the no-LaTeX fallback for PDF export.
    @MainActor
    private static func htmlToPdf(_ html: String) async -> Data? {
        let config = WKWebViewConfiguration()
        let webView = WKWebView(
            frame: NSRect(x: 0, y: 0, width: 816, height: 1056), // ~US Letter @ 96 dpi
            configuration: config
        )
        webView.loadHTMLString(html, baseURL: nil)
        // Wait for the page to finish loading before printing —
        // KVO on `isLoading` is the most reliable signal across
        // the WKWebView lifecycle.
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            var token: NSKeyValueObservation? = nil
            token = webView.observe(\.isLoading, options: [.initial, .new]) { wv, _ in
                if !wv.isLoading {
                    token?.invalidate()
                    cont.resume()
                }
            }
        }
        // Tiny extra delay so any deferred layout settles before
        // we snapshot. PDF render fails silently if layout isn't
        // complete.
        try? await Task.sleep(nanoseconds: 250_000_000)
        let pdfConfig = WKPDFConfiguration()
        return try? await webView.pdf(configuration: pdfConfig)
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
