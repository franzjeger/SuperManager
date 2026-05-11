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
        DebugLog.write("[PDF] exportPdf: trying server PDF (silent)")
        // First try the server-side pandoc+LaTeX path — gives the
        // best typography when BasicTeX / tectonic is installed.
        // `silent: true` so the global "no PDF engine" error
        // dialog doesn't fire before we get a chance to fall
        // back to the WebKit renderer.
        var pdfData = await appState.renderEngagementPdf(
            engagementId: engagementId,
            silent: true
        )
        // Stash whatever message the silent call left in errorMessage —
        // we'll surface it ONLY if the fallback also fails.
        let serverErr = appState.errorMessage
        DebugLog.write("[PDF] exportPdf: server PDF returned \(pdfData?.count ?? 0) bytes; serverErr='\(serverErr)'")
        var htmlErr = ""
        if pdfData == nil {
            // No LaTeX engine? Fall back to the HTML path: ask
            // pandoc for HTML (no engine needed), render in
            // WKWebView, and export PDF locally. Always silent —
            // we handle the combined failure below.
            DebugLog.write("[PDF] exportPdf: server PDF failed, trying HTML+WebKit fallback")
            if let html = await appState.renderEngagementHtml(
                engagementId: engagementId,
                silent: true
            ) {
                DebugLog.write("[PDF] exportPdf: got HTML (\(html.count) chars), rendering")
                pdfData = Self.htmlToPdf(html)
                DebugLog.write("[PDF] exportPdf: htmlToPdf returned \(pdfData?.count ?? 0) bytes")
            } else {
                htmlErr = appState.errorMessage
                DebugLog.write("[PDF] exportPdf: HTML endpoint FAILED: \(htmlErr)")
            }
        }
        guard let pdf = pdfData else {
            let detail = !htmlErr.isEmpty
                ? "\n\nHTML endpoint failed: \(htmlErr)"
                : (serverErr.isEmpty ? "" : "\n\nDaemon: \(serverErr)")
            error = "Could not generate PDF. Check Console.app logs (filter \"SuperManagerMac\") for [PDF] entries.\(detail)"
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

    /// HTML → PDF via macOS-native `NSAttributedString(html:)` +
    /// `NSPrintOperation`. Synchronous, no async timing dance, no
    /// off-screen WKWebView in a fake window.
    ///
    /// Tradeoff: NSAttributedString's HTML import is older WebKit
    /// (NSHTMLReader) and handles CSS less faithfully than WKWebView.
    /// For an engagement report (headings, paragraphs, tables, code
    /// blocks) it's perfectly readable, and unlike the WKWebView
    /// path it actually works from a SwiftUI Task without window
    /// hosting tricks.
    @MainActor
    private static func htmlToPdf(_ html: String) -> Data? {
        DebugLog.write("[PDF] htmlToPdf: starting, html size=\(html.count)")
        guard let htmlData = html.data(using: .utf8) else {
            DebugLog.write("[PDF] htmlToPdf: UTF-8 encode failed")
            return nil
        }

        let attr: NSAttributedString
        do {
            attr = try NSAttributedString(
                data: htmlData,
                options: [
                    .documentType: NSAttributedString.DocumentType.html,
                    .characterEncoding: String.Encoding.utf8.rawValue,
                ],
                documentAttributes: nil
            )
        } catch {
            DebugLog.write("[PDF] htmlToPdf: NSAttributedString HTML parse failed: \(error)")
            return nil
        }
        DebugLog.write("[PDF] htmlToPdf: parsed HTML to \(attr.length) chars of attributed text")

        // US Letter @ 72 dpi (PDF native units).
        let pageSize = NSSize(width: 612, height: 792)
        let margin: CGFloat = 36
        let contentWidth = pageSize.width - 2 * margin

        // Tall throwaway NSTextView. `sizeToFit` packs the content
        // height; NSPrintOperation paginates by `verticalPagination`.
        let textView = NSTextView(
            frame: NSRect(x: 0, y: 0, width: contentWidth, height: 10_000)
        )
        textView.isEditable = false
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.textContainer?.containerSize = NSSize(
            width: contentWidth,
            height: .greatestFiniteMagnitude
        )
        textView.textContainer?.widthTracksTextView = false
        textView.textStorage?.setAttributedString(attr)
        textView.sizeToFit()

        let printInfo = NSPrintInfo()
        printInfo.paperSize = pageSize
        printInfo.orientation = .portrait
        printInfo.topMargin = margin
        printInfo.bottomMargin = margin
        printInfo.leftMargin = margin
        printInfo.rightMargin = margin
        printInfo.horizontalPagination = .fit
        printInfo.verticalPagination = .automatic

        let data = NSMutableData()
        let op = NSPrintOperation.pdfOperation(
            with: textView,
            inside: textView.bounds,
            to: data,
            printInfo: printInfo
        )
        op.showsPrintPanel = false
        op.showsProgressPanel = false

        guard op.run() else {
            DebugLog.write("[PDF] htmlToPdf: NSPrintOperation.run() returned false")
            return nil
        }
        DebugLog.write("[PDF] htmlToPdf: NSPrintOperation produced \(data.length) bytes")
        return data as Data
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

