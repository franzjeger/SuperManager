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
        if pdfData == nil {
            // No LaTeX engine? Fall back to the HTML path: ask
            // pandoc for HTML (no engine needed), render in
            // WKWebView, and export PDF locally. Always silent —
            // we handle the combined failure below.
            if let html = await appState.renderEngagementHtml(
                engagementId: engagementId,
                silent: true
            ) {
                pdfData = await Self.htmlToPdf(html)
            }
        }
        guard let pdf = pdfData else {
            let hint = serverErr.isEmpty ? "" : "\n\nDaemon said: \(serverErr)"
            error = "Could not generate PDF. Ensure pandoc is installed (Settings → Integrations).\(hint)"
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
    ///
    /// We use `WKNavigationDelegate.didFinish` rather than KVO on
    /// `isLoading` because the latter races: with `.initial` the
    /// observer fires synchronously at attach time (before
    /// `loadHTMLString` flips `isLoading=true`), so the continuation
    /// resumed instantly and `pdf(configuration:)` ran against an
    /// empty WebView. The user got the daemon's "no PDF engine"
    /// dialog and then nothing — the fallback silently produced
    /// empty/nil data.
    @MainActor
    private static func htmlToPdf(_ html: String) async -> Data? {
        let webView = WKWebView(
            frame: NSRect(x: 0, y: 0, width: 816, height: 1056), // ~US Letter @ 96 dpi
            configuration: WKWebViewConfiguration()
        )
        // Strong-hold the delegate for the lifetime of the await —
        // WKWebView only weakly references it.
        let delegate = HtmlToPdfDelegate()
        webView.navigationDelegate = delegate

        let loaded: Bool = await withCheckedContinuation { cont in
            delegate.onFinish = { cont.resume(returning: true) }
            delegate.onFail = { _ in cont.resume(returning: false) }
            webView.loadHTMLString(html, baseURL: nil)
        }
        guard loaded else { return nil }

        // Let one runloop tick pass so deferred layout (web-fonts,
        // image decoding) settles before we snapshot.
        try? await Task.sleep(nanoseconds: 150_000_000)

        return try? await webView.pdf(configuration: WKPDFConfiguration())
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

/// Bridges `WKNavigationDelegate` to async closures. Used by the
/// PDF-fallback path in `EngagementReportSheet.htmlToPdf` to await
/// page-load completion via the proper navigation API rather than
/// racing against `isLoading` KVO. Lives outside the View struct
/// because `WKWebView.navigationDelegate` is `weak` — the delegate
/// has to outlive the assignment, which a stored property on a
/// SwiftUI View wouldn't.
private final class HtmlToPdfDelegate: NSObject, WKNavigationDelegate {
    var onFinish: (() -> Void)?
    var onFail: ((Error) -> Void)?

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        onFinish?()
    }
    func webView(
        _ webView: WKWebView,
        didFail navigation: WKNavigation!,
        withError error: Error
    ) {
        onFail?(error)
    }
    func webView(
        _ webView: WKWebView,
        didFailProvisionalNavigation navigation: WKNavigation!,
        withError error: Error
    ) {
        onFail?(error)
    }
}
