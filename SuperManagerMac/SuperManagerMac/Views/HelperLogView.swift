import SwiftUI

/// Live-tail of `/var/log/supermanager-helper.log`. Lets the user
/// inspect what the helper is doing without dropping to Terminal.
/// Refreshes every 2 seconds while open. Auto-scrolls to bottom
/// on each refresh unless the user has scrolled up manually.
///
/// Sources its data from the helper's `tail_log` RPC (already in
/// place for diagnostics). 32 KB pulled per refresh — enough to
/// cover several minutes of activity even at high log volume.
struct HelperLogView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var logText: String = ""
    @State private var loadError: String?
    @State private var pollTask: Task<Void, Never>?
    @State private var autoScroll: Bool = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollViewReader { proxy in
                ScrollView {
                    Text(logText.isEmpty ? "(empty — waiting for log lines…)" : logText)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .id("logBottom")
                }
                .onChange(of: logText) { _, _ in
                    if autoScroll {
                        withAnimation(.linear(duration: 0.08)) {
                            proxy.scrollTo("logBottom", anchor: .bottom)
                        }
                    }
                }
            }
            Divider()
            footer
        }
        .frame(width: 760, height: 480)
        .onAppear {
            // Initial fetch + start the polling loop.
            startPolling()
        }
        .onDisappear {
            pollTask?.cancel()
            pollTask = nil
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.title3)
                .foregroundStyle(.secondary)
            Text("Helper Log")
                .font(.headline)
            Text("/var/log/supermanager-helper.log")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            Spacer()
            Toggle("Auto-scroll", isOn: $autoScroll)
                .toggleStyle(.switch)
                .controlSize(.small)
            Button {
                Task { await fetch() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .help("Refresh now.")
            .accessibilityLabel("Refresh helper log")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var footer: some View {
        HStack {
            if let err = loadError {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Text(err)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            Spacer()
            Button("Copy all") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(logText, forType: .string)
            }
            .controlSize(.small)
            .disabled(logText.isEmpty)
            Button("Done") { dismiss() }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { @MainActor in
            await fetch()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                await fetch()
            }
        }
    }

    private func fetch() async {
        do {
            // 32 KB tail. Enough for the last several minutes of
            // activity even at high log volume.
            let text = try await HelperClient.shared.tailLog(bytes: 32 * 1024)
            logText = text
            loadError = nil
        } catch {
            loadError = error.localizedDescription
        }
    }
}
