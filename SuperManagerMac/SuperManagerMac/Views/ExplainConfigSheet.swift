import SwiftUI

/// "Explain config" — Claude-augmented analysis of FortiOS or
/// UniFi configuration text.
///
/// Use cases:
///   - Auditor pastes a FortiOS block they don't fully understand
///     and gets a plain-English explanation per setting.
///   - Engineer pastes a controversial change and asks "what does
///     this actually do?".
///   - Customer-facing: paste the whole rendered template and
///     get a non-technical summary for the deployment report.
///
/// We send the user's text + a tightly-scoped system prompt to
/// Claude. Output is plain Markdown which we render as
/// monospaced text for now — a future revision could parse it
/// into structured sections.
struct ExplainConfigSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var settings = AppSettings.shared

    /// Optional pre-fill — when invoked from a context that
    /// already has config in hand (e.g. "Explain this rendered
    /// template" from ProvisioningView), the caller passes it
    /// here to skip the paste step.
    let initialConfig: String

    @State private var configText: String = ""
    @State private var explanation: String = ""
    @State private var loading = false
    @State private var error: String?
    @FocusState private var inputFocused: Bool

    init(initialConfig: String = "") {
        self.initialConfig = initialConfig
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            HStack(alignment: .top, spacing: 0) {
                inputPane
                Divider()
                outputPane
            }
            footer
        }
        .frame(width: 960, height: 620)
        .onAppear {
            if configText.isEmpty {
                configText = initialConfig
            }
        }
        .task {
            try? await Task.sleep(for: .milliseconds(100))
            inputFocused = true
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "sparkles")
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 0) {
                Text("Explain configuration")
                    .font(.title3.weight(.semibold))
                Text("Paste FortiOS CLI or UniFi JSON. Claude returns a plain-English explanation.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !settings.hasAnthropicKey {
                Label("API key required", systemImage: "key")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(14)
        .background(.background.secondary)
    }

    private var inputPane: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Configuration")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text("\(configText.count) chars · \(configText.split(separator: "\n").count) lines")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            TextEditor(text: $configText)
                .font(.system(.caption, design: .monospaced))
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(8)
                .background(.background.tertiary)
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .focused($inputFocused)
        }
        .padding(14)
        .frame(maxWidth: .infinity)
    }

    private var outputPane: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Explanation")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                if !explanation.isEmpty {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(explanation, forType: .string)
                    } label: {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                    .controlSize(.small)
                }
            }
            if loading {
                VStack(spacing: 10) {
                    ProgressView()
                    Text("Claude is reading the config…")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let error {
                ScrollView {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.red.opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
                .frame(maxHeight: .infinity)
            } else if explanation.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "text.bubble")
                        .font(.system(size: 40))
                        .foregroundStyle(.tertiary)
                    Text("Click 'Explain' to send the config to Claude.")
                        .font(.callout)
                        .foregroundStyle(.tertiary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    Text(explanation)
                        .font(.callout)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .textSelection(.enabled)
                }
                .frame(maxHeight: .infinity)
                .background(.background.tertiary)
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity)
    }

    private var footer: some View {
        HStack {
            Spacer()
            Button("Close") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Button {
                Task { await explain() }
            } label: {
                if loading {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Explaining…")
                    }
                } else {
                    Label("Explain", systemImage: "sparkles")
                }
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .disabled(
                loading
                    || configText.trimmingCharacters(in: .whitespaces).isEmpty
                    || !settings.hasAnthropicKey
            )
        }
        .padding(14)
        .background(.background.secondary)
    }

    private func explain() async {
        loading = true
        defer { loading = false }
        error = nil
        explanation = ""
        let systemPrompt = """
You are an expert network engineer reviewing FortiOS or UniFi controller configurations. \
The user pastes a config snippet. Respond with a plain-English explanation organized as:

1. **One-line summary** of what the config does as a whole.
2. **Per-setting breakdown** — for each meaningful directive, one bullet explaining its effect and why it might be set this way.
3. **Security notes** — any settings worth flagging (insecure defaults, deprecated options, missing hardening).
4. **Compatibility notes** — known issues with specific firmware versions or deployment scenarios.

Keep the explanation concise. Use Markdown headings + bullets but no code fences.
"""
        do {
            let result = try await ClaudeClient.send(
                system: systemPrompt,
                userMessage: configText,
                apiKey: settings.anthropicApiKey
            )
            explanation = result
        } catch {
            self.error = error.localizedDescription
        }
    }
}
