import SwiftUI

/// Subdomain enumeration via Certificate Transparency logs.
/// Queries crt.sh for every certificate ever issued for the
/// domain, extracts the unique hostnames. Useful for engagement-
/// scope sanity checks: "what hostnames does this org actually
/// have that I might not know about?"
struct SubdomainEnumSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AppState.self) private var appState

    @State private var domain: String = ""
    @State private var isRunning: Bool = false
    @State private var result: AppState.SubdomainEnumResult?

    var body: some View {
        VStack(spacing: 0) {
            header

            Form {
                Section {
                    HStack {
                        TextField("example.com", text: $domain)
                            .textFieldStyle(.roundedBorder)
                            .font(.body.monospaced())
                            .disabled(isRunning)
                            .onSubmit { Task { await run() } }
                        Button(isRunning ? "Querying…" : "Run") {
                            Task { await run() }
                        }
                        .keyboardShortcut(.return, modifiers: [])
                        .disabled(isRunning || cleanDomain.isEmpty)
                    }
                } header: {
                    Text("Domain")
                } footer: {
                    Text(
                        "Queries crt.sh's Certificate Transparency database for every "
                        + "cert ever issued for *.<domain>. Returns the unique hostnames. "
                        + "Passive recon — no traffic to the target. Typical runtime: "
                        + "5–20 seconds depending on cert count."
                    )
                    .font(.caption)
                }

                if let r = result {
                    Section("Summary") {
                        LabeledContent("Subdomains found") {
                            Text("\(r.found.count)").font(.body.bold())
                        }
                        LabeledContent("Certificates seen") {
                            Text("\(r.certCount)").foregroundStyle(.secondary)
                        }
                    }
                    if !r.found.isEmpty {
                        Section("Subdomains") {
                            ForEach(r.found, id: \.self) { host in
                                HStack {
                                    Text(host).font(.body.monospaced())
                                    Spacer()
                                    Button {
                                        copyToClipboard(host)
                                    } label: {
                                        Image(systemName: "doc.on.doc")
                                    }
                                    .buttonStyle(.borderless)
                                    .help("Copy hostname")
                                }
                            }
                        }
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                if let r = result, !r.found.isEmpty {
                    Button("Copy all (\(r.found.count))") {
                        copyToClipboard(r.found.joined(separator: "\n"))
                    }
                }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(12)
        }
        .frame(minWidth: 560, minHeight: 480)
    }

    private var header: some View {
        HStack {
            Image(systemName: "magnifyingglass.circle.fill")
                .foregroundStyle(.tint).imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("Subdomain enumeration").font(.headline)
                Text("Certificate-Transparency log search via crt.sh")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(.background.secondary)
    }

    private var cleanDomain: String {
        domain.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func run() async {
        guard !cleanDomain.isEmpty else { return }
        isRunning = true
        defer { isRunning = false }
        result = await appState.runSubdomainEnum(domain: cleanDomain)
    }

    private func copyToClipboard(_ s: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(s, forType: .string)
    }
}

#if DEBUG
#Preview {
    SubdomainEnumSheet().environment(AppState.previewSeeded)
}
#endif
