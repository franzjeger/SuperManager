// Dev-only view; source is copied into the isolated app build.
import SwiftUI

struct TailscaleServiceSwitch: View {
    @Environment(AppState.self) private var appState
    @State private var stableRunning = false
    @State private var devRunning = false
    @State private var loaded = false
    @State private var busy = false
    @State private var failure: String?
    @State private var target: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("TAILSCALE SERVICE").font(.caption.weight(.semibold))
            Text(loaded ? "Dev: \(devRunning ? "running" : "stopped") · Regular: \(stableRunning ? "running" : "stopped")" : "Checking services…")
            Text("Use one Tailscale node at a time. Switching briefly interrupts Tailscale connections and preserves each node’s login and settings. The other service stays paused after restart.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Use Dev Tailscale") { target = "dev" }
                    .disabled(busy || (loaded && devRunning && !stableRunning))
                Button("Use regular Tailscale") { target = "stable" }
                    .disabled(busy || (loaded && stableRunning && !devRunning))
                Button("Refresh") { Task { await refresh() } }.disabled(busy)
            }
            if busy { ProgressView("Switching Tailscale service…") }
            if let failure { Text(failure).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
        }
        .task { await refresh() }
        .alert("Switch Tailscale service?", isPresented: Binding(get: { target != nil }, set: { if !$0 { target = nil } })) {
            Button("Switch") {
                guard let selected = target else { return }; target = nil
                Task {
                    busy = true; failure = nil
                    defer { busy = false }
                    do { _ = try await HelperClient.shared.devTailscaleSwitch(selected) }
                    catch { failure = error.localizedDescription }
                    await refresh()
                    await appState.refreshTailscale()
                    await appState.refreshTailscaledDaemon()
                }
            }
            Button("Cancel", role: .cancel) { target = nil }
        } message: {
            Text("Current Tailscale connections will be interrupted. The selected node will use its own saved identity. Other VPN tunnels are not switched.")
        }
    }
    private func refresh() async {
        do {
            let status = try await HelperClient.shared.devTailscaleServiceStatus()
            stableRunning = status["stable_running"] as? Bool ?? false
            devRunning = status["dev_running"] as? Bool ?? false
            loaded = true
        } catch { failure = error.localizedDescription; loaded = false }
    }
}
