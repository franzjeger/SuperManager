import SwiftUI

/// Settings tab for network-shaped tunables and audit views.
///
/// Tranche 1 scope (intentionally limited):
///   1. **Device-type overrides** — list every operator-set
///      rule (by MAC + by OUI prefix) with a Revoke button.
///      Surfaces the previously-wired-but-invisible
///      `device_type_overrides_list` reader RPC. The setter
///      is wired from the NetworkScanSheet host-row menu; the
///      reader had no UI consumer until this tab.
///
/// Deferred to Tranche 2 (deliberately not here):
///   - VPN default DNS fallbacks (helper has the state, no UI)
///   - VPN kill-switch defaults
///   - Auto-reconnect defaults
///   These touch the kill-switch coupling work (Q5) that
///   Tranche 2 owns. Adding the controls here without the
///   coupling fix would be premature — see Phase-1 Q5 + the
///   Tranche-2 Window-C entry.
struct NetworkSettingsView: View {
    @Environment(AppState.self) private var appState

    @State private var overrides: DeviceTypeOverrides = .empty
    @State private var loading = false
    @State private var clearingKey: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                deviceTypeOverridesCard
                tranche2Placeholder
            }
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .task { await refresh() }
    }

    // MARK: - Device-type overrides

    private var deviceTypeOverridesCard: some View {
        sectionCard(
            title: "Device-type overrides",
            systemImage: "tag.fill"
        ) {
            Text("Rules the operator set from network-scan results when the engine's OUI lookup + banner heuristics misclassified a device. Exact-MAC entries win over OUI-prefix entries. Re-scanning a host with an active override keeps the override, not the heuristic.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if loading {
                ProgressView().controlSize(.small)
            } else if overrides.isEmpty {
                ContentUnavailableView(
                    "No overrides set",
                    systemImage: "tag",
                    description: Text("Open a network scan → click the `…` menu on any host row → 'Set device type…' to override the engine's classification.")
                )
                .frame(maxHeight: 180)
            } else {
                if !overrides.byMac.isEmpty {
                    subheading("Per-MAC (\(overrides.byMac.count))")
                    ForEach(sortedKeys(overrides.byMac), id: \.self) { mac in
                        overrideRow(
                            key: mac,
                            scope: .mac,
                            type: overrides.byMac[mac] ?? ""
                        )
                    }
                }
                if !overrides.byOui.isEmpty {
                    subheading("Per-OUI prefix (\(overrides.byOui.count))")
                    ForEach(sortedKeys(overrides.byOui), id: \.self) { oui in
                        overrideRow(
                            key: oui,
                            scope: .oui,
                            type: overrides.byOui[oui] ?? ""
                        )
                    }
                }
            }

            HStack {
                Button("Refresh") { Task { await refresh() } }
                    .controlSize(.small)
                Spacer()
            }
        }
    }

    private func subheading(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.top, 4)
    }

    private func overrideRow(
        key: String,
        scope: AppState.DeviceTypeOverrideScope,
        type: String
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: scope == .mac ? "barcode" : "rectangle.3.group.fill")
                .foregroundStyle(.tint)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 1) {
                Text(key).font(.body.monospaced())
                Text("→ \(type)")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await revoke(key: key, scope: scope) }
            } label: {
                if clearingKey == key {
                    ProgressView().controlSize(.mini)
                } else {
                    Label("Revoke", systemImage: "xmark.circle")
                }
            }
            .controlSize(.small)
            .disabled(clearingKey != nil)
        }
        .padding(.vertical, 2)
    }

    // MARK: - Tranche 2 placeholder

    /// Honest placeholder for the tunables that need Tranche 2's
    /// kill-switch coupling work to land first. Documenting
    /// here so the operator knows the tab is incomplete by
    /// design, not by oversight.
    private var tranche2Placeholder: some View {
        sectionCard(
            title: "Tunnel defaults",
            systemImage: "ellipsis.curlybraces"
        ) {
            Text("DNS fallback servers, kill-switch defaults, and auto-reconnect policy land in this tab in Tranche 2 — they're sequenced behind the kill-switch coupling fix (Phase-1 Q5 Window C). For now they live on individual VPN profiles via the per-row edit sheets.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Section card chrome

    @ViewBuilder
    private func sectionCard<C: View>(
        title: String,
        systemImage: String,
        @ViewBuilder content: () -> C
    ) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: systemImage)
                    .foregroundStyle(.tint)
                Text(title).font(.headline)
                Spacer()
            }
            content()
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 10).fill(.background.secondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10).stroke(.separator, lineWidth: 0.5)
        )
    }

    // MARK: - Data ops

    private func refresh() async {
        loading = true
        defer { loading = false }
        overrides = await appState.loadDeviceTypeOverrides()
    }

    private func revoke(
        key: String,
        scope: AppState.DeviceTypeOverrideScope
    ) async {
        clearingKey = key
        defer { clearingKey = nil }
        _ = await appState.setDeviceTypeOverride(
            mac: key,
            scope: scope,
            deviceType: nil
        )
        await refresh()
    }

    private func sortedKeys(_ map: [String: String]) -> [String] {
        map.keys.sorted()
    }
}
