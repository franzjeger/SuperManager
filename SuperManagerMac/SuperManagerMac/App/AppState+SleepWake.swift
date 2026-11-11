import AppKit
import Foundation

extension AppState {
    /// Register for macOS sleep/wake notifications.
    ///
    /// Call once during app startup (idempotent — the system does not
    /// deduplicate NSWorkspace observers, so calling more than once from
    /// the same code path would register multiple listeners). In practice
    /// this is called from `RootView`'s `.task {}` block, which SwiftUI
    /// guarantees fires exactly once per window lifetime.
    ///
    /// ## What this fixes
    ///
    /// Without sleep/wake awareness SuperManager suffers three failure
    /// modes when the user closes the lid and later opens it elsewhere:
    ///
    /// 1. **Stale VPN state** — the polling loop's last sample showed
    ///    "connected" and that result is frozen until the next poll
    ///    fires. On wake the helper polls again, but by then the user
    ///    may have tried to use the (fake) connection. We reset all
    ///    states to "disconnected" immediately on wake so the UI is
    ///    honest before the first poll returns.
    ///
    /// 2. **Stale route guardian snapshot** — the guardian took a
    ///    snapshot of the default gateway on the *old* network
    ///    (e.g., `192.168.1.1 via en0`). On wake at a new location
    ///    it would try to "restore" that gateway — which is now
    ///    unreachable — flooding the routing table with useless
    ///    `route add` calls. `system_wake` tells the helper to clear
    ///    the snapshot so the guardian re-learns the new gateway.
    ///
    /// 3. **Stale kernel host routes** — if charon was killed mid-
    ///    tunnel during sleep it leaves a `<server_ip> via <old-gw>`
    ///    host route. The next connect attempt fails with "unable to
    ///    determine source address". `system_wake` sweeps those.
    func startSleepWakeMonitor() {
        guard !sleepWakeMonitorStarted else { return }
        sleepWakeMonitorStarted = true

        let wc = NSWorkspace.shared.notificationCenter

        // willSleep fires while the system is still fully running —
        // we get a few hundred milliseconds to do cleanup.
        wc.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in await self.handleWillSleep() }
        }

        // didWake fires when the system has resumed and the display
        // is coming back on, but typically *before* the network is
        // fully re-configured. We reset UI state immediately and
        // schedule a delayed re-poll to let the network settle.
        wc.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in await self.handleDidWake() }
        }

        // Wake the status poller out of closed-window backoff immediately when
        // the operator focuses SuperManager (`P3-8`).
        NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                self.bumpVpnFastPolling(seconds: 6)
                await self.refreshMissingDependencies()
            }
        }
    }

    // MARK: - Handlers

    @MainActor
    private func handleWillSleep() async {
        // Snapshot every VPN profile that was active right before sleep (`P2-8`)
        // so `handleDidWake` restores the operator's active tunnels instead of
        // leaving them permanently disconnected after every lid close.
        let activeStates: Set<String> = ["connected", "connecting", "reconnecting"]
        vpnProfilesActiveBeforeSleep = Set(
            vpnProfiles
                .map(\.id)
                .filter { activeStates.contains(vpnConnectionStates[$0] ?? "") }
        )
        DebugLog.write("[sleep] willSleep — active before sleep=\(vpnProfilesActiveBeforeSleep); disconnecting all VPNs")

        await disconnectAllVpns(suppressKillSwitchReleaseForSleepReconnect: false)

        _ = try? await HelperClient.shared.systemSleep()

        DebugLog.write("[sleep] pre-sleep teardown complete")
    }

    @MainActor
    private func handleDidWake() async {
        let toReconnect = vpnProfilesActiveBeforeSleep
        vpnProfilesActiveBeforeSleep.removeAll()
        DebugLog.write("[wake] didWake — resetting VPN state, cleaning up, will reconnect=\(toReconnect)")

        for id in vpnConnectionStates.keys {
            bumpVpnGeneration(id)
            vpnConnectionStates[id] = "disconnected"
        }
        vpnByteCounters.removeAll()
        vpnByteRates.removeAll()
        vpnLastByteSample.removeAll()
        vpnLastHandshakeUnix.removeAll()
        vpnPeerEndpoints.removeAll()
        vpnLiveRouting.removeAll()
        vpnLiveDetails.removeAll()

        _ = try? await HelperClient.shared.systemWake()

        // Allow physical interface / Wi-Fi association + DHCP to settle on wake
        // before polling and re-establishing pre-sleep tunnels.
        try? await Task.sleep(for: .seconds(3))

        await pollAllVpnStates()

        if !toReconnect.isEmpty && !LockState.shared.isLocked {
            for profileId in toReconnect {
                let current = vpnConnectionStates[profileId] ?? "disconnected"
                guard current != "connected" && current != "connecting" else { continue }
                guard let summary = vpnProfiles.first(where: { $0.id == profileId }) else { continue }
                if summary.backend.lowercased().contains("azure") {
                    ActivityLog.shared.record(
                        profileId: profileId,
                        kind: .disconnectComplete,
                        message: "Disconnected across system sleep (Azure Entra sign-in required to reconnect)"
                    )
                    continue
                }
                DebugLog.write("[wake] reconnecting pre-sleep VPN profile \(summary.name) (\(profileId))")
                let result = await connectProfile(profileId: profileId, interactive: false)
                if !result.success {
                    DebugLog.write("[wake] post-wake reconnect failed for \(profileId): \(result.message)")
                }
            }
            await pollAllVpnStates()
        }
        DebugLog.write("[wake] post-wake states: \(vpnConnectionStates)")
    }
}
