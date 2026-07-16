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
    }

    // MARK: - Handlers

    @MainActor
    private func handleWillSleep() async {
        DebugLog.write("[sleep] willSleep — disconnecting all VPNs before sleep")
        // Disconnect every profile cleanly. This fires the proper
        // backend-specific RPC (swanctl --terminate, wg-quick down,
        // ovpncli kill) so the tunnels are properly torn down while
        // the network is still up. Failures are swallowed — if a
        // tunnel disconnect fails here, the system-sleep RPC below
        // sweeps it as belt-and-braces.
        await disconnectAllVpns()

        // Tell the helper to terminate any remaining IKEv2 SAs and
        // kill ovpncli processes. Best-effort — if the helper is
        // unreachable (rare race), we accept some cleanup happening
        // on the wake side instead.
        _ = try? await HelperClient.shared.systemSleep()

        DebugLog.write("[sleep] pre-sleep teardown complete")
    }

    @MainActor
    private func handleDidWake() async {
        DebugLog.write("[wake] didWake — resetting VPN state and cleaning up")

        // --- Optimistic reset ---
        // Mark every profile as disconnected before the first poll
        // returns. Any tunnel that legitimately auto-reconnected will
        // be corrected by the poll below — but the user sees an
        // honest "Disconnected" rather than a stale "Connected" while
        // they wait.
        for id in vpnConnectionStates.keys {
            vpnConnectionStates[id] = "disconnected"
        }
        // Drop all stale throughput/handshake metrics so the detail
        // view doesn't show pre-sleep byte counts for a dead tunnel.
        vpnByteCounters.removeAll()
        vpnByteRates.removeAll()
        vpnLastByteSample.removeAll()
        vpnLastHandshakeUnix.removeAll()
        vpnPeerEndpoints.removeAll()

        // --- Helper-side cleanup ---
        // Reset route guardian snapshot + sweep stale strongSwan
        // configs + kernel host routes. Fire-and-forget: if the
        // helper isn't reachable yet (rare; it's a LaunchDaemon that
        // doesn't sleep) the first poll will still reflect clean UI
        // state from the reset above.
        _ = try? await HelperClient.shared.systemWake()

        // --- Network settle ---
        // On wake the network interface is typically not ready yet.
        // Give it 2 seconds before polling so we don't flood the log
        // with "helper not reachable" or false-negative "disconnected"
        // entries from half-configured interfaces.
        try? await Task.sleep(for: .seconds(2))

        // --- Reconcile ---
        // Force a full poll. Any profile that auto-reconnected
        // (always-on, ovpncli reconnect loop) will show as connected.
        await pollAllVpnStates()
        DebugLog.write("[wake] post-wake states: \(vpnConnectionStates)")
    }
}
