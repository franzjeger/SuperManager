import AppKit
import Foundation
import SwiftUI

/// One status-poll snapshot for a single VPN profile, returned by
/// `fetchProfileStatus`. Bundled into a struct so adding a new live
/// metric (e.g. RTT, uptime) doesn't require changing every call
/// site of the polling task group.
struct VpnPollSample {
    let profileId: String
    let state: String
    let bytes: (UInt64, UInt64)?
    let lastHandshakeUnix: Int64?
    let peerEndpoint: String?
    /// What the tunnel routes, when its status says.
    var routing: VpnLiveRouting?
    /// Live UI metadata populated by the single global poller (`P3-8`).
    var detail: AppState.VpnLiveDetail = .init()

    static func disconnected(profileId: String) -> VpnPollSample {
        VpnPollSample(
            profileId: profileId,
            state: "disconnected",
            bytes: nil,
            lastHandshakeUnix: nil,
            peerEndpoint: nil
        )
    }
}

/// What a connected tunnel routes, as its backend's status reports it.
struct VpnLiveRouting: Equatable {
    /// Whether it took the default route. nil: the status does not say, and
    /// the profile's own setting stands.
    let takesAll: Bool?
    /// The networks it carries besides.
    let routes: [String]

    /// IKEv2 reports the selectors the gateway granted: everything, or the
    /// networks it narrowed a full tunnel to.
    static func ikev2(selectors: [String]) -> VpnLiveRouting? {
        guard !selectors.isEmpty else { return nil }
        let everything: Set = ["0.0.0.0/0", "::/0"]
        return VpnLiveRouting(
            takesAll: selectors.contains("0.0.0.0/0"),
            routes: selectors.filter { !everything.contains($0) }
        )
    }
}

extension AppState {
    /// Single sweep across all profiles. Each backend has its own
    /// status RPC on the helper. Helper absent: leave existing states
    /// alone — the helper might just be racing a `launchctl bootout` /
    /// `bootstrap`, and trampling stable states with "disconnected"
    /// causes user-visible flicker. Helper present but not answering:
    /// see below. Public so connect/disconnect actions can force a
    /// refresh without waiting for the timer.
    /// Coalesced, non-reentrant sweep across all VPN profiles (`P2-10`, `P3-8`).
    /// Concurrent callers join the in-flight task (scheduling one follow-up
    /// sweep so post-action callers never read pre-action state), and per-profile
    /// generation numbers prevent stale in-flight samples from overwriting a
    /// newer explicit connect/disconnect/wake transition.
    func pollAllVpnStates() async {
        if let inFlight = vpnPollInFlight {
            vpnPollNeedsFollowUp = true
            await inFlight.value
            return
        }
        let task = Task { @MainActor in
            repeat {
                self.vpnPollNeedsFollowUp = false
                await self.pollAllVpnStatesOnce()
            } while self.vpnPollNeedsFollowUp && !Task.isCancelled
        }
        vpnPollInFlight = task
        await task.value
        vpnPollInFlight = nil
    }

    private func pollAllVpnStatesOnce() async {
        let profilesSnapshot = vpnProfiles
        let generationSnapshot = Dictionary(
            uniqueKeysWithValues: profilesSnapshot.map { ($0.id, vpnProfileGeneration[$0.id] ?? 0) }
        )
        let pollStart = Date()

        // Fast path (`P3-8`): single batched helper RPC returning kill-switch
        // leases + every profile's backend status in ONE Unix-socket round trip.
        do {
            let response = try await HelperClient.shared.vpnPollAll(
                profiles: profilesSnapshot.map { (id: $0.id, backend: $0.backend) }
            )
            helperHealth = .healthy
            if let ksDict = response["kill_switch"] as? [String: Any],
               let activeDict = ksDict["active"] as? [String: Any] {
                killSwitchActiveProfiles = Set(activeDict.keys)
            }
            let rawProfiles = (response["profiles"] as? [String: [String: Any]]) ?? [:]
            for summary in profilesSnapshot {
                let raw = rawProfiles[summary.id] ?? ["state": "disconnected"]
                let sample = Self.parseProfileSample(summary, raw: raw)
                applyPollSample(
                    sample,
                    expectedGeneration: generationSnapshot[summary.id] ?? 0,
                    pollStart: pollStart
                )
            }
            let connectedCount = vpnConnectionStates.values.filter { $0 == "connected" }.count
            DebugLog.write("[AppState] pollAllVpnStates (batched): \(vpnConnectionStates.count) profiles, \(connectedCount) connected")
            return
        } catch HelperClient.HelperError.rpcFailure(let code, _) where code == -32601 {
            // Deployed helper predates `vpn_poll_all` — fall through to legacy path.
        } catch {
            // Helper unreachable or timed out — probe health once to distinguish
            // `.absent` from `.unresponsive`.
        }

        let health = await HelperClient.shared.health()
        helperHealth = health
        switch health {
        case .absent:
            DebugLog.write("[AppState] pollAllVpnStates: helper not reachable, leaving states alone")
            return
        case .unresponsive:
            for summary in profilesSnapshot {
                guard (vpnProfileGeneration[summary.id] ?? 0) == (generationSnapshot[summary.id] ?? 0) else {
                    continue
                }
                var streak = vpnStatusMissStreak[summary.id] ?? 0
                vpnConnectionStates[summary.id] = Self.stabilizedVpnState(
                    previous: vpnConnectionStates[summary.id] ?? "disconnected",
                    sample: "unknown",
                    missStreak: &streak
                )
                vpnStatusMissStreak[summary.id] = streak
            }
            DebugLog.write("[AppState] pollAllVpnStates: helper not answering, states unconfirmed")
            return
        case .healthy:
            break
        }
        if let ks = try? await HelperClient.shared.killSwitchStatus() {
            killSwitchActiveProfiles = ks.active
        }
        guard !profilesSnapshot.isEmpty else { return }

        await withTaskGroup(of: VpnPollSample.self) { group in
            for summary in profilesSnapshot {
                group.addTask {
                    await Self.fetchProfileStatus(summary)
                }
            }
            for await sample in group {
                applyPollSample(
                    sample,
                    expectedGeneration: generationSnapshot[sample.profileId] ?? 0,
                    pollStart: pollStart
                )
            }
        }
    }

    private func applyPollSample(
        _ sample: VpnPollSample,
        expectedGeneration: UInt64,
        pollStart: Date
    ) {
        let id = sample.profileId
        guard (vpnProfileGeneration[id] ?? 0) == expectedGeneration else {
            return
        }
        var streak = vpnStatusMissStreak[id] ?? 0
        let next = Self.stabilizedVpnState(
            previous: vpnConnectionStates[id] ?? "disconnected",
            sample: sample.state,
            missStreak: &streak
        )
        vpnStatusMissStreak[id] = streak
        vpnConnectionStates[id] = next
        vpnLiveDetails[id] = sample.detail
        if let (rx, tx) = sample.bytes {
            vpnByteCounters[id] = (rx: rx, tx: tx)
            if let prev = vpnLastByteSample[id] {
                let dt = pollStart.timeIntervalSince(prev.at)
                if dt > 0.05 && rx >= prev.rx && tx >= prev.tx {
                    let rxRate = Double(rx - prev.rx) / dt
                    let txRate = Double(tx - prev.tx) / dt
                    vpnByteRates[id] = (rxPerSec: rxRate, txPerSec: txRate)
                } else if rx < prev.rx || tx < prev.tx {
                    vpnByteRates.removeValue(forKey: id)
                }
            }
            vpnLastByteSample[id] = (rx: rx, tx: tx, at: pollStart)
        } else if next != "connected" {
            vpnByteCounters.removeValue(forKey: id)
            vpnByteRates.removeValue(forKey: id)
            vpnLastByteSample.removeValue(forKey: id)
        }
        if next == "connected" {
            if let hs = sample.lastHandshakeUnix {
                vpnLastHandshakeUnix[id] = hs
            }
            if let ep = sample.peerEndpoint {
                vpnPeerEndpoints[id] = ep
            }
            if let routing = sample.routing {
                vpnLiveRouting[id] = routing
            }
        } else {
            vpnLastHandshakeUnix.removeValue(forKey: id)
            vpnPeerEndpoints.removeValue(forKey: id)
            vpnLiveRouting.removeValue(forKey: id)
        }
    }

    /// Anti-flicker hysteresis for one profile's displayed state.
    ///
    /// The raw per-poll sample is noisy: a socket hiccup or a slow
    /// `swanctl --list-sas` (charon busy, rekey, pollers contending on the
    /// strongSwan lock) makes a single poll report `unknown`/`connecting`/
    /// `disconnected` for a tunnel that is plainly up. Writing that straight to
    /// the dot produced the constant blink the user reported. Rules:
    ///
    /// - `connected` sample → `connected`, streak reset. (Truth wins instantly.)
    /// - Non-connected sample while we're SHOWING `connected`: hold `connected`
    ///   for the first miss (ride out one bad poll), then on the 2nd consecutive
    ///   miss commit the transition — to `disconnected` only if the helper
    ///   DEFINITIVELY reported the SA gone, otherwise to `problem` (it was up and
    ///   we can no longer confirm it: timeout / RPC threw / stuck "connecting").
    /// - Not currently `connected`: an `unknown` sample carries no information,
    ///   so keep the previous state; any other sample is followed directly
    ///   (e.g. the honest `connecting → connected` path of a fresh connect, or a
    ///   clean `problem → disconnected` once the SA is really gone).
    static func stabilizedVpnState(
        previous: String,
        sample: String,
        missStreak: inout Int
    ) -> String {
        if sample == "connected" {
            missStreak = 0
            return "connected"
        }
        if previous == "connected" {
            missStreak += 1
            if missStreak < 2 {
                return "connected" // ride out a single hiccup
            }
            missStreak = 0
            return sample == "disconnected" ? "disconnected" : "problem"
        }
        if sample == "unknown" {
            return previous // no information — don't invent a transition
        }
        missStreak = 0
        return sample
    }

    /// Static so it can run concurrently inside `withTaskGroup`
    /// without capturing `self`.
    ///
    /// `summary.backend` is the daemon's display-form string
    /// ("WireGuard", "FortiGate (IPsec/IKEv2)", "OpenVPN3"), not a
    /// stable discriminator ("wire_guard", "forti_gate", "open_vpn").
    /// Substring matching keeps us robust against the daemon
    /// renaming labels for UI purposes.
    ///
    /// Bytes / handshake / endpoint are all WG-only today; OpenVPN
    /// and strongSwan leave them nil and the detail view falls back
    /// to a more sparse "Connected" badge for those backends.
    fileprivate static func parseProfileSample(
        _ summary: VpnProfileSummary,
        raw r: [String: Any]
    ) -> VpnPollSample {
        let backend = summary.backend.lowercased()
        if backend.contains("wireguard") || backend.contains("wire_guard") {
            let state = (r["state"] as? String) ?? "disconnected"
            let rx = toUInt64(r["rx_bytes"])
            let tx = toUInt64(r["tx_bytes"])
            let bytes: (UInt64, UInt64)? = (rx != nil && tx != nil) ? (rx!, tx!) : nil
            let handshake = toInt64(r["last_handshake_unix"])
            let endpoint = r["peer_endpoint"] as? String
            var live = VpnLiveDetail()
            if state == "connected", let rx, let tx {
                live.stateDetail = "rx \(rx) bytes · tx \(tx) bytes"
            }
            return VpnPollSample(
                profileId: summary.id,
                state: state,
                bytes: bytes,
                lastHandshakeUnix: handshake,
                peerEndpoint: endpoint,
                detail: live
            )
        }
        if backend.contains("openvpn") || backend.contains("open_vpn") || backend.contains("azure") {
            let state = (r["state"] as? String) ?? "disconnected"
            let rx = toUInt64(r["rx_bytes"])
            let tx = toUInt64(r["tx_bytes"])
            let bytes: (UInt64, UInt64)? = (rx != nil && tx != nil) ? (rx!, tx!) : nil
            var live = VpnLiveDetail()
            live.reconnectReason = r["error_reason"] as? String
            if state == "connected" {
                if let pid = toInt64(r["pid"]) {
                    live.stateDetail = "openvpn pid \(pid)"
                }
                live.interface = (r["interface"] as? String) ?? ""
                live.virtualIp = (r["virtual_ip"] as? String) ?? ""
                live.virtualGateway = (r["virtual_gateway"] as? String) ?? ""
                live.routes = (r["active_routes"] as? [String]) ?? []
                live.routesInstalled = r["routes_installed"] as? Bool
                live.cipherSuite = (r["cipher_suite"] as? String) ?? ""
            }
            return VpnPollSample(
                profileId: summary.id,
                state: state,
                bytes: bytes,
                lastHandshakeUnix: nil,
                peerEndpoint: nil,
                routing: Self.ovpnRouting(r),
                detail: live
            )
        }
        if backend.contains("fortigate") || backend.contains("forti_gate") || backend.contains("ikev2") || backend.contains("ipsec") {
            var state = (r["state"] as? String) ?? "disconnected"
            let detailText = (r["detail"] as? String) ?? ""
            if state == "connecting" && detailText.contains("timed out") {
                state = "unknown"
            }
            let rx = toUInt64(r["bytes_in"])
            let tx = toUInt64(r["bytes_out"])
            let bytes: (UInt64, UInt64)? = (rx != nil && tx != nil) ? (rx!, tx!) : nil
            var live = VpnLiveDetail()
            live.stateDetail = detailText
            live.strongswanMissing = detailText.contains("strongSwan not installed")
            if state == "connected" {
                live.interface = (r["interface"] as? String) ?? ""
                live.virtualIp = (r["virtual_ip"] as? String) ?? ""
                live.virtualGateway = (r["virtual_gateway"] as? String) ?? ""
                live.routes = (r["active_routes"] as? [String]) ?? []
                live.routesInstalled = r["routes_installed"] as? Bool
                live.cipherSuite = (r["cipher_suite"] as? String) ?? ""
            }
            return VpnPollSample(
                profileId: summary.id,
                state: state,
                bytes: bytes,
                lastHandshakeUnix: nil,
                peerEndpoint: nil,
                routing: VpnLiveRouting.ikev2(selectors: (r["active_routes"] as? [String]) ?? []),
                detail: live
            )
        }
        return VpnPollSample.disconnected(profileId: summary.id)
    }

    fileprivate static func fetchProfileStatus(_ summary: VpnProfileSummary) async -> VpnPollSample {
        let backend = summary.backend.lowercased()
        do {
            if backend.contains("wireguard") || backend.contains("wire_guard") {
                let r = try await HelperClient.shared.wgStatus(profileId: summary.id)
                return parseProfileSample(summary, raw: r)
            }
            if backend.contains("openvpn") || backend.contains("open_vpn") || backend.contains("azure") {
                let r = try await HelperClient.shared.ovpnStatus(profileId: summary.id)
                return parseProfileSample(summary, raw: r)
            }
            if backend.contains("fortigate") || backend.contains("forti_gate") || backend.contains("ikev2") || backend.contains("ipsec") {
                let r = try await HelperClient.shared.vpnStatus(profileId: summary.id)
                return parseProfileSample(summary, raw: r)
            }
            DebugLog.write("fetchProfileStatus: unknown backend \(summary.backend) for \(summary.id)")
            return VpnPollSample.disconnected(profileId: summary.id)
        } catch {
            DebugLog.write("fetchProfileStatus: \(summary.backend) \(summary.id) threw \(error)")
            return VpnPollSample(
                profileId: summary.id,
                state: "unknown",
                bytes: nil,
                lastHandshakeUnix: nil,
                peerEndpoint: nil
            )
        }
    }

    /// `ovpn_status`'s pushed routes, and whether the gateway's
    /// `redirect-gateway` took the default route. A helper too old to say
    /// leaves `takesAll` nil.
    fileprivate static func ovpnRouting(_ status: [String: Any]) -> VpnLiveRouting {
        VpnLiveRouting(
            takesAll: status["takes_all"] as? Bool,
            routes: (status["active_routes"] as? [String]) ?? []
        )
    }

    /// Like `toUInt64` but for signed Unix timestamps. JSONSerialization
    /// turns small ints into NSNumber regardless of declared signedness;
    /// go through the NSNumber bridge so a negative value (shouldn't
    /// happen but be defensive) survives the round-trip.
    fileprivate static func toInt64(_ any: Any?) -> Int64? {
        if let i = any as? Int64 { return i }
        if let n = any as? NSNumber { return n.int64Value }
        if let s = any as? String, let v = Int64(s) { return v }
        return nil
    }

    /// JSON numbers come through as NSNumber via JSONSerialization.
    /// Direct `as? UInt64` casts can fail depending on how the
    /// value was bridged — go through NSNumber for robustness.
    fileprivate static func toUInt64(_ any: Any?) -> UInt64? {
        if let u = any as? UInt64 { return u }
        if let i = any as? Int64, i >= 0 { return UInt64(i) }
        if let n = any as? NSNumber { return n.uint64Value }
        if let s = any as? String, let v = UInt64(s) { return v }
        return nil
    }

    /// Rename a VPN profile. Trimmed + non-empty enforced on
    /// the daemon side; we just relay. Refreshes the profile
    /// list on success so the sidebar updates.
    @discardableResult
    func renameVpnProfile(profileId: String, newName: String) async -> Bool {
        let trimmed = newName.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return false }
        do {
            let _: VpnProfile = try await client.call(
                "vpn_rename_profile",
                params: ["profile_id": profileId, "name": trimmed]
            )
            await refreshProfiles()
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    /// Duplicate a VPN profile via the daemon's
    /// `vpn_duplicate_profile` RPC.
    ///
    /// The daemon clones the .ovpn file and whatever secrets live in its
    /// own store — on macOS that is WireGuard key material only. IKEv2,
    /// OpenVPN and Azure credentials are in the Keychain, which the
    /// daemon cannot reach, so we copy those across here. Without this
    /// the duplicate points at credential labels that were never
    /// populated and the tunnel fails to authenticate.
    @discardableResult
    func duplicateVpnProfile(profileId: String) async -> Bool {
        do {
            let result: VpnProfile = try await client.call(
                "vpn_duplicate_profile",
                params: ["profile_id": profileId]
            )
            try VPNKeychain.copyAll(from: profileId, to: result.id)
            await refreshProfiles()
            // Select the duplicate so it's immediately visible —
            // matches the import-flow UX.
            selectedProfileId = result.id
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    /// Opt this profile in or out of pushing its DNS servers to the
    /// system resolver.
    ///
    /// Takes effect on the next connect — the daemon re-renders the conf
    /// each time, so an already-up tunnel keeps what it started with.
    @discardableResult
    func setPushDns(profileId: String, enabled: Bool) async -> Bool {
        do {
            let _: VpnProfile = try await client.call(
                "vpn_set_push_dns",
                params: ["profile_id": profileId, "enabled": enabled]
            )
            await refreshProfiles()
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    /// Set the `kill_switch` flag on a profile. Persisted in both the
    /// daemon's profile store and the helper's `kill_switch.json`. When
    /// disabled while connected, releases ONLY this profile's active pf lease.
    @discardableResult
    func setKillSwitch(profileId: String, enabled: Bool) async -> Bool {
        do {
            let _: VpnProfile = try await client.call(
                "vpn_set_kill_switch",
                params: ["profile_id": profileId, "enabled": enabled]
            )
            await refreshProfiles()
            let wasActive = killSwitchActiveProfiles.contains(profileId)
            if await HelperClient.shared.health() == .healthy {
                let status = try await HelperClient.shared.killSwitchSetIntent(
                    profileId: profileId,
                    enabled: enabled
                )
                let activeDict = (status["active"] as? [String: Any]) ?? [:]
                killSwitchActiveProfiles = Set(activeDict.keys)
                if wasActive && !killSwitchActiveProfiles.contains(profileId) {
                    ActivityLog.shared.record(
                        profileId: profileId,
                        kind: .killSwitchReleased,
                        message: "Kill-switch released"
                    )
                }
            }
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    /// Force the system resolver to the user's fallback DNS list
    /// via scutil. Used as a recovery action when DNS state gets
    /// stuck on an unreachable IPv6 RDNSS or similar configd
    /// glitch. Reads the persisted fallback list from the helper.
    func resetDNSToFallbacks() async {
        do {
            let fallbacks = try await HelperClient.shared.tailscaleGetDNSFallbacks()
            let servers = (fallbacks["fallbacks"] as? [String]) ?? ["1.1.1.1"]
            _ = try await HelperClient.shared.tailscaleForceDNSState(servers: servers)
            DebugLog.write("[ts/dns] manual DNS reset to \(servers)")
        } catch {
            handleError(error)
        }
    }

    /// Refresh the helper's auto-reconnect watch list, and re-arm any
    /// Always-on profiles whose credentials were cleared across a helper
    /// restart (credentials live in `VPNKeychain`, never in
    /// `/var/lib/supermanager/auto_reconnect.json`).
    func refreshAutoReconnect() async {
        do {
            let r = try await HelperClient.shared.autoReconnectList()
            autoReconnectEnabled = Set(r.watched)
            autoReconnectUnarmed = Set(r.unarmed)
        } catch {
            DebugLog.write("[auto-reconnect] autoReconnectList failed: \(error.localizedDescription)")
            return
        }

        guard !LockState.shared.isLocked, !autoReconnectUnarmed.isEmpty else { return }
        let candidates = autoReconnectUnarmed.subtracting(autoReconnectRearmFailed)
        guard !candidates.isEmpty else { return }

        var rearmedAny = false
        for profileId in candidates {
            guard let summary = vpnProfiles.first(where: { $0.id == profileId }) else {
                continue
            }
            do {
                let (backend, args) = try await buildAutoReconnectArgs(for: summary)
                _ = try await HelperClient.shared.autoReconnectEnable(
                    profileId: profileId,
                    backend: backend,
                    connectArgs: args
                )
                rearmedAny = true
            } catch {
                autoReconnectRearmFailed.insert(profileId)
                ActivityLog.shared.record(
                    profileId: profileId,
                    kind: .connectFailed,
                    message: "Always-on could not re-arm: \(error.localizedDescription)"
                )
                DebugLog.write("[auto-reconnect] could not re-arm \(profileId): \(error.localizedDescription)")
                handleError(error)
            }
        }
        if rearmedAny {
            do {
                let updated = try await HelperClient.shared.autoReconnectList()
                autoReconnectEnabled = Set(updated.watched)
                autoReconnectUnarmed = Set(updated.unarmed)
            } catch {
                DebugLog.write("[auto-reconnect] post-rearm list failed: \(error.localizedDescription)")
            }
        }
    }

    /// Construct validated connect arguments for an Always-on profile from the
    /// daemon's profile store and the user's Data Protection Keychain.
    private func buildAutoReconnectArgs(
        for summary: VpnProfileSummary
    ) async throws -> (backend: String, args: [String: Any]) {
        let profileId = summary.id
        let backendLower = summary.backend.lowercased()
        if backendLower.contains("wireguard") || backendLower.contains("wire_guard") {
            await installVPNRuntime()
            struct Rendered: Decodable {
                let conf: String
                let dnsServers: [String]
                enum CodingKeys: String, CodingKey {
                    case conf
                    case dnsServers = "dns_servers"
                }
            }
            let r: Rendered = try await client.call(
                "vpn_render_wireguard_conf",
                params: ["profile_id": profileId]
            )
            let args = HelperClient.wgConnectArgs(
                profileId: profileId,
                confContent: r.conf,
                dnsServers: r.dnsServers,
                native: AppSettings.shared.wireguardNativeSetup,
                killSwitch: summary.killSwitch
            )
            return ("wireguard", args)
        } else if backendLower.contains("openvpn") || backendLower.contains("open_vpn") {
            try await HelperClient.shared.installBundledVPNRuntime()
            let profile: VpnProfile = try await client.call(
                "vpn_get_profile", params: ["id": profileId])
            guard case .openvpn(let cfg) = profile.config else {
                throw NSError(
                    domain: "SuperManager.AutoReconnect",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Profile \(summary.name) is not an OpenVPN profile"]
                )
            }
            var args: [String: Any] = [
                "profile_id": profileId,
                "config": try String(contentsOfFile: cfg.configFile, encoding: .utf8),
                "kill_switch": profile.killSwitch,
            ]
            if let u = try VPNKeychain.getOptionalString(account: "vpn/\(profileId)/ovpn-username") {
                args["username"] = u
            }
            if let p = try VPNKeychain.getOptionalString(account: "vpn/\(profileId)/ovpn-password") {
                args["password"] = p
            }
            return ("openvpn", args)
        } else if backendLower.contains("fortigate")
            || backendLower.contains("forti_gate")
            || backendLower.contains("ikev2")
            || backendLower.contains("ipsec")
        {
            try await HelperClient.shared.installBundledVPNRuntime()
            let profile: VpnProfile = try await client.call(
                "vpn_get_profile", params: ["id": profileId])
            guard case .ikev2(let cfg) = profile.config else {
                throw NSError(
                    domain: "SuperManager.AutoReconnect",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Profile \(summary.name) has no IKEv2 configuration"]
                )
            }
            let credentials = try VPNKeychain.ikev2Credentials(
                passwordAccount: cfg.password,
                pskAccount: cfg.psk
            )
            let args: [String: Any] = [
                "profile_id": profile.id,
                "name": profile.name,
                "host": cfg.host,
                "username": cfg.username,
                "password": credentials.password,
                "shared_secret": credentials.sharedSecret,
                "full_tunnel": profile.fullTunnel,
                "routes": cfg.routes,
                "dns_servers": cfg.dnsServers,
                "local_id": cfg.localId,
                "kill_switch": profile.killSwitch,
            ]
            return ("ikev2", args)
        } else {
            throw NSError(
                domain: "SuperManager.AutoReconnect",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Unknown backend for always-on: \(summary.backend)"]
            )
        }
    }

    /// Toggle always-on for a profile. Captures the connect args
    /// from the profile's current config + Keychain so the helper holds
    /// them in RAM.
    @discardableResult
    func setAutoReconnect(profileId: String, enabled: Bool) async -> Bool {
        guard let summary = vpnProfiles.first(where: { $0.id == profileId }) else {
            return false
        }
        if !enabled {
            do {
                _ = try await HelperClient.shared.autoReconnectDisable(profileId: profileId)
                autoReconnectEnabled.remove(profileId)
                autoReconnectUnarmed.remove(profileId)
                autoReconnectRearmFailed.remove(profileId)
                return true
            } catch {
                handleError(error)
                return false
            }
        }
        let backendStr: String
        let args: [String: Any]
        do {
            (backendStr, args) = try await buildAutoReconnectArgs(for: summary)
        } catch {
            handleError(error)
            return false
        }
        do {
            _ = try await HelperClient.shared.autoReconnectEnable(
                profileId: profileId,
                backend: backendStr,
                connectArgs: args
            )
            autoReconnectEnabled.insert(profileId)
            autoReconnectUnarmed.remove(profileId)
            autoReconnectRearmFailed.remove(profileId)
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    // MARK: - VPN Profiles

    /// Loads every profile. Deliberately unscoped by customer — see below.
    ///
    /// ## Why the global customer picker is hidden on the VPN section
    ///
    /// The wire format already has the field. `ProfileSummary` in
    /// supermgr-core carries `customer: String` and the list response emits it
    /// (as `customer`, absent rather than `""` when unset, because of
    /// `skip_serializing_if`). So decoding it here would work today.
    ///
    /// It would also be useless, and then harmful. This app talks to
    /// supermgrd-mac, which is a thin wrapper around `supermgr_engine`, and the
    /// engine has no customer setter: `set_profile_customer` exists only on the
    /// Linux D-Bus daemon, and every profile-creating handler in
    /// supermgr-engine/src/handlers/vpn.rs hardcodes `customer: String::new()`.
    /// Every profile on macOS therefore has an empty tag. Filter on it and
    /// picking any customer hides the entire list.
    ///
    /// Making it real needs, in order:
    ///   1. a `vpn_set_customer` handler in supermgr-engine + its dispatch entry
    ///   2. `customer` decoded in VpnProfileSummary
    ///      (`decodeIfPresent(...) ?? ""`, since the key is omitted when empty)
    ///   3. somewhere to set it — a picker in the profile editor or an
    ///      "Assign to customer…" item in the list row's context menu
    ///   4. the filter itself, mirroring `filteredHosts`
    ///   5. a one-time pass tagging the existing profiles
    ///
    /// Until step 1 exists there is nothing to filter on, so the picker is
    /// hidden on this section rather than left there implying a scope it
    /// doesn't have.
    func refreshProfiles() async {
        do {
            vpnProfiles = try await client.call("list_profiles")
            autoReconnectRearmFailed.removeAll()
        } catch {
            handleError(error)
        }
    }

    func deleteVpnProfile(_ id: String, profileName: String? = nil) async {
        let summary = vpnProfiles.first(where: { $0.id == id })
        bumpVpnGeneration(id)
        do {
            _ = try? await HelperClient.shared.autoReconnectDisable(profileId: id)
            _ = try? await HelperClient.shared.killSwitchSetIntent(profileId: id, enabled: false)
            if let summary {
                await dispatchDisconnect(profileId: id, backend: summary.backend)
            } else {
                _ = try? await HelperClient.shared.vpnDisconnect(profileId: id)
                _ = try? await HelperClient.shared.wgDisconnect(profileId: id)
                _ = try? await HelperClient.shared.ovpnDisconnect(profileId: id)
            }

            try await client.callVoid("vpn_delete_profile", params: ["id": id])
            VPNKeychain.deleteAll(profileId: id)

            autoReconnectEnabled.remove(id)
            autoReconnectUnarmed.remove(id)
            autoReconnectRearmFailed.remove(id)
            killSwitchActiveProfiles.remove(id)
            vpnBusyProfiles.remove(id)
            vpnConnectionStates.removeValue(forKey: id)
            vpnStatusMissStreak.removeValue(forKey: id)
            vpnByteCounters.removeValue(forKey: id)
            vpnByteRates.removeValue(forKey: id)
            vpnLastByteSample.removeValue(forKey: id)
            vpnLastHandshakeUnix.removeValue(forKey: id)
            vpnPeerEndpoints.removeValue(forKey: id)
            vpnLiveRouting.removeValue(forKey: id)
            vpnLiveDetails.removeValue(forKey: id)
            vpnProfileGeneration.removeValue(forKey: id)

            await refreshProfiles()
            if selectedProfileId == id { selectedProfileId = nil }
        } catch {
            handleError(error)
        }
    }

    /// Import a WireGuard `.conf` profile. The daemon parses, persists
    /// the private key (and any per-peer PSKs) in its secret store, and
    /// writes the profile to disk. Returns the new profile id on
    /// success so the caller can select it in the list.
    @discardableResult
    func importWireguard(name: String, content: String) async -> String? {
        do {
            let profile: VpnProfile = try await client.call(
                "vpn_import_wireguard",
                params: ["name": name, "content": content]
            )
            await refreshProfiles()
            return profile.id
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Import an OpenVPN `.ovpn` profile. The daemon stores the raw
    /// config under its data directory (mode 0600) and persists the
    /// profile metadata.
    @discardableResult
    func importOpenVPN(name: String, content: String) async -> String? {
        do {
            let profile: VpnProfile = try await client.call(
                "vpn_import_openvpn",
                params: ["name": name, "content": content]
            )
            await refreshProfiles()
            return profile.id
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Import a Microsoft `.azurevpnconfig` (XML) blob. The daemon
    /// parses it into the structured `AzureVpnConfig`, validates the
    /// fields, and persists a Profile under the AzureVpn variant.
    /// Connecting is a separate step (see `azureConnect`) because
    /// it requires an Entra-ID OAuth2 token that we acquire after
    /// the user has imported and clicked Connect.
    @discardableResult
    func importAzureVPN(name: String, content: String) async -> String? {
        do {
            let profile: VpnProfile = try await client.call(
                "vpn_import_azure",
                params: ["name": name, "content": content]
            )
            await refreshProfiles()
            return profile.id
        } catch {
            handleError(error)
            return nil
        }
    }

    // MARK: - VPN Connect dispatch (backend-aware)

    /// Bring up a WireGuard tunnel. Two-step:
    ///   1. Daemon renders the .conf with the private key spliced in
    ///      (private key never leaves the daemon's secret store
    ///      until this single RPC).
    ///   2. GUI hands the rendered body to the privileged helper,
    ///      which writes it to `/etc/wireguard/...` and runs
    ///      `wg-quick up`.
    ///
    /// Returns the operational result (success/message) so the view
    /// can show inline diagnostics without a refresh round-trip.
    /// Install the VPN runtime this app bundles before WireGuard uses it.
    /// A failure is logged, not fatal: the helper keeps the runtime it
    /// installed before, and a development build without one runs
    /// Homebrew's WireGuard.
    func installVPNRuntime() async {
        guard let dir = HelperClient.bundledVPNRuntime else { return }
        do {
            let result = try await HelperClient.shared.vpnRuntimeInstall(bundledDir: dir)
            if let installed = result["installed"] as? [String], !installed.isEmpty {
                DebugLog.write("[vpn-runtime] installed \(installed)")
            }
        } catch {
            DebugLog.write("[vpn-runtime] install failed: \(error)")
        }
    }

    @discardableResult
    func wireguardConnect(profileId: String) async -> (success: Bool, message: String) {
        ActivityLog.shared.record(profileId: profileId, kind: .connectStarted,
                                  message: "User clicked Connect (WireGuard)")
        bumpVpnGeneration(profileId)
        vpnConnectionStates[profileId] = "connecting"
        await installVPNRuntime()
        bumpVpnFastPolling()
        do {
            struct RenderedConf: Decodable {
                let conf: String
                let dnsServers: [String]
                enum CodingKeys: String, CodingKey {
                    case conf
                    case dnsServers = "dns_servers"
                }
            }
            let rendered: RenderedConf = try await client.call(
                "vpn_render_wireguard_conf",
                params: ["profile_id": profileId]
            )
            let wantKillSwitch = vpnProfiles.first(where: { $0.id == profileId })?.killSwitch ?? false
            let result = try await HelperClient.shared.wgConnect(
                profileId: profileId,
                confContent: rendered.conf,
                dnsServers: rendered.dnsServers,
                native: AppSettings.shared.wireguardNativeSetup,
                killSwitch: wantKillSwitch
            )
            let success = (result["success"] as? Bool) ?? false
            let message = (result["message"] as? String)
                ?? (success ? "Connected" : "Connect failed")
            if success && wantKillSwitch {
                let iface = (result["interface"] as? String) ?? "tunnel"
                ActivityLog.shared.record(
                    profileId: profileId,
                    kind: .killSwitchEngaged,
                    message: "Kill-switch installed on \(iface)"
                )
            }
            ActivityLog.shared.record(
                profileId: profileId,
                kind: success ? .connectSucceeded : .connectFailed,
                message: message
            )
            bumpVpnGeneration(profileId)
            vpnConnectionStates[profileId] = success ? "connected" : "disconnected"
            await pollAllVpnStates()
            return (success, message)
        } catch {
            bumpVpnGeneration(profileId)
            vpnConnectionStates[profileId] = "disconnected"
            ActivityLog.shared.record(profileId: profileId, kind: .connectFailed,
                                      message: error.localizedDescription)
            return (false, error.localizedDescription)
        }
    }

    @discardableResult
    func wireguardDisconnect(profileId: String) async -> (success: Bool, message: String) {
        ActivityLog.shared.record(profileId: profileId, kind: .disconnectRequested,
                                  message: "User clicked Disconnect (WireGuard)")
        bumpVpnGeneration(profileId)
        vpnConnectionStates[profileId] = "disconnected"
        bumpVpnFastPolling()
        do {
            let result = try await HelperClient.shared.wgDisconnect(profileId: profileId)
            let success = (result["success"] as? Bool) ?? false
            let message = (result["message"] as? String) ?? "Disconnected"
            ActivityLog.shared.record(profileId: profileId, kind: .disconnectComplete,
                                      message: message)
            await pollAllVpnStates()
            return (success, message)
        } catch {
            return (false, error.localizedDescription)
        }
    }

    @discardableResult
    func openVPNConnect(
        profileId: String,
        configFile: String
    ) async -> (success: Bool, message: String) {
        ActivityLog.shared.record(profileId: profileId, kind: .connectStarted,
                                  message: "User clicked Connect (OpenVPN)")
        let username: String?
        let password: String?
        do {
            username = try VPNKeychain.getOptionalString(account: "vpn/\(profileId)/ovpn-username")
            password = try VPNKeychain.getOptionalString(account: "vpn/\(profileId)/ovpn-password")
        } catch {
            ActivityLog.shared.record(profileId: profileId, kind: .connectFailed,
                                      message: error.localizedDescription)
            return (false, error.localizedDescription)
        }
        let config: String
        do {
            config = try String(contentsOfFile: configFile, encoding: .utf8)
        } catch {
            return (false, error.localizedDescription)
        }
        if username == nil || password == nil, OpenVPNCredentials.areAsked(in: config) {
            let message = "This profile asks for a username and password, and none are stored "
                + "for it. Add them with Edit credentials, then connect."
            ActivityLog.shared.record(profileId: profileId, kind: .connectFailed, message: message)
            return (false, message)
        }

        bumpVpnGeneration(profileId)
        vpnConnectionStates[profileId] = "connecting"
        bumpVpnFastPolling()
        do {
            let wantKillSwitch = vpnProfiles.first(where: { $0.id == profileId })?.killSwitch ?? false
            let result = try await HelperClient.shared.ovpnConnect(
                profileId: profileId,
                config: config,
                username: username,
                password: password,
                killSwitch: wantKillSwitch
            )
            let success = (result["success"] as? Bool) ?? false
            let message = (result["message"] as? String)
                ?? (success ? "Connected" : "Connect failed")
            if success && wantKillSwitch {
                let iface = (result["interface"] as? String) ?? "tunnel"
                ActivityLog.shared.record(
                    profileId: profileId,
                    kind: .killSwitchEngaged,
                    message: "Kill-switch installed on \(iface)"
                )
            }
            ActivityLog.shared.record(
                profileId: profileId,
                kind: success ? .connectSucceeded : .connectFailed,
                message: message
            )
            bumpVpnGeneration(profileId)
            vpnConnectionStates[profileId] = success ? "connected" : "disconnected"
            await pollAllVpnStates()
            return (success, message)
        } catch {
            bumpVpnGeneration(profileId)
            vpnConnectionStates[profileId] = "disconnected"
            ActivityLog.shared.record(profileId: profileId, kind: .connectFailed,
                                      message: error.localizedDescription)
            return (false, error.localizedDescription)
        }
    }

    @discardableResult
    func openVPNDisconnect(profileId: String) async -> (success: Bool, message: String) {
        bumpVpnGeneration(profileId)
        vpnConnectionStates[profileId] = "disconnected"
        bumpVpnFastPolling()
        do {
            let result = try await HelperClient.shared.ovpnDisconnect(profileId: profileId)
            let success = (result["success"] as? Bool) ?? false
            let message = (result["message"] as? String) ?? "Disconnected"
            await pollAllVpnStates()
            return (success, message)
        } catch {
            return (false, error.localizedDescription)
        }
    }

    /// Connect an IKEv2 / FortiGate profile from `AppState` (used by Menu Bar
    /// Connect and post-wake reconnect).
    @discardableResult
    func ikev2Connect(profileId: String) async -> (success: Bool, message: String) {
        ActivityLog.shared.record(profileId: profileId, kind: .connectStarted,
                                  message: "Connecting IKEv2 tunnel")
        do {
            let profile: VpnProfile = try await client.call("vpn_get_profile", params: ["id": profileId])
            guard case .ikev2(let cfg) = profile.config else {
                return (false, "Profile has no IKEv2 configuration")
            }
            let credentials = try VPNKeychain.ikev2Credentials(
                passwordAccount: cfg.password,
                pskAccount: cfg.psk
            )
            try await HelperInstaller.install()
            helperHealth = .healthy
            bumpVpnGeneration(profileId)
            vpnConnectionStates[profileId] = "connecting"
            bumpVpnFastPolling()
            let result = try await HelperClient.shared.vpnConnect(
                profileId: profile.id,
                name: profile.name,
                host: cfg.host,
                username: cfg.username,
                password: credentials.password,
                sharedSecret: credentials.sharedSecret,
                fullTunnel: profile.fullTunnel,
                routes: cfg.routes,
                dnsServers: cfg.dnsServers,
                localId: cfg.localId,
                killSwitch: profile.killSwitch
            )
            let ok = (result["ok"] as? Bool) == true
            let message = (result["message"] as? String) ?? (ok ? "Connected" : "Connect failed")
            if ok && profile.killSwitch {
                ActivityLog.shared.record(
                    profileId: profile.id,
                    kind: .killSwitchEngaged,
                    message: "Kill-switch installed for IKEv2 tunnel"
                )
            }
            ActivityLog.shared.record(
                profileId: profile.id,
                kind: ok ? .connectSucceeded : .connectFailed,
                message: message
            )
            bumpVpnGeneration(profileId)
            vpnConnectionStates[profileId] = ok ? "connected" : "disconnected"
            await pollAllVpnStates()
            return (ok, message)
        } catch {
            bumpVpnGeneration(profileId)
            vpnConnectionStates[profileId] = "disconnected"
            ActivityLog.shared.record(profileId: profileId, kind: .connectFailed,
                                      message: error.localizedDescription)
            return (false, error.localizedDescription)
        }
    }

    /// Backend-aware connect entry point for the Menu Bar (`P2-9`) and
    /// post-sleep wake recovery (`P2-8`).
    @discardableResult
    func connectProfile(
        profileId: String,
        interactive: Bool = true
    ) async -> (success: Bool, message: String) {
        guard !vpnBusyProfiles.contains(profileId) else {
            return (false, "An operation is already in flight for this profile")
        }
        guard let summary = vpnProfiles.first(where: { $0.id == profileId }) else {
            return (false, "Profile not found")
        }
        let b = summary.backend.lowercased()
        if b.contains("azure") {
            if interactive {
                selectedSection = .vpn
                selectedProfileId = profileId
                for window in NSApp.windows where window.title == "SuperManager" || window.contentViewController != nil {
                    window.makeKeyAndOrderFront(nil)
                    break
                }
                NSApp.activate(ignoringOtherApps: true)
            }
            return (false, "Azure VPN requires Entra ID sign-in in the SuperManager window")
        }

        vpnBusyProfiles.insert(profileId)
        defer { vpnBusyProfiles.remove(profileId) }

        do {
            try await HelperInstaller.install()
            helperHealth = .healthy
        } catch {
            if interactive { handleError(error) }
            return (false, error.localizedDescription)
        }

        let outcome: (success: Bool, message: String)
        if b.contains("wireguard") || b.contains("wire_guard") {
            outcome = await wireguardConnect(profileId: profileId)
        } else if b.contains("openvpn") || b.contains("open_vpn") {
            do {
                let profile: VpnProfile = try await client.call("vpn_get_profile", params: ["id": profileId])
                guard case .openvpn(let cfg) = profile.config else {
                    return (false, "Profile has no OpenVPN configuration")
                }
                outcome = await openVPNConnect(profileId: profileId, configFile: cfg.configFile)
            } catch {
                outcome = (false, error.localizedDescription)
            }
        } else if b.contains("fortigate") || b.contains("forti_gate") || b.contains("ikev2") || b.contains("ipsec") {
            outcome = await ikev2Connect(profileId: profileId)
        } else {
            outcome = (false, "Unsupported VPN backend: \(summary.backend)")
        }

        if !outcome.success && interactive {
            errorMessage = outcome.message
            showingError = true
        }
        return outcome
    }

    // MARK: - Force / fleet disconnect

    func disconnectAllVpns(suppressKillSwitchReleaseForSleepReconnect: Bool = false) async {
        if !suppressKillSwitchReleaseForSleepReconnect, await HelperClient.shared.health() == .healthy {
            do {
                _ = try await HelperClient.shared.killSwitchDisable()
            } catch {
                DebugLog.write("[kill-switch] killSwitchDisable failed in disconnectAllVpns: \(error.localizedDescription)")
                handleError(error)
            }
        }
        for summary in vpnProfiles {
            bumpVpnGeneration(summary.id)
            await dispatchDisconnect(profileId: summary.id, backend: summary.backend)
            vpnConnectionStates[summary.id] = "disconnected"
        }
        await pollAllVpnStates()
    }

    fileprivate func _logForceDisconnect(_ profileId: String) {
        ActivityLog.shared.record(profileId: profileId, kind: .forceDisconnect,
                                  message: "User force-disconnected")
    }

    func forceDisconnect(profileId: String) async {
        _logForceDisconnect(profileId)
        bumpVpnGeneration(profileId)
        bumpVpnFastPolling()
        if let summary = vpnProfiles.first(where: { $0.id == profileId }) {
            await dispatchDisconnect(profileId: profileId, backend: summary.backend)
        } else {
            _ = try? await HelperClient.shared.vpnDisconnect(profileId: profileId)
            _ = try? await HelperClient.shared.wgDisconnect(profileId: profileId)
            _ = try? await HelperClient.shared.ovpnDisconnect(profileId: profileId)
        }
        do {
            _ = try await HelperClient.shared.killSwitchDisable(profileId: profileId)
        } catch {
            ActivityLog.shared.record(
                profileId: profileId,
                kind: .connectFailed,
                message: "Could not release kill-switch: \(error.localizedDescription)"
            )
            DebugLog.write("[kill-switch] killSwitchDisable(\(profileId)) failed: \(error.localizedDescription)")
            handleError(error)
        }
        vpnConnectionStates[profileId] = "disconnected"
        await pollAllVpnStates()
    }

    /// Single source of truth for backend → disconnect-RPC. Uses
    /// substring matching against the daemon's display-form
    /// `backend` string ("WireGuard", "FortiGate (IPsec/IKEv2)",
    /// "OpenVPN3", "Azure VPN") rather than the discriminator names — see
    /// `fetchProfileState` for the same reasoning.
    fileprivate func dispatchDisconnect(profileId: String, backend: String) async {
        let b = backend.lowercased()
        if b.contains("wireguard") || b.contains("wire_guard") {
            _ = try? await HelperClient.shared.wgDisconnect(profileId: profileId)
        } else if b.contains("openvpn") || b.contains("open_vpn") || b.contains("azure") {
            _ = try? await HelperClient.shared.ovpnDisconnect(profileId: profileId)
        } else if b.contains("fortigate") || b.contains("forti_gate") || b.contains("ikev2") || b.contains("ipsec") {
            _ = try? await HelperClient.shared.vpnDisconnect(profileId: profileId)
        }
    }

    // MARK: - Routing (full vs split tunnel)

    /// Switch a profile between full-tunnel and split-tunnel.
    ///
    /// `routes` are CIDR strings (e.g. `["192.168.1.0/24", "10.0.0.0/8"]`)
    /// — only meaningful when `fullTunnel == false`. The daemon
    /// validates that split mode has at least one route and rejects
    /// the change if not.
    ///
    /// Does NOT touch a running tunnel — caller is responsible for
    /// disconnect+reconnect to apply. Returns `true` on persisted
    /// success.
    @discardableResult
    func setRouting(
        profileId: String,
        fullTunnel: Bool,
        routes: [String]
    ) async -> Bool {
        do {
            let _: VpnProfile = try await client.call(
                "vpn_set_routing",
                params: [
                    "profile_id": profileId,
                    "full_tunnel": fullTunnel,
                    "routes": routes,
                ]
            )
            await refreshProfiles()
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    /// Toggle pin on a VPN profile and persist immediately.
    func toggleVpnPin(_ profileId: String) {
        if pinnedVpnIds.contains(profileId) {
            pinnedVpnIds.remove(profileId)
        } else {
            pinnedVpnIds.insert(profileId)
        }
        UserDefaults.standard.set(Array(pinnedVpnIds), forKey: Self.pinnedVpnDefaultsKey)
    }

}

// MARK: - Tunnels in each other's way

extension AppState {
    /// A tunnel in one of these is up, or about to be.
    private static let tunnelUpStates: Set<String> = ["connected", "connecting", "reconnecting"]

    /// What the tunnels already up would do to `profile`'s, and it to them.
    func tunnelConflicts(connecting profile: VpnProfile) -> [TunnelConflict] {
        TunnelConflicts.between(Self.askedRouting(profile), and: tunnelsUp(except: profile.id))
    }

    /// What gets in the way of `profileId`'s tunnel while it is up.
    func tunnelConflicts(ofConnected profileId: String) -> [TunnelConflict] {
        guard let summary = vpnProfiles.first(where: { $0.id == profileId }) else { return [] }
        return TunnelConflicts.between(routing(of: summary), and: tunnelsUp(except: profileId))
    }

    /// The tunnels up now: VPN profiles, and Tailscale while it sends
    /// everything through an exit node.
    private func tunnelsUp(except profileId: String) -> [TunnelRouting] {
        var up = vpnProfiles
            .filter { $0.id != profileId && Self.tunnelUpStates.contains(vpnConnectionStates[$0.id] ?? "") }
            .map(routing(of:))
        if tailscaleStatus?.backendState == "Running", let exit = currentExitNodeName() {
            up.append(TunnelRouting(name: "Tailscale (exit node \(exit))", takesAll: true, routes: []))
        }
        return up
    }

    /// What `summary`'s tunnel routes: what its status reports while it is
    /// up, else what the profile asks for.
    private func routing(of summary: VpnProfileSummary) -> TunnelRouting {
        let asked = Self.askedRouting(summary)
        guard let live = vpnLiveRouting[summary.id] else { return asked }
        return TunnelRouting(
            name: summary.name,
            takesAll: live.takesAll ?? asked.takesAll,
            routes: live.routes
        )
    }

    /// What a profile asks for. A plain OpenVPN profile does not choose: its
    /// server pushes the default route or not, and the status says which
    /// once it is up. An Azure one does, through `redirect-gateway`.
    static func askedRouting(_ summary: VpnProfileSummary) -> TunnelRouting {
        let backend = summary.backend.lowercased()
        if backend.contains("openvpn") {
            return TunnelRouting(name: summary.name, takesAll: false, routes: [])
        }
        return TunnelRouting(
            name: summary.name,
            takesAll: summary.fullTunnel,
            routes: summary.fullTunnel ? [] : summary.splitRoutes
        )
    }

    /// The same for a full profile, which also has an Azure profile's routes.
    static func askedRouting(_ profile: VpnProfile) -> TunnelRouting {
        let routes: [String]
        switch profile.config {
        case .ikev2(let cfg): routes = cfg.routes
        case .wireguard(let wg): routes = wg.splitRoutes
        case .azure(let az): routes = az.routes
        case .openvpn, .unsupported:
            return TunnelRouting(name: profile.name, takesAll: false, routes: [])
        }
        return TunnelRouting(
            name: profile.name,
            takesAll: profile.fullTunnel,
            routes: profile.fullTunnel ? [] : routes
        )
    }
}
