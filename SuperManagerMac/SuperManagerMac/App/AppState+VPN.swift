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

extension AppState {
    /// Single sweep across all profiles. Each backend has its own
    /// status RPC on the helper. Helper unreachable: leave
    /// existing states alone — the helper might just be racing a
    /// `launchctl bootout` / `bootstrap`, and trampling stable
    /// states with "disconnected" causes user-visible flicker.
    /// Public so connect/disconnect actions can force a refresh
    /// without waiting for the timer.
    func pollAllVpnStates() async {
        let reachable = await HelperClient.shared.isReachable()
        guard reachable else {
            DebugLog.write("[AppState] pollAllVpnStates: helper not reachable, leaving states alone")
            return
        }
        guard !vpnProfiles.isEmpty else {
            DebugLog.write("[AppState] pollAllVpnStates: vpnProfiles empty, nothing to poll")
            return
        }
        // Run the per-profile status calls in parallel. With 3+
        // profiles a serial sweep takes seconds and stalls the dots
        // visibly; concurrent gives us all states in one round-trip
        // worth of latency.
        let pollStart = Date()
        await withTaskGroup(of: VpnPollSample.self) { group in
            for summary in vpnProfiles {
                group.addTask {
                    await Self.fetchProfileStatus(summary)
                }
            }
            for await sample in group {
                let id = sample.profileId
                vpnConnectionStates[id] = sample.state
                if let (rx, tx) = sample.bytes {
                    vpnByteCounters[id] = (rx: rx, tx: tx)
                    // Derive bytes/sec from the delta against the
                    // previous sample. UInt64 wraps to a small
                    // value if the counter resets on reconnect —
                    // detect that with `rx >= prev.rx` and only
                    // emit a positive rate when monotonic.
                    if let prev = vpnLastByteSample[id] {
                        let dt = pollStart.timeIntervalSince(prev.at)
                        if dt > 0.05 && rx >= prev.rx && tx >= prev.tx {
                            let rxRate = Double(rx - prev.rx) / dt
                            let txRate = Double(tx - prev.tx) / dt
                            vpnByteRates[id] = (rxPerSec: rxRate, txPerSec: txRate)
                        } else if rx < prev.rx || tx < prev.tx {
                            // Counter went backwards (reconnect /
                            // tunnel restart). Drop the stale rate
                            // rather than emit a confusing zero.
                            vpnByteRates.removeValue(forKey: id)
                        }
                    }
                    vpnLastByteSample[id] = (rx: rx, tx: tx, at: pollStart)
                } else if sample.state != "connected" {
                    // Drop counters + rate + history once tunnel
                    // goes down so the detail view doesn't show
                    // stale numbers.
                    vpnByteCounters.removeValue(forKey: id)
                    vpnByteRates.removeValue(forKey: id)
                    vpnLastByteSample.removeValue(forKey: id)
                }
                // Handshake / endpoint enrichment (WG-only today).
                // Same drop-on-disconnect logic as the byte counters
                // — the detail view should never show a "12s ago"
                // for a tunnel that's been down for an hour.
                if sample.state == "connected" {
                    if let hs = sample.lastHandshakeUnix {
                        vpnLastHandshakeUnix[id] = hs
                    }
                    if let ep = sample.peerEndpoint {
                        vpnPeerEndpoints[id] = ep
                    }
                } else {
                    vpnLastHandshakeUnix.removeValue(forKey: id)
                    vpnPeerEndpoints.removeValue(forKey: id)
                }
            }
        }
        let connectedCount = vpnConnectionStates.values.filter { $0 == "connected" }.count
        DebugLog.write("[AppState] pollAllVpnStates: \(vpnConnectionStates.count) profiles polled, \(connectedCount) connected, full map=\(vpnConnectionStates)")
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
    fileprivate static func fetchProfileStatus(_ summary: VpnProfileSummary) async -> VpnPollSample {
        let backend = summary.backend.lowercased()
        do {
            if backend.contains("wireguard") || backend.contains("wire_guard") {
                let r = try await HelperClient.shared.wgStatus(profileId: summary.id)
                let state = (r["state"] as? String) ?? "disconnected"
                let rx = toUInt64(r["rx_bytes"])
                let tx = toUInt64(r["tx_bytes"])
                let bytes: (UInt64, UInt64)? = (rx != nil && tx != nil) ? (rx!, tx!) : nil
                let handshake = toInt64(r["last_handshake_unix"])
                let endpoint = r["peer_endpoint"] as? String
                return VpnPollSample(
                    profileId: summary.id,
                    state: state,
                    bytes: bytes,
                    lastHandshakeUnix: handshake,
                    peerEndpoint: endpoint
                )
            }
            if backend.contains("openvpn") || backend.contains("open_vpn") {
                let r = try await HelperClient.shared.ovpnStatus(profileId: summary.id)
                let rx = toUInt64(r["rx_bytes"])
                let tx = toUInt64(r["tx_bytes"])
                let bytes: (UInt64, UInt64)? = (rx != nil && tx != nil) ? (rx!, tx!) : nil
                return VpnPollSample(
                    profileId: summary.id,
                    state: (r["state"] as? String) ?? "disconnected",
                    bytes: bytes,
                    lastHandshakeUnix: nil,
                    peerEndpoint: nil
                )
            }
            // Azure VPN tunnels are spawned via the same OpenVPN
            // binary as the OpenVPN backend (ovpncli on macOS,
            // openvpn 2.x as fallback). Status polling lands on
            // the same `ovpn_status` RPC, which now also returns
            // `rx_bytes` / `tx_bytes` parsed from `netstat -ibn`
            // for the tunnel interface.
            if backend.contains("azure") {
                let r = try await HelperClient.shared.ovpnStatus(profileId: summary.id)
                let rx = toUInt64(r["rx_bytes"])
                let tx = toUInt64(r["tx_bytes"])
                let bytes: (UInt64, UInt64)? = (rx != nil && tx != nil) ? (rx!, tx!) : nil
                return VpnPollSample(
                    profileId: summary.id,
                    state: (r["state"] as? String) ?? "disconnected",
                    bytes: bytes,
                    lastHandshakeUnix: nil,
                    peerEndpoint: nil
                )
            }
            if backend.contains("fortigate") || backend.contains("forti_gate") || backend.contains("ikev2") || backend.contains("ipsec") {
                let r = try await HelperClient.shared.vpnStatus(profileId: summary.id)
                return VpnPollSample(
                    profileId: summary.id,
                    state: (r["state"] as? String) ?? "disconnected",
                    bytes: nil,
                    lastHandshakeUnix: nil,
                    peerEndpoint: nil
                )
            }
            DebugLog.write("fetchProfileStatus: unknown backend \(summary.backend) for \(summary.id)")
            return VpnPollSample.disconnected(profileId: summary.id)
        } catch {
            DebugLog.write("fetchProfileStatus: \(summary.backend) \(summary.id) threw \(error)")
            return VpnPollSample.disconnected(profileId: summary.id)
        }
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
    /// `vpn_duplicate_profile` RPC. Daemon clones secrets +
    /// .ovpn files server-side; we just refresh the list and
    /// auto-select the duplicate so the user sees the result.
    @discardableResult
    func duplicateVpnProfile(profileId: String) async -> Bool {
        do {
            let result: VpnProfile = try await client.call(
                "vpn_duplicate_profile",
                params: ["profile_id": profileId]
            )
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

    /// Set the `kill_switch` flag on a profile. Persisted in the
    /// daemon's profile state; takes effect on next connect (the
    /// connect path inspects the profile and asks the helper to
    /// install pf rules if true). To enable kill-switch on an
    /// already-connected profile: toggle on + reconnect.
    @discardableResult
    func setKillSwitch(profileId: String, enabled: Bool) async -> Bool {
        do {
            let _: VpnProfile = try await client.call(
                "vpn_set_kill_switch",
                params: ["profile_id": profileId, "enabled": enabled]
            )
            await refreshProfiles()
            // If user is turning kill-switch OFF and tunnel is up,
            // tear down the pf rules immediately (don't wait for
            // disconnect+reconnect).
            if !enabled {
                _ = try? await HelperClient.shared.killSwitchDisable()
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

    /// Refresh the helper's auto-reconnect watch list. Drives
    /// the "Always on" toggle's UI state. Helper-unreachable
    /// leaves the local set untouched.
    func refreshAutoReconnect() async {
        do {
            let list = try await HelperClient.shared.autoReconnectList()
            autoReconnectEnabled = Set(list)
        } catch {
            // Silent; not critical for steady-state.
        }
    }

    /// Toggle always-on for a profile. Captures the connect args
    /// from the profile's current config so the helper can replay
    /// them. Returns false if we couldn't construct args (e.g.
    /// missing daemon-side render).
    @discardableResult
    func setAutoReconnect(profileId: String, enabled: Bool) async -> Bool {
        guard let summary = vpnProfiles.first(where: { $0.id == profileId }) else {
            return false
        }
        if !enabled {
            do {
                _ = try await HelperClient.shared.autoReconnectDisable(profileId: profileId)
                autoReconnectEnabled.remove(profileId)
                return true
            } catch {
                handleError(error)
                return false
            }
        }
        // Build connect args matching the backend's RPC schema.
        // For WireGuard we need the rendered .conf; daemon owns
        // it via vpn_render_wireguard_conf.
        let backendLower = summary.backend.lowercased()
        var args: [String: Any] = ["profile_id": profileId]
        let backendStr: String
        do {
            if backendLower.contains("wireguard") || backendLower.contains("wire_guard") {
                backendStr = "wireguard"
                struct Rendered: Decodable { let conf: String }
                let r: Rendered = try await client.call(
                    "vpn_render_wireguard_conf",
                    params: ["profile_id": profileId]
                )
                args["confContent"] = r.conf
            } else if backendLower.contains("openvpn") || backendLower.contains("open_vpn") {
                backendStr = "openvpn"
                // OpenVPN connect needs config_file + creds. Read
                // from secret store if present.
                let username = try? VPNKeychain.getString(account: "vpn/\(profileId)/ovpn-username")
                let password = try? VPNKeychain.getString(account: "vpn/\(profileId)/ovpn-password")
                // config file path is on the profile — we'd need
                // to fetch full profile. Use the imported path
                // convention.
                let dataDir = ("~/Library/Application Support/SuperManager/openvpn" as NSString).expandingTildeInPath
                args["configFile"] = "\(dataDir)/\(profileId).ovpn"
                if let u = username { args["username"] = u }
                if let p = password { args["password"] = p }
            } else if backendLower.contains("fortigate") || backendLower.contains("forti_gate") || backendLower.contains("ikev2") || backendLower.contains("ipsec") {
                backendStr = "ikev2"
                // IKEv2 connect args are richer; for the always-on
                // capture, we rely on the helper having stored args
                // from a recent successful connect. If user hasn't
                // connected since enabling always-on, args will be
                // empty and helper will skip. The connect refresh
                // hook in helper main.rs ensures we get them on
                // next manual connect.
            } else {
                tailscaleActionError = "Unknown backend for always-on: \(summary.backend)"
                return false
            }
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
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    // MARK: - VPN Profiles

    func refreshProfiles() async {
        do {
            vpnProfiles = try await client.call("list_profiles")
        } catch {
            handleError(error)
        }
    }

    func deleteVpnProfile(_ id: String, profileName: String? = nil) async {
        do {
            // If the tunnel is currently up, ask the helper to bring it
            // down — this also clears the swanctl config the helper wrote.
            // Best-effort: a "helper unreachable" error here is fine, the
            // helper will discard stale configs on its next start anyway.
            _ = try? await HelperClient.shared.vpnDisconnect(profileId: id)

            try await client.callVoid("vpn_delete_profile", params: ["id": id])
            VPNKeychain.deleteAll(profileId: id)
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
    @discardableResult
    func wireguardConnect(profileId: String) async -> (success: Bool, message: String) {
        ActivityLog.shared.record(profileId: profileId, kind: .connectStarted,
                                  message: "User clicked Connect (WireGuard)")
        // Optimistic update — sidebar dot flips to orange immediately
        // rather than waiting for the next 4 s poll. Verified by
        // `pollAllVpnStates()` at the bottom of this method, which
        // either confirms or corrects.
        vpnConnectionStates[profileId] = "connecting"
        // Drop poll cadence to 500 ms for the next 30 s so the
        // user sees the dot flip green within half a second of
        // the tunnel actually coming up, not after the next 4 s
        // tick.
        bumpVpnFastPolling()
        do {
            struct RenderedConf: Decodable {
                let conf: String
            }
            let rendered: RenderedConf = try await client.call(
                "vpn_render_wireguard_conf",
                params: ["profile_id": profileId]
            )
            let result = try await HelperClient.shared.wgConnect(
                profileId: profileId,
                confContent: rendered.conf
            )
            let success = (result["success"] as? Bool) ?? false
            let message = (result["message"] as? String)
                ?? (success ? "Connected" : "Connect failed")
            // Engage kill-switch if profile has it enabled. The
            // helper response includes the just-installed utun
            // name; without that we'd guess the wrong iface for
            // the pf rules.
            if success,
               let iface = result["interface"] as? String {
                await applyKillSwitchIfEnabled(profileId: profileId, iface: iface)
            }
            ActivityLog.shared.record(
                profileId: profileId,
                kind: success ? .connectSucceeded : .connectFailed,
                message: message
            )
            // Optimistic post-action update + immediate poll. Pull
            // ground-truth status now rather than relying on the
            // background timer's next tick.
            vpnConnectionStates[profileId] = success ? "connected" : "disconnected"
            await pollAllVpnStates()
            return (success, message)
        } catch {
            vpnConnectionStates[profileId] = "disconnected"
            ActivityLog.shared.record(profileId: profileId, kind: .connectFailed,
                                      message: error.localizedDescription)
            return (false, error.localizedDescription)
        }
    }

    /// If the profile has `kill_switch=true` and we just brought
    /// up its tunnel, ask the helper to install the pf rules.
    /// Idempotent on the helper side — safe to call repeatedly.
    /// Failures here are non-fatal: the tunnel is up and the user
    /// just doesn't have leak protection.
    fileprivate func applyKillSwitchIfEnabled(profileId: String, iface: String) async {
        // We check the cached profile flag rather than fetching
        // the full profile — the GUI already has it via
        // refreshProfiles. ProfileSummary doesn't carry
        // kill_switch yet so we fall through to fetching the
        // full profile if needed.
        let enabled: Bool
        do {
            let p: VpnProfile = try await client.call(
                "vpn_get_profile",
                params: ["id": profileId]
            )
            enabled = p.killSwitch
        } catch {
            DebugLog.write("[killSwitch] couldn't read profile: \(error.localizedDescription)")
            return
        }
        guard enabled else { return }
        do {
            _ = try await HelperClient.shared.killSwitchEnable(tunnelInterface: iface)
            DebugLog.write("[killSwitch] enabled on \(iface) for profile \(profileId)")
            ActivityLog.shared.record(profileId: profileId, kind: .killSwitchEngaged,
                                      message: "Kill-switch installed on \(iface)")
        } catch {
            DebugLog.write("[killSwitch] enable failed: \(error.localizedDescription)")
        }
    }

    @discardableResult
    func wireguardDisconnect(profileId: String) async -> (success: Bool, message: String) {
        ActivityLog.shared.record(profileId: profileId, kind: .disconnectRequested,
                                  message: "User clicked Disconnect (WireGuard)")
        // Optimistic disconnect — even if the RPC bombs, we want
        // the dot to leave green so the user sees the action took
        // effect somewhere. The poll afterwards reconciles.
        vpnConnectionStates[profileId] = "disconnected"
        bumpVpnFastPolling()
        // Tear down kill-switch first so the user isn't trapped
        // with a tunnel down + pf blocking everything. Idempotent.
        _ = try? await HelperClient.shared.killSwitchDisable()
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

    /// Bring up an OpenVPN tunnel. The .ovpn lives at the path
    /// stored on the profile (`OpenVpnConfig.config_file`). If the
    /// profile has stored credentials in DPK
    /// (`vpn/<id>/ovpn-username` + `vpn/<id>/ovpn-password`), we
    /// fetch them and pass to the helper for the
    /// `--auth-user-pass`-driven login. Profiles without stored
    /// creds connect without — fine for cert-only setups.
    @discardableResult
    func openVPNConnect(
        profileId: String,
        configFile: String
    ) async -> (success: Bool, message: String) {
        ActivityLog.shared.record(profileId: profileId, kind: .connectStarted,
                                  message: "User clicked Connect (OpenVPN)")
        let username = try? VPNKeychain.getString(account: "vpn/\(profileId)/ovpn-username")
        let password = try? VPNKeychain.getString(account: "vpn/\(profileId)/ovpn-password")

        vpnConnectionStates[profileId] = "connecting"
        bumpVpnFastPolling()
        do {
            let result = try await HelperClient.shared.ovpnConnect(
                profileId: profileId,
                configFile: configFile,
                username: username,
                password: password
            )
            let success = (result["success"] as? Bool) ?? false
            let message = (result["message"] as? String)
                ?? (success ? "Connected" : "Connect failed")
            if success, let iface = result["interface"] as? String {
                await applyKillSwitchIfEnabled(profileId: profileId, iface: iface)
            }
            ActivityLog.shared.record(
                profileId: profileId,
                kind: success ? .connectSucceeded : .connectFailed,
                message: message
            )
            vpnConnectionStates[profileId] = success ? "connected" : "disconnected"
            await pollAllVpnStates()
            return (success, message)
        } catch {
            vpnConnectionStates[profileId] = "disconnected"
            return (false, error.localizedDescription)
        }
    }

    @discardableResult
    func openVPNDisconnect(profileId: String) async -> (success: Bool, message: String) {
        vpnConnectionStates[profileId] = "disconnected"
        bumpVpnFastPolling()
        _ = try? await HelperClient.shared.killSwitchDisable()
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

    // MARK: - Force / fleet disconnect

    /// Walk every known VPN profile, fire the backend's disconnect
    /// RPC, and rebuild the connection-state map. Used for the
    /// "Disconnect All" toolbar action and as a reset when the UI
    /// state has gotten out of sync with the actual tunnel state.
    ///
    /// We don't trust `vpnConnectionStates` to know which tunnels
    /// are up — we ask each backend's helper RPC to disconnect
    /// regardless. Disconnect is idempotent on every backend
    /// (`wg-quick down` on a non-existent name, `swanctl --terminate`
    /// on a non-existent SA, `kill` on a missing PID — all
    /// no-ops). So this is the nuke-button: when in doubt, click.
    func disconnectAllVpns() async {
        // Tear down kill-switch FIRST so the user isn't trapped
        // with all tunnels down + pf rules still blocking traffic.
        _ = try? await HelperClient.shared.killSwitchDisable()
        for summary in vpnProfiles {
            await dispatchDisconnect(profileId: summary.id, backend: summary.backend)
            vpnConnectionStates[summary.id] = "disconnected"
        }
        await pollAllVpnStates()
    }

    /// Disconnect a single profile by id. Backend-aware. Used by
    /// the per-profile "Force Disconnect" menu item — fires the
    /// right RPC even if the UI thinks the profile is already
    /// disconnected. Belt-and-braces: also tries every backend's
    /// disconnect (idempotent on every one) so a misclassified
    /// profile still gets torn down.
    /// Surface "user mashed Force Disconnect" events. Treated as
    /// noteworthy because it usually indicates the regular UI is
    /// out-of-sync — and we want a record of how often that happens.
    fileprivate func _logForceDisconnect(_ profileId: String) {
        ActivityLog.shared.record(profileId: profileId, kind: .forceDisconnect,
                                  message: "User force-disconnected")
    }

    func forceDisconnect(profileId: String) async {
        _logForceDisconnect(profileId)
        bumpVpnFastPolling()
        if let summary = vpnProfiles.first(where: { $0.id == profileId }) {
            await dispatchDisconnect(profileId: profileId, backend: summary.backend)
        } else {
            // Profile no longer in our list? Try them all.
            _ = try? await HelperClient.shared.vpnDisconnect(profileId: profileId)
            _ = try? await HelperClient.shared.wgDisconnect(profileId: profileId)
            _ = try? await HelperClient.shared.ovpnDisconnect(profileId: profileId)
        }
        vpnConnectionStates[profileId] = "disconnected"
        await pollAllVpnStates()
    }

    /// Single source of truth for backend → disconnect-RPC. Uses
    /// substring matching against the daemon's display-form
    /// `backend` string ("WireGuard", "FortiGate (IPsec/IKEv2)",
    /// "OpenVPN3") rather than the discriminator names — see
    /// `fetchProfileState` for the same reasoning.
    fileprivate func dispatchDisconnect(profileId: String, backend: String) async {
        let b = backend.lowercased()
        if b.contains("wireguard") || b.contains("wire_guard") {
            _ = try? await HelperClient.shared.wgDisconnect(profileId: profileId)
        } else if b.contains("openvpn") || b.contains("open_vpn") {
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

    /// Aggregate of CIDRs reachable via currently-connected VPN
    /// profiles (split-tunnel routes pushed by the customer endpoint).
    /// Drives the "scan over VPN" affordance — when an MSP connects
    /// to a customer's IPsec/WireGuard, the routes that VPN pushed are
    /// exactly the ranges the operator has line-of-sight to.
    ///
    /// Each entry is `(profileName, [cidr, …])`. Empty list means
    /// no VPN is connected, no full-tunnel-with-routes is up, or
    /// every connected profile is full-tunnel without split-routes
    /// (in which case the entire internet is "reachable" — not a
    /// useful scan-scope suggestion).
    func reachableVpnNetworks() -> [(name: String, cidrs: [String])] {
        var out: [(String, [String])] = []
        for profile in vpnProfiles {
            // Only surface profiles that the daemon currently
            // reports as connected.
            let state = vpnConnectionStates[profile.id] ?? "disconnected"
            guard state == "connected" else { continue }
            let routes = profile.splitRoutes
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.starts(with: "0.0.0.0") && !$0.starts(with: "::") }
            // Full-tunnel with no split routes = the world; skip.
            if routes.isEmpty { continue }
            out.append((profile.name, routes))
        }
        return out
    }
}
