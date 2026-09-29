import Foundation
import ServiceManagement

/// IPC client for the privileged `supermanager-helper` LaunchDaemon.
///
/// Talks to it over a Unix socket at
/// `/var/run/com.sybr.supermanager.helper.sock` using the same length-prefixed
/// JSON-RPC framing as the user-space `supermgrd-mac` daemon, so we can reuse
/// the wire model rather than introducing a second protocol.
///
/// Why a Unix socket and not XPC?
/// - We already have a JSON-RPC implementation we trust (the user-space
///   daemon talks to the GUI the same way), and porting that to XPC would
///   double the surface area for bugs.
/// - Unix-socket peer credentials + 0660 mode + group `admin` already give
///   us "only admin users on the box can connect," which matches our
///   threat model.
@MainActor
final class HelperClient {
    static let shared = HelperClient()

    nonisolated static let socketPath = "/var/run/com.sybr.supermanager.helper.sock"
    nonisolated static let helperLabel = "com.sybr.supermanager.helper"

    enum HelperError: Error, LocalizedError {
        case notInstalled
        case ioFailure(String)
        case rpcFailure(code: Int, message: String)
        case decodeFailure(String)

        var errorDescription: String? {
            switch self {
            case .notInstalled:
                return "Helper isn't installed yet — call HelperInstaller.install() first"
            case .ioFailure(let m): return "Helper IPC failed: \(m)"
            case .rpcFailure(_, let m): return m
            case .decodeFailure(let m): return "Helper response decode failed: \(m)"
            }
        }
    }

    private init() {}

    // MARK: - Reachability

    /// What a probe can tell apart. "Absent" and "unresponsive" need
    /// different responses: the first is fixed by installing or approving the
    /// daemon, the second by waiting or restarting it — reinstalling a helper
    /// that is merely busy only costs the user an admin prompt.
    enum Health: Equatable {
        /// No helper to talk to: the socket is missing or refuses connections.
        case absent
        /// The socket accepts connections but the helper did not answer a
        /// ping in time. The listen backlog lives in the kernel, so
        /// `connect()` alone proves nothing about the process behind it.
        case unresponsive
        case healthy
    }

    /// One `ping` round trip on a short budget, without `call`'s retry.
    func health() async -> Health {
        guard FileManager.default.fileExists(atPath: Self.socketPath) else { return .absent }
        do {
            _ = try await roundTrip(method: "ping", params: [:])
            return .healthy
        } catch let failure as UnixSocketRPC.Failure {
            if failure.kind == .unreachable { return .absent }
            DebugLog.write("[helper] ping unanswered: \(failure)")
            return .unresponsive
        } catch {
            // An RPC or decode error is still an answer.
            return .healthy
        }
    }

    /// True when the helper answered a ping. Callers that act on the
    /// difference between "not installed" and "not answering" use `health()`.
    func isReachable() async -> Bool {
        await health() == .healthy
    }

    // MARK: - High-level RPCs

    @discardableResult
    func ping() async throws -> [String: Any] {
        try await call("ping", params: [:])
    }

    @discardableResult
    func vpnConnect(
        profileId: String,
        name: String,
        host: String,
        username: String,
        password: String,
        sharedSecret: String,
        fullTunnel: Bool,
        routes: [String] = [],
        dnsServers: [String] = [],
        localId: String = ""
    ) async throws -> [String: Any] {
        try await call("vpn_connect", params: [
            "profile_id": profileId,
            "name": name,
            "host": host,
            "username": username,
            "password": password,
            "shared_secret": sharedSecret,
            "full_tunnel": fullTunnel,
            "routes": routes,
            "dns_servers": dnsServers,
            "local_id": localId,
        ])
    }

    @discardableResult
    func vpnDisconnect(profileId: String) async throws -> [String: Any] {
        try await call("vpn_disconnect", params: ["profile_id": profileId])
    }

    @discardableResult
    func vpnStatus(profileId: String) async throws -> [String: Any] {
        try await call("vpn_status", params: ["profile_id": profileId])
    }

    // MARK: - WireGuard

    /// Bring up a WireGuard tunnel. The helper writes
    /// `/etc/wireguard/<derived-name>.conf` (mode 0600) and runs
    /// `wg-quick up`. `confContent` is what the daemon's
    /// `vpn_render_wireguard_conf` returned — the full file body
    /// including the spliced-in private key.
    @discardableResult
    func wgConnect(profileId: String, confContent: String, dnsServers: [String]) async throws -> [String: Any] {
        try await call("wg_connect", params: [
            "profile_id": profileId,
            "conf_content": confContent,
            "dns_servers": dnsServers,
        ])
    }

    @discardableResult
    func wgDisconnect(profileId: String) async throws -> [String: Any] {
        try await call("wg_disconnect", params: ["profile_id": profileId])
    }

    @discardableResult
    func wgStatus(profileId: String) async throws -> [String: Any] {
        try await call("wg_status", params: ["profile_id": profileId])
    }

    // MARK: - OpenVPN

    /// Bring up an OpenVPN tunnel. `configFile` is the absolute path
    /// the daemon stored at `vpn_import_openvpn` time
    /// (`<data_dir>/ovpn/<id>.ovpn`). Username + password are passed
    /// only when the .ovpn declares `auth-user-pass`; otherwise omit.
    @discardableResult
    func ovpnConnect(
        profileId: String,
        configFile: String,
        username: String? = nil,
        password: String? = nil,
        requireOpenVPN3: Bool = false
    ) async throws -> [String: Any] {
        var params: [String: Any] = [
            "profile_id": profileId,
            "config_file": configFile,
            "require_openvpn3": requireOpenVPN3,
        ]
        if let u = username { params["username"] = u }
        if let p = password { params["password"] = p }
        return try await call("ovpn_connect", params: params)
    }

    @discardableResult
    func ovpnDisconnect(profileId: String) async throws -> [String: Any] {
        try await call("ovpn_disconnect", params: ["profile_id": profileId])
    }

    @discardableResult
    func ovpnStatus(profileId: String) async throws -> [String: Any] {
        try await call("ovpn_status", params: ["profile_id": profileId])
    }

    // MARK: - Helper self-management (dev iteration)

    /// Probe the deployed helper for its version + capabilities.
    /// Returns the JSON object verbatim — caller picks out `version`,
    /// `methods`, etc. Throws if the helper doesn't even respond.
    ///
    /// Falls back gracefully on a *very* old helper that doesn't
    /// implement `helper_version`: returns an empty methods list so
    /// the caller's "is this method present" check forces a redeploy.
    func helperVersion() async throws -> [String: Any] {
        do {
            return try await call("helper_version", params: [:])
        } catch HelperError.rpcFailure(_, let msg) where msg.contains("unknown method") {
            // Pre-versioning helper — pretend we got an empty
            // capability set so the caller decides to redeploy.
            return ["version": "0.0.0", "methods": [String](), "build_timestamp": "0"]
        }
    }

    // MARK: - Tailscale daemon management

    /// Install the bundled `tailscaled` as a LaunchDaemon. Hands the
    /// privileged helper an absolute path to the binary inside our
    /// app bundle; it copies to /usr/local/sbin, writes the launchd
    /// plist, and bootstraps. Idempotent — calling on an existing
    /// install re-copies the binary and re-bootstraps (useful when
    /// SuperManager itself ships a newer Tailscale).
    @discardableResult
    func tailscaledInstall(bundledDaemonPath: String) async throws -> [String: Any] {
        try await call("tailscaled_install",
                       params: ["bundled_daemon_path": bundledDaemonPath])
    }

    /// Tear down the LaunchDaemon. Preserves the state directory so
    /// a future re-install (ours or Tailscale.app's) keeps the
    /// user's tailnet identity.
    @discardableResult
    func tailscaledUninstall() async throws -> [String: Any] {
        try await call("tailscaled_uninstall", params: [:])
    }

    /// Read whether the LaunchDaemon is installed and whether the
    /// process is alive. Cheaper than `tailscale status` and
    /// distinguishes "not installed" from "installed but down" — UI
    /// uses that to pick between the Install button and the Start
    /// button.
    func tailscaledStatus() async throws -> [String: Any] {
        try await call("tailscaled_status", params: [:])
    }

    /// Install split-default IPv4/IPv6 routes via the Tailscale
    /// utun so non-tailnet traffic actually reaches the selected
    /// exit-node peer. Open-source tailscaled on macOS doesn't do
    /// this itself — that's why "select exit node" used to be a
    /// no-op. See `install_exit_routes` in the helper for the
    /// full rationale.
    /// `autoExitNode` tells the helper the user picked `auto:any` rather than a
    /// named peer, so its persisted self-heal intent records "any exit node"
    /// instead of pinning whichever peer tailscaled happened to resolve to.
    /// Without it, the reconciler re-asserts that one peer after every wake —
    /// silently converting an auto selection into a fixed one, and stranding
    /// self-heal entirely once that peer goes offline.
    ///
    /// We state it here rather than let the helper infer it because this is
    /// where the user's choice is known first-hand; tailscaled's prefs only
    /// report what it resolved to.
    @discardableResult
    func tailscaleInstallExitRoutes(autoExitNode: Bool = false) async throws -> [String: Any] {
        try await call(
            "tailscale_install_exit_routes",
            params: ["auto_exit_node": autoExitNode]
        )
    }

    /// Tear down the split-default routes. Idempotent — safe to
    /// call when no exit node was set or routes were never
    /// installed.
    @discardableResult
    func tailscaleRemoveExitRoutes() async throws -> [String: Any] {
        try await call("tailscale_remove_exit_routes", params: [:])
    }

    // MARK: - Always-on / auto-reconnect

    /// Register a profile for auto-reconnect. Helper persists the
    /// connect args + watches every 30s, replaying on failure.
    /// Survives helper restart (LaunchDaemon).
    ///
    /// - Parameter backend: "wireguard" | "openvpn" | "ikev2"
    /// - Parameter connectArgs: the same params the GUI sends to
    ///   the corresponding `*_connect` RPC. Helper stores it
    ///   verbatim and replays.
    @discardableResult
    func autoReconnectEnable(
        profileId: String,
        backend: String,
        connectArgs: [String: Any]
    ) async throws -> [String: Any] {
        try await call("auto_reconnect_enable", params: [
            "profile_id": profileId,
            "backend": backend,
            "connect_args": connectArgs,
        ])
    }

    /// Remove a profile from auto-reconnect watch list. Idempotent.
    @discardableResult
    func autoReconnectDisable(profileId: String) async throws -> [String: Any] {
        try await call("auto_reconnect_disable",
                       params: ["profile_id": profileId])
    }

    /// List watched profile IDs, and the subset that is enrolled but not
    /// yet armed (no replayable connect args stored — IKEv2 before its
    /// first manual connect). UI reads this to render the always-on
    /// toggle's correct state, and to avoid presenting an unarmed entry
    /// as protection. `unarmed` is absent from older helpers; that maps
    /// to the empty set, which is also the honest default.
    func autoReconnectList() async throws -> (watched: [String], unarmed: [String]) {
        let r = try await call("auto_reconnect_list", params: [:])
        return (
            watched: (r["watched"] as? [String]) ?? [],
            unarmed: (r["unarmed"] as? [String]) ?? []
        )
    }

    // MARK: - Kill-switch

    /// Install pf rules that block all egress except via the
    /// named tunnel interface + LAN. Helper rebuilds /etc/pf.conf
    /// references and reloads pf. Idempotent. Caller must already
    /// know the tunnel iface (e.g. utun7) — typically pulled from
    /// the connect-result of wg/ovpn/ikev2.
    @discardableResult
    func killSwitchEnable(tunnelInterface: String) async throws -> [String: Any] {
        try await call("kill_switch_enable",
                       params: ["tunnel_interface": tunnelInterface])
    }

    /// Tear down the kill-switch. Idempotent — safe to call when
    /// no kill-switch is active.
    @discardableResult
    func killSwitchDisable() async throws -> [String: Any] {
        try await call("kill_switch_disable", params: [:])
    }

    /// Pause the connectivity watchdog's panic_reset escalation
    /// for `seconds` seconds. Probes still run and log misses,
    /// but no automatic recovery action fires. Critical wrapper
    /// around exit-node transitions, which are inherently
    /// disruptive (DNS reconfig + TCP resets) and would
    /// otherwise be undone by the watchdog.
    @discardableResult
    func tailscalePauseWatchdog(seconds: Int) async throws -> [String: Any] {
        try await call("tailscale_pause_watchdog", params: ["seconds": seconds])
    }

    @discardableResult
    func tailscaleResumeWatchdog() async throws -> [String: Any] {
        try await call("tailscale_resume_watchdog", params: [:])
    }

    /// Pre-flight test: with the daemon already configured for an
    /// exit node, install a single /32 route to a known public IP
    /// via Tailscale's utun, probe it (2s budget), clean up, and
    /// report whether the peer actually forwarded.
    ///
    /// Returns dict with `success: Bool`, `response_code: String`,
    /// `message: String`. Caller commits to the full split-default
    /// install only when `success == true`.
    func tailscaleTestExitReachability() async throws -> [String: Any] {
        try await call("tailscale_test_exit_reachability", params: [:])
    }

    /// Force-write the system DNS state via scutil to the given
    /// servers list. Bypasses configd's normal merge logic — used
    /// when the resolver gets stuck on an unreachable IPv6 RDNSS.
    @discardableResult
    func tailscaleForceDNSState(servers: [String]) async throws -> [String: Any] {
        try await call("tailscale_force_dns_state", params: ["servers": servers])
    }

    /// Read the user's persisted DNS fallback list (used by the
    /// DNS health watchdog). Defaults baked into helper if never
    /// set.
    func tailscaleGetDNSFallbacks() async throws -> [String: Any] {
        try await call("tailscale_get_dns_fallbacks", params: [:])
    }

    /// Persist a new DNS fallback list. Watchdog uses these when
    /// it detects a stuck resolver. Persisted to
    /// /var/lib/supermanager/dns_fallbacks.json.
    @discardableResult
    func tailscaleSetDNSFallbacks(servers: [String]) async throws -> [String: Any] {
        try await call("tailscale_set_dns_fallbacks", params: ["servers": servers])
    }

    /// Install or remove the per-tailnet `/etc/resolver/<domain>`
    /// file that macOS uses to route MagicDNS queries to
    /// 100.100.100.100. Backstops a tailscaled-on-macOS bug where
    /// the open-source daemon writes the search-domain file but
    /// not the nameserver file; without this, `mac.tailnet.ts.net`
    /// doesn't resolve through the system resolver even though
    /// `dig @100.100.100.100` works.
    @discardableResult
    func tailscaleInstallMagicDNSResolver(tailnetSuffix: String, install: Bool) async throws -> [String: Any] {
        try await call("tailscale_install_magicdns_resolver",
                       params: ["tailnet_suffix": tailnetSuffix, "install": install])
    }

    /// Emergency reset: clear any stuck exit-node + accept-routes
    /// preference and renew DHCP on the active network interface.
    /// Used when an exit-node selection has trashed the routing
    /// table and the user can't reach the internet at all.
    ///
    /// Returns `{success, message}`. Even on partial failure
    /// (DHCP renew worked but daemon wasn't responsive, or vice
    /// versa) the helper does as much as it can rather than
    /// bailing — the user is in trouble and any progress helps.
    @discardableResult
    func tailscalePanicReset() async throws -> [String: Any] {
        // This is the user-initiated hard reset (the "Panic reset" menu), so
        // clear_pref=true: the helper also clears the tailscaled exit-node pref
        // and the persisted desired-state. The connectivity watchdog's
        // automatic blip recovery calls panic_reset in-process with
        // clear_pref=false (fail open, keep intent for self-heal).
        try await call("tailscale_panic_reset", params: ["clear_pref": true])
    }

    /// What the helper did on its own after `cursor`: auto-reconnects,
    /// reconnects that keep failing, watchdog fail-opens. No cursor, or one
    /// from before the helper last restarted, gets everything it still holds.
    func eventsSince(_ cursor: HelperEventCursor?) async throws -> HelperEventBatch {
        var params: [String: Any] = [:]
        if let cursor {
            params["boot"] = cursor.boot
            params["after"] = cursor.seq
        }
        let result = try await call("events_since", params: params)
        guard let batch = HelperEventBatch(result) else {
            throw HelperError.decodeFailure("events_since: not an event batch")
        }
        return batch
    }

    /// Tail the helper's log file. Returns the trailing `bytes` of
    /// `/var/log/supermanager-helper.log` (or the whole file if shorter).
    /// Used by the "View Helper Log" button so a user diagnosing a
    /// failed connect can see what charon actually said without escalating
    /// out of the app.
    func tailLog(bytes: Int = 8 * 1024) async throws -> String {
        let result = try await call("tail_log", params: ["bytes": bytes])
        return result["log"] as? String ?? ""
    }

    // MARK: - System sleep / wake

    /// Notify the helper that the system is about to sleep.
    /// Belt-and-braces cleanup after the Swift layer has already
    /// fired individual disconnect RPCs: terminates any lingering
    /// IKEv2 SAs and kills orphaned ovpncli processes so they
    /// don't hold stale tunnel state across the sleep boundary.
    @discardableResult
    func systemSleep() async throws -> [String: Any] {
        try await call("system_sleep", params: [:])
    }

    /// Notify the helper that the system just woke from sleep.
    /// Clears the route guardian's pre-sleep snapshot (stale
    /// gateway from the old network) and sweeps leftover strongSwan
    /// configs + kernel host routes so the first post-wake connect
    /// attempt starts from a clean slate.
    @discardableResult
    func systemWake() async throws -> [String: Any] {
        try await call("system_wake", params: [:])
    }

    // MARK: - Wire protocol

    private static var nextId: UInt64 = 0

    /// End-to-end budget for one RPC. These are ceilings derived from the
    /// helper's own per-command budgets (`proc.rs`), not guesses: an IKEv2
    /// connect may legitimately spend 30 s in `swanctl --initiate`, and
    /// declaring it dead earlier reports a failure for a tunnel that is
    /// coming up.
    private static func budget(for method: String) -> Duration {
        switch method {
        case "ping", "events_since":
            // Neither waits on anything in the helper, and both are polled.
            return .seconds(3)
        case "tailscaled_install", "tailscale_panic_reset":
            // `launchctl bootstrap` / `ipconfig set … DHCP` run on 60 s budgets.
            return .seconds(120)
        case "wg_connect":
            // A stale-tunnel `wg-quick down` + `ifconfig destroy`, then
            // `wg-quick up`: 30 + 10 + 30 s at the helper's ceilings.
            return .seconds(90)
        case "vpn_connect", "vpn_disconnect", "wg_disconnect", "system_sleep":
            // charon restart + `--initiate` (30 s), or `--terminate` and
            // `--load-all` (20 s each), plus bounded route/DNS cleanup.
            return .seconds(60)
        case "ovpn_connect", "ovpn_disconnect", "tailscaled_uninstall",
             "tailscale_install_exit_routes", "tailscale_remove_exit_routes",
             "tailscale_test_exit_reachability", "tailscale_force_dns_state",
             "tailscale_install_magicdns_resolver", "kill_switch_enable",
             "kill_switch_disable", "system_wake":
            return .seconds(45)
        default:
            return .seconds(15)
        }
    }

    private func call(_ method: String, params: [String: Any]) async throws -> [String: Any] {
        do {
            return try await roundTrip(method: method, params: params)
        } catch let failure as UnixSocketRPC.Failure {
            // Retry only what provably never reached the helper (it was
            // restarting between accept and read). Once the frame is written
            // the helper may be executing it — most of these RPCs change
            // system state, and a second `vpn_connect` kills the charon the
            // first one just brought up — so any later failure is final.
            guard !failure.requestSent, failure.kind != .unreachable else { throw Self.helperError(failure) }
            DebugLog.write("[helper] retry \(method) after I/O failure before send: \(failure)")
            try? await Task.sleep(for: .milliseconds(400))
            do {
                return try await roundTrip(method: method, params: params)
            } catch let again as UnixSocketRPC.Failure {
                throw Self.helperError(again)
            }
        }
    }

    /// One request/response exchange on a fresh connection. Throws
    /// `UnixSocketRPC.Failure` for socket-level failures, `HelperError` for
    /// everything the helper actually said.
    private func roundTrip(method: String, params: [String: Any]) async throws -> [String: Any] {
        Self.nextId &+= 1
        let body = try JSONSerialization.data(withJSONObject: [
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": Self.nextId,
        ] as [String: Any])
        let reply = try await UnixSocketRPC.roundTrip(
            path: Self.socketPath,
            body: body,
            deadline: .init(method: method, budget: Self.budget(for: method)),
            maxReply: 10 * 1024 * 1024
        )

        guard let json = try? JSONSerialization.jsonObject(with: reply) as? [String: Any] else {
            throw HelperError.decodeFailure("not a JSON object")
        }
        if let err = json["error"] as? [String: Any] {
            let code = err["code"] as? Int ?? 0
            let msg = err["message"] as? String ?? "unknown helper error"
            throw HelperError.rpcFailure(code: code, message: msg)
        }
        return json["result"] as? [String: Any] ?? [:]
    }

    private static func helperError(_ failure: UnixSocketRPC.Failure) -> HelperError {
        switch failure.kind {
        case .unreachable: return .notInstalled
        case .timedOut: return .ioFailure("\(failure) (helper not responding)")
        case .replyTooLarge, .io: return .ioFailure(failure.description)
        }
    }
}
