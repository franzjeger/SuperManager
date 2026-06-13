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

    /// True when the LaunchDaemon socket exists and we can `connect()` to it.
    /// This is cheap (<1ms) so callers can poll it for UI state.
    func isReachable() async -> Bool {
        guard FileManager.default.fileExists(atPath: Self.socketPath) else { return false }
        do {
            let fd = try connectFD()
            close(fd)
            return true
        } catch {
            return false
        }
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
        routes: [String] = []
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
    func wgConnect(profileId: String, confContent: String) async throws -> [String: Any] {
        try await call("wg_connect", params: [
            "profile_id": profileId,
            "conf_content": confContent,
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
        password: String? = nil
    ) async throws -> [String: Any] {
        var params: [String: Any] = [
            "profile_id": profileId,
            "config_file": configFile,
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

    // MARK: - FortiGate SSL-VPN (openfortivpn)

    /// Bring up a FortiGate SSL-VPN tunnel via openfortivpn.
    /// `host` is the gateway address (e.g. `vpn.sybr.no`).
    /// `port` defaults to 443; admins occasionally move it.
    /// `trustedCert` is an optional SHA-256 fingerprint —
    /// only needed for gateways with non-public CAs.
    @discardableResult
    func fortiConnect(
        profileId: String,
        host: String,
        port: UInt16 = 443,
        username: String,
        password: String,
        trustedCert: String? = nil,
        noDefaultRoute: Bool = false
    ) async throws -> [String: Any] {
        var params: [String: Any] = [
            "profile_id": profileId,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "no_default_route": noDefaultRoute,
        ]
        if let cert = trustedCert, !cert.isEmpty {
            params["trusted_cert"] = cert
        }
        return try await call("forti_connect", params: params)
    }

    @discardableResult
    func fortiDisconnect(profileId: String) async throws -> [String: Any] {
        try await call("forti_disconnect", params: ["profile_id": profileId])
    }

    @discardableResult
    func fortiStatus(profileId: String) async throws -> [String: Any] {
        try await call("forti_status", params: ["profile_id": profileId])
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
            return ["version": "0.0.0", "methods": [String](), "build_timestamp": "0", "dev_rpc": false]
        }
    }

    /// Generic typed-decoded helper RPC call. Wraps the private
    /// `call(method:params:)` and decodes the response body into
    /// the caller's `Decodable` type. New call sites should use
    /// this in preference to dictionary-fishing through the raw
    /// `[String: Any]` form.
    func callRaw<T: Decodable>(method: String, params: [String: Any]) async throws -> T {
        let raw = try await call(method, params: params)
        let data = try JSONSerialization.data(withJSONObject: raw)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// Hand the deployed helper an absolute path to a *new* binary
    /// and have it copy itself, then exit so launchd respawns from
    /// the new code. Only works when the deployed helper was built
    /// with `--features dev-rpc` (which our Xcode build does).
    ///
    /// Production hardening: replace this with a notarised installer
    /// + admin auth prompt before shipping. Documented at the
    /// `deploy_self` RPC in `supermanager-helper/src/main.rs`.
    @discardableResult
    func deploySelf(sourcePath: String) async throws -> [String: Any] {
        try await call("deploy_self", params: ["source": sourcePath])
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
    @discardableResult
    func tailscaleInstallExitRoutes() async throws -> [String: Any] {
        try await call("tailscale_install_exit_routes", params: [:])
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

    /// List currently-watched profile IDs. UI reads this to render
    /// the always-on toggle's correct state.
    func autoReconnectList() async throws -> [String] {
        let r = try await call("auto_reconnect_list", params: [:])
        return (r["watched"] as? [String]) ?? []
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
        try await call("tailscale_panic_reset", params: [:])
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

    // MARK: - Wire protocol

    private static var nextId: UInt64 = 0

    private func call(_ method: String, params: [String: Any]) async throws -> [String: Any] {
        // Single-retry policy: socket-level failures (helper
        // mid-respawn after deploy_self, transient ECONNREFUSED)
        // are extremely common during dev iteration and benign
        // — the helper comes back within ~300 ms. Retrying once
        // makes the GUI tolerant of these without surfacing a
        // user-visible error. RPC-level errors (`-32000` etc.)
        // are NOT retried — they're caller bugs or genuine
        // failures that won't change on retry.
        do {
            return try await callOnce(method: method, params: params, timeoutSeconds: 8)
        } catch HelperError.notInstalled {
            // Helper genuinely missing — don't retry; the user
            // needs to run install_helper.sh.
            throw HelperError.notInstalled
        } catch HelperError.ioFailure(let m) {
            // Transient socket failure — sleep briefly + retry.
            DebugLog.write("[helper] retry \(method) after I/O fail: \(m)")
            try? await Task.sleep(for: .milliseconds(400))
            return try await callOnce(method: method, params: params, timeoutSeconds: 8)
        }
    }

    /// One round-trip with a wall-clock timeout. macOS gives us
    /// no socket-level read timeout by default, and a wedged
    /// helper would otherwise hang the GUI thread until the user
    /// force-quits. The timeout is per-call, applied via a
    /// `Task.timeout` race.
    private func callOnce(
        method: String,
        params: [String: Any],
        timeoutSeconds: Int
    ) async throws -> [String: Any] {
        Self.nextId &+= 1
        let id = Self.nextId

        let payload: [String: Any] = [
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        ]
        let data = try JSONSerialization.data(withJSONObject: payload)

        let work = Task.detached(priority: .userInitiated) { [data] () -> [String: Any] in
            let fd = try Self.connectFDStatic()
            defer { close(fd) }
            try Self.writeFrame(fd: fd, data: data)
            let respData = try Self.readFrame(fd: fd)
            guard let json = try? JSONSerialization.jsonObject(with: respData) as? [String: Any] else {
                throw HelperError.decodeFailure("not a JSON object")
            }
            if let err = json["error"] as? [String: Any] {
                let code = err["code"] as? Int ?? 0
                let msg = err["message"] as? String ?? "unknown helper error"
                throw HelperError.rpcFailure(code: code, message: msg)
            }
            if let result = json["result"] as? [String: Any] { return result }
            return [:]
        }

        // Race the work against a deadline. If the deadline wins,
        // cancel the work and surface a clear timeout error.
        let timeout = Task.detached(priority: .userInitiated) { () -> [String: Any] in
            try await Task.sleep(for: .seconds(timeoutSeconds))
            throw HelperError.ioFailure("RPC \(method) timed out after \(timeoutSeconds)s")
        }
        do {
            let result = try await work.value
            timeout.cancel()
            return result
        } catch {
            work.cancel()
            timeout.cancel()
            throw error
        }
    }

    private func connectFD() throws -> Int32 {
        try Self.connectFDStatic()
    }

    nonisolated private static func connectFDStatic() throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw HelperError.ioFailure("socket(): \(errno)")
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(Self.socketPath.utf8)
        let sunPathCap = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < sunPathCap else {
            close(fd)
            throw HelperError.ioFailure("socket path too long")
        }
        // Copy into the fixed-size sun_path C-array. Locking in `sunPathCap`
        // up front avoids the exclusivity violation Swift would otherwise
        // flag for reading `addr.sun_path` while we hold a mutable pointer
        // to it.
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: sunPathCap) { dst in
                for (i, b) in pathBytes.enumerated() {
                    dst[i] = CChar(bitPattern: b)
                }
                dst[pathBytes.count] = 0
            }
        }
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                connect(fd, sp, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0 {
            let e = errno
            close(fd)
            if e == ENOENT || e == ECONNREFUSED {
                throw HelperError.notInstalled
            }
            throw HelperError.ioFailure("connect(): errno=\(e)")
        }
        return fd
    }

    nonisolated private static func writeFrame(fd: Int32, data: Data) throws {
        var lenBE = UInt32(data.count).bigEndian
        let lenData = Data(bytes: &lenBE, count: 4)
        try writeAll(fd: fd, data: lenData)
        try writeAll(fd: fd, data: data)
    }

    nonisolated private static func writeAll(fd: Int32, data: Data) throws {
        try data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> Void in
            var written = 0
            while written < data.count {
                let n = write(fd, buf.baseAddress!.advanced(by: written), data.count - written)
                if n <= 0 {
                    throw HelperError.ioFailure("write(): errno=\(errno)")
                }
                written += n
            }
        }
    }

    nonisolated private static func readFrame(fd: Int32) throws -> Data {
        let lenBytes = try readExact(fd: fd, count: 4)
        let len = lenBytes.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            UInt32(bigEndian: buf.load(as: UInt32.self))
        }
        guard len <= 10 * 1024 * 1024 else {
            throw HelperError.ioFailure("frame too large (\(len) bytes)")
        }
        return try readExact(fd: fd, count: Int(len))
    }

    nonisolated private static func readExact(fd: Int32, count: Int) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { (buf: UnsafeMutableRawBufferPointer) -> Void in
            var got = 0
            while got < count {
                let n = read(fd, buf.baseAddress!.advanced(by: got), count - got)
                if n == 0 {
                    throw HelperError.ioFailure("EOF before frame complete")
                }
                if n < 0 {
                    throw HelperError.ioFailure("read(): errno=\(errno)")
                }
                got += n
            }
        }
        return data
    }
}
