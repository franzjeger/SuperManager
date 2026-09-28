import Foundation

/// JSON-RPC client for the user daemon, `supermgrd-mac`.
///
/// Each call is one exchange on a fresh connection (`UnixSocketRPC`), so
/// calls run side by side, a slow one holds up only its own caller, and a
/// daemon replaced between two calls costs nothing. A call that failed before
/// its request was completely written is sent once more, since the daemon
/// cannot have run it. Once the request is out a failure is final: the daemon
/// may have executed it, and most of these calls change state.
actor ServiceClient {
    private var requestId: UInt64 = 0
    /// Where the daemon listens. Only tests point it anywhere else.
    private let path: String

    init(socketPath: String = ServiceClient.socketPath) {
        path = socketPath
    }

    static var socketPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/Library/Application Support/SuperManager/supermgrd.sock"
    }

    /// Throws unless the daemon's socket accepts connections: the launch-time
    /// check that there is a daemon at all. Every call connects on its own.
    func probe() throws {
        do {
            try UnixSocketRPC.probe(path: path)
        } catch let failure as UnixSocketRPC.Failure {
            throw ServiceError(failure)
        }
    }

    func call<T: Decodable>(_ method: String, params: [String: Any] = [:]) async throws -> T {
        guard let result = try await send(method, params: params)["result"] else {
            throw ServiceError.noResult
        }
        return try Self.decode(T.self, from: result)
    }

    func callVoid(_ method: String, params: [String: Any] = [:]) async throws {
        _ = try await send(method, params: params)
    }

    /// One call, sent a second time only if the first never got out.
    private func send(_ method: String, params: [String: Any]) async throws -> [String: Any] {
        do {
            return try await exchange(method, params: params)
        } catch let failure as UnixSocketRPC.Failure where !failure.requestSent {
            // Not written, so not run. Usually the daemon is between
            // processes: a new launch has just replaced it.
            DebugLog.write("[daemon] retrying \(method) after a failure before sending: \(failure)")
            try? await Task.sleep(for: .milliseconds(400))
            do {
                return try await exchange(method, params: params)
            } catch let again as UnixSocketRPC.Failure {
                DebugLog.write("[daemon] \(method) failed: \(again)")
                throw ServiceError(again)
            }
        } catch let failure as UnixSocketRPC.Failure {
            DebugLog.write("[daemon] \(method) failed: \(failure)")
            throw ServiceError(failure)
        }
    }

    /// One request/response exchange. Throws `UnixSocketRPC.Failure` for the
    /// socket and `ServiceError.rpcError` for an error the daemon returned.
    private func exchange(_ method: String, params: [String: Any]) async throws -> [String: Any] {
        requestId &+= 1
        let body = try JSONSerialization.data(withJSONObject: [
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": requestId,
        ] as [String: Any])
        let reply = try await UnixSocketRPC.roundTrip(
            path: path,
            body: body,
            deadline: .init(method: method, budget: Self.budget(for: method)),
            maxReply: kMaxRpcResponseBytes
        )
        let json = try JSONSerialization.jsonObject(with: reply) as? [String: Any] ?? [:]
        if let error = json["error"] as? [String: Any] {
            throw ServiceError.rpcError(Self.parseRpcErrorPayload(error))
        }
        return json
    }

    /// End-to-end budget for one call, or nil to wait as long as the daemon
    /// takes. Derived from the daemon's handlers, not guessed:
    /// - What is local to the daemon (its state, secret store and files)
    ///   answers in milliseconds and gets the default.
    /// - A call bounded by the daemon's own network and subprocess timeouts
    ///   gets twice that ceiling, so a slow success is never reported as a
    ///   failure.
    /// - A call whose run time grows with the hosts, devices or data it
    ///   covers, or that waits on SSH authentication or a remote command
    ///   with no timeout, gets none. No finite budget is guaranteed not to
    ///   cut off real work, and the daemon goes on running a call its client
    ///   has given up on: a deploy reported as timed out would still be
    ///   pushing configuration.
    /// A new method belongs in the class its handler does.
    static func budget(for method: String) -> Duration? {
        switch method {
        case "ssh_test_connection", "ssh_execute_command", "ssh_push_key", "ssh_probe_hosts",
             "compliance_run", "compliance_run_linux", "compliance_scan_all",
             "discovery_passive_scan", "fortigate_generate_api_token",
             "provisioning_diff_preview", "provisioning_deploy", "provisioning_rollback",
             "unifi_set_inform", "unifi_controller_devices", "backup_import":
            return nil
        case "unifi_test":
            // Two requests, each a 30 s login plus a 30 s call.
            return .seconds(240)
        case "dns_health_audit":
            // 14 DKIM selectors, one 4 s `dig` after another.
            return .seconds(112)
        case "unifi_controller_save", "unifi_controller_mfa_complete":
            // Three 15 s controller requests.
            return .seconds(90)
        case "cve_feed_refresh", "subdomain_enum", "fortigate_test_connection",
             "fortigate_get_dashboard", "unifi_set_controller", "unifi_controller_test",
             "unifi_controller_mfa_send", "unifi_controller_devmgr":
            // One 30 s request, or two of 15 s.
            return .seconds(60)
        case "ssh_generate_key", "backup_export":
            // Local, but CPU- or size-bound: an RSA-4096 prime search, or
            // the whole store serialised.
            return .seconds(60)
        default:
            return .seconds(30)
        }
    }

    private static func decode<T: Decodable>(_ type: T.Type, from result: Any) throws -> T {
        let resultData: Data
        if result is NSNull {
            resultData = "null".data(using: .utf8)!
        } else if let str = result as? String {
            // JSONSerialization crashes on bare strings - encode manually
            let jsonStr = try JSONEncoder().encode(str)
            resultData = jsonStr
        } else if let num = result as? NSNumber {
            resultData = "\(num)".data(using: .utf8)!
        } else {
            resultData = try JSONSerialization.data(withJSONObject: result)
        }

        // ISO-8601 (RFC3339) is the format chrono::DateTime<Utc>
        // serializes to in serde, so any DTO with a Date field
        // (compliance runs, audit entries, …) decodes without
        // per-call configuration. Existing callers that expect
        // numeric epoch dates don't currently exist.
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(T.self, from: resultData)
    }

    /// Lift `error.data.{kind,actionable}` (when the daemon used
    /// `Response::err_engine`) into a structured `RpcErrorInfo`.
    /// Older handlers that still use plain `Response::err` produce
    /// `data == nil`, so `kind` falls back to `"other"`.
    private static func parseRpcErrorPayload(_ obj: [String: Any]) -> RpcErrorInfo {
        let message = obj["message"] as? String ?? "Unknown error"
        let code = obj["code"] as? Int ?? -32603
        let data = obj["data"] as? [String: Any]
        let kind = data?["kind"] as? String ?? "other"
        let actionable = data?["actionable"] as? Bool ?? false
        return RpcErrorInfo(
            code: code,
            message: message,
            kind: kind,
            actionable: actionable
        )
    }
}

/// Structured payload extracted from a daemon JSON-RPC error.
///
/// `kind` is the stable machine-readable category (e.g.
/// `"pdf_engine_missing"`, `"ssh_auth"`, `"tool_missing"`) — the
/// Mac UI switches on it for category-specific UX. `"other"` is
/// the catch-all for handlers that haven't been migrated to
/// `Response::err_engine` yet.
struct RpcErrorInfo: Hashable {
    let code: Int
    let message: String
    let kind: String
    let actionable: Bool
}

enum ServiceError: LocalizedError {
    /// The daemon hung up, or the socket failed, after the request was sent.
    case disconnected
    case connectionFailed(String)
    /// No reply within the call's budget.
    case timedOut(String)
    /// RPC error from the daemon. The associated `RpcErrorInfo`
    /// carries the structured kind/actionable so callers can
    /// branch on category — see `RpcErrorInfo.kind` for the
    /// known values.
    case rpcError(RpcErrorInfo)
    case noResult
    case messageTooLarge(Int)

    var errorDescription: String? {
        switch self {
        case .disconnected: return "Connection to daemon lost"
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .timedOut(let msg): return "\(msg) (daemon not responding)"
        case .rpcError(let info): return "Daemon error: \(info.message)"
        case .noResult: return "No result from daemon"
        case .messageTooLarge(let n):
            return "Daemon response exceeded 256 MB limit (\(n) bytes); refusing to allocate."
        }
    }

    /// Convenience accessor for the structured error kind, or
    /// `nil` if this isn't an RPC error. Callers do
    /// `if case .rpcError(let info) = error, info.kind == "..."`
    /// — this is a shorthand for branch-on-kind code paths.
    var rpcKind: String? {
        if case .rpcError(let info) = self { return info.kind }
        return nil
    }

    /// What a caller sees of a socket failure. The detail is in the debug log.
    init(_ failure: UnixSocketRPC.Failure) {
        switch failure.kind {
        case .unreachable: self = .connectionFailed(failure.description)
        case .timedOut: self = .timedOut(failure.description)
        case .replyTooLarge(let length): self = .messageTooLarge(Int(length))
        case .io: self = .disconnected
        }
    }
}

/// Cap on a single RPC response. The daemon already has a 10 MiB
/// inbound limit; this protects the app side from a malicious or
/// corrupted daemon sending an oversized length-prefix and forcing
/// us to allocate hundreds of MB before we know the body is bogus.
/// 256 MB is more than enough for the largest legitimate response
/// (an engagement PDF is typically <2 MB).
private let kMaxRpcResponseBytes: UInt32 = 256 * 1024 * 1024

/// Wire-protocol version this app expects to talk to. Major bumps
/// indicate a breaking-change handshake; the app warns the user
/// when the daemon reports a different major. Kept in sync with
/// `supermgr-engine::protocol::API_VERSION_MAJOR`.
public enum DaemonApiVersion {
    public static let expectedMajor: UInt32 = 1

    /// Decoded shape of `api_version` RPC response.
    public struct Info: Codable, Equatable {
        public let major: UInt32
        public let minor: UInt32
    }

    /// `true` when the daemon's major matches the app's expectation.
    /// Minor differences are always compatible (additive changes only).
    public static func isCompatible(_ info: Info) -> Bool {
        info.major == expectedMajor
    }
}
