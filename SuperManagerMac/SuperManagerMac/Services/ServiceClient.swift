import Foundation

/// JSON-RPC client over Unix domain socket using POSIX sockets.
/// Much simpler and more reliable than NWConnection for sequential request/response.
actor ServiceClient {
    private var fd: Int32 = -1
    private var requestId: UInt64 = 0

    static var socketPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/Library/Application Support/SuperManager/supermgrd.sock"
    }

    func connect() async throws {
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            throw ServiceError.connectionFailed("socket() failed: \(errno)")
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = Self.socketPath
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            path.withCString { cstr in
                _ = memcpy(ptr, cstr, min(path.utf8.count, 104))
            }
        }

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(sock, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard result == 0 else {
            close(sock)
            throw ServiceError.connectionFailed("connect() failed: \(errno)")
        }

        self.fd = sock
    }

    /// Run an RPC, transparently re-establishing the socket once if the
    /// daemon dropped us between calls (e.g. it restarted, the user put
    /// the laptop to sleep, the OS reaped the fd). Without this every
    /// daemon respawn forces a full app restart.
    ///
    /// We retry exactly once. If the daemon is *truly* unreachable, the
    /// second attempt fails and the caller surfaces the error normally.
    func call<T: Decodable>(_ method: String, params: [String: Any] = [:]) async throws -> T {
        do {
            return try await callOnce(method, params: params)
        } catch ServiceError.notConnected, ServiceError.disconnected {
            disconnect()
            try await connect()
            return try await callOnce(method, params: params)
        }
    }

    func callVoid(_ method: String, params: [String: Any] = [:]) async throws {
        do {
            try await callVoidOnce(method, params: params)
        } catch ServiceError.notConnected, ServiceError.disconnected {
            disconnect()
            try await connect()
            try await callVoidOnce(method, params: params)
        }
    }

    private func callOnce<T: Decodable>(_ method: String, params: [String: Any]) async throws -> T {
        guard fd >= 0 else { throw ServiceError.notConnected }

        requestId += 1
        let id = requestId

        let request: [String: Any] = [
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: request)

        // Send length-prefixed frame
        var len = UInt32(jsonData.count).bigEndian
        let lenData = Data(bytes: &len, count: 4)
        try sendAll(lenData)
        try sendAll(jsonData)

        // Read 4-byte length
        let respLenData = try recvExact(4)
        let respLen = respLenData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard respLen <= kMaxRpcResponseBytes else {
            throw ServiceError.messageTooLarge(Int(respLen))
        }

        // Read response
        let respData = try recvExact(Int(respLen))

        // Parse
        let jsonResp = try JSONSerialization.jsonObject(with: respData) as? [String: Any]

        if let error = jsonResp?["error"] as? [String: Any] {
            throw ServiceError.rpcError(error["message"] as? String ?? "Unknown error")
        }

        guard let result = jsonResp?["result"] else {
            throw ServiceError.noResult
        }

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

    private func callVoidOnce(_ method: String, params: [String: Any]) async throws {
        guard fd >= 0 else { throw ServiceError.notConnected }

        requestId += 1
        let request: [String: Any] = [
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": requestId
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: request)
        var len = UInt32(jsonData.count).bigEndian
        try sendAll(Data(bytes: &len, count: 4))
        try sendAll(jsonData)

        let respLenData = try recvExact(4)
        let respLen = respLenData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        let respData = try recvExact(Int(respLen))

        let jsonResp = try JSONSerialization.jsonObject(with: respData) as? [String: Any]
        if let error = jsonResp?["error"] as? [String: Any] {
            throw ServiceError.rpcError(error["message"] as? String ?? "Unknown error")
        }
    }

    func disconnect() {
        if fd >= 0 {
            close(fd)
            fd = -1
        }
    }

    // MARK: - Low-level I/O

    private func sendAll(_ data: Data) throws {
        try data.withUnsafeBytes { buffer in
            var sent = 0
            while sent < buffer.count {
                let n = Darwin.send(fd, buffer.baseAddress! + sent, buffer.count - sent, 0)
                guard n > 0 else {
                    throw ServiceError.disconnected
                }
                sent += n
            }
        }
    }

    private func recvExact(_ count: Int) throws -> Data {
        var buffer = Data(count: count)
        var received = 0
        try buffer.withUnsafeMutableBytes { ptr in
            while received < count {
                let n = Darwin.recv(fd, ptr.baseAddress! + received, count - received, 0)
                guard n > 0 else {
                    throw ServiceError.disconnected
                }
                received += n
            }
        }
        return buffer
    }
}

enum ServiceError: LocalizedError {
    case notConnected
    case disconnected
    case connectionFailed(String)
    case rpcError(String)
    case noResult
    case messageTooLarge(Int)

    var errorDescription: String? {
        switch self {
        case .notConnected: return "Not connected to daemon"
        case .disconnected: return "Connection to daemon lost"
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .rpcError(let msg): return "Daemon error: \(msg)"
        case .noResult: return "No result from daemon"
        case .messageTooLarge(let n):
            return "Daemon response exceeded 256 MB limit (\(n) bytes); refusing to allocate."
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
