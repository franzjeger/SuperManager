import XCTest
@testable import SuperManagerMac

/// `ServiceClient` against a stand-in daemon on a private socket.
final class ServiceClientTests: XCTestCase {
    /// sun_path holds 104 bytes. The test's temporary directory can be
    /// longer than that; /tmp never is.
    private let path = "/tmp/sm-\(UUID().uuidString.prefix(8)).sock"

    override func tearDown() {
        unlink(path)
        super.tearDown()
    }

    /// A daemon that went away between two calls — a newer launch replaced
    /// it, or it crashed — must cost the client one failed send, which
    /// `call` turns into a reconnect. Without SO_NOSIGPIPE that send raised
    /// SIGPIPE and terminated the process: this test crashed rather than
    /// failed, as the app did when its daemon was replaced.
    func testCallReconnectsWhenTheDaemonRestarted() async throws {
        let first = try FakeDaemon(path: path)
        let client = ServiceClient(socketPath: path)
        try await client.connect()
        first.dropNextConnection()
        first.stop()

        let second = try FakeDaemon(path: path)
        defer { second.stop() }
        second.answerNextRequest(with: "pong")
        let reply: String = try await client.call("ping")
        XCTAssertEqual(reply, "pong")
    }

    /// With no daemon to come back to, the failed send ends in the
    /// reconnect's error — an error, not a dead process.
    func testCallFailsWhenTheDaemonIsGone() async throws {
        let daemon = try FakeDaemon(path: path)
        let client = ServiceClient(socketPath: path)
        try await client.connect()
        daemon.dropNextConnection()
        daemon.stop()
        do {
            let _: String = try await client.call("ping")
            XCTFail("call succeeded with no daemon listening")
        } catch ServiceError.connectionFailed {
            // The send failed quietly and the reconnect found nothing.
        }
    }
}

/// Just enough of supermgrd-mac: a listening socket that takes length-
/// prefixed JSON-RPC frames.
private final class FakeDaemon {
    private let path: String
    private let listener: Int32
    private let answered = DispatchGroup()

    init(path: String) throws {
        self.path = path
        unlink(path)
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw POSIXError(.EMFILE) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: path.utf8) }
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, listen(listener, 4) == 0 else {
            let code = POSIXErrorCode(rawValue: errno) ?? .EIO
            close(listener)
            throw POSIXError(code)
        }
    }

    /// Accept the client's connection and close it at once: what the
    /// client sees when the daemon process dies under it.
    func dropNextConnection() {
        let conn = Self.accept(listener)
        if conn >= 0 { close(conn) }
    }

    /// Answer the next request, on a background queue, with `result`.
    func answerNextRequest(with result: String) {
        let listener = self.listener
        answered.enter()
        DispatchQueue.global().async { [answered] in
            defer { answered.leave() }
            let conn = Self.accept(listener)
            guard conn >= 0 else { return }
            defer { close(conn) }
            guard let header = Self.read(conn, count: 4),
                  let body = Self.read(conn, count: Int(header.withUnsafeBytes { $0.load(as: UInt32.self) }.bigEndian)),
                  let request = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                  let reply = try? JSONSerialization.data(withJSONObject: [
                      "jsonrpc": "2.0", "id": request["id"] ?? NSNull(), "result": result,
                  ] as [String: Any])
            else { return }
            var frame = withUnsafeBytes(of: UInt32(reply.count).bigEndian) { Data($0) }
            frame.append(reply)
            _ = frame.withUnsafeBytes { write(conn, $0.baseAddress, $0.count) }
        }
    }

    /// Stop listening, once any answer in flight has been sent.
    func stop() {
        answered.wait()
        close(listener)
        unlink(path)
    }

    /// `accept`, but give up after five seconds rather than hang the suite
    /// when the client never connects.
    private static func accept(_ listener: Int32) -> Int32 {
        var ready = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
        guard poll(&ready, 1, 5_000) == 1 else { return -1 }
        return Darwin.accept(listener, nil, nil)
    }

    private static func read(_ fd: Int32, count: Int) -> Data? {
        var data = Data(count: count)
        var received = 0
        while received < count {
            let n = data.withUnsafeMutableBytes { recv(fd, $0.baseAddress! + received, count - received, 0) }
            guard n > 0 else { return nil }
            received += n
        }
        return data
    }
}
