import Foundation

/// Just enough of a daemon for the socket tests: a listening Unix socket
/// that serves one connection per `serve(_:)`, on a background queue, in
/// the length-prefixed JSON-RPC framing both real daemons use.
final class FakeDaemon {
    enum Behavior {
        /// Read the request and reply with `result`.
        case answer(String)
        /// Read the request, then hang up without replying: a daemon that
        /// died mid-call, after it may have acted.
        case hangUpAfterRequest
        /// Read the request and never reply, until `stop()`.
        case stall
        /// Accept and close at once, before reading anything.
        case drop
        /// Read the request, then announce a reply of this many bytes.
        case announce(UInt32)
    }

    private let path: String
    private let listener: Int32
    private let workers = DispatchGroup()
    private let stopping = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var requestsRead = 0

    /// Requests read to the end so far.
    var requests: Int {
        lock.lock()
        defer { lock.unlock() }
        return requestsRead
    }

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

    /// Serve the next connection with `behavior`.
    func serve(_ behavior: Behavior) {
        workers.enter()
        DispatchQueue.global().async { [self] in
            defer { workers.leave() }
            let conn = Self.accept(listener)
            guard conn >= 0 else { return }
            defer { close(conn) }
            if case .drop = behavior { return }
            guard let request = Self.readRequest(conn) else { return }
            lock.lock()
            requestsRead += 1
            lock.unlock()
            switch behavior {
            case .answer(let result):
                guard let reply = try? JSONSerialization.data(withJSONObject: [
                    "jsonrpc": "2.0", "id": request["id"] ?? NSNull(), "result": result,
                ] as [String: Any]) else { return }
                Self.write(conn, Self.header(UInt32(reply.count)) + reply)
            case .announce(let length):
                Self.write(conn, Self.header(length))
            case .stall:
                stopping.wait()
            case .hangUpAfterRequest, .drop:
                break
            }
        }
    }

    /// True if a client connects within `window`: how a test tells that a
    /// failed call was not sent a second time.
    func sawConnection(within window: Duration) -> Bool {
        var ready = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
        let (seconds, attoseconds) = window.components
        return poll(&ready, 1, Int32(seconds * 1000 + attoseconds / 1_000_000_000_000_000)) == 1
    }

    /// Stop listening, releasing a stalled reply, once every worker is done.
    func stop() {
        stopping.signal()
        close(listener)
        unlink(path)
        workers.wait()
    }

    /// `accept`, but give up after five seconds rather than hang the suite
    /// when the client never connects. The connection must not raise
    /// SIGPIPE either: a reply to a client that gave up would end the run.
    private static func accept(_ listener: Int32) -> Int32 {
        var ready = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
        guard poll(&ready, 1, 5_000) == 1 else { return -1 }
        let conn = Darwin.accept(listener, nil, nil)
        var on: Int32 = 1
        if conn >= 0 { setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size)) }
        return conn
    }

    private static func readRequest(_ fd: Int32) -> [String: Any]? {
        guard let header = read(fd, count: 4) else { return nil }
        let length = header.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
        guard let body = read(fd, count: Int(length)) else { return nil }
        return (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
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

    private static func header(_ length: UInt32) -> Data {
        withUnsafeBytes(of: length.bigEndian) { Data($0) }
    }

    private static func write(_ fd: Int32, _ data: Data) {
        _ = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    }
}
