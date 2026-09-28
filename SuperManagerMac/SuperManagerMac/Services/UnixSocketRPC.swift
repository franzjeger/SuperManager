import Foundation

/// One exchange of the length-prefixed JSON-RPC that both of the app's
/// daemons speak, `supermgrd-mac` (`ServiceClient`) and the privileged
/// helper (`HelperClient`): a 4-byte big-endian length, then that many bytes
/// of JSON, one request and one reply on a fresh connection.
///
/// Every exchange is held to one absolute deadline. The socket is
/// non-blocking and every wait is a `poll()` bounded by the time left, so no
/// syscall can outlive the budget however the peer misbehaves (accepts and
/// goes silent, or trickles bytes). The blocking I/O runs on `ioQueue`, never
/// on the Swift cooperative pool: a wedged peer would otherwise park one pool
/// thread per call in flight, and a handful of pollers would starve every
/// other task in the app.
enum UnixSocketRPC {
    /// Why an exchange failed, and whether the request got out. A peer parses
    /// nothing until it has the whole frame, so a request that was not
    /// completely written cannot have run: the only kind a caller may send
    /// again.
    struct Failure: Error, CustomStringConvertible {
        enum Kind: Equatable {
            /// No socket at the path, or nothing accepting on it.
            case unreachable
            /// The deadline passed.
            case timedOut
            /// The reply announced more bytes than the caller accepts.
            case replyTooLarge(UInt32)
            /// Any other socket failure, including a peer that hung up.
            case io
        }

        let kind: Kind
        let requestSent: Bool
        let description: String
    }

    /// Where one exchange must be finished by. A `nil` budget waits as long
    /// as the peer takes, for work that scales with its input: any fixed
    /// ceiling would report a legitimate long run as a failure.
    struct Deadline: Sendable {
        let method: String
        let budget: Duration?
        let instant: ContinuousClock.Instant?

        init(method: String, budget: Duration?) {
            self.method = method
            self.budget = budget
            instant = budget.map { .now + $0 }
        }
    }

    private static let ioQueue = DispatchQueue(
        label: "com.sybr.supermanager.socket-rpc", qos: .userInitiated, attributes: .concurrent)

    /// Send `body` as one frame to the peer at `path` and return its reply
    /// frame. Throws `Failure` for everything that went wrong on the socket.
    static func roundTrip(path: String, body: Data, deadline: Deadline, maxReply: UInt32) async throws -> Data {
        var frame = Data(capacity: 4 + body.count)
        withUnsafeBytes(of: UInt32(body.count).bigEndian) { frame.append(contentsOf: $0) }
        frame.append(body)
        return try await withCheckedThrowingContinuation { continuation in
            ioQueue.async {
                continuation.resume(with: Result {
                    try exchange(path: path, frame: frame, deadline: deadline, maxReply: maxReply)
                })
            }
        }
    }

    /// Throws unless something accepts connections at `path`. The listen
    /// backlog lives in the kernel, so this says nothing about whether the
    /// process behind it will answer.
    static func probe(path: String) throws {
        close(try connectSocket(path: path))
    }

    private static func exchange(path: String, frame: Data, deadline: Deadline, maxReply: UInt32) throws -> Data {
        let fd = try connectSocket(path: path)
        defer { close(fd) }
        try writeAll(fd: fd, data: frame, deadline: deadline)
        // From here on the peer has the whole request and may be running it.
        do {
            let header = try readExact(fd: fd, count: 4, deadline: deadline)
            let length = header.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
            guard length <= maxReply else {
                throw Failure(kind: .replyTooLarge(length), requestSent: true,
                              description: "reply of \(length) bytes exceeds the \(maxReply)-byte limit")
            }
            return try readExact(fd: fd, count: Int(length), deadline: deadline)
        } catch let failure as Failure {
            throw Failure(kind: failure.kind, requestSent: true, description: failure.description)
        }
    }

    private static func connectSocket(path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw Failure(kind: .io, requestSent: false, description: "socket(): errno=\(errno)")
        }
        // A peer that exits mid-exchange must come back as EPIPE, not as a
        // SIGPIPE that terminates the whole app: nothing here ignores it.
        var on: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            let e = errno
            close(fd)
            throw Failure(kind: .io, requestSent: false, description: "setsockopt(SO_NOSIGPIPE): errno=\(e)")
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let sunPathCap = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < sunPathCap else {
            close(fd)
            throw Failure(kind: .io, requestSent: false, description: "socket path too long: \(path)")
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
        // AF_UNIX connect() never blocks on macOS: it either lands in the
        // listen backlog or fails at once (ECONNREFUSED when the backlog is
        // full or nobody listens).
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                connect(fd, sp, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0 {
            let e = errno
            close(fd)
            let kind: Failure.Kind = (e == ENOENT || e == ECONNREFUSED) ? .unreachable : .io
            throw Failure(kind: kind, requestSent: false, description: "connect(\(path)): errno=\(e)")
        }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            let e = errno
            close(fd)
            throw Failure(kind: .io, requestSent: false, description: "fcntl(O_NONBLOCK): errno=\(e)")
        }
        return fd
    }

    private static func writeAll(fd: Int32, data: Data, deadline: Deadline) throws {
        try data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> Void in
            var written = 0
            while written < data.count {
                let n = write(fd, buf.baseAddress! + written, data.count - written)
                if n > 0 {
                    written += n
                    continue
                }
                let e = errno
                if n < 0 && e == EINTR { continue }
                guard n < 0 && (e == EAGAIN || e == EWOULDBLOCK) else {
                    throw Failure(kind: .io, requestSent: false, description: "write(): errno=\(e)")
                }
                try waitUntilReady(fd: fd, events: Int16(POLLOUT), deadline: deadline)
            }
        }
    }

    private static func readExact(fd: Int32, count: Int, deadline: Deadline) throws -> Data {
        var data = Data(count: count)
        guard count > 0 else { return data }
        try data.withUnsafeMutableBytes { (buf: UnsafeMutableRawBufferPointer) -> Void in
            var got = 0
            while got < count {
                let n = read(fd, buf.baseAddress! + got, count - got)
                if n > 0 {
                    got += n
                    continue
                }
                if n == 0 {
                    throw Failure(kind: .io, requestSent: true, description: "peer closed the connection mid-reply")
                }
                let e = errno
                if e == EINTR { continue }
                guard e == EAGAIN || e == EWOULDBLOCK else {
                    throw Failure(kind: .io, requestSent: true, description: "read(): errno=\(e)")
                }
                try waitUntilReady(fd: fd, events: Int16(POLLIN), deadline: deadline)
            }
        }
        return data
    }

    /// Wait for `events` on `fd` until the call's deadline. Readiness includes
    /// hang-up and error; the read or write that follows reports which. The
    /// `requestSent` on a timeout here is corrected by `exchange` once the
    /// frame is out.
    private static func waitUntilReady(fd: Int32, events: Int16, deadline: Deadline) throws {
        while true {
            var milliseconds: Int32 = -1
            if let instant = deadline.instant, let budget = deadline.budget {
                let left = ContinuousClock.now.duration(to: instant)
                guard left > .zero else {
                    throw Failure(kind: .timedOut, requestSent: false,
                                  description: "\(deadline.method) got no answer within \(budget)")
                }
                let (seconds, attoseconds) = left.components
                milliseconds = Int32(clamping: seconds * 1000 + attoseconds / 1_000_000_000_000_000 + 1)
            }
            var pfd = pollfd(fd: fd, events: events, revents: 0)
            let rc = poll(&pfd, 1, milliseconds)
            if rc > 0 { return }
            if rc < 0 && errno != EINTR {
                throw Failure(kind: .io, requestSent: false, description: "poll(): errno=\(errno)")
            }
            // Timed out or interrupted: the loop re-checks the deadline.
        }
    }
}
