import Darwin
import Foundation

/// Bounded debug log in the user's private `~/Library/Logs/SuperManager/`
/// directory (mode `0700` dir, `0600` file, rotated at 10 MiB).
///
/// Never writes to world-readable `/tmp`. The unit-test host writes its own
/// `debug-tests.log` in the same directory so running tests never truncates
/// or mixes with a live app session's `debug.log`.
enum DebugLog {
    private static let maxBytes: UInt64 = 10 * 1024 * 1024

    static let logURL: URL = {
        let base = FileManager.default
            .urls(for: .libraryDirectory, in: .userDomainMask)
            .first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library")
        let dir = base.appendingPathComponent("Logs/SuperManager", isDirectory: true)
        let fileName = ProcessInfo.processInfo.isUnitTestHost ? "debug-tests.log" : "debug.log"
        return dir.appendingPathComponent(fileName, isDirectory: false)
    }()

    private static var didPrepare = false
    private static let lock = NSLock()
    private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// Ensure the private log directory (`0700`) and file (`0600`) exist and
    /// return `logURL` so Finder can reveal it even before the first log line.
    @discardableResult
    static func ensureFileExists() -> URL {
        lock.lock()
        defer { lock.unlock() }
        prepareLocked(truncateOnFirstLaunch: false)
        return logURL
    }

    /// Write a line, prefixed with an ISO-8601 millisecond timestamp.
    static func write(_ message: String) {
        lock.lock()
        defer { lock.unlock() }

        prepareLocked(truncateOnFirstLaunch: !didPrepare)
        didPrepare = true
        rotateIfNeededLocked()

        let timestamp = formatter.string(from: Date())
        let line = "[\(timestamp)] \(message)\n"
        guard let fd = openPrivateFileLocked(flags: O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW) else {
            return
        }
        defer { close(fd) }
        let bytes = Array(line.utf8)
        bytes.withUnsafeBytes { buf in
            guard let base = buf.baseAddress else { return }
            var written = 0
            while written < buf.count {
                let n = Darwin.write(fd, base + written, buf.count - written)
                if n > 0 {
                    written += n
                } else if n < 0 && errno == EINTR {
                    continue
                } else {
                    break
                }
            }
        }
    }

    private static func prepareLocked(truncateOnFirstLaunch: Bool) {
        let dir = logURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        _ = dir.path.withCString { Darwin.chmod($0, mode_t(0o700)) }

        var flags: Int32 = O_WRONLY | O_CREAT | O_NOFOLLOW
        if truncateOnFirstLaunch {
            flags |= O_TRUNC
        }
        if let fd = openPrivateFileLocked(flags: flags) {
            close(fd)
        }
    }

    private static func rotateIfNeededLocked() {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: logURL.path),
              let size = (attrs[.size] as? NSNumber)?.uint64Value,
              size >= maxBytes
        else { return }

        let rotated = logURL.appendingPathExtension("1")
        try? FileManager.default.removeItem(at: rotated)
        try? FileManager.default.moveItem(at: logURL, to: rotated)
        _ = rotated.path.withCString { Darwin.chmod($0, mode_t(0o600)) }
        if let fd = openPrivateFileLocked(flags: O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW) {
            close(fd)
        }
    }

    private static func openPrivateFileLocked(flags: Int32) -> Int32? {
        let fd = logURL.path.withCString { cPath in
            Darwin.open(cPath, flags, mode_t(0o600))
        }
        guard fd >= 0 else { return nil }
        _ = Darwin.fchmod(fd, mode_t(0o600))
        return fd
    }
}
