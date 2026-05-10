import Foundation

/// Append-only debug log to a fixed file path. Used while iterating
/// on tricky timing bugs where `print` and `NSLog` either don't
/// flush or get swallowed by the system log stream.
///
/// Path: `/tmp/supermanager-debug.log`. Cleared on every app start
/// so stale logs from previous launches don't confuse readings.
enum DebugLog {
    private static let path = "/tmp/supermanager-debug.log"
    private static var didTruncate = false
    private static let lock = NSLock()

    /// Write a line, prefixed with a millisecond timestamp.
    static func write(_ message: String) {
        lock.lock()
        defer { lock.unlock() }

        if !didTruncate {
            try? "".write(toFile: path, atomically: true, encoding: .utf8)
            didTruncate = true
        }

        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        let line = "[\(formatter.string(from: Date()))] \(message)\n"
        if let handle = try? FileHandle(forWritingTo: URL(fileURLWithPath: path)) {
            try? handle.seekToEnd()
            try? handle.write(contentsOf: Data(line.utf8))
            try? handle.close()
        }
    }
}
