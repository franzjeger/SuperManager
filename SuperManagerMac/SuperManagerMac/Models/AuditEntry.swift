import Foundation

/// A single line in the SSH audit log, mirroring the Rust
/// `supermgr_core::ssh::audit::AuditEntry`.
///
/// On-disk format is pipe-delimited so it's grep-friendly:
///
///     2026-05-09T11:24:33+00:00 | PUSH | my-key | SHA256:abc… | webserver | 10.0.0.1:22 | OK
///
/// Older entries with bad timestamps or truncated lines parse to `nil`
/// and are skipped — we don't fail the whole view because one line is
/// corrupt.
struct AuditEntry: Identifiable, Hashable {
    enum Action: String, CaseIterable {
        case push     = "PUSH"
        case revoke   = "REVOKE"
        case generate = "GENERATE"
        case `import` = "IMPORT"
        case delete   = "DELETE"
        case connect  = "CONNECT"

        var icon: String {
            switch self {
            case .push:     return "arrow.up.circle"
            case .revoke:   return "minus.circle"
            case .generate: return "key.horizontal"
            case .import:   return "tray.and.arrow.down"
            case .delete:   return "trash"
            case .connect:  return "terminal"
            }
        }
    }

    /// Stable id for SwiftUI list diffing — index in the parsed file.
    /// (Two entries with the same timestamp + action + host are
    /// genuinely the same event from the user's perspective; we don't
    /// need a UUID.)
    let id: Int
    let timestamp: Date
    let action: Action
    let keyName: String
    let keyFingerprint: String
    let hostLabel: String
    let hostname: String
    let port: UInt16
    let success: Bool

    /// Parse a single audit-log line. Returns `nil` for malformed input.
    static func parse(line: String, id: Int) -> AuditEntry? {
        let parts = line.split(separator: "|", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count == 7 else { return nil }

        // RFC3339 with offset (`%+` chrono format) — ISO8601DateFormatter
        // is what we want here, with both internet-date-time and
        // fractional seconds disabled (Rust's `%+` doesn't emit them).
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        guard let ts = formatter.date(from: parts[0]) else { return nil }

        guard let action = Action(rawValue: parts[1]) else { return nil }

        // host:port — split on the LAST colon, since IPv6 may contain colons.
        let hostport = parts[5]
        guard let lastColon = hostport.lastIndex(of: ":") else { return nil }
        let hostname = String(hostport[..<lastColon])
        let portString = String(hostport[hostport.index(after: lastColon)...])
        guard let port = UInt16(portString) else { return nil }

        let success = parts[6] == "OK"

        return AuditEntry(
            id: id,
            timestamp: ts,
            action: action,
            keyName: parts[2],
            keyFingerprint: parts[3],
            hostLabel: parts[4],
            hostname: hostname,
            port: port,
            success: success
        )
    }
}
