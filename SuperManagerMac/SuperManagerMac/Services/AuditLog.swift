import Foundation

/// Reads the daemon's SSH audit log from disk.
///
/// The log lives at `~/Library/Application Support/SuperManager/ssh-audit.log`
/// (matching `supermgr_engine::ssh::audit::audit_log_path`). Both the
/// daemon and this GUI run as the same user, so reading directly is
/// fine — there's no need to plumb an RPC for what amounts to "tail an
/// append-only text file." Audit entries are already public-by-design
/// (no secrets, just metadata about who-did-what-where).
///
/// `loadAll(maxLines:)` is intentionally simple: read the whole file,
/// keep the last `maxLines`, parse each, drop malformed entries. For
/// the volumes we expect (one entry per SSH operation, sorted) this is
/// fine. If the log ever grows pathological we can switch to a
/// streaming reader.
enum AuditLog {
    /// Path to the audit log file. Public so the UI can show it for
    /// "Reveal in Finder" / copy-path diagnostics.
    static var path: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base
            .appendingPathComponent("SuperManager", isDirectory: true)
            .appendingPathComponent("ssh-audit.log")
    }

    /// Read up to `maxLines` most-recent entries. Newest first (we
    /// reverse the file order so the UI doesn't need a `.reversed()`
    /// in the view body).
    static func loadAll(maxLines: Int = 5000) -> [AuditEntry] {
        guard let text = try? String(contentsOf: path, encoding: .utf8) else {
            return []
        }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true)
        let trimmed = lines.suffix(maxLines)
        var out: [AuditEntry] = []
        out.reserveCapacity(trimmed.count)
        for (i, line) in trimmed.enumerated() {
            if let entry = AuditEntry.parse(line: String(line), id: i) {
                out.append(entry)
            }
        }
        // Newest first — daemon writes append-only, so the LAST line
        // is the most recent event.
        return out.reversed()
    }

    /// File modification date — used by the view to know when to
    /// auto-refresh. `nil` if the file doesn't exist yet.
    static func modificationDate() -> Date? {
        try? FileManager.default
            .attributesOfItem(atPath: path.path)[.modificationDate] as? Date
    }
}
