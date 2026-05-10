import Foundation

/// Compact ring-buffer of per-profile + global events. Surfaced
/// in the VPN detail view so the user can see "what just
/// happened" — when did the tunnel go up, did auto-reconnect
/// kick in, was kill-switch installed, did the user click
/// disconnect themselves.
///
/// Persisted to `~/Library/Application Support/SuperManager/
/// activity.json` so the log survives app restart but not OS
/// reboot (deliberate — events older than the boot window are
/// rarely useful and we don't want this file growing forever).
///
/// Bounded at 200 events globally; older entries are dropped on
/// each `record(...)` call. Per-profile filter happens at read
/// time.
@MainActor
final class ActivityLog {
    static let shared = ActivityLog()

    /// Enum-tagged event kinds. Adding a new kind doesn't break
    /// older logs because we serialise the raw string and the
    /// view layer just renders unknown kinds with a generic icon.
    enum Kind: String, Codable {
        case connectStarted
        case connectSucceeded
        case connectFailed
        case disconnectRequested
        case disconnectComplete
        case autoReconnectFired
        case killSwitchEngaged
        case killSwitchReleased
        case forceDisconnect
        case panicReset
    }

    struct Event: Codable, Identifiable {
        let id: UUID
        let timestamp: Date
        let profileId: String?  // nil = global event (e.g. panic reset)
        let kind: Kind
        let message: String     // free-form one-line description

        init(profileId: String?, kind: Kind, message: String) {
            self.id = UUID()
            self.timestamp = Date()
            self.profileId = profileId
            self.kind = kind
            self.message = message
        }
    }

    private static let maxEvents = 200
    private static let storageURL: URL = {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first!
            .appendingPathComponent("SuperManager", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: base, withIntermediateDirectories: true)
        return base.appendingPathComponent("activity.json")
    }()

    private(set) var events: [Event] = []

    private init() {
        load()
    }

    /// Append a new event + persist. Trims oldest if over the cap.
    func record(profileId: String?, kind: Kind, message: String) {
        let ev = Event(profileId: profileId, kind: kind, message: message)
        events.append(ev)
        if events.count > Self.maxEvents {
            events.removeFirst(events.count - Self.maxEvents)
        }
        persist()
    }

    /// Filter to a specific profile, newest first. Used by the
    /// VPN detail view's "Recent activity" section.
    func events(for profileId: String) -> [Event] {
        events.filter { $0.profileId == profileId }.reversed()
    }

    func clear(profileId: String? = nil) {
        if let pid = profileId {
            events.removeAll { $0.profileId == pid }
        } else {
            events.removeAll()
        }
        persist()
    }

    private func load() {
        guard let data = try? Data(contentsOf: Self.storageURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        if let arr = try? decoder.decode([Event].self, from: data) {
            events = arr
        }
    }

    private func persist() {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(events) {
            try? data.write(to: Self.storageURL, options: .atomic)
        }
    }
}

extension ActivityLog.Kind {
    /// SF Symbol name for each event kind.
    var symbol: String {
        switch self {
        case .connectStarted:      return "play.circle"
        case .connectSucceeded:    return "checkmark.circle.fill"
        case .connectFailed:       return "xmark.circle.fill"
        case .disconnectRequested: return "stop.circle"
        case .disconnectComplete:  return "stop.circle.fill"
        case .autoReconnectFired:  return "arrow.clockwise.circle.fill"
        case .killSwitchEngaged:   return "lock.shield.fill"
        case .killSwitchReleased:  return "lock.open"
        case .forceDisconnect:     return "exclamationmark.triangle.fill"
        case .panicReset:          return "tornado"
        }
    }
}
