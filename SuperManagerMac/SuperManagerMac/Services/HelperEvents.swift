import Foundation

/// Something the helper did on its own: auto-reconnect replayed a tunnel or
/// keeps failing to, or the connectivity watchdog failed egress open.
///
/// Read with `HelperClient.eventsSince`. It replaces scraping the helper's
/// log file for phrases, which never once saw a reconnect: the log colours
/// each field name, so `profile_id=` never occurred as one run of text. The
/// wire form is pinned by `wire_form_is_what_the_app_reads` in the helper's
/// `events.rs` and by `HelperEventTests` here.
struct HelperEvent: Equatable {
    let seq: UInt64
    let at: Date
    let kind: Kind

    enum Kind: Equatable {
        /// Auto-reconnect brought a profile back. `routesOnly`: it was
        /// connected by hand and only its full-tunnel routes had gone
        /// missing; an Always-on profile comes back whole.
        case vpnReconnected(profileId: String, routesOnly: Bool)
        /// An Always-on profile failed to reconnect `attempts` times in a
        /// row. The helper reports this once per run of failures.
        case vpnReconnectFailing(profileId: String, attempts: Int, error: String)
        /// The connectivity watchdog ran panic_reset after a sustained
        /// outage. `exitNode`: it moved egress off a dead Tailscale exit
        /// node onto the local network.
        case connectivityFailedOpen(exitNode: Bool)
    }
}

/// How far the app has read in the helper's event list. `boot` changes when
/// the helper restarts, and the new helper answers an old cursor with
/// everything it holds.
struct HelperEventCursor: Codable, Equatable {
    let boot: String
    let seq: UInt64

    static let defaultsKey = "helperEventCursor"

    static func load(from defaults: UserDefaults = .standard) -> HelperEventCursor? {
        defaults.data(forKey: defaultsKey).flatMap { try? JSONDecoder().decode(Self.self, from: $0) }
    }

    func save(to defaults: UserDefaults = .standard) {
        guard let data = try? JSONEncoder().encode(self) else { return }
        defaults.set(data, forKey: Self.defaultsKey)
    }
}

/// One `events_since` answer.
struct HelperEventBatch: Equatable {
    /// The cursor to ask with next time. It moves past every event,
    /// including kinds this build does not know and skips.
    let next: HelperEventCursor
    let events: [HelperEvent]

    /// Decode an `events_since` result; nil if it is not one.
    init?(_ result: [String: Any]) {
        guard let boot = result["boot"] as? String,
              let latest = result["latest"] as? UInt64,
              let raw = result["events"] as? [[String: Any]] else { return nil }
        next = HelperEventCursor(boot: boot, seq: latest)
        events = raw.compactMap(HelperEvent.init)
    }

    init(next: HelperEventCursor, events: [HelperEvent]) {
        self.next = next
        self.events = events
    }
}

extension HelperEvent {
    /// Decode one entry of `events_since`'s `events`; nil for a kind this
    /// build does not know, which a newer helper may send.
    init?(_ raw: [String: Any]) {
        guard let seq = raw["seq"] as? UInt64,
              let atMs = raw["at_ms"] as? UInt64,
              let kind = raw["kind"] as? String else { return nil }
        let profileId = raw["profile_id"] as? String
        switch kind {
        case "vpn_reconnected":
            guard let profileId, let mode = raw["mode"] as? String else { return nil }
            self.kind = .vpnReconnected(profileId: profileId, routesOnly: mode == "route_guard")
        case "vpn_reconnect_failing":
            guard let profileId, let attempts = raw["attempts"] as? Int else { return nil }
            self.kind = .vpnReconnectFailing(
                profileId: profileId, attempts: attempts, error: raw["error"] as? String ?? "")
        case "connectivity_failed_open":
            guard let exitNode = raw["exit_node"] as? Bool else { return nil }
            self.kind = .connectivityFailedOpen(exitNode: exitNode)
        default:
            return nil
        }
        self.seq = seq
        self.at = Date(timeIntervalSince1970: Double(atMs) / 1000)
    }

    /// The activity-log entry for this event. `name` turns a profile id into
    /// what the user calls it.
    func activity(name: (String) -> String) -> (profileId: String?, kind: ActivityLog.Kind, message: String) {
        switch kind {
        case let .vpnReconnected(profileId, routesOnly):
            return (profileId, .autoReconnectFired, routesOnly
                ? "Restored \(name(profileId))'s missing full-tunnel routes"
                : "Always-on watchdog restored \(name(profileId))")
        case let .vpnReconnectFailing(profileId, attempts, error):
            // One line: the row shows one, and a backend's stderr has several.
            let reason = error.split(whereSeparator: \.isNewline).joined(separator: " ")
            return (profileId, .connectFailed,
                    "Always-on failed to reconnect \(name(profileId)) \(attempts) times in a row: \(reason)")
        case .connectivityFailedOpen(exitNode: false):
            return (nil, .panicReset, "Connectivity watchdog fired")
        case .connectivityFailedOpen(exitNode: true):
            return (nil, .panicReset,
                    "Connectivity watchdog fired: the exit node stopped forwarding, so traffic went direct")
        }
    }
}

/// Which of the helper's events become notifications.
///
/// Every event goes in the activity log; a notification is for news. Pure,
/// so the rules are tested without a helper, a notification centre or a
/// wall clock.
struct HelperEventInbox {
    /// Events from before this happened while the app was closed. They go in
    /// the activity log with the time they happened. As notifications they
    /// would be old news, and replaying a log as news is how one outage once
    /// became a dozen "Connectivity watchdog fired" alerts.
    let openedAt: Date

    /// A tunnel that flaps reconnects every 30 s; one notification a minute
    /// per profile says so without drowning everything else.
    static let reconnectNoticeInterval: TimeInterval = 60

    private var lastReconnectNotice: [String: Date] = [:]

    init(openedAt: Date) {
        self.openedAt = openedAt
    }

    /// Whether `event` should also be a notification. Remembers the ones it
    /// lets through.
    mutating func shouldNotify(_ event: HelperEvent) -> Bool {
        guard event.at >= openedAt else { return false }
        guard case let .vpnReconnected(profileId, _) = event.kind else { return true }
        if let last = lastReconnectNotice[profileId],
           event.at.timeIntervalSince(last) < Self.reconnectNoticeInterval {
            return false
        }
        lastReconnectNotice[profileId] = event.at
        return true
    }
}
