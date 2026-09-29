import XCTest

@testable import SuperManagerMac

/// The helper's event feed, which replaced scraping its log file. The
/// scraping never saw an auto-reconnect: the log colours each field name,
/// so `profile_id=` never occurred as one run of text.
final class HelperEventTests: XCTestCase {

    // MARK: - Wire form

    /// Exactly what `wire_form_is_what_the_app_reads` in the helper's
    /// `events.rs` produces. Change one, change both.
    private static let wireForm = """
        {"boot": "0c6e6d4a", "latest": 4, "events": [
          {"seq": 1, "at_ms": 1790000000000, "kind": "vpn_reconnected",
           "profile_id": "p1", "backend": "ikev2", "mode": "always_on"},
          {"seq": 2, "at_ms": 1790000001000, "kind": "vpn_reconnected",
           "profile_id": "p2", "backend": "wireguard", "mode": "route_guard"},
          {"seq": 3, "at_ms": 1790000002000, "kind": "vpn_reconnect_failing",
           "profile_id": "p1", "backend": "ikev2", "attempts": 3, "error": "charon refused"},
          {"seq": 4, "at_ms": 1790000003000, "kind": "connectivity_failed_open", "exit_node": true}
        ]}
        """

    private func batch(_ json: String) throws -> HelperEventBatch? {
        let object = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        return HelperEventBatch(try XCTUnwrap(object))
    }

    private func at(_ milliseconds: Double) -> Date {
        Date(timeIntervalSince1970: milliseconds / 1000)
    }

    func testReadsEveryKindTheHelperSends() throws {
        XCTAssertEqual(try batch(Self.wireForm), HelperEventBatch(
            next: HelperEventCursor(boot: "0c6e6d4a", seq: 4),
            events: [
                HelperEvent(seq: 1, at: at(1_790_000_000_000),
                            kind: .vpnReconnected(profileId: "p1", routesOnly: false)),
                HelperEvent(seq: 2, at: at(1_790_000_001_000),
                            kind: .vpnReconnected(profileId: "p2", routesOnly: true)),
                HelperEvent(seq: 3, at: at(1_790_000_002_000),
                            kind: .vpnReconnectFailing(profileId: "p1", attempts: 3, error: "charon refused")),
                HelperEvent(seq: 4, at: at(1_790_000_003_000),
                            kind: .connectivityFailedOpen(exitNode: true)),
            ]))
    }

    /// A newer helper may send kinds this build has never heard of. They are
    /// skipped, and the cursor still moves past them; otherwise every poll
    /// would ask for them again.
    func testSkipsUnknownKindsButMovesPastThem() throws {
        let b = try XCTUnwrap(batch("""
            {"boot": "b", "latest": 7, "events": [
              {"seq": 6, "at_ms": 1, "kind": "something_new", "detail": 1},
              {"seq": 7, "at_ms": 2, "kind": "connectivity_failed_open", "exit_node": false}
            ]}
            """))
        XCTAssertEqual(b.events.map(\.seq), [7])
        XCTAssertEqual(b.next, HelperEventCursor(boot: "b", seq: 7))
    }

    func testAnAnswerWithoutABootIsNotABatch() throws {
        XCTAssertNil(try batch(#"{"latest": 1, "events": []}"#))
    }

    func testTheCursorSurvivesARelaunch() throws {
        let suite = "HelperEventTests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        XCTAssertNil(HelperEventCursor.load(from: defaults))
        HelperEventCursor(boot: "b", seq: 42).save(to: defaults)
        XCTAssertEqual(HelperEventCursor.load(from: defaults), HelperEventCursor(boot: "b", seq: 42))
    }

    // MARK: - What becomes a notification

    private let opened = Date(timeIntervalSince1970: 1_000_000)

    private func event(_ kind: HelperEvent.Kind, secondsAfterOpening seconds: TimeInterval) -> HelperEvent {
        HelperEvent(seq: 1, at: opened.addingTimeInterval(seconds), kind: kind)
    }

    /// What happened while the app was closed is history, not news.
    func testEventsFromBeforeTheAppOpenedAreNotNotified() {
        var inbox = HelperEventInbox(openedAt: opened)
        XCTAssertFalse(inbox.shouldNotify(
            event(.connectivityFailedOpen(exitNode: false), secondsAfterOpening: -1)))
        XCTAssertFalse(inbox.shouldNotify(
            event(.vpnReconnected(profileId: "p1", routesOnly: false), secondsAfterOpening: -3600)))
        XCTAssertTrue(inbox.shouldNotify(
            event(.connectivityFailedOpen(exitNode: false), secondsAfterOpening: 0)))
    }

    /// A flapping tunnel reconnects every 30 s: one notification a minute per
    /// profile, and one profile's quiet minute does not mute another.
    func testAtMostOneReconnectNotificationPerProfilePerMinute() {
        var inbox = HelperEventInbox(openedAt: opened)
        let p1 = HelperEvent.Kind.vpnReconnected(profileId: "p1", routesOnly: false)
        let p2 = HelperEvent.Kind.vpnReconnected(profileId: "p2", routesOnly: true)

        XCTAssertTrue(inbox.shouldNotify(event(p1, secondsAfterOpening: 10)))
        XCTAssertFalse(inbox.shouldNotify(event(p1, secondsAfterOpening: 40)))
        XCTAssertTrue(inbox.shouldNotify(event(p2, secondsAfterOpening: 41)))
        XCTAssertTrue(inbox.shouldNotify(event(p1, secondsAfterOpening: 70)))
    }

    /// The helper reports a failing run once and fails open once per outage,
    /// so neither is held back here.
    func testFailingAndFailOpenEventsAreAlwaysNews() {
        var inbox = HelperEventInbox(openedAt: opened)
        let failing = HelperEvent.Kind.vpnReconnectFailing(profileId: "p1", attempts: 3, error: "x")
        XCTAssertTrue(inbox.shouldNotify(event(failing, secondsAfterOpening: 1)))
        XCTAssertTrue(inbox.shouldNotify(event(failing, secondsAfterOpening: 2)))
        XCTAssertTrue(inbox.shouldNotify(event(.connectivityFailedOpen(exitNode: true), secondsAfterOpening: 3)))
    }

    // MARK: - Activity log

    func testActivityNamesTheProfileAndWhatCameBack() {
        let name = { (id: String) in id == "p1" ? "Office" : id }

        let whole = event(.vpnReconnected(profileId: "p1", routesOnly: false), secondsAfterOpening: 0)
            .activity(name: name)
        XCTAssertEqual(whole.profileId, "p1")
        XCTAssertEqual(whole.kind, .autoReconnectFired)
        XCTAssertEqual(whole.message, "Always-on watchdog restored Office")

        let routes = event(.vpnReconnected(profileId: "p1", routesOnly: true), secondsAfterOpening: 0)
            .activity(name: name)
        XCTAssertEqual(routes.message, "Restored Office's missing full-tunnel routes")
    }

    /// The row is one line; a backend's stderr is several.
    func testFailingReasonIsFlattenedToOneLine() {
        let entry = event(
            .vpnReconnectFailing(profileId: "p1", attempts: 3, error: "initiate failed:\nno response\n"),
            secondsAfterOpening: 0
        ).activity { _ in "Office" }
        XCTAssertEqual(entry.kind, .connectFailed)
        XCTAssertEqual(
            entry.message,
            "Always-on failed to reconnect Office 3 times in a row: initiate failed: no response")
    }

    /// A helper event arrives a poll late, or hours late after the app was
    /// closed. The log stays in time order all the same.
    func testActivityLogKeepsTimeOrderAndItsCap() {
        func entry(_ seconds: TimeInterval, _ message: String) -> ActivityLog.Event {
            ActivityLog.Event(profileId: nil, kind: .panicReset, message: message,
                              timestamp: Date(timeIntervalSince1970: seconds))
        }
        var events = [entry(10, "a"), entry(30, "c")]
        ActivityLog.insert(entry(20, "b"), into: &events, cap: 10)
        ActivityLog.insert(entry(30, "c2"), into: &events, cap: 10)
        ActivityLog.insert(entry(5, "first"), into: &events, cap: 10)
        XCTAssertEqual(events.map(\.message), ["first", "a", "b", "c", "c2"])

        ActivityLog.insert(entry(40, "d"), into: &events, cap: 3)
        XCTAssertEqual(events.map(\.message), ["c", "c2", "d"])
    }
}
