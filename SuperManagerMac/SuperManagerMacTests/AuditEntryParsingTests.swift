import XCTest

@testable import SuperManagerMac

/// Parsing tests for the SSH audit log.
///
/// The failure these guard against is quiet: a line that doesn't parse is
/// dropped, so a timestamp-format mismatch between the daemon writer and
/// this reader shows up as an audit pane that is simply empty — not as an
/// error anyone would notice.
final class AuditEntryParsingTests: XCTestCase {

    /// The format the daemon writes today.
    func testParsesSecondsPrecisionLine() {
        let line = "2026-03-28T14:30:00Z | PUSH | my-key | SHA256:abc "
            + "| webserver | 10.0.0.1:22 | OK"
        let entry = AuditEntry.parse(line: line, id: 0)

        XCTAssertNotNil(entry)
        XCTAssertEqual(entry?.action, .push)
        XCTAssertEqual(entry?.keyName, "my-key")
        XCTAssertEqual(entry?.hostLabel, "webserver")
        XCTAssertEqual(entry?.hostname, "10.0.0.1")
        XCTAssertEqual(entry?.port, 22)
        XCTAssertEqual(entry?.success, true)
    }

    /// Lines written before the daemon switched to seconds precision carry
    /// six fractional digits. They must still parse, or existing logs go
    /// blank the moment someone opens the pane.
    func testParsesMicrosecondTimestamp() {
        let line = "2026-07-28T16:41:18.026235+00:00 | GENERATE | k "
            + "| SHA256:abc |  | :0 | OK"
        let entry = AuditEntry.parse(line: line, id: 0)

        XCTAssertNotNil(entry, "microsecond timestamps must not drop the row")
        XCTAssertEqual(entry?.action, .generate)
        XCTAssertEqual(
            entry?.timestamp,
            AuditEntry.parseTimestamp("2026-07-28T16:41:18+00:00"),
            "stripping sub-second digits must not shift the instant"
        )
    }

    /// Millisecond precision with a `Z` designator — the other shape a
    /// chrono `%+` writer can emit.
    func testParsesMillisecondTimestampWithZulu() {
        XCTAssertNotNil(AuditEntry.parseTimestamp("2026-03-28T14:30:00.123Z"))
    }

    /// Key-lifecycle events have no host. The host:port field is `:0`, and
    /// splitting on the last colon has to yield an empty hostname, not nil.
    func testParsesKeyLifecycleLineWithoutHost() {
        let line = "2026-03-28T14:30:00Z | DELETE | my-key | SHA256:abc |  | :0 | OK"
        let entry = AuditEntry.parse(line: line, id: 0)

        XCTAssertNotNil(entry)
        XCTAssertEqual(entry?.hostname, "")
        XCTAssertEqual(entry?.port, 0)
        XCTAssertEqual(entry?.hostLabel, "")
    }

    /// IPv6 literals contain colons; the host:port split takes the last one.
    func testParsesIPv6Host() {
        let line = "2026-03-28T14:30:00Z | PUSH | k | SHA256:abc "
            + "| gw | fd00::1:2201 | OK"
        let entry = AuditEntry.parse(line: line, id: 0)

        XCTAssertEqual(entry?.hostname, "fd00::1")
        XCTAssertEqual(entry?.port, 2201)
    }

    func testFailureLineParsesAsUnsuccessful() {
        let line = "2026-03-28T14:30:00Z | REVOKE | k | SHA256:abc "
            + "| gw | 10.0.0.1:22 | FAIL"
        XCTAssertEqual(AuditEntry.parse(line: line, id: 0)?.success, false)
    }

    func testMalformedLinesAreRejected() {
        // Too few fields.
        XCTAssertNil(AuditEntry.parse(line: "2026-03-28T14:30:00Z | PUSH | k", id: 0))
        // Unparseable timestamp.
        XCTAssertNil(AuditEntry.parse(
            line: "not-a-date | PUSH | k | SHA256:abc | gw | 10.0.0.1:22 | OK", id: 0))
        // Unknown action.
        XCTAssertNil(AuditEntry.parse(
            line: "2026-03-28T14:30:00Z | FROBNICATE | k | SHA256:abc | gw | 10.0.0.1:22 | OK",
            id: 0))
        // Non-numeric port.
        XCTAssertNil(AuditEntry.parse(
            line: "2026-03-28T14:30:00Z | PUSH | k | SHA256:abc | gw | 10.0.0.1:ssh | OK", id: 0))
    }
}
