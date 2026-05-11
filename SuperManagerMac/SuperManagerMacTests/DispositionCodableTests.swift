import XCTest
@testable import SuperManagerMac

/// Codable round-trip tests for `Disposition`.
///
/// `Disposition` is the most schema-drift-sensitive type in the
/// Mac↔daemon protocol: the Rust side uses
/// `#[serde(tag = "kind", rename_all = "snake_case")]` and the
/// Swift side hand-rolls the decoder. A drift here silently
/// downgrades every finding to `.open` and corrupts the entire
/// remediation timeline.
///
/// These tests lock in the wire format both directions.
final class DispositionCodableTests: XCTestCase {
    // MARK: - decode (daemon → app)

    func testDecodeOpen() throws {
        let json = #"{"kind":"open"}"#
        let d = try JSONDecoder.daemon.decode(Disposition.self, from: Data(json.utf8))
        if case .open = d { /* ok */ } else { XCTFail("expected .open, got \(d)") }
    }

    func testDecodeAcceptedRiskWithReasonAndUntil() throws {
        // Daemon emits ISO-8601 with offset for `until`.
        let json = #"""
        {"kind":"accepted_risk","reason":"vendor patches next month","until":"2026-06-01T00:00:00Z"}
        """#
        let d = try JSONDecoder.daemon.decode(Disposition.self, from: Data(json.utf8))
        guard case .acceptedRisk(let reason, let until) = d else {
            XCTFail("expected .acceptedRisk, got \(d)")
            return
        }
        XCTAssertEqual(reason, "vendor patches next month")
        XCTAssertNotNil(until)
    }

    func testDecodeAcceptedRiskWithoutUntilLeavesItNil() throws {
        // Some accepted-risk dispositions are untimed ("permanent
        // accept" until explicitly reviewed). The encoder skips
        // `until` in that case — the decoder must accept missing.
        let json = #"{"kind":"accepted_risk","reason":"permanent"}"#
        let d = try JSONDecoder.daemon.decode(Disposition.self, from: Data(json.utf8))
        guard case .acceptedRisk(let reason, let until) = d else {
            XCTFail("expected .acceptedRisk")
            return
        }
        XCTAssertEqual(reason, "permanent")
        XCTAssertNil(until)
    }

    func testDecodeFixedAutoTrue() throws {
        // `auto:true` means the engine inferred the fix from a
        // clean re-scan; `auto:false` means an operator marked it.
        // The Severity / Critical filter in the UI cares about
        // this distinction.
        let json = #"{"kind":"fixed","auto":true}"#
        let d = try JSONDecoder.daemon.decode(Disposition.self, from: Data(json.utf8))
        guard case .fixed(let auto) = d else {
            XCTFail("expected .fixed")
            return
        }
        XCTAssertTrue(auto)
    }

    func testDecodeFixedAutoFalse() throws {
        let json = #"{"kind":"fixed","auto":false}"#
        let d = try JSONDecoder.daemon.decode(Disposition.self, from: Data(json.utf8))
        guard case .fixed(let auto) = d else {
            XCTFail("expected .fixed")
            return
        }
        XCTAssertFalse(auto)
    }

    func testDecodeFalsePositive() throws {
        let json = #"{"kind":"false_positive","reason":"intentional banner"}"#
        let d = try JSONDecoder.daemon.decode(Disposition.self, from: Data(json.utf8))
        guard case .falsePositive(let reason) = d else {
            XCTFail("expected .falsePositive")
            return
        }
        XCTAssertEqual(reason, "intentional banner")
    }

    func testDecodeUnknownKindFallsBackToOpen() throws {
        // Schema drift: daemon shipped a new disposition kind the
        // app doesn't know. Spec: log + fall back to `.open` rather
        // than crash. Without this fallback every new finding
        // type would fail the entire findings_list RPC.
        let json = #"{"kind":"quarantined","reason":"sandboxed"}"#
        let d = try JSONDecoder.daemon.decode(Disposition.self, from: Data(json.utf8))
        if case .open = d { /* ok */ } else {
            XCTFail("unknown kind should degrade to .open, got \(d)")
        }
    }

    // MARK: - encode (app → daemon)

    func testEncodeOpen() throws {
        let data = try JSONEncoder.daemon.encode(Disposition.open)
        let dict = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(dict["kind"] as? String, "open")
        XCTAssertEqual(dict.count, 1, "encoder must not emit extra keys for .open")
    }

    func testEncodeAcceptedRiskWithoutUntilOmitsKey() throws {
        let d = Disposition.acceptedRisk(reason: "ok", until: nil)
        let data = try JSONEncoder.daemon.encode(d)
        let dict = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(dict["kind"] as? String, "accepted_risk")
        XCTAssertEqual(dict["reason"] as? String, "ok")
        XCTAssertNil(dict["until"], "nil until must be omitted, not encoded as null")
    }

    func testEncodeFixedAutoTrue() throws {
        let data = try JSONEncoder.daemon.encode(Disposition.fixed(auto: true))
        let dict = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(dict["kind"] as? String, "fixed")
        XCTAssertEqual(dict["auto"] as? Bool, true)
    }

    func testEncodeFalsePositive() throws {
        let data = try JSONEncoder.daemon.encode(Disposition.falsePositive(reason: "by design"))
        let dict = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(dict["kind"] as? String, "false_positive")
        XCTAssertEqual(dict["reason"] as? String, "by design")
    }

    // MARK: - round-trip (the actual schema-drift guard)

    func testRoundTripPreservesAllVariants() throws {
        let cases: [Disposition] = [
            .open,
            .acceptedRisk(reason: "r", until: nil),
            .acceptedRisk(reason: "r", until: Date(timeIntervalSince1970: 1_800_000_000)),
            .fixed(auto: true),
            .fixed(auto: false),
            .falsePositive(reason: "fp"),
        ]
        for c in cases {
            let data = try JSONEncoder.daemon.encode(c)
            let back = try JSONDecoder.daemon.decode(Disposition.self, from: data)
            XCTAssertEqual(c.label, back.label,
                           "round-trip changed label for \(c)")
        }
    }

    // MARK: - label() — surface in the Findings list

    func testLabelMatchesVariant() {
        XCTAssertEqual(Disposition.open.label, "Open")
        XCTAssertEqual(Disposition.acceptedRisk(reason: "", until: nil).label, "Accepted risk")
        XCTAssertEqual(Disposition.fixed(auto: true).label, "Fixed")
        XCTAssertEqual(Disposition.falsePositive(reason: "").label, "False positive")
    }
}

// MARK: - Test helpers

/// JSON coders configured the same way the live RPC client does —
/// `iso8601` dates match the daemon's `chrono::DateTime<Utc>`
/// serialisation.
extension JSONDecoder {
    static var daemon: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}

extension JSONEncoder {
    static var daemon: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }
}
