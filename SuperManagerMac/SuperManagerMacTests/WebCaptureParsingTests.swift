import XCTest
@testable import SuperManagerMac

/// `WebCapture.from(url:)` parses a `supermgr://` deep link — the payload a
/// browser bookmarklet fires at the app to capture a device. It is one of the
/// few places SuperManager ingests fully untrusted, externally-shaped input,
/// so its contract (what it accepts, what it rejects, how it resolves
/// conflicting signals) deserves to be pinned rather than trusted.
final class WebCaptureParsingTests: XCTestCase {

    private func parse(_ s: String) -> WebCapture? {
        guard let url = URL(string: s) else { return nil }
        return WebCapture.from(url: url)
    }

    // MARK: scheme gating — reject anything not ours

    func testWrongSchemeIsRejected() {
        // A link that isn't supermgr:// must never be parsed, whatever it
        // carries — this is the gate on untrusted input.
        XCTAssertNil(parse("https://evil.example.com/?ip=10.0.0.1"))
        XCTAssertNil(parse("javascript://?ip=10.0.0.1"))
    }

    func testSchemeMatchIsCaseInsensitive() {
        XCTAssertNotNil(parse("SUPERMGR://capture?ip=10.0.0.1"))
    }

    // MARK: host resolution — required, with a precedence order

    func testMissingHostYieldsNil() {
        // No ip, no hostname, no source host = nothing to capture.
        XCTAssertNil(parse("supermgr://capture?label=Nothing"))
    }

    func testIpWinsOverHostnameAndSource() {
        let c = parse("supermgr://c?ip=10.0.0.5&hostname=box.local&source=https://9.9.9.9/")
        XCTAssertEqual(c?.hostname, "10.0.0.5", "explicit ip is the strongest host signal")
    }

    func testFallsBackToSourceHostWhenNoIpOrHostname() {
        let c = parse("supermgr://c?source=https://192.0.2.7:8443/admin/")
        XCTAssertEqual(c?.hostname, "192.0.2.7")
    }

    // MARK: port — explicit, then source URL, else nil

    func testExplicitPortParsed() {
        XCTAssertEqual(parse("supermgr://c?ip=10.0.0.5&port=2222")?.port, 2222)
    }

    func testPortFallsBackToSourceUrlPort() {
        XCTAssertEqual(parse("supermgr://c?ip=10.0.0.5&source=https://10.0.0.5:8443/")?.port, 8443)
    }

    func testGarbagePortIsDroppedNotCrashed() {
        // Out-of-range / non-numeric port must be ignored, not throw.
        XCTAssertNil(parse("supermgr://c?ip=10.0.0.5&port=99999")?.port)
        XCTAssertNil(parse("supermgr://c?ip=10.0.0.5&port=abc")?.port)
    }

    // MARK: device-type sniffing + username default

    func testVendorHintSetsDeviceTypeAndDefaultUsername() {
        let c = parse("supermgr://c?ip=10.0.0.5&vendor=fortigate")
        XCTAssertEqual(c?.deviceType, .fortigate)
        XCTAssertEqual(c?.username, "admin", "fortigate's default SSH username")
    }

    func testExplicitUsernameOverridesTheDeviceDefault() {
        let c = parse("supermgr://c?ip=10.0.0.5&vendor=fortigate&username=svc-admin")
        XCTAssertEqual(c?.username, "svc-admin")
    }

    func testVendorSniffedFromSourceUrlWhenNoHint() {
        // No explicit hint, but the source URL screams FortiGate.
        let c = parse("supermgr://c?ip=10.0.0.5&source=https://fortigate.corp.example/admin/")
        XCTAssertEqual(c?.deviceType, .fortigate)
    }

    // MARK: label — label, else title, else host

    func testLabelFallsBackToTitleThenHost() {
        XCTAssertEqual(parse("supermgr://c?ip=10.0.0.5&title=Edge%20FW")?.label, "Edge FW")
        XCTAssertEqual(parse("supermgr://c?ip=10.0.0.5")?.label, "10.0.0.5")
    }

    // MARK: percent-encoding is decoded

    func testPercentEncodedValuesAreDecoded() {
        let c = parse("supermgr://c?ip=10.0.0.5&label=Rack%20A%20%2F%20Core")
        XCTAssertEqual(c?.label, "Rack A / Core")
    }
}
