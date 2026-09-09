import XCTest

@testable import SuperManagerMac

final class TailscaleVersionTests: XCTestCase {
    func testNormalizesDaemonLongVersion() {
        XCTAssertEqual(
            TailscaleVersion.normalized("1.102.3-t53a0d659a\n  go version: go1.26.7\n"),
            "1.102.3"
        )
    }

    func testNewerMinorVersionWinsNumerically() {
        XCTAssertTrue(TailscaleVersion.isNewer("1.102.3", than: "1.96.4"))
        XCTAssertFalse(TailscaleVersion.isNewer("1.96.4", than: "1.102.3"))
    }

    func testEqualAndOlderBundlesDoNotTriggerUpdate() {
        XCTAssertFalse(TailscaleVersion.isNewer("1.102.3", than: "1.102.3"))
        XCTAssertFalse(TailscaleVersion.isNewer("1.100.0", than: "1.102.3"))
    }

    func testMissingOrMalformedVersionFailsClosed() {
        XCTAssertNil(TailscaleVersion.normalized("not-a-version"))
        XCTAssertFalse(TailscaleVersion.isNewer(nil, than: "1.96.4"))
        XCTAssertFalse(TailscaleVersion.isNewer("1.102.3", than: nil))
    }
}
