import XCTest

@testable import SuperManagerMac

/// Connect must bring Tailscale up without touching the user's settings.
final class TailscaleConnectTests: XCTestCase {
    /// `--reset` reset every unnamed setting to its default on each Connect.
    func testConnectKeepsTheUsersSettings() {
        XCTAssertEqual(TailscaleClient.upArguments, ["up"])
    }
}
