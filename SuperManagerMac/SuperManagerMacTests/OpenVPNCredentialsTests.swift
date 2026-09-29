import XCTest

@testable import SuperManagerMac

/// A profile that asks for a username and password, and has none stored,
/// is stopped before OpenVPN gives up on it with a terminal prompt.
final class OpenVPNCredentialsTests: XCTestCase {
    func testAPlainAuthUserPassAsks() {
        XCTAssertTrue(OpenVPNCredentials.areAsked(in: "client\nauth-user-pass\nverb 3\n"))
        XCTAssertTrue(OpenVPNCredentials.areAsked(in: "client\r\n  --auth-user-pass # login\r\n"))
    }

    func testCredentialsInlineOrNoDirectiveDoNotAsk() {
        XCTAssertFalse(OpenVPNCredentials.areAsked(in: "client\nauth-user-pass\n<auth-user-pass>\nuser\npass\n</auth-user-pass>\n"))
        XCTAssertFalse(OpenVPNCredentials.areAsked(in: "client\nauth-user-pass [inline]\n<auth-user-pass>\nuser\npass\n</auth-user-pass>\n"))
        XCTAssertFalse(OpenVPNCredentials.areAsked(in: "client\ndev tun\n<cert>\nMIIB\n</cert>\n"))
    }

    /// Comments and the text inside key blocks are not directives.
    func testCommentsAndBlockTextDoNotAsk() {
        XCTAssertFalse(OpenVPNCredentials.areAsked(in: "client\n# auth-user-pass\n; auth-user-pass\n"))
        XCTAssertFalse(OpenVPNCredentials.areAsked(in: "client\n<ca>\nauth-user-pass\n</ca>\n"))
    }
}
