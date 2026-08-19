import XCTest

@testable import SuperManagerMac

/// Decoding of `tailscale switch --list --json`, pinned to the real
/// output shape so a future Tailscale field rename is caught here rather
/// than as an empty switcher in the UI.
final class TailscaleProfileTests: XCTestCase {

    func testDecodesRealSwitchListJSON() throws {
        // Verbatim shape from `tailscale switch --list --json`, extended
        // with a second (work) tailnet.
        let json = """
        [
          {"id":"bbb1","nickname":"franzjeger@gmail.com","tailnet":"franzjeger@gmail.com","account":"franzjeger@gmail.com","selected":true},
          {"id":"a2c9","nickname":"","tailnet":"sybr.no","account":"frank@sybr.no","selected":false}
        ]
        """
        let profiles = try JSONDecoder().decode([TailscaleProfile].self, from: Data(json.utf8))
        XCTAssertEqual(profiles.count, 2)
        XCTAssertEqual(profiles[0].id, "bbb1")
        XCTAssertTrue(profiles[0].selected)
        XCTAssertEqual(profiles[1].tailnet, "sybr.no")
        XCTAssertFalse(profiles[1].selected)
    }

    func testEmptyListDecodes() throws {
        let profiles = try JSONDecoder().decode([TailscaleProfile].self, from: Data("[]".utf8))
        XCTAssertTrue(profiles.isEmpty)
    }

    /// An empty nickname falls back to the account; the tailnet is shown
    /// only when it differs, so a personal tailnet (tailnet == account)
    /// does not read as "me@x.com — me@x.com".
    func testDisplayNameFallbackAndDedup() {
        let personal = TailscaleProfile(
            id: "1", nickname: "", tailnet: "me@x.com", account: "me@x.com", selected: true)
        XCTAssertEqual(personal.displayName, "me@x.com")

        let work = TailscaleProfile(
            id: "2", nickname: "", tailnet: "sybr.no", account: "frank@sybr.no", selected: false)
        XCTAssertEqual(work.displayName, "frank@sybr.no — sybr.no")

        let nicknamed = TailscaleProfile(
            id: "3", nickname: "Work", tailnet: "sybr.no", account: "frank@sybr.no", selected: false)
        XCTAssertEqual(nicknamed.displayName, "Work — sybr.no")
    }
}
