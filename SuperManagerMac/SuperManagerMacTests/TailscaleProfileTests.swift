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

    // MARK: - CLI failures

    /// `tailscale switch` to a tailnet that has not approved this Mac, as
    /// the app logged it: the only stderr line is the version warning, and
    /// showing it made a missing approval read as a broken daemon.
    func testVersionWarningIsNotTheReasonACommandFailed() {
        let warning = "Warning: client version \"1.104.5-t73a48057a\" != tailscaled server version \"1.102.4-tbbcd7d1fc\"\n"
        XCTAssertEqual(
            TailscaleClient.failureMessage(
                stderr: warning, stdout: "Switching to account \"a0e9\"\n", exitCode: 1),
            "Switching to account \"a0e9\"")
        XCTAssertEqual(
            TailscaleClient.failureMessage(
                stderr: warning + "profile not found\n", stdout: "ignored", exitCode: 1),
            "profile not found")
        XCTAssertEqual(
            TailscaleClient.failureMessage(stderr: warning, stdout: "\n", exitCode: 3),
            "tailscale exited with status 3 and said nothing")
    }

    /// A switch that landed on the profile is not reported as failed, even
    /// when the CLI exited non-zero because the profile cannot connect yet.
    func testOnlyASwitchThatDidNotHappenIsAnError() {
        let profiles = [
            TailscaleProfile(id: "a0e9", nickname: "", tailnet: "sybr.no", account: "f@sybr.no", selected: true),
            TailscaleProfile(id: "741e", nickname: "", tailnet: "hub", account: "hub", selected: false),
        ]
        XCTAssertTrue(AppState.isActiveProfile("a0e9", in: profiles))
        XCTAssertFalse(AppState.isActiveProfile("741e", in: profiles))
        XCTAssertFalse(AppState.isActiveProfile("gone", in: profiles))
    }

    @MainActor
    func testRemovalWarningSaysWhetherTheConnectionGoes() {
        let active = TailscaleProfile(id: "1", nickname: "", tailnet: "t", account: "a", selected: true)
        let other = TailscaleProfile(id: "2", nickname: "", tailnet: "t", account: "b", selected: false)
        XCTAssertTrue(TailscaleHeaderView.removalWarning(for: active).contains("disconnects"))
        XCTAssertTrue(TailscaleHeaderView.removalWarning(for: other).contains("not affected"))
    }
}
