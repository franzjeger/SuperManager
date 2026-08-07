import XCTest

@testable import SuperManagerMac

/// The rule that stops the app pushing an older helper over a newer
/// one. Worth testing on its own: the failure it prevents is close to
/// invisible in the field — the file in /Library/PrivilegedHelperTools
/// is correct, `strings` confirms the fix is in it, and the fix still
/// isn't running because the process launchd respawned came from the
/// app bundle instead.
final class HelperRedeployGuardTests: XCTestCase {

    func testNewerBundledDeploys() {
        XCTAssertTrue(AppState.shouldRedeploy(bundled: 2000, deployed: 1000))
    }

    /// The regression: a helper hand-deployed from a fresh build is
    /// newer than the one embedded in the installed app.
    func testOlderBundledIsRefused() {
        XCTAssertFalse(AppState.shouldRedeploy(bundled: 1000, deployed: 2000))
    }

    /// Equal timestamps are the same build — redeploying achieves
    /// nothing and costs a daemon respawn.
    func testEqualTimestampsAreRefused() {
        XCTAssertFalse(AppState.shouldRedeploy(bundled: 1500, deployed: 1500))
    }

    /// A deployed helper too old to report a timestamp is exactly the
    /// stale case this mechanism exists to repair — deploy.
    func testUnknownDeployedDeploys() {
        XCTAssertTrue(AppState.shouldRedeploy(bundled: 1000, deployed: nil))
    }

    /// A bundled binary predating `--version` tells us nothing, and we
    /// only got here because the live helper was missing methods.
    func testUnknownBundledDeploys() {
        XCTAssertTrue(AppState.shouldRedeploy(bundled: nil, deployed: 1000))
    }

    func testBothUnknownDeploys() {
        XCTAssertTrue(AppState.shouldRedeploy(bundled: nil, deployed: nil))
    }
}
