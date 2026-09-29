import XCTest

@testable import SuperManagerMac

/// Whether the installed tailscaled is the one the app bundles. The app
/// offers an update, which restarts the service, only when it is not.
final class TailscaledOutdatedTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tailscaled-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func file(_ name: String, _ contents: String) throws -> String {
        let url = directory.appendingPathComponent(name)
        try contents.write(to: url, atomically: true, encoding: .utf8)
        return url.path
    }

    func testTheBundledDaemonIsNotOutdated() async throws {
        let bundled = try file("bundled", "tailscaled 1.102.4")
        let installed = try file("installed", "tailscaled 1.102.4")
        let outdated = await AppState.differsFromBundled(installed: installed, bundled: bundled)
        XCTAssertFalse(outdated)
    }

    func testAnotherDaemonIsOutdated() async throws {
        let bundled = try file("bundled", "tailscaled 1.102.4")
        let installed = try file("installed", "tailscaled 1.86.2")
        let outdated = await AppState.differsFromBundled(installed: installed, bundled: bundled)
        XCTAssertTrue(outdated)
    }

    /// No installed daemon, or a build without one bundled: nothing to offer.
    func testNothingToCompareIsNotOutdated() async throws {
        let bundled = try file("bundled", "tailscaled 1.102.4")
        let noneInstalled = await AppState.differsFromBundled(installed: nil, bundled: bundled)
        let noneBundled = await AppState.differsFromBundled(installed: bundled, bundled: nil)
        XCTAssertFalse(noneInstalled)
        XCTAssertFalse(noneBundled)
    }
}
