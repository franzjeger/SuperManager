import XCTest
@testable import SuperManagerMac

final class TailscaleBinarySelectionTests: XCTestCase {
    func testConcurrentBinaryRefreshPreservesCacheOwnership() {
        let cache = TailscaleClient.BinaryCache()
        let initial = URL(fileURLWithPath: "/Example.app/Contents/Resources/tailscale-bin/0")
        XCTAssertEqual(cache.resolve { _ in initial }, initial)
        // Each resolution reads and replaces the previous value, just like
        // the overlapping status/prefs/profile refreshes in the app.
        DispatchQueue.concurrentPerform(iterations: 1_000) { _ in
            _ = cache.resolve { previous in
                let count = Int(previous!.lastPathComponent)!
                return previous!.deletingLastPathComponent().appendingPathComponent(String(count + 1))
            }
        }
        XCTAssertEqual(cache.resolve { $0 }?.lastPathComponent, "1000")
    }

    private let native = TailscaleClient.nativeAppBinaryPath
    private let bundled = "/Example.app/Contents/Resources/tailscale-bin/tailscale"
    private let brew = "/opt/homebrew/bin/tailscale"

    func testManagedServiceWinsOverNativeAppAndHomebrew() {
        let available = Set([native, bundled, brew])
        let selected = TailscaleClient.resolveBinary(
            bundledPath: bundled, cached: nil,
            isExecutable: { available.contains($0) }, validate: { _ in true })
        XCTAssertEqual(selected?.path, bundled)
    }

    func testInstallingNativeAppDoesNotSwitchManagedIdentity() {
        let available = Set([native, bundled])
        let selected = TailscaleClient.resolveBinary(
            bundledPath: bundled, cached: URL(fileURLWithPath: bundled),
            isExecutable: { available.contains($0) }, validate: { _ in true })
        XCTAssertEqual(selected?.path, bundled)
    }

    func testRemovedNativeAppDoesNotLeaveStaleCachedCLI() {
        let selected = TailscaleClient.resolveBinary(
            bundledPath: bundled, cached: URL(fileURLWithPath: native),
            isExecutable: { $0 == self.bundled }, validate: { _ in true })
        XCTAssertEqual(selected?.path, bundled)
    }

    func testBrokenNativeBinaryFallsBackToWorkingBundledCLI() {
        let selected = TailscaleClient.resolveBinary(
            bundledPath: bundled, cached: nil,
            isExecutable: { _ in true }, validate: { $0.path == self.bundled })
        XCTAssertEqual(selected?.path, bundled)
    }

    func testHomebrewStillWorksWithoutNativeAppOrBundledCLI() {
        let selected = TailscaleClient.resolveBinary(
            bundledPath: nil, cached: nil,
            isExecutable: { $0 == self.brew }, validate: { _ in true })
        XCTAssertEqual(selected?.path, brew)
    }

    func testMissingBinariesDoNotReturnCachedPath() {
        let selected = TailscaleClient.resolveBinary(
            bundledPath: nil, cached: URL(fileURLWithPath: native),
            isExecutable: { _ in false }, validate: { _ in XCTFail("Cannot execute a missing binary"); return true })
        XCTAssertNil(selected)
    }

    func testManagedCLIReplacesCachedNativeFallback() {
        let selected = TailscaleClient.resolveBinary(
            bundledPath: bundled, cached: URL(fileURLWithPath: native),
            isExecutable: { _ in true }, validate: { _ in true })
        XCTAssertEqual(selected?.path, bundled)
    }

    func testNativeAppRemainsFallbackWhenNoManagedCLIExists() {
        let selected = TailscaleClient.resolveBinary(
            bundledPath: nil, cached: nil,
            isExecutable: { $0 == self.native }, validate: { _ in true })
        XCTAssertEqual(selected?.path, native)
    }

    func testManagedCommandsAlwaysAddressTheManagedSocket() {
        for args in [["status", "--json"], ["login"], ["set", "--accept-dns=true"], ["down"]] {
            XCTAssertEqual(TailscaleClient.commandArguments(bin: URL(fileURLWithPath: bundled), args: args),
                           ["--socket=/var/run/tailscaled.socket"] + args)
            XCTAssertEqual(TailscaleClient.commandArguments(bin: URL(fileURLWithPath: native), args: args), args)
        }
    }
}
