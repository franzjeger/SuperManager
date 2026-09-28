import XCTest
@testable import SuperManagerMac

final class TailscaleBinarySelectionTests: XCTestCase {
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

    // MARK: Validation memo

    private func makeExecutable(_ body: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("tailscale-memo-\(UUID().uuidString)")
        try body.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    func testVerdictIsProbedOncePerFileIdentity() throws {
        let memo = TailscaleClient.ValidationMemo()
        let bin = try makeExecutable("#!/bin/sh\nexit 0\n")
        var probes = 0
        for _ in 0..<5 {
            XCTAssertTrue(memo.verdict(for: bin) { _ in probes += 1; return true })
        }
        XCTAssertEqual(probes, 1, "an unchanged binary must not be re-executed")
    }

    func testReplacedBinaryIsProbedAgain() throws {
        let memo = TailscaleClient.ValidationMemo()
        let bin = try makeExecutable("#!/bin/sh\nexit 1\n")
        XCTAssertFalse(memo.verdict(for: bin) { _ in false })
        // An upgrade replaces the file: new inode/size/mtime, new verdict.
        try FileManager.default.removeItem(at: bin)
        try "#!/bin/sh\n# upgraded\nexit 0\n".write(to: bin, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bin.path)
        XCTAssertTrue(memo.verdict(for: bin) { _ in true })
    }

    func testInconclusiveProbeIsNotRemembered() throws {
        let memo = TailscaleClient.ValidationMemo()
        let bin = try makeExecutable("#!/bin/sh\nexit 0\n")
        XCTAssertFalse(memo.verdict(for: bin) { _ in nil }, "a timeout is not a pass")
        XCTAssertTrue(memo.verdict(for: bin) { _ in true }, "…nor a remembered failure")
    }

    func testMissingFileIsInvalidWithoutProbing() {
        let memo = TailscaleClient.ValidationMemo()
        let missing = URL(fileURLWithPath: "/nonexistent/tailscale-\(UUID().uuidString)")
        XCTAssertFalse(memo.verdict(for: missing) { _ in XCTFail("nothing to probe"); return true })
    }
}
