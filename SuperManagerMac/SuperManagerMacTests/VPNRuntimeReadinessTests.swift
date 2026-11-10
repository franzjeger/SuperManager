import XCTest
@testable import SuperManagerMac

@MainActor
final class VPNRuntimeReadinessTests: XCTestCase {
    private let executable = "/Library/PrivilegedHelperTools/SuperManagerVPN/openvpn3"

    func testAProtectedExecutableAndItsParentsAreReady() {
        XCTAssertTrue(Dependencies.hasRootOwnedParents(executable) { _ in
            [.ownerAccountID: NSNumber(value: 0), .posixPermissions: NSNumber(value: 0o755)]
        })
    }

    func testARootOwnedExecutableInAUserOwnedDirectoryNeedsRepair() {
        XCTAssertFalse(Dependencies.hasRootOwnedParents(executable) { path in
            [.ownerAccountID: NSNumber(value: path.hasSuffix("SuperManagerVPN") ? 501 : 0),
             .posixPermissions: NSNumber(value: 0o755)]
        })
    }

    func testWritableOrUnreadableParentsNeedRepair() {
        XCTAssertFalse(Dependencies.hasRootOwnedParents(executable) { path in
            [.ownerAccountID: NSNumber(value: 0),
             .posixPermissions: NSNumber(value: path == "/Library" ? 0o775 : 0o755)]
        })
        XCTAssertFalse(Dependencies.hasRootOwnedParents(executable) { _ in
            throw CocoaError(.fileReadNoPermission)
        })
    }

    func testAUserOwnedSymlinkToAProtectedExecutableNeedsRepair() throws {
        guard getuid() != 0 else { throw XCTSkip("Requires an unprivileged test user") }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vpn-runtime-readiness-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let link = directory.appendingPathComponent("openvpn3")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/usr/bin/true")
        XCTAssertTrue(Dependencies.isRootOwnedExecutable("/usr/bin/true"))
        XCTAssertFalse(Dependencies.isRootOwnedExecutable(link.path))
    }

    func testOrdinaryOpenVPNCanUseVersionThreeButAzureCannotUseVersionTwo() {
        XCTAssertTrue(Dependencies.hasProtectedOpenVPN(requireOpenVPN3: false) { $0 == executable })
        XCTAssertTrue(Dependencies.hasProtectedOpenVPN(requireOpenVPN3: true) { $0 == executable })
        let versionTwo = "/Library/PrivilegedHelperTools/SuperManagerVPN/openvpn"
        XCTAssertTrue(Dependencies.hasProtectedOpenVPN(requireOpenVPN3: false) { $0 == versionTwo })
        XCTAssertFalse(Dependencies.hasProtectedOpenVPN(requireOpenVPN3: true) { $0 == versionTwo })
        XCTAssertFalse(Dependencies.hasProtectedOpenVPN(requireOpenVPN3: false) { _ in false })
    }

    func testOrdinaryProfilesCanInstallBundledVersionThreeWithoutHomebrew() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vpn-runtime-bundle-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let versionThree = directory.appendingPathComponent("openvpn3")
        try "#!/bin/sh\n".write(to: versionThree, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: versionThree.path)
        XCTAssertTrue(Dependencies.hasBundledRuntime(for: "openvpn", directory: directory.path))
        XCTAssertTrue(Dependencies.hasBundledRuntime(for: "openvpn3", directory: directory.path))
        try FileManager.default.moveItem(at: versionThree, to: directory.appendingPathComponent("openvpn"))
        XCTAssertTrue(Dependencies.hasBundledRuntime(for: "openvpn", directory: directory.path))
        XCTAssertFalse(Dependencies.hasBundledRuntime(for: "openvpn3", directory: directory.path))
    }
}
