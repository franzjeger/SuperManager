import XCTest

@testable import SuperManagerMac

/// The backup dress rehearsal, exercised against real directories and a
/// real tar round-trip — the whole point of the feature is to catch a
/// broken archive, so the tests build broken archives.
final class BackupVerifyTests: XCTestCase {

    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("bv-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func write(_ name: String, _ content: String) throws {
        let url = dir.appendingPathComponent(name)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try content.write(to: url, atomically: true, encoding: .utf8)
    }

    func testHealthyDirectoryPasses() throws {
        try write("secrets.json",
                  #"{"vpn/abc/wg-private-key": "c2VjcmV0"}"#)
        try write("profiles/abc.toml", """
            id = "abc"
            [config]
            backend = "wire_guard"
            private_key = "vpn/abc/wg-private-key"
            """)
        let checks = BackupVerify.inspect(extracted: dir)
        XCTAssertTrue(checks.allSatisfy { $0.status == .pass },
                      "\(checks.map { "\($0.title): \($0.status)" })")
        XCTAssertTrue(checks.contains { $0.title == "Secret cross-reference" })
    }

    /// The invariant with teeth: a profile referencing a daemon-store
    /// secret the archive doesn't carry must FAIL the rehearsal — that
    /// is precisely the archive that breaks on restore.
    func testMissingWireGuardKeyFails() throws {
        try write("secrets.json", "{}")
        try write("profiles/abc.toml", """
            id = "abc"
            private_key = "vpn/abc/wg-private-key"
            """)
        let checks = BackupVerify.inspect(extracted: dir)
        let xref = checks.first { $0.title == "Secret cross-reference" }
        XCTAssertEqual(xref?.status, .fail)
        XCTAssertTrue(xref?.detail.contains("wg-private-key") == true)
    }

    /// Keychain-held credentials are NEVER in the archive on macOS, so
    /// an IKEv2 profile's password/psk refs must not be flagged — that
    /// would fail every single healthy backup.
    func testKeychainHeldRefsAreNotFlagged() throws {
        try write("secrets.json", "{}")
        try write("profiles/ike.toml", """
            id = "ike"
            password = "vpn/ike/password"
            psk = "vpn/ike/psk"
            """)
        let checks = BackupVerify.inspect(extracted: dir)
        XCTAssertEqual(checks.first { $0.title == "Secret cross-reference" }?.status, .pass)
    }

    func testCorruptSecretsJsonFails() throws {
        try write("secrets.json", "{ not json")
        let checks = BackupVerify.inspect(extracted: dir)
        XCTAssertEqual(checks.first { $0.title == "Secret store" }?.status, .fail)
    }

    func testZeroByteOvpnFails() throws {
        try write("secrets.json", "{}")
        try write("ovpn/x.ovpn", "")
        let checks = BackupVerify.inspect(extracted: dir)
        XCTAssertEqual(checks.first { $0.title == "OpenVPN configs" }?.status, .fail)
    }

    func testReferencedLabelExtraction() {
        let toml = """
            password = "vpn/a/password"
            private_key = "vpn/a/wg-private-key"
            other = "unifi/controller/xyz"
            """
        XCTAssertEqual(BackupVerify.referencedLabels(inProfileToml: toml),
                       ["vpn/a/password", "vpn/a/wg-private-key"])
    }

    /// Full round-trip through /usr/bin/tar — the same binary export
    /// uses — so the extract path is exercised, not just the inspection.
    func testTarRoundTrip() throws {
        try write("secrets.json", #"{"vpn/abc/wg-private-key": "yg=="}"#)
        try write("profiles/abc.toml", "id = \"abc\"\nprivate_key = \"vpn/abc/wg-private-key\"")
        let archive = FileManager.default.temporaryDirectory
            .appendingPathComponent("bv-\(UUID().uuidString).tar.gz")
        defer { try? FileManager.default.removeItem(at: archive) }

        let tar = Process()
        tar.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        tar.arguments = ["-czf", archive.path, "-C", dir.path, "."]
        try tar.run(); tar.waitUntilExit()
        XCTAssertEqual(tar.terminationStatus, 0)

        let report = BackupVerify.verify(archive: archive)
        XCTAssertEqual(report.worst, .pass,
                       "\(report.checks.map { "\($0.title): \($0.status) — \($0.detail)" })")
    }

    func testGarbageArchiveFailsExtraction() throws {
        let bogus = FileManager.default.temporaryDirectory
            .appendingPathComponent("bv-bogus-\(UUID().uuidString).tar.gz")
        try Data("not a tarball".utf8).write(to: bogus)
        defer { try? FileManager.default.removeItem(at: bogus) }
        XCTAssertEqual(BackupVerify.verify(archive: bogus).worst, .fail)
    }
}
