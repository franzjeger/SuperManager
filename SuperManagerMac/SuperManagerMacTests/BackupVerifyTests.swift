import CryptoKit
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

    func testEncryptedBackupRoundTripAndWrongPasswordPreservesDataDir() throws {
        // Build an AES-256-GCM v2 secrets.json matching Rust's FileSecretStore::with_master_key.
        let masterKey = Data(repeating: 0x42, count: 32)
        let innerJson = Data(#"{"vpn/abc/wg-private-key":"c2VjcmV0"}"#.utf8)
        let nonceBytes = Data((0..<12).map(UInt8.init))
        let sealedSecrets = try CryptoKit.AES.GCM.seal(
            innerJson,
            using: CryptoKit.SymmetricKey(data: masterKey),
            nonce: try CryptoKit.AES.GCM.Nonce(data: nonceBytes),
            authenticating: Data("supermanager-secrets-v2".utf8)
        )
        var ctAndTag = Data(sealedSecrets.ciphertext)
        ctAndTag.append(sealedSecrets.tag)
        let envelope = """
        {
          "version": 2,
          "cipher": "aes-256-gcm",
          "nonce": "\(nonceBytes.base64EncodedString())",
          "ciphertext": "\(ctAndTag.base64EncodedString())"
        }
        """
        try write("secrets.json", envelope)
        try write("profiles/abc.toml", """
            id = "abc"
            [config]
            backend = "wire_guard"
            private_key = "vpn/abc/wg-private-key"
            """)

        // Inspecting v2 secrets.json directly with masterKey passes cross-reference.
        let directChecks = BackupVerify.inspect(extracted: dir, masterKey: masterKey)
        XCTAssertTrue(directChecks.allSatisfy { $0.status == .pass })

        let archive = FileManager.default.temporaryDirectory
            .appendingPathComponent("bv-enc-\(UUID().uuidString).tar.gz.enc")
        let restoredDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("bv-restored-\(UUID().uuidString)", isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: archive)
            try? FileManager.default.removeItem(at: restoredDir)
        }

        // Weak password must be refused.
        XCTAssertThrowsError(try Backup.export(
            to: archive,
            password: "short",
            iterations: 2_000,
            sourceDir: dir,
            masterKey: masterKey
        ))

        try Backup.export(
            to: archive,
            password: "CorrectHorseBatteryStaple!",
            iterations: 2_000,
            sourceDir: dir,
            masterKey: masterKey
        )
        XCTAssertTrue(Backup.isEncryptedArchive(archive))

        // Verify fails without/wrong password and passes with right password.
        XCTAssertEqual(BackupVerify.verify(archive: archive).worst, .fail)
        XCTAssertEqual(BackupVerify.verify(archive: archive, password: "wrong-password").worst, .fail)
        XCTAssertEqual(BackupVerify.verify(archive: archive, password: "CorrectHorseBatteryStaple!").worst, .pass)

        // Populate existing targetDir and confirm wrong password leaves it completely untouched.
        try FileManager.default.createDirectory(at: restoredDir, withIntermediateDirectories: true)
        let sentinel = restoredDir.appendingPathComponent("keep.txt")
        try "existing-state".write(to: sentinel, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try Backup.restore(
            from: archive,
            password: "wrong-password",
            targetDir: restoredDir
        ))
        XCTAssertEqual(try String(contentsOf: sentinel, encoding: .utf8), "existing-state")

        // Correct password restores unwrapped secrets.json + profiles cleanly.
        try Backup.restore(
            from: archive,
            password: "CorrectHorseBatteryStaple!",
            targetDir: restoredDir
        )
        let restoredSecrets = try Data(contentsOf: restoredDir.appendingPathComponent("secrets.json"))
        let decoded = try JSONDecoder().decode([String: String].self, from: restoredSecrets)
        XCTAssertEqual(decoded["vpn/abc/wg-private-key"], "c2VjcmV0")
    }
}
