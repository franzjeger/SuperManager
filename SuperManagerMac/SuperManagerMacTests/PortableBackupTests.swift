import XCTest
import Security

@testable import SuperManagerMac

/// The Keychain/file-store split: which secret labels the app must route
/// to the macOS Keychain on import (and read from it on export) versus
/// hand to the engine. Getting this wrong either strands IKEv2/OpenVPN
/// passwords (they'd never reach the Keychain the connect path reads) or
/// misfiles a WireGuard key.
final class PortableBackupTests: XCTestCase {

    func testKeychainBoundLabels() {
        let id = "8bff563e-1111-2222-3333-444455556666"
        XCTAssertTrue(PortableBackup.isKeychainLabel("vpn/\(id)/password"))
        XCTAssertTrue(PortableBackup.isKeychainLabel("vpn/\(id)/psk"))
        XCTAssertTrue(PortableBackup.isKeychainLabel("vpn/\(id)/ovpn-username"))
        XCTAssertTrue(PortableBackup.isKeychainLabel("vpn/\(id)/ovpn-password"))
    }

    /// WireGuard material shares the `vpn/` prefix but lives in the
    /// engine's file store, not the Keychain. Must NOT be captured.
    func testWireGuardLabelsAreNotKeychainBound() {
        let id = "8bff563e-1111-2222-3333-444455556666"
        XCTAssertFalse(PortableBackup.isKeychainLabel("vpn/\(id)/wg-private-key"))
        XCTAssertFalse(PortableBackup.isKeychainLabel("vpn/\(id)/wg-psk-0"))
    }

    func testNonVpnLabelsAreNotKeychainBound() {
        XCTAssertFalse(PortableBackup.isKeychainLabel("ssh/host/abc/password"))
        XCTAssertFalse(PortableBackup.isKeychainLabel("supermgr/ssh/host/abc/certificate"))
        XCTAssertFalse(PortableBackup.isKeychainLabel("unifi/controller/xyz"))
        XCTAssertFalse(PortableBackup.isKeychainLabel(""))
    }

    func testRequiredMissingCredentialMakesExportIncomplete() throws {
        let result = try export(config: ["backend": "forti_gate",
                                         "password": "vpn/test/password", "psk": "vpn/test/psk"]) { account in
            if account.hasSuffix("/psk") { return Data("group-key".utf8) }
            throw VPNKeychain.KeychainError.osStatus(errSecItemNotFound, "not found")
        }
        XCTAssertEqual(result.unreadable, ["vpn/test/password"])
        XCTAssertEqual(result.incompleteProfiles, ["Office VPN"])
        let secrets = try exportedSecrets(result)
        XCTAssertNotNil(secrets["vpn/test/psk"])
        XCTAssertNil(secrets["vpn/test/password"])
    }

    func testWireGuardNeverReadsKeychainSlots() throws {
        let result = try export(config: ["backend": "wire_guard", "private_key": "vpn/test/wg-private-key"]) { _ in
            XCTFail("WireGuard's credentials belong to the engine")
            throw VPNKeychain.KeychainError.osStatus(errSecAuthFailed, "denied")
        }
        XCTAssertTrue(result.unreadable.isEmpty)
    }

    func testCertificateOnlyOpenVPNDoesNotWarnAboutUnusedSlots() throws {
        let result = try export(config: ["backend": "open_vpn", "config_file": "/test.ovpn"],
                                openVPN: "client\nremote vpn.example.com\n") { _ in
            throw VPNKeychain.KeychainError.osStatus(errSecItemNotFound, "not found")
        }
        XCTAssertTrue(result.unreadable.isEmpty)
    }

    func testDeniedOptionalOpenVPNAccountsWarnAboutUnreadableLegacyCredentials() throws {
        let result = try export(config: ["backend": "open_vpn", "config_file": "/test.ovpn"],
                                openVPN: "client\nremote vpn.example.com\n") { _ in
            throw VPNKeychain.KeychainError.osStatus(errSecAuthFailed, "denied")
        }
        XCTAssertEqual(Set(result.unreadable), ["vpn/test/ovpn-username", "vpn/test/ovpn-password"])
        XCTAssertEqual(result.incompleteProfiles, ["Office VPN"])
        XCTAssertTrue(result.unverifiedProfiles.isEmpty)
    }

    func testUnavailableOpenVPNConfigWarnsWithoutInventingMissingCredentials() throws {
        let result = try export(config: ["backend": "open_vpn", "config_file": "/missing.ovpn"]) { _ in
            throw VPNKeychain.KeychainError.osStatus(errSecItemNotFound, "not found")
        }
        XCTAssertTrue(result.unreadable.isEmpty)
        XCTAssertTrue(result.incompleteProfiles.isEmpty)
        XCTAssertEqual(result.unverifiedProfiles, ["Office VPN"])
    }

    func testUnverifiedOpenVPNProfileStillReportsKnownMissingCredential() throws {
        let result = try export(config: ["backend": "open_vpn", "config_file": "/missing.ovpn",
                                         "password": "vpn/test/ovpn-password"]) { _ in
            throw VPNKeychain.KeychainError.osStatus(errSecItemNotFound, "not found")
        }
        XCTAssertEqual(result.unreadable, ["vpn/test/ovpn-password"])
        XCTAssertEqual(result.incompleteProfiles, ["Office VPN"])
        XCTAssertEqual(result.unverifiedProfiles, ["Office VPN"])
    }

    func testMacOpenVPNAuthDirectiveRequiresCredentialsWithoutSecretRefs() throws {
        let result = try export(config: ["backend": "open_vpn", "config_file": "/test.ovpn"],
                                openVPN: "client\nauth-user-pass\n") { _ in
            throw VPNKeychain.KeychainError.osStatus(errSecItemNotFound, "not found")
        }
        XCTAssertEqual(Set(result.unreadable), ["vpn/test/ovpn-username", "vpn/test/ovpn-password"])
        XCTAssertEqual(result.incompleteProfiles, ["Office VPN"])
    }

    func testStoredLegacyOpenVPNAccountsAreStillExported() throws {
        let result = try export(config: ["backend": "open_vpn"]) { account in
            Data(account.utf8)
        }
        let secrets = try exportedSecrets(result)
        XCTAssertNotNil(secrets["vpn/test/ovpn-username"])
        XCTAssertNotNil(secrets["vpn/test/ovpn-password"])
        XCTAssertTrue(result.unreadable.isEmpty)
        XCTAssertEqual(result.unverifiedProfiles, ["Office VPN"])
    }

    func testAccessDeniedWarnsAndDoesNotDropOtherCredentials() throws {
        let result = try export(config: ["backend": "forti_gate", "password": "vpn/test/password"]) { _ in
            throw VPNKeychain.KeychainError.osStatus(errSecAuthFailed, "denied")
        }
        XCTAssertEqual(result.unreadable, ["vpn/test/password"])
    }

    func testExpectedLabelsUseRealSecretRefsOnly() {
        XCTAssertEqual(PortableBackup.expectedKeychainLabels(config: [
            "backend": "open_vpn", "username": "alice", "password": "vpn/test/ovpn-password",
        ]), ["vpn/test/ovpn-password"])
        XCTAssertTrue(PortableBackup.expectedKeychainLabels(config: nil).isEmpty)
        XCTAssertTrue(PortableBackup.expectedKeychainLabels(config: ["psk": "vpn/test/wg-psk-0"]).isEmpty)
    }

    func testAuthDirectiveDoesNotMistakeCommentsOrCredentialFilesForKeychainUse() {
        XCTAssertFalse(PortableBackup.requiresOpenVPNKeychainCredentials("# auth-user-pass\n;auth-user-pass\n"))
        XCTAssertFalse(PortableBackup.requiresOpenVPNKeychainCredentials("auth-user-pass /etc/credentials\n"))
        XCTAssertTrue(PortableBackup.requiresOpenVPNKeychainCredentials("  auth-user-pass # login\n"))
    }

    private func export(
        config: [String: Any], openVPN: String? = nil,
        read: (String) throws -> Data
    ) throws -> PortableBackup.ExportResult {
        try PortableBackup.completeExport(
            root: ["version": 1, "profiles": [["id": "test", "name": "Office VPN", "config": config]],
                   "secrets": ["vpn/test/wg-private-key": Data("key".utf8).base64EncodedString()]],
            readCredential: read, readOpenVPNConfig: { _ in openVPN })
    }

    private func exportedSecrets(_ result: PortableBackup.ExportResult) throws -> [String: String] {
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: result.data) as? [String: Any])
        return try XCTUnwrap(root["secrets"] as? [String: String])
    }
}
