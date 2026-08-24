import XCTest

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
}

extension PortableBackupTests {
    func testExpectedLabelsFromFortiGateConfig() {
        let cfg: [String: Any] = [
            "backend": "forti_gate",
            "password": "vpn/abc/password",
            "psk": "vpn/abc/psk",
        ]
        let labels = PortableBackup.expectedKeychainLabels(config: cfg)
        XCTAssertEqual(Set(labels), ["vpn/abc/password", "vpn/abc/psk"])
    }

    func testWireGuardConfigHasNoExpectedKeychainLabels() {
        let cfg: [String: Any] = ["backend": "wire_guard", "private_key": "vpn/abc/wg-private-key"]
        XCTAssertTrue(PortableBackup.expectedKeychainLabels(config: cfg).isEmpty)
    }

    func testOpenVpnCredentialFieldsAreExpected() {
        let cfg: [String: Any] = [
            "backend": "open_vpn",
            "ovpn_username": "vpn/x/ovpn-username",
            "ovpn_password": "vpn/x/ovpn-password",
        ]
        XCTAssertEqual(Set(PortableBackup.expectedKeychainLabels(config: cfg)),
                       ["vpn/x/ovpn-username", "vpn/x/ovpn-password"])
    }

    func testNilConfigYieldsNoLabels() {
        XCTAssertTrue(PortableBackup.expectedKeychainLabels(config: nil).isEmpty)
    }
}
