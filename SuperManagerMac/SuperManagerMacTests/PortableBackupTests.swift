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
