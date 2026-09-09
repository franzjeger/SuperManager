import Security
import XCTest
@testable import SuperManagerMac

/// Release builds intentionally carry no keychain-access-groups entitlement.
/// Keep the normal credential queries on the entitlement-free login Keychain;
/// opting into DPK here recreates errSecMissingEntitlement (-34018).
final class KeychainBackendTests: XCTestCase {
    func testVPNCredentialsUseLoginKeychain() {
        let query = VPNKeychain.loginKeychainQuery(account: "vpn/test/password")

        XCTAssertNil(query[kSecUseDataProtectionKeychain as String])
        XCTAssertEqual(query[kSecAttrService as String] as? String,
                       "com.sybr.supermanager.vpn")
    }

    func testMasterPasswordUsesLoginKeychain() {
        let query = MasterPassword.loginKeychainQuery()

        XCTAssertNil(query[kSecUseDataProtectionKeychain as String])
        XCTAssertEqual(query[kSecAttrService as String] as? String,
                       "com.sybr.supermanager.masterpassword")
    }
}
