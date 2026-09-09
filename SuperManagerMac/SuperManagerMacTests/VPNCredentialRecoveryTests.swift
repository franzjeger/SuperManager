import Security
import XCTest
@testable import SuperManagerMac

final class VPNCredentialRecoveryTests: XCTestCase {
    func testMissingCredentialExplainsRecoveryWithoutMisclassifyingAccessFailure() {
        let missing = VPNKeychain.KeychainError.osStatus(errSecItemNotFound, "copy").localizedDescription
        XCTAssertTrue(missing.contains("Edit credentials"))
        XCTAssertFalse(missing.contains("-25300"))
        let denied = VPNKeychain.KeychainError.osStatus(errSecAuthFailed, "copy").localizedDescription
        XCTAssertFalse(denied.contains("credentials are missing"))
    }
}
