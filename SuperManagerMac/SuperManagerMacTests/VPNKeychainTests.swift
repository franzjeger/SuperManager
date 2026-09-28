import Security
import XCTest
@testable import SuperManagerMac

final class VPNKeychainTests: XCTestCase {
    func testRestoredProfileWithNoSecretsRequestsBothCredentials() {
        XCTAssertThrowsError(try VPNKeychain.ikev2Credentials(
            passwordAccount: "password", pskAccount: "psk",
            read: { _ in throw VPNKeychain.KeychainError.osStatus(errSecItemNotFound, "copy") }
        )) { error in
            let missing = error as? VPNKeychain.MissingIKEv2Credentials
            XCTAssertEqual(missing?.password, true)
            XCTAssertEqual(missing?.sharedSecret, true)
        }
    }

    func testMissingPSKIsNotSilentlyChangedToCertificateAuthentication() {
        XCTAssertThrowsError(try VPNKeychain.ikev2Credentials(
            passwordAccount: "password", pskAccount: "psk",
            read: { account in
                if account == "password" { return "example-password" }
                throw VPNKeychain.KeychainError.osStatus(errSecItemNotFound, "copy")
            }
        )) { error in
            let missing = error as? VPNKeychain.MissingIKEv2Credentials
            XCTAssertEqual(missing?.password, false)
            XCTAssertEqual(missing?.sharedSecret, true)
        }
    }

    /// The helper authenticates the gateway with the PSK and has no
    /// certificate path, so an empty stored PSK is as unusable as a missing
    /// one and must bring back the recovery prompt.
    func testEmptyStoredPSKCountsAsMissing() {
        XCTAssertThrowsError(try VPNKeychain.ikev2Credentials(
            passwordAccount: "password", pskAccount: "psk",
            read: { $0 == "password" ? "example-password" : "" }
        )) { error in
            let missing = error as? VPNKeychain.MissingIKEv2Credentials
            XCTAssertEqual(missing?.password, false)
            XCTAssertEqual(missing?.sharedSecret, true)
        }
    }

    func testEmptyPSKReferenceDoesNotQueryKeychain() throws {
        var accounts: [String] = []
        let credentials = try VPNKeychain.ikev2Credentials(
            passwordAccount: "password", pskAccount: "",
            read: { accounts.append($0); return "example-password" })
        XCTAssertEqual(accounts, ["password"])
        XCTAssertEqual(credentials.sharedSecret, "")
    }

    func testEmptyPasswordRequiresRecoveryButPreservesPSK() {
        XCTAssertThrowsError(try VPNKeychain.ikev2Credentials(
            passwordAccount: "password", pskAccount: "psk",
            read: { $0 == "password" ? "" : "example-psk" }
        )) { error in
            let missing = error as? VPNKeychain.MissingIKEv2Credentials
            XCTAssertEqual(missing?.password, true)
            XCTAssertEqual(missing?.sharedSecret, false)
        }
    }

    func testAccessErrorsAreNotTreatedAsMissingCredentials() {
        for status in [errSecAuthFailed, errSecInteractionNotAllowed, errSecMissingEntitlement, errSecDecode] {
            for failedAccount in ["password", "psk"] {
                XCTAssertThrowsError(try VPNKeychain.ikev2Credentials(
                    passwordAccount: "password", pskAccount: "psk",
                    read: { account in
                        if account == failedAccount {
                            throw VPNKeychain.KeychainError.osStatus(status, "copy")
                        }
                        return "example-value"
                    }
                )) { error in
                    guard case VPNKeychain.KeychainError.osStatus(let actual, _) = error else {
                        return XCTFail("Expected the original Keychain error")
                    }
                    XCTAssertEqual(actual, status)
                }
            }
        }
    }

    func testExistingCredentialsRemainUnchanged() throws {
        let credentials = try VPNKeychain.ikev2Credentials(
            passwordAccount: "password", pskAccount: "psk", read: { "saved-\($0)" })
        XCTAssertEqual(credentials.password, "saved-password")
        XCTAssertEqual(credentials.sharedSecret, "saved-psk")
    }
}
