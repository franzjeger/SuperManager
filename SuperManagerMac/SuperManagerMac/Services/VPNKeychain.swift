import Foundation
import Security

/// Stores VPN credentials in the user's macOS login Keychain.
///
/// ## Why the login Keychain
///
/// Data Protection Keychain requires `keychain-access-groups`. The
/// notarised Developer ID build deliberately ships without that restricted
/// entitlement because it has no matching distribution provisioning
/// profile. Passing `kSecUseDataProtectionKeychain: true` from that build
/// therefore fails every write with `errSecMissingEntitlement` (-34018).
///
/// The regular login Keychain does not require that entitlement. It is
/// still encrypted and access-controlled by macOS, and a stable Developer
/// ID signature keeps access intact across application updates. Older
/// development builds wrote to Data Protection Keychain, so reads include
/// a one-time best-effort migration from that store when the entitlement is
/// available.
enum VPNKeychain {
    /// Keychain `service` string. Combined with `account` it forms the
    /// unique key for each item.
    static let service = "com.sybr.supermanager.vpn"

    enum KeychainError: Error, LocalizedError {
        case osStatus(OSStatus, String)
        case missingReference

        var errorDescription: String? {
            switch self {
            case .osStatus(let s, let op):
                if s == errSecItemNotFound {
                    return "VPN credentials are missing from this app's Keychain. Edit credentials and enter the EAP password and, if configured, the shared secret (PSK). Copying a profile does not guarantee its credentials are available."
                }
                return "Keychain \(op) failed (\(s))"
            case .missingReference:
                return "Keychain item has no value"
            }
        }
    }

    /// Common attributes for the production-safe login Keychain.
    /// Internal so tests can assert that the release path never silently
    /// opts back into Data Protection Keychain.
    static func loginKeychainQuery(account: String) -> [String: Any] {
        [
            kSecClass as String:                kSecClassGenericPassword,
            kSecAttrService as String:          service,
            kSecAttrAccount as String:          account,
        ]
    }

    /// Query used only to recover values written by entitlement-equipped
    /// development builds before the production backend was corrected.
    private static func oldDataProtectionQuery(account: String) -> [String: Any] {
        var query = loginKeychainQuery(account: account)
        query[kSecUseDataProtectionKeychain as String] = true
        return query
    }

    /// Avoid even querying DPK from the production build. Besides being
    /// pointless, doing so produces the same -34018 we are protecting the
    /// user from. Development builds signed with the access group return a
    /// non-nil entitlement value and may perform the legacy migration.
    private static var canAccessOldDataProtectionKeychain: Bool {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        return SecTaskCopyValueForEntitlement(
            task, "keychain-access-groups" as CFString, nil) != nil
    }

    /// Store or replace a generic-password item keyed by `account`.
    static func set(_ data: Data, account: String) throws {
        let query = loginKeychainQuery(account: account)
        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = data
            let addStatus = SecItemAdd(add as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainError.osStatus(addStatus, "add")
            }
            return
        }
        throw KeychainError.osStatus(status, "update")
    }

    /// Fetch the raw value data for an item.
    static func getData(account: String) throws -> Data {
        var query = loginKeychainQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data {
            return data
        }
        guard status == errSecItemNotFound else {
            throw KeychainError.osStatus(status, "copy")
        }
        guard canAccessOldDataProtectionKeychain else {
            throw KeychainError.osStatus(status, "copy")
        }

        // One-time migration for credentials created by an older
        // development build.
        var oldQuery = oldDataProtectionQuery(account: account)
        oldQuery[kSecReturnData as String] = true
        oldQuery[kSecMatchLimit as String] = kSecMatchLimitOne
        var oldResult: AnyObject?
        let oldStatus = SecItemCopyMatching(oldQuery as CFDictionary, &oldResult)
        guard oldStatus == errSecSuccess else {
            throw KeychainError.osStatus(status, "copy")
        }
        guard let data = oldResult as? Data else { throw KeychainError.missingReference }

        // Return the recovered value even if migration itself cannot be
        // completed. Never trade access to a credential for cleanup.
        if (try? set(data, account: account)) != nil {
            SecItemDelete(oldDataProtectionQuery(account: account) as CFDictionary)
        }
        return data
    }

    /// Convenience: fetch the value as a UTF-8 string. Throws if missing
    /// or if the bytes aren't valid UTF-8.
    static func getString(account: String) throws -> String {
        let data = try getData(account: account)
        guard let s = String(data: data, encoding: .utf8) else {
            throw KeychainError.osStatus(errSecDecode, "decode utf8")
        }
        return s
    }

    /// Delete an item. Missing items are ignored.
    static func delete(account: String) {
        SecItemDelete(loginKeychainQuery(account: account) as CFDictionary)
        // Best-effort cleanup of the pre-fix development store. Production
        // builds never query the entitlement-protected backend.
        if canAccessOldDataProtectionKeychain {
            SecItemDelete(oldDataProtectionQuery(account: account) as CFDictionary)
        }
    }

    /// Every account name this app stores for one profile.
    ///
    /// Single source of truth: `deleteAll` and the duplicate flow both
    /// read it, so a new credential kind can't be added to one and
    /// forgotten in the other. Account-name format matches the
    /// producers in `AddVpnProfileSheet`, `EditOvpnCredentialsSheet`
    /// and `ImportVpnSheet`.
    static func accounts(for profileId: String) -> [String] {
        [
            "vpn/\(profileId)/password",
            "vpn/\(profileId)/psk",
            "vpn/\(profileId)/ovpn-username",
            "vpn/\(profileId)/ovpn-password",
        ]
    }

    /// Delete every stored entry for a profile id.
    ///
    /// Previously covered only password and PSK, so deleting an OpenVPN
    /// or Azure profile left its username and password behind in the
    /// Keychain indefinitely.
    static func deleteAll(profileId: String) {
        for account in accounts(for: profileId) {
            delete(account: account)
        }
    }

    /// Copy every stored entry from one profile id to another.
    ///
    /// Used by Duplicate. The daemon can only clone what lives in its
    /// own store, which on macOS excludes IKEv2, OpenVPN and Azure
    /// credentials, so the GUI carries those across itself. Entries the
    /// source doesn't have are skipped — a WireGuard profile has none of
    /// these, and that is not a failure.
    static func copyAll(from sourceId: String, to targetId: String) {
        for (source, target) in zip(accounts(for: sourceId), accounts(for: targetId)) {
            guard let data = try? getData(account: source) else { continue }
            try? set(data, account: target)
        }
    }
}
