import Foundation
import Security

/// VPN secrets stay in the Data Protection Keychain across updates.
/// Both development and Developer ID builds must carry an App ID, the same
/// access group, and a provisioning profile authorizing their signing certificate.
/// A Developer ID signature alone does not grant access (-34018).
enum VPNKeychain {
    /// Keychain `service` string. Combined with `account` it forms the
    /// unique key for each item.
    static let service = "com.sybr.supermanager.vpn"

    enum KeychainError: Error, LocalizedError {
        case osStatus(OSStatus, String)
        case missingReference

        var errorDescription: String? {
            switch self {
            case .osStatus(let s, _) where s == errSecMissingEntitlement:
                return "This SuperManager build is missing valid Keychain permissions (-34018). " +
                    "Install a corrected signed update. Creating another VPN profile will not fix this."
            case .osStatus(let s, let op):
                return "Keychain \(op) failed (\(s))"
            case .missingReference:
                return "Keychain item has no value"
            }
        }
    }

    /// Common attributes for every Data-Protection-Keychain query we issue.
    /// Centralised so changing accessibility (e.g. raising it to
    /// `WhenUnlockedThisDeviceOnly`) only happens in one place.
    private static func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String:                kSecClassGenericPassword,
            kSecAttrService as String:          service,
            kSecAttrAccount as String:          account,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessible as String:       kSecAttrAccessibleWhenUnlocked,
        ]
    }

    /// Store or replace a generic-password item keyed by `account`.
    static func set(_ data: Data, account: String) throws {
        let query = baseQuery(account: account)
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
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status, "copy")
        }
        guard let data = result as? Data else {
            throw KeychainError.missingReference
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

    /// Release gate: uses only a unique disposable account, never user secrets.
    /// Runs in the signed app process, because a separate test tool has different entitlements.
    static func selfTest() throws {
        let account = "release-self-test/\(UUID().uuidString)"
        defer { delete(account: account) }
        for value in [Data("initial".utf8), Data("updated".utf8)] {
            try set(value, account: account)
            guard try getData(account: account) == value else {
                throw KeychainError.osStatus(errSecDecode, "self-test readback")
            }
        }
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status, "self-test delete")
        }
        do {
            _ = try getData(account: account)
        } catch KeychainError.osStatus(let status, _) where status == errSecItemNotFound {
            return
        }
        throw KeychainError.osStatus(errSecInternalComponent, "self-test deletion verification")
    }

    /// Delete an item. Missing items are ignored.
    static func delete(account: String) {
        let query = baseQuery(account: account)
        SecItemDelete(query as CFDictionary)
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
