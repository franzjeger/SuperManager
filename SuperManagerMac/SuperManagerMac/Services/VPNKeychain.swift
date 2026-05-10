import Foundation
import Security

/// Stores VPN credentials in the macOS **Data Protection Keychain**.
///
/// ## Why DPK
///
/// macOS exposes two keychains. The **legacy file-based keychain** pins
/// every item to the calling app's *cdhash*; every ad-hoc rebuild gives
/// you a fresh cdhash, the OS treats it as a different process, and the
/// user gets the "Type your login password to allow access" prompt on
/// every read. Unworkable for development.
///
/// The **Data Protection Keychain** (the one iOS has always used,
/// ported to macOS in 10.15) replaces cdhash pinning with **access
/// groups** keyed on the bundle id, which is stable across rebuilds.
/// Items are file-system-encrypted on disk and only readable while the
/// user's session is unlocked.
///
/// To opt into DPK we need two things:
///
/// 1. `kSecUseDataProtectionKeychain: true` on every SecItem call.
/// 2. A `keychain-access-groups` entitlement on the signed bundle.
///    Without it, every SecItem call returns
///    `errSecMissingEntitlement` (-34018).
///
/// The entitlement is gated on the binary being signed with an explicit
/// **App ID**. Per Apple DTS Quinn: *"To use the data protection
/// keychain your app must be signed with an App ID."* Two ways to get
/// one:
///
/// - **Paid Apple Developer Program** — issues full Developer ID + App
///   IDs at will. We have one pending KYC verification (pass + Sybr AS
///   firmaattest still under Apple's review).
/// - **Free Apple ID via Xcode "Personal Team"** — Xcode synthesises
///   an App ID for the project, but only when the project carries a
///   capability that triggers it. Quinn explicitly cites Maps:
///   adding it to Signing & Capabilities forces App ID creation.
///   That entitles `keychain-access-groups`, which is what we need.
///
/// We're using the second path while the paid enrollment processes.
/// Once Developer ID lands, the entitlement is the same — just signed
/// with a stronger identity. No code changes.
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
            // The fix: items live in the modern data-protection keychain.
            // Without this flag SecItem* drops into the legacy file-based
            // keychain (cdhash-pinned ACLs, prompt on every rebuild).
            kSecUseDataProtectionKeychain as String: true,
            // Items are readable while the user is logged in. We don't
            // need them to migrate to a different Mac via backup-restore,
            // so plain `WhenUnlocked` is the right knob (not the
            // ThisDeviceOnly variant — for VPN passwords roaming via
            // iCloud Keychain is actually a feature, not a hazard).
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

    /// Delete an item. Missing items are ignored.
    static func delete(account: String) {
        let query = baseQuery(account: account)
        SecItemDelete(query as CFDictionary)
    }

    /// Delete both password and PSK entries for a profile id.
    /// Account-name format matches the producer in `AddVpnProfileSheet`.
    static func deleteAll(profileId: String) {
        delete(account: "vpn/\(profileId)/password")
        delete(account: "vpn/\(profileId)/psk")
    }
}
