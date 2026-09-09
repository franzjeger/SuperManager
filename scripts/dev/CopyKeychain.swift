// One-time app-owned credential copy. Values never leave process memory/Keychain.
import Foundation
import Security

var copied = 0
var existing = 0
var failed = 0
for suffix in ["vpn", "masterpassword", "azure-vpn", "tailscale"] {
    let source = "com.sybr.supermanager." + suffix
    let destination = "com.sybr.supermanager.dev." + suffix
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: source, kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { continue }
    guard status == errSecSuccess, let items = result as? [[String: Any]] else {
        failed += 1; print("Credential service \(suffix): access failed (\(status))"); continue
    }
    for item in items {
        guard let account = item[kSecAttrAccount as String] as? String else { failed += 1; continue }
        let read: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: source, kSecAttrAccount as String: account,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var value: CFTypeRef?
        let readStatus = SecItemCopyMatching(read as CFDictionary, &value)
        guard readStatus == errSecSuccess, let data = value as? Data else {
            failed += 1; print("Credential read failed (\(readStatus))"); continue
        }
        let copy: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: destination, kSecAttrAccount as String: account,
            kSecValueData as String: data]
        let added = SecItemAdd(copy as CFDictionary, nil)
        if added == errSecSuccess { copied += 1 }
        else if added == errSecDuplicateItem { existing += 1 }
        else { failed += 1; print("Credential copy failed (\(added))") }
    }
}
print("Credential copy: \(copied) copied, \(existing) already present, \(failed) failures")
exit(failed == 0 ? 0 : 1)
