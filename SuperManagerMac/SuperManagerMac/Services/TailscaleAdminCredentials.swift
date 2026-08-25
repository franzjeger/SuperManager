import Foundation
import Security

/// Persists the Tailscale **admin API** OAuth client credentials
/// (`client_id` + `client_secret`) used by `TailscaleAPI`.
///
/// Storage is the **legacy file-based Keychain** — the exact store
/// `AzureOAuth` uses — deliberately NOT the data-protection keychain.
/// The data-protection keychain needs a `keychain-access-groups`
/// entitlement + App ID, which the Developer-ID release build ships
/// without (it breaks AMFI launch), so items written there are
/// unreadable on release. The legacy keychain has no such requirement
/// and works identically on dev and release builds.
///
/// The `client_id` is not strictly a secret, but keeping both values in
/// one store keeps "is it configured?" and "forget it" trivial.
enum TailscaleAdminCredentials {
    private static let service = "com.sybr.supermanager.tailscale"
    private static let idAccount = "oauth-client-id"
    private static let secretAccount = "oauth-client-secret"

    struct Credentials: Equatable {
        var clientId: String
        var clientSecret: String
        var isComplete: Bool {
            !clientId.trimmingCharacters(in: .whitespaces).isEmpty
                && !clientSecret.trimmingCharacters(in: .whitespaces).isEmpty
        }
    }

    static func load() -> Credentials {
        Credentials(
            clientId: keychainGet(account: idAccount) ?? "",
            clientSecret: keychainGet(account: secretAccount) ?? "")
    }

    static var isConfigured: Bool { load().isComplete }

    static func save(clientId: String, clientSecret: String) {
        keychainSet(account: idAccount, value: clientId)
        keychainSet(account: secretAccount, value: clientSecret)
    }

    static func clear() {
        keychainDelete(account: idAccount)
        keychainDelete(account: secretAccount)
    }

    // MARK: - Legacy keychain primitives (mirrors AzureOAuth)

    private static func keychainSet(account: String, value: String) {
        let attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        SecItemDelete(attrs as CFDictionary)  // delete-then-add = upsert
        var add = attrs
        add[kSecValueData] = Data(value.utf8)
        _ = SecItemAdd(add as CFDictionary, nil)
    }

    private static func keychainGet(account: String) -> String? {
        let q: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
            let data = out as? Data,
            let str = String(data: data, encoding: .utf8)
        else { return nil }
        return str
    }

    private static func keychainDelete(account: String) {
        let attrs: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        SecItemDelete(attrs as CFDictionary)
    }
}
