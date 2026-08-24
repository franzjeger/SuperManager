import Foundation

/// Cross-platform ("portable") backup — the JSON format the macOS engine
/// and the Linux daemon share, so a backup taken here restores there and
/// vice versa.
///
/// The engine (`backup_export` / `backup_import`) handles everything in
/// its own file store: profiles, SSH material, WireGuard keys, API
/// tokens, UniFi passwords. This Swift layer adds the one half the engine
/// cannot see — the IKEv2/OpenVPN login credentials the app keeps in the
/// macOS Keychain — folding them into an export and routing them back to
/// the Keychain on import.
enum PortableBackup {

    struct ImportSummary {
        let profiles: Int
        let sshKeys: Int
        let hosts: Int
        let secrets: Int
    }

    enum BackupError: LocalizedError {
        case malformedEngineResponse
        case malformedFile(String)
        var errorDescription: String? {
            switch self {
            case .malformedEngineResponse:
                return "The engine returned a backup we couldn't read."
            case .malformedFile(let detail):
                return "This is not a SuperManager portable backup (\(detail))."
            }
        }
    }

    /// Whether a secret label belongs to the macOS app Keychain (IKEv2
    /// EAP password + group PSK, OpenVPN/Azure username + password)
    /// rather than the engine's file store. Everything else in a
    /// backup's `secrets` map is the engine's — including WireGuard
    /// keys, whose `vpn/<id>/wg-*` labels share the `vpn/` prefix but
    /// not these suffixes. Pure, so the split is unit-tested.
    static func isKeychainLabel(_ label: String) -> Bool {
        guard label.hasPrefix("vpn/") else { return false }
        return label.hasSuffix("/password")
            || label.hasSuffix("/psk")
            || label.hasSuffix("/ovpn-username")
            || label.hasSuffix("/ovpn-password")
    }

    /// The portable backup bytes: the engine's JSON with the Keychain
    /// credentials merged into its `secrets` map. Write these 0600 — a
    /// populated backup carries private keys and passwords in the clear.
    static func export(client: ServiceClient) async throws -> Data {
        struct ExportResp: Decodable { let backup: String }
        let resp: ExportResp = try await client.call("backup_export")

        guard
            let obj = try? JSONSerialization.jsonObject(with: Data(resp.backup.utf8)),
            var root = obj as? [String: Any]
        else {
            throw BackupError.malformedEngineResponse
        }

        var secrets = root["secrets"] as? [String: String] ?? [:]
        let profiles = root["profiles"] as? [[String: Any]] ?? []
        for profile in profiles {
            guard let pid = profile["id"] as? String else { continue }
            for account in VPNKeychain.accounts(for: pid) {
                if let data = try? VPNKeychain.getData(account: account) {
                    secrets[account] = data.base64EncodedString()
                }
            }
        }
        root["secrets"] = secrets

        return try JSONSerialization.data(
            withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
    }

    /// Restore a portable backup: the Keychain-bound secrets go to the
    /// Keychain, the rest to the engine. Order does not matter — the two
    /// stores are independent — but stripping the Keychain labels before
    /// the engine call keeps each store holding only what it owns.
    @discardableResult
    static func restore(from data: Data, client: ServiceClient) async throws -> ImportSummary {
        guard
            let obj = try? JSONSerialization.jsonObject(with: data),
            var root = obj as? [String: Any]
        else {
            throw BackupError.malformedFile("not JSON")
        }
        guard root["version"] != nil else {
            throw BackupError.malformedFile("missing version field")
        }

        var secrets = root["secrets"] as? [String: String] ?? [:]
        for (label, b64) in secrets where isKeychainLabel(label) {
            if let bytes = Data(base64Encoded: b64) {
                try? VPNKeychain.set(bytes, account: label)
            }
            secrets.removeValue(forKey: label)
        }
        root["secrets"] = secrets

        let stripped = try JSONSerialization.data(withJSONObject: root)
        guard let strippedStr = String(data: stripped, encoding: .utf8) else {
            throw BackupError.malformedFile("re-encode failed")
        }

        struct ImportResp: Decodable {
            let profiles: Int
            let ssh_keys: Int
            let hosts: Int
            let secrets: Int
        }
        let resp: ImportResp = try await client.call(
            "backup_import", params: ["backup": strippedStr])
        return ImportSummary(
            profiles: resp.profiles, sshKeys: resp.ssh_keys,
            hosts: resp.hosts, secrets: resp.secrets)
    }
}
