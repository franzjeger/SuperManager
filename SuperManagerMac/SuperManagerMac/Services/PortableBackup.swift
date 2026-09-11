import Foundation
import Security

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
        /// Secrets the engine took into its own file store.
        let secrets: Int
        /// Secrets written back into the macOS Keychain. Counted
        /// separately from `secrets` because the two stores fail
        /// independently: the engine can accept every key it owns while
        /// every Keychain write fails, and a summary that reported only
        /// the engine's tally called that a clean restore.
        let keychainSecrets: Int
        /// Keychain labels that could not be written. Non-empty means
        /// the restore is incomplete — those profiles still have no
        /// credential and will fail at connect with errSecItemNotFound.
        let keychainFailures: [String]
    }

    /// A portable backup plus whatever it could not capture.
    struct ExportResult {
        let data: Data
        /// Keychain accounts that exist but could not be read. Empty on
        /// a healthy export. Non-empty means `data` is missing
        /// credentials it should have carried, so the caller must say so
        /// rather than reporting a clean export.
        let unreadable: [String]
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
    static func export(client: ServiceClient) async throws -> ExportResult {
        struct ExportResp: Decodable { let backup: String }
        let resp: ExportResp = try await client.call("backup_export")

        guard
            let obj = try? JSONSerialization.jsonObject(with: Data(resp.backup.utf8)),
            var root = obj as? [String: Any]
        else {
            throw BackupError.malformedEngineResponse
        }

        var secrets = root["secrets"] as? [String: String] ?? [:]
        var unreadable: [String] = []
        let profiles = root["profiles"] as? [[String: Any]] ?? []
        for profile in profiles {
            guard let pid = profile["id"] as? String else { continue }
            for account in VPNKeychain.accounts(for: pid) {
                do {
                    secrets[account] = try VPNKeychain
                        .getData(account: account)
                        .base64EncodedString()
                } catch let VPNKeychain.KeychainError.osStatus(status, _)
                    where status == errSecItemNotFound
                {
                    // Nothing stored under this account, which is the
                    // normal case for most of them: a WireGuard profile
                    // has none of these, an IKEv2 one has no `ovpn-*`
                    // pair. Not a failure.
                    continue
                } catch {
                    // Anything else — keychain locked, entitlement gone,
                    // item present but unreadable — means a credential
                    // exists and we could not capture it. Dropping it
                    // silently produced a backup that looked complete
                    // and restored a profile that cannot connect, so
                    // carry the account out to the caller.
                    DebugLog.write(
                        "[PortableBackup] export: cannot read \(account): "
                        + error.localizedDescription)
                    unreadable.append(account)
                }
            }
        }
        root["secrets"] = secrets

        let data = try JSONSerialization.data(
            withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        return ExportResult(data: data, unreadable: unreadable.sorted())
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
        var keychainSecrets = 0
        var keychainFailures: [String] = []
        for (label, b64) in secrets where isKeychainLabel(label) {
            // Removed either way: the label is the Keychain's to own, so
            // it must not fall through to the engine's store even when
            // the Keychain write fails. A failure is reported, not
            // rerouted.
            defer { secrets.removeValue(forKey: label) }
            guard let bytes = Data(base64Encoded: b64) else {
                DebugLog.write("[PortableBackup] restore: bad base64 for \(label)")
                keychainFailures.append(label)
                continue
            }
            do {
                try VPNKeychain.set(bytes, account: label)
                keychainSecrets += 1
            } catch {
                DebugLog.write(
                    "[PortableBackup] restore: cannot write \(label): "
                    + error.localizedDescription)
                keychainFailures.append(label)
            }
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
            hosts: resp.hosts, secrets: resp.secrets,
            keychainSecrets: keychainSecrets,
            keychainFailures: keychainFailures.sorted())
    }
}
