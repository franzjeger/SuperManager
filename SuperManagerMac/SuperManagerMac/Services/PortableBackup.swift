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
        /// Referenced accounts that are missing, or legacy OpenVPN
        /// accounts whose contents could not be checked. The caller must
        /// report these gaps rather than describing the export as complete.
        let unreadable: [String]
        let incompleteProfiles: [String]
        /// OpenVPN profiles whose config could not be read, so we could
        /// not determine which credentials the backup needs to contain.
        let unverifiedProfiles: [String]
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
            let root = obj as? [String: Any]
        else {
            throw BackupError.malformedEngineResponse
        }

        return try completeExport(
            root: root,
            readCredential: { try VPNKeychain.getData(account: $0) },
            readOpenVPNConfig: { try? String(contentsOfFile: $0, encoding: .utf8) })
    }

    /// SecretRef fields serialized by the engine. WireGuard keys belong
    /// to the file store, so sharing the `vpn/` prefix isn't sufficient.
    static func expectedKeychainLabels(config: [String: Any]?) -> Set<String> {
        guard let config else { return [] }
        return Set(["password", "psk"].compactMap { field in
            guard let label = config[field] as? String, isKeychainLabel(label) else { return nil }
            return label
        })
    }

    /// macOS OpenVPN imports keep credentials only in the Keychain, not
    /// in config SecretRefs. A bare auth-user-pass directive references
    /// those accounts; a supplied credential file or cert-only profile
    /// does not require them.
    static func requiresOpenVPNKeychainCredentials(_ content: String) -> Bool {
        content.components(separatedBy: .newlines).contains { line in
            let fields = line.split(whereSeparator: { $0.isWhitespace })
            guard let directive = fields.first,
                  directive == "auth-user-pass" || directive == "--auth-user-pass" else { return false }
            return fields.count == 1 || fields[1].hasPrefix("#") || fields[1].hasPrefix(";")
        }
    }

    /// Injectable reads keep missing-item and access-denied behavior
    /// testable without altering the user's Keychain.
    static func completeExport(
        root: [String: Any],
        readCredential: (String) throws -> Data,
        readOpenVPNConfig: (String) -> String?
    ) throws -> ExportResult {
        var root = root
        var secrets = (root["secrets"] as? [String: String]) ?? [:]
        var unreadable: Set<String> = []
        var incompleteProfiles: [String] = []
        var unverifiedProfiles: [String] = []
        for profile in (root["profiles"] as? [[String: Any]]) ?? [] {
            guard let pid = profile["id"] as? String else { continue }
            let name = (profile["name"] as? String) ?? pid
            let config = profile["config"] as? [String: Any]
            var expected = expectedKeychainLabels(config: config)
            let backend = config?["backend"] as? String
            var accounts = expected
            if backend == "open_vpn" || backend == "azure_vpn" {
                // Preserve legacy/macOS-only credentials even when the
                // engine has no SecretRef for them. Missing optional
                // slots are normal and must not warn on cert-only VPNs.
                let ovpnAccounts: Set<String> = ["vpn/\(pid)/ovpn-username", "vpn/\(pid)/ovpn-password"]
                accounts.formUnion(ovpnAccounts)
                if backend == "open_vpn" {
                    if let path = config?["config_file"] as? String,
                       let content = readOpenVPNConfig(path) {
                        if requiresOpenVPNKeychainCredentials(content) {
                            expected.formUnion(ovpnAccounts)
                        }
                    } else {
                        unverifiedProfiles.append(name)
                    }
                }
            }
            var incomplete = false
            for account in accounts {
                do {
                    secrets[account] = try readCredential(account).base64EncodedString()
                } catch let VPNKeychain.KeychainError.osStatus(status, _)
                    where status == errSecItemNotFound && !expected.contains(account) {
                    // An optional account that does not exist is normal.
                    continue
                } catch {
                    // Locked/denied optional OpenVPN accounts may contain
                    // real legacy credentials. Preserve that warning too.
                    // errSecItemNotFound is a real failure for a referenced
                    // credential, including an item hidden by a signing
                    // access-group change. Never call that a clean backup.
                    if secrets[account] != nil { continue }
                    DebugLog.write("[PortableBackup] export: cannot read \(account): \(error.localizedDescription)")
                    unreadable.insert(account)
                    incomplete = true
                }
            }
            if incomplete { incompleteProfiles.append(name) }
        }
        root["secrets"] = secrets
        let data = try JSONSerialization.data(
            withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        return ExportResult(data: data, unreadable: unreadable.sorted(),
                            incompleteProfiles: incompleteProfiles.sorted(),
                            unverifiedProfiles: unverifiedProfiles.sorted())
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

        var secrets = (root["secrets"] as? [String: String]) ?? [:]
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
