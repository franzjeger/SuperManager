import Foundation

/// Dress rehearsal for a backup archive (both `SMBKUP01` encrypted archives
/// and legacy `.tar.gz` archives).
enum BackupVerify {

    struct Check: Identifiable {
        enum Status { case pass, warn, fail }
        let title: String
        let status: Status
        let detail: String
        var id: String { title }
    }

    struct Report {
        var checks: [Check]
        /// Worst status across the checks — drives the summary line.
        var worst: Check.Status {
            if checks.contains(where: { $0.status == .fail }) { return .fail }
            if checks.contains(where: { $0.status == .warn }) { return .warn }
            return .pass
        }
    }

    /// Extract `archive` to a private `0700` temp dir and inspect it.
    static func verify(archive: URL, password: String? = nil) -> Report {
        let fm = FileManager.default
        let scratch = fm.temporaryDirectory
            .appendingPathComponent("supermgr-verify-\(UUID().uuidString)", isDirectory: true)
        do {
            try fm.createDirectory(at: scratch, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
        } catch {
            return Report(checks: [Check(
                title: "Prepare scratch directory", status: .fail,
                detail: error.localizedDescription)])
        }
        defer { try? fm.removeItem(at: scratch) }

        var checks: [Check] = []
        let extractedDir = scratch.appendingPathComponent("extracted", isDirectory: true)
        try? fm.createDirectory(at: extractedDir, withIntermediateDirectories: true,
                                attributes: [.posixPermissions: 0o700])

        let tarInput: URL
        if Backup.isEncryptedArchive(archive) {
            guard let pw = password, !pw.isEmpty else {
                return Report(checks: [Check(
                    title: "Decrypt archive", status: .fail,
                    detail: Backup.BackupError.passwordRequired.localizedDescription)])
            }
            do {
                let raw = try Data(contentsOf: archive)
                let plainTar = try Backup.openArchive(raw, password: pw)
                let tmpTar = scratch.appendingPathComponent("decrypted.tar.gz")
                try plainTar.write(to: tmpTar, options: [.atomic])
                tarInput = tmpTar
                checks.append(Check(
                    title: "Decrypt archive", status: .pass,
                    detail: "AES-256-GCM authentication and decryption succeeded"))
            } catch {
                return Report(checks: [Check(
                    title: "Decrypt archive", status: .fail,
                    detail: error.localizedDescription)])
            }
        } else {
            tarInput = archive
        }

        // 1. Does the archive extract at all?
        let tar = Process()
        tar.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        tar.arguments = ["-xzf", tarInput.path, "-C", extractedDir.path]
        let stderr = Pipe()
        tar.standardError = stderr
        do {
            try tar.run()
            tar.waitUntilExit()
        } catch {
            return Report(checks: checks + [Check(
                title: "Extract archive", status: .fail,
                detail: error.localizedDescription)])
        }
        guard tar.terminationStatus == 0 else {
            let msg = String(
                data: stderr.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8) ?? "unknown"
            return Report(checks: checks + [Check(
                title: "Extract archive", status: .fail,
                detail: "tar exited \(tar.terminationStatus): \(msg.trimmingCharacters(in: .whitespacesAndNewlines))")])
        }
        checks.append(Check(title: "Extract archive", status: .pass,
                            detail: "tar extracted cleanly"))

        checks.append(contentsOf: inspect(extracted: extractedDir))
        return Report(checks: checks)
    }

    /// The content checks, split from the tar plumbing so tests can run
    /// them against a plain directory without building an archive first.
    static func inspect(extracted dir: URL, masterKey: Data? = nil) -> [Check] {
        let fm = FileManager.default
        var checks: [Check] = []

        // 2. Secret store parses (plain JSON map or AES-256-GCM v2 envelope).
        let secretsURL = dir.appendingPathComponent("secrets.json")
        var secrets: [String: String] = [:]
        var canCrossReferenceSecrets = true
        if let data = fm.contents(atPath: secretsURL.path) {
            if let env = try? JSONDecoder().decode(Backup.SecretsEnvelopeV2.self, from: data),
               env.version == 2, env.cipher == "aes-256-gcm" {
                let resolvedKey = masterKey ?? (try? VPNKeychain.getData(account: VPNKeychain.engineSecretsMasterKeyAccount))
                if let unwrapped = try? Backup.unwrapSecretsJsonIfNeeded(data, masterKey: resolvedKey),
                   let parsed = try? JSONDecoder().decode([String: String].self, from: unwrapped) {
                    secrets = parsed
                    checks.append(Check(
                        title: "Secret store", status: .pass,
                        detail: "secrets.json (AES-256-GCM v2) decrypted — \(parsed.count) entries"))
                } else if Data(base64Encoded: env.nonce)?.count == 12,
                          let ct = Data(base64Encoded: env.ciphertext), ct.count >= 16 {
                    canCrossReferenceSecrets = false
                    checks.append(Check(
                        title: "Secret store", status: .warn,
                        detail: "secrets.json is wrapped with another Mac's Keychain key; contents not decrypted here"))
                } else {
                    checks.append(Check(
                        title: "Secret store", status: .fail,
                        detail: "secrets.json v2 envelope is malformed"))
                }
            } else if let parsed = try? JSONDecoder().decode([String: String].self, from: data) {
                secrets = parsed
                checks.append(Check(
                    title: "Secret store", status: .pass,
                    detail: "secrets.json parses — \(parsed.count) entries"))
            } else {
                checks.append(Check(
                    title: "Secret store", status: .fail,
                    detail: "secrets.json exists but does not parse as a string map"))
            }
        } else {
            checks.append(Check(
                title: "Secret store", status: .warn,
                detail: "no secrets.json in the archive"))
        }

        // 3. VPN profiles are present and readable.
        let profilesDir = dir.appendingPathComponent("profiles")
        let profileFiles = (try? fm.contentsOfDirectory(at: profilesDir, includingPropertiesForKeys: nil))?
            .filter { $0.pathExtension == "toml" } ?? []
        var profileTexts: [String: String] = [:]
        var unreadable: [String] = []
        for f in profileFiles {
            if let text = try? String(contentsOf: f, encoding: .utf8), text.contains("id = ") {
                profileTexts[f.deletingPathExtension().lastPathComponent] = text
            } else {
                unreadable.append(f.lastPathComponent)
            }
        }
        if profileFiles.isEmpty {
            checks.append(Check(title: "VPN profiles", status: .warn,
                                detail: "no profiles/ in the archive"))
        } else if unreadable.isEmpty {
            checks.append(Check(title: "VPN profiles", status: .pass,
                                detail: "\(profileTexts.count) profile files readable"))
        } else {
            checks.append(Check(
                title: "VPN profiles", status: .fail,
                detail: "unreadable or empty: \(unreadable.joined(separator: ", "))"))
        }

        // 4. Every daemon-store secret a profile references must exist in the archived store.
        if canCrossReferenceSecrets && !profileTexts.isEmpty {
            var missing: [String] = []
            for (profileId, text) in profileTexts {
                for label in referencedLabels(inProfileToml: text)
                where daemonStoreOwns(label: label) && secrets[label] == nil {
                    missing.append("\(profileId.prefix(8)): \(label)")
                }
            }
            if missing.isEmpty {
                checks.append(Check(
                    title: "Secret cross-reference", status: .pass,
                    detail: "every daemon-store secret referenced by a profile is present"))
            } else {
                checks.append(Check(
                    title: "Secret cross-reference", status: .fail,
                    detail: "referenced but absent — a restore breaks these: "
                        + missing.sorted().joined(separator: "; ")))
            }
        }

        // 5. The .ovpn files OpenVPN profiles point at.
        let ovpnDir = dir.appendingPathComponent("ovpn")
        let ovpnFiles = (try? fm.contentsOfDirectory(at: ovpnDir, includingPropertiesForKeys: nil))?
            .filter { $0.pathExtension == "ovpn" } ?? []
        let emptyOvpn = ovpnFiles.filter {
            ((try? $0.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0) == 0
        }
        if !ovpnFiles.isEmpty {
            checks.append(emptyOvpn.isEmpty
                ? Check(title: "OpenVPN configs", status: .pass,
                        detail: "\(ovpnFiles.count) .ovpn files, none empty")
                : Check(title: "OpenVPN configs", status: .fail,
                        detail: "zero-byte: \(emptyOvpn.map(\.lastPathComponent).joined(separator: ", "))"))
        }

        return checks
    }

    static func referencedLabels(inProfileToml text: String) -> [String] {
        var labels: [String] = []
        var rest = Substring(text)
        while let start = rest.range(of: "\"vpn/") {
            let after = rest[start.upperBound...]
            guard let end = after.firstIndex(of: "\"") else { break }
            labels.append("vpn/" + after[..<end])
            rest = after[after.index(after: end)...]
        }
        return labels
    }

    static func daemonStoreOwns(label: String) -> Bool {
        label.contains("/wg-private-key") || label.contains("/wg-psk-")
    }
}
