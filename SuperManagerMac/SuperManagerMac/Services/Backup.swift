import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Full-config backup / restore with authenticated `AES-256-GCM` archive encryption.
///
/// Exports `~/Library/Application Support/SuperManager/` into a temporary
/// `.tar.gz` archive (unwrapping `secrets.json` v2 inside a private `0700`
/// staging copy using the Mac's Data Protection Keychain wrapping key so the
/// archive is self-contained across Macs), and seals the `.tar.gz` with
/// `PBKDF2-HMAC-SHA256` + `AES-256-GCM` under a user-chosen backup passphrase.
///
/// Binary format (`SMBKUP01`):
///   • `0..<8`   — ASCII magic `"SMBKUP01"`
///   • `8..<12`  — Big-endian `UInt32` PBKDF2 iteration count
///   • `12..<28` — 16-byte random PBKDF2 salt
///   • `28..<40` — 12-byte random AES-GCM nonce
///   • `40...`   — AES-256-GCM ciphertext + 16-byte authentication tag
///                 (with bytes `0..<28` bound as AAD)
///
/// Legacy unencrypted `.tar.gz` archives remain supported by `restore` and
/// `BackupVerify.verify` so older backups can still be recovered.
enum Backup {
    static let encryptedMagic = Data("SMBKUP01".utf8)
    static let defaultIterations: UInt32 = 600_000
    static let minPasswordLength = 8
    private static let secretsEnvelopeAAD = Data("supermanager-secrets-v2".utf8)

    enum BackupError: Error, LocalizedError {
        case dataDirMissing
        case weakPassword
        case passwordRequired
        case invalidPasswordOrCorruptArchive
        case cryptoFailure(String)
        case tarFailed(Int32, String)
        case restoreFailed(String)

        var errorDescription: String? {
            switch self {
            case .dataDirMissing:
                return "SuperManager's data directory doesn't exist yet — there's nothing to back up."
            case .weakPassword:
                return "Backup passphrase must be at least \(Backup.minPasswordLength) characters."
            case .passwordRequired:
                return "This backup archive is encrypted and requires its passphrase."
            case .invalidPasswordOrCorruptArchive:
                return "Incorrect backup passphrase or corrupted archive."
            case .cryptoFailure(let detail):
                return "Backup encryption error: \(detail)"
            case .tarFailed(let code, let msg):
                return "tar exited with code \(code): \(msg)"
            case .restoreFailed(let msg):
                return "Restore failed: \(msg)"
            }
        }
    }

    struct SecretsEnvelopeV2: Decodable {
        let version: Int
        let cipher: String
        let nonce: String
        let ciphertext: String
    }

    /// Path to SuperManager's data directory.
    static var dataDir: URL {
        let support = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appendingPathComponent("SuperManager", isDirectory: true)
    }

    /// Suggested filename for a fresh encrypted backup.
    static func suggestedFilename() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        return "supermanager-backup-\(formatter.string(from: Date())).tar.gz.enc"
    }

    /// Check whether `archive` starts with the `SMBKUP01` encrypted header.
    static func isEncryptedArchive(_ archive: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: archive) else { return false }
        defer { try? handle.close() }
        guard let prefix = try? handle.read(upToCount: encryptedMagic.count) else { return false }
        return prefix == encryptedMagic
    }

    /// Derive a 256-bit key from `password` and `salt` via `PBKDF2-HMAC-SHA256`.
    static func deriveKey(password: String, salt: Data, iterations: UInt32) throws -> SymmetricKey {
        guard iterations >= 1_000 else {
            throw BackupError.cryptoFailure("PBKDF2 iteration count too low")
        }
        let pwBytes = Array(password.utf8)
        var derived = [UInt8](repeating: 0, count: 32)
        let status = salt.withUnsafeBytes { saltRaw -> CCCryptorStatus in
            guard let saltBase = saltRaw.bindMemory(to: UInt8.self).baseAddress else {
                return CCCryptorStatus(kCCParamError)
            }
            return CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                pwBytes,
                pwBytes.count,
                saltBase,
                salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                iterations,
                &derived,
                derived.count
            )
        }
        guard status == kCCSuccess else {
            throw BackupError.cryptoFailure("CCKeyDerivationPBKDF status \(status)")
        }
        return SymmetricKey(data: Data(derived))
    }

    /// Seal raw `.tar.gz` bytes into an `SMBKUP01` `AES-256-GCM` archive.
    static func sealArchive(
        _ plaintext: Data,
        password: String,
        iterations: UInt32 = defaultIterations
    ) throws -> Data {
        guard password.count >= minPasswordLength else {
            throw BackupError.weakPassword
        }
        var saltBytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes) == errSecSuccess else {
            throw BackupError.cryptoFailure("SecRandomCopyBytes salt failed")
        }
        var nonceBytes = [UInt8](repeating: 0, count: 12)
        guard SecRandomCopyBytes(kSecRandomDefault, nonceBytes.count, &nonceBytes) == errSecSuccess else {
            throw BackupError.cryptoFailure("SecRandomCopyBytes nonce failed")
        }
        let salt = Data(saltBytes)
        var header = Data()
        header.append(encryptedMagic)
        var bigIter = iterations.bigEndian
        withUnsafeBytes(of: &bigIter) { header.append(contentsOf: $0) }
        header.append(salt)

        let key = try deriveKey(password: password, salt: salt, iterations: iterations)
        let nonce = try AES.GCM.Nonce(data: Data(nonceBytes))
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: header)

        var out = Data()
        out.reserveCapacity(header.count + 12 + sealed.ciphertext.count + sealed.tag.count)
        out.append(header)
        out.append(contentsOf: nonceBytes)
        out.append(sealed.ciphertext)
        out.append(sealed.tag)
        return out
    }

    /// Open an `SMBKUP01` `AES-256-GCM` archive back to `.tar.gz` bytes.
    static func openArchive(_ archiveData: Data, password: String) throws -> Data {
        // Minimum: 8 magic + 4 iter + 16 salt + 12 nonce + 16 tag = 56 bytes.
        guard archiveData.count >= 56,
              archiveData.prefix(encryptedMagic.count) == encryptedMagic else {
            throw BackupError.invalidPasswordOrCorruptArchive
        }
        let header = archiveData.subdata(in: 0..<28)
        let iterSlice = archiveData.subdata(in: 8..<12)
        let iterations = iterSlice.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard (1_000...10_000_000).contains(iterations) else {
            throw BackupError.invalidPasswordOrCorruptArchive
        }
        let salt = archiveData.subdata(in: 12..<28)
        let nonceData = archiveData.subdata(in: 28..<40)
        let body = archiveData.subdata(in: 40..<archiveData.count)
        guard body.count >= 16 else {
            throw BackupError.invalidPasswordOrCorruptArchive
        }
        let ciphertext = body.dropLast(16)
        let tag = body.suffix(16)

        let key = try deriveKey(password: password, salt: salt, iterations: iterations)
        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(box, using: key, authenticating: header)
        } catch {
            throw BackupError.invalidPasswordOrCorruptArchive
        }
    }

    /// Decrypt an engine `secrets.json` v2 envelope (`AES-256-GCM`) into its
    /// inner `[String: String]` JSON bytes when `masterKey` is available.
    /// Plain v1 JSON is returned unchanged.
    static func unwrapSecretsJsonIfNeeded(_ data: Data, masterKey: Data?) throws -> Data {
        guard let env = try? JSONDecoder().decode(SecretsEnvelopeV2.self, from: data) else {
            return data
        }
        guard env.version == 2, env.cipher == "aes-256-gcm" else {
            throw BackupError.cryptoFailure("Unsupported secrets.json envelope v\(env.version) (\(env.cipher))")
        }
        guard let keyData = masterKey, keyData.count == 32 else {
            throw BackupError.cryptoFailure("Keychain wrapping key unavailable to decrypt secrets.json")
        }
        guard let nonceBytes = Data(base64Encoded: env.nonce), nonceBytes.count == 12,
              let ctAndTag = Data(base64Encoded: env.ciphertext), ctAndTag.count >= 16 else {
            throw BackupError.cryptoFailure("Malformed secrets.json v2 envelope")
        }
        let box = try AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: nonceBytes),
            ciphertext: ctAndTag.dropLast(16),
            tag: ctAndTag.suffix(16)
        )
        return try AES.GCM.open(
            box,
            using: SymmetricKey(data: keyData),
            authenticating: secretsEnvelopeAAD
        )
    }

    /// Export `sourceDir` (defaults to `dataDir`) as a passphrase-encrypted
    /// `SMBKUP01` archive at `destination` (`0600`).
    static func export(
        to destination: URL,
        password: String,
        iterations: UInt32 = defaultIterations,
        sourceDir: URL? = nil,
        masterKey: Data? = nil
    ) throws {
        guard password.count >= minPasswordLength else {
            throw BackupError.weakPassword
        }
        let fm = FileManager.default
        let dir = sourceDir ?? dataDir
        guard fm.fileExists(atPath: dir.path) else {
            throw BackupError.dataDirMissing
        }

        let work = fm.temporaryDirectory
            .appendingPathComponent("supermgr-export-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: work, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: work) }

        let staging = work.appendingPathComponent("staging", isDirectory: true)
        try fm.copyItem(at: dir, to: staging)
        // Remove Unix socket or lock files that cannot/should not be archived.
        try? fm.removeItem(at: staging.appendingPathComponent("supermgrd.sock"))
        try? fm.removeItem(at: staging.appendingPathComponent("secrets.lock"))

        let stagedSecrets = staging.appendingPathComponent("secrets.json")
        if let rawSecrets = try? Data(contentsOf: stagedSecrets) {
            let resolvedKey = masterKey ?? (try? VPNKeychain.getData(account: VPNKeychain.engineSecretsMasterKeyAccount))
            let unwrapped = try unwrapSecretsJsonIfNeeded(rawSecrets, masterKey: resolvedKey)
            try unwrapped.write(to: stagedSecrets, options: [.atomic])
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stagedSecrets.path)
        }

        let tempTar = work.appendingPathComponent("archive.tar.gz")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.arguments = ["-czf", tempTar.path, "-C", staging.path, "."]
        let stderr = Pipe()
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let errBytes = stderr.fileHandleForReading.readDataToEndOfFile()
            let errStr = String(data: errBytes, encoding: .utf8) ?? "unknown"
            throw BackupError.tarFailed(process.terminationStatus, errStr)
        }

        let tarBytes = try Data(contentsOf: tempTar)
        let sealed = try sealArchive(tarBytes, password: password, iterations: iterations)
        try sealed.write(to: destination, options: [.atomic])
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
    }

    /// Restore an encrypted (`SMBKUP01`) or legacy `.tar.gz` archive into
    /// `targetDir` (defaults to `dataDir`), extracting into a `0700` sibling
    /// staging directory FIRST so a corrupt or truncated tar never leaves
    /// `targetDir` empty, then swapping `stageDir` into place atomically.
    static func restore(
        from archive: URL,
        password: String? = nil,
        targetDir: URL? = nil
    ) throws {
        let fm = FileManager.default
        let dir = targetDir ?? dataDir
        let parentDir = dir.deletingLastPathComponent()
        try fm.createDirectory(at: parentDir, withIntermediateDirectories: true)

        let work = fm.temporaryDirectory
            .appendingPathComponent("supermgr-restore-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: work, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: work) }

        let tarToExtract: URL
        if isEncryptedArchive(archive) {
            guard let pw = password, !pw.isEmpty else {
                throw BackupError.passwordRequired
            }
            let sealed = try Data(contentsOf: archive)
            let decrypted = try openArchive(sealed, password: pw)
            let tempTar = work.appendingPathComponent("decrypted.tar.gz")
            try decrypted.write(to: tempTar, options: [.atomic])
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tempTar.path)
            tarToExtract = tempTar
        } else {
            tarToExtract = archive
        }

        // Extract into a sibling staging directory on the SAME filesystem as
        // `dir` so the final swap is an atomic `rename(2)` and a failed `tar`
        // never touches the live directory.
        let stageDir = parentDir
            .appendingPathComponent("SuperManager.restore-staging-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: stageDir, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: stageDir) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        process.arguments = ["-xzf", tarToExtract.path, "-C", stageDir.path]
        let stderr = Pipe()
        process.standardError = stderr
        do {
            try process.run()
        } catch {
            throw BackupError.restoreFailed("tar launch: \(error.localizedDescription)")
        }
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let errBytes = stderr.fileHandleForReading.readDataToEndOfFile()
            let errStr = String(data: errBytes, encoding: .utf8) ?? "unknown"
            throw BackupError.tarFailed(process.terminationStatus, errStr)
        }

        // Never carry stale Unix sockets or lock files into the live directory.
        try? fm.removeItem(at: stageDir.appendingPathComponent("supermgrd.sock"))
        try? fm.removeItem(at: stageDir.appendingPathComponent("secrets.lock"))

        var quarantineURL: URL?
        if fm.fileExists(atPath: dir.path) {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd-HHmmss"
            let backupName = "SuperManager.before-restore-\(formatter.string(from: Date()))-\(UUID().uuidString.prefix(6))"
            let quarantine = parentDir.appendingPathComponent(backupName, isDirectory: true)
            do {
                try fm.moveItem(at: dir, to: quarantine)
                quarantineURL = quarantine
            } catch {
                throw BackupError.restoreFailed(
                    "Couldn't quarantine existing data dir: \(error.localizedDescription)"
                )
            }
        }

        do {
            try fm.moveItem(at: stageDir, to: dir)
            try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        } catch {
            if let q = quarantineURL {
                try? fm.removeItem(at: dir)
                try? fm.moveItem(at: q, to: dir)
            }
            throw BackupError.restoreFailed(
                "Couldn't swap staged restore into place: \(error.localizedDescription)"
            )
        }
    }
}
