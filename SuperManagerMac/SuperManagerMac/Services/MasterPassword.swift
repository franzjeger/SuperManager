import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Master-password storage and verification.
///
/// ## Storage
///
/// We store a PBKDF2-SHA256 *hash* of the password — never the plaintext
/// — in the Data Protection Keychain under
/// `com.sybr.supermanager.masterpassword` with account `default`. The
/// hash record is:
///
///     v1 || salt(32 bytes) || iter_count_be_u32 || hash(32 bytes)
///
/// `v1` is a single byte version tag so future changes to the KDF
/// (e.g. moving to Argon2id when CryptoKit ever adds it) can be
/// migrated transparently without breaking existing installs.
///
/// ## Why PBKDF2 (and not just `SHA256(password || salt)`)
///
/// Password-equivalent secrets need a memory- or time-hard hash so that
/// an attacker who recovers `vpn-secrets.bin`-style files plus the
/// keychain dump can't brute-force the master with stock GPUs. Argon2id
/// would be better but it's not in CryptoKit; PBKDF2-SHA256 with
/// 600 000 iterations (OWASP 2023 recommendation) is the strongest
/// option that's available system-level on macOS without dragging in
/// a third-party SwiftPM dep we'd then have to vet.
///
/// ## Why not Touch ID / Face ID
///
/// We could trade the password for an `LAContext` biometric prompt and
/// store the encryption key behind a Secure-Enclave-bound key with
/// `.userPresence`. That's the slick path — but it ties unlock to the
/// *device*, not a secret the user knows. Setting up SuperManager on a
/// new Mac would require redoing every credential. A password the user
/// remembers is restorable from a backup; biometry is not. Keep the
/// password as the source of truth; biometry is a nice-to-have we can
/// add as an *additional* unlock method later.
enum MasterPassword {
    /// Keychain identifier — service + account.
    private static let service = "com.sybr.supermanager.masterpassword"
    private static let account = "default"

    /// PBKDF2 iteration count. OWASP 2023 baseline for SHA-256.
    /// Bump this number when migrating to v2+; the version byte in
    /// the stored hash record tells us which iteration count to use
    /// when verifying.
    private static let iterations: UInt32 = 600_000

    /// Length of the random salt and the derived hash, in bytes.
    private static let saltLength = 32
    private static let hashLength = 32

    enum Error: Swift.Error, LocalizedError {
        case keychain(OSStatus, String)
        case wrongPassword
        case malformedRecord

        var errorDescription: String? {
            switch self {
            case .keychain(let s, let op): return "Keychain \(op) failed (\(s))"
            case .wrongPassword:           return "Incorrect password."
            case .malformedRecord:         return "Stored password record is malformed."
            }
        }
    }

    // MARK: - Public API

    /// Whether a master password has ever been set on this device.
    /// Cheap (one `SecItemCopyMatching` with `kSecMatchLimitOne`).
    static var isSet: Bool {
        var q = baseQuery()
        q[kSecReturnAttributes as String] = false
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        return SecItemCopyMatching(q as CFDictionary, nil) == errSecSuccess
    }

    /// Set or replace the master password. The plaintext is consumed
    /// once to derive the hash; we never store it.
    static func set(_ password: String) throws {
        let salt = randomBytes(saltLength)
        let hash = pbkdf2(password: password, salt: salt, iterations: iterations)
        try store(record: encodeRecord(salt: salt, iterations: iterations, hash: hash))
    }

    /// Verify a candidate password against the stored hash. Constant-
    /// time compare to avoid timing oracles (PBKDF2 is the heavy work,
    /// but stay defensive).
    static func verify(_ password: String) throws -> Bool {
        let record = try fetchRecord()
        let (salt, iter, expected) = try decodeRecord(record)
        let candidate = pbkdf2(password: password, salt: salt, iterations: iter)
        return constantTimeEquals(candidate, expected)
    }

    /// Remove the master password entirely. Caller is responsible for
    /// clearing `requireMasterPassword` in `AppSettings` afterwards.
    static func remove() throws {
        let q = baseQuery()
        let status = SecItemDelete(q as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Error.keychain(status, "delete")
        }
    }

    // MARK: - Keychain plumbing

    private static func baseQuery() -> [String: Any] {
        [
            kSecClass as String:                kSecClassGenericPassword,
            kSecAttrService as String:          service,
            kSecAttrAccount as String:          account,
            // Same DPK opt-in as VPNKeychain — without it we'd land in
            // the legacy keychain whose ACL is cdhash-pinned and
            // re-prompts on every rebuild.
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessible as String:       kSecAttrAccessibleWhenUnlocked,
        ]
    }

    private static func store(record: Data) throws {
        // Try update first; fall back to add. Same pattern as VPNKeychain.set.
        let query = baseQuery()
        let update: [String: Any] = [kSecValueData as String: record]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = record
            let s = SecItemAdd(add as CFDictionary, nil)
            guard s == errSecSuccess else { throw Error.keychain(s, "add") }
            return
        }
        throw Error.keychain(status, "update")
    }

    private static func fetchRecord() throws -> Data {
        var q = baseQuery()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data else {
            throw Error.keychain(status, "fetch")
        }
        return data
    }

    // MARK: - Record encoding (v1)

    private static let recordVersion: UInt8 = 1

    private static func encodeRecord(salt: Data, iterations: UInt32, hash: Data) -> Data {
        var out = Data()
        out.append(recordVersion)
        out.append(salt)
        var be = iterations.bigEndian
        out.append(Data(bytes: &be, count: MemoryLayout<UInt32>.size))
        out.append(hash)
        return out
    }

    private static func decodeRecord(_ record: Data) throws -> (Data, UInt32, Data) {
        // 1 (version) + saltLength + 4 (iter) + hashLength
        let expectedLen = 1 + saltLength + 4 + hashLength
        guard record.count == expectedLen,
              record[0] == recordVersion
        else { throw Error.malformedRecord }

        let salt = record.subdata(in: 1..<(1 + saltLength))
        let iterBytes = record.subdata(in: (1 + saltLength)..<(1 + saltLength + 4))
        let iter = iterBytes.withUnsafeBytes { buf in
            UInt32(bigEndian: buf.load(as: UInt32.self))
        }
        let hash = record.subdata(in: (1 + saltLength + 4)..<expectedLen)
        return (salt, iter, hash)
    }

    // MARK: - Crypto

    /// PBKDF2-SHA256 via CommonCrypto. CryptoKit added a `KeyDerivation`
    /// API in macOS 15 with PBKDF2 support, but we target macOS 14, so
    /// we go through the C interface.
    private static func pbkdf2(password: String, salt: Data, iterations: UInt32) -> Data {
        var derived = Data(count: hashLength)
        let pwBytes = Array(password.utf8)
        derived.withUnsafeMutableBytes { (derivedBuf: UnsafeMutableRawBufferPointer) -> Void in
            salt.withUnsafeBytes { (saltBuf: UnsafeRawBufferPointer) -> Void in
                _ = CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pwBytes, pwBytes.count,
                    saltBuf.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations,
                    derivedBuf.bindMemory(to: UInt8.self).baseAddress, hashLength
                )
            }
        }
        return derived
    }

    private static func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        let _ = data.withUnsafeMutableBytes { (buf: UnsafeMutableRawBufferPointer) -> Int32 in
            SecRandomCopyBytes(kSecRandomDefault, count, buf.baseAddress!)
        }
        return data
    }

    /// Constant-time `Data` equality. PBKDF2 already dwarfs the time of
    /// a `==` comparison, but a timing oracle here would be embarrassing.
    private static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[i] ^ b[i]
        }
        return diff == 0
    }
}
