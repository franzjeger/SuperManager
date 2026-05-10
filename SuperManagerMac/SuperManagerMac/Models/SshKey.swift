import Foundation

/// Mirrors the Rust `SshKeySummary` type.
struct SshKeySummary: Codable, Identifiable, Hashable {
    let id: String
    let name: String
    let keyType: SshKeyType
    let fingerprint: String
    let tags: [String]
    let deployedCount: Int
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case id, name, fingerprint, tags
        case keyType = "key_type"
        case deployedCount = "deployed_count"
        case createdAt = "created_at"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        keyType = try c.decode(SshKeyType.self, forKey: .keyType)
        fingerprint = try c.decode(String.self, forKey: .fingerprint)
        tags = (try? c.decode([String].self, forKey: .tags)) ?? []
        deployedCount = try c.decode(Int.self, forKey: .deployedCount)
        createdAt = try c.decode(String.self, forKey: .createdAt)
    }
}

/// Mirrors the Rust `SshKey` type (full detail).
struct SshKeyDetail: Codable, Identifiable {
    let id: String
    let name: String
    let description: String
    let keyType: SshKeyType
    let publicKey: String
    let fingerprint: String
    let tags: [String]
    let deployedTo: [String]
    let createdAt: String
    let updatedAt: String

    enum CodingKeys: String, CodingKey {
        case id, name, description, fingerprint, tags
        case keyType = "key_type"
        case publicKey = "public_key"
        case deployedTo = "deployed_to"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        description = (try? c.decode(String.self, forKey: .description)) ?? ""
        keyType = try c.decode(SshKeyType.self, forKey: .keyType)
        publicKey = try c.decode(String.self, forKey: .publicKey)
        fingerprint = try c.decode(String.self, forKey: .fingerprint)
        tags = (try? c.decode([String].self, forKey: .tags)) ?? []
        deployedTo = (try? c.decode([String].self, forKey: .deployedTo)) ?? []
        createdAt = try c.decode(String.self, forKey: .createdAt)
        updatedAt = try c.decode(String.self, forKey: .updatedAt)
    }
}

/// Rust serializes as SCREAMING_CASE: "ED25519", "RSA2048", "RSA4096"
enum SshKeyType: String, Codable, CaseIterable, Hashable {
    case ed25519 = "ED25519"
    case rsa2048 = "RSA2048"
    case rsa4096 = "RSA4096"

    var displayName: String {
        switch self {
        case .ed25519: return "Ed25519"
        case .rsa2048: return "RSA 2048"
        case .rsa4096: return "RSA 4096"
        }
    }
}
