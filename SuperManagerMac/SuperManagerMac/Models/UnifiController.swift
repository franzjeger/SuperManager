import Foundation

/// First-class UniFi controller — stored standalone in the
/// daemon's `unifi_controllers/<id>.toml`, NOT keyed to an SSH
/// host. The controller can run on a UDM-Pro, a Cloud Key, a
/// hosted VM, a Mac, Docker — anywhere reachable over HTTPS.
///
/// Field order + naming mirrors the Rust `UnifiController` so
/// the same JSON shape goes both ways through the engine RPC.
struct UnifiController: Codable, Identifiable, Hashable {
    let id: String   // UUID as string
    var label: String
    var url: String
    var siteId: String
    var username: String
    /// Reference into the keychain; the password itself never
    /// appears in this struct. The engine resolves it during
    /// every API call.
    var credsRef: String
    /// Optional customer scoping for MSP setups.
    var customerSlug: String?
    /// Last successful `test_connection`. Nil = never verified
    /// (or last test failed).
    var verifiedAt: Date?
    var createdAt: Date
    var updatedAt: Date

    enum CodingKeys: String, CodingKey {
        case id, label, url, username
        case siteId = "site_id"
        case credsRef = "creds_ref"
        case customerSlug = "customer_slug"
        case verifiedAt = "verified_at"
        case createdAt = "created_at"
        case updatedAt = "updated_at"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        label = try c.decode(String.self, forKey: .label)
        url = try c.decode(String.self, forKey: .url)
        siteId = (try? c.decode(String.self, forKey: .siteId)) ?? "default"
        username = try c.decode(String.self, forKey: .username)

        // SecretRef serialises as a single-string tuple struct
        // on the Rust side via serde's default representation —
        // i.e. `{"0": "label/foo"}`. Tolerate both that shape
        // and a bare string so the GUI doesn't break if the
        // engine ever switches representation.
        if let str = try? c.decode(String.self, forKey: .credsRef) {
            credsRef = str
        } else if let dict = try? c.decode([String: String].self, forKey: .credsRef) {
            credsRef = dict.values.first ?? ""
        } else {
            credsRef = ""
        }

        customerSlug = try? c.decodeIfPresent(String.self, forKey: .customerSlug)
        verifiedAt = try? c.decodeIfPresent(Date.self, forKey: .verifiedAt)
        createdAt = (try? c.decode(Date.self, forKey: .createdAt)) ?? Date()
        updatedAt = (try? c.decode(Date.self, forKey: .updatedAt)) ?? Date()
    }
}

/// One row of `/api/s/<site>/stat/device` after engine
/// massaging. Used by the controller-devices browse UI.
struct UnifiManagedDevice: Codable, Identifiable, Hashable {
    let mac: String
    let ip: String?
    let model: String?
    let name: String?
    let state: String
    let version: String?
    let adopted: Bool?
    let informUrl: String?
    let uptime: UInt64?
    let lastSeen: Int64?
    let controllerId: String?
    let controllerLabel: String?

    var id: String { mac }

    enum CodingKeys: String, CodingKey {
        case mac, ip, model, name, state, version, adopted, uptime
        case informUrl = "inform_url"
        case lastSeen = "last_seen"
        case controllerId = "controller_id"
        case controllerLabel = "controller_label"
    }
}

/// Controller sysinfo returned by `unifi_controller_test`.
struct UnifiSysInfo: Codable, Hashable {
    let version: String
    let hostname: String?
    let name: String?
}
