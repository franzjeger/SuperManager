import Foundation

/// Mirrors the Rust `SshHostSummary` type.
struct SshHostSummary: Codable, Identifiable, Hashable {
    let id: String
    let label: String
    let hostname: String
    let port: UInt16
    let username: String
    let group: String
    let deviceType: DeviceType
    let authMethod: AuthMethod
    let authKeyId: String?
    let vpnProfileId: String?
    let hasApi: Bool
    let apiPort: UInt16?
    let hasUnifiController: Bool
    let pinned: Bool

    enum CodingKeys: String, CodingKey {
        case id, label, hostname, port, username, group, pinned
        case deviceType = "device_type"
        case authMethod = "auth_method"
        case authKeyId = "auth_key_id"
        case vpnProfileId = "vpn_profile_id"
        case hasApi = "has_api"
        case apiPort = "api_port"
        case hasUnifiController = "has_unifi_controller"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        label = try c.decode(String.self, forKey: .label)
        hostname = try c.decode(String.self, forKey: .hostname)
        port = (try? c.decode(UInt16.self, forKey: .port)) ?? 22
        username = try c.decode(String.self, forKey: .username)
        group = (try? c.decode(String.self, forKey: .group)) ?? ""
        deviceType = (try? c.decode(DeviceType.self, forKey: .deviceType)) ?? .linux
        authMethod = (try? c.decode(AuthMethod.self, forKey: .authMethod)) ?? .key
        authKeyId = try? c.decode(String.self, forKey: .authKeyId)
        vpnProfileId = try? c.decode(String.self, forKey: .vpnProfileId)
        hasApi = (try? c.decode(Bool.self, forKey: .hasApi)) ?? false
        apiPort = try? c.decode(UInt16.self, forKey: .apiPort)
        hasUnifiController = (try? c.decode(Bool.self, forKey: .hasUnifiController)) ?? false
        pinned = (try? c.decode(Bool.self, forKey: .pinned)) ?? false
    }
}

/// Rust uses `#[serde(rename_all = "snake_case")]`
enum DeviceType: String, Codable, CaseIterable, Hashable {
    case linux = "linux"
    case unifi = "uni_fi"
    case pfSense = "pf_sense"
    case openWrt = "open_wrt"
    case fortigate = "fortigate"
    case windows = "windows"
    case custom = "custom"

    var displayName: String {
        switch self {
        case .linux: return "Linux"
        case .unifi: return "UniFi"
        case .pfSense: return "pfSense"
        case .openWrt: return "OpenWrt"
        case .fortigate: return "FortiGate"
        case .windows: return "Windows"
        case .custom: return "Custom"
        }
    }

    // Accept various forms from JSON
    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        switch raw.lowercased() {
        case "linux": self = .linux
        case "unifi", "un_ifi", "uni_fi": self = .unifi
        case "pfsense", "pf_sense": self = .pfSense
        case "openwrt", "open_wrt": self = .openWrt
        case "fortigate": self = .fortigate
        case "windows": self = .windows
        default: self = .custom
        }
    }
}

/// Rust uses `#[serde(rename_all = "snake_case")]`
enum AuthMethod: String, Codable, CaseIterable, Hashable {
    case password = "password"
    case key = "key"

    var displayName: String {
        switch self {
        case .password: return "Password"
        case .key: return "SSH Key"
        }
    }
}
