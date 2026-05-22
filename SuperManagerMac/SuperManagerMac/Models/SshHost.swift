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

    /// Carries the original wire string when the engine sent a
    /// `device_type` value Swift's `DeviceType` enum didn't
    /// recognise (i.e. the inner decoder hit its `default:` branch
    /// for a wire value that wasn't `"custom"`). Nil for all
    /// known types and for genuinely-`.custom` hosts.
    ///
    /// **Why this exists:** without it, a host whose engine-side
    /// type is `"opn_sense"` or a future 10th Rust variant decodes
    /// as `.custom`, and the write path (addHost / updateHost)
    /// serialises `"custom"` back on the wire — permanently
    /// destroying the host's type on first save. Carrying the raw
    /// string allows the write path to round-trip the original
    /// value instead.
    ///
    /// **Decoder-contract design:** Two silent defaults were stacked
    /// in the previous code. This property resolves both:
    /// 1. The inner `DeviceType.init(from:)` no longer silently
    ///    absorbs unknown values — it calls `DeviceType.map(rawValue:)`
    ///    which returns `.custom` for unknowns, but the raw string is
    ///    preserved here rather than discarded.
    /// 2. The outer `try? c.decode(...) ?? .linux` fallback (which
    ///    would swallow any throw and produce `.linux`, strictly
    ///    worse than `.custom`) is replaced by an explicit raw-string
    ///    read. If `device_type` is absent from the JSON entirely,
    ///    the host still falls back to `.linux` (unchanged behaviour
    ///    for pre-existing rows that lack the field), but the logic
    ///    is explicit and documented rather than hidden in a `?? `.
    let unrecognizedDeviceTypeRawValue: String?

    /// The value to send on the wire when writing this host back to
    /// the engine. Prefers the original raw string over the enum's
    /// `rawValue` — prevents write-amplification for unrecognised
    /// types, which would otherwise overwrite the engine's persisted
    /// type with `"custom"` on first edit.
    var deviceTypeWireValue: String {
        unrecognizedDeviceTypeRawValue ?? deviceType.rawValue
    }

    /// The human-readable name to show in host-detail surfaces
    /// that have a `SshHostSummary` in hand. Distinct from
    /// `DeviceType.displayName` (which has no access to the raw
    /// string and returns `"Custom"` for the `.custom` case
    /// regardless of whether it was genuinely custom or a silent
    /// decoder fallback). The pickers, which iterate
    /// `DeviceType.allCases`, should continue to use
    /// `DeviceType.displayName` — this property is only for
    /// surfaces that show an existing host's identity.
    var effectiveDeviceTypeDisplayName: String {
        if let raw = unrecognizedDeviceTypeRawValue {
            return "Unrecognized: \(raw)"
        }
        return deviceType.displayName
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        label = try c.decode(String.self, forKey: .label)
        hostname = try c.decode(String.self, forKey: .hostname)
        port = (try? c.decode(UInt16.self, forKey: .port)) ?? 22
        username = try c.decode(String.self, forKey: .username)
        group = (try? c.decode(String.self, forKey: .group)) ?? ""
        authMethod = (try? c.decode(AuthMethod.self, forKey: .authMethod)) ?? .key
        authKeyId = try? c.decode(String.self, forKey: .authKeyId)
        vpnProfileId = try? c.decode(String.self, forKey: .vpnProfileId)
        hasApi = (try? c.decode(Bool.self, forKey: .hasApi)) ?? false
        apiPort = try? c.decode(UInt16.self, forKey: .apiPort)
        hasUnifiController = (try? c.decode(Bool.self, forKey: .hasUnifiController)) ?? false
        pinned = (try? c.decode(Bool.self, forKey: .pinned)) ?? false

        // Decode device_type with explicit raw-string inspection so
        // we can distinguish "unrecognised wire value that fell to
        // .custom" from "genuinely .custom host". The previous
        // `(try? c.decode(DeviceType.self, ..)) ?? .linux` pattern
        // stacked two silent defaults: the inner decoder silently
        // mapped unknowns to .custom, and the outer `?? .linux`
        // would silently swallow any throw and produce .linux (a
        // strictly worse default for firewall-type hosts).
        if let rawStr = try? c.decode(String.self, forKey: .deviceType) {
            deviceType = DeviceType.map(rawValue: rawStr)
            // Populated only when: the field was present, we
            // recognised it as not a known type, AND the raw value
            // wasn't literally "custom" (which would be a genuine
            // custom host, not a silent-decoder fall-through).
            unrecognizedDeviceTypeRawValue =
                (deviceType == .custom && rawStr.lowercased() != "custom")
                ? rawStr : nil
        } else {
            // Field absent from JSON entirely (pre-existing rows
            // that pre-date the `device_type` engine field). Keep
            // the same fallback as before: .linux, null raw.
            deviceType = .linux
            unrecognizedDeviceTypeRawValue = nil
        }
    }
}

/// Rust uses `#[serde(rename_all = "snake_case")]`
///
/// **Schema parity (1.12b investigation):** Rust's `DeviceType`
/// had 9 cases while Swift had 7. The two missing cases —
/// `OpnSense` (wire `"opn_sense"`) and `Sophos` (wire `"sophos"`)
/// — caused hosts of those types to decode silently as `.custom`,
/// mis-rendering app-wide and (critically) write-amplifying back
/// to `"custom"` on first edit, permanently destroying the type
/// in the engine. Both cases are added here as part of the
/// schema-drift gate. `SshHostSummary.unrecognizedDeviceTypeRawValue`
/// catches any future Rust additions before a Swift sync.
enum DeviceType: String, Codable, CaseIterable, Hashable {
    case linux = "linux"
    case unifi = "uni_fi"
    case pfSense = "pf_sense"
    case openWrt = "open_wrt"
    case fortigate = "fortigate"
    /// OPNsense (FreeBSD-based pfSense fork). Wire value `"opn_sense"`.
    /// Key deployment: OPNsense → System → Access → Users.
    case opnSense = "opn_sense"
    /// Sophos XG / SFOS firewall. Wire value `"sophos"`.
    /// Key deployment: Sophos Webadmin → Authentication → Users.
    case sophos = "sophos"
    case windows = "windows"
    case custom = "custom"

    var displayName: String {
        switch self {
        case .linux: return "Linux"
        case .unifi: return "UniFi"
        case .pfSense: return "pfSense"
        case .openWrt: return "OpenWrt"
        case .fortigate: return "FortiGate"
        case .opnSense: return "OPNsense"
        case .sophos: return "Sophos"
        case .windows: return "Windows"
        case .custom: return "Custom"
        }
    }

    /// Map a raw wire string to a `DeviceType`. The single source
    /// of truth for the wire-value → case mapping, used by both
    /// the `Codable` init below and `SshHostSummary.init(from:)`.
    /// Returns `.custom` for unrecognised values (not a throw) so
    /// that `SshHostSummary` can carry the raw string alongside and
    /// distinguish "unrecognised" from "genuinely custom" without
    /// needing associated values or a CaseIterable break.
    static func map(rawValue raw: String) -> DeviceType {
        switch raw.lowercased() {
        case "linux":                   return .linux
        case "unifi", "un_ifi", "uni_fi": return .unifi
        case "pfsense", "pf_sense":     return .pfSense
        case "openwrt", "open_wrt", "lede": return .openWrt
        case "fortigate":               return .fortigate
        case "opn_sense", "opnsense":   return .opnSense
        case "sophos", "sfos", "xg":    return .sophos
        case "windows":                 return .windows
        default:                        return .custom
        }
    }

    // Codable conformance delegates to the shared mapping helper.
    // The previous `default: self = .custom` is no longer here —
    // all unrecognised values still route to `.custom` via
    // `map(rawValue:)`, but `SshHostSummary`'s decoder now reads
    // the raw string first so the original value can be preserved.
    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = DeviceType.map(rawValue: raw)
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
