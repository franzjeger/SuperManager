import Foundation

/// Mirrors the Rust `ProfileSummary` type.
///
/// The Rust side uses `skip_serializing_if` on several fields (empty vecs,
/// `None` options), so the JSON from the daemon can be missing keys that a
/// Swift-synthesized decoder treats as required. The custom `init(from:)`
/// below mirrors Rust's serde defaults so every field decodes cleanly.
struct VpnProfileSummary: Decodable, Identifiable, Hashable {
    let id: String
    let name: String
    let backend: String
    let autoConnect: Bool
    let fullTunnel: Bool
    let splitRoutes: [String]
    let lastConnectedSecs: UInt64?
    let host: String?
    let username: String?
    let killSwitch: Bool

    enum CodingKeys: String, CodingKey {
        case id, name, backend, host, username
        case autoConnect = "auto_connect"
        case fullTunnel = "full_tunnel"
        case splitRoutes = "split_routes"
        case lastConnectedSecs = "last_connected_secs"
        case killSwitch = "kill_switch"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        backend = try c.decode(String.self, forKey: .backend)
        autoConnect = try c.decodeIfPresent(Bool.self, forKey: .autoConnect) ?? false
        fullTunnel = try c.decodeIfPresent(Bool.self, forKey: .fullTunnel) ?? true
        splitRoutes = try c.decodeIfPresent([String].self, forKey: .splitRoutes) ?? []
        lastConnectedSecs = try c.decodeIfPresent(UInt64.self, forKey: .lastConnectedSecs)
        host = try c.decodeIfPresent(String.self, forKey: .host)
        username = try c.decodeIfPresent(String.self, forKey: .username)
        killSwitch = try c.decodeIfPresent(Bool.self, forKey: .killSwitch) ?? false
    }
}

/// VPN connection state.
enum VpnConnectionState: Equatable {
    case disconnected
    case connecting(profileId: String, phase: String)
    case connected(profileId: String, interface: String)
    case disconnecting(profileId: String)
    case error(message: String)
}

// MARK: - Full profile (decoded from `vpn_get_profile`)

/// Full VPN profile returned by `vpn_get_profile`. Mirrors the Rust `Profile`.
struct VpnProfile: Decodable, Identifiable, Hashable {
    let id: String
    let name: String
    let autoConnect: Bool
    let fullTunnel: Bool
    let killSwitch: Bool
    let config: VpnProfileConfig
    let lastConnectedAt: String?

    enum CodingKeys: String, CodingKey {
        case id, name, config
        case autoConnect = "auto_connect"
        case fullTunnel = "full_tunnel"
        case killSwitch = "kill_switch"
        case lastConnectedAt = "last_connected_at"
    }
}

/// Discriminated union matching Rust's `ProfileConfig` (tagged with "backend").
enum VpnProfileConfig: Decodable, Hashable {
    case ikev2(IKEv2Config)
    case wireguard(WireGuardSummary)
    case openvpn(OpenVpnSummary)
    case azure(AzureVpnSummary)
    case unsupported(String)

    private enum CodingKeys: String, CodingKey {
        case backend
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let backend = try c.decode(String.self, forKey: .backend)
        switch backend {
        // The daemon encodes IKEv2 under the "forti_gate" discriminator
        // — that Rust variant backs any IKEv2-with-EAP endpoint, not
        // just FortiGate.
        case "forti_gate":
            self = .ikev2(try IKEv2Config(from: decoder))
        case "wire_guard":
            self = .wireguard(try WireGuardSummary(from: decoder))
        case "open_vpn":
            self = .openvpn(try OpenVpnSummary(from: decoder))
        case "azure_vpn":
            self = .azure(try AzureVpnSummary(from: decoder))
        default:
            // Unknown backend tag = daemon shipped a new VPN type
            // the app doesn't know about. Log so the mismatch is
            // visible during dev / support, then degrade gracefully
            // (the UI renders .unsupported as a greyed-out row).
            DebugLog.write("[VpnProfileConfig] unknown backend '\(backend)' from daemon — type-erasing to .unsupported")
            self = .unsupported(backend)
        }
    }
}

/// IKEv2 config — shared shape with Rust's FortiGateConfig.
struct IKEv2Config: Decodable, Hashable {
    let host: String
    let username: String
    /// Keyring label for the EAP password (opaque to the Mac app).
    let password: String
    /// Keyring label for the group PSK.
    let psk: String
    let dnsServers: [String]
    let routes: [String]
    /// IKE identity (IDi) the client sends. Empty means "not set" — the
    /// daemon then lets strongSwan default IDi to the connection IP.
    let localId: String

    enum CodingKeys: String, CodingKey {
        case host, username, password, psk
        case dnsServers = "dns_servers"
        case routes
        case localId = "local_id"
    }

    // Hand-rolled so `local_id` is migration-safe: a daemon (or persisted
    // response) predating the field simply omits it, and we default to
    // empty instead of failing the whole profile decode. dns_servers /
    // routes get the same treatment since the daemon marks them
    // `#[serde(default)]` too.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        host = try c.decode(String.self, forKey: .host)
        username = try c.decode(String.self, forKey: .username)
        password = try c.decode(String.self, forKey: .password)
        psk = try c.decode(String.self, forKey: .psk)
        dnsServers = try c.decodeIfPresent([String].self, forKey: .dnsServers) ?? []
        routes = try c.decodeIfPresent([String].self, forKey: .routes) ?? []
        localId = try c.decodeIfPresent(String.self, forKey: .localId) ?? ""
    }
}

/// WireGuard config — display-only shape. We don't surface full peer
/// details in the UI yet (just count + first endpoint for the detail
/// row), so keep the decoded shape minimal — except for `splitRoutes`,
/// which the Routing editor needs to round-trip.
struct WireGuardSummary: Decodable, Hashable {
    let addresses: [String]
    let dns: [String]
    let peerCount: Int
    let firstPeerEndpoint: String?
    /// CIDR strings (`192.168.1.0/24`, `2001:db8::/32`, …). Empty
    /// when the profile is in full-tunnel mode — the daemon's
    /// `vpn_set_routing` clears the list when full=true.
    let splitRoutes: [String]

    enum CodingKeys: String, CodingKey {
        case addresses, dns, peers
        case splitRoutes = "split_routes"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        addresses = try c.decodeIfPresent([String].self, forKey: .addresses) ?? []
        dns       = try c.decodeIfPresent([String].self, forKey: .dns) ?? []
        // The Rust shape has a `peers: Vec<WireGuardPeer>`; we only need
        // a count + a sample endpoint to render the detail row, so
        // decode peers as an array of dictionaries and pick out what
        // we want without modeling the whole `WireGuardPeer` struct.
        let peers: [[String: AnyDecodable]]? =
            try c.decodeIfPresent([[String: AnyDecodable]].self, forKey: .peers)
        peerCount = peers?.count ?? 0
        firstPeerEndpoint = peers?.first?["endpoint"]?.value as? String
        splitRoutes = try c.decodeIfPresent([String].self, forKey: .splitRoutes) ?? []
    }
}

/// OpenVPN config — also display-only. The full `.ovpn` lives on disk
/// at `config_file`; the GUI never needs to read it.
struct OpenVpnSummary: Decodable, Hashable {
    let configFile: String
    let username: String?

    enum CodingKeys: String, CodingKey {
        case configFile = "config_file"
        case username
    }
}

/// Azure VPN (Entra ID Point-to-Site) summary. Mirrors the
/// public-facing fields of Rust's `AzureVpnConfig`. The tls-crypt
/// secret and full PEM CA blob are deliberately omitted from the
/// Swift shape — they're sensitive payloads the daemon needs but
/// the GUI never displays. Connect renders them inline into a
/// just-in-time `.ovpn` body server-side.
struct AzureVpnSummary: Decodable, Hashable {
    let gatewayFqdn: String
    let tenantId: String
    let clientId: String
    let routes: [String]
    let dnsServers: [String]

    enum CodingKeys: String, CodingKey {
        case gatewayFqdn = "gateway_fqdn"
        case tenantId    = "tenant_id"
        case clientId    = "client_id"
        case routes
        case dnsServers  = "dns_servers"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        gatewayFqdn = try c.decode(String.self, forKey: .gatewayFqdn)
        tenantId    = try c.decode(String.self, forKey: .tenantId)
        clientId    = try c.decode(String.self, forKey: .clientId)
        // Rust serde skips empty Vec serialisation, so the keys may
        // not appear at all when the gateway didn't push any
        // routes / DNS — decode-if-present + default empty.
        routes      = try c.decodeIfPresent([String].self, forKey: .routes) ?? []
        dnsServers  = try c.decodeIfPresent([String].self, forKey: .dnsServers) ?? []
    }
}

/// Type-erased `Decodable` value used to skim WireGuard peer dictionaries
/// for a couple of fields without modeling the whole struct.
private struct AnyDecodable: Decodable {
    let value: Any?

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let v = try? c.decode(String.self)        { value = v; return }
        if let v = try? c.decode(Int.self)           { value = v; return }
        if let v = try? c.decode(Double.self)        { value = v; return }
        if let v = try? c.decode(Bool.self)          { value = v; return }
        if let v = try? c.decode([String].self)      { value = v; return }
        if c.decodeNil()                             { value = nil; return }
        // Fall through — we don't need every shape, just don't fail.
        value = nil
    }
}
