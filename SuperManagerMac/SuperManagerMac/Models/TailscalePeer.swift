import Foundation

/// One node in the user's Tailnet (their own Mac plus every other
/// device they own / share). Decoded from `tailscale status --json`'s
/// `Peer` map — keyed on the node's `PublicKey`, so we drop that and
/// surface a stable `id` from `ID` instead.
///
/// We don't model every field — Tailscale's status JSON has ~30
/// per-peer keys, most of which are uninteresting for a UI. If we
/// later need transfer rates, last-handshake age, or capability
/// flags, we can extend this struct without touching call sites.
struct TailscalePeer: Identifiable, Hashable, Decodable {
    /// Stable per-peer identifier from the coordinator. Suitable for
    /// SwiftUI `ForEach` selection.
    let id: String

    /// Short name as shown in the Tailscale admin console, e.g.
    /// `docker` or `franks-mac-mini`. May contain spaces (Apple
    /// devices often use the human-readable computer name).
    let hostName: String

    /// Full MagicDNS name including the tailnet suffix, e.g.
    /// `docker.tailb0b06a.ts.net.` (note: trailing dot).
    let dnsName: String

    /// "macOS", "linux", "windows", "iOS", "android", … Used to
    /// pick a sensible icon in the list view.
    let os: String

    /// Tailnet IPs (IPv4 100.x.y.z and IPv6 fd7a:…). First one is
    /// usually the IPv4. SSH-ing into the node uses index 0.
    let tailscaleIPs: [String]

    /// Whether the coordinator currently sees this peer as online.
    /// Reflects last-keepalive in the last ~2 minutes.
    let online: Bool

    /// True iff this peer is currently advertised as an exit node.
    let exitNodeOption: Bool

    /// True iff WE are currently routing through this peer as our
    /// exit node. Mutually exclusive across the peer set.
    let exitNode: Bool

    /// Bytes sent / received over this tunnel since the daemon
    /// started. Useful as a "is this peer being talked to right now"
    /// indicator without us having to sniff packets.
    let rxBytes: Int64
    let txBytes: Int64

    /// When the peer was last seen by the coordinator. ISO-8601;
    /// the zero value `0001-01-01T00:00:00Z` means "never since
    /// daemon start" (i.e. peer has only handshook, never sent
    /// data via this client). Surfaced for sorting + display.
    let lastSeenIso: String?

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case hostName = "HostName"
        case dnsName = "DNSName"
        case os = "OS"
        case tailscaleIPs = "TailscaleIPs"
        case online = "Online"
        case exitNodeOption = "ExitNodeOption"
        case exitNode = "ExitNode"
        case rxBytes = "RxBytes"
        case txBytes = "TxBytes"
        case lastSeenIso = "LastSeen"
    }

    /// Custom decoder that tolerates the logged-out daemon's
    /// half-populated `Self` block — `TailscaleIPs` comes in as
    /// `null` rather than `[]`, `ID` as `""`, etc. The synthesized
    /// Decodable would throw "data missing" on the null array, which
    /// in turn caused the whole status decode to fail and the UI to
    /// stick on "Loading…" with no actionable buttons.
    ///
    /// Strategy: every field gets a sensible empty default so a
    /// node that hasn't fully come up still produces a usable
    /// TailscalePeer. The few callers that care about real data
    /// (peer detail view, exit-node picker) gate on `online` /
    /// `tailscaleIPs.isEmpty` already.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? ""
        hostName = try c.decodeIfPresent(String.self, forKey: .hostName) ?? ""
        dnsName = try c.decodeIfPresent(String.self, forKey: .dnsName) ?? ""
        os = try c.decodeIfPresent(String.self, forKey: .os) ?? ""
        tailscaleIPs = try c.decodeIfPresent([String].self, forKey: .tailscaleIPs) ?? []
        online = try c.decodeIfPresent(Bool.self, forKey: .online) ?? false
        exitNodeOption = try c.decodeIfPresent(Bool.self, forKey: .exitNodeOption) ?? false
        exitNode = try c.decodeIfPresent(Bool.self, forKey: .exitNode) ?? false
        rxBytes = try c.decodeIfPresent(Int64.self, forKey: .rxBytes) ?? 0
        txBytes = try c.decodeIfPresent(Int64.self, forKey: .txBytes) ?? 0
        lastSeenIso = try c.decodeIfPresent(String.self, forKey: .lastSeenIso)
    }

    /// Primary IPv4 address — the one most useful as an SSH target.
    /// Falls back to the first listed IP (which is sometimes IPv6
    /// if the user's tailnet is v6-only).
    var primaryIP: String? {
        tailscaleIPs.first { ip in
            // Cheap "looks like IPv4" check — three dots, no colons.
            ip.contains(".") && !ip.contains(":")
        } ?? tailscaleIPs.first
    }

    /// Short DNS name without the trailing dot or tailnet suffix.
    /// Used in detail views where the full FQDN is too noisy.
    func shortDnsName(stripping suffix: String) -> String {
        var s = dnsName
        if s.hasSuffix(".") { s.removeLast() }
        if s.hasSuffix(suffix) { s.removeLast(suffix.count) }
        if s.hasSuffix(".") { s.removeLast() }
        return s.isEmpty ? hostName : s
    }

    /// Parsed `LastSeen` timestamp. Tailscale uses Go's zero-time
    /// (`0001-01-01T00:00:00Z`) when the peer has never communicated
    /// since this client started — we treat that as "no data" and
    /// return nil. Otherwise returns the actual Date.
    var lastSeen: Date? {
        guard let iso = lastSeenIso, !iso.isEmpty else { return nil }
        if iso.hasPrefix("0001-") { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: iso) { return d }
        // Fall back without fractional seconds — Tailscale sometimes
        // emits whole-second timestamps for older state.
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: iso)
    }
}

/// The bits we surface from `tailscale status --json`. Drops the
/// noisy fields (`Capabilities`, `Health`, `User` map). Keeping
/// only what the UI actually renders means the decoder doesn't
/// fail when Tailscale ships a new field we don't know about.
struct TailscaleStatus: Decodable {
    /// `Running` — tunnel up and authenticated.
    /// `NeedsLogin` — daemon hasn't been authed yet (or was logged out).
    /// `Stopped` — tunnel deliberately brought down via `tailscale down`.
    /// `Starting` — transient. We treat it like `Running` for UI badges.
    /// `NoState` — daemon not yet talking. Shown as "loading".
    let backendState: String
    let tailscaleIPs: [String]
    let magicDNSSuffix: String?
    /// Human-readable tailnet name from the coordinator, e.g.
    /// `franks-personal.ts.net` or `someone@gmail.com`. Surfaced in
    /// the header so the user can confirm which account this Mac is
    /// joined to without leaving the app.
    let currentTailnetName: String?
    let selfNode: TailscalePeer
    let peers: [TailscalePeer]

    enum CodingKeys: String, CodingKey {
        case backendState = "BackendState"
        case tailscaleIPs = "TailscaleIPs"
        case magicDNSSuffix = "MagicDNSSuffix"
        case currentTailnet = "CurrentTailnet"
        case selfNode = "Self"
        case peer = "Peer"
    }

    /// Sub-decoder for the `CurrentTailnet` object. We only care
    /// about `Name`; the other fields (MagicDNSSuffix, MagicDNSEnabled)
    /// are duplicated at the top level.
    private struct CurrentTailnet: Decodable {
        let name: String?
        enum CodingKeys: String, CodingKey { case name = "Name" }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        backendState = try c.decode(String.self, forKey: .backendState)
        tailscaleIPs = try c.decodeIfPresent([String].self, forKey: .tailscaleIPs) ?? []
        magicDNSSuffix = try c.decodeIfPresent(String.self, forKey: .magicDNSSuffix)
        currentTailnetName = try c.decodeIfPresent(CurrentTailnet.self, forKey: .currentTailnet)?.name
        selfNode = try c.decode(TailscalePeer.self, forKey: .selfNode)
        // `Peer` is a dictionary keyed on the public key — we don't
        // need the key, just the values, sorted by hostname for a
        // stable list.
        let peerMap = try c.decodeIfPresent([String: TailscalePeer].self, forKey: .peer) ?? [:]
        peers = peerMap.values.sorted { lhs, rhs in
            lhs.hostName.localizedCaseInsensitiveCompare(rhs.hostName) == .orderedAscending
        }
    }
}
