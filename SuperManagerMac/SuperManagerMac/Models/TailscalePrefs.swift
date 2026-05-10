import Foundation

/// User-changeable preferences from `tailscale debug prefs`. Mirrors
/// the subset of the daemon's Prefs struct that we surface in the
/// settings UI.
///
/// We don't model every field. The Tailscale daemon's full Prefs has
/// ~40 keys, half of them either internal-only (`InternalExitNodePrior`,
/// `Sync`) or set exclusively by the Linux-style installer
/// (`NetfilterKind`, `NetfilterMode`). This struct picks out the
/// preferences that map to a real toggle in the UI; everything else is
/// ignored on decode (Decodable is forgiving by default).
///
/// Two-stage decode for nested objects (`AutoUpdate`, `Config.UserProfile`)
/// — Tailscale's JSON nests the email/login under `Config.UserProfile`
/// rather than at the top level, so we mirror that nesting and pull
/// the few fields we need into flat properties for the UI to consume.
struct TailscalePrefs: Decodable {
    /// Accept routes advertised by peers (`tailscale set --accept-routes`).
    var routeAll: Bool
    /// Currently selected exit-node by stable node ID. Empty string
    /// means no exit node. We render the matching peer's hostname
    /// rather than this raw ID.
    var exitNodeID: String
    /// Some installs only expose the IP, not the ID — the Tailscale
    /// preferences object always populates one or the other when an
    /// exit node is in use.
    var exitNodeIP: String
    /// Allow direct local-network access (e.g. printers, NAS) even
    /// while exit-noding through a peer.
    var exitNodeAllowLANAccess: Bool
    /// Use Tailscale's MagicDNS / split DNS (`--accept-dns`).
    var corpDNS: Bool
    /// Run an SSH server on this node accessible via Tailscale-SSH.
    var runSSH: Bool
    /// Block all incoming connections regardless of ACLs (`--shields-up`).
    var shieldsUp: Bool
    /// Routes this node is offering to advertise as a subnet router.
    /// Nil if the user has never set any. Empty list means "actively
    /// not advertising" (different state from never-set, but the UI
    /// treats them the same).
    var advertiseRoutes: [String]?
    /// Override hostname (empty string = use the OS hostname).
    var hostname: String
    /// Daemon-managed auto-update settings.
    var autoUpdate: AutoUpdate?
    /// Currently logged-in user. Useful so the settings sheet can show
    /// "Logged in as foo@bar.com" without a second RPC.
    var userLogin: String?
    /// True iff the user is advertising this Mac as an exit node.
    /// Tailscale's prefs JSON doesn't have a top-level
    /// `AdvertiseExitNode` field — it's inferred from the magic
    /// `AdvertiseRoutes` entries `0.0.0.0/0` + `::/0`. We surface a
    /// boolean here so the UI doesn't have to know that detail.
    var advertiseExitNode: Bool {
        guard let routes = advertiseRoutes else { return false }
        return routes.contains("0.0.0.0/0") && routes.contains("::/0")
    }
    /// Routes the user has manually advertised (excludes the magic
    /// 0.0.0.0/0 + ::/0 pair that means "exit node"). Used by the
    /// subnet-router section of the settings sheet.
    var manualAdvertiseRoutes: [String] {
        (advertiseRoutes ?? []).filter { $0 != "0.0.0.0/0" && $0 != "::/0" }
    }

    /// True when an exit node is selected via EITHER field.
    /// `tailscale set --exit-node=<ip>` on macOS stores it as
    /// `ExitNodeID` (resolved by the daemon), leaving
    /// `ExitNodeIP` empty. UI that read only IP rendered "None"
    /// even when an exit was actually active. Always check both.
    var hasExitNode: Bool {
        !exitNodeIP.isEmpty || !exitNodeID.isEmpty
    }

    /// Resolve the active exit-node peer from the current peer
    /// list, checking IP first then stable ID. Nil if no exit
    /// is selected or the resolved peer isn't in the list.
    func currentExitNode(in peers: [TailscalePeer]) -> TailscalePeer? {
        if !exitNodeIP.isEmpty,
           let p = peers.first(where: { $0.tailscaleIPs.contains(exitNodeIP) }) {
            return p
        }
        if !exitNodeID.isEmpty,
           let p = peers.first(where: { $0.id == exitNodeID }) {
            return p
        }
        return nil
    }

    /// Tailscale's `AutoUpdate` block has two booleans, but `Apply`
    /// can come back as JSON `null` when the daemon hasn't decided
    /// yet (fresh install, App-Store-managed install where the
    /// flag is overridden, etc.). Synthesized Decodable on a
    /// non-optional `Bool` throws on null and cratered the entire
    /// prefs decode — every toggle in the settings sheet flipped
    /// visually, then snapped back when the failed refresh nilled
    /// `tailscalePrefs`. Both fields are now tolerant.
    struct AutoUpdate: Decodable {
        let check: Bool
        let apply: Bool
        enum CodingKeys: String, CodingKey {
            case check = "Check"
            case apply = "Apply"
        }
        /// Memberwise init for callers that build a new AutoUpdate
        /// from existing values (e.g. flipping `apply` while
        /// preserving `check`).
        init(check: Bool, apply: Bool) {
            self.check = check
            self.apply = apply
        }
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            check = try c.decodeIfPresent(Bool.self, forKey: .check) ?? false
            apply = try c.decodeIfPresent(Bool.self, forKey: .apply) ?? false
        }
    }

    enum CodingKeys: String, CodingKey {
        case routeAll = "RouteAll"
        case exitNodeID = "ExitNodeID"
        case exitNodeIP = "ExitNodeIP"
        case exitNodeAllowLANAccess = "ExitNodeAllowLANAccess"
        case corpDNS = "CorpDNS"
        case runSSH = "RunSSH"
        case shieldsUp = "ShieldsUp"
        case advertiseRoutes = "AdvertiseRoutes"
        case hostname = "Hostname"
        case autoUpdate = "AutoUpdate"
        case config = "Config"
    }

    private struct ConfigBlock: Decodable {
        let userProfile: UserProfile?
        struct UserProfile: Decodable {
            let loginName: String?
            enum CodingKeys: String, CodingKey { case loginName = "LoginName" }
        }
        enum CodingKeys: String, CodingKey { case userProfile = "UserProfile" }
    }

    /// Empty/default prefs for use as a fallback when the real
    /// snapshot hasn't loaded yet (sheet opened before first
    /// refresh, daemon temporarily unreachable, etc.). Lets the
    /// optimistic-update path in `applyTailscalePref` always
    /// produce a usable struct so toggles flip visually even on
    /// first interaction.
    ///
    /// Decode all fields from `{}` since the custom `init(from:)`
    /// uses `decodeIfPresent` everywhere — every field falls
    /// through to its declared default.
    static let empty: TailscalePrefs = {
        let data = "{}".data(using: .utf8)!
        // Force-try is correct here: if our own decoder can't
        // handle an empty object, every other call site is broken
        // anyway and crashing in a static initializer is the
        // loudest possible signal.
        return try! JSONDecoder().decode(TailscalePrefs.self, from: data)
    }()

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        routeAll = try c.decodeIfPresent(Bool.self, forKey: .routeAll) ?? false
        exitNodeID = try c.decodeIfPresent(String.self, forKey: .exitNodeID) ?? ""
        exitNodeIP = try c.decodeIfPresent(String.self, forKey: .exitNodeIP) ?? ""
        exitNodeAllowLANAccess = try c.decodeIfPresent(Bool.self, forKey: .exitNodeAllowLANAccess) ?? false
        corpDNS = try c.decodeIfPresent(Bool.self, forKey: .corpDNS) ?? true
        runSSH = try c.decodeIfPresent(Bool.self, forKey: .runSSH) ?? false
        shieldsUp = try c.decodeIfPresent(Bool.self, forKey: .shieldsUp) ?? false
        advertiseRoutes = try c.decodeIfPresent([String].self, forKey: .advertiseRoutes)
        hostname = try c.decodeIfPresent(String.self, forKey: .hostname) ?? ""
        autoUpdate = try c.decodeIfPresent(AutoUpdate.self, forKey: .autoUpdate)
        let cfg = try c.decodeIfPresent(ConfigBlock.self, forKey: .config)
        userLogin = cfg?.userProfile?.loginName
    }
}
