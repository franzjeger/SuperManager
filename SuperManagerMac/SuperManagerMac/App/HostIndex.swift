import Foundation

/// Unified Customer -> Site -> Host resolver.
///
/// SuperManager identifies the same host up to four incompatible ways:
///   1. `SshHostSummary.group` — a free-text customer slug (but also holds
///      `"Discovered"`, typos, or `""`).
///   2. `Site.hostIds` — *intended* to hold host record ids, but every writer
///      stores the host's IP instead (`DiscoveryPanel`, `CustomerEditSheet`).
///   3. The IP-keyed security findings store (`HostRisk.hostIp`).
///   4. The record-id-keyed compliance store (`complianceHistory`).
///
/// Nothing reconciled them, so a FortiGate sitting under a customer in
/// Provisioning was invisible to Compliance ("No compliance-capable hosts"),
/// Fleet was blind to compliance scores, and Provisioning diff/deploy was
/// permanently disabled for auto-discovered hosts (an IP can never `==` a
/// record id).
///
/// `HostIndex` is a pure, additive value type: it persists nothing and
/// changes no wire shape. It is rebuilt from the two in-memory stores that
/// already exist (`AppState.sshHosts` + `AppState.customers`) at the tail of
/// `refreshHosts()` / `refreshCustomers()`, so it is always current with zero
/// new call sites in the views. Cost is O(hosts + sites) over a handful of
/// arrays.
///
/// The single object that knows all four keys is `SshHostSummary`: it carries
/// the record id (`id`), the IP (`hostname` — both discovery writers store
/// `hostname = host.ip`), and the customer string (`group`). The index folds
/// in the only structural Customer→Site→host edge (`Site.hostIds`), tolerating
/// a token that is EITHER a record id OR an IP.
///
/// An address is not an identity: two customers' firewalls can both sit at
/// 192.168.1.1. So an address that more than one host carries resolves to
/// nothing, a host that sites of more than one customer link belongs to none
/// of them, and provisioning picks a firewall only when the site itself links
/// exactly one. The index used to keep the last host per address, which
/// could hand one customer's site another customer's firewall.
struct HostIndex {
    /// Record id (canonical spelling) -> host, for ids that only one host has.
    private let byId: [String: SshHostSummary]
    /// Hostname (IP/DNS) -> every host carrying it.
    private let byAddress: [String: [SshHostSummary]]
    /// Host id -> customers whose sites link it, ambiguous links included.
    private let owners: [String: Set<String>]
    /// Host id -> customers whose sites link it unambiguously.
    private let memberships: [String: Set<String>]
    private let knownSlugs: Set<String>

    init(hosts: [SshHostSummary], customers: [Customer]) {
        byId = Dictionary(grouping: hosts, by: { Self.canonicalId($0.id) })
            .compactMapValues { $0.count == 1 ? $0.first : nil }
        // hostname == IP for discovered hosts; this is the join that
        // NetworkScanSheet already does ad-hoc, generalized.
        byAddress = Dictionary(grouping: hosts.filter { !$0.hostname.isEmpty }, by: \.hostname)
        knownSlugs = Set(customers.map(\.slug))

        var owners: [String: Set<String>] = [:]
        var memberships: [String: Set<String>] = [:]
        for customer in customers {
            for site in customer.sites {
                for token in site.hostIds {
                    // A Site.hostIds token may be a record id (intended) or an
                    // IP (what writers actually store). Every host it could
                    // mean records the claim, so an ambiguous link can never
                    // quietly settle on one of them.
                    let matches = byId[Self.canonicalId(token)].map { [$0] } ?? byAddress[token] ?? []
                    for host in matches {
                        owners[host.id, default: []].insert(customer.slug)
                    }
                    if matches.count == 1, let host = matches.first {
                        memberships[host.id, default: []].insert(customer.slug)
                    }
                }
            }
        }
        self.owners = owners
        self.memberships = memberships
    }

    /// Record ids arrive as dashed UUIDs in any case, and the Rust side also
    /// persists the compact 32-hex spelling. All of them mean one id.
    private static func canonicalId(_ token: String) -> String {
        if let uuid = UUID(uuidString: token) { return uuid.uuidString.lowercased() }
        if token.count == 32, token.allSatisfy({ $0.isASCII && $0.isHexDigit }) {
            let chars = Array(token.lowercased())
            let parts = [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(chars[$0]) }
            return parts.joined(separator: "-")
        }
        return token
    }

    /// Resolve a `Site.hostIds` token (record id OR IP) to a real host, or
    /// nil when the token is an address more than one host carries. The
    /// returned host's `id` is always a real record id, so downstream daemon
    /// calls keep receiving an id even when the token was an IP.
    func host(forToken token: String) -> SshHostSummary? {
        if let host = byId[Self.canonicalId(token)] { return host }
        guard let matches = byAddress[token], matches.count == 1 else { return nil }
        return matches[0]
    }

    /// `host(forToken:)`, but only a host that belongs to `customerSlug`: not
    /// assigned to another customer, and linked by no other customer's site.
    func host(forToken token: String, customerSlug: String) -> SshHostSummary? {
        guard let host = host(forToken: token), knownSlugs.contains(customerSlug),
              !knownSlugs.contains(host.group) || host.group == customerSlug,
              owners[host.id] == [customerSlug] else { return nil }
        return host
    }

    /// The FortiGate that provisioning for `site` targets: the one FortiGate
    /// this site links, or nil. Never another site's firewall, and never the
    /// first of several.
    func provisioningHost(customer: Customer, site: Site) -> SshHostSummary? {
        guard customer.sites.filter({ $0.id == site.id }).count == 1 else { return nil }
        let firewalls = site.hostIds
            .compactMap { host(forToken: $0, customerSlug: customer.slug) }
            .filter { $0.deviceType == .fortigate }
        let distinct = Dictionary(firewalls.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return distinct.count == 1 ? distinct.values.first : nil
    }

    /// The customer slug a host belongs to, by precedence:
    ///   (a) `group` is exactly a known customer slug, else
    ///   (b) sites of exactly one customer link the host, unambiguously.
    /// Returns nil when the host is ungrouped or claimed by several.
    func customerSlug(forHost host: SshHostSummary) -> String? {
        if knownSlugs.contains(host.group) { return host.group }
        guard let slugs = memberships[host.id], slugs.count == 1,
              owners[host.id] == slugs else { return nil }
        return slugs.first
    }

    /// Every host record id belonging to a customer.
    func recordIds(forCustomer slug: String) -> Set<String> {
        Set(byId.values.filter { customerSlug(forHost: $0) == slug }.map(\.id))
    }
}
