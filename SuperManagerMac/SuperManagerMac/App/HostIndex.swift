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
struct HostIndex {
    private let byId: [String: SshHostSummary]    // record id -> host
    private let byIp: [String: SshHostSummary]    // host.hostname (IP/DNS) -> host
    private let slugForRecordId: [String: String] // record id -> customer slug (via Site.hostIds)
    private let recordIdsBySlug: [String: Set<String>]
    private let knownSlugs: Set<String>

    init(hosts: [SshHostSummary], customers: [Customer]) {
        var byId: [String: SshHostSummary] = [:]
        var byIp: [String: SshHostSummary] = [:]
        for h in hosts {
            byId[h.id] = h
            // hostname == IP for discovered hosts; this is the join that
            // NetworkScanSheet already does ad-hoc, generalized.
            if !h.hostname.isEmpty { byIp[h.hostname] = h }
        }

        var slugForRecordId: [String: String] = [:]
        var recordIdsBySlug: [String: Set<String>] = [:]
        for c in customers {
            for site in c.sites {
                for token in site.hostIds {
                    // A Site.hostIds token may be a record id (intended) or an
                    // IP (what writers actually store). Resolve either way.
                    if let h = byId[token] ?? byIp[token] {
                        slugForRecordId[h.id] = c.slug
                        recordIdsBySlug[c.slug, default: []].insert(h.id)
                    }
                }
            }
        }

        self.byId = byId
        self.byIp = byIp
        self.slugForRecordId = slugForRecordId
        self.recordIdsBySlug = recordIdsBySlug
        self.knownSlugs = Set(customers.map(\.slug))
    }

    /// Resolve a `Site.hostIds` token (record id OR IP) to a real host.
    /// The returned host's `id` is always a real record id, so downstream
    /// daemon calls keep receiving an id even when the token was an IP.
    func host(forToken token: String) -> SshHostSummary? {
        byId[token] ?? byIp[token]
    }

    /// The customer slug a host belongs to, by precedence:
    ///   (a) `group` is exactly a known customer slug, else
    ///   (b) the host is reachable through some `Site.hostIds` (by id or IP).
    /// Returns nil only when the host is genuinely ungrouped.
    func customerSlug(forHost host: SshHostSummary) -> String? {
        if knownSlugs.contains(host.group) { return host.group }
        return slugForRecordId[host.id]
    }

    /// Bridge an IP-keyed security finding (`HostRisk.hostIp`) back to a real
    /// host record. Used by Fleet / Security to make findings actionable.
    func host(forIp ip: String) -> SshHostSummary? {
        byIp[ip]
    }

    /// Every host record id belonging to a customer — lets Fleet fold the
    /// record-id-keyed compliance store into per-customer cards.
    func recordIds(forCustomer slug: String) -> Set<String> {
        recordIdsBySlug[slug] ?? []
    }
}
