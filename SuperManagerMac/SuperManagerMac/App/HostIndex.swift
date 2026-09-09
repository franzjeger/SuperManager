import Foundation

/// Reconciles legacy address links without treating an IP as a unique identity.
/// Ambiguous addresses and conflicting customer links require explicit repair.
struct HostIndex {
    private let byId: [String: SshHostSummary]
    private let byAddress: [String: [SshHostSummary]]
    private let owners: [String: Set<String>]
    private let memberships: [String: Set<String>]
    private let knownSlugs: Set<String>

    init(hosts: [SshHostSummary], customers: [Customer]) {
        byId = Dictionary(grouping: hosts, by: { Self.canonicalId($0.id) })
            .compactMapValues { $0.count == 1 ? $0.first : nil }
        byAddress = Dictionary(grouping: hosts.filter { !$0.hostname.isEmpty }, by: \.hostname)
        knownSlugs = Set(customers.map(\.slug))
        var links: [String: Set<String>] = [:]
        var resolvedLinks: [String: Set<String>] = [:]
        for customer in customers {
            for site in customer.sites {
                for token in site.hostIds {
                    // Preserve every claim, including ambiguous aliases. A later
                    // mutation must never silently pick the last matching host.
                    let matches = byId[Self.canonicalId(token)].map { [$0] } ?? byAddress[token] ?? []
                    for host in matches { links[host.id, default: []].insert(customer.slug) }
                    if matches.count == 1, let host = matches.first {
                        resolvedLinks[host.id, default: []].insert(customer.slug)
                    }
                }
            }
        }
        owners = links
        memberships = resolvedLinks
    }

    private static func canonicalId(_ token: String) -> String {
        if let uuid = UUID(uuidString: token) { return uuid.uuidString.lowercased() }
        // Rust also writes the compact 32-hex spelling in persisted references.
        if token.count == 32, token.utf8.allSatisfy({
            (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
        }) {
            let chars = Array(token)
            let parts = [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(chars[$0]) }
            return parts.joined(separator: "-").lowercased()
        }
        return token
    }

    func host(forToken token: String) -> SshHostSummary? {
        if let host = byId[Self.canonicalId(token)] { return host }
        guard let matches = byAddress[token], matches.count == 1 else { return nil }
        return matches[0]
    }

    func host(forToken token: String, customerSlug: String) -> SshHostSummary? {
        guard let host = host(forToken: token), knownSlugs.contains(customerSlug),
              !knownSlugs.contains(host.group) || host.group == customerSlug,
              owners[host.id] == Set([customerSlug]) else { return nil }
        return host
    }

    /// No other-site fallback and no arbitrary first firewall when several exist.
    func provisioningHost(customer: Customer, site: Site) -> SshHostSummary? {
        guard customer.sites.filter({ $0.id == site.id }).count == 1 else { return nil }
        let matches = site.hostIds.compactMap { host(forToken: $0, customerSlug: customer.slug) }
            .filter { $0.deviceType == .fortigate }
        let unique = Dictionary(matches.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return unique.count == 1 ? unique.values.first : nil
    }

    func customerSlug(forHost host: SshHostSummary) -> String? {
        if knownSlugs.contains(host.group) { return host.group }
        guard let slugs = memberships[host.id], slugs.count == 1,
              owners[host.id] == slugs else { return nil }
        return slugs.first
    }

    func recordIds(forCustomer slug: String) -> Set<String> {
        Set(byId.values.filter { customerSlug(forHost: $0) == slug }.map(\.id))
    }
}
