import Foundation

// MARK: - Provisioning (customers + templates)
//
// Customers are TOML files under
// `~/Library/Application Support/SuperManager/customers/`,
// each containing a sites array. Templates render against a
// (customer, site, extras) triple via Tera on the daemon side.
// The GUI only manipulates the JSON shapes — never touches
// the TOML directly — so future changes to persistence
// (sqlite? CRDT?) don't ripple into Swift.

struct Vlan: Codable, Hashable, Identifiable {
    var id: UInt16   // VLAN id IS the unique key
    var name: String
    var subnet: String
    var purpose: String
}

struct Site: Codable, Hashable, Identifiable {
    var id: String
    var displayName: String
    var address: String
    var hostIds: [String]
    var wanType: String
    var wanStaticIp: String
    var lanBase: String
    var vlans: [Vlan]
    enum CodingKeys: String, CodingKey {
        case id, address, vlans
        case displayName = "display_name"
        case hostIds = "host_ids"
        case wanType = "wan_type"
        case wanStaticIp = "wan_static_ip"
        case lanBase = "lan_base"
    }
}

struct Customer: Codable, Hashable, Identifiable {
    var slug: String
    var displayName: String
    var contactName: String
    var contactEmail: String
    var notes: String
    var defaultTemplate: String?
    var mgmtAllowlistDomains: [String]
    var primaryDomain: String
    var sites: [Site]
    var id: String { slug }
    enum CodingKeys: String, CodingKey {
        case slug, notes, sites
        case displayName = "display_name"
        case contactName = "contact_name"
        case contactEmail = "contact_email"
        case defaultTemplate = "default_template"
        case mgmtAllowlistDomains = "mgmt_allowlist_domains"
        case primaryDomain = "primary_domain"
    }

    // Defaulting custom decoder so old TOML files without
    // mgmt_allowlist_domains keep working after upgrade.
    init(
        slug: String,
        displayName: String,
        contactName: String,
        contactEmail: String,
        notes: String,
        defaultTemplate: String?,
        mgmtAllowlistDomains: [String] = [],
        primaryDomain: String = "",
        sites: [Site]
    ) {
        self.slug = slug
        self.displayName = displayName
        self.contactName = contactName
        self.contactEmail = contactEmail
        self.notes = notes
        self.defaultTemplate = defaultTemplate
        self.mgmtAllowlistDomains = mgmtAllowlistDomains
        self.primaryDomain = primaryDomain
        self.sites = sites
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        slug = try c.decode(String.self, forKey: .slug)
        displayName = try c.decode(String.self, forKey: .displayName)
        contactName = (try? c.decode(String.self, forKey: .contactName)) ?? ""
        contactEmail = (try? c.decode(String.self, forKey: .contactEmail)) ?? ""
        notes = (try? c.decode(String.self, forKey: .notes)) ?? ""
        defaultTemplate = try? c.decode(String.self, forKey: .defaultTemplate)
        mgmtAllowlistDomains = (try? c.decode([String].self, forKey: .mgmtAllowlistDomains)) ?? []
        primaryDomain = (try? c.decode(String.self, forKey: .primaryDomain)) ?? ""
        sites = (try? c.decode([Site].self, forKey: .sites)) ?? []
    }
}

struct ProvisioningTemplate: Codable, Identifiable {
    let id: String
    let displayName: String
    let description: String
    let vendor: String
    let category: String
    let builtIn: Bool
    enum CodingKeys: String, CodingKey {
        case id, description, vendor, category
        case displayName = "display_name"
        case builtIn = "built_in"
    }
}

struct ProvisioningRenderResult: Codable {
    let templateId: String
    let output: String
    let extrasUsed: [String]
    enum CodingKeys: String, CodingKey {
        case output
        case templateId = "template_id"
        case extrasUsed = "extras_used"
    }
}

// MARK: - Provisioning deployment

struct Deployment: Codable, Identifiable {
    let id: String
    let hostId: String
    let customerSlug: String
    let siteId: String
    let templateId: String
    let startedAt: Date
    let finishedAt: Date?
    let status: DeploymentStatus
    let backupPath: String?
    let renderedConfig: String
    let linesPushed: UInt64
    let error: String?
    enum CodingKeys: String, CodingKey {
        case id, status, error
        case hostId = "host_id"
        case customerSlug = "customer_slug"
        case siteId = "site_id"
        case templateId = "template_id"
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case backupPath = "backup_path"
        case renderedConfig = "rendered_config"
        case linesPushed = "lines_pushed"
    }
}

enum DeploymentStatus: String, Codable {
    case running
    case succeeded
    case failed
    case rolledBack = "rolled_back"
}

// MARK: - Network detection

struct NetworkDetect: Codable {
    let defaultGateway: String?
    let primaryInterface: String?
    let primaryCidr: String?
    let lanBase: String?
    let primaryMac: String?
    let publicIp: String?
    let dnsServers: [String]
    enum CodingKeys: String, CodingKey {
        case dnsServers = "dns_servers"
        case defaultGateway = "default_gateway"
        case primaryInterface = "primary_interface"
        case primaryCidr = "primary_cidr"
        case lanBase = "lan_base"
        case primaryMac = "primary_mac"
        case publicIp = "public_ip"
    }
}

// MARK: - Push results (key push + multi-host operations)

struct PushResult: Codable, Identifiable {
    let hostId: String
    let hostLabel: String
    let success: Bool
    let message: String

    var id: String { hostId }

    enum CodingKeys: String, CodingKey {
        case hostId = "host_id"
        case hostLabel = "host_label"
        case success, message
    }
}
