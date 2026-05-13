import Foundation
import SwiftUI

// MARK: - Security: Engagement + Discovery

enum SecurityTechnique: String, Codable, CaseIterable, Hashable {
    case recon
    case discovery
    case vulnScan = "vuln_scan"
    case tlsAudit = "tls_audit"
    case credTest = "cred_test"
    case webExploit = "web_exploit"
    case smbEnum = "smb_enum"
    case snmpRead = "snmp_read"
    case wireless
    case dosTest = "dos_test"

    var label: String {
        switch self {
        case .recon:       return "Recon"
        case .discovery:   return "Discovery"
        case .vulnScan:    return "Vulnerability scan"
        case .tlsAudit:    return "TLS audit"
        case .credTest:    return "Credential testing"
        case .webExploit:  return "Web testing"
        case .smbEnum:     return "SMB enumeration"
        case .snmpRead:    return "SNMP read"
        case .wireless:    return "Wireless attacks"
        case .dosTest:     return "DoS testing"
        }
    }
}

struct EngagementEvent: Codable, Identifiable {
    let at: Date
    let technique: SecurityTechnique
    let target: String
    let action: String
    let findings: UInt32
    let notes: String
    var id: String { "\(at.timeIntervalSince1970)-\(action)" }
}

enum ScheduleCadence: String, Codable, CaseIterable, Identifiable {
    case hourly, daily, weekly, monthly
    var id: String { rawValue }
    var label: String {
        switch self {
        case .hourly: return "Hourly"
        case .daily:  return "Daily"
        case .weekly: return "Weekly"
        case .monthly: return "Monthly"
        }
    }
}

struct EngagementSchedule: Codable {
    let cadence: ScheduleCadence
    let nextScanAt: Date
    let lastScanAt: Date?
    enum CodingKeys: String, CodingKey {
        case cadence
        case nextScanAt = "next_scan_at"
        case lastScanAt = "last_scan_at"
    }
}

struct Engagement: Codable, Identifiable {
    var id: String
    var customerSlug: String
    var title: String
    var scopeCidrs: [String]
    var scopeHosts: [String]
    var exclusions: [String]
    var allowedTechniques: [SecurityTechnique]
    var startedAt: Date
    var expiresAt: Date
    var authorizedBy: String
    var authorizationDocPath: String?
    var log: [EngagementEvent]
    var notes: String
    var schedule: EngagementSchedule?
    /// When true, active scans started under this engagement reject
    /// any target IP that doesn't fall within `scopeCidrs`. When
    /// false (default), the GUI shows a soft warning for out-of-
    /// scope targets but the scan proceeds.
    var strictScope: Bool
    enum CodingKeys: String, CodingKey {
        case id, title, log, notes, schedule
        case customerSlug = "customer_slug"
        case scopeCidrs = "scope_cidrs"
        case scopeHosts = "scope_hosts"
        case exclusions
        case allowedTechniques = "allowed_techniques"
        case startedAt = "started_at"
        case expiresAt = "expires_at"
        case authorizedBy = "authorized_by"
        case authorizationDocPath = "authorization_doc_path"
        case strictScope = "strict_scope"
    }

    var isActive: Bool { expiresAt > Date() }

    // Custom decoder so old TOML files lacking optional
    // fields don't trip Decodable.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        customerSlug = (try? c.decode(String.self, forKey: .customerSlug)) ?? ""
        title = try c.decode(String.self, forKey: .title)
        scopeCidrs = (try? c.decode([String].self, forKey: .scopeCidrs)) ?? []
        scopeHosts = (try? c.decode([String].self, forKey: .scopeHosts)) ?? []
        exclusions = (try? c.decode([String].self, forKey: .exclusions)) ?? []
        allowedTechniques =
            (try? c.decode([SecurityTechnique].self, forKey: .allowedTechniques)) ?? []
        startedAt = try c.decode(Date.self, forKey: .startedAt)
        expiresAt = try c.decode(Date.self, forKey: .expiresAt)
        authorizedBy = (try? c.decode(String.self, forKey: .authorizedBy)) ?? ""
        authorizationDocPath = try? c.decode(String.self, forKey: .authorizationDocPath)
        log = (try? c.decode([EngagementEvent].self, forKey: .log)) ?? []
        notes = (try? c.decode(String.self, forKey: .notes)) ?? ""
        schedule = try? c.decodeIfPresent(EngagementSchedule.self, forKey: .schedule)
        strictScope = (try? c.decode(Bool.self, forKey: .strictScope)) ?? false
    }

    init(
        id: String,
        customerSlug: String,
        title: String,
        scopeCidrs: [String] = [],
        scopeHosts: [String] = [],
        exclusions: [String] = [],
        allowedTechniques: [SecurityTechnique] = [],
        startedAt: Date = Date(),
        expiresAt: Date,
        authorizedBy: String = "",
        authorizationDocPath: String? = nil,
        log: [EngagementEvent] = [],
        notes: String = "",
        schedule: EngagementSchedule? = nil,
        strictScope: Bool = false
    ) {
        self.id = id
        self.customerSlug = customerSlug
        self.title = title
        self.scopeCidrs = scopeCidrs
        self.scopeHosts = scopeHosts
        self.exclusions = exclusions
        self.allowedTechniques = allowedTechniques
        self.startedAt = startedAt
        self.expiresAt = expiresAt
        self.authorizedBy = authorizedBy
        self.authorizationDocPath = authorizationDocPath
        self.log = log
        self.notes = notes
        self.schedule = schedule
        self.strictScope = strictScope
    }
}

// MARK: Active scan + findings

enum FindingSeverity: String, Codable {
    case info, low, medium, high, critical
}

struct SecurityFinding: Codable, Identifiable {
    let id: String
    let hostIp: String
    let port: UInt16?
    let service: String?
    let severity: FindingSeverity
    let title: String
    let detail: String
    let recommendation: String
    let cve: String?
    let cvss: Double?
    var compoundId: String { "\(id)-\(hostIp)-\(port ?? 0)" }
    enum CodingKeys: String, CodingKey {
        case id, severity, title, detail, recommendation, cve, cvss, port, service
        case hostIp = "host_ip"
    }
}

struct TlsInfo: Codable {
    let version: String
    let cipher: String
    let certSubject: String?
    let certIssuer: String?
    let certSan: [String]
    let certExpiresIso: String?
    let selfSigned: Bool
    let weakCiphersAccepted: [String]
    let protocolsAccepted: [String]
    enum CodingKeys: String, CodingKey {
        case version, cipher
        case certSubject = "cert_subject"
        case certIssuer = "cert_issuer"
        case certSan = "cert_san"
        case certExpiresIso = "cert_expires_iso"
        case selfSigned = "self_signed"
        case weakCiphersAccepted = "weak_ciphers_accepted"
        case protocolsAccepted = "protocols_accepted"
    }

    // Tolerate older daemon responses that lack the cipher
    // matrix fields.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(String.self, forKey: .version)
        cipher = try c.decode(String.self, forKey: .cipher)
        certSubject = try c.decodeIfPresent(String.self, forKey: .certSubject)
        certIssuer = try c.decodeIfPresent(String.self, forKey: .certIssuer)
        certSan = (try? c.decode([String].self, forKey: .certSan)) ?? []
        certExpiresIso = try c.decodeIfPresent(String.self, forKey: .certExpiresIso)
        selfSigned = (try? c.decode(Bool.self, forKey: .selfSigned)) ?? false
        weakCiphersAccepted = (try? c.decode([String].self, forKey: .weakCiphersAccepted)) ?? []
        protocolsAccepted = (try? c.decode([String].self, forKey: .protocolsAccepted)) ?? []
    }
}

struct PortProbe: Codable, Identifiable {
    let port: UInt16
    let service: String
    let banner: String?
    let serverHeader: String?
    let title: String?
    let poweredBy: String?
    let tls: TlsInfo?
    let fingerprints: [String]
    let webPaths: [WebPath]
    let smb: SmbInfo?
    let snmp: SnmpDetail?
    var id: UInt16 { port }
    enum CodingKeys: String, CodingKey {
        case port, service, banner, title, tls, fingerprints, smb, snmp
        case serverHeader = "server_header"
        case poweredBy = "powered_by"
        case webPaths = "web_paths"
    }

    // Tolerate older snapshots that didn't include fingerprints/etc.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        port = try c.decode(UInt16.self, forKey: .port)
        service = try c.decode(String.self, forKey: .service)
        banner = try? c.decodeIfPresent(String.self, forKey: .banner)
        serverHeader = try? c.decodeIfPresent(String.self, forKey: .serverHeader)
        title = try? c.decodeIfPresent(String.self, forKey: .title)
        poweredBy = try? c.decodeIfPresent(String.self, forKey: .poweredBy)
        tls = try? c.decodeIfPresent(TlsInfo.self, forKey: .tls)
        fingerprints = (try? c.decode([String].self, forKey: .fingerprints)) ?? []
        webPaths = (try? c.decode([WebPath].self, forKey: .webPaths)) ?? []
        smb = try? c.decodeIfPresent(SmbInfo.self, forKey: .smb)
        snmp = try? c.decodeIfPresent(SnmpDetail.self, forKey: .snmp)
    }
}

struct WebPath: Codable, Identifiable {
    let path: String
    let status: UInt16
    let size: Int
    let contentType: String?
    let matched: Bool
    var id: String { path }
    enum CodingKeys: String, CodingKey {
        case path, status, size, matched
        case contentType = "content_type"
    }
}

struct SmbShare: Codable, Identifiable {
    let name: String
    let kind: String
    let comment: String
    var id: String { name }
}

struct SmbInfo: Codable {
    let shares: [SmbShare]
    let netbiosName: String?
    let workgroup: String?
    let serverRole: String?
    let nullSession: Bool
    enum CodingKeys: String, CodingKey {
        case shares, workgroup
        case netbiosName = "netbios_name"
        case serverRole = "server_role"
        case nullSession = "null_session"
    }
}

struct SnmpDetail: Codable {
    let community: String?
    let sysDescr: String?
    let sysName: String?
    let sysContact: String?
    let sysLocation: String?
    let sysUptime: String?
    let interfaces: [String]
    let rawCount: UInt32
    enum CodingKeys: String, CodingKey {
        case community, interfaces
        case sysDescr = "sys_descr"
        case sysName = "sys_name"
        case sysContact = "sys_contact"
        case sysLocation = "sys_location"
        case sysUptime = "sys_uptime"
        case rawCount = "raw_count"
    }
}

struct ActiveHost: Codable, Identifiable {
    let ip: String
    let mac: String?
    let hostname: String?
    let vendor: String?
    let probes: [PortProbe]
    let findingCount: UInt32
    let zone: String?
    /// Engine post-scan annotation: which configured UniFi
    /// controller (if any) claims this MAC. Drives the
    /// "managed by" badge + the controller-API-driven action
    /// menu in the scan-result row.
    let controllerState: ControllerStateRef?
    var id: String { ip }
    enum CodingKeys: String, CodingKey {
        case ip, mac, hostname, vendor, probes, zone
        case findingCount = "finding_count"
        case controllerState = "controller_state"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        ip = try c.decode(String.self, forKey: .ip)
        mac = try c.decodeIfPresent(String.self, forKey: .mac)
        hostname = try c.decodeIfPresent(String.self, forKey: .hostname)
        vendor = try c.decodeIfPresent(String.self, forKey: .vendor)
        probes = (try? c.decode([PortProbe].self, forKey: .probes)) ?? []
        findingCount = (try? c.decode(UInt32.self, forKey: .findingCount)) ?? 0
        zone = try c.decodeIfPresent(String.self, forKey: .zone)
        controllerState = try? c.decodeIfPresent(ControllerStateRef.self, forKey: .controllerState)
    }
}

/// Cross-reference annotation from the engine — a UniFi
/// controller's view of this scanned host. Codable to/from the
/// engine's `ControllerStateRef` JSON shape.
struct ControllerStateRef: Codable, Hashable {
    let controllerId: String
    let controllerLabel: String
    /// Engine-side human label: "connected", "pending-adoption",
    /// "managed-by-other", "isolated", "adopting", etc.
    let state: String
    let adopted: Bool
    let model: String?
    let name: String?
    enum CodingKeys: String, CodingKey {
        case state, adopted, model, name
        case controllerId = "controller_id"
        case controllerLabel = "controller_label"
    }
}

struct ActiveScanResult: Codable {
    let startedAt: Date
    let finishedAt: Date
    let hosts: [ActiveHost]
    let findings: [SecurityFinding]
    let engagementId: String?
    let diff: ScanDiff?
    let findingsScope: String?
    enum CodingKeys: String, CodingKey {
        case hosts, findings, diff
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case engagementId = "engagement_id"
        case findingsScope = "findings_scope"
    }
}

// MARK: Persisted findings (Track A)

/// Workflow state of a finding. Mirrors the engine's
/// `findings_store::Disposition` enum-with-payload.
enum Disposition: Codable, Hashable {
    case open
    case acceptedRisk(reason: String, until: Date?)
    case fixed(auto: Bool)
    case falsePositive(reason: String)

    // Custom Codable to match Rust `#[serde(tag = "kind", rename_all = "snake_case")]`.
    enum CodingKeys: String, CodingKey {
        case kind, reason, until, auto
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(String.self, forKey: .kind)
        switch kind {
        case "open":
            self = .open
        case "accepted_risk":
            self = .acceptedRisk(
                reason: (try? c.decode(String.self, forKey: .reason)) ?? "",
                until: try? c.decodeIfPresent(Date.self, forKey: .until)
            )
        case "fixed":
            self = .fixed(auto: (try? c.decode(Bool.self, forKey: .auto)) ?? false)
        case "false_positive":
            self = .falsePositive(reason: (try? c.decode(String.self, forKey: .reason)) ?? "")
        default:
            // Unknown disposition kind = schema drift between
            // app and daemon. Logging it surfaces the mismatch
            // instead of silently downgrading every new state
            // to .open and corrupting downstream logic.
            DebugLog.write("[Disposition] unknown kind '\(kind)' from daemon — falling back to .open")
            self = .open
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .open:
            try c.encode("open", forKey: .kind)
        case .acceptedRisk(let reason, let until):
            try c.encode("accepted_risk", forKey: .kind)
            try c.encode(reason, forKey: .reason)
            try c.encodeIfPresent(until, forKey: .until)
        case .fixed(let auto):
            try c.encode("fixed", forKey: .kind)
            try c.encode(auto, forKey: .auto)
        case .falsePositive(let reason):
            try c.encode("false_positive", forKey: .kind)
            try c.encode(reason, forKey: .reason)
        }
    }

    var label: String {
        switch self {
        case .open: return "Open"
        case .acceptedRisk: return "Accepted risk"
        case .fixed: return "Fixed"
        case .falsePositive: return "False positive"
        }
    }
}

struct DispositionChange: Codable, Hashable {
    let at: Date
    let by: String
    let from: Disposition
    let to: Disposition
    let note: String
}

struct PersistedFinding: Codable, Identifiable {
    let key: String
    let finding: SecurityFinding
    let disposition: Disposition
    let firstSeen: Date
    let lastSeen: Date
    let scanCount: UInt32
    let history: [DispositionChange]
    let note: String
    var id: String { key }
    enum CodingKeys: String, CodingKey {
        case key, finding, disposition, history, note
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
        case scanCount = "scan_count"
    }
}

struct ScanDiff: Codable {
    let newFindings: [PersistedFinding]
    let stillOpen: [PersistedFinding]
    let regressed: [PersistedFinding]
    let autoResolved: [PersistedFinding]
    let acceptedRisk: [PersistedFinding]
    let generatedAt: Date
    enum CodingKeys: String, CodingKey {
        case regressed
        case newFindings = "new_findings"
        case stillOpen = "still_open"
        case autoResolved = "auto_resolved"
        case acceptedRisk = "accepted_risk"
        case generatedAt = "generated_at"
    }
}

struct StoreSummary: Codable {
    let total: UInt32
    let open: UInt32
    let acceptedRisk: UInt32
    let fixed: UInt32
    let falsePositive: UInt32
    let critical: UInt32
    let high: UInt32
    let medium: UInt32
    let low: UInt32
    let info: UInt32
    let lastScanAt: Date?
    enum CodingKeys: String, CodingKey {
        case total, open, fixed, critical, high, medium, low, info
        case acceptedRisk = "accepted_risk"
        case falsePositive = "false_positive"
        case lastScanAt = "last_scan_at"
    }
}

enum RiskBand: String, Codable {
    case critical, elevated, moderate, low, clean

    var label: String {
        switch self {
        case .critical: return "Critical"
        case .elevated: return "Elevated"
        case .moderate: return "Moderate"
        case .low:      return "Low"
        case .clean:    return "Clean"
        }
    }

    var color: Color {
        switch self {
        case .critical: return .red
        case .elevated: return .orange
        case .moderate: return .yellow
        case .low:      return .blue
        case .clean:    return .green
        }
    }
}

struct HostRisk: Codable, Identifiable {
    let hostIp: String
    let score: UInt8
    let band: RiskBand
    let openFindings: UInt32
    let hint: String
    let critical: UInt32
    let high: UInt32
    let medium: UInt32
    let low: UInt32
    var id: String { hostIp }
    enum CodingKeys: String, CodingKey {
        case score, band, hint, critical, high, medium, low
        case hostIp = "host_ip"
        case openFindings = "open_findings"
    }
}

struct NotifyConfig: Codable {
    let webhooks: [String: String]
    let pagerdutyKeys: [String: String]
    let opsgenieKeys: [String: String]
    enum CodingKeys: String, CodingKey {
        case webhooks
        case pagerdutyKeys = "pagerduty_keys"
        case opsgenieKeys = "opsgenie_keys"
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        webhooks = (try? c.decode([String: String].self, forKey: .webhooks)) ?? [:]
        pagerdutyKeys = (try? c.decode([String: String].self, forKey: .pagerdutyKeys)) ?? [:]
        opsgenieKeys = (try? c.decode([String: String].self, forKey: .opsgenieKeys)) ?? [:]
    }
}

// MARK: - Subdomain enum + asset enrichment

struct SubdomainResult: Codable {
    let domain: String
    let found: [String]
    let certCount: UInt32
    let queriedAt: Date
    enum CodingKeys: String, CodingKey {
        case domain, found
        case certCount = "cert_count"
        case queriedAt = "queried_at"
    }
}

enum AssetZone: String, Codable {
    case loopback, internalZone = "internal", cgnat, multicast
    case linkLocal = "link-local"
    case publicZone = "public"
}

struct AssetEnrichment: Codable, Identifiable {
    let ip: String
    let reverseDns: String?
    let zone: AssetZone
    var id: String { ip }
    enum CodingKeys: String, CodingKey {
        case ip, zone
        case reverseDns = "reverse_dns"
    }
}

// MARK: - DNS health

/// Free-form DNS health report. Server returns rich enum-shaped
/// data — we keep the Swift side minimal: each state becomes a
/// `(label, raw)` pair derivable from the JSON without a per-case
/// enum that needs maintenance whenever the server adds states.
struct DnsHealthReport: Codable {
    let domain: String
    let dkimSelectorsFound: [String]
    let mxRecords: [String]
    let findings: [SecurityFinding]
    let spfLabel: String
    let dmarcLabel: String
    let mtaStsLabel: String
    let dnssecLabel: String

    enum CodingKeys: String, CodingKey {
        case domain, spf, dmarc, findings
        case dkimSelectorsFound = "dkim_selectors_found"
        case mtaSts = "mta_sts"
        case dnssec
        case mxRecords = "mx_records"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        domain = try c.decode(String.self, forKey: .domain)
        dkimSelectorsFound =
            (try? c.decode([String].self, forKey: .dkimSelectorsFound)) ?? []
        mxRecords = (try? c.decode([String].self, forKey: .mxRecords)) ?? []
        findings = (try? c.decode([SecurityFinding].self, forKey: .findings)) ?? []
        spfLabel = Self.enumLabel(from: try? c.decode(DnsHealthAnyJson.self, forKey: .spf))
        dmarcLabel = Self.enumLabel(from: try? c.decode(DnsHealthAnyJson.self, forKey: .dmarc))
        mtaStsLabel = Self.enumLabel(from: try? c.decode(DnsHealthAnyJson.self, forKey: .mtaSts))
        dnssecLabel = Self.enumLabel(from: try? c.decode(DnsHealthAnyJson.self, forKey: .dnssec))
    }

    // Encoding back is not used (one-way RPC) — synthesize a
    // minimal version so Codable conformance holds.
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(domain, forKey: .domain)
        try c.encode(dkimSelectorsFound, forKey: .dkimSelectorsFound)
        try c.encode(mxRecords, forKey: .mxRecords)
        try c.encode(findings, forKey: .findings)
    }

    /// Pull the variant tag out of a Rust serde-tagged enum
    /// like `{"Strict": {"record": "..."}}`. Returns "Strict" /
    /// "Missing" / etc. — sufficient for label rendering.
    private static func enumLabel(from any: DnsHealthAnyJson?) -> String {
        guard let any else { return "Unknown" }
        switch any.value {
        case let s as String:
            return s
        case let dict as [String: Any]:
            return dict.keys.first ?? "Unknown"
        default:
            return "Unknown"
        }
    }
}

/// Tiny type-erased JSON value used for fields whose Rust shape
/// is enum-tagged-with-payload — we only need the tag name, not
/// the payload, on the Swift side.
private struct DnsHealthAnyJson: Decodable {
    let value: Any
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let s = try? c.decode(String.self) { value = s; return }
        if let d = try? c.decode([String: DnsHealthAnyJson].self) {
            var dict: [String: Any] = [:]
            for (k, v) in d { dict[k] = v.value }
            value = dict; return
        }
        value = NSNull()
    }
}

// MARK: - Unified activity timeline + remediation script

enum ActivityKind: String, Codable {
    case passiveScan = "passive_scan"
    case activeScan = "active_scan"
    case complianceRun = "compliance_run"
    case deploy
    case dispositionChange = "disposition_change"
    case dnsAudit = "dns_audit"
    case finding
    case misc

    var icon: String {
        switch self {
        case .passiveScan: return "antenna.radiowaves.left.and.right"
        case .activeScan: return "scope"
        case .complianceRun: return "checkmark.shield"
        case .deploy: return "wand.and.stars"
        case .dispositionChange: return "tag.fill"
        case .dnsAudit: return "stethoscope"
        case .finding: return "exclamationmark.shield.fill"
        case .misc: return "circle.dotted"
        }
    }
}

struct ActivityEvent: Codable, Identifiable {
    let at: Date
    let kind: ActivityKind
    let title: String
    let detail: String
    let refId: String?
    var id: String { "\(at.timeIntervalSince1970)-\(refId ?? title)" }
    enum CodingKeys: String, CodingKey {
        case at, kind, title, detail
        case refId = "ref_id"
    }
}

struct RemediationScript: Codable {
    let script: String
    let applied: Int
    let totalFindings: Int?
    let message: String?
    enum CodingKeys: String, CodingKey {
        case script, applied, message
        case totalFindings = "total_findings"
    }
}
