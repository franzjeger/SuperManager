// Models that cross the JSON-RPC boundary for DNS health, subdomain
// enumeration and notification config, plus the finding vocabulary
// (`FindingSeverity`, `SecurityFinding`, `Disposition`, `RiskBand`)
// the remaining UI and tests are built on.
//
// The engagement/active-scan half of this file went with the
// Fleet/Recon/Security cut. The engine still owns those capabilities
// for the Linux console; what lived here was only the macOS mirror.

import SwiftUI

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
