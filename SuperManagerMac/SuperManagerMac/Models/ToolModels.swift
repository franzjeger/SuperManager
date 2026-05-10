import Foundation

// MARK: - Track 5: tool dependencies + CVE feed

struct ToolInfo: Codable, Identifiable {
    let name: String
    let purpose: String
    let installed: Bool
    let version: String?
    let path: String?
    let brewFormula: String?
    let source: String
    var id: String { name }
    enum CodingKeys: String, CodingKey {
        case name, purpose, installed, version, path, source
        case brewFormula = "brew_formula"
    }
}

struct CveFeedStatus: Codable {
    let total: Int
    let lastFetchedAt: Date?
    enum CodingKeys: String, CodingKey {
        case total
        case lastFetchedAt = "last_fetched_at"
    }
}
