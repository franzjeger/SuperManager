import AppKit
import Foundation
import SwiftUI

extension AppState {
    func detectNetwork() async -> NetworkDetect? {
        do {
            return try await client.call("network_detect")
        } catch {
            handleError(error)
            return nil
        }
    }

    // MARK: - Track 5: tool dependencies + DNS health + CVE feed

    func loadToolStatus() async -> [ToolInfo]? {
        do {
            return try await client.call("tools_status")
        } catch {
            handleError(error)
            return nil
        }
    }

    func auditDnsHealth(domain: String, scope: String? = nil) async -> DnsHealthReport? {
        var params: [String: Any] = ["domain": domain]
        if let s = scope { params["scope"] = s }
        do {
            return try await client.call("dns_health_audit", params: params)
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadCveFeedStatus() async -> CveFeedStatus? {
        do {
            return try await client.call("cve_feed_status")
        } catch {
            handleError(error)
            return nil
        }
    }

    @discardableResult
    func refreshCveFeed() async -> Int? {
        struct Resp: Codable { let added: Int }
        do {
            let r: Resp = try await client.call("cve_feed_refresh")
            return r.added
        } catch {
            handleError(error)
            return nil
        }
    }

    // MARK: - Subdomain enum + asset enrichment + PDF report

    func enumerateSubdomains(domain: String) async -> SubdomainResult? {
        do {
            return try await client.call(
                "subdomain_enum",
                params: ["domain": domain]
            )
        } catch {
            handleError(error)
            return nil
        }
    }

    func enrichAssets(ips: [String]) async -> [AssetEnrichment]? {
        do {
            return try await client.call(
                "asset_enrich",
                params: ["ips": ips]
            )
        } catch {
            handleError(error)
            return nil
        }
    }
}
