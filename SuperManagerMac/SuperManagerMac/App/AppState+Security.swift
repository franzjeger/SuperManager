import AppKit
import Foundation
import SwiftUI

extension AppState {
    func refreshEngagements() async {
        do {
            engagements = try await client.call("engagement_list")
        } catch {
            handleError(error)
        }
    }

    @discardableResult
    func saveEngagement(_ engagement: Engagement) async -> Engagement? {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        do {
            let data = try encoder.encode(engagement)
            let json = try JSONSerialization.jsonObject(with: data)
            guard let dict = json as? [String: Any] else { return nil }
            let saved: Engagement = try await client.call("engagement_save", params: dict)
            await refreshEngagements()
            return saved
        } catch {
            handleError(error)
            return nil
        }
    }

    @discardableResult
    func deleteEngagement(id: String) async -> Bool {
        struct R: Codable { let deleted: Bool }
        do {
            let _: R = try await client.call("engagement_delete", params: ["id": id])
            await refreshEngagements()
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    func runPassiveDiscovery(customerSlug: String?, engagementId: String?) async -> PassiveScanResult? {
        guard !discoveryInFlight else { return nil }
        discoveryInFlight = true
        defer { discoveryInFlight = false }
        var params: [String: Any] = [:]
        if let s = customerSlug { params["customer_slug"] = s }
        if let e = engagementId { params["engagement_id"] = e }
        do {
            let result: PassiveScanResult = try await client.call(
                "discovery_passive_scan",
                params: params
            )
            lastDiscoveryResult = result
            return result
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadDiscoveryInventory(customerSlug: String) async -> [DiscoveredHost]? {
        do {
            return try await client.call(
                "discovery_inventory",
                params: ["customer_slug": customerSlug]
            )
        } catch {
            handleError(error)
            return nil
        }
    }

    func runActiveDiscovery(
        targets: [String],
        customerSlug: String?,
        engagementId: String?
    ) async -> ActiveScanResult? {
        guard !activeScanInFlight else { return nil }
        activeScanInFlight = true
        defer { activeScanInFlight = false }
        var params: [String: Any] = ["targets": targets, "max_targets": 256]
        if let s = customerSlug { params["customer_slug"] = s }
        if let e = engagementId { params["engagement_id"] = e }
        do {
            let result: ActiveScanResult = try await client.call(
                "discovery_active_scan",
                params: params
            )
            lastActiveScan = result
            return result
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadFindings(customerSlug: String) async -> [SecurityFinding]? {
        do {
            return try await client.call(
                "discovery_findings",
                params: ["customer_slug": customerSlug]
            )
        } catch {
            handleError(error)
            return nil
        }
    }

    // MARK: Persisted-findings RPCs

    /// Resolve the persistence scope for a finding store request:
    /// prefer customer slug, fall back to engagement id when the
    /// engagement is "ad-hoc" (no slug).
    fileprivate func findingsScopeParams(
        scope: String?,
        engagementId: String?
    ) -> [String: Any] {
        var params: [String: Any] = [:]
        if let s = scope, !s.isEmpty { params["scope"] = s }
        if let e = engagementId, !e.isEmpty { params["engagement_id"] = e }
        return params
    }

    func loadPersistedFindings(
        scope: String? = nil,
        engagementId: String? = nil
    ) async -> [PersistedFinding]? {
        let params = findingsScopeParams(scope: scope, engagementId: engagementId)
        guard !params.isEmpty else { return nil }
        do {
            return try await client.call("findings_list", params: params)
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadFindingsSummary(
        scope: String? = nil,
        engagementId: String? = nil
    ) async -> StoreSummary? {
        let params = findingsScopeParams(scope: scope, engagementId: engagementId)
        guard !params.isEmpty else { return nil }
        do {
            return try await client.call("findings_summary", params: params)
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadHostRisks(
        scope: String? = nil,
        engagementId: String? = nil
    ) async -> [HostRisk]? {
        let params = findingsScopeParams(scope: scope, engagementId: engagementId)
        guard !params.isEmpty else { return nil }
        do {
            return try await client.call("findings_risk_hosts", params: params)
        } catch {
            handleError(error)
            return nil
        }
    }

    func setFindingDisposition(
        scope: String? = nil,
        engagementId: String? = nil,
        key: String,
        disposition: Disposition,
        note: String
    ) async -> PersistedFinding? {
        var params = findingsScopeParams(scope: scope, engagementId: engagementId)
        guard !params.isEmpty else { return nil }
        params["key"] = key
        if let dispJson = try? JSONEncoder().encode(disposition),
           let dispObj = try? JSONSerialization.jsonObject(with: dispJson) {
            params["disposition"] = dispObj
        } else {
            return nil
        }
        params["note"] = note
        params["by"] = "operator"
        do {
            return try await client.call("findings_set_disposition", params: params)
        } catch {
            handleError(error)
            return nil
        }
    }

    func renderEngagementReport(engagementId: String) async -> String? {
        struct Resp: Codable { let markdown: String }
        do {
            let r: Resp = try await client.call(
                "engagement_report",
                params: ["engagement_id": engagementId]
            )
            return r.markdown
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadNotifyConfig() async -> NotifyConfig? {
        do {
            return try await client.call("notify_get_config")
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadActivityTimeline(customerSlug: String, limit: Int = 200) async -> [ActivityEvent]? {
        do {
            return try await client.call(
                "activity_timeline",
                params: ["customer_slug": customerSlug, "limit": limit]
            )
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Generate a remediation shell-script for one finding (`key`)
    /// or every open finding on a single host (`host`).
    func generateRemediationScript(
        scope: String,
        host: String? = nil,
        key: String? = nil
    ) async -> RemediationScript? {
        var params: [String: Any] = ["scope": scope]
        if let h = host { params["host"] = h }
        if let k = key { params["key"] = k }
        do {
            return try await client.call("remediation_script", params: params)
        } catch {
            handleError(error)
            return nil
        }
    }

    func renderEngagementPdf(engagementId: String) async -> Data? {
        struct Resp: Codable {
            let pdfBase64: String
            let size: Int
            enum CodingKeys: String, CodingKey {
                case pdfBase64 = "pdf_base64"
                case size
            }
        }
        do {
            let r: Resp = try await client.call(
                "engagement_report_pdf",
                params: ["engagement_id": engagementId]
            )
            return Data(base64Encoded: r.pdfBase64)
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Returns the engagement report as a standalone HTML document.
    /// Used as a PDF fallback when no LaTeX engine is installed —
    /// the caller renders this in `WKWebView` and calls `createPDF`.
    func renderEngagementHtml(engagementId: String) async -> String? {
        struct Resp: Codable { let html: String }
        do {
            let r: Resp = try await client.call(
                "engagement_report_html",
                params: ["engagement_id": engagementId]
            )
            return r.html
        } catch {
            handleError(error)
            return nil
        }
    }

    @discardableResult
    func setEngagementSchedule(
        engagementId: String,
        cadence: ScheduleCadence?
    ) async -> Engagement? {
        var params: [String: Any] = ["engagement_id": engagementId]
        if let c = cadence {
            params["cadence"] = c.rawValue
        }
        do {
            let updated: Engagement = try await client.call(
                "engagement_set_schedule",
                params: params
            )
            await refreshEngagements()
            return updated
        } catch {
            handleError(error)
            return nil
        }
    }

    @discardableResult
    func setNotifyPagerduty(scope: String, key: String) async -> Bool {
        struct Resp: Codable { let ok: Bool }
        do {
            let _: Resp = try await client.call(
                "notify_set_pagerduty",
                params: ["scope": scope, "key": key]
            )
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    @discardableResult
    func setNotifyOpsgenie(scope: String, key: String) async -> Bool {
        struct Resp: Codable { let ok: Bool }
        do {
            let _: Resp = try await client.call(
                "notify_set_opsgenie",
                params: ["scope": scope, "key": key]
            )
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    func setNotifyWebhook(scope: String, webhookUrl: String) async -> Bool {
        struct Resp: Codable { let ok: Bool }
        do {
            let _: Resp = try await client.call(
                "notify_set_webhook",
                params: ["scope": scope, "webhook_url": webhookUrl]
            )
            return true
        } catch {
            handleError(error)
            return false
        }
    }

    func testDefaultCreds(host: String, port: UInt16, service: String) async -> [SecurityFinding]? {
        do {
            return try await client.call(
                "security_test_default_creds",
                params: ["host": host, "port": port, "service": service]
            )
        } catch {
            handleError(error)
            return nil
        }
    }
}
