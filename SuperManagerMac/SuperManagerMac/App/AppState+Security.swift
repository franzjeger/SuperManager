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
        // Kick off operation polling alongside the scan so the
        // Stop button can target whichever operation_id the
        // engine assigns. Cancelled when the scan task exits.
        let pollTask = Task { await pollOperationsWhileScanning() }
        defer {
            activeScanInFlight = false
            pollTask.cancel()
            runningOperations = []
        }
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

    /// Snapshot the current running long-running operations.
    /// UI uses this to populate the Stop button + per-op tooltips.
    func loadRunningOperations() async -> [RunningOperation]? {
        do {
            return try await client.call("operation_list")
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Request cooperative cancellation of an operation. The
    /// worker honours the request at its next safe checkpoint;
    /// this call returns as soon as the flag is set, NOT after
    /// the worker has stopped.
    @discardableResult
    func cancelOperation(id: String) async -> Bool {
        struct Resp: Codable { let cancelled: Bool }
        do {
            let r: Resp = try await client.call(
                "operation_cancel",
                params: ["id": id]
            )
            // Refresh the local snapshot immediately so the UI
            // can show "Cancelling…" without waiting for the
            // next poll tick.
            if let ops = await loadRunningOperations() {
                runningOperations = ops
            }
            return r.cancelled
        } catch {
            handleError(error)
            return false
        }
    }

    /// Poll `operation_list` ~every 500 ms while a scan is in
    /// flight. The Task is cancelled by the scan-runner when the
    /// scan exits, so this terminates cleanly.
    private func pollOperationsWhileScanning() async {
        while !Task.isCancelled {
            if let ops = await loadRunningOperations() {
                runningOperations = ops
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
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

    /// Result type that lets the caller distinguish "no PDF engine
    /// installed" (silent → WebKit fallback) from any other failure
    /// (still surface to the user). Uses the structured `rpcKind`
    /// from `ServiceError` now that the daemon emits
    /// `data.kind = "pdf_engine_missing"` for this specific case.
    enum PdfRenderResult {
        case ok(Data)
        case engineMissing(serverMessage: String)
        case otherFailure(Error)
    }

    func renderEngagementPdf(engagementId: String) async -> PdfRenderResult {
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
            guard let data = Data(base64Encoded: r.pdfBase64) else {
                return .otherFailure(ServiceError.noResult)
            }
            return .ok(data)
        } catch let err as ServiceError {
            // Structured-kind branch: the engine sets data.kind to
            // "pdf_engine_missing" when no LaTeX/wkhtml engine is on
            // PATH. The caller silently falls back to the WebKit /
            // NSPrintOperation path. All other RPC errors are
            // genuine failures the user should know about.
            if case .rpcError(let info) = err, info.kind == "pdf_engine_missing" {
                return .engineMissing(serverMessage: info.message)
            }
            return .otherFailure(err)
        } catch {
            return .otherFailure(error)
        }
    }

    /// Returns the engagement report as a standalone HTML document.
    /// Used as a PDF fallback when no LaTeX engine is installed —
    /// the caller renders this in `WKWebView` and calls `createPDF`.
    func renderEngagementHtml(engagementId: String, silent: Bool = false) async -> String? {
        struct Resp: Codable { let html: String }
        do {
            let r: Resp = try await client.call(
                "engagement_report_html",
                params: ["engagement_id": engagementId]
            )
            return r.html
        } catch {
            if silent {
                errorMessage = error.localizedDescription
            } else {
                handleError(error)
            }
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

    // MARK: - DNS AXFR (zone-transfer audit)

    struct DnsAxfrResult: Codable {
        let findings: [SecurityFinding]
    }

    /// Probe the given domain's authoritative nameservers for
    /// anonymous AXFR. Returns one finding per leaking NS (or
    /// empty when no NS allowed it).
    ///
    /// Backed by `discovery_dns_axfr` RPC. ~8 sec per NS, runs
    /// nameservers sequentially — typical domain has 2-4 NSes so
    /// expect 10-30 sec wall-clock total.
    func runDnsAxfr(domain: String) async -> [SecurityFinding]? {
        do {
            let result: DnsAxfrResult = try await client.call(
                "discovery_dns_axfr",
                params: ["domain": domain]
            )
            return result.findings
        } catch {
            handleError(error)
            return nil
        }
    }

    // MARK: - Traffic sniffer (cleartext-credential capture)

    struct TrafficAuditResult: Codable {
        let findings: [SecurityFinding]
        let evidenceFiles: [String]
        let packetsInspected: Int
        let eventsMatched: Int

        enum CodingKeys: String, CodingKey {
            case findings
            case evidenceFiles = "evidence_files"
            case packetsInspected = "packets_inspected"
            case eventsMatched = "events_matched"
        }
    }

    /// Analyse an existing pcap for cleartext-protocol exposure.
    /// Used both for one-shot analysis and for live-streaming
    /// polling: call this repeatedly while a capture is running
    /// and the partial-pcap tolerance in the engine ensures each
    /// call returns the cumulative findings so far.
    func analyseTrafficPcap(
        pcapPath: String,
        engagementId: String?
    ) async -> TrafficAuditResult? {
        var params: [String: Any] = ["pcap_path": pcapPath]
        if let e = engagementId {
            params["engagement_id"] = e
        }
        do {
            return try await client.call("discovery_analyse_pcap", params: params)
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Helper-side: start a tcpdump capture. The helper validates
    /// args + writes the pcap as root to a path under our data
    /// dir, chmod'd 0644 so the engine analyser can read it.
    /// Returns the pcap path + size on success.
    struct CaptureReport: Codable {
        let pcapPath: String
        let sizeBytes: Int
        let durationSecs: Int
        let interface: String
        let completedCleanly: Bool
        let packetCountEstimate: Int

        enum CodingKeys: String, CodingKey {
            case pcapPath = "pcap_path"
            case sizeBytes = "size_bytes"
            case durationSecs = "duration_secs"
            case interface
            case completedCleanly = "completed_cleanly"
            case packetCountEstimate = "packet_count_estimate"
        }
    }

    func startTrafficCapture(
        interface: String,
        outputPath: String,
        bpfFilter: String,
        durationSecs: Int
    ) async throws -> CaptureReport {
        return try await HelperClient.shared.callRaw(
            method: "traffic_capture",
            params: [
                "interface": interface,
                "output_path": outputPath,
                "bpf_filter": bpfFilter,
                "duration_secs": durationSecs,
            ]
        )
    }

    // MARK: - DNS health audit (SPF / DKIM / DMARC / DNSSEC)

    /// Run the SPF/DKIM/DMARC/DNSSEC audit for the given domain.
    /// Returns the structured report; the GUI renders the per-
    /// component states + emitted findings.
    func runDnsHealthAudit(domain: String) async -> DnsHealthReport? {
        do {
            return try await client.call(
                "dns_health_audit",
                params: ["domain": domain]
            )
        } catch {
            handleError(error)
            return nil
        }
    }

    // MARK: - Subdomain enumeration

    struct SubdomainEnumResult: Codable {
        let domain: String
        let found: [String]
        let certCount: Int

        enum CodingKeys: String, CodingKey {
            case domain
            case found
            case certCount = "cert_count"
        }
    }

    /// Query crt.sh for `*.<domain>` and return discovered subdomains.
    /// Useful for engagement-scope sanity checks ("what hostnames
    /// does this customer have that I might not know about?").
    func runSubdomainEnum(domain: String) async -> SubdomainEnumResult? {
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

    /// Build a BPF filter that covers ALL the cleartext-protocol
    /// detections in the engine: FTP, Telnet, HTTP-alt ports for
    /// basic-auth + form-POST, POP3, IMAP, SMTP-AUTH, SNMP v1/v2c,
    /// NTLM via SMB, MQTT.
    static let cleartextProtocolBpf: String =
        "tcp port 21 or tcp port 23 or tcp port 80 or tcp port 110 "
        + "or tcp port 143 or tcp port 25 or tcp port 465 or tcp port 587 "
        + "or tcp port 445 or tcp port 1883 or tcp port 8080 or tcp port 8000 "
        + "or tcp port 8888 or udp port 161 or udp port 162"
}
