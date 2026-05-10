import AppKit
import Foundation
import SwiftUI

extension AppState {
    @discardableResult
    func runCompliance(hostId: String) async -> ComplianceRun? {
        guard !complianceRunInFlight.contains(hostId) else { return nil }
        complianceRunInFlight.insert(hostId)
        defer { complianceRunInFlight.remove(hostId) }
        do {
            let run: ComplianceRun = try await client.call(
                "compliance_run",
                params: ["host_id": hostId, "triggered_by": "manual"]
            )
            complianceLatestRun[hostId] = run
            // Push the new run to the front of the cached history
            // so the UI updates without a separate fetch round.
            let summary = ComplianceRunSummary(
                id: run.id,
                startedAt: run.startedAt,
                score: run.score,
                passed: run.passed,
                failed: run.failed,
                errored: run.errored,
                firmware: run.firmware,
                triggeredBy: run.triggeredBy
            )
            var existing = complianceHistory[hostId] ?? []
            existing.insert(summary, at: 0)
            complianceHistory[hostId] = existing
            // Auto-load drift against the previous run so the
            // "since last scan" panel renders without waiting for
            // a second user action. First-ever run will get a
            // drift report with previous_run_id == nil.
            await loadComplianceDrift(hostId: hostId, runId: run.id)
            return run
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadComplianceHistory(hostId: String, limit: Int = 50) async {
        do {
            let summaries: [ComplianceRunSummary] = try await client.call(
                "compliance_history",
                params: ["host_id": hostId, "limit": limit]
            )
            complianceHistory[hostId] = summaries
        } catch {
            DebugLog.write("[compliance] history fetch failed for host \(hostId): \(error)")
        }
    }

    @discardableResult
    func loadComplianceRun(hostId: String, runId: String) async -> ComplianceRun? {
        do {
            let run: ComplianceRun = try await client.call(
                "compliance_get_run",
                params: ["host_id": hostId, "run_id": runId]
            )
            complianceLatestRun[hostId] = run
            return run
        } catch {
            handleError(error)
            return nil
        }
    }

    func loadComplianceCheckLibrary() async {
        do {
            let checks: [ComplianceCheckDefinition] = try await client.call(
                "compliance_list_checks"
            )
            complianceCheckLibrary = checks
        } catch {
            DebugLog.write("[compliance] check library load failed: \(error)")
        }
    }

    func loadComplianceDrift(hostId: String, runId: String) async {
        do {
            let report: DriftReport = try await client.call(
                "compliance_drift",
                params: ["host_id": hostId, "run_id": runId]
            )
            complianceDrift[hostId] = report
        } catch {
            DebugLog.write("[compliance] drift fetch failed for host \(hostId), run \(runId): \(error)")
        }
    }

    /// Concurrent client-side fan-out version of scan-all. Calls
    /// `compliance_run` per host in parallel (limited to 4 in
    /// flight at a time so we don't hammer the daemon's SSH pool)
    /// and updates `complianceScanProgress` as each host
    /// transitions queued → scanning → done/failed. The UI uses
    /// that map to render a per-host progress strip instead of
    /// the opaque single-spinner that `runComplianceScanAll`
    /// produces.
    ///
    /// Skips hosts that lack an API token — same as the daemon's
    /// scan-all does.
    @discardableResult
    func runComplianceScanAllConcurrent() async -> [ComplianceScanAllResult] {
        guard !complianceScanAllInFlight else { return [] }
        complianceScanAllInFlight = true
        defer {
            complianceScanAllInFlight = false
            // Leave progress visible briefly so the user can see
            // the final state; clear from caller via
            // `clearComplianceScanProgress()` after toast settles.
        }
        let hosts = sshHosts.filter { $0.deviceType == .fortigate && $0.hasApi }
        guard !hosts.isEmpty else { return [] }
        // Reset progress map: every host starts queued.
        complianceScanProgress = Dictionary(uniqueKeysWithValues:
            hosts.map { ($0.id, "queued") })

        // Bounded-concurrency TaskGroup. 4 = matches the daemon's
        // SSH pool default; higher and we'd queue inside the
        // daemon for no observable speedup.
        let maxConcurrent = 4
        var results: [ComplianceScanAllResult] = []
        await withTaskGroup(of: ComplianceScanAllResult.self) { group in
            var iterator = hosts.makeIterator()
            // Prime the pump.
            for _ in 0..<maxConcurrent {
                if let host = iterator.next() {
                    group.addTask { [self] in
                        await scanOneHostForFanOut(host)
                    }
                }
            }
            // As each finishes, kick off the next.
            while let r = await group.next() {
                results.append(r)
                if let host = iterator.next() {
                    group.addTask { [self] in
                        await scanOneHostForFanOut(host)
                    }
                }
            }
        }
        return results
    }

    private func scanOneHostForFanOut(_ host: SshHostSummary) async -> ComplianceScanAllResult {
        complianceScanProgress[host.id] = "scanning"
        if let run = await runCompliance(hostId: host.id) {
            complianceScanProgress[host.id] = "done"
            return ComplianceScanAllResult(
                hostId: host.id,
                hostLabel: host.label,
                runId: run.id,
                score: run.score,
                error: nil
            )
        }
        complianceScanProgress[host.id] = "failed"
        return ComplianceScanAllResult(
            hostId: host.id,
            hostLabel: host.label,
            runId: nil,
            score: nil,
            error: "scan failed"
        )
    }

    /// Wipe the progress map. The UI surfaces it briefly after
    /// completion so the user sees the final state; the column
    /// view calls this after a few seconds.
    func clearComplianceScanProgress() {
        complianceScanProgress = [:]
    }

    /// Run compliance against every FortiGate host with an API
    /// token. `unconditional == false` skips hosts whose last
    /// run is < 24h old (matches the auto-scan-on-launch path).
    /// Returns per-host outcomes; the GUI surfaces them in a
    /// transient toast.
    @discardableResult
    func runComplianceScanAll(unconditional: Bool) async -> [ComplianceScanAllResult]? {
        guard !complianceScanAllInFlight else { return nil }
        complianceScanAllInFlight = true
        defer { complianceScanAllInFlight = false }

        var params: [String: Any] = [
            "triggered_by": unconditional ? "manual" : "scheduled",
        ]
        if !unconditional {
            params["min_age_hours"] = 24
        }
        do {
            let results: [ComplianceScanAllResult] = try await client.call(
                "compliance_scan_all",
                params: params
            )
            // Refresh per-host history caches so the sidebar
            // pills update immediately without a per-host fetch.
            for r in results where r.runId != nil {
                await loadComplianceHistory(hostId: r.hostId, limit: 50)
                if let runId = r.runId {
                    await loadComplianceDrift(hostId: r.hostId, runId: runId)
                    if let drift = complianceDrift[r.hostId] {
                        await maybeNotifyDrift(
                            hostId: r.hostId,
                            hostLabel: r.hostLabel,
                            drift: drift
                        )
                    }
                }
            }
            return results
        } catch {
            handleError(error)
            return nil
        }
    }

    /// Called once per app launch. If the user has opted in,
    /// fires `runComplianceScanAll(unconditional: false)` so any
    /// FortiGate host that hasn't been scanned in 24h gets fresh
    /// data without manual interaction. Daemon-side recency
    /// filter handles the "host scanned 1h ago" case — we don't
    /// need to dedupe here.
    func kickComplianceAutoScanIfDue() async {
        guard AppSettings.shared.complianceAutoScanEnabled else { return }
        // No FortiGate hosts at all? Don't bother.
        let hasAny = sshHosts.contains { $0.deviceType == .fortigate && $0.hasApi }
        guard hasAny else { return }
        DebugLog.write("[compliance] auto-scan kick: enabled and host(s) present")
        _ = await runComplianceScanAll(unconditional: false)
    }

    /// If the drift report shows new failures or a score drop,
    /// post a system notification (subject to user prefs).
    fileprivate func maybeNotifyDrift(
        hostId: String,
        hostLabel: String,
        drift: DriftReport
    ) async {
        guard AppSettings.shared.notifyComplianceDrift else { return }
        // Only notify when meaningfully worse — ignore ±1 score
        // jitter and only-newly-passing improvements.
        let regressed = drift.scoreDelta < -1 || !drift.newlyFailing.isEmpty
        guard regressed else { return }
        let title = "Compliance regression: \(hostLabel)"
        let bodyParts: [String] = {
            var p: [String] = []
            if let prev = drift.previousScore {
                p.append("Score \(prev) → \(drift.currentScore) (\(drift.scoreDelta > 0 ? "+" : "")\(drift.scoreDelta))")
            } else {
                p.append("Score \(drift.currentScore)")
            }
            if !drift.newlyFailing.isEmpty {
                p.append("\(drift.newlyFailing.count) new failure\(drift.newlyFailing.count == 1 ? "" : "s")")
            }
            return p
        }()
        NotificationManager.complianceDrift(
            id: "compliance-drift-\(hostId)",
            title: title,
            body: bodyParts.joined(separator: " · ")
        )
    }

    /// Fetch the Markdown report for a run. Returns nil + toast on error.
    func renderComplianceReport(hostId: String, runId: String) async -> String? {
        struct ReportResponse: Codable { let markdown: String }
        do {
            let resp: ReportResponse = try await client.call(
                "compliance_render_report",
                params: ["host_id": hostId, "run_id": runId]
            )
            return resp.markdown
        } catch {
            handleError(error)
            return nil
        }
    }
}
