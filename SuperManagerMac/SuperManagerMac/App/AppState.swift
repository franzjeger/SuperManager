import AppKit
import Foundation
import SwiftUI

/// Observable application state.
@MainActor
@Observable
class AppState {
    // Navigation
    var selectedSection: AppSection = .ssh
    var selectedHostId: String?
    var selectedKeyId: String?
    var selectedProfileId: String?

    // SSH
    var sshHosts: [SshHostSummary] = []
    var sshKeys: [SshKeySummary] = []
    var hostHealth: [String: Bool] = [:]

    // VPN
    var vpnProfiles: [VpnProfileSummary] = []
    var vpnState: VpnConnectionState = .disconnected
    /// Per-profile connection state, keyed by profile id. Populated
    /// by the global VPN poller (`startVpnStatusPolling`). Drives
    /// the green-dot indicators in the VPN list — without this, you
    /// can't tell at a glance which profile is currently active.
    /// "connected" / "connecting" / "disconnected" / `nil` (not yet
    /// polled).
    var vpnConnectionStates: [String: String] = [:]

    // MARK: - Tailscale

    /// Latest snapshot of `tailscale status --json`. Refreshed every
    /// few seconds while the Tailscale section is selected. `nil`
    /// before the first refresh OR if the daemon isn't reachable —
    /// the view differentiates "loading" from "not installed" via
    /// `tailscaleError`.
    var tailscaleStatus: TailscaleStatus?
    /// Last error from `TailscaleClient.status()`. Surfaced in the
    /// list-empty-state. Common values: "Tailscale not installed",
    /// "daemon not running."
    var tailscaleError: String?
    /// Selected peer in the Tailnet list, drives the detail view.
    var selectedTailscalePeerId: String?
    /// While non-nil, the Tailscale auth flow is in progress and the
    /// CLI gave us this URL to complete authentication in a browser.
    /// The header view binds a sheet to this; clearing it cancels
    /// the visible "waiting for browser" UI (the spawned `tailscale
    /// up` subprocess keeps running until the user finishes the
    /// browser flow or the daemon-side timeout expires).
    var pendingTailscaleAuthURL: URL?
    /// Last error from a Tailscale login/logout/up/down RPC.
    /// Surfaced inline in the header instead of a system alert —
    /// auth flows fail in mundane ways (network down, browser
    /// cancelled) and a modal alert for each is overkill.
    var tailscaleActionError: String?
    /// Current Tailscale preferences (from `tailscale debug prefs`).
    /// Refreshed alongside status, plus once explicitly when the
    /// user opens the settings sheet so they always see a fresh
    /// snapshot. nil before the first refresh OR if the daemon is
    /// down.
    var tailscalePrefs: TailscalePrefs?

    // UI
    var isLocked = false
    var daemonAvailable = false
    var statusMessage: String?
    /// True when the alert is currently visible. Bound to via
    /// `RootView.alertBinding`. Setting back to false drains the
    /// next queued error (see `dismissCurrentError`).
    var showingError = false
    /// Message currently displayed in the alert. Set by
    /// `handleError` (or directly by code that writes the alert
    /// text itself, e.g. `errorMessage = "Failed to write report"`).
    var errorMessage = ""
    /// FIFO queue of errors that arrived while the alert was
    /// already showing. Without this, `handleError` calls in rapid
    /// succession would each overwrite `errorMessage` and the user
    /// would see only the last one. With it, dismissing the alert
    /// pops the next message into view.
    private var errorQueue: [String] = []

    // Service client
    let client = ServiceClient()

    /// Background task that polls every VPN profile's connection
    /// state every few seconds, populating `vpnConnectionStates`.
    /// Started by `connectToDaemon`; cancelled on app shutdown by
    /// SwiftUI's normal lifecycle.
    private var vpnStatusPollTask: Task<Void, Never>?
    /// Deadline for the "fast-poll window". When set in the future,
    /// the VPN-status poll loop drops to 500 ms cadence so the UI
    /// updates within half a second of a user-initiated connect /
    /// disconnect / etc. Cleared (read as "in the past") once the
    /// window expires; the loop falls back to 4 s polling.
    var vpnFastPollUntil: Date?

    /// Connect to the daemon and load initial data.
    func connectToDaemon() async {
        DebugLog.write("[AppState] connectToDaemon: starting")
        // Ask for notification permission early so the first
        // helper-fired event (auto-reconnect, watchdog escalation)
        // can surface as a banner. macOS deduplicates this prompt
        // per-bundle — repeat calls after first run are silent.
        await NotificationManager.requestAuthorization()
        // Subscribe to system sleep/wake notifications so we can
        // trigger immediate reconnect probes after wake instead
        // of waiting for the 30s watchdog tick.
        installSleepWakeObservers()
        // Make sure the deployed privileged helper has the same RPC
        // surface as the helper we just bundled. Without this, every
        // Cargo iteration that adds a new RPC surfaces as "unknown
        // method" until the user manually re-runs install_helper.sh.
        // This step is best-effort: if it fails, we continue and let
        // individual call sites handle missing RPCs gracefully.
        await ensureHelperUpToDate()
        do {
            try await client.connect()
            DebugLog.write("[AppState] connectToDaemon: socket connected")
            // Verify the daemon's wire-protocol version matches
            // what this app build expects. Mismatched majors mean
            // the user upgraded one side but not the other; we
            // surface a clear warning instead of letting RPCs
            // silently fail with malformed responses.
            do {
                let info: DaemonApiVersion.Info = try await client.call("api_version")
                DebugLog.write("[AppState] daemon api_version: \(info.major).\(info.minor)")
                if !DaemonApiVersion.isCompatible(info) {
                    let msg = "Daemon API v\(info.major).\(info.minor) doesn't match app's expected v\(DaemonApiVersion.expectedMajor).x. Reinstall the helper or upgrade the app."
                    DebugLog.write("[AppState] API version mismatch: \(msg)")
                    errorMessage = msg
                    showingError = true
                }
            } catch {
                // `api_version` was added in v1.0; older daemons
                // return METHOD_NOT_FOUND. Treat that as v0.x and
                // warn — but still proceed (most RPCs work).
                DebugLog.write("[AppState] daemon predates api_version RPC — running in legacy mode")
            }
            daemonAvailable = true
            await refreshAll()
            DebugLog.write("[AppState] connectToDaemon: refreshAll done, vpnProfiles=\(vpnProfiles.count)")
            startVpnStatusPolling()
            // Auto-scan FortiGate hosts whose last compliance run
            // is over 24h old, if the user has opted in. Daemon-
            // side recency filter handles dedup; this is just the
            // launch-time trigger.
            Task { @MainActor in
                await kickComplianceAutoScanIfDue()
            }
            DebugLog.write("[AppState] connectToDaemon: VPN polling started")
        } catch {
            DebugLog.write("[AppState] connectToDaemon: failed: \(error)")
            daemonAvailable = false
            errorMessage = "Could not connect to daemon: \(error.localizedDescription)"
            showingError = true
        }
    }

    /// Hot-swap the privileged helper at /Library/PrivilegedHelperTools/
    /// for the freshly-built version embedded in this app bundle, if
    /// the deployed one is missing any RPC the new code uses.
    ///
    /// Mechanism:
    ///   1. Ask the deployed helper for its supported method list.
    ///   2. Diff against the methods we know we need.
    ///   3. If anything's missing AND the deployed helper has
    ///      `deploy_self` (the dev-rpc feature), call it with the
    ///      bundled helper's path.
    ///   4. The deployed helper copies, exits, launchd respawns from
    ///      the new binary.
    ///   5. We poll the socket for ~3 seconds for the respawn to
    ///      happen, then return.
    ///
    /// If the deployed helper has no `deploy_self` (production build,
    /// or first-ever install before install_helper.sh), we surface a
    /// gentle log message and let the user install via the normal
    /// path. We don't block the rest of `connectToDaemon` on this.
    private func ensureHelperUpToDate() async {
        guard await HelperClient.shared.isReachable() else {
            DebugLog.write("[helper] not reachable yet, skipping version check")
            return
        }
        // 1. What does the deployed helper expose?
        let deployed: [String: Any]
        do {
            deployed = try await HelperClient.shared.helperVersion()
        } catch {
            DebugLog.write("[helper] helperVersion failed: \(error) — assuming stale")
            await redeployBundledHelper()
            return
        }
        // 2. Methods the new code expects but the deployed helper
        // might not have. Add to this list whenever a new RPC
        // is introduced — it's the trigger for auto-redeploy.
        let requiredMethods = [
            "helper_version",
            "tailscaled_install",
            "tailscaled_uninstall",
            "tailscaled_status",
            "tailscale_panic_reset",
            "tailscale_install_magicdns_resolver",
            "tailscale_install_exit_routes",
            "tailscale_remove_exit_routes",
        ]
        let methods = (deployed["methods"] as? [String]) ?? []
        let missing = requiredMethods.filter { !methods.contains($0) }
        if missing.isEmpty {
            DebugLog.write("[helper] up to date (\(methods.count) methods, build=\(deployed["build_timestamp"] ?? "?"))")
            return
        }
        DebugLog.write("[helper] missing methods: \(missing) — redeploying")
        await redeployBundledHelper()
    }

    /// Fire `deploy_self` against the deployed helper, pointing it
    /// at the bundled helper inside our app's Contents/MacOS/.
    /// Then poll for the daemon to respawn.
    private func redeployBundledHelper() async {
        // Bundled helper sits next to the GUI executable. We know
        // the file name because the embed-rust phase pins it.
        guard let exec = Bundle.main.executableURL else {
            DebugLog.write("[helper] no Bundle.main.executableURL — can't redeploy")
            return
        }
        let bundledHelper = exec
            .deletingLastPathComponent()
            .appendingPathComponent("com.sybr.supermanager.helper")
        guard FileManager.default.isReadableFile(atPath: bundledHelper.path) else {
            DebugLog.write("[helper] bundled helper not at \(bundledHelper.path)")
            return
        }
        do {
            _ = try await HelperClient.shared.deploySelf(sourcePath: bundledHelper.path)
            DebugLog.write("[helper] deploy_self issued, waiting for respawn")
        } catch {
            DebugLog.write("[helper] deploy_self failed: \(error)")
            return
        }
        // Wait up to ~3s for launchd to respawn from the new binary.
        // First poll: socket goes away briefly during exec.
        for attempt in 1...12 {
            try? await Task.sleep(for: .milliseconds(250))
            if await HelperClient.shared.isReachable() {
                DebugLog.write("[helper] respawned after \(attempt * 250)ms")
                return
            }
        }
        DebugLog.write("[helper] socket didn't come back after 3s — proceeding anyway")
    }

    /// Poll each known VPN profile's status from the helper, every
    /// 4 seconds. Drives the per-profile dots in the sidebar list
    /// so users can see at a glance which tunnel is up.
    private func startVpnStatusPolling() {
        vpnStatusPollTask?.cancel()
        // First pass right now so the dots populate within a second
        // of app start, not after the first 4 s sleep.
        Task { @MainActor in await pollAllVpnStates() }
        vpnStatusPollTask = Task { @MainActor in
            while !Task.isCancelled {
                // Adaptive cadence: 4 s normally, 500 ms while a
                // user action is "still settling" (the helper just
                // accepted a connect / disconnect / etc and the
                // tunnel state is mid-transition). The fast window
                // is bounded so we drop back to 4 s once nothing
                // is changing — keeps idle CPU low while making
                // the UI feel instant right after user action.
                let interval: Duration =
                    (vpnFastPollUntil ?? .distantPast) > Date()
                        ? .milliseconds(500)
                        : .seconds(4)
                try? await Task.sleep(for: interval)
                await pollAllVpnStates()
                // Surface helper-side events (auto-reconnect
                // succeeded, panic_reset escalation) as user
                // notifications. Cheap tail-of-log read.
                await pollHelperEventsForNotifications()
            }
        }
    }

    /// Trigger a 30-second window of fast (500 ms) VPN-status
    /// polling. Call after any user action that will cause the
    /// helper to start/stop a tunnel — connect, disconnect,
    /// force-disconnect, panic-reset, profile import. The poll
    /// loop reads `vpnFastPollUntil` on each iteration; it does
    /// NOT need to be cancelled — the window expires by itself.
    func bumpVpnFastPolling(seconds: TimeInterval = 30) {
        vpnFastPollUntil = Date().addingTimeInterval(seconds)
    }

    /// Track whether we've already wired up sleep/wake observers
    /// so a re-entry into `connectToDaemon` doesn't pile up
    /// duplicate handlers.
    private var sleepWakeObserversInstalled = false

    /// Subscribe to NSWorkspace sleep / wake notifications.
    /// Without this, after a long sleep the helper's watchdog
    /// only notices the dropped tunnel on its next 30s tick —
    /// causing a 30-second delay before always-on profiles come
    /// back. With this, we kick a re-poll within 1s of wake so
    /// the helper RPCs fire immediately.
    private func installSleepWakeObservers() {
        guard !sleepWakeObserversInstalled else { return }
        sleepWakeObserversInstalled = true
        let center = NSWorkspace.shared.notificationCenter
        center.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                DebugLog.write("[AppState] system woke — kicking reconnect poll")
                // Refresh tailscale state, force route guardian
                // to re-snapshot, and prod the connectivity
                // watchdog. The auto-reconnect watchdog ticks
                // on its own 30s schedule but the helper-side
                // tunnel-status query is fast.
                await self.refreshTailscale()
                await self.pollAllVpnStates()
            }
        }
        center.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: .main
        ) { _ in
            DebugLog.write("[AppState] system going to sleep")
            // Nothing to do proactively — tailscaled handles its
            // own pre-sleep teardown. Just log so post-mortems
            // can correlate symptoms with sleep timing.
        }
    }

    /// Mirrors `auto_reconnect_succeeded` lines in the helper log
    /// onto a per-profile timestamp so we can avoid renotifying
    /// on the same event after every poll.
    var lastReconnectNotifiedAt: [String: Date] = [:]

    /// Track byte position in the helper log so we only scan the
    /// new tail each poll instead of re-parsing 200 KB every time.
    private var helperLogReadOffset: Int = 0

    /// Poll the helper log for newly-emitted "auto-reconnect
    /// succeeded" / "panic_reset" lines and surface them as
    /// notifications. Runs alongside the VPN status poller.
    /// Cheap because we only read the file's tail.
    func pollHelperEventsForNotifications() async {
        let path = "/var/log/supermanager-helper.log"
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attrs[.size] as? Int else { return }
        // Reset offset if log was truncated/rotated.
        if size < helperLogReadOffset { helperLogReadOffset = 0 }
        guard size > helperLogReadOffset else { return }

        guard let handle = try? FileHandle(forReadingAtPath: path) else { return }
        defer { try? handle.close() }
        try? handle.seek(toOffset: UInt64(helperLogReadOffset))
        let chunk = (try? handle.read(upToCount: size - helperLogReadOffset)) ?? Data()
        helperLogReadOffset = size

        guard let text = String(data: chunk, encoding: .utf8) else { return }
        for rawLine in text.split(separator: "\n") {
            let line = String(rawLine)
            // "auto-reconnect succeeded profile_id=<uuid> backend=..."
            if line.contains("auto-reconnect succeeded") {
                if let pid = extractField(line, key: "profile_id") {
                    let label = vpnProfiles.first(where: { $0.id == pid })?.name ?? pid
                    ActivityLog.shared.record(
                        profileId: pid, kind: .autoReconnectFired,
                        message: "Always-on watchdog restored \(label)")
                    let last = lastReconnectNotifiedAt[pid] ?? .distantPast
                    if Date().timeIntervalSince(last) > 60 {
                        NotificationManager.vpnReconnected(profileLabel: label)
                        lastReconnectNotifiedAt[pid] = Date()
                    }
                }
            } else if line.contains("escalating to panic_reset") {
                ActivityLog.shared.record(profileId: nil, kind: .panicReset,
                                          message: "Connectivity watchdog fired")
                NotificationManager.connectivityWatchdogFired()
            } else if line.contains("AUTO-REVERT: 12s no internet") {
                // Captured client-side too, but if user has GUI
                // closed we still want the notification.
                let peer = appState_currentExitName() ?? "exit node"
                NotificationManager.exitNodeAutoReverted(peerName: peer)
            }
        }
    }

    private func appState_currentExitName() -> String? {
        guard let prefs = tailscalePrefs,
              let peers = tailscaleStatus?.peers else { return nil }
        return prefs.currentExitNode(in: peers)?.hostName
    }

    private func extractField(_ line: String, key: String) -> String? {
        // tracing format: ` profile_id=abcdef-1234 ...`
        guard let r = line.range(of: "\(key)=") else { return nil }
        let after = line[r.upperBound...]
        let value = after.prefix(while: { !$0.isWhitespace })
        return value.isEmpty ? nil : String(value)
    }

    /// Refresh all data from the daemon.
    ///
    /// Sets `isRefreshing = true` for the duration so the
    /// toolbar refresh button can swap its glyph for an in-flight
    /// progress indicator. Released in a defer so a thrown error
    /// doesn't strand the spinner on permanently.
    func refreshAll() async {
        isRefreshing = true
        defer { isRefreshing = false }
        await refreshHosts()
        await refreshKeys()
        await refreshProfiles()
        await refreshAutoReconnect()
        await refreshCustomers()
        await refreshEngagements()
    }

    /// True while `refreshAll` is in flight. Drives the toolbar
    /// refresh button's spinner — purely cosmetic, but bridges
    /// the gap between user clicking and the daemon's response
    /// so it doesn't feel like nothing happened.
    var isRefreshing: Bool = false

    // MARK: - FortiGate REST API
    //
    // Three operations the GUI cares about:
    //   - generateApiToken: SSH into the device, run the FortiOS CLI to
    //     mint a token, store it in the keychain. Returns the cleartext
    //     token *once* — subsequent reads must go through the keychain.
    //   - testFortigateConnection: hit /monitor/system/status to verify
    //     the stored token works. Returns rich device info (model,
    //     firmware, hostname, serial) for confirmation UX.
    //   - getApiToken: pull the stored token in cleartext for "Copy".
    //   - setApiToken: paste-in flow when the user has an externally-
    //     generated token.
    //   - clearApiToken: forget the stored token.
    //   - fortigateApi: generic REST proxy for richer feature work
    //     (live dashboard, compliance, push-key-via-API, …).

    /// Result of `testFortigateConnection`. Mirrors `fortigate::TestResult`
    /// on the daemon side. UI uses these fields to render
    /// "Connected to FortiGate-100F (FortiOS v7.4.3)" rather than
    /// just "OK".
    struct FortigateTestInfo: Codable {
        let ok: Bool
        let version: String
        let model: String
        let hostname: String
        let serial: String
    }

    /// Result of `fortigate_generate_api_token`. The daemon also
    /// returns a `label` (the keychain entry name) but the UI only
    /// needs the token + the api_user echo.
    struct GeneratedFortigateToken: Codable {
        let token: String
        let apiUser: String
        enum CodingKeys: String, CodingKey {
            case token
            case apiUser = "api_user"
        }
    }

    /// Result of generic `fortigate_api` calls — the helper returns
    /// the raw HTTP status alongside the body so the GUI can branch
    /// on 4xx/5xx without losing access to the FortiOS error JSON.
    struct FortigateApiRawResponse: Codable {
        let status: Int
        let body: String
    }

    // MARK: - UniFi controller

    struct UnifiTestInfo: Codable {
        let ok: Bool
        let username: String
        let site: String
        let adminRole: String
        let serverVersion: String
        enum CodingKeys: String, CodingKey {
            case ok, username, site
            case adminRole = "admin_role"
            case serverVersion = "server_version"
        }
    }

    // MARK: FortiGate dashboard

    /// Snapshot returned by `fortigate_get_dashboard`. All sections
    /// are optional — the daemon returns nil for any sub-call that
    /// failed, so a missing VPN-scope token still gives us the
    /// rest of the dashboard.
    struct FortigateDashboardSnapshot: Codable {
        let status: DashboardStatus?
        let resource: DashboardResource?
        let interfaces: [DashboardInterface]?
        let vpn: DashboardVpn?
        let fetchedAt: Date

        enum CodingKeys: String, CodingKey {
            case status, resource, interfaces, vpn
            case fetchedAt = "fetched_at"
        }
    }

    struct DashboardStatus: Codable {
        let model: String
        let version: String
        let hostname: String
        let serial: String
        let uptimeSeconds: UInt64
        enum CodingKeys: String, CodingKey {
            case model, version, hostname, serial
            case uptimeSeconds = "uptime_seconds"
        }
    }

    struct DashboardResource: Codable {
        let cpuPct: UInt8
        let memPct: UInt8
        let sessions: UInt64
        let diskPct: UInt8
        enum CodingKeys: String, CodingKey {
            case cpuPct = "cpu_pct"
            case memPct = "mem_pct"
            case sessions
            case diskPct = "disk_pct"
        }
    }

    struct DashboardInterface: Codable, Identifiable {
        let name: String
        let alias: String
        let rxBytes: UInt64
        let txBytes: UInt64
        let status: String
        let speedMbps: UInt64
        var id: String { name }
        enum CodingKeys: String, CodingKey {
            case name, alias, status
            case rxBytes = "rx_bytes"
            case txBytes = "tx_bytes"
            case speedMbps = "speed_mbps"
        }
    }

    struct DashboardVpn: Codable {
        let tunnelsTotal: UInt32
        let tunnelsUp: UInt32
        enum CodingKeys: String, CodingKey {
            case tunnelsTotal = "tunnels_total"
            case tunnelsUp = "tunnels_up"
        }
    }

    // MARK: - Compliance
    //
    // Models mirror the daemon's `crate::compliance` types. Codable
    // is straightforward because both sides share the same JSON
    // shapes; no manual decoding required.

    enum ComplianceStatus: String, Codable {
        case pass, fail, skip, error
    }

    enum ComplianceSeverity: String, Codable {
        case info, low, medium, high, critical
    }

    enum ComplianceTrigger: String, Codable {
        case manual
        case scheduled
        case postDeploy = "post_deploy"
    }

    struct ComplianceCheckResult: Codable, Identifiable {
        let checkId: String
        let title: String
        let category: String
        let severity: ComplianceSeverity
        let status: ComplianceStatus
        let detail: String
        let rawValue: String?
        var id: String { checkId }
        enum CodingKeys: String, CodingKey {
            case title, category, severity, status, detail
            case checkId = "check_id"
            case rawValue = "raw_value"
        }
    }

    struct ComplianceRun: Codable, Identifiable {
        let id: String
        let hostId: String
        let startedAt: Date
        let finishedAt: Date
        let firmware: String?
        let model: String?
        let hostname: String?
        let triggeredBy: ComplianceTrigger
        let score: UInt8
        let passed: UInt32
        let failed: UInt32
        let errored: UInt32
        let skipped: UInt32
        let checks: [ComplianceCheckResult]
        enum CodingKeys: String, CodingKey {
            case id, firmware, model, hostname, score, passed, failed, errored, skipped, checks
            case hostId = "host_id"
            case startedAt = "started_at"
            case finishedAt = "finished_at"
            case triggeredBy = "triggered_by"
        }
    }

    struct ComplianceRunSummary: Codable, Identifiable {
        let id: String
        let startedAt: Date
        let score: UInt8
        let passed: UInt32
        let failed: UInt32
        let errored: UInt32
        let firmware: String?
        let triggeredBy: ComplianceTrigger
        enum CodingKeys: String, CodingKey {
            case id, score, passed, failed, errored, firmware
            case startedAt = "started_at"
            case triggeredBy = "triggered_by"
        }
    }

    struct ComplianceCheckDefinition: Codable, Identifiable {
        let id: String
        let title: String
        let description: String
        let category: String
        let severity: ComplianceSeverity
        let framework: String
        let cisReference: String?
        let remediation: String?
        enum CodingKeys: String, CodingKey {
            case id, title, description, category, severity, framework, remediation
            case cisReference = "cis_reference"
        }
    }

    /// In-memory cache so the GUI doesn't refetch the immutable
    /// check list on every detail-view mount.
    var complianceCheckLibrary: [ComplianceCheckDefinition] = []

    /// History per host. Loaded on demand by the Compliance view;
    /// populated by `loadComplianceHistory(hostId:)` and updated
    /// in place when a new run completes.
    var complianceHistory: [String: [ComplianceRunSummary]] = [:]

    /// Latest run loaded into the GUI per host. `runCompliance`
    /// stores its result here; `loadComplianceRun` overrides on
    /// click-through from the history list.
    var complianceLatestRun: [String: ComplianceRun] = [:]

    /// True while a manual compliance run is in flight. Drives a
    /// progress indicator in the ComplianceView; we don't allow
    /// two concurrent runs against the same host (FortiOS rate
    /// limits and the result would be confusing anyway).
    var complianceRunInFlight: Set<String> = []

    // MARK: Drift detection

    enum DriftKind: String, Codable {
        case newlyFailing = "newly_failing"
        case newlyPassing = "newly_passing"
        case stillFailing = "still_failing"
        case stillPassing = "still_passing"
        case errored
        case added
        case removed
    }

    struct DriftEntry: Codable, Identifiable {
        let checkId: String
        let title: String
        let category: String
        let severity: ComplianceSeverity
        let kind: DriftKind
        let previousStatus: ComplianceStatus?
        let currentStatus: ComplianceStatus?
        let previousDetail: String?
        let currentDetail: String?
        var id: String { checkId }
        enum CodingKeys: String, CodingKey {
            case title, category, severity, kind
            case checkId = "check_id"
            case previousStatus = "previous_status"
            case currentStatus = "current_status"
            case previousDetail = "previous_detail"
            case currentDetail = "current_detail"
        }
    }

    struct DriftReport: Codable {
        let currentRunId: String
        let previousRunId: String?
        let currentScore: UInt8
        let previousScore: UInt8?
        let scoreDelta: Int
        let newlyFailing: [DriftEntry]
        let newlyPassing: [DriftEntry]
        let stillFailing: [DriftEntry]
        let errored: [DriftEntry]
        enum CodingKeys: String, CodingKey {
            case currentRunId = "current_run_id"
            case previousRunId = "previous_run_id"
            case currentScore = "current_score"
            case previousScore = "previous_score"
            case scoreDelta = "score_delta"
            case newlyFailing = "newly_failing"
            case newlyPassing = "newly_passing"
            case stillFailing = "still_failing"
            case errored
        }
    }

    /// Drift report cached per host. Populated by `loadComplianceDrift`
    /// after a new run completes; rendered by ComplianceHostView's
    /// "Since last scan" section.
    var complianceDrift: [String: DriftReport] = [:]

    // MARK: Scan all FortiGate hosts

    struct ComplianceScanAllResult: Codable, Identifiable {
        let hostId: String
        let hostLabel: String
        let runId: String?
        let score: UInt8?
        let error: String?
        var id: String { hostId }
        enum CodingKeys: String, CodingKey {
            case hostLabel = "host_label"
            case runId = "run_id"
            case score, error
            case hostId = "host_id"
        }
    }

    /// True while a fleet-wide scan is in flight. Drives the
    /// "Run all" button's spinner and disables it during a run.
    var complianceScanAllInFlight = false
    /// Per-host status during a fleet-wide scan, keyed by hostId.
    /// Populated when `runComplianceScanAllConcurrent` starts and
    /// cleared on completion. Values: "queued", "scanning", "done",
    /// "failed". Drives a fan-out progress display so the user
    /// sees which hosts are stuck rather than watching a spinner.
    var complianceScanProgress: [String: String] = [:]

    // MARK: - Provisioning (customers + templates)
    //
    // Customers are TOML files under
    // `~/Library/Application Support/SuperManager/customers/`,
    // each containing a sites array. Data-transfer types
    // (Customer, Site, Vlan, ProvisioningTemplate, ProvisioningRenderResult)
    // live in `Models/ProvisioningModels.swift`.

    /// All customers loaded from disk. Refreshed by
    /// `refreshCustomers`; the Provisioning sidebar uses this
    /// directly as its data source.
    var customers: [Customer] = []

    /// Global customer-context filter — when non-empty, every
    /// section (SSH, Compliance, Provisioning, Security, Fleet)
    /// scopes its list to records belonging to this customer.
    /// Empty string = "All customers" (no filter).
    /// Persisted across launches via `@AppStorage("globalCustomerSlug")`
    /// in the toolbar view; AppState just owns the in-memory state.
    var globalCustomerSlug: String = ""

    /// Selected customer slug + site id for the Provisioning view.
    /// Persisted only in memory — survives section navigation
    /// but resets on app restart, same as VPN profile selection.
    var selectedCustomerSlug: String?
    var selectedSiteId: String?

    /// Available templates (built-in + user). Refreshed lazily
    /// when the Provisioning section first activates.
    var provisioningTemplates: [ProvisioningTemplate] = []

    /// Last successful render result per (customer, template) pair.
    /// Cached so navigating away and back doesn't re-render
    /// (which is cheap but would discard the user's extras-form
    /// inputs without persistence).
    var lastRenderResult: ProvisioningRenderResult?

    // MARK: - Security: Engagement + Discovery
    //
    // SecurityTechnique, EngagementEvent, ScheduleCadence,
    // EngagementSchedule, and Engagement live in
    // `Models/SecurityModels.swift`.

    struct DiscoveredService: Codable, Hashable, Identifiable {
        let port: UInt16
        let proto: String
        let serviceType: String
        let instanceName: String?
        let txtRecords: [String]
        var id: String { "\(serviceType)-\(port)" }
        enum CodingKeys: String, CodingKey {
            case port
            case proto = "protocol"
            case serviceType = "service_type"
            case instanceName = "instance_name"
            case txtRecords = "txt_records"
        }
    }

    struct DiscoveredHost: Codable, Identifiable {
        let ip: String
        let mac: String?
        let hostname: String?
        let vendor: String?
        let firstSeen: Date
        let lastSeen: Date
        let services: [DiscoveredService]
        let sources: [String]
        var id: String { ip }
        enum CodingKeys: String, CodingKey {
            case ip, mac, hostname, vendor, services, sources
            case firstSeen = "first_seen"
            case lastSeen = "last_seen"
        }
    }

    struct LocalInterface: Codable, Identifiable {
        let name: String
        let mac: String?
        let ipv4: String?
        let cidr: String?
        let ipv6: String?
        var id: String { name }
    }

    struct PassiveScanResult: Codable {
        let startedAt: Date
        let finishedAt: Date
        let localInterfaces: [LocalInterface]
        let hosts: [DiscoveredHost]
        let engagementId: String?
        enum CodingKeys: String, CodingKey {
            case hosts
            case startedAt = "started_at"
            case finishedAt = "finished_at"
            case localInterfaces = "local_interfaces"
            case engagementId = "engagement_id"
        }
    }

    var engagements: [Engagement] = []
    var selectedEngagementId: String?
    var lastDiscoveryResult: PassiveScanResult?
    var discoveryInFlight = false

    // MARK: Active scan + findings
    //
    // FindingSeverity, SecurityFinding, TlsInfo, PortProbe, WebPath,
    // SmbShare, SmbInfo, SnmpDetail, ActiveHost, ActiveScanResult,
    // Disposition, DispositionChange, PersistedFinding, ScanDiff,
    // StoreSummary, RiskBand, HostRisk, NotifyConfig, SubdomainResult,
    // AssetZone, AssetEnrichment, DnsHealthReport, ActivityKind,
    // ActivityEvent, RemediationScript live in
    // `Models/SecurityModels.swift`.
    //
    // ToolInfo, CveFeedStatus live in `Models/ToolModels.swift`.
    //
    // NetworkDetect lives in `Models/ProvisioningModels.swift`.

    var lastActiveScan: ActiveScanResult?
    var activeScanInFlight = false

    /// Running long-running operations, refreshed by
    /// `pollOperations()` while `activeScanInFlight` (and friends)
    /// is true. Drives the Stop button + "Cancelling…" indicator.
    var runningOperations: [RunningOperation] = []

    struct RunningOperation: Codable, Identifiable, Equatable {
        let id: String
        let kind: String
        let label: String
        let startedAt: Date
        let cancelRequested: Bool

        enum CodingKeys: String, CodingKey {
            case id
            case kind
            case label
            case startedAt = "started_at"
            case cancelRequested = "cancel_requested"
        }
    }

    // MARK: Provisioning — diff preview + deploy

    enum SectionStatus: String, Codable {
        case added
        case deviceOnly = "device_only"
        case equal
        case modified
    }

    struct SectionDiff: Codable, Identifiable {
        let path: String
        let status: SectionStatus
        let templateBody: String?
        let deviceBody: String?
        let unifiedDiff: String
        var id: String { path }
        enum CodingKeys: String, CodingKey {
            case path, status
            case templateBody = "template_body"
            case deviceBody = "device_body"
            case unifiedDiff = "unified_diff"
        }
    }

    struct DiffSummary: Codable {
        let added: UInt32
        let modified: UInt32
        let equal: UInt32
        let total: UInt32
    }

    struct DiffPreviewResult: Codable {
        let rendered: String
        let sections: [SectionDiff]
        let summary: DiffSummary
    }

    // Deployment + DeploymentStatus live in `Models/ProvisioningModels.swift`.

    /// Per-host deployment history. Loaded on demand by the
    /// ProvisioningView when the user expands the "History"
    /// disclosure.
    var deploymentHistory: [String: [Deployment]] = [:]

    // MARK: - Tailscale operations

    /// Coalesces overlapping `refreshTailscale` calls. Without
    /// this, the per-view `.task` polling loop, the wake-from-
    /// sleep handler, and the install/connect flows would all
    /// fire `refreshTailscale` simultaneously — three CLI
    /// invocations of `tailscale status --json` and `prefs`
    /// stacked up, costing 600+ ms each before the first
    /// completes. With it, only one refresh runs at a time;
    /// subsequent callers await the in-flight Task.
    var inflightRefresh: Task<Void, Never>?

    /// Tracks the last MagicDNS domain we wrote a per-tailnet
    /// resolver file for via the helper. Drives the install/uninstall
    /// reconciliation in `ensureMagicDNSResolver`.
    var lastInstalledMagicDNSDomain: String?

    /// Whether the local Tailscale CLI we'd shell out to is the
    /// bundled-in-app version. UI uses this to decide whether to
    /// show "Install Tailscale daemon" — only meaningful when we
    /// actually have our own binary to install.
    var tailscaleIsBundled: Bool { TailscaleClient.bundledDaemonPath != nil }

    /// Last result of `tailscaled_status` from the helper. nil
    /// before the first poll. Drives the install/uninstall buttons
    /// in the header.
    var tailscaledRunning: Bool?
    var tailscaledInstalled: Bool?
    /// Per-profile-id auto-reconnect-enabled flag. Refreshed
    /// from helper's `auto_reconnect_list` RPC. Drives the
    /// "Always on" toggle in the VPN detail view.
    var autoReconnectEnabled: Set<String> = []
    /// Per-profile bandwidth counters from the helper's status
    /// RPC (rx_bytes / tx_bytes). nil if the backend doesn't
    /// expose them or the tunnel isn't connected.
    var vpnByteCounters: [String: (rx: UInt64, tx: UInt64)] = [:]

    /// Per-profile derived throughput rate in bytes/sec, computed
    /// from the delta between consecutive `vpnByteCounters` polls.
    /// Updated by `pollAllVpnStates` after each refresh. Cleared
    /// (along with the underlying counters) when the tunnel goes
    /// down so the detail view doesn't display stale rates.
    var vpnByteRates: [String: (rxPerSec: Double, txPerSec: Double)] = [:]

    /// Last (counter, timestamp) seen for each profile — used
    /// internally to derive `vpnByteRates`. Wall-clock timestamp
    /// captured at the start of the polling sweep so jitter from
    /// individual RPC latencies doesn't skew the rate.
    var vpnLastByteSample: [String: (rx: UInt64, tx: UInt64, at: Date)] = [:]

    /// Per-profile freshest peer handshake (Unix timestamp seconds).
    /// WireGuard-only today — `wg show <if> dump` reports it; OpenVPN
    /// and IKEv2 don't expose an equivalent. The detail view turns
    /// this into a live "12s ago" label so the operator can spot a
    /// stale tunnel without dropping to a terminal.
    var vpnLastHandshakeUnix: [String: Int64] = [:]

    /// Per-profile peer endpoint reported by the helper status RPC
    /// (`<host-or-ip>:<port>`). Pulled from the WireGuard peer with
    /// the freshest handshake — useful to confirm "where am I
    /// actually connected to" when a profile has multiple peers.
    var vpnPeerEndpoints: [String: String] = [:]

    /// Set of VPN profile IDs that the user has pinned to the top
    /// of the sidebar list. Local-only (not synced through the
    /// daemon — pinning is per-device convenience, not part of the
    /// profile's portable state). Persisted to UserDefaults so the
    /// pin survives app restart.
    static let pinnedVpnDefaultsKey = "pinnedVpnProfileIds"
    var pinnedVpnIds: Set<String> = {
        let raw = UserDefaults.standard.array(forKey: pinnedVpnDefaultsKey) as? [String] ?? []
        return Set(raw)
    }()

    /// Set of persisted-finding ids the user has pinned to the top
    /// of the findings list. Same persistence pattern as VPN pins:
    /// device-local, UserDefaults-backed, survives restart. The
    /// finding-id (`PersistedFinding.id`) is the daemon's `key`
    /// hash — stable across scans for the same finding.
    static let pinnedFindingsDefaultsKey = "findings.pinned"
    var pinnedFindingIds: Set<String> = {
        let raw = UserDefaults.standard.array(forKey: pinnedFindingsDefaultsKey) as? [String] ?? []
        return Set(raw)
    }()

    /// Toggle the pin state of a finding and persist immediately.
    func toggleFindingPin(_ findingId: String) {
        if pinnedFindingIds.contains(findingId) {
            pinnedFindingIds.remove(findingId)
        } else {
            pinnedFindingIds.insert(findingId)
        }
        UserDefaults.standard.set(Array(pinnedFindingIds), forKey: Self.pinnedFindingsDefaultsKey)
    }

    // MARK: - Error handling

    /// Surface an error to the user. Handles rapid back-to-back
    /// calls by queueing — the user sees errors one at a time
    /// instead of having all but the last overwritten silently.
    func handleError(_ error: Error) {
        let msg = error.localizedDescription
        if showingError {
            errorQueue.append(msg)
        } else {
            errorMessage = msg
            showingError = true
        }
    }

    /// Called by `RootView` when the user dismisses the alert
    /// (the alertBinding setter triggers this via `showingError = false`).
    /// Pops the next message from the queue if any, else clears state.
    func dismissCurrentError() {
        if let next = errorQueue.first {
            errorQueue.removeFirst()
            errorMessage = next
            // Defer the next show by one runloop tick so SwiftUI
            // sees the dismissal of the current alert before the
            // new one fires — without this, the alert would
            // visually flash without dismissing.
            DispatchQueue.main.async {
                self.showingError = true
            }
        } else {
            errorMessage = ""
        }
    }
}

/// Top-level app sections that get a sidebar entry.
///
/// `console` (Claude AI) and `provisioning` (device-bringup playbooks)
/// were carried over from the Linux build's roadmap but were rendered as
/// "Coming in Phase N" placeholders. Empty placeholder tabs make a half-
/// finished app feel half-finished — they're cut from the sidebar until
/// the corresponding feature has at least a thin-slice MVP. The enum
/// values are kept (commented below) so the eventual feature can wire
/// itself back in without renaming things downstream.
enum AppSection: String, CaseIterable, Identifiable {
    case fleet = "Fleet"
    case ssh = "SSH"
    case vpn = "VPN"
    case tailscale = "Tailscale"
    case compliance = "Compliance"
    case provisioning = "Provisioning"
    case security = "Security"
    // case console = "Console"          — re-enable once we ship the Claude integration

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .fleet: return "building.2.fill"
        case .ssh: return "terminal"
        case .vpn: return "lock.shield"
        case .tailscale: return "network"
        case .compliance: return "checkmark.shield"
        case .provisioning: return "wand.and.stars"
        case .security: return "shield.lefthalf.filled.badge.checkmark"
        }
    }
}

struct CommandResult: Codable {
    let stdout: String
    let stderr: String
    let exitCode: Int

    enum CodingKeys: String, CodingKey {
        case stdout, stderr
        case exitCode = "exit_code"
    }
}

// PushResult lives in `Models/ProvisioningModels.swift`.
