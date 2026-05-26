import AppKit
import Foundation
import SwiftUI

extension AppState {
    /// Pull the latest `tailscale status --json`. Caller is
    /// responsible for cadence — the Tailscale list view kicks
    /// this every 5 seconds while it's on screen, so we don't
    /// burn cycles polling the CLI when the user isn't looking.
    ///
    /// Also pulls preferences in parallel so the settings sheet has
    /// fresh data on open without an extra round-trip. Prefs are
    /// quick (<50 ms) — folding them into the same poll keeps the
    /// CLI invocations bounded.
    func refreshTailscale() async {
        // Coalesce overlapping refreshes. If one is in flight,
        // await its completion instead of starting a parallel
        // CLI invocation — the result is identical to ours, and
        // the second `tailscale status --json` would just burn
        // 200+ ms of CLI startup for nothing.
        if let existing = inflightRefresh {
            await existing.value
            return
        }
        let task = Task { @MainActor in
            await self.refreshTailscaleInner()
        }
        inflightRefresh = task
        await task.value
        inflightRefresh = nil
    }

    fileprivate func refreshTailscaleInner() async {
        async let statusTask = TailscaleClient.status()
        async let prefsTask: TailscalePrefs? = {
            // Prefs only readable when the daemon is responsive.
            // Don't propagate a prefs failure as a status failure —
            // for an unauthenticated daemon, status works but
            // prefs may not.
            //
            // CRITICAL: log the error explicitly. The previous
            // `try?` form swallowed decode failures, leaving
            // `tailscalePrefs == nil` and toggles dead-binding to
            // `false` regardless of the daemon's actual state. If
            // prefs decode breaks again, this is the only place
            // we'll see it.
            do {
                return try await TailscaleClient.prefs()
            } catch {
                DebugLog.write("[ts] prefs FETCH FAILED: \(error.localizedDescription)")
                return nil
            }
        }()
        // Snapshot the existing prefs BEFORE we await — needed for
        // the keep-last-known-good fallback below.
        let priorPrefs = tailscalePrefs
        // Helper-side daemon status runs in parallel with the CLI
        // probes — we want it for *all* polls so the header can
        // flip between Install / Start / Sign-in states without an
        // extra round-trip when the user navigates back.
        async let daemonRefresh: Void = refreshTailscaledDaemon()
        do {
            let s = try await statusTask
            tailscaleStatus = s
            tailscaleError = nil
        } catch {
            tailscaleStatus = nil
            tailscaleError = error.localizedDescription
            DebugLog.write("[ts] refreshTailscale: status error: \(error.localizedDescription)")
        }
        // Keep last-known-good prefs on a transient decode failure.
        // A future Tailscale version that adds an unexpected null
        // field shouldn't cause every toggle to snap back; we'd
        // rather show slightly stale state than erase known-good
        // values and revert the user's optimistic update.
        let freshPrefs = await prefsTask
        if let fresh = freshPrefs {
            tailscalePrefs = fresh
        } else if priorPrefs == nil {
            // Never had prefs — leave nil. Empty fallback handled
            // at click-time inside applyTailscalePref.
            tailscalePrefs = nil
        } else {
            // Decode failed but we had prior state. Keep it. The
            // user's optimistic toggle stays visually correct, and
            // the next successful poll reconciles.
            DebugLog.write("[ts] keeping prior prefs (decode failed this round)")
        }
        await daemonRefresh
        // MagicDNS backstop: open-source tailscaled on macOS
        // doesn't install the per-tailnet `/etc/resolver/<domain>`
        // nameserver file. Detect that condition and have the
        // helper write it, so `<peer>.ts.net` resolves through the
        // system resolver and not just `dig @100.100.100.100`.
        // See `install_magicdns_resolver` in the helper.
        await ensureMagicDNSResolver()
        DebugLog.write("[ts] refreshTailscale: backend=\(tailscaleStatus?.backendState ?? "nil") "
            + "daemonRunning=\(tailscaledRunning?.description ?? "nil") "
            + "daemonInstalled=\(tailscaledInstalled?.description ?? "nil") "
            + "error=\(tailscaleError ?? "none") "
            + "peers=\(tailscaleStatus?.peers.count ?? -1) "
            + "prefs=\(tailscalePrefs == nil ? "nil" : "set(corpDNS=\(tailscalePrefs!.corpDNS))")")
    }

    /// Reconcile the per-tailnet resolver file with current state.
    ///
    /// Install when: BackendState=Running AND CorpDNS=true AND we
    /// know the suffix.
    /// Uninstall when: any of those conditions go false.
    ///
    /// Idempotent — calling on an already-correct state is a no-op
    /// from the helper's side. Logs each transition so the
    /// MagicDNS bug is debuggable end-to-end.
    fileprivate func ensureMagicDNSResolver() async {
        let running = tailscaleStatus?.backendState == "Running"
        let corpDNS = tailscalePrefs?.corpDNS ?? false
        let suffix = tailscaleStatus?.magicDNSSuffix ?? ""
        let shouldInstall = running && corpDNS && !suffix.isEmpty
        let target: String? = shouldInstall ? suffix : nil
        if target == lastInstalledMagicDNSDomain { return }
        if let suf = target {
            do {
                _ = try await HelperClient.shared.tailscaleInstallMagicDNSResolver(
                    tailnetSuffix: suf, install: true)
                DebugLog.write("[ts/dns] installed /etc/resolver/\(suf)")
                lastInstalledMagicDNSDomain = suf
            } catch {
                DebugLog.write("[ts/dns] install failed: \(error.localizedDescription)")
            }
        } else if let prev = lastInstalledMagicDNSDomain {
            do {
                _ = try await HelperClient.shared.tailscaleInstallMagicDNSResolver(
                    tailnetSuffix: prev, install: false)
                DebugLog.write("[ts/dns] removed /etc/resolver/\(prev)")
                lastInstalledMagicDNSDomain = nil
            } catch {
                DebugLog.write("[ts/dns] remove failed: \(error.localizedDescription)")
            }
        }
    }

    /// Apply a single preference change. Optimistic UI: the caller
    /// passes a closure that mutates a local copy of the prefs so
    /// the toggles snap immediately, then we run the CLI and
    /// reconcile via a fresh refresh. Failure leaves the optimistic
    /// state in place but surfaces the error inline so the user
    /// knows the change didn't take.
    ///
    /// Pattern at the call site:
    ///
    ///     await appState.applyTailscalePref { p in p.routeAll = newValue } cli: {
    ///         try await TailscaleClient.setAcceptRoutes(newValue)
    ///     }
    ///
    /// This way the toggle UI reads `tailscalePrefs?.routeAll`
    /// directly and shows the new state instantly.
    func applyTailscalePref(
        optimistic: (inout TailscalePrefs) -> Void,
        cli: () async throws -> Void
    ) async {
        tailscaleActionError = nil
        DebugLog.write("[ts/pref] applyTailscalePref: starting (prefs=\(tailscalePrefs == nil ? "nil" : "set"))")
        // Always run the optimistic update against a non-nil
        // value — falling back to the empty-default snapshot when
        // we don't yet have real data. This is the fix for the
        // "toggle doesn't visually flip" bug: the previous code
        // gated optimistic updates on `if var p = tailscalePrefs`
        // and silently skipped when prefs was nil, leaving the UI
        // bound to the GET closure's `?? false` fallback while the
        // CLI call STILL went through. User saw zero feedback even
        // though the daemon was changing.
        var p = tailscalePrefs ?? .empty
        optimistic(&p)
        tailscalePrefs = p
        DebugLog.write("[ts/pref] optimistic applied")
        do {
            try await cli()
            DebugLog.write("[ts/pref] cli ok, refreshing")
            // Re-fetch ground truth so any side-effects (e.g.
            // setting an exit node also implicitly enables
            // accept-routes) are reflected in our model.
            await refreshTailscale()
        } catch {
            tailscaleActionError = error.localizedDescription
            DebugLog.write("[ts/pref] cli FAILED: \(error.localizedDescription)")
            // Leave the optimistic state alone — re-querying is
            // cheaper than reverting a SwiftUI Toggle state, and
            // the next 5 s poll will reconcile anyway.
            await refreshTailscale()
        }
    }

    /// Bring Tailscale up. Fires `tailscale up` and refreshes.
    func tailscaleUp() async {
        do {
            try await TailscaleClient.up()
            await refreshTailscale()
        } catch {
            handleError(error)
        }
    }

    /// Bring Tailscale down. Useful when our own WG tunnels would
    /// otherwise collide on routes / DNS.
    func tailscaleDown() async {
        do {
            try await TailscaleClient.down()
            await refreshTailscale()
        } catch {
            handleError(error)
        }
    }

    /// Kick off the Tailscale auth flow from inside the app. Spawns
    /// `tailscale up --force-reauth` in the background, captures
    /// the `https://login.tailscale.com/...` URL the CLI prints to
    /// stderr, opens it in the user's default browser, and shows a
    /// "waiting for browser" sheet. The poller in
    /// `TailscaleListView` keeps refreshing status — once the
    /// daemon flips to `BackendState=Running`, the header re-renders
    /// with the new tailnet and we clear the pending URL.
    ///
    /// Errors from the spawned process show up as
    /// `tailscaleActionError` rather than a modal alert — the most
    /// common case is "user closed the browser tab" which doesn't
    /// warrant breaking the flow.
    func tailscaleLogin() async {
        tailscaleActionError = nil
        do {
            try await TailscaleClient.login { [weak self] url in
                Task { @MainActor in
                    guard let self else { return }
                    self.pendingTailscaleAuthURL = url
                    NSWorkspace.shared.open(url)
                }
            }
            // Spawned process exited (auth complete, cancelled, or
            // timed out). Refresh once; the visible sheet is cleared
            // by the polling loop's success-detection path.
            await refreshTailscale()
            if tailscaleStatus?.backendState == "Running" {
                pendingTailscaleAuthURL = nil
            }
        } catch {
            tailscaleActionError = error.localizedDescription
            pendingTailscaleAuthURL = nil
        }
    }

    /// Install (or refresh) the bundled `tailscaled` as a LaunchDaemon
    /// via the privileged helper. Auto-refreshes Tailscale status
    /// after the helper returns so the UI can flip from "daemon
    /// missing" to "logged out / sign in" once the daemon is up.
    ///
    /// Errors surface in `tailscaleActionError` for the header
    /// banner — install failures are common (helper not installed,
    /// path permissions, sandbox refusing to spawn) and we want
    /// them visible without a modal alert.
    func installTailscaled() async {
        tailscaleActionError = nil
        guard let daemonPath = TailscaleClient.bundledDaemonPath else {
            tailscaleActionError = "Tailscale daemon binary isn't bundled in this build."
            DebugLog.write("[ts] installTailscaled: bundled daemon path missing")
            return
        }
        DebugLog.write("[ts] installTailscaled: starting, daemon=\(daemonPath)")
        do {
            let result = try await HelperClient.shared.tailscaledInstall(
                bundledDaemonPath: daemonPath
            )
            DebugLog.write("[ts] installTailscaled: helper returned \(result)")
            let success = (result["success"] as? Bool) ?? false
            if !success {
                tailscaleActionError = (result["message"] as? String)
                    ?? "Install failed."
            }
            // Daemon takes a beat to start the API socket; poll for a
            // few seconds rather than refreshing once and giving up.
            for attempt in 0..<10 {
                try? await Task.sleep(for: .milliseconds(500))
                await refreshTailscale()
                if tailscaleStatus != nil {
                    DebugLog.write("[ts] installTailscaled: status came up after \(attempt * 500 + 500)ms")
                    break
                }
            }
            await refreshTailscaledDaemon()
            DebugLog.write("[ts] installTailscaled: done. running=\(tailscaledRunning?.description ?? "nil") backend=\(tailscaleStatus?.backendState ?? "nil")")
        } catch {
            tailscaleActionError = error.localizedDescription
            DebugLog.write("[ts] installTailscaled: error: \(error)")
        }
    }

    /// Tear down the LaunchDaemon via the helper. Preserves state.
    func uninstallTailscaled() async {
        tailscaleActionError = nil
        do {
            _ = try await HelperClient.shared.tailscaledUninstall()
            await refreshTailscale()
            await refreshTailscaledDaemon()
        } catch {
            tailscaleActionError = error.localizedDescription
        }
    }

    /// Pull the helper's view of the LaunchDaemon (installed?
    /// running?). Cheap — single launchctl-print call. Folded into
    /// `refreshTailscale` so the header always has fresh info.
    func refreshTailscaledDaemon() async {
        do {
            let r = try await HelperClient.shared.tailscaledStatus()
            tailscaledInstalled = (r["installed"] as? Bool) ?? false
            tailscaledRunning = (r["running"] as? Bool) ?? false
        } catch {
            // Helper unreachable: we don't know either way. Leave
            // the values alone rather than flapping to nil — UI
            // treats nil as "loading."
        }
    }

    /// Emergency reset: clear exit-node + accept-routes via the CLI,
    /// then ask the privileged helper to renew DHCP on the active
    /// network service. This is the recovery path when picking an
    /// exit node has bricked routing — the user can't browse, the
    /// only fix is dropping the exit and bouncing the route.
    ///
    /// Always-available menu item; works even when status is
    /// reporting errors because everything is local-socket / OS-level.
    func panicResetTailscale() async {
        DebugLog.write("[ts/panic] starting reset")
        tailscaleActionError = nil
        // 1. Best-effort: clear exit-node + accept-routes via CLI.
        // We do this before the helper call because the daemon
        // sometimes responds even when the routing table is
        // half-dead (it talks over a Unix socket, not the network).
        do {
            try await TailscaleClient.setExitNode("")
            try await TailscaleClient.setAcceptRoutes(false)
            DebugLog.write("[ts/panic] CLI clear succeeded")
        } catch {
            DebugLog.write("[ts/panic] CLI clear failed: \(error.localizedDescription) — continuing to helper")
        }
        // 2. Helper-side: clear again from root context AND renew
        // DHCP. The DHCP renew is the part that requires root.
        do {
            let result = try await HelperClient.shared.tailscalePanicReset()
            let success = (result["success"] as? Bool) ?? false
            let message = (result["message"] as? String) ?? "Reset attempted."
            DebugLog.write("[ts/panic] helper result: success=\(success) message=\(message)")
            if !success {
                tailscaleActionError = message
            }
        } catch {
            tailscaleActionError = "Helper unavailable: \(error.localizedDescription)"
            DebugLog.write("[ts/panic] helper failed: \(error)")
        }
        await refreshTailscale()
    }

    /// Set an exit node with a built-in safety net.
    ///
    /// Open-source `tailscaled` on macOS rewrites the system default
    /// route through the exit peer's TUN. If the peer is offline or
    /// DERP-flaky, the user loses internet entirely. Tailscale.app
    /// has a NetworkExtension fallback; we don't.
    ///
    /// Strategy:
    ///   1. Apply the exit-node setting normally.
    ///   2. After 4 seconds (give routes time to converge), probe
    ///      a known reachable host (`1.1.1.1:443`).
    ///   3. If the probe fails twice in a row, automatically clear
    ///      the exit node + DHCP-renew. User keeps internet.
    ///
    /// Caller is the UI layer, which should also surface a
    /// confirmation alert before this is invoked — auto-revert is
    /// a backstop, not an excuse to skip user consent.
    func setExitNodeWithSafety(_ ipOrAuto: String) async {
        DebugLog.write("[ts/exit] === setExitNodeWithSafety START target=\(ipOrAuto.isEmpty ? "<NONE>" : ipOrAuto) ===")
        // Suspend connectivity watchdog for 30 seconds so the
        // disruptive transition (DNS reconfig, TCP resets, brief
        // route gaps) doesn't trigger panic_reset which would
        // undo our work. The route guardian + DNS health watchdog
        // continue running underneath.
        do {
            _ = try await HelperClient.shared.tailscalePauseWatchdog(seconds: 30)
            DebugLog.write("[ts/exit] watchdog paused 30s")
        } catch {
            DebugLog.write("[ts/exit] WARN: could not pause watchdog: \(error.localizedDescription)")
        }

        // Empty string = clear. Remove daemon pref + idempotent
        // route teardown.
        if ipOrAuto.isEmpty {
            DebugLog.write("[ts/exit] CLEAR mode")
            await applyTailscalePref(
                optimistic: { p in p.exitNodeIP = ""; p.exitNodeID = "" },
                cli: { try await TailscaleClient.setExitNode("") }
            )
            DebugLog.write("[ts/exit] CLI exit-node cleared")
            do {
                let r = try await HelperClient.shared.tailscaleRemoveExitRoutes()
                DebugLog.write("[ts/exit] split-routes removed: \(r["message"] ?? "")")
            } catch {
                DebugLog.write("[ts/exit] WARN remove failed: \(error.localizedDescription)")
            }
            DebugLog.write("[ts/exit] === CLEAR DONE ===")
            return
        }

        // 1. Apply daemon pref.
        DebugLog.write("[ts/exit] step 1/4: apply daemon pref")
        await applyTailscalePref(
            optimistic: { p in p.exitNodeIP = ipOrAuto == "auto:any" ? "" : ipOrAuto },
            cli: { try await TailscaleClient.setExitNode(ipOrAuto) }
        )
        DebugLog.write("[ts/exit] step 1/4 done — pref set")

        // 2. PRE-FLIGHT TEST.
        DebugLog.write("[ts/exit] step 2/4: pre-flight reachability test (/32 probe)")
        let testResult: [String: Any]
        do {
            testResult = try await HelperClient.shared.tailscaleTestExitReachability()
        } catch {
            DebugLog.write("[ts/exit] step 2/4 FAILED: pre-flight RPC error: \(error.localizedDescription)")
            tailscaleActionError = "Pre-flight test failed: \(error.localizedDescription)"
            _ = try? await TailscaleClient.setExitNode("")
            _ = try? await HelperClient.shared.tailscaleResumeWatchdog()
            await refreshTailscale()
            return
        }
        let testOK = (testResult["success"] as? Bool) ?? false
        let testCode = (testResult["response_code"] as? String) ?? "?"
        let testMsg = (testResult["message"] as? String) ?? "(no message)"
        DebugLog.write("[ts/exit] step 2/4 result: success=\(testOK) code=\(testCode) msg=\(testMsg)")
        if !testOK {
            DebugLog.write("[ts/exit] AUTO-REVERT: pre-flight failed, peer doesn't forward")
            // Surface the raw HTTP code in the UI so the operator can
            // tell "000" (timeout/no route) from "403" (peer reachable
            // but not forwarding) without opening the helper log.
            let codeHint = testCode == "000" || testCode.isEmpty
                ? "timed out (no route through peer)"
                : "HTTP \(testCode)"
            tailscaleActionError =
                "Exit node didn't forward traffic — probe \(codeHint). Daemon pref reverted."
            _ = try? await TailscaleClient.setExitNode("")
            _ = try? await HelperClient.shared.tailscaleResumeWatchdog()
            await refreshTailscale()
            return
        }

        // 3. Install full split-default routes.
        DebugLog.write("[ts/exit] step 3/4: install split-default routes via helper")
        do {
            let r = try await HelperClient.shared.tailscaleInstallExitRoutes()
            DebugLog.write("[ts/exit] step 3/4 done: \(r["message"] ?? "")")
            tailscaleActionError = nil
        } catch {
            DebugLog.write("[ts/exit] step 3/4 FAILED: \(error.localizedDescription)")
            tailscaleActionError = "Could not install exit-node routes: \(error.localizedDescription)"
            _ = try? await TailscaleClient.setExitNode("")
            _ = try? await HelperClient.shared.tailscaleResumeWatchdog()
            await refreshTailscale()
            return
        }

        // 4. Post-install verification with RETRIES. The first 1-3
        //    seconds after install are inherently disruptive — DNS
        //    state churn, TCP resets, route table flux. Don't decide
        //    "exit-node failed" off a single probe. Retry 6 times
        //    over 12s; if ANY one succeeds, the exit-node is
        //    working. Auto-revert only if all 6 fail (i.e., the peer
        //    really is non-functional even after the network settles).
        Task { @MainActor in
            DebugLog.write("[ts/exit] step 4/4: post-install probes (6× over 12s)")
            var anyOk = false
            for attempt in 1...6 {
                try? await Task.sleep(for: .seconds(2))
                let ok = await probeInternet()
                DebugLog.write("[ts/exit] step 4/4 probe \(attempt)/6: \(ok ? "OK" : "fail")")
                if ok {
                    anyOk = true
                    break
                }
            }
            if anyOk {
                DebugLog.write("[ts/exit] === SUCCESS: exit-node \(ipOrAuto) live ===")
                tailscaleActionError = nil
                _ = try? await HelperClient.shared.tailscaleResumeWatchdog()
            } else {
                DebugLog.write("[ts/exit] === AUTO-REVERT: 12s no internet through peer ===")
                tailscaleActionError = "Internet didn't recover after 12s through exit node — auto-reverted."
                await panicResetTailscale()
                _ = try? await HelperClient.shared.tailscaleResumeWatchdog()
            }
        }
    }

    /// Quick TCP-connect probe to a known-reachable internet
    /// endpoint. Returns true within ~2 seconds if the route works.
    /// Used by the exit-node safety net.
    fileprivate func probeInternet() async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            DispatchQueue.global(qos: .userInitiated).async {
                let task = Process()
                task.launchPath = "/usr/bin/nc"
                task.arguments = ["-z", "-G", "2", "-w", "2", "1.1.1.1", "443"]
                task.standardOutput = Pipe()
                task.standardError = Pipe()
                do {
                    try task.run()
                    task.waitUntilExit()
                    cont.resume(returning: task.terminationStatus == 0)
                } catch {
                    cont.resume(returning: false)
                }
            }
        }
    }

    /// Wipe the node key from the daemon and disassociate this Mac
    /// from the currently-logged-in tailnet. After this, `tailscaleLogin()`
    /// can be used to authenticate again — possibly to a different
    /// account.
    func tailscaleLogout() async {
        tailscaleActionError = nil
        do {
            try await TailscaleClient.logout()
            await refreshTailscale()
        } catch {
            tailscaleActionError = error.localizedDescription
        }
    }
}
