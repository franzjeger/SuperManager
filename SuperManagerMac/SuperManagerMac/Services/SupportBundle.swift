import AppKit
import Foundation

/// Build a "support bundle" — a tar.gz of every diagnostic
/// artefact the user might need to share when something goes
/// wrong. Lives at a user-chosen location (Save panel) and
/// contains:
///
///   - helper log tail (last 256 KiB of /var/log/supermanager-helper.log)
///   - daemon debug log (whole /tmp/supermanager-debug.log)
///   - tailscaled log tail
///   - tailscale state snapshot (status + prefs JSON)
///   - helper version + capability list
///   - macOS network state (route + DNS + iface)
///   - SuperManager version metadata
///
/// Secrets-aware: we deliberately don't bundle private keys,
/// stored passwords, or anything from the macOS keychain. Tunnel
/// configs are skipped for the same reason.
enum SupportBundle {
    /// Show a Save panel + write the bundle. Returns the URL
    /// the user picked, or nil if cancelled.
    @MainActor
    static func saveInteractive(appState: AppState) async -> URL? {
        let panel = NSSavePanel()
        panel.title = "Save SuperManager Support Bundle"
        let date = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        panel.nameFieldStringValue = "supermanager-support-\(date).tar.gz"
        panel.allowedContentTypes = [.gzip]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return nil }

        do {
            try await build(at: url, appState: appState)
            return url
        } catch {
            await MainActor.run {
                let alert = NSAlert()
                alert.messageText = "Couldn't write support bundle"
                alert.informativeText = error.localizedDescription
                alert.alertStyle = .warning
                alert.runModal()
            }
            return nil
        }
    }

    /// Build the tar.gz at `url`. Helpers + reads run on a
    /// detached task — file I/O is fine off the main thread.
    static func build(at url: URL, appState: AppState) async throws {
        let staging = FileManager.default.temporaryDirectory
            .appendingPathComponent("supermanager-bundle-\(UUID().uuidString)",
                                    isDirectory: true)
        try FileManager.default.createDirectory(at: staging,
                                                withIntermediateDirectories: true)
        defer {
            // Best-effort clean-up even on partial failure.
            try? FileManager.default.removeItem(at: staging)
        }

        // 1. README explaining what's in the bundle.
        let readme = """
        SuperManager Support Bundle
        Generated: \(Date())

        Contents:
          - app-debug.log         GUI-side log (/tmp/supermanager-debug.log)
          - helper.log            Helper LaunchDaemon log (last 256 KiB)
          - tailscaled.log        Bundled tailscaled log (last 256 KiB)
          - tailscale-status.json `tailscale status --json` snapshot
          - tailscale-prefs.json  `tailscale debug prefs` snapshot
          - helper-version.json   Helper RPC capability list
          - network-state.txt     route + DNS + iface state at capture
          - app-state.txt         GUI's view of profiles + connection state
          - activity.log          Per-profile event history
          - crashes/              Saved crash reports (PLCrashReporter)

        NOT included (privacy):
          - private keys
          - stored credentials
          - tunnel configs (.conf / .ovpn)
          - macOS keychain entries
        """
        try readme.write(to: staging.appendingPathComponent("README.txt"),
                         atomically: true, encoding: .utf8)

        // 1b. Crash reports (PLCrashReporter dumps). May be empty;
        // empty directory is fine — README mentions it either way.
        let crashSrc = CrashReporting.crashDir
        if FileManager.default.fileExists(atPath: crashSrc.path) {
            let crashDest = staging.appendingPathComponent("crashes")
            try? FileManager.default.copyItem(at: crashSrc, to: crashDest)
        }

        // 2. App debug log
        let debugLog = "/tmp/supermanager-debug.log"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: debugLog)) {
            try data.write(to: staging.appendingPathComponent("app-debug.log"))
        }

        // 3. Helper log tail (helper exposes via RPC because user
        // can't read /var/log/supermanager-helper.log directly).
        if let helperLog = try? await HelperClient.shared.tailLog(bytes: 256 * 1024) {
            try helperLog.write(to: staging.appendingPathComponent("helper.log"),
                                atomically: true, encoding: .utf8)
        }

        // 4. Tailscaled log tail. Owned by root but world-readable.
        let tsdLog = "/var/log/supermanager-tailscaled.log"
        if let attrs = try? FileManager.default.attributesOfItem(atPath: tsdLog),
           let size = attrs[.size] as? Int,
           let handle = try? FileHandle(forReadingAtPath: tsdLog) {
            let want = 256 * 1024
            let start = max(0, size - want)
            try? handle.seek(toOffset: UInt64(start))
            let data = (try? handle.read(upToCount: want)) ?? Data()
            try? data.write(to: staging.appendingPathComponent("tailscaled.log"))
            try? handle.close()
        }

        // 5. Tailscale snapshots
        if let bin = TailscaleClient.bundledDaemonPath
            .map({ ($0 as NSString).deletingLastPathComponent + "/tailscale" }),
           FileManager.default.isExecutableFile(atPath: bin) {
            captureCommand(
                staging: staging, name: "tailscale-status.json",
                bin: bin, args: ["status", "--json"]
            )
            captureCommand(
                staging: staging, name: "tailscale-prefs.json",
                bin: bin, args: ["debug", "prefs"]
            )
        }

        // 6. Helper version + RPCs
        if let v = try? await HelperClient.shared.helperVersion() {
            if let data = try? JSONSerialization.data(
                withJSONObject: v, options: .prettyPrinted) {
                try? data.write(to: staging.appendingPathComponent("helper-version.json"))
            }
        }

        // 7. Network state
        var network = ""
        for (label, cmd) in [
            ("--- route -n get default ---", ["/sbin/route", "-n", "get", "default"]),
            ("--- route -n get -inet6 default ---", ["/sbin/route", "-n", "get", "-inet6", "default"]),
            ("--- netstat -rn -f inet | head -30 ---", ["/usr/sbin/netstat", "-rn", "-f", "inet"]),
            ("--- scutil --dns ---", ["/usr/sbin/scutil", "--dns"]),
            ("--- ifconfig -a ---", ["/sbin/ifconfig", "-a"]),
        ] {
            network.append(label + "\n")
            network.append(runCommand(bin: cmd[0], args: Array(cmd.dropFirst())))
            network.append("\n\n")
        }
        try? network.write(to: staging.appendingPathComponent("network-state.txt"),
                           atomically: true, encoding: .utf8)

        // 8. App-state snapshot
        let appState_text = await renderAppStateSnapshot(appState)
        try? appState_text.write(to: staging.appendingPathComponent("app-state.txt"),
                                 atomically: true, encoding: .utf8)

        // 9. Activity log
        let activity = await renderActivityLog()
        try? activity.write(to: staging.appendingPathComponent("activity.log"),
                            atomically: true, encoding: .utf8)

        // 10. Tar+gzip the staging dir into the user's chosen path.
        // Use macOS's built-in `/usr/bin/tar` rather than a Swift
        // tar library to minimise binary size.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        proc.arguments = [
            "-czf", url.path,
            "-C", staging.deletingLastPathComponent().path,
            staging.lastPathComponent,
        ]
        try proc.run()
        proc.waitUntilExit()
        if proc.terminationStatus != 0 {
            throw NSError(
                domain: "SupportBundle", code: Int(proc.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "tar exited \(proc.terminationStatus)"]
            )
        }
    }

    private static func captureCommand(
        staging: URL, name: String, bin: String, args: [String]
    ) {
        let out = runCommand(bin: bin, args: args)
        try? out.write(to: staging.appendingPathComponent(name),
                       atomically: true, encoding: .utf8)
    }

    private static func runCommand(bin: String, args: [String]) -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: bin)
        proc.arguments = args
        let stdout = Pipe()
        proc.standardOutput = stdout
        proc.standardError = stdout
        do {
            try proc.run()
            let data = stdout.fileHandleForReading.readDataToEndOfFile()
            proc.waitUntilExit()
            return String(data: data, encoding: .utf8) ?? "(non-utf8)"
        } catch {
            return "(spawn failed: \(error.localizedDescription))"
        }
    }

    @MainActor
    private static func renderAppStateSnapshot(_ s: AppState) -> String {
        var out = "AppState snapshot at \(Date())\n\n"
        out += "Daemon available: \(s.daemonAvailable)\n"
        out += "VPN profiles: \(s.vpnProfiles.count)\n"
        for p in s.vpnProfiles {
            let state = s.vpnConnectionStates[p.id] ?? "?"
            let ao = s.autoReconnectEnabled.contains(p.id) ? "[always-on]" : ""
            out += "  - \(p.name) (\(p.backend)) → \(state) \(ao)\n"
        }
        out += "\nTailscale:\n"
        out += "  bundled: \(s.tailscaleIsBundled)\n"
        out += "  daemon installed: \(s.tailscaledInstalled?.description ?? "?")\n"
        out += "  daemon running: \(s.tailscaledRunning?.description ?? "?")\n"
        out += "  backend state: \(s.tailscaleStatus?.backendState ?? "n/a")\n"
        out += "  peers: \(s.tailscaleStatus?.peers.count ?? 0)\n"
        return out
    }

    @MainActor
    private static func renderActivityLog() -> String {
        let formatter = ISO8601DateFormatter()
        var out = "ActivityLog snapshot\n\n"
        for ev in ActivityLog.shared.events {
            let pid = ev.profileId ?? "<global>"
            out += "\(formatter.string(from: ev.timestamp)) "
                + "[\(ev.kind.rawValue)] \(pid): \(ev.message)\n"
        }
        return out
    }
}
