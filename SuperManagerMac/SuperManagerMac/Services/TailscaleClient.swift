import Foundation

/// Read-only client for the local Tailscale daemon.
///
/// ## Why CLI and not the local API socket
///
/// Tailscale ships a local HTTP API at
/// `unix:/var/run/tailscale/tailscaled.sock` with a stable
/// `/localapi/v0/status` endpoint that returns the same JSON we
/// shell `tailscale status --json` for. We use the CLI because:
///   • The socket path moves between major releases (and between
///     the App Store build and the Open Source one).
///   • The CLI handles auth + socket discovery for us, including
///     the App Store tailscaled's user-scoped socket.
///   • A subprocess that finishes in <50 ms costs us nothing —
///     polling at 5 s intervals is fine.
///
/// If we ever need write operations that the CLI doesn't expose
/// cleanly (e.g. exit-node selection, advanced ACL inspection),
/// switching to the local API is a per-method change without
/// reshaping the call sites.
///
/// ## CLI lookup
///
/// `/usr/local/bin/tailscale` for Homebrew installs, or the App
/// Store app's bundled binary at
/// `/Applications/Tailscale.app/Contents/MacOS/Tailscale`. We probe
/// both, in that order, and report a clear "not installed" error
/// if neither exists. The user installs Tailscale through their
/// own preferred channel; we don't try to install it.
enum TailscaleClient {
    enum ClientError: Error, LocalizedError {
        case notInstalled
        case daemonNotRunning(String)
        case decodeFailed(String)

        var errorDescription: String? {
            switch self {
            case .notInstalled:
                return "Tailscale is not installed. Install it from tailscale.com or `brew install --cask tailscale`."
            case .daemonNotRunning(let m):
                return "Tailscale daemon isn't responding: \(m)"
            case .decodeFailed(let m):
                return "Couldn't decode Tailscale status: \(m)"
            }
        }
    }

    /// Probe candidate paths in priority order. Returns the first
    /// path that's both executable on disk *and* actually runs (a
    /// dead App Store shim at `/usr/local/bin/tailscale` is
    /// executable but exec-ing it returns 126 — we want to skip
    /// those).
    ///
    /// Priority:
    ///   1. The bundled binary inside SuperManager.app — guarantees
    ///      a working tailscale even if the user has uninstalled
    ///      Tailscale.app or homebrew's formula.
    ///   2. Homebrew on Apple Silicon.
    ///   3. Homebrew on Intel + the legacy App Store shim path.
    ///   4. App Store / DMG install location.
    ///
    /// Result is cached on the actor for the process lifetime — the
    /// validate step does fork+exec which costs ~30 ms per call, and
    /// the binary doesn't move while we're running.
    private static func locateBinary() -> URL? {
        if let cached = _cachedBinary { return cached }
        var candidates: [String] = []
        // 1. Our own bundled copy. Build phase
        // `bundle_tailscale.sh` writes here.
        if let bundled = Bundle.main.url(
            forResource: "tailscale",
            withExtension: nil,
            subdirectory: "tailscale-bin"
        ) {
            candidates.append(bundled.path)
        }
        // 2-4. Common system locations as fallback. Order matters:
        // /opt/homebrew first on arm64 because it's most likely the
        // *real* binary; /usr/local/bin last because it's where the
        // App Store leaves a dead shim.
        candidates.append(contentsOf: [
            "/opt/homebrew/bin/tailscale",
            "/opt/homebrew/opt/tailscale/bin/tailscale",
            "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
            "/usr/local/bin/tailscale",
        ])

        for path in candidates {
            guard FileManager.default.isExecutableFile(atPath: path) else { continue }
            let url = URL(fileURLWithPath: path)
            if validateBinary(at: url) {
                _cachedBinary = url
                return url
            }
        }
        return nil
    }

    /// Probe whether a candidate `tailscale` binary actually
    /// executes. Returns false for shell shims that point at a
    /// missing target (the App Store leaves
    /// `/usr/local/bin/tailscale` behind after uninstall, exec-ing
    /// it returns 126 with "no such file or directory").
    private static func validateBinary(at url: URL) -> Bool {
        let process = Process()
        process.executableURL = url
        process.arguments = ["version"]
        // Discard output; we only care about exit code.
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    /// Per-process cache for the located binary. Reset across app
    /// launches; a SIGINT/restart picks up newly-installed binaries
    /// without manual intervention.
    private static var _cachedBinary: URL?

    /// Path to the bundled `tailscaled` daemon (next to `tailscale`
    /// in the same Resources subdirectory). Used by the privileged
    /// helper to install the LaunchDaemon. nil if the build phase
    /// hasn't bundled the daemon (e.g. a stripped CI build).
    static var bundledDaemonPath: String? {
        Bundle.main.url(
            forResource: "tailscaled",
            withExtension: nil,
            subdirectory: "tailscale-bin"
        )?.path
    }

    /// Whether Tailscale is even installed. UI uses this to decide
    /// between rendering the peer list vs. an "Install Tailscale"
    /// empty state.
    static var isInstalled: Bool { locateBinary() != nil }

    /// Run `tailscale status --json` and decode. Bubbles up
    /// fine-grained errors so the UI can distinguish "not
    /// installed" from "daemon down" from "JSON parse error."
    static func status() async throws -> TailscaleStatus {
        guard let bin = locateBinary() else { throw ClientError.notInstalled }

        let output = try await runTask(bin: bin, args: ["status", "--json"])

        // tailscaled returns its own "not running" message on stdout
        // before the JSON. Detect that explicitly so the user gets
        // a useful next-step instead of a JSON parse error.
        if output.starts(with: "Tailscale is stopped") ||
           output.contains("failed to connect to local tailscaled") {
            throw ClientError.daemonNotRunning(output.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        do {
            return try JSONDecoder().decode(TailscaleStatus.self, from: Data(output.utf8))
        } catch {
            throw ClientError.decodeFailed(error.localizedDescription)
        }
    }

    /// Bring the Tailscale tunnel up against an already-authenticated
    /// node. Idempotent. If the daemon hasn't been authed yet, use
    /// `login(onAuthURL:)` instead — it captures the auth URL and
    /// opens it in the browser.
    static func up() async throws {
        guard let bin = locateBinary() else { throw ClientError.notInstalled }
        _ = try await runTask(bin: bin, args: ["up", "--reset"])
    }

    /// Bring the Tailscale tunnel down. Useful for the "vår WG
    /// tunnel collides with Tailscale" workflow — disconnect
    /// Tailscale, run our test, reconnect.
    static func down() async throws {
        guard let bin = locateBinary() else { throw ClientError.notInstalled }
        _ = try await runTask(bin: bin, args: ["down"])
    }

    /// Log out of the current Tailnet. Wipes the node key from the
    /// daemon and removes this device from the user's tailnet on
    /// the coordinator. After logout, `login(onAuthURL:)` can be
    /// used to authenticate again — possibly to a different
    /// account.
    static func logout() async throws {
        guard let bin = locateBinary() else { throw ClientError.notInstalled }
        _ = try await runTask(bin: bin, args: ["logout"])
    }

    /// Begin the authentication flow.
    ///
    /// `tailscale up` writes to stderr a line of the form
    ///
    ///     To authenticate, visit:
    ///
    ///        https://login.tailscale.com/a/abcd1234
    ///
    /// We spawn the process, read stderr line-by-line until that URL
    /// shows up, fire `onAuthURL(url)` (which the UI uses to open
    /// the browser + show a "waiting for auth" sheet), then keep
    /// reading until the process exits — `tailscale up` blocks
    /// until the user completes the browser flow OR a configurable
    /// timeout. The daemon ends up in `BackendState=Running` on
    /// success; the caller verifies via the next `status()` poll.
    ///
    /// Calling this on an already-authenticated daemon just brings
    /// the tunnel up without surfacing any URL — `onAuthURL` won't
    /// fire in that case.
    static func login(onAuthURL: @escaping @Sendable (URL) -> Void) async throws {
        guard let bin = locateBinary() else { throw ClientError.notInstalled }
        try await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = bin
            // `--force-reauth` forces a fresh auth even if the
            // daemon thinks it's already logged in. Without it, a
            // stale node-key state can make `tailscale up` return
            // immediately without surfacing a URL.
            process.arguments = ["up", "--force-reauth"]
            let stderr = Pipe()
            let stdout = Pipe()
            process.standardError = stderr
            process.standardOutput = stdout
            try process.run()

            // Stream stderr in chunks. Tailscale's CLI prints to
            // stderr, not stdout, for the auth instructions.
            var seenURL = false
            let handle = stderr.fileHandleForReading
            // Read until pipe closes (process exited). We stop
            // looking for the URL after we see it, but keep
            // draining the pipe so the process can exit cleanly.
            while !seenURL {
                let chunk = handle.availableData
                if chunk.isEmpty { break }
                let text = String(data: chunk, encoding: .utf8) ?? ""
                if let url = extractAuthURL(from: text) {
                    onAuthURL(url)
                    seenURL = true
                }
            }
            // Drain remaining output so the child can exit.
            _ = handle.readDataToEndOfFile()
            _ = stdout.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
        }.value
    }

    /// Pluck a `https://login.tailscale.com/...` URL out of
    /// arbitrary text. Tolerant of leading whitespace + the URL
    /// being on its own line indented two spaces (which is the
    /// CLI's actual format).
    private static func extractAuthURL(from text: String) -> URL? {
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("https://login.tailscale.com/") {
                return URL(string: trimmed)
            }
        }
        return nil
    }

    /// Read the daemon's full preferences object. Used by the
    /// settings sheet to seed its toggles from the current state
    /// without hard-coding defaults that drift from the daemon's
    /// own.
    ///
    /// Implemented via `tailscale debug prefs` rather than the
    /// (more documented) `tailscale up --json --dry-run` because
    /// the latter only echoes the proposed prefs after merge — we
    /// want the *current* values.
    static func prefs() async throws -> TailscalePrefs {
        guard let bin = locateBinary() else { throw ClientError.notInstalled }
        let output = try await runTask(bin: bin, args: ["debug", "prefs"])
        do {
            return try JSONDecoder().decode(TailscalePrefs.self, from: Data(output.utf8))
        } catch {
            throw ClientError.decodeFailed(error.localizedDescription)
        }
    }

    /// Apply one or more preference changes via `tailscale set`.
    ///
    /// `set` is fundamentally different from `up`: it merges the
    /// supplied flags into the daemon's existing prefs without
    /// requiring the user to re-state every preference. That makes
    /// it safe to call from a UI for a single toggle without
    /// trampling unrelated settings.
    ///
    /// Caller responsibility: pass *exactly* the flags that need to
    /// change. Typical call sites build the args via the small
    /// builder helpers below (`setExitNode`, `setAcceptRoutes`, etc.)
    /// rather than constructing flag arrays inline.
    private static func runSet(_ args: [String]) async throws {
        guard let bin = locateBinary() else { throw ClientError.notInstalled }
        _ = try await runTask(bin: bin, args: ["set"] + args)
    }

    /// Switch the exit node by stable Tailscale node IP.
    ///
    /// Pass nil (or empty string) to clear the exit node — the
    /// daemon then routes traffic out the local interface again.
    /// We pass the IP rather than the hostname because hostnames can
    /// be ambiguous when the user has multiple peers sharing a
    /// short name across tailnets.
    static func setExitNode(_ ipOrEmpty: String) async throws {
        try await runSet(["--exit-node=\(ipOrEmpty)"])
    }

    /// Allow LAN access while exit-noding. Without this, sending
    /// traffic to your own LAN (printers, NAS, local web servers)
    /// gets routed through the exit node too — usually not what
    /// you want.
    static func setExitNodeAllowLAN(_ allow: Bool) async throws {
        try await runSet(["--exit-node-allow-lan-access=\(allow)"])
    }

    /// Accept subnet routes advertised by other peers. Off by
    /// default; enabling lets you reach `192.168.x.y` networks that
    /// other peers in the tailnet are routing.
    static func setAcceptRoutes(_ accept: Bool) async throws {
        try await runSet(["--accept-routes=\(accept)"])
    }

    /// Use Tailscale's MagicDNS + admin-configured nameservers.
    /// Disabling this is unusual — it's the cause of "I can't
    /// reach peer.tailnet.ts.net by name" issues nine times out
    /// of ten.
    static func setAcceptDNS(_ accept: Bool) async throws {
        try await runSet(["--accept-dns=\(accept)"])
    }

    /// Run a Tailscale-SSH server on this Mac. Off by default. When
    /// on, peers in the tailnet can `ssh user@<this-mac>` and
    /// authenticate against tailnet ACLs instead of needing
    /// per-host SSH keys.
    static func setRunSSH(_ run: Bool) async throws {
        // Tailscale prints a "you might lock yourself out" prompt
        // when toggling SSH; --accept-risk silences it. The risk is
        // genuine but only for users who SSH'd in *via* Tailscale
        // — for a desktop Mac the prompt is just noise.
        try await runSet(["--ssh=\(run)", "--accept-risk=lose-ssh"])
    }

    /// Block incoming connections (Tailscale's "shields up" mode).
    /// When on, no peer can talk to this node regardless of ACLs;
    /// outbound traffic is unaffected.
    static func setShieldsUp(_ on: Bool) async throws {
        try await runSet(["--shields-up=\(on)"])
    }

    /// Advertise this Mac as an exit node for the tailnet.
    ///
    /// Just *advertising* doesn't make it active — the tailnet
    /// admin still needs to approve the route at
    /// login.tailscale.com → Machines → this device → "Exit node".
    /// We surface that as a hint in the settings sheet.
    static func setAdvertiseExitNode(_ on: Bool) async throws {
        try await runSet([
            "--advertise-exit-node=\(on)",
            // Same lockout-prompt rationale as setRunSSH.
            "--accept-risk=lose-ssh",
        ])
    }

    /// Replace the set of advertised subnet routes. Pass an empty
    /// array to clear all advertisements.
    ///
    /// Note: this always *replaces*. There's no "add one route" CLI
    /// — the caller is responsible for fetching current routes via
    /// `prefs()`, mutating, and writing back.
    static func setAdvertiseRoutes(_ routes: [String]) async throws {
        // The flag takes a comma-separated list. Empty string clears.
        let value = routes.joined(separator: ",")
        try await runSet(["--advertise-routes=\(value)"])
    }

    /// Override the hostname Tailscale uses for this node. Pass an
    /// empty string to revert to the OS hostname.
    static func setHostname(_ hostname: String) async throws {
        try await runSet(["--hostname=\(hostname)"])
    }

    /// Toggle the daemon's auto-update behaviour. Tailscale's
    /// auto-update only works for installs from the Tailscale
    /// installer — Homebrew + App Store builds ignore this flag and
    /// the daemon will print a hint. We expose the toggle anyway so
    /// users on the official installer have somewhere to set it.
    static func setAutoUpdate(_ on: Bool) async throws {
        try await runSet(["--auto-update=\(on)"])
    }

    /// Round-trip latency to a peer (in milliseconds, parsed from
    /// `tailscale ping <ip> --c=1`). Returns nil on timeout.
    /// Useful for "is this peer actually reachable" diagnostics in
    /// the detail view.
    static func ping(_ peerIP: String) async throws -> Double? {
        guard let bin = locateBinary() else { throw ClientError.notInstalled }
        let output = try await runTask(bin: bin, args: ["ping", "-c", "1", "--timeout", "3s", peerIP])
        // `tailscale ping` outputs e.g.:
        //   "pong from docker (100.85.18.119) via DERP(hel) in 28ms"
        // We're only after the milliseconds at the end.
        guard let inIndex = output.range(of: " in ")?.upperBound else { return nil }
        let tail = output[inIndex...]
        guard let msIndex = tail.range(of: "ms") else { return nil }
        let numString = tail[..<msIndex.lowerBound]
        return Double(numString.trimmingCharacters(in: .whitespaces))
    }

    /// Spawn a subprocess and capture stdout. Errors include
    /// stderr to make CLI diagnostics actionable.
    ///
    /// All `tailscale set` calls and prefs reads funnel through here
    /// — the args tuple is logged so we can post-mortem "the toggle
    /// didn't take effect" without instrumenting every call site.
    private static func runTask(bin: URL, args: [String]) async throws -> String {
        try await Task.detached(priority: .userInitiated) {
            // Log every invocation. Args list is small (<10 elements),
            // and the cost is dominated by the fork+exec anyway.
            DebugLog.write("[ts/cli] $ \(bin.lastPathComponent) \(args.joined(separator: " "))")
            let process = Process()
            process.executableURL = bin
            process.arguments = args
            let stdout = Pipe()
            let stderr = Pipe()
            process.standardOutput = stdout
            process.standardError = stderr
            try process.run()
            // Read both pipes concurrently to avoid blocking on a
            // full stderr buffer when stdout is the big one.
            let outData = stdout.fileHandleForReading.readDataToEndOfFile()
            let errData = stderr.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let outString = String(data: outData, encoding: .utf8) ?? ""
            let errString = String(data: errData, encoding: .utf8) ?? ""
            if process.terminationStatus != 0 {
                DebugLog.write("[ts/cli] FAILED exit=\(process.terminationStatus) "
                    + "stderr=\(errString.trimmingCharacters(in: .whitespacesAndNewlines)) "
                    + "stdout=\(outString.trimmingCharacters(in: .whitespacesAndNewlines))")
                throw ClientError.daemonNotRunning(
                    "exit \(process.terminationStatus): \(errString.trimmingCharacters(in: .whitespacesAndNewlines))"
                )
            }
            // Suppress logging the full status JSON (10s of KB) to
            // keep the log readable. For `set` and other terse
            // commands, output is normally empty on success.
            if !args.contains("status") && !args.contains("prefs") {
                let preview = outString.prefix(200).trimmingCharacters(in: .whitespacesAndNewlines)
                if !preview.isEmpty {
                    DebugLog.write("[ts/cli] ok stdout=\(preview)")
                } else {
                    DebugLog.write("[ts/cli] ok (silent)")
                }
            }
            return outString
        }.value
    }
}
