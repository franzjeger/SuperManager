import Foundation
import ServiceManagement

/// Installs / uninstalls the privileged `com.sybr.supermanager.helper`
/// LaunchDaemon.
///
/// Two paths, in order of preference:
///
///  1. **`SMAppService.daemon(plistName:)`** — the modern Apple way. Works
///     for Developer-ID-signed apps. Shipping a signed build is the right
///     long-term plan, but during dev (and for users running ad-hoc-signed
///     builds) macOS rejects it with `SMAppServiceErrorDomain code 1
///     "Operation not permitted"`.
///  2. **Manual install via `osascript with administrator privileges`** —
///     copies the plist to `/Library/LaunchDaemons/` and the helper binary
///     to `/Library/PrivilegedHelperTools/`, both chowned root:wheel, then
///     `launchctl bootstrap system <plist>`. This is exactly what
///     SMAppService does under the hood; doing it ourselves trades the
///     UI-side approval flow for a single admin-auth dialog. Single
///     password prompt. Works regardless of code signing.
///
/// We always try (1) first — when the user later distributes a signed
/// build, the SMAppService path is what will run, and switching back is
/// zero work.
@MainActor
enum HelperInstaller {

    static let plistName = "com.sybr.supermanager.helper.plist"
    static let helperLabel = "com.sybr.supermanager.helper"

    /// `/Library/LaunchDaemons/com.sybr.supermanager.helper.plist`
    private static let systemPlistPath =
        "/Library/LaunchDaemons/com.sybr.supermanager.helper.plist"
    /// `/Library/PrivilegedHelperTools/com.sybr.supermanager.helper`
    private static let systemBinaryPath =
        "/Library/PrivilegedHelperTools/com.sybr.supermanager.helper"

    enum InstallError: Error, LocalizedError {
        case registrationFailed(String)
        case bundlePathUnavailable
        case manualInstallFailed(String)
        case unsupportedPlatform

        var errorDescription: String? {
            switch self {
            case .registrationFailed(let m):
                return "Helper registration failed: \(m)"
            case .bundlePathUnavailable:
                return "Could not find helper binary inside app bundle"
            case .manualInstallFailed(let m):
                return "Helper install failed: \(m)"
            case .unsupportedPlatform:
                return "Helper requires macOS 13 (Ventura) or later"
            }
        }
    }

    /// Install the helper as a system LaunchDaemon. Tries SMAppService first
    /// then falls back to a manual install. Either way, a successful return
    /// means the helper is up and listening on its socket within ~1 s.
    ///
    /// **Idempotency contract:** if the helper is *already* installed and
    /// reachable, `install()` is a fast no-op — no SMAppService call, no
    /// osascript admin prompt. Earlier versions skipped this check, so a
    /// poll race or transient socket blip would re-trigger the entire
    /// install dance (and the user got hit with a password prompt every
    /// time they clicked Connect after a fresh app launch). The block
    /// below short-circuits that path.
    static func install() async throws {
        guard #available(macOS 13.0, *) else { throw InstallError.unsupportedPlatform }

        // FAST PATH: helper is already running and listening. We confirm
        // by attempting an actual socket connection (cheap — sub-millisecond
        // when the helper is up) instead of trusting the file-existence
        // check, which can be stale after a bootout.
        if await HelperClient.shared.isReachable() {
            return
        }

        // Try the modern API first. Skip silently if it errors — the
        // fallback handles the "ad-hoc signed" case that SMAppService
        // rejects.
        if (try? trySMAppService()) != nil {
            // Wait for socket to come up.
            for _ in 0 ..< 30 {
                if FileManager.default.fileExists(atPath: HelperClient.socketPath) {
                    return
                }
                try? await Task.sleep(for: .milliseconds(100))
            }
            // SMAppService said yes but the daemon never bound the socket.
            // Fall through to manual install which will replace the plist.
        }

        try await manualInstall()
    }

    /// Modern path. Throws on failure so the caller can fall back.
    @available(macOS 13.0, *)
    private static func trySMAppService() throws {
        let svc = SMAppService.daemon(plistName: plistName)
        do {
            try svc.register()
        } catch {
            let ns = error as NSError
            throw InstallError.registrationFailed(
                "\(ns.localizedDescription) (domain=\(ns.domain) code=\(ns.code))"
            )
        }
    }

    /// Fallback: write the LaunchDaemon plist + helper binary to the system
    /// locations and bootstrap them, all under one `osascript with
    /// administrator privileges` call so the user enters their password
    /// exactly once.
    private static func manualInstall() async throws {
        guard let bundleURL = Bundle.main.bundleURL.path.removingPercentEncoding else {
            throw InstallError.bundlePathUnavailable
        }
        let bundledHelper = "\(bundleURL)/Contents/MacOS/com.sybr.supermanager.helper"
        guard FileManager.default.fileExists(atPath: bundledHelper) else {
            throw InstallError.bundlePathUnavailable
        }

        // Plist is generated rather than copied so we can rewrite the
        // `BundleProgram` (relative path used by SMAppService) into a
        // `Program` (absolute path) for launchd's traditional bootstrap.
        let plist = systemLaunchDaemonPlist(
            label: helperLabel,
            programPath: systemBinaryPath
        )
        let plistB64 = Data(plist.utf8).base64EncodedString()

        // Single bash script run as root via osascript. We base64-decode
        // the plist body in-line to avoid shell-quoting concerns.
        let q: (String) -> String = { Self.shellQuote($0) }
        let script = """
        set -e
        mkdir -p /Library/LaunchDaemons /Library/PrivilegedHelperTools
        printf '%s' \(q(plistB64)) | /usr/bin/base64 -d > \(q(systemPlistPath))
        chown root:wheel \(q(systemPlistPath))
        chmod 644 \(q(systemPlistPath))
        cp \(q(bundledHelper)) \(q(systemBinaryPath))
        chown root:wheel \(q(systemBinaryPath))
        chmod 755 \(q(systemBinaryPath))
        # Replace any existing daemon registration; bootout is a no-op the
        # first time. Then bootstrap from the freshly-written plist.
        launchctl bootout system/\(helperLabel) >/dev/null 2>&1 || true
        launchctl bootstrap system \(q(systemPlistPath))
        # Ask launchd to launch the daemon now rather than waiting on
        # KeepAlive semantics.
        launchctl kickstart -k system/\(helperLabel) >/dev/null 2>&1 || true
        echo OK
        """

        // AppleScript wraps the whole shell command. We keep its argument
        // single-quote escaped for safety.
        let osa = "do shell script \(appleScriptStringLiteral(script)) with administrator privileges"

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", osa]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            throw InstallError.manualInstallFailed(error.localizedDescription)
        }
        process.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            throw InstallError.manualInstallFailed(out.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        // launchctl is async — wait for the socket to come up before
        // returning so the caller can immediately make IPC calls.
        for _ in 0 ..< 50 {
            if FileManager.default.fileExists(atPath: HelperClient.socketPath) {
                return
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        throw InstallError.manualInstallFailed(
            "helper plist installed but socket never appeared; check /var/log/supermanager-helper.log"
        )
    }

    /// Removes the daemon. Best-effort: errors don't propagate because
    /// uninstall is most useful from disposable test environments.
    static func uninstall() async {
        let q: (String) -> String = { Self.shellQuote($0) }
        let script = """
        launchctl bootout system/\(helperLabel) >/dev/null 2>&1 || true
        rm -f \(q(systemPlistPath)) \(q(systemBinaryPath))
        echo OK
        """
        let osa = "do shell script \(appleScriptStringLiteral(script)) with administrator privileges"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", osa]
        try? process.run()
        process.waitUntilExit()
    }

    /// SMAppService status, mostly for diagnostics.
    static func status() -> String {
        guard #available(macOS 13.0, *) else { return "unsupported" }
        let svc = SMAppService.daemon(plistName: plistName)
        switch svc.status {
        case .notRegistered: return "notRegistered"
        case .enabled: return "enabled"
        case .requiresApproval: return "requiresApproval"
        case .notFound: return "notFound"
        @unknown default: return "unknown"
        }
    }

    static func openLoginItemsSettings() {
        if #available(macOS 13.0, *) {
            SMAppService.openSystemSettingsLoginItems()
        }
    }

    // MARK: - Plist construction

    /// Produces the same plist content as the bundled SMAppService one but
    /// with `Program` (absolute path) instead of `BundleProgram`. launchd
    /// requires `Program` for non-bundle daemons, which is what we have
    /// once we copy the binary to /Library/PrivilegedHelperTools/.
    private static func systemLaunchDaemonPlist(label: String, programPath: String) -> String {
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>Program</key>
            <string>\(programPath)</string>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <dict>
                <key>SuccessfulExit</key>
                <false/>
                <key>Crashed</key>
                <true/>
            </dict>
            <key>StandardOutPath</key>
            <string>/var/log/supermanager-helper.log</string>
            <key>StandardErrorPath</key>
            <string>/var/log/supermanager-helper.log</string>
            <key>SoftResourceLimits</key>
            <dict>
                <key>NumberOfFiles</key>
                <integer>2048</integer>
            </dict>
        </dict>
        </plist>
        """
    }

    // MARK: - Shell / AppleScript escaping

    // The escape helpers below are exposed at internal visibility so the
    // test target can poke at them without instantiating SMAppService.
    // Both are pure functions; nothing here touches global state.

    /// Wrap `s` in bash single quotes and escape any embedded single quotes.
    static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// AppleScript double-quoted string literal: escape `"` and `\`.
    /// We pass an entire bash script as a single AppleScript string.
    static func appleScriptStringLiteral(_ s: String) -> String {
        let escaped = s
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
    }
}
