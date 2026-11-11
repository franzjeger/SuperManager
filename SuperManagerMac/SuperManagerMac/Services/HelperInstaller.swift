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
    static let teamID = "LY6LJ395B8"

    /// Designated code-signing requirement for the privileged helper binary:
    /// anchored at Apple, issued to SuperManager's Team ID, with the helper's
    /// exact bundle identifier. Satisfied by both Developer ID Application and
    /// Apple Development certificates on this team, and rejected for ad-hoc,
    /// third-party, or system binaries.
    nonisolated static let helperDesignatedRequirement =
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"\(helperLabel)\""

    /// Matches a bundle signed with a Developer ID Application certificate on
    /// SuperManager's team (same OIDs `supermanager-helper/src/client_auth.rs`
    /// checks). Developer-ID builds use `SMAppService` exclusively and never
    /// fall back to `osascript`.
    nonisolated private static let developerIDRequirement =
        "anchor apple generic"
        + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
        + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        + " and certificate leaf[subject.OU] = \"\(teamID)\""

    /// `/Library/LaunchDaemons/com.sybr.supermanager.helper.plist`
    private static let systemPlistPath =
        "/Library/LaunchDaemons/com.sybr.supermanager.helper.plist"
    /// `/Library/PrivilegedHelperTools/com.sybr.supermanager.helper`
    private static let systemBinaryPath =
        "/Library/PrivilegedHelperTools/com.sybr.supermanager.helper"

    enum InstallError: Error, LocalizedError {
        case registrationFailed(String)
        case approvalRequired
        case invalidSignature(String)
        case bundlePathUnavailable
        case bundledMetadataUnavailable
        case manualInstallFailed(String)
        case unsupportedPlatform

        var errorDescription: String? {
            switch self {
            case .registrationFailed(let m):
                return "Helper registration failed: \(m)"
            case .approvalRequired:
                return "SuperManager needs permission to run its background helper. Enable SuperManager in System Settings → General → Login Items & Extensions, then try again."
            case .invalidSignature(let m):
                return "Bundled helper failed code-signature verification: \(m)"
            case .bundlePathUnavailable:
                return "Could not find helper binary inside app bundle"
            case .bundledMetadataUnavailable:
                return "Could not verify the bundled helper build. Reinstall the app before installing its helper."
            case .manualInstallFailed(let m):
                return "Helper install failed: \(m)"
            case .unsupportedPlatform:
                return "Helper requires macOS 13 (Ventura) or later"
            }
        }
    }

    /// Install the helper as a system LaunchDaemon. Tries `SMAppService` first;
    /// Developer-ID builds stop there (surfacing Login Items approval when
    /// needed), while non-Developer-ID local development builds may fall back
    /// to administrator installation after verifying the team signature.
    static func install() async throws {
        guard #available(macOS 13.0, *) else { throw InstallError.unsupportedPlatform }

        let bundledHelper = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/com.sybr.supermanager.helper")
        guard FileManager.default.isExecutableFile(atPath: bundledHelper.path) else {
            throw InstallError.bundlePathUnavailable
        }

        // Verify the bundled helper's signature BEFORE running `--version` or
        // registering it with launchd.
        let requirement = try await verifiedRequirement(for: bundledHelper)

        // The app and helper have independent version numbers. Compare
        // the running helper with the actual bundled binary, including
        // its build identity and RPC capabilities, before skipping install.
        let bundled: HelperBuildInfo
        do {
            bundled = try await HelperBuildInfo.read(from: bundledHelper)
        } catch {
            throw InstallError.bundledMetadataUnavailable
        }
        if await installedHelperMatches(bundled) { return }

        let svc = SMAppService.daemon(plistName: plistName)
        if svc.status == .requiresApproval {
            openLoginItemsSettings()
            throw InstallError.approvalRequired
        }

        var registrationError: InstallError?
        do {
            try svc.register()
            if svc.status == .requiresApproval {
                openLoginItemsSettings()
                throw InstallError.approvalRequired
            }
            for _ in 0 ..< 30 {
                if await installedHelperMatches(bundled) {
                    return
                }
                if svc.status == .requiresApproval {
                    openLoginItemsSettings()
                    throw InstallError.approvalRequired
                }
                try? await Task.sleep(for: .milliseconds(100))
            }
        } catch let err as InstallError {
            throw err
        } catch {
            if svc.status == .requiresApproval {
                openLoginItemsSettings()
                throw InstallError.approvalRequired
            }
            let ns = error as NSError
            registrationError = .registrationFailed(
                "\(ns.localizedDescription) (domain=\(ns.domain) code=\(ns.code))"
            )
        }

        // Shipped Developer-ID builds never fall back to osascript.
        if await isDeveloperIDSignedBundle() {
            throw registrationError ?? InstallError.registrationFailed(
                "helper registered with launchd (status: \(svc.status.rawValue)), but socket did not become ready; check /var/log/supermanager-helper.log"
            )
        }

        #if DEBUG
        try await manualInstall(
            bundledHelper: bundledHelper,
            expected: bundled,
            requirement: requirement
        )
        #else
        // Local Apple-Development builds (`scripts/install_mac_app.sh`) compile
        // in Release configuration without a Developer ID cert, which macOS's
        // `SMAppService.daemon` rejects with `Operation not permitted`. Allow
        // manualInstall ONLY when the helper carries SuperManager's team cert.
        guard let requirement else {
            throw registrationError ?? InstallError.invalidSignature("missing team signature")
        }
        try await manualInstall(
            bundledHelper: bundledHelper,
            expected: bundled,
            requirement: requirement
        )
        #endif
    }

    /// Verify `bundledHelper` against `helperDesignatedRequirement` and return
    /// the requirement to enforce during staging. In `DEBUG` only, an ad-hoc
    /// signature is tolerated (`nil` requirement) so unsigned local test runs
    /// can still exercise non-Release builds.
    private static func verifiedRequirement(for bundledHelper: URL) async throws -> String? {
        let strict = await checkCodesign(path: bundledHelper.path, requirement: helperDesignatedRequirement)
        if strict.status == 0 {
            return helperDesignatedRequirement
        }
        #if DEBUG
        let basic = await checkCodesign(path: bundledHelper.path, requirement: nil)
        if basic.status == 0 {
            return nil
        }
        #endif
        let detail = strict.output.trimmingCharacters(in: .whitespacesAndNewlines)
        throw InstallError.invalidSignature(detail.isEmpty ? "exit \(strict.status)" : detail)
    }

    nonisolated private static func isDeveloperIDSignedBundle(
        _ bundleURL: URL = Bundle.main.bundleURL
    ) async -> Bool {
        let res = await checkCodesign(path: bundleURL.path, requirement: developerIDRequirement)
        return res.status == 0
    }

    nonisolated private static func checkCodesign(
        path: String,
        requirement: String?
    ) async -> (status: Int32, output: String) {
        await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
            var args = ["--verify", "--strict"]
            if let requirement, !requirement.isEmpty {
                args.append("-R=\(requirement)")
            }
            args.append(path)
            process.arguments = args
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            do {
                try process.run()
            } catch {
                return (-1, error.localizedDescription)
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
        }.value
    }

    private static func installedHelperMatches(_ expected: HelperBuildInfo) async -> Bool {
        guard let response = try? await HelperClient.shared.helperVersion(),
              let deployed = HelperBuildInfo(json: response) else { return false }
        return deployed.matches(expected)
    }

    /// Fallback for non-Developer-ID local builds: write the LaunchDaemon plist
    /// + helper binary to the system locations and bootstrap them under one
    /// `osascript with administrator privileges` call, verifying the designated
    /// code requirement before stopping the existing service and again on the
    /// root-owned staged inode before `mv`.
    private static func manualInstall(
        bundledHelper: URL,
        expected: HelperBuildInfo,
        requirement: String?
    ) async throws {
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
        let verifySourceCmd: String
        if let requirement, !requirement.isEmpty {
            verifySourceCmd = "/usr/bin/codesign --verify --strict -R=\(q(requirement)) \(q(bundledHelper.path))"
        } else {
            verifySourceCmd = "/usr/bin/codesign --verify --strict \(q(bundledHelper.path))"
        }
        let script = """
        set -e
        mkdir -p /Library/LaunchDaemons /Library/PrivilegedHelperTools
        printf '%s' \(q(plistB64)) | /usr/bin/base64 -d > \(q(systemPlistPath))
        chown root:wheel \(q(systemPlistPath))
        chmod 644 \(q(systemPlistPath))
        # Verify before stopping the existing service. Never overwrite a
        # signed executable in place: macOS may retain its old code pages.
        \(verifySourceCmd)
        launchctl bootout system/\(helperLabel) >/dev/null 2>&1 || true
        \(atomicReplacementScript(source: bundledHelper.path, destination: systemBinaryPath, requirement: requirement))
        chown root:wheel \(q(systemBinaryPath))
        for attempt in {1..5}; do
            if launchctl bootstrap system \(q(systemPlistPath)); then break; fi
            sleep 0.3
        done
        # Ask launchd to launch the daemon now rather than waiting on
        # KeepAlive semantics.
        launchctl kickstart -k system/\(helperLabel) >/dev/null 2>&1 || true
        echo OK
        """

        // AppleScript wraps the whole shell command. We keep its argument
        // single-quote escaped for safety, and run `/usr/bin/osascript` off
        // `@MainActor` so the admin authentication dialog never blocks UI events.
        let osa = "do shell script \(appleScriptStringLiteral(script)) with administrator privileges"

        let (status, out): (Int32, String)
        do {
            (status, out) = try await runOsascript(osa)
        } catch {
            throw InstallError.manualInstallFailed(error.localizedDescription)
        }
        guard status == 0 else {
            throw InstallError.manualInstallFailed(out.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        // launchctl is async — wait for the socket to come up before
        // returning so the caller can immediately make IPC calls.
        for _ in 0 ..< 50 {
            if await installedHelperMatches(expected) {
                return
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        throw InstallError.manualInstallFailed(
            "helper installed but a matching build did not become ready; check /var/log/supermanager-helper.log"
        )
    }

    /// Stage on the destination filesystem, validate, then rename to a new
    /// inode. In-place copies of a previously executed signed Mach-O can be
    /// killed by macOS even when codesign says the on-disk bytes are valid.
    /// Exposed internally so tests execute the exact installer operation.
    static func atomicReplacementScript(
        source: String,
        destination: String,
        requirement: String? = helperDesignatedRequirement
    ) -> String {
        let stagedTemplate = destination + ".XXXXXX"
        let verifyStagedCmd: String
        if let requirement, !requirement.isEmpty {
            verifyStagedCmd = "/usr/bin/codesign --verify --strict -R=\(shellQuote(requirement)) \"$helper_staged\""
        } else {
            verifyStagedCmd = "/usr/bin/codesign --verify --strict \"$helper_staged\""
        }
        return """
        helper_staged=$(/usr/bin/mktemp \(shellQuote(stagedTemplate)))
        trap '/bin/rm -f "$helper_staged"' EXIT
        /bin/cp \(shellQuote(source)) "$helper_staged"
        /bin/chmod 755 "$helper_staged"
        \(verifyStagedCmd)
        /bin/mv -f "$helper_staged" \(shellQuote(destination))
        trap - EXIT
        """
    }

    /// Execute `/usr/bin/osascript -e <osa>` off `@MainActor` so waiting on
    /// macOS's administrator password dialog never stalls the main runloop.
    nonisolated private static func runOsascript(_ osa: String) async throws -> (status: Int32, output: String) {
        try await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", osa]
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let out = String(data: data, encoding: .utf8) ?? ""
            return (process.terminationStatus, out)
        }.value
    }

    private static func openLoginItemsSettings() {
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
