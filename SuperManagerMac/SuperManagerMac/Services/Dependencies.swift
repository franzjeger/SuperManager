import Foundation

/// The external tools SuperManager drives, and installing them for the
/// operator instead of handing out shell commands.
///
/// SuperManager runs the real VPN clients rather than reimplementing
/// them, so each VPN type needs its client present. Telling the user to
/// paste a `brew install` line into Terminal is a support burden and a
/// bad first run — the app knows exactly what is missing and can do it.
///
/// Homebrew runs as the logged-in user. The privileged helper verifies
/// and installs bundled runtime programs. We do not silently install Homebrew
/// itself: that is a large third-party install that the user should
/// initiate knowingly, so we link to brew.sh instead.
@MainActor
enum Dependencies {

    /// One external tool, why it is needed, and how to get it.
    struct Tool: Identifiable, Sendable {
        /// Stable key, also the id.
        let id: String
        /// What the operator loses without it.
        let feature: String
        /// Binary names that prove it is installed — any one is enough.
        let binaries: [String]
        /// Homebrew formula, or nil when brew can't supply it.
        let formula: String?
        /// Set when installation is not a brew formula.
        let manualNote: String?

        @MainActor var isInstalled: Bool { binaries.contains { Dependencies.isPresent($0) } }
    }

    /// Search paths. Homebrew differs by architecture, and MacPorts
    /// shows up on some machines; `/usr/local/sbin` is where the app's
    /// own bundled tailscaled lands.
    nonisolated static let searchPaths = [
        "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/opt/local/bin", "/opt/local/sbin",
        "/usr/local/sbin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ]

    static func isPresent(_ binary: String) -> Bool {
        if binary == "openvpn" || binary == "openvpn3" {
            if hasProtectedOpenVPN(requireOpenVPN3: binary == "openvpn3", available: isRootOwnedExecutable) {
                return true
            }
            // Release helpers refuse executables in user-owned prefixes.
            // Merely finding Homebrew's binary must leave Install available.
            #if !DEBUG
            return false
            #endif
        }
        if binary == "swanctl" {
            let runtime = "/Library/PrivilegedHelperTools/SuperManagerVPN"
            if isRootOwnedExecutable("\(runtime)/charon") && isRootOwnedExecutable("\(runtime)/swanctl") {
                return true
            }
        }
        if binary == "wg-quick" {
            let runtime = "/Library/PrivilegedHelperTools/SuperManagerVPN"
            if isRootOwnedExecutable("\(runtime)/wg-quick") {
                return true
            }
        }
        let binaries = binary == "openvpn" ? ["openvpn", "openvpn-patched", "openvpn3"] : [binary]
        return searchPaths.contains { directory in
            binaries.contains { FileManager.default.isExecutableFile(atPath: "\(directory)/\($0)") }
        }
    }

    /// Ordinary profiles can use the helper's protected OpenVPN 3 fallback;
    /// Azure profiles specifically require it and must never accept version 2.
    static func hasProtectedOpenVPN(requireOpenVPN3: Bool, available: (String) -> Bool) -> Bool {
        let runtime = "/Library/PrivilegedHelperTools/SuperManagerVPN"
        let v3 = ["openvpn3", "bin/openvpn3"]
        let programs = requireOpenVPN3 ? v3 : ["openvpn", "sbin/openvpn", "bin/openvpn"] + v3
        return programs.contains { available("\(runtime)/\($0)") }
    }

    /// The helper validates the canonical executable and every parent.
    /// Repeat the ownership check here so the dependency UI reflects what
    /// Release can use; the helper remains responsible for enforcement.
    static func isRootOwnedExecutable(_ path: String) -> Bool {
        guard FileManager.default.isExecutableFile(atPath: path),
              let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let owner = attrs[.ownerAccountID] as? NSNumber,
              owner.uint32Value == 0 else { return false }
        // attributesOfItem describes the link itself. The helper also
        // rejects a user-owned symlink even when its target is protected.
        return hasRootOwnedParents(URL(fileURLWithPath: path).resolvingSymlinksInPath().path) {
            try FileManager.default.attributesOfItem(atPath: $0)
        }
    }

    static func hasRootOwnedParents(
        _ canonicalPath: String,
        attributes: (String) throws -> [FileAttributeKey: Any]
    ) -> Bool {
        var path = canonicalPath
        while true {
            guard let attrs = try? attributes(path),
                  let owner = attrs[.ownerAccountID] as? NSNumber,
                  let mode = attrs[.posixPermissions] as? NSNumber,
                  owner.uint32Value == 0, mode.uint16Value & 0o022 == 0 else { return false }
            if path == "/" { return true }
            path = URL(fileURLWithPath: path).deletingLastPathComponent().path
        }
    }

    static func hasBundledRuntime(for id: String) -> Bool {
        guard let dir = HelperClient.bundledVPNRuntime else { return false }
        return hasBundledRuntime(for: id, directory: dir)
    }

    static func hasBundledRuntime(for id: String, directory: String) -> Bool {
        let programs: [String]
        switch id {
        case "openvpn": programs = ["openvpn", "openvpn3"]
        case "openvpn3": programs = ["openvpn3"]
        default: return false
        }
        return programs.contains { FileManager.default.isExecutableFile(atPath: "\(directory)/\($0)") }
    }

    /// Homebrew itself — everything else depends on it.
    static var brewPath: String? {
        ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static let all: [Tool] = [
        Tool(id: "wireguard-tools",
             feature: "WireGuard profiles",
             binaries: ["wg-quick"],
             formula: "wireguard-tools",
             manualNote: nil),
        Tool(id: "strongswan",
             feature: "IKEv2 and FortiGate IPsec profiles",
             binaries: ["swanctl"],
             formula: "strongswan",
             manualNote: nil),
        Tool(id: "openvpn",
             feature: "OpenVPN profiles",
             binaries: ["openvpn"],
             formula: "openvpn",
             manualNote: nil),
        Tool(id: "openvpn3",
             feature: "Azure VPN (Entra ID sign-in)",
             binaries: ["openvpn3"],
             formula: nil,
             // Microsoft's gateway rejects OpenVPN 2.x in the Entra
             // flow, and upstream ships no bottle — it has to be built.
             manualNote: "Install or repair OpenVPN 3 for Azure VPN. A Homebrew copy alone "
                 + "does not meet the privileged helper's requirements."),
    ]

    static var missing: [Tool] { all.filter { !$0.isInstalled } }

    /// For a tool Homebrew can't supply (`formula == nil`), the shell
    /// command that builds and installs it. Run in Terminal, not
    /// captured in-app: the OpenVPN 3 build takes minutes and ends in a
    /// `sudo install`, so its progress and password prompt have to be
    /// visible. `nil` when brew can do the job instead.
    static func terminalBuildCommand(for id: String) -> String? {
        switch id {
        case "openvpn3":
            // The documented --with-openvpn3 path: installs the build
            // deps (cmake, asio, jsoncpp, openssl@3, lz4) and runs
            // contrib/build-openvpn3-mac.sh.
            // Download completely before execution, and keep Terminal's
            // stdin available for the installer's confirmation prompts.
            return """
                installer=$(/usr/bin/mktemp "${TMPDIR:-/tmp}/supermanager-installer.XXXXXX") || exit 1
                /usr/bin/curl -fsSL https://raw.githubusercontent.com/franzjeger/SuperManager/main/scripts/install.sh -o "$installer"
                status=$?
                if [ "$status" -eq 0 ]; then
                    /bin/bash "$installer" --deps-only --with-openvpn3
                    status=$?
                fi
                /bin/rm -f "$installer"
                (exit "$status")
                """
        default:
            return nil
        }
    }

    // MARK: - Installing

    enum InstallError: LocalizedError {
        case noHomebrew
        case notBrewInstallable(String)
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .noHomebrew:
                return "Homebrew isn't installed. Get it from https://brew.sh, then try again."
            case .notBrewInstallable(let note):
                return note
            case .failed(let output):
                return output
            }
        }
    }

    /// Install a bundled runtime through the helper, or run
    /// `brew install <formula>`, returning its combined output.
    ///
    /// The helper verifies and installs bundled programs. Homebrew runs
    /// as the logged-in user because it refuses to run as root.
    nonisolated static func install(_ tool: Tool) async throws -> String {
        if await hasBundledRuntime(for: tool.id) {
            try await HelperInstaller.install()
            try await HelperClient.shared.installBundledVPNRuntime()
            return "VPN runtime installed."
        }
        guard let note = tool.formula else {
            throw InstallError.notBrewInstallable(tool.manualNote ?? "Not installable automatically.")
        }
        guard let brew = await brewPath else { throw InstallError.noHomebrew }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: brew)
        process.arguments = ["install", note]
        // A login-shell PATH isn't inherited by a GUI app; give brew the
        // prefix it lives in so its own subprocesses resolve.
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = (searchPaths + [env["PATH"] ?? ""]).joined(separator: ":")
        env["HOMEBREW_NO_AUTO_UPDATE"] = "1"   // keep it to the one job
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? ""

        guard process.terminationStatus == 0 else {
            throw InstallError.failed(
                output.isEmpty ? "brew exited \(process.terminationStatus)" : output)
        }
        return output
    }
}
