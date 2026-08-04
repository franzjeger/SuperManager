import Foundation

/// The external tools SuperManager drives, and installing them for the
/// operator instead of handing out shell commands.
///
/// SuperManager runs the real VPN clients rather than reimplementing
/// them, so each VPN type needs its client present. Telling the user to
/// paste a `brew install` line into Terminal is a support burden and a
/// bad first run — the app knows exactly what is missing and can do it.
///
/// Nothing here is privileged. Homebrew refuses to run as root by
/// design, so these run as the logged-in user, exactly as if typed into
/// Terminal. The one thing we will NOT do silently is install Homebrew
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

        var isInstalled: Bool { binaries.contains(where: Dependencies.isPresent) }
    }

    /// Search paths. Homebrew differs by architecture, and MacPorts
    /// shows up on some machines; `/usr/local/sbin` is where the app's
    /// own bundled tailscaled lands.
    static let searchPaths = [
        "/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin",
        "/usr/local/sbin", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    ]

    static func isPresent(_ binary: String) -> Bool {
        searchPaths.contains { FileManager.default.isExecutableFile(atPath: "\($0)/\(binary)") }
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
             feature: "OpenVPN 2.x profiles",
             binaries: ["openvpn"],
             formula: "openvpn",
             manualNote: nil),
        Tool(id: "openvpn3",
             feature: "Azure VPN (Entra ID sign-in)",
             binaries: ["openvpn3", "openvpn-patched"],
             formula: nil,
             // Microsoft's gateway rejects OpenVPN 2.x in the Entra
             // flow, and upstream ships no bottle — it has to be built.
             manualNote: "No Homebrew formula exists. Build it with "
                 + "./contrib/build-openvpn3-mac.sh from a checkout "
                 + "(takes several minutes)."),
    ]

    static var missing: [Tool] { all.filter { !$0.isInstalled } }

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

    /// Run `brew install <formula>`, returning its combined output.
    ///
    /// Deliberately NOT run through the privileged helper: Homebrew
    /// refuses to run as root, and there is no reason to elevate — this
    /// is the same command the user would type themselves.
    nonisolated static func install(_ tool: Tool) async throws -> String {
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
