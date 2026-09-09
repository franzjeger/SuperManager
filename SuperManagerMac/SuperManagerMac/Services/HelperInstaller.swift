import Foundation

/// Reports signed system-package readiness. No unsigned/manual installation fallback.
@MainActor
enum HelperInstaller {

    enum InstallError: Error, LocalizedError {
        case registrationFailed(String)
        case unsupportedPlatform

        var errorDescription: String? {
            switch self {
            case .registrationFailed(let message): return message
            case .unsupportedPlatform: return "System components require macOS 13 or later."
            }
        }
    }

    /// Privileged components are installed together by the signed system package.
    /// A listening socket alone is not proof that this client is authorized.
    static func install() async throws {
        guard #available(macOS 13.0, *) else { throw InstallError.unsupportedPlatform }
        try HelperReleaseTrust.verifyCurrentApplication()
        if await HelperClient.shared.isReachable() {
            let runtime = try await HelperClient.shared.runtimeStatus()
            guard runtime["available"] as? Bool == true else {
                throw InstallError.registrationFailed(runtime["message"] as? String
                    ?? "Install the matching signed SuperManager system package; the VPN runtime is missing.")
            }
            return
        }
        throw InstallError.registrationFailed(
            "Install the signed SuperManager system package, then reopen the app. "
            + "The package installs the helper and its matching VPN runtime. "
            + "Unsigned builds and manual Homebrew installations are not supported.")
    }

}
