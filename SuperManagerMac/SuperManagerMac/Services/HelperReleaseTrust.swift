import Foundation
import Security

/// Match the root helper's release identity policy before offering installation.
enum HelperReleaseTrust {
    static let requirement = "anchor apple generic and certificate leaf[subject.OU] = \"LY6LJ395B8\" and identifier \"com.sybr.supermanager\" and ! entitlement[\"com.apple.security.get-task-allow\"] exists and ! entitlement[\"com.apple.security.cs.disable-library-validation\"] exists and ! entitlement[\"com.apple.security.cs.allow-dyld-environment-variables\"] exists"

    enum TrustError: LocalizedError {
        case releaseRequired
        var errorDescription: String? {
            "Privileged networking requires the signed SuperManager release app. Unsigned or debug builds cannot use the system helper."
        }
    }

    static func verifyCurrentApplication() throws {
        var code: SecCode?
        var policy: SecRequirement?
        guard SecCodeCopySelf([], &code) == errSecSuccess,
              SecRequirementCreateWithString(requirement as CFString, [], &policy) == errSecSuccess,
              let code, let policy,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), policy) == errSecSuccess
        else { throw TrustError.releaseRequired }
        // The helper independently checks the audit token, runtime and debug state.
    }
}
