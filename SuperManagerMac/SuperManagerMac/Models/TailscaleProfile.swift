import Foundation

/// One logged-in Tailscale account/tailnet, as reported by
/// `tailscale switch --list --json`.
///
/// tailscaled stores several of these and swaps the active one with
/// `tailscale switch <id>` — no re-authentication, because the daemon
/// already holds each profile's node key. That is what makes switching
/// between tailnets near-instant rather than a full login.
struct TailscaleProfile: Codable, Identifiable, Equatable {
    /// Short stable id (e.g. `bbb1`), the argument to `tailscale switch`.
    let id: String
    /// User-facing nickname; often empty, in which case fall back to the
    /// account.
    let nickname: String
    /// The tailnet this profile belongs to.
    let tailnet: String
    /// The account (login) this profile authenticated as.
    let account: String
    /// Whether this is the currently-active profile.
    let selected: Bool

    /// Label for the switcher row: the account, plus the tailnet when it
    /// differs (they coincide for a personal tailnet, so showing both
    /// there would just be noise).
    var displayName: String {
        let primary = nickname.isEmpty ? account : nickname
        if !tailnet.isEmpty, tailnet != primary {
            return "\(primary) — \(tailnet)"
        }
        return primary
    }
}
