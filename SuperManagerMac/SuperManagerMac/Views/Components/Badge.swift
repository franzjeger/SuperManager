import SwiftUI

/// Colour categories for `Badge`.
///
/// A badge's colour carries a CATEGORY (which VPN backend, which key type),
/// never a state — state is `StatusStyle`'s job. Keeping the set closed means a
/// new call site can't invent a colour and drift the palette.
enum BadgeKind: Hashable {
    case azure
    case ikev2
    case openvpn
    case wireguard
    /// Device roles, key types, anything without a dedicated colour.
    case neutral

    var color: Color {
        switch self {
        case .azure:     return .indigo
        case .ikev2:     return .blue
        case .openvpn:   return .pink
        case .wireguard: return .teal
        case .neutral:   return .gray
        }
    }
}

extension BadgeKind {
    /// Resolve a backend badge from whatever the daemon calls it.
    ///
    /// The daemon spells backends several ways depending on the endpoint —
    /// `forti_gate` (the serde discriminator) vs `FortiGate (IPsec/IKEv2)` (the
    /// display label) — so match loosely. A tightened match would silently grey
    /// out every badge the day someone renames a label for the UI.
    static func backend(_ raw: String) -> BadgeKind {
        let s = raw.lowercased()
        if s.contains("azure") { return .azure }
        if s.contains("wire") { return .wireguard }
        if s.contains("open") { return .openvpn }
        if s.contains("forti") || s.contains("ikev2") || s.contains("ipsec") { return .ikev2 }
        return .neutral
    }
}

/// Small tinted chip for a categorical label — VPN backend, device role, key
/// type. Sits next to a name in a list row or a detail header.
struct Badge: View {
    let text: String
    var kind: BadgeKind = .neutral

    var body: some View {
        Text(text)
            .font(.system(size: 10, weight: .semibold))
            .fixedSize()              // never wrap a two-word category
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .foregroundStyle(kind.color)
            .background(kind.color.opacity(0.16), in: RoundedRectangle(cornerRadius: 5))
    }
}

#if DEBUG
#Preview("Badges") {
    VStack(alignment: .leading, spacing: 10) {
        HStack(spacing: 6) {
            Badge(text: "Azure", kind: .azure)
            Badge(text: "IKEv2", kind: .ikev2)
            Badge(text: "OpenVPN", kind: .openvpn)
            Badge(text: "WireGuard", kind: .wireguard)
        }
        HStack(spacing: 6) {
            Badge(text: "Gateway")
            Badge(text: "Access point")
            Badge(text: "ed25519")
        }
        // Resolved the way the sidebar will resolve them.
        HStack(spacing: 6) {
            Badge(text: "IKEv2", kind: .backend("FortiGate (IPsec/IKEv2)"))
            Badge(text: "WireGuard", kind: .backend("wire_guard"))
        }
    }
    .padding()
}
#endif
