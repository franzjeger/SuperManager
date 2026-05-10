import SwiftUI

/// Small connection-state indicator dot for VPN profile rows.
/// The whole VPN section uses ad-hoc Circle()s with copy-pasted
/// colour mappings — extracting this here means the legend stays
/// consistent if we add new states later.
struct VpnStatusDot: View {
    /// State string from `AppState.vpnConnectionStates` —
    /// "connected" / "connecting" / "disconnected" / nil.
    let state: String?
    var diameter: CGFloat = 8

    var body: some View {
        Circle()
            .fill(Self.color(state))
            .frame(width: diameter, height: diameter)
            .overlay(
                // Subtle white halo so the dot reads on both
                // light + dark backgrounds.
                Circle().stroke(.white.opacity(0.6), lineWidth: 0.5)
            )
            .help(Self.label(state))
            .accessibilityLabel("VPN \(Self.label(state))")
    }

    static func color(_ state: String?) -> Color {
        switch state {
        case "connected":     return .green
        case "connecting":    return .yellow
        case "disconnecting": return .orange
        case "disconnected":  return .secondary
        case .some(let s) where s.contains("error"):
            return .red
        default:              return .secondary
        }
    }

    static func label(_ state: String?) -> String {
        switch state {
        case "connected":     return "connected"
        case "connecting":    return "connecting"
        case "disconnecting": return "disconnecting"
        case "disconnected":  return "disconnected"
        case .some(let s):    return s
        case nil:             return "unknown"
        }
    }
}

#if DEBUG
#Preview("VPN status dots") {
    HStack(spacing: 16) {
        VStack { VpnStatusDot(state: "connected"); Text("connected").font(.caption) }
        VStack { VpnStatusDot(state: "connecting"); Text("connecting").font(.caption) }
        VStack { VpnStatusDot(state: "disconnecting"); Text("disconnecting").font(.caption) }
        VStack { VpnStatusDot(state: "disconnected"); Text("disconnected").font(.caption) }
        VStack { VpnStatusDot(state: nil); Text("unknown").font(.caption) }
    }
    .padding()
}
#endif
