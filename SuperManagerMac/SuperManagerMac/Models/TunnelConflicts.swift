import Foundation
import Network

/// What a tunnel sends through itself.
struct TunnelRouting: Equatable {
    let name: String
    /// It carries the default route: everything no more specific route
    /// claims, including what other tunnels send to their servers.
    let takesAll: Bool
    /// Networks it carries besides, as `address/length`.
    let routes: [String]
}

/// Why two tunnels get in each other's way.
enum TunnelConflict: Hashable {
    /// `taker` carries the default route and `other` does not, so what
    /// `other` sends to its own server goes through `taker`.
    case takesAll(taker: String, other: String)
    /// Both want the default route, and only one of them gets it.
    case bothTakeAll(String, String)
    /// `route` and `otherRoute` share addresses. The more specific route
    /// gets them, and of two alike, the one installed first.
    case overlap(tunnel: String, route: String, other: String, otherRoute: String)

    var message: String {
        switch self {
        case let .takesAll(taker, other):
            return "\(taker) sends all traffic through its tunnel, including \(other)'s "
                + "connection to its server. \(other) can stop working while both are connected."
        case let .bothTakeAll(one, other):
            return "\(one) and \(other) both send all traffic through their tunnels. "
                + "Only one of them can."
        case let .overlap(tunnel, route, other, otherRoute) where route == otherRoute:
            return "\(tunnel) and \(other) both route \(route). It goes through only one of them."
        case let .overlap(tunnel, route, other, otherRoute):
            let (inner, innerRoute, outer, outerRoute) =
                (IPPrefix(route)?.length ?? 0) > (IPPrefix(otherRoute)?.length ?? 0)
                ? (tunnel, route, other, otherRoute)
                : (other, otherRoute, tunnel, route)
            return "\(inner) routes \(innerRoute), inside \(outer)'s \(outerRoute). "
                + "Those addresses go through \(inner), not \(outer)."
        }
    }
}

enum TunnelConflicts {
    /// What gets in the way when `tunnel` runs alongside `others`, each
    /// conflict once.
    static func between(_ tunnel: TunnelRouting, and others: [TunnelRouting]) -> [TunnelConflict] {
        var seen = Set<TunnelConflict>()
        return others.flatMap { other -> [TunnelConflict] in
            switch (tunnel.takesAll, other.takesAll) {
            case (true, true):
                return [.bothTakeAll(tunnel.name, other.name)]
            case (true, false):
                return [.takesAll(taker: tunnel.name, other: other.name)]
            case (false, true):
                return [.takesAll(taker: other.name, other: tunnel.name)]
            case (false, false):
                return overlaps(tunnel, other)
            }
        }
        .filter { seen.insert($0).inserted }
    }

    private static func overlaps(_ tunnel: TunnelRouting, _ other: TunnelRouting) -> [TunnelConflict] {
        // A default route among them overlaps everything, and is `takesAll`'s
        // business, not a network's.
        func networks(_ routes: [String]) -> [(String, IPPrefix)] {
            routes.compactMap { route in
                IPPrefix(route).flatMap { $0.length > 0 ? (route, $0) : nil }
            }
        }
        let theirs = networks(other.routes)
        return networks(tunnel.routes).flatMap { route, prefix in
            theirs
                .filter { $0.1.overlaps(prefix) }
                .map { .overlap(tunnel: tunnel.name, route: route, other: other.name, otherRoute: $0.0) }
        }
    }
}

/// An IPv4 or IPv6 network, `address/length`. A bare address is one host.
struct IPPrefix: Equatable {
    let bytes: [UInt8]
    let length: Int

    init?(_ text: String) {
        let parts = text.split(separator: "/", maxSplits: 1).map(String.init)
        guard let address = parts.first else { return nil }
        if let v4 = IPv4Address(address) {
            bytes = Array(v4.rawValue)
        } else if let v6 = IPv6Address(address) {
            bytes = Array(v6.rawValue)
        } else {
            return nil
        }
        let bits = bytes.count * 8
        if parts.count == 2 {
            guard let length = Int(parts[1]), (0...bits).contains(length) else { return nil }
            self.length = length
        } else {
            length = bits
        }
    }

    /// Whether the two share an address: the shorter one contains the other.
    func overlaps(_ other: IPPrefix) -> Bool {
        guard bytes.count == other.bytes.count else { return false }
        let shared = min(length, other.length)
        let whole = shared / 8
        guard bytes[..<whole] == other.bytes[..<whole] else { return false }
        let rest = shared % 8
        guard rest > 0 else { return true }
        let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - rest))
        return bytes[whole] & mask == other.bytes[whole] & mask
    }
}
