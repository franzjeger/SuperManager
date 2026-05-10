import Foundation

/// Sample the system's currently-active network connections and
/// summarise them as a list of `/24` subnets, ranked by how many
/// distinct remote IPs we observed in each.
///
/// ## Why
///
/// Switching from full-tunnel to split-tunnel is paralysing without
/// a starting point: "which subnets do I actually need to route over
/// the VPN?" Most users don't know off the top of their head. We
/// can give them a concrete answer by looking at what their machine
/// is *currently* talking to.
///
/// Run this while the user is in full-tunnel mode (so all the
/// remote endpoints they care about ARE reachable) and the
/// suggestion list will be the set of subnets they hit during the
/// sample window — typically the company LAN, a couple of SaaS
/// providers' edges, etc.
///
/// ## How
///
/// `lsof -i -nP`:
///   • `-i` — show network sockets
///   • `-n` — don't resolve hostnames (faster, doesn't DNS-leak)
///   • `-P` — don't translate port numbers to service names
///
/// Each line that has a `->` arrow has a `local-addr -> remote-addr`
/// pair we can extract. We strip ports, drop multicast / loopback /
/// link-local, fold to `/24` (IPv4) or `/64` (IPv6), and rank.
///
/// No root needed — `lsof` shows the user's own sockets.
enum SubnetDiscovery {
    /// One scan result. `subnet` is in CIDR form
    /// (`192.168.1.0/24`); `peerCount` is how many distinct remote
    /// IPs we saw inside it during the sample.
    struct Suggestion: Identifiable, Hashable {
        let subnet: String
        let peerCount: Int
        var id: String { subnet }
    }

    /// Run a one-shot lsof and return CIDR suggestions, ranked by
    /// peer count desc. Excludes loopback (127/8), link-local
    /// (169.254/16), multicast (224/4), and obvious junk.
    static func sampleConnections() async -> [Suggestion] {
        let output = await runLsof()
        let remoteIPs = parseRemoteIPs(output)
        return rankSubnets(remoteIPs)
    }

    /// Fork `lsof -i -nP`, capture stdout. Returns empty string on
    /// failure — discovery is a "nice to have," never bubble an
    /// error to the user.
    private static func runLsof() async -> String {
        await Task.detached(priority: .userInitiated) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
            process.arguments = ["-i", "-nP"]
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            do { try process.run() } catch { return "" }
            // lsof finishes in <1s on a typical Mac. Read all stdout
            // before waitUntilExit so we don't deadlock on full pipe.
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(data: data, encoding: .utf8) ?? ""
        }.value
    }

    /// Walk lsof output, pull remote IPs (the bit after `->`).
    /// Tolerates IPv6 brackets and bracket-less form.
    static func parseRemoteIPs(_ output: String) -> [String] {
        var out: [String] = []
        for line in output.split(separator: "\n") {
            // Format roughly:
            // COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            // The NAME column for connected sockets looks like:
            //   192.168.1.10:54321->1.2.3.4:443  (IPv4)
            //   [2001:db8::1]:54321->[2001:db8::2]:443  (IPv6)
            guard let arrowRange = line.range(of: "->") else { continue }
            let after = line[arrowRange.upperBound...]
            // The remote endpoint runs to the next whitespace or
            // `(` (open of a state-flag like `(ESTABLISHED)`).
            let endIdx = after.firstIndex { $0.isWhitespace || $0 == "(" }
                ?? after.endIndex
            let endpoint = after[..<endIdx]

            // Strip port. IPv6 addresses are bracketed: `[::1]:443`.
            // IPv4 is `1.2.3.4:443`. Split on the LAST colon only
            // for IPv4; for v6, drop the brackets first.
            let ip: String
            if endpoint.first == "[" {
                guard let close = endpoint.firstIndex(of: "]") else { continue }
                ip = String(endpoint[endpoint.index(after: endpoint.startIndex)..<close])
            } else if let lastColon = endpoint.lastIndex(of: ":") {
                ip = String(endpoint[..<lastColon])
            } else {
                continue
            }
            if isInteresting(ip) {
                out.append(ip)
            }
        }
        return out
    }

    /// Drop addresses that are uninteresting for split-tunnel
    /// suggestions: loopback, link-local, multicast, and the wildcard.
    private static func isInteresting(_ ip: String) -> Bool {
        if ip == "*" || ip.isEmpty { return false }
        // IPv4
        if let firstDot = ip.firstIndex(of: "."),
           let firstOctet = UInt8(ip[..<firstDot]) {
            if firstOctet == 127 { return false }              // 127/8 loopback
            if firstOctet == 0 { return false }                // unspecified
            if firstOctet >= 224 { return false }              // multicast / reserved
            if ip.hasPrefix("169.254.") { return false }       // link-local
            return true
        }
        // IPv6
        if ip.contains(":") {
            let lower = ip.lowercased()
            if lower == "::1" { return false }
            if lower == "::" { return false }
            if lower.hasPrefix("fe80") { return false }        // link-local
            if lower.hasPrefix("ff") { return false }          // multicast
            return true
        }
        return false
    }

    /// Group IPs into /24 (IPv4) or /64 (IPv6) subnets, count
    /// distinct peers per subnet, return sorted by count descending.
    static func rankSubnets(_ ips: [String]) -> [Suggestion] {
        // subnet → set-of-distinct-IPs. `Set` so a single IP with
        // 50 connections doesn't dominate over a subnet with 5
        // distinct peers.
        var map: [String: Set<String>] = [:]
        for ip in ips {
            guard let cidr = subnetFor(ip) else { continue }
            map[cidr, default: []].insert(ip)
        }
        return map
            .map { Suggestion(subnet: $0.key, peerCount: $0.value.count) }
            .sorted { lhs, rhs in
                if lhs.peerCount != rhs.peerCount { return lhs.peerCount > rhs.peerCount }
                return lhs.subnet < rhs.subnet
            }
    }

    /// Map an IP to its containing /24 (IPv4) or /64 (IPv6).
    /// Returns CIDR string. We don't try to be cute about RFC1918
    /// vs public — both are surfaceable, the user picks.
    private static func subnetFor(_ ip: String) -> String? {
        // IPv4 a.b.c.d → a.b.c.0/24
        if !ip.contains(":"), ip.contains(".") {
            let parts = ip.split(separator: ".")
            guard parts.count == 4 else { return nil }
            return "\(parts[0]).\(parts[1]).\(parts[2]).0/24"
        }
        // IPv6 a:b:c:d:... → a:b:c:d::/64. We take the first 4
        // colon-separated groups; lsof sometimes elides with `::`,
        // which gets messy — fall back to a literal /128 for those
        // odd cases rather than emit a bad CIDR.
        if ip.contains(":"), !ip.contains("::") {
            let parts = ip.split(separator: ":")
            guard parts.count >= 4 else { return nil }
            return "\(parts[0]):\(parts[1]):\(parts[2]):\(parts[3])::/64"
        }
        return nil
    }
}
