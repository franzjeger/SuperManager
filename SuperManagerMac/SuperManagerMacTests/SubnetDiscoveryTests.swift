import XCTest
@testable import SuperManagerMac

/// Tests for the pure parsing layer of `SubnetDiscovery`.
///
/// The lsof shell-out itself isn't tested here (would need a
/// stubbed Process); we test the three pure helpers it feeds:
///   - `parseRemoteIPs` — string parsing of lsof output
///   - `rankSubnets`    — grouping + ranking
///   - the v4 + v6 path inside `subnetFor` via `rankSubnets`
final class SubnetDiscoveryTests: XCTestCase {
    // MARK: - parseRemoteIPs

    func testParseRemoteIPsExtractsIpv4() {
        let lsof = "Chrome 1 user 5u IPv4 0x1234 0t0 TCP 10.0.0.5:54321->1.2.3.4:443 (ESTABLISHED)"
        let ips = SubnetDiscovery.parseRemoteIPs(lsof)
        XCTAssertEqual(ips, ["1.2.3.4"])
    }

    func testParseRemoteIPsExtractsIpv6Bracketed() {
        let lsof = "Chrome 1 user 5u IPv6 0x1234 0t0 TCP [fe80::1]:54321->[2001:db8::2]:443 (ESTABLISHED)"
        let ips = SubnetDiscovery.parseRemoteIPs(lsof)
        XCTAssertEqual(ips, ["2001:db8::2"], "should strip brackets, drop the fe80 source")
    }

    func testParseRemoteIPsDropsLoopback() {
        // 127/8 must NEVER appear in suggestions — it's never
        // routable over a VPN. Same for the unspecified address.
        let lsof = """
        proc 1 u 3u IPv4 0x1 0t0 TCP 127.0.0.1:5000->127.0.0.1:5001 (ESTABLISHED)
        proc 1 u 4u IPv4 0x2 0t0 TCP 10.0.0.1:5000->0.0.0.0:5001 (ESTABLISHED)
        """
        let ips = SubnetDiscovery.parseRemoteIPs(lsof)
        XCTAssertTrue(ips.isEmpty, "loopback + unspecified must be dropped, got \(ips)")
    }

    func testParseRemoteIPsDropsLinkLocal() {
        // 169.254/16 is APIPA — DHCP-failed self-assigned addresses,
        // never something the user wants to route via a VPN.
        let lsof = "proc 1 u 3u IPv4 0x1 0t0 TCP 10.0.0.1:5000->169.254.1.1:5001 (ESTABLISHED)"
        let ips = SubnetDiscovery.parseRemoteIPs(lsof)
        XCTAssertTrue(ips.isEmpty)
    }

    func testParseRemoteIPsDropsMulticast() {
        // 224/4 is multicast (mDNS, SSDP). Suggesting it would
        // route local discovery traffic over the VPN, breaking
        // AirPlay / printer discovery.
        let lsof = "proc 1 u 3u IPv4 0x1 0t0 TCP 10.0.0.1:5000->239.255.255.250:1900 (ESTABLISHED)"
        let ips = SubnetDiscovery.parseRemoteIPs(lsof)
        XCTAssertTrue(ips.isEmpty)
    }

    func testParseRemoteIPsDropsIpv6LinkLocal() {
        let lsof = "proc 1 u 3u IPv6 0x1 0t0 TCP [fe80::1]:5000->[fe80::2]:5001 (ESTABLISHED)"
        let ips = SubnetDiscovery.parseRemoteIPs(lsof)
        XCTAssertTrue(ips.isEmpty, "fe80::/10 link-local must be dropped, got \(ips)")
    }

    func testParseRemoteIPsIgnoresLinesWithoutArrow() {
        // Listen-only sockets (no `->`) shouldn't crash the parser.
        let lsof = """
        proc 1 u 3u IPv4 0x1 0t0 TCP *:5000 (LISTEN)
        proc 1 u 4u IPv4 0x2 0t0 UDP *:5353
        proc 1 u 5u IPv4 0x3 0t0 TCP 10.0.0.1:5000->1.2.3.4:443 (ESTABLISHED)
        """
        let ips = SubnetDiscovery.parseRemoteIPs(lsof)
        XCTAssertEqual(ips, ["1.2.3.4"])
    }

    func testParseRemoteIPsHandlesEmptyOutput() {
        XCTAssertEqual(SubnetDiscovery.parseRemoteIPs(""), [])
    }

    // MARK: - rankSubnets

    func testRankSubnetsGroupsByCidr() {
        let ips = ["1.2.3.4", "1.2.3.5", "1.2.3.4", "5.6.7.8"]
        let ranked = SubnetDiscovery.rankSubnets(ips)
        XCTAssertEqual(ranked.count, 2)
        XCTAssertEqual(ranked[0].subnet, "1.2.3.0/24")
        XCTAssertEqual(ranked[0].peerCount, 2,
                       "duplicate 1.2.3.4 must NOT double-count")
        XCTAssertEqual(ranked[1].subnet, "5.6.7.0/24")
        XCTAssertEqual(ranked[1].peerCount, 1)
    }

    func testRankSubnetsCountsDistinctPeersNotConnections() {
        // The bug we explicitly guard against: a single noisy IP
        // with 50 connections shouldn't outrank a subnet with 5
        // distinct peers, since the user wants "where am I
        // talking", not "how chatty is one host".
        let manyConnectionsOneHost = Array(repeating: "1.1.1.1", count: 50)
        let fiveHostsOneSubnet = ["2.2.2.1", "2.2.2.2", "2.2.2.3", "2.2.2.4", "2.2.2.5"]
        let ranked = SubnetDiscovery.rankSubnets(manyConnectionsOneHost + fiveHostsOneSubnet)
        XCTAssertEqual(ranked[0].subnet, "2.2.2.0/24",
                       "subnet with more distinct peers wins")
        XCTAssertEqual(ranked[0].peerCount, 5)
    }

    func testRankSubnetsAlphabeticalTiebreak() {
        // Same peer count → deterministic order so the UI doesn't
        // flip rows on every scan.
        let ranked = SubnetDiscovery.rankSubnets(["1.2.3.4", "5.6.7.8"])
        XCTAssertEqual(ranked.map(\.subnet), ["1.2.3.0/24", "5.6.7.0/24"])
    }

    func testRankSubnetsIpv6FoldsToSlashSixtyFour() {
        let ranked = SubnetDiscovery.rankSubnets(["2001:db8:abcd:1234:0:0:0:1",
                                                  "2001:db8:abcd:1234:0:0:0:2"])
        XCTAssertEqual(ranked.first?.subnet, "2001:db8:abcd:1234::/64")
        XCTAssertEqual(ranked.first?.peerCount, 2)
    }

    func testRankSubnetsEmptyInput() {
        XCTAssertEqual(SubnetDiscovery.rankSubnets([]), [])
    }
}
