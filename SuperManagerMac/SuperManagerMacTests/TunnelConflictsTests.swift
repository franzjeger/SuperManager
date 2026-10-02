import XCTest

@testable import SuperManagerMac

/// Tunnels that get in each other's way: one that takes all traffic next to
/// any other, and split tunnels that route the same addresses.
final class TunnelConflictsTests: XCTestCase {
    private func full(_ name: String) -> TunnelRouting {
        TunnelRouting(name: name, takesAll: true, routes: [])
    }

    private func split(_ name: String, _ routes: [String]) -> TunnelRouting {
        TunnelRouting(name: name, takesAll: false, routes: routes)
    }

    /// 2026-10-01: an IKEv2 full tunnel next to Azure took Azure's traffic
    /// to its server, and Azure's tunnel went down.
    func testAFullTunnelTakesTheOthersConnectionToTheirServers() {
        let conflicts = TunnelConflicts.between(
            full("Elteco"), and: [split("Autostrada Azure", ["10.134.0.0/23"])])
        XCTAssertEqual(conflicts, [.takesAll(taker: "Elteco", other: "Autostrada Azure")])
        XCTAssertTrue(conflicts[0].message.contains("Autostrada Azure can stop working"))
    }

    func testASplitTunnelNextToAFullOneIsTakenToo() {
        XCTAssertEqual(
            TunnelConflicts.between(split("Aarsleff", ["10.1.0.0/16"]), and: [full("Elteco")]),
            [.takesAll(taker: "Elteco", other: "Aarsleff")])
    }

    func testTwoFullTunnelsCannotBothHaveTheDefaultRoute() {
        XCTAssertEqual(
            TunnelConflicts.between(full("Elteco"), and: [full("IATA Lunde")]),
            [.bothTakeAll("Elteco", "IATA Lunde")])
    }

    func testSplitTunnelsRoutingTheSameNetworkConflict() {
        let conflicts = TunnelConflicts.between(
            split("Elteco", ["10.20.3.0/24", "10.20.21.0/24"]),
            and: [split("Motavo Oslo", ["10.20.3.0/24"])])
        XCTAssertEqual(conflicts, [
            .overlap(tunnel: "Elteco", route: "10.20.3.0/24", other: "Motavo Oslo", otherRoute: "10.20.3.0/24"),
        ])
        XCTAssertEqual(
            conflicts[0].message,
            "Elteco and Motavo Oslo both route 10.20.3.0/24. It goes through only one of them.")
    }

    /// The more specific route wins its addresses, whichever tunnel asks.
    func testANetworkInsideAnotherGoesThroughTheMoreSpecificTunnel() {
        let narrow = TunnelConflicts.between(
            split("Elteco", ["10.20.3.0/24"]), and: [split("Motavo Oslo", ["10.20.0.0/16"])])
        let wide = TunnelConflicts.between(
            split("Motavo Oslo", ["10.20.0.0/16"]), and: [split("Elteco", ["10.20.3.0/24"])])
        for conflicts in [narrow, wide] {
            XCTAssertEqual(conflicts.count, 1)
            XCTAssertEqual(
                conflicts[0].message,
                "Elteco routes 10.20.3.0/24, inside Motavo Oslo's 10.20.0.0/16. "
                    + "Those addresses go through Elteco, not Motavo Oslo.")
        }
    }

    func testAConflictIsListedOnce() {
        XCTAssertEqual(
            TunnelConflicts.between(
                split("Elteco", ["10.20.3.0/24", "10.20.3.0/24"]),
                and: [split("Motavo Oslo", ["10.20.3.0/24"])]).count,
            1)
    }

    func testSplitTunnelsOnDifferentNetworksGetAlong() {
        XCTAssertEqual(
            TunnelConflicts.between(
                split("Elteco", ["10.20.3.0/24", "10.20.21.0/24"]),
                and: [split("Aarsleff", ["10.20.4.0/24", "192.168.0.0/16", "2001:db8::/32"])]),
            [])
        XCTAssertEqual(TunnelConflicts.between(split("Elteco", ["10.20.3.0/24"]), and: []), [])
    }

    /// A default route among the networks is the full-tunnel case, and a
    /// route that is not one is nobody's network.
    func testDefaultRoutesAndGarbageAreNotNetworks() {
        XCTAssertEqual(
            TunnelConflicts.between(
                split("A", ["0.0.0.0/0", "::/0", "not a route", "10.0.0.0/33"]),
                and: [split("B", ["10.0.0.0/8", "2001:db8::/32"])]),
            [])
    }

    func testPrefixesOverlapWhenTheShorterContainsTheOther() throws {
        func prefix(_ text: String) throws -> IPPrefix { try XCTUnwrap(IPPrefix(text)) }

        XCTAssertTrue(try prefix("10.20.3.5/24").overlaps(prefix("10.20.3.0/24")))
        XCTAssertTrue(try prefix("10.0.0.0/8").overlaps(prefix("10.255.1.0/24")))
        XCTAssertFalse(try prefix("10.20.3.0/24").overlaps(prefix("10.20.4.0/24")))
        // A boundary inside a byte.
        XCTAssertTrue(try prefix("10.20.0.0/14").overlaps(prefix("10.23.255.0/24")))
        XCTAssertFalse(try prefix("10.20.0.0/14").overlaps(prefix("10.24.0.0/24")))
        // A bare address is a host.
        XCTAssertTrue(try prefix("10.20.3.7").overlaps(prefix("10.20.3.0/24")))
        XCTAssertFalse(try prefix("10.20.3.7").overlaps(prefix("10.20.3.8")))
        // IPv6, and never across families.
        XCTAssertTrue(try prefix("2001:db8::/32").overlaps(prefix("2001:db8:1::/48")))
        XCTAssertFalse(try prefix("::/0").overlaps(prefix("0.0.0.0/0")))

        XCTAssertNil(IPPrefix("10.0.0.0/33"))
        XCTAssertNil(IPPrefix("10.0.0.0/-1"))
        XCTAssertNil(IPPrefix("vpn.example.com/24"))
    }
}
