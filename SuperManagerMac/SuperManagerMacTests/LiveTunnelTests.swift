import XCTest

@testable import SuperManagerMac

/// A full tunnel the gateway narrows to its own networks carries only
/// those; the detail view says so under the routes.
final class LiveTunnelTests: XCTestCase {
    private func tunnel(_ routes: [String]) -> VpnDetailView.LiveTunnel {
        VpnDetailView.LiveTunnel(interface: "utun9", virtualIp: "10.20.200.10", routes: routes)
    }

    func testAFullTunnelGrantedOnlySomeNetworksIsNarrowed() {
        // What Elteco's FortiGate granted a full-tunnel profile.
        XCTAssertTrue(tunnel(["10.20.3.0/24", "10.20.21.0/24"]).narrows(fullTunnel: true))
    }

    func testAFullTunnelGrantedEverythingIsNot() {
        XCTAssertFalse(tunnel(["0.0.0.0/0"]).narrows(fullTunnel: true))
    }

    func testASplitTunnelOrUnknownRoutesAreNot() {
        XCTAssertFalse(tunnel(["10.20.3.0/24"]).narrows(fullTunnel: false))
        XCTAssertFalse(tunnel([]).narrows(fullTunnel: true))
    }
}
