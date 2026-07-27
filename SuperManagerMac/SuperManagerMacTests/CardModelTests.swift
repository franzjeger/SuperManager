import XCTest
@testable import SuperManagerMac

/// The detail-card decisions, now testable because they were extracted out of
/// their SwiftUI views into pure value types (`VpnConnectionCardModel`,
/// `HostConnectionCardModel`, `SshHostGrouping`). Each pins a distinction the
/// card leans on — helper-down vs tunnel-down, network-unreachable vs
/// auth-rejected, customer grouping vs manual grouping — that reads as one
/// small string on screen and would regress without a sound.
final class CardModelTests: XCTestCase {

    // MARK: VPN connection card

    private func vpn(
        helper: Bool = true, state: String, full: Bool = true,
        detail: String = "", last: Date? = nil
    ) -> VpnConnectionCardModel {
        VpnConnectionCardModel(
            helperReachable: helper, state: state,
            fullTunnel: full, detail: detail, lastConnectedAt: last
        )
    }

    func testHelperDownIsItsOwnStateNotATunnelState() {
        // Helper unreachable must not masquerade as "disconnected": the next
        // action is install/approve, not connect.
        let c = vpn(helper: false, state: "connected")
        XCTAssertEqual(c.status, .warn)
        XCTAssertEqual(c.title, "Helper not running")
        XCTAssertTrue(c.meta.contains("daemon"))
    }

    func testConnectedShowsHelperDetailWhenPresentElseMode() {
        XCTAssertEqual(vpn(state: "connected", detail: "established 26s ago").meta,
                       "established 26s ago")
        // No detail yet → fall back to the tunnel mode, never an empty line.
        XCTAssertEqual(vpn(state: "connected", full: false, detail: "").meta, "Split tunnel")
    }

    func testProblemStateSurfacesAsError() {
        let c = vpn(state: "problem")
        XCTAssertEqual(c.status, .error)
        XCTAssertEqual(c.title, "Problem")
    }

    func testDisconnectedWithoutHistoryIsJustTheMode() {
        XCTAssertEqual(vpn(state: "disconnected", last: nil).meta, "Full tunnel")
    }

    func testDisconnectedWithHistoryNamesWhenAndMode() {
        // "Disconnected" alone doesn't say a minute or a month; the meta must
        // carry both the last-connected time and the mode. Relative wording is
        // clock-dependent, so assert structure, not the exact phrase.
        let c = vpn(state: "disconnected", full: false, last: Date(timeIntervalSince1970: 1))
        XCTAssertTrue(c.meta.contains("Last connected"), "meta was: \(c.meta)")
        XCTAssertTrue(c.meta.contains("Split tunnel"), "meta was: \(c.meta)")
    }

    func testTitlesForEveryKnownState() {
        XCTAssertEqual(vpn(state: "connected").title, "Connected")
        XCTAssertEqual(vpn(state: "connecting").title, "Connecting…")
        XCTAssertEqual(vpn(state: "reconnecting").title, "Reconnecting…")
        XCTAssertEqual(vpn(state: "disconnecting").title, "Disconnecting…")
        XCTAssertEqual(vpn(state: "disconnected").title, "Disconnected")
    }

    // MARK: SSH host connection card

    func testNotTestedIsUnknownWithAnInvitation() {
        let c = HostConnectionCardModel(probe: .notTested)
        XCTAssertEqual(c.status, .unknown)
        XCTAssertEqual(c.title, "Not tested")
        XCTAssertTrue(c.meta.contains("Test the connection"))
    }

    func testNetworkFailureIsOfflineNotError() {
        // The host isn't broken, the path from here is — offline, with the
        // "is the right VPN up?" nudge. This is the distinction the card exists
        // to draw.
        let c = HostConnectionCardModel(probe: .unreachable("no route to host"))
        XCTAssertEqual(c.status, .offline)
        XCTAssertEqual(c.title, "Unreachable")
        XCTAssertEqual(c.meta, "no route to host — check that the right VPN tunnel is up.")
    }

    func testAuthFailureIsErrorWithTheMessage() {
        // The host answered and rejected us — a fact someone must fix.
        let c = HostConnectionCardModel(probe: .authFailed("permission denied (publickey)"))
        XCTAssertEqual(c.status, .error)
        XCTAssertEqual(c.title, "Auth failed")
        XCTAssertEqual(c.meta, "permission denied (publickey)")
    }

    func testReachableIsOnline() {
        let c = HostConnectionCardModel(probe: .reachable)
        XCTAssertEqual(c.status, .online)
        XCTAssertEqual(c.title, "Reachable")
    }

    func testFailedIsError() {
        let c = HostConnectionCardModel(probe: .failed("something went sideways"))
        XCTAssertEqual(c.status, .error)
        XCTAssertEqual(c.title, "Failed")
        XCTAssertEqual(c.meta, "something went sideways")
    }

    func testTestingIsPendingWithNoMeta() {
        let c = HostConnectionCardModel(probe: .testing)
        XCTAssertEqual(c.status, .pending)
        XCTAssertEqual(c.title, "Testing…")
        XCTAssertEqual(c.meta, "")
    }

    // MARK: SSH sidebar grouping

    // Built the way the rest of the suite builds them: from JSON, so the
    // fixtures stay tolerant of non-public required-field additions.
    private func host(id: String, group: String = "", ip: String) -> SshHostSummary {
        SshHostSummary.previewFixture(
            id: id, label: id, hostname: ip, username: "admin",
            group: group, deviceType: .linux
        )
    }

    /// A customer with `displayName` distinct from `slug` and one site whose
    /// `host_ids` link the given tokens — the shape the resolver reads.
    private func customer(slug: String, displayName: String, linkedHostIds: [String]) -> Customer {
        let ids = linkedHostIds.map { "\"\($0)\"" }.joined(separator: ",")
        let json = """
        {
          "slug": "\(slug)", "display_name": "\(displayName)", "contact_name": "",
          "contact_email": "", "notes": "", "default_template": null,
          "mgmt_allowlist_domains": [], "primary_domain": "",
          "sites": [{
            "id": "s1", "display_name": "Site", "address": "",
            "host_ids": [\(ids)], "wan_type": "dhcp", "wan_static_ip": "",
            "lan_base": "10.0.0.0", "vlans": []
          }]
        }
        """
        return try! JSONDecoder().decode(Customer.self, from: Data(json.utf8))
    }

    func testUngroupedWhenNoCustomerAndNoManualGroup() {
        let h = host(id: "h1", ip: "10.0.0.1")
        let title = SshHostGrouping.sectionTitle(
            for: h, hostIndex: HostIndex(hosts: [h], customers: []), customers: []
        )
        XCTAssertEqual(title, "Ungrouped")
    }

    func testManualGroupUsedWhenNoCustomerLink() {
        let h = host(id: "h1", group: "Lab", ip: "10.0.0.1")
        let title = SshHostGrouping.sectionTitle(
            for: h, hostIndex: HostIndex(hosts: [h], customers: []), customers: []
        )
        XCTAssertEqual(title, "Lab", "manual group is the fallback when the resolver links no customer")
    }

    func testCustomerDisplayNameWinsOverManualGroup() {
        // A host linked to a customer via the resolver groups under the
        // customer's DISPLAY NAME, not its slug and not the manual group.
        let h = host(id: "h1", group: "Lab", ip: "10.0.0.1")
        let c = customer(slug: "acme", displayName: "Acme Corp", linkedHostIds: ["h1"])
        let idx = HostIndex(hosts: [h], customers: [c])
        let title = SshHostGrouping.sectionTitle(for: h, hostIndex: idx, customers: [c])
        XCTAssertEqual(title, "Acme Corp")
    }
}
