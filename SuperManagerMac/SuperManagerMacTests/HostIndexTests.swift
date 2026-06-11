import XCTest
@testable import SuperManagerMac

/// Tests for `HostIndex`, the unified Customer→Site→Host resolver.
///
/// The contract under test is the reconciliation of the four legacy host
/// identities: the `group` slug, the `Site.hostIds` token (which may be a
/// record id OR an IP), and the host's `hostname` (IP). The key regression
/// these lock down: a FortiGate with `group:"Discovered"` linked to its
/// customer only by IP in `Site.hostIds` must still resolve to that customer
/// (the cause of "No compliance-capable hosts").
final class HostIndexTests: XCTestCase {

    /// Build a Customer from JSON so the fixture stays tolerant to model
    /// field additions (same approach as `SshHostSummary.previewFixture`).
    private func customer(slug: String, siteId: String, hostIds: [String]) -> Customer {
        let ids = hostIds.map { "\"\($0)\"" }.joined(separator: ",")
        let json = """
        {
          "slug": "\(slug)", "display_name": "\(slug)", "contact_name": "",
          "contact_email": "", "notes": "", "default_template": null,
          "mgmt_allowlist_domains": [], "primary_domain": "",
          "sites": [{
            "id": "\(siteId)", "display_name": "Site", "address": "",
            "host_ids": [\(ids)], "wan_type": "dhcp", "wan_static_ip": "",
            "lan_base": "10.0.0.0", "vlans": []
          }]
        }
        """
        return try! JSONDecoder().decode(Customer.self, from: Data(json.utf8))
    }

    private func host(id: String, ip: String, group: String) -> SshHostSummary {
        SshHostSummary.previewFixture(
            id: id, label: id, hostname: ip, username: "admin",
            group: group, deviceType: .fortigate
        )
    }

    /// Precedence (a): an exact `group == slug` resolves directly.
    func testGroupEqualsSlugResolvesDirectly() {
        let h = host(id: "h1", ip: "10.0.0.1", group: "acme")
        let idx = HostIndex(hosts: [h], customers: [customer(slug: "acme", siteId: "s1", hostIds: [])])
        XCTAssertEqual(idx.customerSlug(forHost: h), "acme")
    }

    /// Precedence (b) — THE FIX: group is the "Discovered" sentinel, but the
    /// host is linked to its customer by IP in Site.hostIds.
    func testDiscoveredHostLinkedByIpResolvesToCustomer() {
        let h = host(id: "h2", ip: "10.0.0.5", group: "Discovered")
        let idx = HostIndex(hosts: [h], customers: [customer(slug: "acme", siteId: "s1", hostIds: ["10.0.0.5"])])
        XCTAssertEqual(idx.customerSlug(forHost: h), "acme",
                       "An IP-linked discovered host must resolve to its customer")
    }

    /// Site.hostIds may also hold a real record id; that must resolve too.
    func testHostLinkedByRecordIdResolves() {
        let h = host(id: "h3", ip: "10.0.0.9", group: "")
        let idx = HostIndex(hosts: [h], customers: [customer(slug: "beta", siteId: "s1", hostIds: ["h3"])])
        XCTAssertEqual(idx.customerSlug(forHost: h), "beta")
    }

    /// host(forToken:) resolves both id tokens and IP tokens to the same host.
    func testHostForTokenResolvesIdAndIp() {
        let h = host(id: "h4", ip: "10.0.0.7", group: "")
        let idx = HostIndex(hosts: [h], customers: [])
        XCTAssertEqual(idx.host(forToken: "h4")?.id, "h4")
        XCTAssertEqual(idx.host(forToken: "10.0.0.7")?.id, "h4")
        XCTAssertNil(idx.host(forToken: "nope"))
    }

    /// A genuinely ungrouped host (no slug, no site link) resolves to nil.
    func testUngroupedHostResolvesNil() {
        let h = host(id: "h5", ip: "10.0.0.8", group: "")
        let idx = HostIndex(hosts: [h], customers: [customer(slug: "acme", siteId: "s1", hostIds: [])])
        XCTAssertNil(idx.customerSlug(forHost: h))
    }

    /// Precedence (a) wins over (b): an exact group slug takes priority over a
    /// conflicting site link, so a correctly-grouped host is never reassigned.
    func testGroupSlugWinsOverConflictingLink() {
        let h = host(id: "h6", ip: "10.0.0.6", group: "acme")
        let idx = HostIndex(hosts: [h], customers: [
            customer(slug: "acme", siteId: "s1", hostIds: []),
            customer(slug: "beta", siteId: "s2", hostIds: ["10.0.0.6"]),
        ])
        XCTAssertEqual(idx.customerSlug(forHost: h), "acme")
    }

    /// recordIds(forCustomer:) returns the record ids linked to a customer,
    /// resolved from IP tokens — the seam Fleet uses to fold in compliance.
    func testRecordIdsForCustomer() {
        let h = host(id: "h7", ip: "10.0.0.10", group: "Discovered")
        let idx = HostIndex(hosts: [h], customers: [customer(slug: "acme", siteId: "s1", hostIds: ["10.0.0.10"])])
        XCTAssertEqual(idx.recordIds(forCustomer: "acme"), ["h7"])
    }
}
