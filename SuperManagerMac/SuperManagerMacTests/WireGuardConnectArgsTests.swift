import XCTest
@testable import SuperManagerMac

/// The helper reads `wg_connect`'s arguments into `WgConnectArgs`
/// (supermanager-helper/src/wireguard.rs), and stores the same arguments
/// to reconnect an always-on profile. Arguments under other names are
/// refused there, and always-on stays unarmed until the next connect.
final class WireGuardConnectArgsTests: XCTestCase {
    func testTheArgumentsHaveTheNamesTheHelperReads() {
        let args = HelperClient.wgConnectArgs(
            profileId: "p1", confContent: "[Interface]\n", dnsServers: ["10.0.0.1"],
            native: true)
        XCTAssertEqual(
            Set(args.keys), ["profile_id", "conf_content", "dns_servers", "native"])
        XCTAssertEqual(args["profile_id"] as? String, "p1")
        XCTAssertEqual(args["conf_content"] as? String, "[Interface]\n")
        XCTAssertEqual(args["dns_servers"] as? [String], ["10.0.0.1"])
        XCTAssertEqual(args["native"] as? Bool, true)
    }
}
