import XCTest
@testable import SuperManagerMac

/// Decoder tests for `VpnProfileConfig`.
///
/// The discriminator field is `backend` and each value maps to a
/// different concrete variant. The Rust side uses
/// `#[serde(tag = "backend", rename_all = "snake_case")]` so the
/// strings here MUST stay in lockstep with the daemon — a typo
/// causes every profile of that type to render as `.unsupported`.
final class VpnProfileConfigDecoderTests: XCTestCase {
    /// IKEv2 ships under the historical `forti_gate` tag because
    /// the variant predates the protocol-vs-vendor split. Renaming
    /// it would invalidate every saved profile on disk.
    func testForti_gateBackendBecomesIkev2() throws {
        // Daemon wire-format keys: snake_case for everything that
        // isn't a single word. `IKEv2Config` requires
        // host/username/password/psk/dns_servers/routes.
        let json = #"""
        {
            "backend": "forti_gate",
            "host": "vpn.example.com",
            "username": "u",
            "password": "kc/forti/p",
            "psk": "kc/forti/g",
            "dns_servers": ["1.1.1.1"],
            "routes": []
        }
        """#
        let cfg = try JSONDecoder().decode(VpnProfileConfig.self, from: Data(json.utf8))
        guard case .ikev2(let inner) = cfg else {
            XCTFail("forti_gate must decode to .ikev2, got \(cfg)")
            return
        }
        XCTAssertEqual(inner.host, "vpn.example.com")
        XCTAssertEqual(inner.username, "u")
    }

    func testUnknownBackendBecomesUnsupported() throws {
        // A daemon shipping a brand-new VPN type the app doesn't
        // recognise — fall back to .unsupported so the row renders
        // greyed-out rather than crashing the whole list decode.
        let json = #"""
        {
            "backend": "tailscale_vpn"
        }
        """#
        let cfg = try JSONDecoder().decode(VpnProfileConfig.self, from: Data(json.utf8))
        if case .unsupported(let backend) = cfg {
            XCTAssertEqual(backend, "tailscale_vpn",
                           "unsupported variant must carry the original tag for diagnostics")
        } else {
            XCTFail("unknown backend must degrade to .unsupported, got \(cfg)")
        }
    }
}
