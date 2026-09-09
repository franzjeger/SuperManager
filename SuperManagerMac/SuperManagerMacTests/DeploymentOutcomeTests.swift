import XCTest
@testable import SuperManagerMac

final class DeploymentOutcomeTests: XCTestCase {
    private func record(status: String, checked: Bool?) throws -> Deployment {
        var value: [String: Any] = [
            "id": "record", "host_id": "host", "customer_slug": "acme", "site_id": "hq",
            "template_id": "test", "started_at": "2026-09-09T00:00:00Z", "status": status,
            "rendered_config": "first\nsecond", "lines_pushed": 1
        ]
        if let checked { value["acknowledgment_checked"] = checked }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(Deployment.self, from: JSONSerialization.data(withJSONObject: value))
    }

    func testLegacySuccessDoesNotClaimAcknowledgment() throws {
        let result = try record(status: "succeeded", checked: nil)
        XCTAssertEqual(result.outcomeDescription, "Reported success (legacy)")
        XCTAssertEqual(result.progressDescription, "1 line reported by legacy engine")
    }

    func testAcknowledgedCommandsDoNotClaimVerifiedDeploymentOrRestore() throws {
        XCTAssertEqual(try record(status: "succeeded", checked: true).outcomeDescription, "Commands acknowledged")
        XCTAssertEqual(try record(status: "rolled_back", checked: true).outcomeDescription, "Restore commands acknowledged")
        let failed = try record(status: "failed", checked: true)
        XCTAssertEqual(failed.outcomeDescription, "Failed")
        XCTAssertEqual(failed.progressDescription, "1 line acknowledged")
    }
}
