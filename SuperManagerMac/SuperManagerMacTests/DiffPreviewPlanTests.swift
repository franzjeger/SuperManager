import XCTest

@testable import SuperManagerMac

/// A preview carries the plan a deploy of exactly that preview takes. The
/// JSON here is the daemon's `DiffPreviewResult` as serde writes it.
final class DiffPreviewPlanTests: XCTestCase {
    func testThePreviewCarriesThePlanADeployTakes() throws {
        let json = """
        {"plan_id":"6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f","expires_in_secs":900,
         "rendered":"config system global\\n    set hostname branch\\nend\\n",
         "sections":[{"path":"system global","status":"modified",
                      "template_body":"set hostname branch","device_body":"set hostname old",
                      "unified_diff":"-set hostname old\\n+set hostname branch"}],
         "summary":{"added":0,"modified":1,"equal":0,"total":1}}
        """
        let preview = try JSONDecoder().decode(AppState.DiffPreviewResult.self, from: Data(json.utf8))
        XCTAssertEqual(preview.planId, "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f")
        XCTAssertEqual(preview.expiresInSecs, 900)
        XCTAssertEqual(preview.summary.modified, 1)
    }
}
