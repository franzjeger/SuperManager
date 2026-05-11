import XCTest
import SwiftUI
@testable import SuperManagerMac

/// Sanity tests for `RiskBand` — the colour-coded posture
/// indicator on the engagement detail header. The mapping is a
/// stable contract between the daemon's score-bucketing logic and
/// the visual presentation; changing label or colour without
/// changing both ends shifts what the customer sees.
final class RiskBandTests: XCTestCase {
    func testCriticalIsRed() {
        XCTAssertEqual(RiskBand.critical.color, Color.red)
        XCTAssertEqual(RiskBand.critical.label, "Critical")
    }

    func testElevatedIsOrange() {
        XCTAssertEqual(RiskBand.elevated.color, Color.orange)
        XCTAssertEqual(RiskBand.elevated.label, "Elevated")
    }

    func testModerateIsYellow() {
        XCTAssertEqual(RiskBand.moderate.color, Color.yellow)
        XCTAssertEqual(RiskBand.moderate.label, "Moderate")
    }

    func testLowIsBlue() {
        // Blue not green for Low: green is reserved for Clean. A
        // customer with a couple of low findings is "informational
        // hardening" territory, not a victory lap.
        XCTAssertEqual(RiskBand.low.color, Color.blue)
        XCTAssertEqual(RiskBand.low.label, "Low")
    }

    func testCleanIsGreen() {
        XCTAssertEqual(RiskBand.clean.color, Color.green)
        XCTAssertEqual(RiskBand.clean.label, "Clean")
    }

    /// Decode every band from its wire-format string. The daemon
    /// emits these as lowercase strings; a typo here would break
    /// the posture indicator silently.
    func testCodableRoundTrip() throws {
        for raw in ["critical", "elevated", "moderate", "low", "clean"] {
            let json = #""\#(raw)""#
            let band = try JSONDecoder().decode(RiskBand.self, from: Data(json.utf8))
            XCTAssertEqual(band.rawValue, raw)
        }
    }
}
