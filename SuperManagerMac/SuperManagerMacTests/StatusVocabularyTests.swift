import XCTest
@testable import SuperManagerMac

/// The shared status/severity/badge vocabulary.
///
/// These mappings are contracts the whole UI reads through. Each test here
/// pins a decision that was a real bug this codebase already paid for: the
/// nil→unknown (not offline) rule that the anti-flicker work turned on, the
/// single severity palette that six hand-rolled copies had drifted from, and
/// the loose backend matching that keeps a renamed daemon label from greying
/// out every badge.
final class StatusVocabularyTests: XCTestCase {

    // MARK: StatusStyle.vpn — the daemon's state strings → the vocabulary

    func testUnpolledIsUnknownNotOffline() {
        // The lie the hysteresis work removed: a tunnel we haven't measured
        // is `unknown`, never `offline`. Asserting "down" before measuring is
        // the exact defect this rule exists to prevent.
        XCTAssertEqual(StatusStyle.vpn(nil), .unknown)
    }

    func testProblemIsErrorNotOffline() {
        // "was up, can no longer confirm" must read red, not a calm grey.
        XCTAssertEqual(StatusStyle.vpn("problem"), .error)
    }

    func testReconnectingIsWarnNotOnline() {
        // Up-ish but not healthy — degraded, not connected.
        XCTAssertEqual(StatusStyle.vpn("reconnecting"), .warn)
    }

    func testCoreStateMappings() {
        XCTAssertEqual(StatusStyle.vpn("connected"), .online)
        XCTAssertEqual(StatusStyle.vpn("connecting"), .pending)
        XCTAssertEqual(StatusStyle.vpn("disconnecting"), .pending)
        XCTAssertEqual(StatusStyle.vpn("disconnected"), .offline)
    }

    func testAnyErrorContainingStringIsError() {
        XCTAssertEqual(StatusStyle.vpn("auth error"), .error)
        XCTAssertEqual(StatusStyle.vpn("some_error_state"), .error)
    }

    func testUnrecognisedStateFallsBackToUnknownNotOffline() {
        // A state the daemon adds tomorrow must not masquerade as "down".
        XCTAssertEqual(StatusStyle.vpn("frobnicating"), .unknown)
    }

    // MARK: SeverityBadge — the one canonical palette

    func testSeverityPaletteIsStable() {
        // Six copies of this had drifted; this is now the only source.
        XCTAssertEqual(SeverityBadge.color(for: .critical), .red)
        XCTAssertEqual(SeverityBadge.color(for: .high), .orange)
        XCTAssertEqual(SeverityBadge.color(for: .medium), .yellow)
        XCTAssertEqual(SeverityBadge.color(for: .low), .blue)
        XCTAssertEqual(SeverityBadge.color(for: .info), .gray)
    }

    func testSeverityRankOrdersCriticalFirst() {
        // Sort key: lower = more severe. Findings lists sort on this.
        XCTAssertLessThan(SeverityBadge.rank(.critical), SeverityBadge.rank(.high))
        XCTAssertLessThan(SeverityBadge.rank(.high), SeverityBadge.rank(.medium))
        XCTAssertLessThan(SeverityBadge.rank(.medium), SeverityBadge.rank(.low))
        XCTAssertLessThan(SeverityBadge.rank(.low), SeverityBadge.rank(.info))
    }

    // MARK: ComplianceSeverity → FindingSeverity bridge

    func testComplianceSeverityBridgesOneToOne() {
        // Two enums, one meaning. The bridge must be exhaustive and identity-
        // preserving, or Compliance chips drift from the canonical palette —
        // which is exactly where .info had gone wrong (.secondary vs .gray).
        XCTAssertEqual(AppState.ComplianceSeverity.critical.asFindingSeverity, .critical)
        XCTAssertEqual(AppState.ComplianceSeverity.high.asFindingSeverity, .high)
        XCTAssertEqual(AppState.ComplianceSeverity.medium.asFindingSeverity, .medium)
        XCTAssertEqual(AppState.ComplianceSeverity.low.asFindingSeverity, .low)
        XCTAssertEqual(AppState.ComplianceSeverity.info.asFindingSeverity, .info)
    }

    func testComplianceInfoRendersGrayNotSecondary() {
        // The specific drift the bridge fixed, pinned end-to-end: a compliance
        // .info chip must resolve to the same grey as every other .info.
        let color = SeverityBadge.color(for: AppState.ComplianceSeverity.info.asFindingSeverity)
        XCTAssertEqual(color, .gray)
    }

    // MARK: BadgeKind.backend — loose matching against the daemon's labels

    func testBackendMatchingSurvivesLabelVariants() {
        // The daemon spells backends several ways; match on substring so a
        // display-label rename can't grey out every badge.
        XCTAssertEqual(BadgeKind.backend("FortiGate (IPsec/IKEv2)"), .ikev2)
        XCTAssertEqual(BadgeKind.backend("forti_gate"), .ikev2)
        XCTAssertEqual(BadgeKind.backend("wire_guard"), .wireguard)
        XCTAssertEqual(BadgeKind.backend("WireGuard"), .wireguard)
        XCTAssertEqual(BadgeKind.backend("OpenVPN3"), .openvpn)
        XCTAssertEqual(BadgeKind.backend("Azure VPN"), .azure)
    }

    func testUnknownBackendIsNeutralNotAMisassignedColour() {
        XCTAssertEqual(BadgeKind.backend("something-new"), .neutral)
    }
}
