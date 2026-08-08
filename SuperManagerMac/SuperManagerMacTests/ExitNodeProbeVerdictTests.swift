import XCTest

@testable import SuperManagerMac

/// Grading of the post-install exit-node probes.
///
/// The rule this replaces was "any one probe passed", which reported a
/// path that failed four probes and answered on the fifth as live. The
/// user met a 19-second first response and concluded the feature was
/// broken — it effectively was, and we had told them it was fine.
final class ExitNodeProbeVerdictTests: XCTestCase {

    // MARK: - The three verdicts

    func testAnswersImmediatelyAndHoldsIsHealthy() {
        XCTAssertEqual(ExitNodeProbeVerdict.evaluate([true, true]), .healthy)
    }

    func testNothingGetsThroughIsDead() {
        XCTAssertEqual(
            ExitNodeProbeVerdict.evaluate([false, false, false, false, false, false]),
            .dead)
    }

    /// The exact sequence from the field report: fail, fail, fail, fail,
    /// OK. Previously "SUCCESS: exit-node live"; now it is kept — it does
    /// forward traffic — but reported for what it is.
    func testFourFailuresThenSuccessIsDegradedNotHealthy() {
        let verdict = ExitNodeProbeVerdict.evaluate([false, false, false, false, true])
        XCTAssertNotEqual(verdict, .healthy, "a path that took 5 attempts is not healthy")
        XCTAssertEqual(verdict, .degraded(secondsToFirstResponse: 10, failures: 4))
    }

    /// A single success with nothing after it is the fluke the old rule
    /// could not tell from a working path.
    func testLoneSuccessIsNotHealthy() {
        XCTAssertNotEqual(ExitNodeProbeVerdict.evaluate([true]), .healthy)
    }

    /// Answered first, then dropped — settled() is false, so not healthy.
    func testSuccessThenFailureIsDegraded() {
        XCTAssertEqual(
            ExitNodeProbeVerdict.evaluate([true, false]),
            .degraded(secondsToFirstResponse: 2, failures: 1))
    }

    /// One disruptive probe during route flux, then a settled path. Still
    /// not "healthy" — it needed recovery, and the user should know the
    /// path took a moment — but clearly not dead either.
    func testOneFailureThenTwoConsecutiveIsDegraded() {
        XCTAssertEqual(
            ExitNodeProbeVerdict.evaluate([false, true, true]),
            .degraded(secondsToFirstResponse: 4, failures: 1))
    }

    // MARK: - Early exit

    func testSettledRequiresTwoConsecutive() {
        XCTAssertFalse(ExitNodeProbeVerdict.settled([]))
        XCTAssertFalse(ExitNodeProbeVerdict.settled([true]))
        XCTAssertFalse(ExitNodeProbeVerdict.settled([true, false]))
        XCTAssertTrue(ExitNodeProbeVerdict.settled([true, true]))
        XCTAssertTrue(ExitNodeProbeVerdict.settled([false, true, true]))
    }

    /// settled() must look at the END of the sequence, not anywhere in
    /// it — a pair of successes followed by a failure means the path
    /// dropped again and probing should continue.
    func testSettledLooksAtTheTailNotThePast() {
        XCTAssertFalse(ExitNodeProbeVerdict.settled([true, true, false]))
    }

    // MARK: - Reporting

    /// The seconds figure is what makes the warning actionable, so it
    /// must track the probe interval rather than being a magic number.
    func testSecondsToFirstResponseTracksProbeInterval() {
        guard case let .degraded(seconds, _) =
                ExitNodeProbeVerdict.evaluate([false, false, true]) else {
            return XCTFail("expected degraded")
        }
        XCTAssertEqual(seconds, 3 * ExitNodeProbeVerdict.probeIntervalSeconds)
    }

    func testFailureCountIncludesFailuresAfterFirstSuccess() {
        guard case let .degraded(_, failures) =
                ExitNodeProbeVerdict.evaluate([true, false, true, true]) else {
            return XCTFail("expected degraded")
        }
        XCTAssertEqual(failures, 1)
    }

    /// An empty sequence must not read as success. It can only happen if
    /// probing was cancelled, and "we never checked" is not "it works".
    func testNoProbesIsDead() {
        XCTAssertEqual(ExitNodeProbeVerdict.evaluate([]), .dead)
    }
}
