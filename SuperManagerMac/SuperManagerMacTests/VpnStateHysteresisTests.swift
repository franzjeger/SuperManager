import XCTest
@testable import SuperManagerMac

/// The anti-flicker hysteresis for a VPN profile's displayed state.
///
/// This is the single most load-bearing piece of untested logic in the VPN
/// section: it is what stopped the constant connected/connecting blink the
/// operator reported, and it decides — on every poll — whether a
/// non-connected sample is a hiccup to ride out, a real disconnect, or a
/// tunnel that was up and can no longer be confirmed (`problem`). A
/// regression here doesn't crash; it quietly brings the flicker back or,
/// worse, hides a dead tunnel behind a green dot. That is exactly the class
/// of bug a test has to hold down.
@MainActor
final class VpnStateHysteresisTests: XCTestCase {

    /// Helper: run one sample against a previous state + streak, returning
    /// both the new state and the mutated streak so a test can chain polls.
    private func step(previous: String, sample: String, streak: Int) -> (state: String, streak: Int) {
        var s = streak
        let out = AppState.stabilizedVpnState(previous: previous, sample: sample, missStreak: &s)
        return (out, s)
    }

    // MARK: truth wins instantly

    func testConnectedSampleWinsImmediatelyAndResetsStreak() {
        // Even mid-streak, a real "connected" reading commits at once.
        let r = step(previous: "problem", sample: "connected", streak: 1)
        XCTAssertEqual(r.state, "connected")
        XCTAssertEqual(r.streak, 0, "a confirmed connection clears any accumulated miss streak")
    }

    // MARK: ride out a single hiccup

    func testOneBadSampleWhileConnectedHoldsConnected() {
        // The whole point: a lone slow/failed poll must NOT flip the dot.
        let r = step(previous: "connected", sample: "unknown", streak: 0)
        XCTAssertEqual(r.state, "connected", "first miss is ridden out")
        XCTAssertEqual(r.streak, 1)
    }

    func testSecondConsecutiveMissCommitsTheTransition() {
        // Two misses in a row is a real change, not noise.
        let r = step(previous: "connected", sample: "unknown", streak: 1)
        XCTAssertNotEqual(r.state, "connected", "a sustained miss must commit")
        XCTAssertEqual(r.streak, 0, "streak resets once the transition commits")
    }

    // MARK: the disconnected-vs-problem distinction (the important one)

    func testCommitToDisconnectedOnlyWhenDefinitivelyGone() {
        // Second miss, and the helper DEFINITIVELY said the SA is gone.
        let r = step(previous: "connected", sample: "disconnected", streak: 1)
        XCTAssertEqual(r.state, "disconnected")
    }

    func testCommitToProblemWhenWasUpAndCanNoLongerConfirm() {
        // Second miss, but the sample is anything other than a clean
        // "disconnected" (timeout / stuck "connecting" / RPC threw). The
        // tunnel was up and we can't confirm it — that must read as a
        // problem, never as a tidy "disconnected".
        for ambiguous in ["unknown", "connecting", "problem", "error"] {
            let r = step(previous: "connected", sample: ambiguous, streak: 1)
            XCTAssertEqual(r.state, "problem", "‘\(ambiguous)’ after a confirmed connection is a problem, not a clean disconnect")
        }
    }

    // MARK: not-currently-connected: unknown carries no information

    func testUnknownWhileNotConnectedHoldsPreviousState() {
        // An unknown sample must never invent a transition out of a
        // non-connected state — that was a flicker source.
        for prev in ["disconnected", "connecting", "problem", "reconnecting"] {
            let r = step(previous: prev, sample: "unknown", streak: 0)
            XCTAssertEqual(r.state, prev, "unknown must hold ‘\(prev)’, not overwrite it")
        }
    }

    func testHonestConnectingToConnectedPathIsFollowedDirectly() {
        // A fresh connect's normal progression is not noise; follow it.
        let r = step(previous: "disconnected", sample: "connecting", streak: 0)
        XCTAssertEqual(r.state, "connecting")
    }

    func testCleanProblemToDisconnectedOnceSaIsReallyGone() {
        // Once showing "problem", a definitive disconnected sample is
        // information, so it's followed directly (not held).
        let r = step(previous: "problem", sample: "disconnected", streak: 0)
        XCTAssertEqual(r.state, "disconnected")
    }

    // MARK: a full realistic sequence

    func testHiccupThenRecoveryNeverFlips() {
        // connected → one bad poll → connected again. The dot must stay
        // green the whole way; this is the exact scenario that flickered.
        var streak = 0
        var state = "connected"
        state = AppState.stabilizedVpnState(previous: state, sample: "unknown", missStreak: &streak)
        XCTAssertEqual(state, "connected")
        state = AppState.stabilizedVpnState(previous: state, sample: "connected", missStreak: &streak)
        XCTAssertEqual(state, "connected")
        XCTAssertEqual(streak, 0)
    }
}
