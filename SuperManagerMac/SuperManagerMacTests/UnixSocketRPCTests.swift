import XCTest
@testable import SuperManagerMac

/// The shared transport's promises, which both daemon clients build their
/// retry rule and their deadlines on.
final class UnixSocketRPCTests: XCTestCase {
    /// sun_path holds 104 bytes. The test's temporary directory can be
    /// longer than that; /tmp never is.
    private let path = "/tmp/sm-\(UUID().uuidString.prefix(8)).sock"

    override func tearDown() {
        unlink(path)
        super.tearDown()
    }

    func testNothingListeningIsUnreachableAndUnsent() async {
        let failure = await failure(of: roundTrip())
        XCTAssertEqual(failure?.kind, .unreachable)
        XCTAssertEqual(failure?.requestSent, false)
    }

    /// A peer that accepts and goes silent costs its budget, not forever.
    func testAPeerThatNeverAnswersTimesOutAtTheDeadline() async throws {
        let daemon = try FakeDaemon(path: path)
        defer { daemon.stop() }
        daemon.serve(.stall)
        let start = ContinuousClock.now
        let failure = await failure(of: roundTrip(budget: .milliseconds(300)))
        let elapsed = start.duration(to: .now)
        XCTAssertEqual(failure?.kind, .timedOut)
        XCTAssertEqual(failure?.requestSent, true)
        XCTAssertGreaterThanOrEqual(elapsed, .milliseconds(300))
        XCTAssertLessThan(elapsed, .seconds(3))
    }

    func testAHangUpAfterTheRequestCountsAsSent() async throws {
        let daemon = try FakeDaemon(path: path)
        defer { daemon.stop() }
        daemon.serve(.hangUpAfterRequest)
        let failure = await failure(of: roundTrip())
        XCTAssertEqual(failure?.kind, .io)
        XCTAssertEqual(failure?.requestSent, true)
    }

    /// The peer closes while the frame is still being written. Without
    /// SO_NOSIGPIPE this test crashes with "signal pipe", as the app did
    /// when a new launch replaced the daemon it was talking to.
    func testAPeerThatClosesMidWriteIsAnUnsentFailureNotASignal() async throws {
        let daemon = try FakeDaemon(path: path)
        defer { daemon.stop() }
        daemon.serve(.drop)
        // Far more than a Unix socket buffers, so the write is still going
        // when the peer closes.
        let failure = await failure(of: roundTrip(body: Data(count: 4 << 20)))
        XCTAssertEqual(failure?.kind, .io)
        XCTAssertEqual(failure?.requestSent, false)
    }

    func testAnOversizedReplyIsRefusedBeforeItIsRead() async throws {
        let daemon = try FakeDaemon(path: path)
        defer { daemon.stop() }
        daemon.serve(.announce(2 << 20))
        let failure = await failure(of: roundTrip(maxReply: 1 << 20))
        XCTAssertEqual(failure?.kind, .replyTooLarge(2 << 20))
        XCTAssertEqual(failure?.requestSent, true)
    }

    func testAnAnsweredRequestReturnsTheReplyBody() async throws {
        let daemon = try FakeDaemon(path: path)
        defer { daemon.stop() }
        daemon.serve(.answer("pong"))
        let reply = try await roundTrip()()
        let json = try JSONSerialization.jsonObject(with: reply) as? [String: Any]
        XCTAssertEqual(json?["result"] as? String, "pong")
    }

    // MARK: - Helpers

    /// A round trip to `path`, not yet started.
    private func roundTrip(
        budget: Duration? = .seconds(5),
        body: Data = Data(#"{"jsonrpc":"2.0","method":"ping","id":1}"#.utf8),
        maxReply: UInt32 = 1 << 20
    ) -> () async throws -> Data {
        let path = path
        return {
            try await UnixSocketRPC.roundTrip(
                path: path, body: body,
                deadline: .init(method: "ping", budget: budget), maxReply: maxReply)
        }
    }

    /// The `Failure` a round trip ended in, or nil (and a test failure) if it
    /// succeeded or threw anything else.
    private func failure(of roundTrip: () async throws -> Data) async -> UnixSocketRPC.Failure? {
        do {
            _ = try await roundTrip()
            XCTFail("round trip succeeded")
        } catch let failure as UnixSocketRPC.Failure {
            return failure
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        return nil
    }
}
