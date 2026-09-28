import XCTest
@testable import SuperManagerMac

/// `ServiceClient`'s retry rule against a stand-in daemon: a request that
/// never got out is sent again, and one the daemon read is not.
final class ServiceClientTests: XCTestCase {
    /// sun_path holds 104 bytes. The test's temporary directory can be
    /// longer than that; /tmp never is.
    private let path = "/tmp/sm-\(UUID().uuidString.prefix(8)).sock"

    override func tearDown() {
        unlink(path)
        super.tearDown()
    }

    /// Every call has a connection of its own, so a daemon replaced between
    /// two calls (a newer launch took over, or it crashed) is invisible to
    /// the second.
    func testCallsReachADaemonReplacedBetweenThem() async throws {
        let client = ServiceClient(socketPath: path)
        let first = try FakeDaemon(path: path)
        first.serve(.answer("one"))
        let one: String = try await client.call("ping")
        first.stop()

        let second = try FakeDaemon(path: path)
        defer { second.stop() }
        second.serve(.answer("two"))
        let two: String = try await client.call("ping")
        XCTAssertEqual([one, two], ["one", "two"])
    }

    /// A daemon that read the request and then died may have acted on it.
    /// Sending it again could run it twice, so the failure is final.
    func testARequestTheDaemonReadIsNotSentAgain() async throws {
        let daemon = try FakeDaemon(path: path)
        defer { daemon.stop() }
        daemon.serve(.hangUpAfterRequest)
        let client = ServiceClient(socketPath: path)
        do {
            try await client.callVoid("customer_delete")
            XCTFail("call succeeded without a reply")
        } catch ServiceError.disconnected {
            // The only acceptable outcome.
        }
        XCTAssertEqual(daemon.requests, 1)
        XCTAssertFalse(daemon.sawConnection(within: .milliseconds(800)), "the call was sent again")
    }

    /// No daemon yet, as while a launch is replacing it, is a failure before
    /// sending: the call goes out again once the daemon is up.
    func testARequestThatNeverGotOutIsSentAgain() async throws {
        let client = ServiceClient(socketPath: path)
        async let reply: String = client.call("ping")
        try await Task.sleep(for: .milliseconds(100))
        let daemon = try FakeDaemon(path: path)
        defer { daemon.stop() }
        daemon.serve(.answer("pong"))
        let pong = try await reply
        XCTAssertEqual(pong, "pong")
    }

    /// The daemon goes on running a call its client has given up on, so a
    /// deadline on one that changes a device would report a push that is
    /// still under way as failed.
    func testCallsThatChangeRemoteDevicesNeverTimeOut() {
        for method in ["provisioning_deploy", "provisioning_rollback", "ssh_push_key",
                       "ssh_execute_command", "fortigate_generate_api_token", "unifi_set_inform"] {
            XCTAssertNil(ServiceClient.budget(for: method), method)
        }
        XCTAssertEqual(ServiceClient.budget(for: "list_profiles"), .seconds(30))
    }

    /// With no daemon to come back to, the call fails once the retry has.
    func testCallFailsWhenNoDaemonListens() async throws {
        let client = ServiceClient(socketPath: path)
        do {
            let _: String = try await client.call("ping")
            XCTFail("call succeeded with no daemon listening")
        } catch ServiceError.connectionFailed {
            // Unreachable, retried once, still unreachable.
        }
    }
}
